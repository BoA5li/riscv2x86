"""Admission-only promotion of a verified evaluation staging tree."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
from typing import Mapping

from .candidate_materialization import (
    CandidateArtifactManifest, candidate_tree_digest,
    load_candidate_artifact_manifest, verify_candidate_artifact_manifest,
)
from .schema import TranslationOutcome
from .translation_validation import (
    ProgramArtifact, TargetEnvironment, TranslationValidationResult,
    ValidationPlan, ValidationProfile, _result as rebuild_validation_result,
    program_artifact_from_dict, target_environment_from_dict,
    translation_artifact_from_dict, translation_validation_result_from_dict,
    validation_plan_from_dict,
)
from .validation_status import PreservationMode, ValidationStatus


WRITEBACK_PROMOTION_SCHEMA = "riscv2x86.writeback-promotion.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_EMITTED = {
    TranslationOutcome.EMITTED, TranslationOutcome.STRENGTHENED,
    TranslationOutcome.FUNCTIONAL_FALLBACK,
}
_PROFILE_LEVELS = {
    ValidationProfile.BUILD: ("L0",),
    ValidationProfile.FUNCTIONAL: ("L0", "L1"),
    ValidationProfile.ARCHITECTURAL: ("L0", "L1", "L2"),
    ValidationProfile.MICROARCH: ("L0", "L1", "L2", "L3"),
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


@dataclass(frozen=True)
class EvaluatedAttempt:
    finding_id: str
    fragment_id: str
    attempt_artifact_id: str
    translation_outcome: TranslationOutcome
    status: ValidationStatus
    validation: TranslationValidationResult | None
    translation_artifact: object | None


@dataclass(frozen=True)
class CompletedEvaluation:
    evaluation_identity: str
    request_identity: str
    status: ValidationStatus
    candidate_manifest_id: str
    attempts: tuple[EvaluatedAttempt, ...]
    validation_plan: ValidationPlan
    target_environment: TargetEnvironment
    source_program: ProgramArtifact
    target_program: ProgramArtifact
    comparison_policy: str
    raw: Mapping[str, object]


def completed_evaluation_from_dict(value: Mapping[str, object]) -> CompletedEvaluation:
    fields = {"schemaVersion", "requestIdentity", "status", "reasonCodes",
              "candidateManifestId", "attempts", "commands", "replayArtifact",
              "evaluationIdentity", "validationPlan", "targetEnvironment",
              "sourceProgramArtifact", "targetProgramArtifact", "comparisonPolicy"}
    if set(value) != fields or value.get("schemaVersion") != "riscv2x86.evaluation-result.v1":
        raise ValueError("completed evaluation schema or fields are invalid")
    evaluation_id, request_id, candidate_id = (
        value.get("evaluationIdentity"), value.get("requestIdentity"), value.get("candidateManifestId"),
    )
    if not all(isinstance(item, str) and _SHA256.fullmatch(item) for item in
               (evaluation_id, request_id, candidate_id)):
        raise ValueError("completed evaluation identities are invalid")
    identity_payload = dict(value)
    identity_payload.pop("evaluationIdentity")
    identity_payload.pop("replayArtifact")
    if _digest(_canonical(identity_payload)) != evaluation_id:
        raise ValueError("completed evaluation identity does not match content")
    raw_attempts = value.get("attempts")
    if not isinstance(raw_attempts, list):
        raise ValueError("completed evaluation attempts are invalid")
    attempts = []
    seen = set()
    expected_attempt_fields = {"findingId", "fragmentId", "attemptArtifactId",
                               "translationOutcome", "status", "validation",
                               "translationArtifact", "reasonCodes", "replayArtifacts"}
    for raw in raw_attempts:
        if not isinstance(raw, Mapping) or set(raw) != expected_attempt_fields:
            raise ValueError("completed evaluation attempt is malformed")
        strings = (raw.get("findingId"), raw.get("fragmentId"), raw.get("attemptArtifactId"))
        if not all(isinstance(item, str) and item for item in strings):
            raise ValueError("completed evaluation attempt identity is incomplete")
        if strings[2] in seen or _SHA256.fullmatch(strings[2]) is None:
            raise ValueError("completed evaluation attempt identity is duplicate or invalid")
        seen.add(strings[2])
        validation_raw, translation_raw = raw.get("validation"), raw.get("translationArtifact")
        validation = None
        translation = None
        if validation_raw is not None:
            if not isinstance(validation_raw, Mapping):
                raise ValueError("completed evaluation validation evidence is malformed")
            validation = translation_validation_result_from_dict(validation_raw)
        if translation_raw is not None:
            if not isinstance(translation_raw, Mapping):
                raise ValueError("completed evaluation translation evidence is malformed")
            translation = translation_artifact_from_dict(translation_raw)
        attempts.append(EvaluatedAttempt(
            strings[0], strings[1], strings[2],
            TranslationOutcome(str(raw.get("translationOutcome"))),
            ValidationStatus(str(raw.get("status"))), validation, translation,
        ))
    typed_values = (value.get("validationPlan"), value.get("targetEnvironment"),
                    value.get("sourceProgramArtifact"), value.get("targetProgramArtifact"))
    if not all(isinstance(item, Mapping) for item in typed_values):
        raise ValueError("completed evaluation typed execution context is missing")
    comparison_policy = value.get("comparisonPolicy")
    if not isinstance(comparison_policy, str) or not comparison_policy:
        raise ValueError("completed evaluation comparison policy is missing")
    return CompletedEvaluation(
        evaluation_id, request_id, ValidationStatus(str(value.get("status"))),
        candidate_id, tuple(attempts),
        validation_plan_from_dict(typed_values[0]),
        target_environment_from_dict(typed_values[1]),
        program_artifact_from_dict(typed_values[2]),
        program_artifact_from_dict(typed_values[3]),
        comparison_policy, dict(value),
    )


def load_completed_evaluation(path: str | Path) -> CompletedEvaluation:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("completed evaluation root must be an object")
    return completed_evaluation_from_dict(value)


@dataclass(frozen=True)
class PromotionAdmission:
    allowed: bool
    reason_code: str


def _profile_reason(evaluation: CompletedEvaluation, attempt: EvaluatedAttempt) -> str:
    result, translation = attempt.validation, attempt.translation_artifact
    if result is None or translation is None:
        return "promotion.typed-validation-evidence-missing"
    if result.status is not ValidationStatus.VERIFIED or attempt.status is not ValidationStatus.VERIFIED:
        return "promotion.attempt-not-verified"
    rebuilt = rebuild_validation_result(
        status=result.status, plan=evaluation.validation_plan,
        layers=result.layer_results, reasons=result.reason_codes,
        translation_artifact=translation,
        source_program_artifact=evaluation.source_program,
        target_program_artifact=evaluation.target_program,
        target_environment=evaluation.target_environment.to_dict(),
        comparison_policy=evaluation.comparison_policy,
    )
    if rebuilt.validation_identity != result.validation_identity:
        return "promotion.validation-identity-binding-invalid"
    required = _PROFILE_LEVELS[result.profile]
    actual = tuple(item.level.value for item in result.layer_results)
    completed = tuple(item.value for item in result.completed_levels)
    if (actual != required or completed != required or result.reason_codes
            or any(item.status is not ValidationStatus.VERIFIED for item in result.layer_results)
            or any(_SHA256.fullmatch(item.evidence_identity) is None for item in result.layer_results)):
        return "promotion.validation-level-evidence-incomplete"
    if translation.fragment_id != attempt.fragment_id:
        return "promotion.translation-fragment-mismatch"
    minimum = {
        PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY: ValidationProfile.FUNCTIONAL,
        PreservationMode.ARCHITECTURE_EQUIVALENT: ValidationProfile.ARCHITECTURAL,
        PreservationMode.MICROARCHITECTURE_INTENT_PRESERVED: ValidationProfile.MICROARCH,
    }[translation.preservation_mode]
    order = tuple(ValidationProfile)
    if order.index(result.profile) < order.index(minimum):
        return "promotion.validation-profile-insufficient"
    if (translation.preservation_mode is PreservationMode.ARCHITECTURE_EQUIVALENT
            and translation.ignored_source_state):
        return "promotion.architecture-ignored-state-invalid"
    return ""


def admit_evaluation_promotion(
    evaluation: CompletedEvaluation,
    candidate_manifest: CandidateArtifactManifest,
) -> PromotionAdmission:
    if evaluation.status is not ValidationStatus.VERIFIED:
        return PromotionAdmission(False, "promotion.evaluation-not-verified")
    if evaluation.candidate_manifest_id != candidate_manifest.manifest_id:
        return PromotionAdmission(False, "promotion.candidate-manifest-mismatch")
    attempts = {item.attempt_artifact_id: item for item in evaluation.attempts}
    edits = {item.attempt_artifact_id: item for item in candidate_manifest.edits}
    if len(edits) != len(candidate_manifest.edits):
        return PromotionAdmission(False, "promotion.candidate-edit-coverage-invalid")
    emitted = {key for key, item in attempts.items() if item.translation_outcome in _EMITTED}
    if emitted != set(edits):
        return PromotionAdmission(False, "promotion.candidate-edit-coverage-invalid")
    for artifact_id in sorted(emitted):
        edit, attempt = edits[artifact_id], attempts[artifact_id]
        if not edit.binding_complete:
            return PromotionAdmission(False, "promotion.attempt-binding-incomplete")
        reason = _profile_reason(evaluation, attempt)
        if reason:
            return PromotionAdmission(False, reason)
    return PromotionAdmission(True, "")


def promote_evaluated_staging(
    *, evaluation_result: str | Path, candidate_manifest: str | Path,
    source_root: str | Path, staging_root: str | Path,
    translated_report: str | Path, attempt_archive: str | Path,
    final_output: str | Path,
) -> dict[str, object]:
    """Admit first, then atomically copy staging; never consume evidence."""
    evaluation = load_completed_evaluation(evaluation_result)
    manifest = load_candidate_artifact_manifest(candidate_manifest)
    verify_candidate_artifact_manifest(
        manifest, source_root=source_root, staging_root=staging_root,
        translated_report=translated_report, attempt_archive=attempt_archive,
    )
    admission = admit_evaluation_promotion(evaluation, manifest)
    final = Path(final_output).resolve()
    staging = Path(staging_root).resolve()
    source = Path(source_root).resolve()
    if final.exists():
        return _promotion_result(evaluation, manifest, False,
                                 "promotion.final-output-exists", "")
    for root in (source, staging):
        if final == root or root in final.parents or final in root.parents:
            return _promotion_result(evaluation, manifest, False,
                                     "promotion.output-tree-overlap", "")
    if not admission.allowed:
        return _promotion_result(evaluation, manifest, False, admission.reason_code, "")
    temporary = final.with_name(final.name + ".promotion-" + evaluation.evaluation_identity[7:19])
    if temporary.exists():
        return _promotion_result(evaluation, manifest, False,
                                 "promotion.temporary-output-exists", "")
    final.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(staging, temporary, symlinks=False)
        digest = candidate_tree_digest(temporary)
        if digest != manifest.target_tree_digest:
            raise ValueError("promoted tree digest mismatch")
        os.replace(temporary, final)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return _promotion_result(evaluation, manifest, True, "", manifest.target_tree_digest)


def _promotion_result(evaluation: CompletedEvaluation, manifest: CandidateArtifactManifest,
                      promoted: bool, reason: str, tree_digest: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": WRITEBACK_PROMOTION_SCHEMA,
        "promoted": promoted, "reasonCode": reason,
        "evaluationIdentity": evaluation.evaluation_identity,
        "candidateManifestId": manifest.manifest_id,
        "finalTreeDigest": tree_digest,
    }
    payload["promotionIdentity"] = _digest(_canonical(payload))
    return payload


def persist_promotion_result(value: Mapping[str, object], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)
