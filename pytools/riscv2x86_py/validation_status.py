"""Authoritative Phase-8 validation conclusions and writeback admission.

``build_only`` was a useful implementation detail while Phase 8 only had a
compiler gate.  It is not a semantic conclusion and must never authorize a
replacement.  The public conclusion set below is deliberately small and is
shared by the pipeline, manifests, and future differential runners.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:
    from .l0_artifact_manifest import L0ArtifactManifest
    from .translation_validation import (
        ProgramArtifact, TargetEnvironment, TranslationArtifact, TranslationValidationResult,
    )
    from .output_manifest import OutputManifest


VALIDATION_STATUS_VERSION = "riscv2x86.validation-status.v1"
WRITEBACK_VALIDATION_EVIDENCE_VERSION = (
    "riscv2x86.writeback-validation-evidence.v1"
)

_SHA256_IDENTITY = re.compile(r"sha256:[0-9a-f]{64}")
_PROFILE_LEVELS = {
    "build": ("L0",),
    "functional": ("L0", "L1"),
    "architectural": ("L0", "L1", "L2"),
    "microarch": ("L0", "L1", "L2", "L3"),
}


class ValidationStatus(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    NEEDS_ROUTE = "needs_route"
    UNSUPPORTED = "unsupported"
    KEEP = "keep"
    NOT_VERIFIED = "not_verified"


class PreservationMode(str, Enum):
    ARCHITECTURE_EQUIVALENT = "architecture_equivalent"
    FUNCTIONAL_EQUIVALENCE_ONLY = "functional_equivalence_only"
    MICROARCHITECTURE_INTENT_PRESERVED = "microarchitecture_intent_preserved"


@dataclass(frozen=True)
class WritebackAdmission:
    allowed: bool
    status: ValidationStatus
    reason_code: str = ""


def normalize_validation_status(value: str | ValidationStatus) -> ValidationStatus:
    """Normalize legacy checker output without treating it as a pass."""
    if isinstance(value, ValidationStatus):
        return value
    if value == "build_only":
        return ValidationStatus.INCONCLUSIVE
    try:
        return ValidationStatus(str(value))
    except ValueError:
        return ValidationStatus.INCONCLUSIVE


def preservation_mode_from_artifact(
    artifact: Mapping[str, object] | None,
) -> PreservationMode | None:
    if not artifact:
        return None
    value = artifact.get("preservationMode")
    if isinstance(value, PreservationMode):
        return value
    try:
        return PreservationMode(str(value))
    except ValueError:
        return None


def _sha256_identity(value: object) -> bool:
    return isinstance(value, str) and _SHA256_IDENTITY.fullmatch(value) is not None


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _runtime_identity(artifact: Mapping[str, object]) -> tuple[object, object]:
    contract = artifact.get("runtimeContractId", artifact.get("runtimeContract"))
    version = artifact.get("runtimeContractVersion", artifact.get("runtimeVersion"))
    return contract, version


def _required_profile(mode: PreservationMode) -> str:
    if mode is PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY:
        return "functional"
    if mode is PreservationMode.ARCHITECTURE_EQUIVALENT:
        return "architectural"
    return "microarch"


def _profile_satisfies(actual: object, required: str) -> bool:
    if not isinstance(actual, str) or actual not in _PROFILE_LEVELS:
        return False
    return len(_PROFILE_LEVELS[actual]) >= len(_PROFILE_LEVELS[required])


def _verified_levels(evidence: Mapping[str, object], required: str) -> bool:
    levels = evidence.get("levels")
    if not isinstance(levels, Mapping):
        return False
    for level in _PROFILE_LEVELS[required]:
        item = levels.get(level)
        if not isinstance(item, Mapping):
            return False
        if item.get("status") != ValidationStatus.VERIFIED.value:
            return False
        if not _sha256_identity(item.get("evidenceIdentity")):
            return False
    return True


def _artifact_binding_complete(evidence: Mapping[str, object]) -> bool:
    binding = evidence.get("artifactManifestBinding")
    if not isinstance(binding, Mapping):
        return False
    for name in ("translationManifestDigest", "sourceArtifactDigest",
                 "targetArtifactDigest"):
        if not _sha256_identity(evidence.get(name)):
            return False
        if binding.get(name) != evidence.get(name):
            return False
    return True


def _observation_binding_complete(evidence: Mapping[str, object]) -> bool:
    binding = evidence.get("observationBinding")
    if not isinstance(binding, Mapping):
        return False
    return (
        _sha256_identity(binding.get("sourceObservationIdentity"))
        and _sha256_identity(binding.get("targetObservationIdentity"))
        and binding.get("translationManifestDigest")
            == evidence.get("translationManifestDigest")
        and binding.get("sourceArtifactDigest")
            == evidence.get("sourceArtifactDigest")
        and binding.get("targetArtifactDigest")
            == evidence.get("targetArtifactDigest")
    )


def _validation_evidence_reason(
    artifact: Mapping[str, object], mode: PreservationMode,
) -> str:
    evidence = artifact.get("validationEvidence")
    if not isinstance(evidence, Mapping):
        return "validation.writeback-evidence-missing"
    if evidence.get("schemaVersion") != WRITEBACK_VALIDATION_EVIDENCE_VERSION:
        return "validation.writeback-evidence-version-mismatch"
    if evidence.get("validationStatus") != ValidationStatus.VERIFIED.value:
        return "validation.writeback-evidence-not-verified"
    if not _sha256_identity(evidence.get("validationIdentity")):
        return "validation.writeback-identity-missing"
    for name in (
        "validationIdentity", "validationProfile", "validationStatus",
        "translationManifestDigest", "sourceArtifactDigest",
        "targetArtifactDigest",
    ):
        if artifact.get(name) != evidence.get(name):
            return "validation.writeback-manifest-evidence-mismatch"

    required_profile = _required_profile(mode)
    if not _profile_satisfies(evidence.get("validationProfile"), required_profile):
        return "validation.writeback-profile-insufficient"
    if not _verified_levels(evidence, required_profile):
        return "validation.writeback-level-evidence-incomplete"

    proof_status = artifact.get("proofStatus")
    expected_proof_status = (
        "functional_approved"
        if mode is PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY
        else "approved"
    )
    if proof_status != expected_proof_status:
        return "validation.writeback-proof-status-invalid"
    if evidence.get("proofStatus") != proof_status:
        return "validation.writeback-proof-status-invalid"
    if (not _nonempty_text(artifact.get("proofIdentity"))
            or evidence.get("proofIdentity") != artifact.get("proofIdentity")):
        return "validation.writeback-proof-identity-mismatch"

    shell_facts_identity = evidence.get("shellFactsIdentity")
    if (artifact.get("shellSemanticsPreserved") is not True
            or evidence.get("shellSemanticsPreserved") is not True
            or not _nonempty_text(shell_facts_identity)
            or artifact.get("shellFactsIdentity") != shell_facts_identity):
        return "validation.writeback-shell-evidence-incomplete"
    if not _artifact_binding_complete(evidence):
        return "validation.writeback-artifact-binding-incomplete"
    if not _observation_binding_complete(evidence):
        return "validation.writeback-observation-binding-incomplete"

    artifact_contract, artifact_version = _runtime_identity(artifact)
    if (not _nonempty_text(artifact_contract)
            or not _nonempty_text(artifact_version)
            or evidence.get("runtimeContractId") != artifact_contract
            or evidence.get("runtimeContractVersion") != artifact_version):
        return "validation.writeback-runtime-contract-mismatch"

    ignored = artifact.get("ignoredSourceState")
    if not isinstance(ignored, (list, tuple)):
        return "validation.writeback-ignored-state-invalid"
    evidence_ignored = evidence.get("ignoredSourceState")
    if not isinstance(evidence_ignored, (list, tuple)):
        return "validation.writeback-ignored-state-invalid"
    if list(evidence_ignored) != list(ignored):
        return "validation.writeback-ignored-state-mismatch"
    if evidence.get("ignoredStateEscapes") is not False:
        return "validation.writeback-ignored-state-escape-unproven"

    if mode is PreservationMode.ARCHITECTURE_EQUIVALENT:
        if ignored:
            return "validation.architecture-ignored-state-not-empty"
        if artifact.get("architectureSemanticsPreserved") is not True:
            return "validation.architecture-claim-incomplete"
    elif mode is PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY:
        if not (
            artifact.get("functionalFallbackEnabled") is True
            and artifact.get("architectureSemanticsPreserved") is False
            and artifact.get("microarchitectureSemanticsPreserved") is False
        ):
            return "validation.functional-manifest-incomplete"
    else:
        contract_id = artifact.get("microarchitectureExperimentContractId")
        if not (
            artifact.get("architectureSemanticsPreserved") is True
            and artifact.get("microarchitectureSemanticsPreserved") is True
            and _nonempty_text(contract_id)
            and evidence.get("microarchitectureExperimentContractId")
                == contract_id
        ):
            return "validation.microarch-evidence-incomplete"
    return ""


def _typed_writeback_binding_reason(
    result: "TranslationValidationResult",
    manifest: "L0ArtifactManifest",
    manifest_digest: str,
    translation: "TranslationArtifact",
    source: "ProgramArtifact",
    target: "ProgramArtifact",
    artifact: Mapping[str, object],
) -> str:
    """Prove that the gate inputs form one validation transaction."""
    from .translation_validation import ValidationProfile

    evidence = artifact.get("validationEvidence")
    if not isinstance(evidence, Mapping):
        return "validation.writeback-evidence-missing"
    if not _sha256_identity(result.validation_identity):
        return "validation.writeback-result-identity-invalid"
    if (
        evidence.get("validationIdentity") != result.validation_identity
        or evidence.get("validationStatus") != result.status.value
        or evidence.get("validationProfile") != result.profile.value
    ):
        return "validation.writeback-result-evidence-mismatch"

    profile_levels = {
        ValidationProfile.BUILD: ("L0",),
        ValidationProfile.FUNCTIONAL: ("L0", "L1"),
        ValidationProfile.ARCHITECTURAL: ("L0", "L1", "L2"),
        ValidationProfile.MICROARCH: ("L0", "L1", "L2", "L3"),
    }
    required = profile_levels.get(result.profile)
    actual_levels = tuple(item.level.value for item in result.layer_results)
    completed = tuple(item.value for item in result.completed_levels)
    if (
        required is None
        or actual_levels != required
        or completed != required
        or result.reason_codes
        or any(item.status is not ValidationStatus.VERIFIED for item in result.layer_results)
        or any(not _sha256_identity(item.evidence_identity) for item in result.layer_results)
    ):
        return "validation.writeback-result-levels-invalid"
    evidence_levels = evidence.get("levels")
    if not isinstance(evidence_levels, Mapping) or set(evidence_levels) != set(required):
        return "validation.writeback-result-evidence-mismatch"
    for item in result.layer_results:
        recorded = evidence_levels.get(item.level.value)
        if not isinstance(recorded, Mapping) or (
            recorded.get("status") != item.status.value
            or recorded.get("evidenceIdentity") != item.evidence_identity
        ):
            return "validation.writeback-result-evidence-mismatch"

    if not _sha256_identity(manifest_digest):
        return "validation.writeback-manifest-digest-invalid"
    if evidence.get("translationManifestDigest") != manifest_digest:
        return "validation.writeback-manifest-object-mismatch"
    baseline = manifest.targets.get("gcc-O0-none")
    if baseline is None:
        return "validation.writeback-manifest-target-missing"
    if (
        manifest.translation_identity != translation.identity
        or manifest.plan_identity != translation.translation_plan_id
        or manifest.proof_identity != translation.proof_identity
        or manifest.runtime_contract_id != translation.runtime_contract_id
        or manifest.runtime_contract_version != translation.runtime_contract_version
        or manifest.recipe_identity != translation.recipe_id
        or manifest.source.artifact_digest != source.artifact_digest
        or manifest.source.artifact_kind != source.artifact_kind
        or baseline.artifact_digest != target.artifact_digest
        or baseline.artifact_kind != target.artifact_kind
    ):
        return "validation.writeback-typed-manifest-binding-mismatch"
    if (
        evidence.get("sourceArtifactDigest") != source.artifact_digest
        or evidence.get("targetArtifactDigest") != target.artifact_digest
        or preservation_mode_from_artifact(artifact) is not translation.preservation_mode
        or artifact.get("proofIdentity") != translation.proof_identity
        or artifact.get("shellFactsIdentity") != translation.shell_facts_identity
        or _runtime_identity(artifact) != (
            translation.runtime_contract_id, translation.runtime_contract_version,
        )
        or tuple(artifact.get("ignoredSourceState", ()))
            != translation.ignored_source_state
    ):
        return "validation.writeback-typed-artifact-binding-mismatch"
    return ""


def _output_manifest_reason(
    output: "OutputManifest", result: "TranslationValidationResult",
    translation: "TranslationArtifact", source: "ProgramArtifact", target: "ProgramArtifact",
    environment: "TargetEnvironment", artifact_manifest_digest: str,
    artifact: Mapping[str, object],
) -> str:
    """Validate the final v3 declaration independently of mutable approval fields."""
    from .output_manifest import OUTPUT_MANIFEST_SCHEMA, is_sha256_identity

    if output.schema_version != OUTPUT_MANIFEST_SCHEMA or not output.complete:
        return "validation.output-manifest-incomplete"
    if output.validation_status is not ValidationStatus.VERIFIED or output.validation_status is not result.status:
        return "validation.output-manifest-status-mismatch"
    if (not is_sha256_identity(output.validation_identity)
            or output.validation_identity != result.validation_identity
            or output.validation_profile != result.profile.value):
        return "validation.output-manifest-validation-binding-mismatch"
    expected_levels = tuple(item.level.value for item in result.layer_results)
    if output.validation_levels != expected_levels:
        return "validation.output-manifest-level-binding-mismatch"
    if (output.translation_id != translation.identity or output.fragment_id != translation.fragment_id
            or output.preservation_mode is not translation.preservation_mode):
        return "validation.output-manifest-translation-binding-mismatch"
    if (not is_sha256_identity(output.proof_identity) or output.proof_identity != translation.proof_identity):
        return "validation.output-manifest-proof-binding-mismatch"
    if (not is_sha256_identity(output.shell_facts_identity)
            or output.shell_facts_identity != translation.shell_facts_identity
            or not output.shell_semantics_preserved):
        return "validation.output-manifest-shell-facts-incomplete"
    expected_runtime = (
        translation.runtime_contract_id + "@" + translation.runtime_contract_version,
    )
    if (not translation.runtime_contract_id or not translation.runtime_contract_version
            or output.runtime_contracts != expected_runtime
            or output.runtime_registry_version != artifact.get("validationEvidence", {}).get("runtimeRegistryVersion")):
        return "validation.output-manifest-runtime-version-mismatch"
    required_environment = output.required_environment
    if (required_environment.source_profile != environment.source_isa + "-user"
            or required_environment.target_mode != environment.target_isa + "-user"
            or required_environment.environment_id != environment.environment_id
            or required_environment.runtime_identity != environment.runtime_identity
            or required_environment.loader_identity != environment.loader_identity):
        return "validation.output-manifest-environment-mismatch"
    if (output.artifact_manifest_digest != artifact_manifest_digest
            or output.source_artifact_digest != source.artifact_digest
            or output.target_artifact_digest != target.artifact_digest):
        return "validation.output-manifest-artifact-binding-mismatch"
    if output.ignored_source_state != translation.ignored_source_state or output.ignored_state_escapes:
        return "validation.output-manifest-ignored-state-invalid"

    required_profile = _required_profile(output.preservation_mode)
    if not _profile_satisfies(output.validation_profile, required_profile):
        return "validation.output-manifest-profile-insufficient"
    if output.preservation_mode is PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY:
        if (output.architecture_semantics_preserved or output.microarchitecture_semantics_preserved
                or output.microarchitecture_preservation != "not_preserved"
                or not output.ignored_source_state):
            return "validation.output-manifest-functional-claim-invalid"
    elif output.preservation_mode is PreservationMode.ARCHITECTURE_EQUIVALENT:
        if not output.architecture_semantics_preserved or output.ignored_source_state:
            return "validation.output-manifest-architecture-claim-invalid"
    else:
        if (not output.architecture_semantics_preserved
                or not output.microarchitecture_semantics_preserved
                or output.microarchitecture_preservation not in {"intent_preserved", "strengthened"}):
            return "validation.output-manifest-microarchitecture-claim-invalid"

    if output.microarchitecture_semantics_preserved != (
            output.microarchitecture_preservation in {"intent_preserved", "strengthened"}):
        return "validation.output-manifest-microarchitecture-claim-invalid"

    if output.l3_required:
        levels = {item.level.value: item for item in result.layer_results}
        l3 = levels.get("L3")
        if (not output.experiment_contract_id or output.validation_profile != "microarch"
                or l3 is None or l3.status is not ValidationStatus.VERIFIED
                or not _sha256_identity(l3.evidence_identity)
                or artifact.get("validationEvidence", {}).get("microarchitectureExperimentContractId")
                    != output.experiment_contract_id):
            return "validation.output-manifest-l3-contract-missing"
    elif output.experiment_contract_id and output.validation_profile != "microarch":
        return "validation.output-manifest-experiment-profile-mismatch"
    return ""


def admit_writeback(
    validation_result: "TranslationValidationResult",
    artifact_manifest: "L0ArtifactManifest",
    *,
    manifest_digest: str,
    translation_artifact: "TranslationArtifact",
    source_program_artifact: "ProgramArtifact",
    target_program_artifact: "ProgramArtifact",
    target_environment: "TargetEnvironment",
    output_manifest: "OutputManifest",
    approval_artifact: Mapping[str, object] | None = None,
) -> WritebackAdmission:
    """Authorize only one complete, typed and manifest-bound transaction."""
    from .l0_artifact_manifest import L0ArtifactManifest
    from .translation_validation import (
        ProgramArtifact, TargetEnvironment, TranslationArtifact, TranslationValidationResult,
    )
    from .output_manifest import OutputManifest

    if not (
        isinstance(validation_result, TranslationValidationResult)
        and isinstance(artifact_manifest, L0ArtifactManifest)
        and isinstance(translation_artifact, TranslationArtifact)
        and isinstance(source_program_artifact, ProgramArtifact)
        and isinstance(target_program_artifact, ProgramArtifact)
        and isinstance(target_environment, TargetEnvironment)
        and isinstance(output_manifest, OutputManifest)
    ):
        return WritebackAdmission(
            False, ValidationStatus.FAILED,
            "validation.writeback-typed-input-invalid",
        )
    normalized = validation_result.status
    if normalized is not ValidationStatus.VERIFIED:
        return WritebackAdmission(False, normalized, "validation.writeback-not-verified")

    artifact = approval_artifact or {}
    mode = preservation_mode_from_artifact(artifact)
    if mode is None:
        return WritebackAdmission(
            False, normalized, "validation.writeback-preservation-mode-missing",
        )
    reason = _typed_writeback_binding_reason(
        validation_result, artifact_manifest, manifest_digest,
        translation_artifact, source_program_artifact,
        target_program_artifact, artifact,
    )
    if reason:
        return WritebackAdmission(False, normalized, reason)
    reason = _validation_evidence_reason(artifact, mode)
    if reason:
        return WritebackAdmission(False, normalized, reason)
    reason = _output_manifest_reason(
        output_manifest, validation_result, translation_artifact,
        source_program_artifact, target_program_artifact, target_environment,
        manifest_digest, artifact,
    )
    if reason:
        return WritebackAdmission(False, normalized, reason)
    return WritebackAdmission(True, normalized)
