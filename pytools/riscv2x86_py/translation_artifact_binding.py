"""Fail-closed construction of validation artifacts from archived approvals."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from .translation_attempt import TranslationAttempt, TranslationAttemptArchive
from .translation_validation import TranslationArtifact
from .validation_status import PreservationMode


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"approval artifact lacks {name}")
    return value


def _identity(value: Mapping[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def translation_artifact_from_approval(
    attempt: TranslationAttempt, approval: Mapping[str, object],
) -> TranslationArtifact:
    """Construct an evaluation artifact from an approved candidate binding.

    Publication-only provenance remains guarded by ``attempt.binding_complete``
    in the writeback path.  This constructor deliberately accepts the smaller
    reproducible binding needed to measure L0/L1 candidates.
    """
    if not attempt.evaluation_binding_complete:
        missing = ", ".join(attempt.evaluation_binding_missing_fields)
        raise ValueError("attempt lacks evaluation binding: " + missing)
    bindings = {
        "sourceModelId": attempt.source_model_id,
        "planId": attempt.plan_id,
        "constraintsId": attempt.constraints_id,
        "rendererId": attempt.renderer_id,
        "rendererVersion": attempt.renderer_version,
    }
    for name, expected in bindings.items():
        if approval.get(name) != expected:
            raise ValueError(f"approval/attempt binding mismatch: {name}")
    # Optional publication bindings, when present on the attempt, must still
    # agree.  Their absence cannot silently weaken writeback because the
    # publication gate continues to require binding_complete.
    for name, expected in {
        "targetEnvironmentId": attempt.target_environment_id,
        "rendererContractId": attempt.renderer_contract_id,
    }.items():
        if expected and approval.get(name) != expected:
            raise ValueError(f"approval/attempt binding mismatch: {name}")
    if approval.get("proofStatus") != "approved":
        raise ValueError("approval proof status is not approved")
    fragment = approval.get("sourceFragmentId")
    if fragment != attempt.fragment_id:
        raise ValueError("approval/attempt fragment mismatch")
    preservation = approval.get("preservationMode")
    if not isinstance(preservation, str) or not preservation:
        preservation = ("functional_equivalence_only"
                        if attempt.translation_outcome.value == "functional_fallback"
                        else "architecture_equivalent")
    shell_identity = approval.get("shellFactsIdentity")
    if not isinstance(shell_identity, str) or not shell_identity:
        shell_identity = _identity({
            "schemaVersion": "riscv2x86.shell-facts-binding.v1",
            "sourceFragmentId": attempt.fragment_id,
            "sourceModelId": attempt.source_model_id,
            "constraintsId": attempt.constraints_id,
        })
    runtime_id = approval.get("runtimeContractId")
    runtime_version = approval.get("runtimeContractVersion")
    if not isinstance(runtime_id, str) or not runtime_id:
        runtime_id = approval.get("helperRuntimeContractId", "riscv2x86.runtime.none")
    if not isinstance(runtime_version, str) or not runtime_version:
        runtime_version = approval.get("helperSemanticVersion", "v1")
    ignored = approval.get("ignoredSourceState", [])
    if not isinstance(ignored, list) or not all(isinstance(x, str) and x for x in ignored):
        raise ValueError("approval ignoredSourceState is not an array of strings")
    if ignored != sorted(set(ignored)):
        raise ValueError("approval ignoredSourceState is not canonical")
    recipe_id = approval.get("recipeId") or attempt.renderer_contract_id
    if not isinstance(recipe_id, str) or not recipe_id:
        recipe_id = _identity({
            "schemaVersion": "riscv2x86.evaluation-recipe-binding.v1",
            "planId": attempt.plan_id,
            "rendererId": attempt.renderer_id,
            "rendererVersion": attempt.renderer_version,
            "candidateReplacementDigest": attempt.candidate_replacement_digest,
        })
    return TranslationArtifact(
        fragment_id=attempt.fragment_id,
        source_model_identity=attempt.source_model_id,
        translation_plan_id=attempt.plan_id,
        constraint_id=attempt.constraints_id,
        proof_identity=attempt.proof_binding_identity,
        preservation_mode=PreservationMode(preservation),
        shell_facts_identity=shell_identity,
        runtime_contract_id=_text(runtime_id, "runtimeContractId"),
        runtime_contract_version=_text(runtime_version, "runtimeContractVersion"),
        recipe_id=recipe_id,
        ignored_source_state=tuple(ignored),
        semantic_class=_text(approval.get("semanticClass", attempt.candidate_kind), "semanticClass"),
        target_route=_text(approval.get("targetRoute", attempt.candidate_route), "targetRoute"),
    )


def artifacts_from_report(
    report_path: str | Path, archive: TranslationAttemptArchive, *,
    finding_ids: set[str] | None = None,
) -> dict[str, TranslationArtifact]:
    """Join findings to attempts by their stable finding index/fragment identity."""
    raw = json.loads(Path(report_path).read_text(encoding="utf-8"))
    findings = raw.get("findings") if isinstance(raw, Mapping) else None
    if not isinstance(findings, list):
        raise ValueError("translated report findings are malformed")
    attempts = {item.finding_id: item for item in archive.attempts}
    result: dict[str, TranslationArtifact] = {}
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise ValueError("translated report finding is malformed")
        fragment = finding.get("fragment")
        fragment_id = fragment.get("id") if isinstance(fragment, Mapping) else ""
        finding_id = f"finding:{index}:{fragment_id}"
        attempt = attempts.get(finding_id)
        if attempt is None:
            raise ValueError("translated report and attempt archive do not form a total join")
        approval = finding.get("approvalArtifact")
        if attempt.evaluation_binding_complete and (finding_ids is None or finding_id in finding_ids):
            if not isinstance(approval, Mapping):
                raise ValueError("approved attempt has no approval artifact")
            result[finding_id] = translation_artifact_from_approval(attempt, approval)
    return result
