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
from typing import Mapping


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


def admit_writeback(
    status: str | ValidationStatus,
    *,
    approval_artifact: Mapping[str, object] | None = None,
) -> WritebackAdmission:
    """Return the only policy decision that may authorize a replacement.

    Unclassified legacy strict recipes remain eligible only after an actual
    ``verified`` result.  New functional and microarchitecture claims have
    stronger, explicit manifest requirements.
    """
    normalized = normalize_validation_status(status)
    if normalized is not ValidationStatus.VERIFIED:
        return WritebackAdmission(False, normalized, "validation.writeback-not-verified")

    artifact = approval_artifact or {}
    mode = preservation_mode_from_artifact(artifact)
    if mode is None:
        return WritebackAdmission(
            False, normalized, "validation.writeback-preservation-mode-missing",
        )
    reason = _validation_evidence_reason(artifact, mode)
    if reason:
        return WritebackAdmission(False, normalized, reason)
    return WritebackAdmission(True, normalized)
