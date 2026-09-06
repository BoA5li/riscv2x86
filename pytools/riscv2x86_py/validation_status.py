"""Authoritative Phase-8 validation conclusions and writeback admission.

``build_only`` was a useful implementation detail while Phase 8 only had a
compiler gate.  It is not a semantic conclusion and must never authorize a
replacement.  The public conclusion set below is deliberately small and is
shared by the pipeline, manifests, and future differential runners.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


VALIDATION_STATUS_VERSION = "riscv2x86.validation-status.v1"


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
    try:
        return PreservationMode(str(value))
    except ValueError:
        return None


def _functional_manifest_complete(artifact: Mapping[str, object]) -> bool:
    ignored = artifact.get("ignoredSourceState")
    return (
        artifact.get("proofStatus") == "functional_approved"
        and artifact.get("functionalFallbackEnabled") is True
        and artifact.get("architectureSemanticsPreserved") is False
        and artifact.get("microarchitectureSemanticsPreserved") is False
        and isinstance(ignored, (list, tuple))
    )


def _microarchitecture_evidence_complete(artifact: Mapping[str, object]) -> bool:
    levels = artifact.get("validationLevels")
    return (
        artifact.get("microarchitectureSemanticsPreserved") is True
        and isinstance(levels, (list, tuple))
        and {"L0", "L1", "L2", "L3"}.issubset(set(map(str, levels)))
        and bool(artifact.get("microarchitectureExperimentContractId"))
    )


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
    if mode is PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY:
        if not _functional_manifest_complete(artifact):
            return WritebackAdmission(False, normalized, "validation.functional-manifest-incomplete")
    elif mode is PreservationMode.MICROARCHITECTURE_INTENT_PRESERVED:
        if not _microarchitecture_evidence_complete(artifact):
            return WritebackAdmission(False, normalized, "validation.microarch-evidence-incomplete")
    return WritebackAdmission(True, normalized)
