"""Canonical L2 dimension and outcome vocabulary.

These enums are the only public spelling authority shared by L2 planning,
runtime registration, evidence attribution, and paper aggregation.  Parsing is
deliberately strict: legacy aliases are accepted only by the explicit
requirement-manifest migration in :mod:`l2_eligibility`.
"""
from __future__ import annotations

from enum import Enum
from typing import Iterable


class L2Dimension(str, Enum):
    LOGICAL_OPERANDS = "logical_operands"
    MEMORY_EFFECTS = "memory_effects"
    CONTROL_FLOW = "control_flow"
    SHELL_SEMANTICS = "shell_semantics"
    TRAP_SEMANTICS = "trap_semantics"
    PRIVILEGED_STATE = "privileged_state"
    ATOMIC_MEMORY_ORDER = "atomic_memory_order"


class L2EligibilityStatus(str, Enum):
    ELIGIBLE = "eligible"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"


class L2DimensionStatus(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    NOT_RUN = "not_run"
    NOT_APPLICABLE = "not_applicable"


class L2ClaimScope(str, Enum):
    ARCHITECTURAL = "architectural"
    APPROVED_FUNCTIONAL_RELATION = "approved_functional_relation"
    DIAGNOSTIC_ONLY = "diagnostic_only"
    NONE = "none"


class L2ClaimConclusion(str, Enum):
    """Typed public conclusion; status alone is never a claim boundary."""
    ARCHITECTURAL_VERIFIED = "l2_architectural_verified"
    APPROVED_FUNCTIONAL_RELATION_VERIFIED = "l2_approved_functional_relation_verified"
    DIAGNOSTIC_PASSED = "l2_diagnostic_passed"
    ARCHITECTURAL_FAILED = "l2_architectural_failed"
    INCONCLUSIVE = "l2_inconclusive"
    NOT_RUN = "l2_not_run"
    NOT_APPLICABLE = "l2_not_applicable"


def l2_claim_conclusion(
    status: L2DimensionStatus, scope: L2ClaimScope,
) -> L2ClaimConclusion:
    if status is L2DimensionStatus.VERIFIED:
        return {
            L2ClaimScope.ARCHITECTURAL: L2ClaimConclusion.ARCHITECTURAL_VERIFIED,
            L2ClaimScope.APPROVED_FUNCTIONAL_RELATION:
                L2ClaimConclusion.APPROVED_FUNCTIONAL_RELATION_VERIFIED,
            L2ClaimScope.DIAGNOSTIC_ONLY: L2ClaimConclusion.DIAGNOSTIC_PASSED,
        }[scope]
    if status is L2DimensionStatus.FAILED:
        return L2ClaimConclusion.ARCHITECTURAL_FAILED
    if status is L2DimensionStatus.NOT_RUN:
        return L2ClaimConclusion.NOT_RUN
    if status is L2DimensionStatus.NOT_APPLICABLE:
        return L2ClaimConclusion.NOT_APPLICABLE
    return L2ClaimConclusion.INCONCLUSIVE


def parse_l2_dimension(value: str) -> L2Dimension:
    """Parse one canonical dimension without trimming or alias conversion."""
    if not isinstance(value, str):
        raise ValueError("L2 dimension must be a string")
    try:
        return L2Dimension(value)
    except ValueError as exc:
        raise ValueError(f"unsupported L2 dimension: {value!r}") from exc


def parse_l2_dimensions(values: Iterable[str]) -> tuple[L2Dimension, ...]:
    parsed = tuple(parse_l2_dimension(value) for value in values)
    canonical = tuple(sorted(set(parsed), key=lambda item: item.value))
    if parsed != canonical:
        raise ValueError("L2 dimensions must be unique and canonically ordered")
    return parsed


CANONICAL_L2_DIMENSION_VALUES = frozenset(item.value for item in L2Dimension)
