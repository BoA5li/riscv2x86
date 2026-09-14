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
