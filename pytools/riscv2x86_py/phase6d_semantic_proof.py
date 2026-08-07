"""Phase 6D plan-specific semantic proof gate.

This module deliberately consumes only Phase-6 boundary DTOs.  It never
rescans assembly, p-code, CFG artifacts, lifted instructions, or renderer
output.  A successful constraint derivation is not proof success.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from .phase6c_constraints import TargetConstraintModel, TargetEnvironment
from .plan_types import PlanRequirement, TargetLoweringKind, TargetLoweringPlan
from .semantic_types import PreservationLevel
from .source_model import SourceSemanticModel


class SemanticProofReasonCode(str, Enum):
    INVALID_SOURCE_MODEL = "phase6d.invalid_source_model"
    INVALID_CANDIDATE_PLAN = "phase6d.invalid_candidate_plan"
    INVALID_CONSTRAINTS = "phase6d.invalid_constraints"
    INVALID_TARGET_ENVIRONMENT = "phase6d.invalid_target_environment"
    PLAN_CONSTRAINT_MISMATCH = "phase6d.plan_constraint_mismatch"
    CONSTRAINT_ENVIRONMENT_MISMATCH = "phase6d.constraint_environment_mismatch"
    TARGET_FEATURE_MISSING = "phase6d.target_feature_missing"
    SOURCE_INCOMPLETE = "phase6d.source_incomplete"
    SHELL_SEMANTICS_UNPRESERVED = "phase6d.shell_semantics_unpreserved"
    MEMORY_SEMANTICS_UNPRESERVED = "phase6d.memory_semantics_unpreserved"
    ATOMIC_ORDERING_UNPRESERVED = "phase6d.atomic_ordering_unpreserved"
    BARRIER_SEMANTICS_UNPRESERVED = "phase6d.barrier_semantics_unpreserved"
    CONTROL_FLOW_UNPRESERVED = "phase6d.control_flow_unpreserved"
    ABI_SEMANTICS_UNPRESERVED = "phase6d.abi_semantics_unpreserved"
    MICROARCH_INTENT_UNPRESERVED = "phase6d.microarch_intent_unpreserved"
    PLAN_CONTRACT_MISSING = "phase6d.plan_contract_missing"
    PLAN_KIND_UNSUPPORTED = "phase6d.plan_kind_unsupported"
    INTERNAL_INVARIANT_VIOLATION = "phase6d.internal_invariant_violation"


class PreservationConclusion(str, Enum):
    ARCHITECTURE_EQUIVALENT = "architecture_equivalent"
    SHELL_PRESERVED = "shell_preserved"
    MICROARCH_INTENT_PRESERVED = "microarchitecture_intent_preserved"
    MICROARCH_STRENGTHENED = "microarchitecture_strengthened"
    BEST_EFFORT = "best_effort"
    NOT_PRESERVED = "not_preserved"


@dataclass(frozen=True)
class SemanticProofResult:
    """Independent Phase-6D result; it does not mutate its inputs."""
    approved: bool
    plan_id: str | None
    conclusions: tuple[PreservationConclusion, ...] = ()
    reason_codes: tuple[SemanticProofReasonCode, ...] = ()
    details: Mapping[str, str | int | bool | None] = MappingProxyType({})

    def __post_init__(self) -> None:
        if not isinstance(self.approved, bool):
            raise TypeError("approved must be bool")
        conclusions = tuple(self.conclusions)
        reasons = tuple(self.reason_codes)
        if any(not isinstance(item, PreservationConclusion) for item in conclusions):
            raise TypeError("conclusions must contain PreservationConclusion")
        if any(not isinstance(item, SemanticProofReasonCode) for item in reasons):
            raise TypeError("reason_codes must contain SemanticProofReasonCode")
        if self.approved:
            if reasons or PreservationConclusion.NOT_PRESERVED in conclusions:
                raise ValueError("approved proof cannot contain failure conclusions")
        elif not reasons:
            raise ValueError("failed proof requires a stable reason code")
        object.__setattr__(self, "conclusions", tuple(sorted(set(conclusions), key=lambda x: x.value)))
        object.__setattr__(self, "reason_codes", tuple(sorted(set(reasons), key=lambda x: x.value)))
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    @classmethod
    def passed(cls, plan_id: str, conclusions: tuple[PreservationConclusion, ...]) -> "SemanticProofResult":
        return cls(True, plan_id, conclusions)

    @classmethod
    def failed(cls, plan_id: str | None, reason: SemanticProofReasonCode, details=None) -> "SemanticProofResult":
        return cls(False, plan_id, (PreservationConclusion.NOT_PRESERVED,), (reason,), {} if details is None else details)


@dataclass(frozen=True)
class ApprovedTargetLoweringPlan:
    """Only this wrapper may cross from Phase 6D to Phase 6E/6F."""
    plan: TargetLoweringPlan
    constraints: TargetConstraintModel
    proof: SemanticProofResult

    def __post_init__(self) -> None:
        if not self.proof.approved or self.proof.plan_id != self.plan.plan_id:
            raise ValueError("ApprovedTargetLoweringPlan requires a matching approved proof")
        if self.constraints.plan_id != self.plan.plan_id:
            raise ValueError("constraints must belong to plan")


def _fail(plan_id, code, details=None):
    return SemanticProofResult.failed(plan_id, code, details)


def _common_gate(source_model, candidate_plan, constraints, target_environment):
    if not isinstance(source_model, SourceSemanticModel):
        return _fail(None, SemanticProofReasonCode.INVALID_SOURCE_MODEL)
    if not isinstance(candidate_plan, TargetLoweringPlan):
        return _fail(None, SemanticProofReasonCode.INVALID_CANDIDATE_PLAN)
    if not isinstance(constraints, TargetConstraintModel):
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.INVALID_CONSTRAINTS)
    if not isinstance(target_environment, TargetEnvironment):
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.INVALID_TARGET_ENVIRONMENT)
    if constraints.plan_id != candidate_plan.plan_id:
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.PLAN_CONSTRAINT_MISMATCH)
    if constraints.environment != target_environment:
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.CONSTRAINT_ENVIRONMENT_MISMATCH)
    if not candidate_plan.supports_features(target_environment.available_features):
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.TARGET_FEATURE_MISSING)
    if not source_model.operation.complete or not source_model.operands.complete:
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.SOURCE_INCOMPLETE)
    if (source_model.microarch.explicitly_microarch_sensitive
            and not candidate_plan.requires(PlanRequirement.PRESERVE_MICROARCH_INTENT)):
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.MICROARCH_INTENT_UNPRESERVED)
    return None


def _prove_c_expression(source, plan, constraints):
    if constraints.c_expression_constraint is None:
        return _fail(plan.plan_id, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if not constraints.memory_constraint.is_no_memory_effect() or not constraints.control_flow_constraint.is_simple_fallthrough():
        return _fail(plan.plan_id, SemanticProofReasonCode.MEMORY_SEMANTICS_UNPRESERVED)
    if source.shell.requires_shell_aware_lowering or source.atomic.present or source.barrier.present:
        return _fail(plan.plan_id, SemanticProofReasonCode.SHELL_SEMANTICS_UNPRESERVED)
    return SemanticProofResult.passed(plan.plan_id, (PreservationConclusion.ARCHITECTURE_EQUIVALENT,))


def _prove_builtin(source, plan, constraints):
    if constraints.c_builtin_constraint is None:
        return _fail(plan.plan_id, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if source.atomic.present and not constraints.memory_constraint.requires_atomic_ordering:
        return _fail(plan.plan_id, SemanticProofReasonCode.ATOMIC_ORDERING_UNPRESERVED)
    if source.barrier.present and not (constraints.memory_constraint.requires_compiler_barrier or constraints.memory_constraint.requires_hardware_barrier):
        return _fail(plan.plan_id, SemanticProofReasonCode.BARRIER_SEMANTICS_UNPRESERVED)
    return SemanticProofResult.passed(plan.plan_id, (PreservationConclusion.ARCHITECTURE_EQUIVALENT, PreservationConclusion.SHELL_PRESERVED))


def _prove_x86_asm(source, plan, constraints):
    if constraints.x86_gnu_inline_asm_contract is None and constraints.x86_memory_inline_asm_contract is None:
        return _fail(plan.plan_id, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if source.atomic.present or source.barrier.present or source.operation.has_control_flow:
        return _fail(plan.plan_id, SemanticProofReasonCode.PLAN_KIND_UNSUPPORTED)
    if source.shell.has_cc_clobber and not constraints.preserve_cc_clobber:
        return _fail(plan.plan_id, SemanticProofReasonCode.SHELL_SEMANTICS_UNPRESERVED)
    if source.shell.is_volatile and not constraints.preserve_volatile:
        return _fail(plan.plan_id, SemanticProofReasonCode.SHELL_SEMANTICS_UNPRESERVED)
    if source.shell.has_memory_clobber and not constraints.memory_constraint.requires_memory_clobber:
        return _fail(plan.plan_id, SemanticProofReasonCode.MEMORY_SEMANTICS_UNPRESERVED)
    return SemanticProofResult.passed(plan.plan_id, (PreservationConclusion.ARCHITECTURE_EQUIVALENT, PreservationConclusion.SHELL_PRESERVED))


def _prove_atomic_or_barrier(source, plan, constraints):
    if plan.kind is TargetLoweringKind.X86_ATOMIC:
        if constraints.x86_atomic_contract is None or not constraints.memory_constraint.requires_atomic_ordering:
            return _fail(plan.plan_id, SemanticProofReasonCode.ATOMIC_ORDERING_UNPRESERVED)
        if constraints.memory_constraint.atomic_success_ordering != source.atomic.success_ordering or constraints.memory_constraint.atomic_failure_ordering != source.atomic.failure_ordering:
            return _fail(plan.plan_id, SemanticProofReasonCode.ATOMIC_ORDERING_UNPRESERVED)
    else:
        if constraints.x86_barrier_contract is None:
            return _fail(plan.plan_id, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        if source.barrier.compiler_barrier and not constraints.memory_constraint.requires_compiler_barrier:
            return _fail(plan.plan_id, SemanticProofReasonCode.BARRIER_SEMANTICS_UNPRESERVED)
        if source.barrier.hardware_memory_barrier and not constraints.memory_constraint.requires_hardware_barrier:
            return _fail(plan.plan_id, SemanticProofReasonCode.BARRIER_SEMANTICS_UNPRESERVED)
        contract = constraints.x86_barrier_contract
        if (contract.ordering != source.barrier.ordering
                or contract.scope != source.barrier.scope):
            return _fail(plan.plan_id, SemanticProofReasonCode.BARRIER_SEMANTICS_UNPRESERVED)
    return SemanticProofResult.passed(plan.plan_id, (PreservationConclusion.ARCHITECTURE_EQUIVALENT, PreservationConclusion.SHELL_PRESERVED))


def _prove_control_or_helper(source, plan, constraints):
    if plan.kind is TargetLoweringKind.STRUCTURED_CONTROL_FLOW:
        if constraints.structured_control_flow_contract is None or not constraints.control_flow_constraint.preserve_control_flow:
            return _fail(plan.plan_id, SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    else:
        if constraints.helper_abi_contract is None or not constraints.control_flow_constraint.requires_helper_abi_contract:
            return _fail(plan.plan_id, SemanticProofReasonCode.ABI_SEMANTICS_UNPRESERVED)
    return SemanticProofResult.passed(plan.plan_id, (PreservationConclusion.ARCHITECTURE_EQUIVALENT, PreservationConclusion.SHELL_PRESERVED))


def run_semantic_proof_gate(*, source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, constraints: TargetConstraintModel, target_environment: TargetEnvironment) -> SemanticProofResult:
    """Prove one concrete plan/constraint pair, or reject it fail-closed."""
    common = _common_gate(source_model, candidate_plan, constraints, target_environment)
    if common is not None:
        return common
    try:
        dispatch = {
            TargetLoweringKind.C_EXPRESSION: _prove_c_expression,
            TargetLoweringKind.C_BUILTIN: _prove_builtin,
            TargetLoweringKind.X86_GNU_INLINE_ASM: _prove_x86_asm,
            TargetLoweringKind.X86_ATOMIC: _prove_atomic_or_barrier,
            TargetLoweringKind.X86_BARRIER: _prove_atomic_or_barrier,
            TargetLoweringKind.STRUCTURED_CONTROL_FLOW: _prove_control_or_helper,
            TargetLoweringKind.HELPER_CALL: _prove_control_or_helper,
        }
        proof = dispatch.get(candidate_plan.kind)
        if proof is None:
            return _fail(candidate_plan.plan_id, SemanticProofReasonCode.PLAN_KIND_UNSUPPORTED)
        return proof(source_model, candidate_plan, constraints)
    except (AttributeError, TypeError, ValueError):
        return _fail(candidate_plan.plan_id, SemanticProofReasonCode.INTERNAL_INVARIANT_VIOLATION)
