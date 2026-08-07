"""Phase 6C-3 structured compiler-builtin contracts (fail closed)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import SourceAtomicKind, SourceSemanticModel

if TYPE_CHECKING:
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetEnvironment


class CBuiltinKind(str, Enum):
    ATOMIC_LOAD = "atomic_load"
    ATOMIC_STORE = "atomic_store"
    ATOMIC_RMW = "atomic_rmw"
    ATOMIC_COMPARE_EXCHANGE = "atomic_compare_exchange"
    COMPILER_BARRIER = "compiler_barrier"


@dataclass(frozen=True)
class CBuiltinContract:
    """Renderer-independent builtin semantic contract; never builtin text."""
    kind: CBuiltinKind
    capability: str
    object_operand_index: int | None = None
    value_operand_index: int | None = None
    expected_operand_index: int | None = None
    desired_operand_index: int | None = None
    result_operand_index: int | None = None
    width_bits: int | None = None
    alignment_bytes: int | None = None
    success_ordering: str | None = None
    failure_ordering: str | None = None
    compiler_barrier: bool = False
    hardware_barrier: bool = False


def _failure(plan, name, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id, reason_codes=(getattr(TargetConstraintReasonCode, name),), details={} if details is None else details)


def derive_c_builtin_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    """Derive only supported, fully modelled builtin contracts."""
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint
    if candidate_plan.kind is not TargetLoweringKind.C_BUILTIN:
        return _failure(candidate_plan, "C_BUILTIN_PLAN_KIND_MISMATCH")
    if not source_model.operands.complete or not source_model.operation.complete:
        return _failure(candidate_plan, "C_BUILTIN_SOURCE_INCOMPLETE")
    capability = ""
    contract = None
    if source_model.atomic.present:
        atom = source_model.atomic
        if not atom.complete or atom.kind is None or atom.width_bits is None or atom.alignment_bytes is None or atom.address_operand_index is None or atom.success_ordering is None:
            return _failure(candidate_plan, "C_BUILTIN_ATOMIC_FACTS_INCOMPLETE")
        if atom.alignment_bytes <= 0 or atom.width_bits not in {8, 16, 32, 64, 128}:
            return _failure(candidate_plan, "C_BUILTIN_ATOMIC_TYPE_UNSUPPORTED")
        capability = "c_builtin:atomic"
        kind = {SourceAtomicKind.LOAD: CBuiltinKind.ATOMIC_LOAD, SourceAtomicKind.STORE: CBuiltinKind.ATOMIC_STORE, SourceAtomicKind.READ_MODIFY_WRITE: CBuiltinKind.ATOMIC_RMW, SourceAtomicKind.COMPARE_EXCHANGE: CBuiltinKind.ATOMIC_COMPARE_EXCHANGE}[atom.kind]
        if kind is CBuiltinKind.ATOMIC_COMPARE_EXCHANGE and (atom.expected_operand_index is None or atom.desired_operand_index is None or atom.failure_ordering is None):
            return _failure(candidate_plan, "C_BUILTIN_ATOMIC_FACTS_INCOMPLETE")
        contract = CBuiltinContract(kind, capability, atom.address_operand_index, atom.value_operand_index, atom.expected_operand_index, atom.desired_operand_index, atom.result_operand_index, atom.width_bits, atom.alignment_bytes, atom.success_ordering.value, atom.failure_ordering.value if atom.failure_ordering else None, True, True)
    elif source_model.barrier.present:
        barrier = source_model.barrier
        if not barrier.complete or not barrier.compiler_barrier or barrier.hardware_memory_barrier or barrier.instruction_serializing or barrier.speculation_control:
            return _failure(candidate_plan, "C_BUILTIN_BARRIER_UNSUPPORTED")
        capability = "c_builtin:compiler_barrier"
        contract = CBuiltinContract(CBuiltinKind.COMPILER_BARRIER, capability, compiler_barrier=True)
    else:
        return _failure(candidate_plan, "C_BUILTIN_OPERATION_UNSUPPORTED")
    if capability not in target_environment.builtin_capabilities:
        return _failure(candidate_plan, "C_BUILTIN_CAPABILITY_UNAVAILABLE", {"capability": capability})
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id, environment=target_environment, c_builtin_constraint=contract, memory_constraint=TargetMemoryConstraint(), control_flow_constraint=TargetControlFlowConstraint()))
