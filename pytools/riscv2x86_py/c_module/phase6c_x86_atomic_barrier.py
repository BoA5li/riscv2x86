"""Phase 6C-6 x86 atomic and barrier contracts, derived fail-closed."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import (
    SourceAtomicKind,
    SourceAtomicRmwOperation,
    SourceBarrierScope,
    SourceMemoryOrdering,
    SourceSemanticModel,
)


class X86AtomicLockMechanism(str, Enum):
    LOCK_PREFIX = "lock_prefix"
    IMPLICIT_XCHG_LOCK = "implicit_xchg_lock"

if TYPE_CHECKING:
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetEnvironment


@dataclass(frozen=True)
class X86AtomicContract:
    """A renderer-independent atomic contract; not an instruction selection."""
    kind: SourceAtomicKind
    object_operand_index: int
    width_bits: int
    alignment_bytes: int
    success_ordering: SourceMemoryOrdering
    failure_ordering: SourceMemoryOrdering | None
    value_operand_index: int | None
    expected_operand_index: int | None
    desired_operand_index: int | None
    result_operand_index: int | None
    requires_lock_semantics: bool
    requires_compiler_barrier: bool
    requires_hardware_ordering: bool
    required_target_feature: str
    semantic_contract_id: str
    rmw_operation: SourceAtomicRmwOperation | None
    lock_mechanism: X86AtomicLockMechanism | None


@dataclass(frozen=True)
class X86BarrierContract:
    """Compiler and hardware barrier obligations remain explicitly separate."""
    compiler_barrier: bool
    hardware_memory_fence: bool
    ordering: SourceMemoryOrdering | None
    scope: SourceBarrierScope | None
    instruction_serializing: bool
    speculation_control: bool
    required_target_feature: str | None
    semantic_contract_id: str
    route: str


def _failure(plan: TargetLoweringPlan, name: str, details=None):
    from ..phase6c_constraints import (
        TargetConstraintDerivationResult,
        TargetConstraintReasonCode,
    )
    return TargetConstraintDerivationResult.failure(
        plan_id=plan.plan_id,
        reason_codes=(getattr(TargetConstraintReasonCode, name),),
        details={} if details is None else details,
    )


def _atomic_required_fields_present(atom) -> bool:
    base = (
        atom.complete and atom.kind is not None and atom.width_bits is not None
        and atom.alignment_bytes is not None and atom.address_operand_index is not None
        and atom.success_ordering is not None
    )
    if not base:
        return False
    if atom.kind is SourceAtomicKind.STORE:
        return atom.value_operand_index is not None
    if atom.kind is SourceAtomicKind.READ_MODIFY_WRITE:
        return (atom.rmw_operation is not None and atom.value_operand_index is not None
                and atom.result_operand_index is not None)
    if atom.kind is SourceAtomicKind.COMPARE_EXCHANGE:
        return (atom.expected_operand_index is not None and atom.desired_operand_index is not None
                and atom.result_operand_index is not None and atom.failure_ordering is not None)
    return atom.kind is SourceAtomicKind.LOAD and atom.result_operand_index is not None


def _operand_indexes_exist(source_model: SourceSemanticModel, indexes: tuple[int | None, ...]) -> bool:
    available = {operand.source_operand_index for operand in source_model.operands.operands}
    return all(index is None or index in available for index in indexes)


_LOCK_RMW_CONTRACTS = {
    SourceAtomicRmwOperation.FETCH_ADD: (
        "x86.gnu-att.atomic.lock-xadd.u32-u64.seq-cst.v1",
        X86AtomicLockMechanism.LOCK_PREFIX,
    ),
    SourceAtomicRmwOperation.EXCHANGE: (
        "x86.gnu-att.atomic.xchg.u32-u64.seq-cst.v1",
        X86AtomicLockMechanism.IMPLICIT_XCHG_LOCK,
    ),
}


def _derive_lock_rmw_contract(source_model, candidate_plan, atom):
    """Derive the narrow no-temporary lock-RMW form or reject.

    The current renderer contract can only preserve an old-value result when
    the source explicitly binds the RMW input and result to the same
    read-write C lvalue.  Distinct value/result operands need an approved
    structured temporary recipe and therefore remain needs-route.
    """
    from ..phase6c_constraints import TargetOperandClass, TargetOperandConstraint, TargetOperandRole
    from ..source_model import SourceOperandAccess
    if atom.kind is not SourceAtomicKind.READ_MODIFY_WRITE or atom.rmw_operation not in _LOCK_RMW_CONTRACTS:
        return _failure(candidate_plan, "X86_ATOMIC_ORDERING_UNSUPPORTED", {"expected": "registered_rmw_operation"})
    if atom.width_bits not in {32, 64} or atom.alignment_bytes < atom.width_bits // 8:
        return _failure(candidate_plan, "X86_ATOMIC_FACTS_INCOMPLETE", {"expected": "naturally_aligned_u32_or_u64"})
    if atom.success_ordering is not SourceMemoryOrdering.SEQ_CST or atom.failure_ordering is not None:
        return _failure(candidate_plan, "X86_ATOMIC_ORDERING_UNSUPPORTED", {"expected": "seq_cst_rmw_without_failure_order"})
    if atom.value_operand_index != atom.result_operand_index:
        return _failure(candidate_plan, "X86_ATOMIC_FACTS_INCOMPLETE", {"expected": "read_write_value_result_binding"})
    by_index = {op.source_operand_index: op for op in source_model.operands.operands}
    address = by_index.get(atom.address_operand_index)
    value = by_index.get(atom.value_operand_index)
    if (address is None or value is None or address.address is None or
            not address.address.provenance_known or
            address.address.alignment_bytes is None or
            address.address.alignment_bytes < atom.width_bits // 8 or
            address.expression is None or not address.expression.c_type_id or
            value.access is not SourceOperandAccess.READ_WRITE or
            value.expression is None or value.lvalue is None or
            not value.lvalue.is_modifiable or
            value.width_bits != atom.width_bits):
        return _failure(candidate_plan, "X86_ATOMIC_FACTS_INCOMPLETE", {"expected": "typed_address_and_read_write_value"})
    semantic_id, mechanism = _LOCK_RMW_CONTRACTS[atom.rmw_operation]
    if candidate_plan.metadata.get("renderer_semantic_contract_id") != semantic_id:
        return _failure(candidate_plan, "X86_ATOMIC_ORDERING_UNSUPPORTED", {"expected_semantic_contract_id": semantic_id})
    operands = (
        TargetOperandConstraint(
            value.source_operand_index, TargetOperandRole.READ_WRITE,
            frozenset({TargetOperandClass.GENERAL_REGISTER}),
            required_width_bits=atom.width_bits,
            required_signedness=value.signedness,
        ),
        TargetOperandConstraint(
            address.source_operand_index, TargetOperandRole.READ_WRITE,
            frozenset({TargetOperandClass.MEMORY}),
        ),
    )
    return (semantic_id, mechanism, operands)


def derive_x86_atomic_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    """Derive an atomic contract without treating clobbers as ordering proof."""
    from ..phase6c_constraints import TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint, TargetConstraintDerivationResult
    if candidate_plan.kind is not TargetLoweringKind.X86_ATOMIC:
        return _failure(candidate_plan, "X86_ATOMIC_PLAN_KIND_MISMATCH")
    if (not source_model.operands.complete or not source_model.operation.complete
            or source_model.operation.has_control_flow or source_model.operation.has_call
            or source_model.operation.has_return is not False):
        return _failure(candidate_plan, "X86_ATOMIC_SOURCE_INCOMPLETE")
    atom = source_model.atomic
    if not atom.present or not _atomic_required_fields_present(atom):
        return _failure(candidate_plan, "X86_ATOMIC_FACTS_INCOMPLETE")
    if not _operand_indexes_exist(source_model, (atom.address_operand_index, atom.value_operand_index,
            atom.expected_operand_index, atom.desired_operand_index, atom.result_operand_index)):
        return _failure(candidate_plan, "X86_ATOMIC_FACTS_INCOMPLETE")
    if "x86:atomic" not in target_environment.available_features or not target_environment.supports_gnu_inline_asm:
        return _failure(candidate_plan, "X86_ATOMIC_FEATURE_UNAVAILABLE", {"feature": "x86:atomic_and_gnu_inline_asm"})
    derived = _derive_lock_rmw_contract(source_model, candidate_plan, atom)
    if not isinstance(derived, tuple):
        return derived
    semantic_id, mechanism, operand_constraints = derived
    contract = X86AtomicContract(atom.kind, atom.address_operand_index, atom.width_bits, atom.alignment_bytes,
        atom.success_ordering, atom.failure_ordering, atom.value_operand_index, atom.expected_operand_index,
        atom.desired_operand_index, atom.result_operand_index, True, True, True, "x86:atomic",
        semantic_id, atom.rmw_operation, mechanism)
    memory = TargetMemoryConstraint(requires_memory_clobber=True, requires_atomic_ordering=True,
        requires_compiler_barrier=True, requires_hardware_barrier=True,
        atomic_success_ordering=atom.success_ordering, atomic_failure_ordering=atom.failure_ordering,
        required_atomic_width_bits=atom.width_bits, required_alignment_bytes=atom.alignment_bytes)
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,
        environment=target_environment, operand_constraints=operand_constraints,
        x86_atomic_contract=contract, memory_constraint=memory,
        control_flow_constraint=TargetControlFlowConstraint(), preserve_volatile=True,
        preserve_cc_clobber=True))


def derive_x86_barrier_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    """Derive explicit barrier obligations; never infer an mfence mapping."""
    from ..phase6c_constraints import TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint, TargetConstraintDerivationResult
    if candidate_plan.kind is not TargetLoweringKind.X86_BARRIER:
        return _failure(candidate_plan, "X86_BARRIER_PLAN_KIND_MISMATCH")
    if (not source_model.operation.complete or not source_model.barrier.complete
            or source_model.operation.has_control_flow or source_model.operation.has_call
            or source_model.operation.has_return is not False):
        return _failure(candidate_plan, "X86_BARRIER_SOURCE_INCOMPLETE")
    barrier = source_model.barrier
    if source_model.memory.has_unknown_barrier or not barrier.present:
        return _failure(candidate_plan, "X86_BARRIER_UNKNOWN")
    # Instruction-stream synchronization is distinct from serialization and
    # must not fall back to mfence (e.g. RISC-V fence.i != x86 mfence).
    if source_model.memory.has_instruction_barrier:
        return _failure(candidate_plan, "X86_BARRIER_INSTRUCTION_STREAM_UNSUPPORTED")
    if barrier.speculation_control:
        return _failure(candidate_plan, "X86_BARRIER_INSTRUCTION_STREAM_UNSUPPORTED")
    if source_model.atomic.present or (not barrier.compiler_barrier and not barrier.hardware_memory_barrier):
        return _failure(candidate_plan, "X86_BARRIER_SEMANTICS_UNSUPPORTED")
    if barrier.hardware_memory_barrier and (barrier.ordering is None or barrier.scope is None):
        return _failure(candidate_plan, "X86_BARRIER_SEMANTICS_UNSUPPORTED")
    if not target_environment.supports_gnu_inline_asm:
        return _failure(candidate_plan, "X86_BARRIER_FEATURE_UNAVAILABLE", {"feature": "gnu_inline_asm"})

    if barrier.instruction_serializing:
        semantic_id = "x86.gnu-att.serialize.instruction-serialization.v1"
        feature, route = "x86:serialize", "instruction_serialization"
        if (candidate_plan.metadata.get("renderer_semantic_contract_id") != semantic_id or
                feature not in target_environment.available_features):
            return _failure(candidate_plan, "X86_BARRIER_FEATURE_UNAVAILABLE", {"feature": feature})
        contract = X86BarrierContract(True, False, barrier.ordering, barrier.scope,
            True, False, feature, semantic_id, route)
        memory = TargetMemoryConstraint(requires_memory_clobber=True,
            requires_compiler_barrier=True, requires_instruction_serialization=True,
            barrier_scope=barrier.scope)
    else:
        # This is deliberately the narrow SYSTEM + seq_cst full-fence route.
        # Load/store-only ordering lacks an authoritative direction model and
        # is therefore not guessed as lfence/sfence.
        semantic_id = "x86.gnu-att.mfence.full-system-seq-cst.v1"
        feature, route = "x86:hardware_fence", "full_hardware_fence"
        if (not barrier.hardware_memory_barrier or
                barrier.ordering is not SourceMemoryOrdering.SEQ_CST or
                barrier.scope is not SourceBarrierScope.SYSTEM):
            return _failure(candidate_plan, "X86_BARRIER_SEMANTICS_UNSUPPORTED", {"expected": "system_seq_cst_full_fence"})
        if (candidate_plan.metadata.get("renderer_semantic_contract_id") != semantic_id or
                feature not in target_environment.available_features):
            return _failure(candidate_plan, "X86_BARRIER_FEATURE_UNAVAILABLE", {"feature": feature})
        contract = X86BarrierContract(True, True, barrier.ordering, barrier.scope,
            False, False, feature, semantic_id, route)
        memory = TargetMemoryConstraint(requires_memory_clobber=True,
            requires_compiler_barrier=True, requires_hardware_barrier=True,
            barrier_scope=barrier.scope)
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,
        environment=target_environment, x86_barrier_contract=contract, memory_constraint=memory,
        control_flow_constraint=TargetControlFlowConstraint(), preserve_volatile=True))
