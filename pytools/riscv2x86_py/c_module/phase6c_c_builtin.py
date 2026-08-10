"""Phase 6C-3 structured compiler-builtin contracts (fail closed)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import (
    SourceAtomicKind,
    SourceMemoryOrdering,
    SourceOperandAccess,
    SourceSemanticModel,
)

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
    semantic_contract_id: str = ""
    builtin_identifier: str = ""
    required_declaration: str | None = None
    object_pointee_type_id: str | None = None
    value_c_type_id: str | None = None
    result_c_type_id: str | None = None


_ORDER_CONSTANTS = {
    SourceMemoryOrdering.RELAXED: "__ATOMIC_RELAXED",
    SourceMemoryOrdering.CONSUME: "__ATOMIC_CONSUME",
    SourceMemoryOrdering.ACQUIRE: "__ATOMIC_ACQUIRE",
    SourceMemoryOrdering.RELEASE: "__ATOMIC_RELEASE",
    SourceMemoryOrdering.ACQ_REL: "__ATOMIC_ACQ_REL",
    SourceMemoryOrdering.SEQ_CST: "__ATOMIC_SEQ_CST",
}

_LOAD_CONTRACT_ID = "c.builtin.atomic-load-n.u32-u64.v1"
_STORE_CONTRACT_ID = "c.builtin.atomic-store-n.u32-u64.v1"
_COMPILER_BARRIER_CONTRACT_ID = (
    "c.builtin.atomic-signal-fence.compiler-barrier.seq-cst.v1"
)


def _failure(plan, name, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id, reason_codes=(getattr(TargetConstraintReasonCode, name),), details={} if details is None else details)


def _operand_by_index(source_model, index):
    return next(
        (item for item in source_model.operands.operands
         if item.source_operand_index == index),
        None,
    )


def _atomic_binding_failure(plan, *, expected: str):
    return _failure(plan, "C_BUILTIN_ATOMIC_FACTS_INCOMPLETE", {
        "expected": expected,
    })


def _derive_atomic_contract(source_model, candidate_plan):
    """Derive only registered load/store public-builtin contracts.

    RMW and CAS remain deliberately unsupported here: the current source
    atomic model does not carry an RMW operator contract or a complete CAS
    result/expected-value update contract, so rendering either would require
    guessing semantics.
    """
    atom = source_model.atomic
    if (not atom.complete or atom.kind is None or atom.width_bits is None or
            atom.alignment_bytes is None or atom.address_operand_index is None or
            atom.success_ordering is None):
        return _atomic_binding_failure(candidate_plan, expected="complete_atomic_model")
    if atom.width_bits not in {32, 64} or atom.alignment_bytes < atom.width_bits // 8:
        return _failure(candidate_plan, "C_BUILTIN_ATOMIC_TYPE_UNSUPPORTED", {
            "width_bits": atom.width_bits,
            "alignment_bytes": atom.alignment_bytes,
        })
    address = _operand_by_index(source_model, atom.address_operand_index)
    if (address is None or address.address is None or
            not address.address.provenance_known or
            address.address.alignment_bytes is None or
            address.address.alignment_bytes < atom.width_bits // 8 or
            not address.address.pointee_type_id or address.expression is None or
            not address.expression.c_type_id):
        return _atomic_binding_failure(candidate_plan, expected="proven_address_binding")

    common = {
        "object_operand_index": atom.address_operand_index,
        "width_bits": atom.width_bits,
        "alignment_bytes": atom.alignment_bytes,
        "success_ordering": atom.success_ordering.value,
        "compiler_barrier": True,
        "hardware_barrier": True,
        "object_pointee_type_id": address.address.pointee_type_id,
    }
    if atom.kind is SourceAtomicKind.LOAD:
        if atom.result_operand_index is None or atom.value_operand_index is not None:
            return _atomic_binding_failure(candidate_plan, expected="load_result_and_no_store_value")
        result = _operand_by_index(source_model, atom.result_operand_index)
        if (result is None or result.access not in {SourceOperandAccess.OUTPUT, SourceOperandAccess.READ_WRITE} or
                result.lvalue is None or not result.lvalue.is_modifiable or
                result.lvalue.c_type_id != address.address.pointee_type_id or
                result.width_bits != atom.width_bits):
            return _atomic_binding_failure(candidate_plan, expected="typed_load_result_binding")
        return CBuiltinContract(
            CBuiltinKind.ATOMIC_LOAD, "c_builtin:atomic", result_operand_index=atom.result_operand_index,
            result_c_type_id=result.lvalue.c_type_id, semantic_contract_id=_LOAD_CONTRACT_ID,
            builtin_identifier="__atomic_load_n", **common,
        )
    if atom.kind is SourceAtomicKind.STORE:
        if atom.value_operand_index is None or atom.result_operand_index is not None:
            return _atomic_binding_failure(candidate_plan, expected="typed_store_value_and_no_result")
        value = _operand_by_index(source_model, atom.value_operand_index)
        if (value is None or value.expression is None or
                value.expression.c_type_id != address.address.pointee_type_id or
                value.width_bits != atom.width_bits):
            return _atomic_binding_failure(candidate_plan, expected="typed_store_value_binding")
        return CBuiltinContract(
            CBuiltinKind.ATOMIC_STORE, "c_builtin:atomic", value_operand_index=atom.value_operand_index,
            value_c_type_id=value.expression.c_type_id, semantic_contract_id=_STORE_CONTRACT_ID,
            builtin_identifier="__atomic_store_n", **common,
        )
    return _failure(candidate_plan, "C_BUILTIN_OPERATION_UNSUPPORTED", {
        "atomic_kind": atom.kind.value,
    })


def derive_c_builtin_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    """Derive only supported, fully modelled builtin contracts."""
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint
    if candidate_plan.kind is not TargetLoweringKind.C_BUILTIN:
        return _failure(candidate_plan, "C_BUILTIN_PLAN_KIND_MISMATCH")
    if not source_model.operands.complete or not source_model.operation.complete:
        return _failure(candidate_plan, "C_BUILTIN_SOURCE_INCOMPLETE")
    capability = ""
    contract = None
    memory_constraint = TargetMemoryConstraint()
    if source_model.atomic.present:
        contract = _derive_atomic_contract(source_model, candidate_plan)
        if not isinstance(contract, CBuiltinContract):
            return contract
        capability = contract.capability
        ordering = SourceMemoryOrdering(contract.success_ordering)
        memory_constraint = TargetMemoryConstraint(
            requires_atomic_ordering=True,
            requires_compiler_barrier=True,
            required_atomic_width_bits=contract.width_bits,
            required_alignment_bytes=contract.alignment_bytes,
            atomic_success_ordering=ordering,
        )
    elif source_model.barrier.present:
        barrier = source_model.barrier
        if not barrier.complete or not barrier.compiler_barrier or barrier.hardware_memory_barrier or barrier.instruction_serializing or barrier.speculation_control:
            return _failure(candidate_plan, "C_BUILTIN_BARRIER_UNSUPPORTED")
        capability = "c_builtin:compiler_barrier"
        contract = CBuiltinContract(
            CBuiltinKind.COMPILER_BARRIER, capability, compiler_barrier=True,
            semantic_contract_id=_COMPILER_BARRIER_CONTRACT_ID,
            builtin_identifier="__atomic_signal_fence",
        )
        memory_constraint = TargetMemoryConstraint(
            requires_compiler_barrier=True,
        )
    else:
        return _failure(candidate_plan, "C_BUILTIN_OPERATION_UNSUPPORTED")
    if capability not in target_environment.builtin_capabilities:
        return _failure(candidate_plan, "C_BUILTIN_CAPABILITY_UNAVAILABLE", {"capability": capability})
    expected_semantic_id = candidate_plan.metadata.get("renderer_semantic_contract_id")
    if expected_semantic_id != contract.semantic_contract_id:
        return _failure(candidate_plan, "C_BUILTIN_OPERATION_UNSUPPORTED", {
            "expected_semantic_contract_id": str(expected_semantic_id),
        })
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id, environment=target_environment, c_builtin_constraint=contract, memory_constraint=memory_constraint, control_flow_constraint=TargetControlFlowConstraint()))
