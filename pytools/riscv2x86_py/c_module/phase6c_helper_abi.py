"""Phase 6C-8 verified helper ABI contracts; deliberately fail-closed."""
from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING
from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import SourceHelperMemoryEffect, SourceSemanticModel
if TYPE_CHECKING:
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetEnvironment

@dataclass(frozen=True)
class HelperAbiContract:
    helper_symbol: str
    semantic_version: str
    calling_convention: str
    parameter_operand_indexes: tuple[int, ...]
    return_operand_index: int | None
    memory_effect: SourceHelperMemoryEffect
    may_return: bool
    may_unwind: bool
    required_stack_alignment_bytes: int
    preserves_stack_pointer: bool
    preserves_frame_pointer: bool
    caller_saved_registers: tuple[str, ...]
    callee_saved_registers: tuple[str, ...]
    pic_plt_compatible: bool
    runtime_contract_id: str
    target_abi: str
    parameter_type_ids: tuple[str, ...]
    return_type_id: str | None

def _fail(plan, name, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id, reason_codes=(getattr(TargetConstraintReasonCode, name),), details={} if details is None else details)

def derive_helper_abi_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    """Derive only an explicit versioned helper semantic/ABI contract."""
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint
    if candidate_plan.kind is not TargetLoweringKind.HELPER_CALL:
        return _fail(candidate_plan, "HELPER_ABI_PLAN_KIND_MISMATCH")
    if not source_model.operands.complete or not source_model.operation.complete:
        return _fail(candidate_plan, "HELPER_ABI_SOURCE_INCOMPLETE")
    helper = source_model.helper_abi
    required = (helper.complete and helper.present and helper.helper_symbol and helper.semantic_version
        and helper.calling_convention and helper.may_return is not None and helper.may_unwind is not None
        and helper.required_stack_alignment_bytes and helper.preserves_stack_pointer is not None
        and helper.preserves_frame_pointer is not None and helper.pic_plt_compatible is not None
        and helper.memory_effect is not SourceHelperMemoryEffect.UNKNOWN)
    if not required:
        return _fail(candidate_plan, "HELPER_ABI_CONTRACT_INCOMPLETE")
    if not helper.runtime_available:
        return _fail(candidate_plan, "HELPER_ABI_RUNTIME_UNAVAILABLE")
    contract_id = f"{helper.helper_symbol}@{helper.semantic_version}"
    if contract_id not in target_environment.helper_contract_capabilities:
        return _fail(candidate_plan, "HELPER_ABI_SEMANTIC_VERSION_UNAVAILABLE", {"contract": contract_id})
    if helper.may_return != (source_model.operation.has_return is not True):
        return _fail(candidate_plan, "HELPER_ABI_CONTROL_FLOW_MISMATCH")
    stack_sensitive = source_model.registers.reads_or_writes_stack_pointer or source_model.registers.reads_or_writes_frame_pointer
    if stack_sensitive and (not helper.preserves_stack_pointer or not helper.preserves_frame_pointer):
        return _fail(candidate_plan, "HELPER_ABI_STACK_FRAME_UNSUPPORTED")
    by_index = {item.source_operand_index: item for item in source_model.operands.operands}
    parameter_types = []
    for index in helper.parameter_operand_indexes:
        operand = by_index.get(index)
        if operand is None or operand.expression is None or not operand.expression.c_type_id:
            return _fail(candidate_plan, "HELPER_ABI_CONTRACT_INCOMPLETE", {"parameter_index": index})
        parameter_types.append(operand.expression.c_type_id)
    return_type = None
    if helper.return_operand_index is not None:
        result = by_index.get(helper.return_operand_index)
        if result is None or result.lvalue is None or not result.lvalue.is_modifiable or not result.lvalue.c_type_id:
            return _fail(candidate_plan, "HELPER_ABI_CONTRACT_INCOMPLETE", {"return_index": helper.return_operand_index})
        return_type = result.lvalue.c_type_id
    if source_model.atomic.present or source_model.barrier.present:
        # The current source helper model has no structured atomic/barrier
        # effect contract.  Never assume a helper preserves either.
        return _fail(candidate_plan, "HELPER_ABI_CONTRACT_INCOMPLETE", {"expected": "explicit_helper_atomic_barrier_effects"})
    contract = HelperAbiContract(helper.helper_symbol, helper.semantic_version, helper.calling_convention,
        helper.parameter_operand_indexes, helper.return_operand_index, helper.memory_effect, helper.may_return,
        helper.may_unwind, helper.required_stack_alignment_bytes, helper.preserves_stack_pointer,
        helper.preserves_frame_pointer, helper.caller_saved_registers, helper.callee_saved_registers,
        helper.pic_plt_compatible, contract_id, target_environment.abi.value,
        tuple(parameter_types), return_type)
    memory = TargetMemoryConstraint(requires_memory_clobber=helper.memory_effect is not SourceHelperMemoryEffect.NONE)
    flow = TargetControlFlowConstraint(requires_helper_abi_contract=True,
        preserve_stack_pointer=stack_sensitive, preserve_frame_pointer=stack_sensitive)
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,
        environment=target_environment, helper_abi_contract=contract, memory_constraint=memory,
        control_flow_constraint=flow))
