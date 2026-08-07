"""Fail-closed Phase 6C-2 contracts for pure C expressions.

This module consumes only the Phase-6A source model, a Phase-6B plan, and
the target environment.  It deliberately has no dependency on asm text,
lifting artefacts, or raw runtime facts.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Mapping

from .plan_types import TargetLoweringKind, TargetLoweringPlan
from .source_model import (
    SourceOperandAccess,
    SourceOperandBinding,
    SourceOperandKind,
    SourceOperationKind,
    SourceSemanticModel,
    SourceSignedness,
    SourceValueOperationKind,
)

if TYPE_CHECKING:  # Avoid a phase6c_constraints import cycle.
    from .phase6c_constraints import (
        TargetConstraintDerivationResult,
        TargetConstraintReasonCode,
        TargetEnvironment,
    )


class CExpressionOperationKind(str, Enum):
    COPY = "copy"
    BIT_NOT = "bit_not"
    BIT_AND = "bit_and"
    BIT_OR = "bit_or"
    BIT_XOR = "bit_xor"
    UNSIGNED_ADD = "unsigned_add"
    UNSIGNED_SUB = "unsigned_sub"
    UNSIGNED_MUL = "unsigned_mul"
    ZERO_EXTEND = "zero_extend"
    TRUNCATE = "truncate"


class CExpressionConstraintValidationError(ValueError):
    """Compatibility error type; public derivation returns reason codes."""


def validate_c_expression_constraint(constraint: "CExpressionConstraint") -> None:
    if not isinstance(constraint, CExpressionConstraint):
        raise CExpressionConstraintValidationError("invalid C expression constraint")


_SOURCE_OPERATION_MAP = {
    SourceValueOperationKind.COPY: CExpressionOperationKind.COPY,
    SourceValueOperationKind.BIT_NOT: CExpressionOperationKind.BIT_NOT,
    SourceValueOperationKind.BIT_AND: CExpressionOperationKind.BIT_AND,
    SourceValueOperationKind.BIT_OR: CExpressionOperationKind.BIT_OR,
    SourceValueOperationKind.BIT_XOR: CExpressionOperationKind.BIT_XOR,
    SourceValueOperationKind.UNSIGNED_ADD: CExpressionOperationKind.UNSIGNED_ADD,
    SourceValueOperationKind.UNSIGNED_SUB: CExpressionOperationKind.UNSIGNED_SUB,
    SourceValueOperationKind.UNSIGNED_MUL: CExpressionOperationKind.UNSIGNED_MUL,
    SourceValueOperationKind.ZERO_EXTEND: CExpressionOperationKind.ZERO_EXTEND,
    SourceValueOperationKind.TRUNCATE: CExpressionOperationKind.TRUNCATE,
}


@dataclass(frozen=True)
class CExpressionTypeContract:
    width_bits: int
    unsigned: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.width_bits, bool) or not isinstance(self.width_bits, int) or self.width_bits <= 0:
            raise ValueError("width_bits must be a positive integer")
        if not self.unsigned:
            raise ValueError("Phase 6C-2 accepts only unsigned C value contracts")


@dataclass(frozen=True)
class CExpressionOperandBinding:
    source_operand_index: int
    type_contract: CExpressionTypeContract
    is_result: bool = False


@dataclass(frozen=True)
class CExpressionDefinednessContract:
    unsigned_modular_arithmetic: bool = True
    no_signed_overflow: bool = True
    no_divide_by_zero: bool = True
    shift_count_in_range: bool = True
    no_signed_left_shift: bool = True


@dataclass(frozen=True)
class CExpressionConstraint:
    operation_kind: CExpressionOperationKind
    input_bindings: tuple[CExpressionOperandBinding, ...]
    result_binding: CExpressionOperandBinding
    result_type: CExpressionTypeContract
    definedness: CExpressionDefinednessContract

    def __post_init__(self) -> None:
        expected = 1 if self.operation_kind in {
            CExpressionOperationKind.COPY, CExpressionOperationKind.BIT_NOT,
            CExpressionOperationKind.ZERO_EXTEND, CExpressionOperationKind.TRUNCATE,
        } else 2
        if len(self.input_bindings) != expected:
            raise ValueError("C expression operation arity does not match contract")
        if not self.result_binding.is_result or self.result_binding.type_contract != self.result_type:
            raise ValueError("C expression result binding is invalid")


def _failure(plan_id: str, code_name: str, details: Mapping[str, str | int | bool] | None = None):
    # Imported only after phase6c_constraints has completed initialization.
    from .phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(
        plan_id=plan_id,
        reason_codes=(getattr(TargetConstraintReasonCode, code_name),),
        details={} if details is None else details,
    )


def _operand_contract(operand: SourceOperandBinding, *, result: bool):
    if operand.kind not in {SourceOperandKind.REGISTER, SourceOperandKind.IMMEDIATE, SourceOperandKind.EXPRESSION}:
        return None, "C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED"
    if operand.width_bits is None:
        return None, "C_EXPRESSION_OPERAND_WIDTH_MISSING"
    if operand.signedness is not SourceSignedness.UNSIGNED:
        return None, "C_EXPRESSION_OPERAND_SIGNEDNESS_UNSUPPORTED"
    if result:
        if operand.access not in {SourceOperandAccess.OUTPUT, SourceOperandAccess.READ_WRITE} or not operand.writes or operand.lvalue is None or not operand.lvalue.is_modifiable:
            return None, "C_EXPRESSION_RESULT_CONTRACT_INVALID"
    elif not operand.reads or operand.expression is None or not operand.expression.is_side_effect_free:
        return None, "C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED"
    return CExpressionOperandBinding(operand.source_operand_index, CExpressionTypeContract(operand.width_bits), result), None


def derive_c_expression_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    """Derive only a pure, single-result, unsigned value-expression contract."""
    if candidate_plan.kind is not TargetLoweringKind.C_EXPRESSION:
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_PLAN_KIND_MISMATCH")
    if not source_model.operands.complete or not source_model.operation.complete:
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_SOURCE_INCOMPLETE")
    if source_model.operation.kind is not SourceOperationKind.REGISTER_ONLY:
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_OPERATION_UNSUPPORTED")
    if any((source_model.operation.reads_memory, source_model.operation.writes_memory, source_model.memory.reads_memory, source_model.memory.writes_memory, source_model.atomic.present, source_model.barrier.present)):
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_MEMORY_UNSUPPORTED")
    if (source_model.shell.is_volatile or source_model.shell.has_memory_clobber or source_model.shell.has_cc_clobber or source_model.shell.has_asm_goto or source_model.shell.has_early_clobber or source_model.shell.has_tied_operands):
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_SHELL_NOT_NEUTRAL")
    if (source_model.operation.has_control_flow or source_model.operation.has_call or source_model.operation.has_return is not False or source_model.operation.may_trap is not False or source_model.control_flow.has_internal_branch or source_model.control_flow.has_call or source_model.control_flow.has_return is not False or source_model.control_flow.has_asm_goto or source_model.control_flow.has_multiple_exits or source_model.control_flow.has_indirect_control_flow is not False):
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_CONTROL_FLOW_UNSUPPORTED")
    if (source_model.registers.reads_or_writes_stack_pointer or source_model.registers.reads_or_writes_frame_pointer or source_model.implicit_state.reads_condition_codes or source_model.implicit_state.writes_condition_codes or source_model.implicit_state.reads_implicit_machine_state or source_model.implicit_state.writes_implicit_machine_state or source_model.microarch.explicitly_microarch_sensitive or source_model.microarch.has_structured_microarch_intent):
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_IMPLICIT_STATE_UNSUPPORTED")
    value_operation = source_model.value_operation
    if value_operation is None or not value_operation.complete:
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_OPERATION_INCOMPLETE")
    operation_kind = _SOURCE_OPERATION_MAP.get(value_operation.kind)
    if operation_kind is None:
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_OPERATION_UNSUPPORTED")
    by_index = {item.source_operand_index: item for item in source_model.operands.operands}
    inputs = []
    for index in value_operation.input_operand_indexes:
        operand = by_index.get(index)
        if operand is None:
            return _failure(candidate_plan.plan_id, "C_EXPRESSION_OPERAND_BINDING_MISSING", {"source_operand_index": index})
        binding, error = _operand_contract(operand, result=False)
        if error:
            return _failure(candidate_plan.plan_id, error, {"source_operand_index": index})
        inputs.append(binding)
    result_operand = by_index.get(value_operation.result_operand_index)
    if result_operand is None:
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_RESULT_CONTRACT_INVALID")
    result, error = _operand_contract(result_operand, result=True)
    if error:
        return _failure(candidate_plan.plan_id, error, {"source_operand_index": value_operation.result_operand_index})
    try:
        return _success(candidate_plan.plan_id, target_environment, operation_kind, tuple(inputs), result)
    except ValueError:
        return _failure(candidate_plan.plan_id, "C_EXPRESSION_C_DEFINEDNESS_UNPROVEN")


def _success(plan_id: str, environment: "TargetEnvironment", operation: CExpressionOperationKind, inputs: tuple[CExpressionOperandBinding, ...], result: CExpressionOperandBinding):
    from .phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint
    constraint = CExpressionConstraint(operation, inputs, result, result.type_contract, CExpressionDefinednessContract())
    model = TargetConstraintModel(plan_id=plan_id, environment=environment, c_expression_constraint=constraint, memory_constraint=TargetMemoryConstraint(), control_flow_constraint=TargetControlFlowConstraint())
    return TargetConstraintDerivationResult.succeeded(model)
