# phase6c_c_expression.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from .phase6c_constraints import TargetConstraintReasonCode, TargetConstraintDetailValue, _freeze_details 
from typing import Iterable, Optional, Tuple,  Mapping, Sequence
try:
    # Package import.
    from .source_model import (
        SourceOperandKind,
        SourceSignedness,
    )
except ImportError:  # pragma: no cover
    # Direct-module import fallback for local/unit-test execution.
    from source_model import (
        SourceOperandKind,
        SourceSignedness,
    )

# ---------------------------------------------------------------------------
# Stable reason-code infrastructure.
#
# If your repository already defines TargetConstraintReasonCode and
# TargetConstraintDetailValue in a shared module, remove these definitions and
# import the shared versions instead.
# ---------------------------------------------------------------------------

class CExpressionConstraintValidationError(ValueError):
    """
    Raised when a purported pure C-expression constraint is internally invalid.

    A caller should normally receive a structured
    TargetConstraintDerivationResult from the public Phase 6C deriver.
    This exception is intended for local intrinsic validation failures while
    constructing a CExpressionConstraint.
    """

    def __init__(
        self,
        reason_code: TargetConstraintReasonCode,
        *,
        details: Mapping[str, TargetConstraintDetailValue] | None = None,
        message: str | None = None,
    ) -> None:
        if not isinstance(reason_code, TargetConstraintReasonCode):
            raise TypeError(
                "reason_code must be TargetConstraintReasonCode, got "
                f"{type(reason_code).__name__}"
            )

        frozen_details = _freeze_details(details)

        self.reason_code = reason_code
        self.details = frozen_details

        if message is None:
            message = reason_code.value

        super().__init__(message)


# ---------------------------------------------------------------------------
# Core C-expression operation model.
# ---------------------------------------------------------------------------


class CExpressionOperationKind(str, Enum):
    """Operations that Phase 6C may represent as pure C expressions."""

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

    UNSIGNED_EQUAL = "unsigned_equal"
    UNSIGNED_NOT_EQUAL = "unsigned_not_equal"
    UNSIGNED_LESS_THAN = "unsigned_less_than"
    UNSIGNED_LESS_EQUAL = "unsigned_less_equal"
    UNSIGNED_GREATER_THAN = "unsigned_greater_than"
    UNSIGNED_GREATER_EQUAL = "unsigned_greater_equal"


class CExpressionIntegerKind(str, Enum):
    """
    Integer categories permitted by the pure C-expression contract.

    This intentionally excludes signed arithmetic and signed shifts.  Such
    operations must be rejected until the pipeline has a separate, proven-safe
    signed-integer model.
    """

    UNSIGNED_INTEGER = "unsigned_integer"
    BOOLEAN = "boolean"


class CExpressionOperandRole(str, Enum):
    """Role played by a source operand in the resulting C expression."""

    INPUT = "input"
    RESULT = "result"


_PURE_C_EXPRESSION_OPERAND_KINDS = frozenset(
    {
        SourceOperandKind.REGISTER,
        SourceOperandKind.TEMPORARY,
        SourceOperandKind.IMMEDIATE,
    }
)


_UNARY_OPERATIONS = frozenset(
    {
        CExpressionOperationKind.COPY,
        CExpressionOperationKind.BIT_NOT,
        CExpressionOperationKind.ZERO_EXTEND,
        CExpressionOperationKind.TRUNCATE,
    }
)


_BINARY_OPERATIONS = frozenset(
    {
        CExpressionOperationKind.BIT_AND,
        CExpressionOperationKind.BIT_OR,
        CExpressionOperationKind.BIT_XOR,

        CExpressionOperationKind.UNSIGNED_ADD,
        CExpressionOperationKind.UNSIGNED_SUB,
        CExpressionOperationKind.UNSIGNED_MUL,

        CExpressionOperationKind.UNSIGNED_EQUAL,
        CExpressionOperationKind.UNSIGNED_NOT_EQUAL,
        CExpressionOperationKind.UNSIGNED_LESS_THAN,
        CExpressionOperationKind.UNSIGNED_LESS_EQUAL,
        CExpressionOperationKind.UNSIGNED_GREATER_THAN,
        CExpressionOperationKind.UNSIGNED_GREATER_EQUAL,
    }
)


_OPERATION_ARITY: Mapping[CExpressionOperationKind, int] = MappingProxyType(
    {
        CExpressionOperationKind.COPY: 1,
        CExpressionOperationKind.BIT_NOT: 1,

        CExpressionOperationKind.BIT_AND: 2,
        CExpressionOperationKind.BIT_OR: 2,
        CExpressionOperationKind.BIT_XOR: 2,

        CExpressionOperationKind.UNSIGNED_ADD: 2,
        CExpressionOperationKind.UNSIGNED_SUB: 2,
        CExpressionOperationKind.UNSIGNED_MUL: 2,

        CExpressionOperationKind.ZERO_EXTEND: 1,
        CExpressionOperationKind.TRUNCATE: 1,

        CExpressionOperationKind.UNSIGNED_EQUAL: 2,
        CExpressionOperationKind.UNSIGNED_NOT_EQUAL: 2,
        CExpressionOperationKind.UNSIGNED_LESS_THAN: 2,
        CExpressionOperationKind.UNSIGNED_LESS_EQUAL: 2,
        CExpressionOperationKind.UNSIGNED_GREATER_THAN: 2,
        CExpressionOperationKind.UNSIGNED_GREATER_EQUAL: 2,
    }
)


# ---------------------------------------------------------------------------
# Type, operand, and definedness contracts.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CExpressionTypeContract:
    """
    Type requirements for an operand or result C expression.

    `requires_explicit_width_cast` and `requires_explicit_unsigned_cast` are
    renderer obligations.  They indicate that Phase 6F must introduce explicit
    casts around operands and/or results to preserve the intended fixed-width
    unsigned semantics in the presence of C integer promotions.
    """

    width_bits: int
    integer_kind: CExpressionIntegerKind

    requires_explicit_width_cast: bool = False
    requires_explicit_unsigned_cast: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.width_bits, int)
            or isinstance(self.width_bits, bool)
            or self.width_bits <= 0
        ):
            raise ValueError(
                "width_bits must be a positive non-boolean int, got "
                f"{self.width_bits!r}"
            )

        if not isinstance(self.integer_kind, CExpressionIntegerKind):
            raise TypeError(
                "integer_kind must be CExpressionIntegerKind, got "
                f"{type(self.integer_kind).__name__}"
            )

        if not isinstance(self.requires_explicit_width_cast, bool):
            raise TypeError(
                "requires_explicit_width_cast must be bool, got "
                f"{type(self.requires_explicit_width_cast).__name__}"
            )

        if not isinstance(self.requires_explicit_unsigned_cast, bool):
            raise TypeError(
                "requires_explicit_unsigned_cast must be bool, got "
                f"{type(self.requires_explicit_unsigned_cast).__name__}"
            )

    @property
    def is_unsigned_integer(self) -> bool:
        return (
            self.integer_kind
            is CExpressionIntegerKind.UNSIGNED_INTEGER
        )

    @property
    def is_boolean(self) -> bool:
        return self.integer_kind is CExpressionIntegerKind.BOOLEAN

    @property
    def is_raw_bit_pattern(self) -> bool:
        """
        Compatibility name for bitwise validation.

        Phase 6C currently models raw fixed-width bit patterns using unsigned
        integer C types only.
        """

        return self.is_unsigned_integer


@dataclass(frozen=True)
class CExpressionOperandBinding:
    """
    Binding between a source semantic operand and a C-expression role.

    A binding identifies the source operand without carrying raw register
    names, raw asm text, lifted IR values, or C renderer identifiers.
    """

    source_operand_index: int
    source_operand_kind: SourceOperandKind
    type_contract: CExpressionTypeContract

    reads_value: bool
    writes_value: bool
    is_result_lvalue: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_operand_index, int)
            or isinstance(self.source_operand_index, bool)
            or self.source_operand_index < 0
        ):
            raise ValueError(
                "source_operand_index must be a non-negative non-boolean int"
            )

        if not isinstance(self.source_operand_kind, SourceOperandKind):
            raise TypeError(
                "source_operand_kind must be SourceOperandKind, got "
                f"{type(self.source_operand_kind).__name__}"
            )

        if not isinstance(self.type_contract, CExpressionTypeContract):
            raise TypeError(
                "type_contract must be CExpressionTypeContract, got "
                f"{type(self.type_contract).__name__}"
            )

        for field_name in (
            "reads_value",
            "writes_value",
            "is_result_lvalue",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, bool):
                raise TypeError(
                    f"{field_name} must be bool, got "
                    f"{type(value).__name__}"
                )

        if self.is_result_lvalue and not self.writes_value:
            raise ValueError(
                "is_result_lvalue=True requires writes_value=True"
            )


@dataclass(frozen=True)
class CExpressionDefinednessContract:
    """
    Proof obligations required for a successful C-expression lowering.

    A successful CExpressionConstraint must not contain unknown or unproven
    definedness facts.  Therefore every field must be True.

    For operations where a particular risk is inapplicable, the derivation
    layer may set that field to True as a vacuous proof.
    """

    no_signed_overflow: bool
    no_divide_by_zero: bool
    shift_count_in_range: bool
    no_signed_left_shift: bool
    preserves_source_modular_arithmetic: bool

    def __post_init__(self) -> None:
        for field_name in (
            "no_signed_overflow",
            "no_divide_by_zero",
            "shift_count_in_range",
            "no_signed_left_shift",
            "preserves_source_modular_arithmetic",
        ):
            value = getattr(self, field_name)

            if not isinstance(value, bool):
                raise TypeError(
                    f"{field_name} must be bool, got "
                    f"{type(value).__name__}"
                )

            if not value:
                raise ValueError(
                    "successful CExpressionDefinednessContract requires "
                    f"{field_name}=True"
                )


@dataclass(frozen=True)
class CExpressionConstraint:
    """
    Fully validated pure C-expression lowering contract.

    This is not final C syntax.  It describes a semantic expression operation
    and the renderer obligations necessary to preserve its type semantics.
    """

    operation_kind: CExpressionOperationKind

    input_bindings: tuple[CExpressionOperandBinding, ...]
    result_binding: CExpressionOperandBinding
    result_type: CExpressionTypeContract

    definedness: CExpressionDefinednessContract

    requires_memory_access: bool = False
    requires_address_computation: bool = False
    requires_barrier: bool = False
    requires_condition_code_read: bool = False
    requires_condition_code_write: bool = False
    requires_implicit_machine_state: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.operation_kind, CExpressionOperationKind):
            raise TypeError(
                "operation_kind must be CExpressionOperationKind, got "
                f"{type(self.operation_kind).__name__}"
            )

        if not isinstance(self.input_bindings, tuple):
            raise TypeError("input_bindings must be a tuple")

        for binding in self.input_bindings:
            if not isinstance(binding, CExpressionOperandBinding):
                raise TypeError(
                    "input_bindings must contain CExpressionOperandBinding"
                )

        if not isinstance(
            self.result_binding,
            CExpressionOperandBinding,
        ):
            raise TypeError(
                "result_binding must be CExpressionOperandBinding"
            )

        if not isinstance(self.result_type, CExpressionTypeContract):
            raise TypeError(
                "result_type must be CExpressionTypeContract"
            )

        if not isinstance(
            self.definedness,
            CExpressionDefinednessContract,
        ):
            raise TypeError(
                "definedness must be CExpressionDefinednessContract"
            )

        for field_name in (
            "requires_memory_access",
            "requires_address_computation",
            "requires_barrier",
            "requires_condition_code_read",
            "requires_condition_code_write",
            "requires_implicit_machine_state",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, bool):
                raise TypeError(
                    f"{field_name} must be bool, got "
                    f"{type(value).__name__}"
                )

        _validate_pure_c_expression_machine_state(self)
        _validate_c_expression_operation_arity(self)
        _validate_c_expression_binding_roles(self)
        _validate_c_expression_operand_bindings(self.input_bindings)
        _validate_c_expression_operand_bindings((self.result_binding,))
        _validate_result_type_consistency(self)
        _validate_operation_type_contract(self)


# ---------------------------------------------------------------------------
# Intrinsic validation.
# ---------------------------------------------------------------------------


def _validate_pure_c_expression_machine_state(
    constraint: CExpressionConstraint,
) -> None:
    forbidden_requirements = {
        "requires_memory_access": constraint.requires_memory_access,
        "requires_address_computation": (
            constraint.requires_address_computation
        ),
        "requires_barrier": constraint.requires_barrier,
        "requires_condition_code_read": (
            constraint.requires_condition_code_read
        ),
        "requires_condition_code_write": (
            constraint.requires_condition_code_write
        ),
        "requires_implicit_machine_state": (
            constraint.requires_implicit_machine_state
        ),
    }

    enabled = tuple(
        name
        for name, is_enabled in forbidden_requirements.items()
        if is_enabled
    )

    if enabled:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_UNSUPPORTED_MACHINE_STATE,
            details={
                "enabled_requirements": enabled,
            },
            message=(
                "pure C expression constraint may not require memory, "
                "address computation, barriers, condition codes, or "
                "implicit machine state"
            ),
        )


def _validate_c_expression_operation_arity(
    constraint: CExpressionConstraint,
) -> None:
    expected_arity = _OPERATION_ARITY.get(constraint.operation_kind)

    if expected_arity is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_UNSUPPORTED_OPERATION,
            details={
                "operation_kind": constraint.operation_kind.value,
            },
            message=(
                "unsupported C expression operation kind: "
                f"{constraint.operation_kind.value}"
            ),
        )

    actual_arity = len(constraint.input_bindings)

    if actual_arity != expected_arity:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_INVALID_OPERATION_ARITY,
            details={
                "operation_kind": constraint.operation_kind.value,
                "expected_arity": expected_arity,
                "actual_arity": actual_arity,
            },
            message=(
                f"{constraint.operation_kind.value} requires "
                f"{expected_arity} input operand(s), got {actual_arity}"
            ),
        )


def _validate_c_expression_binding_roles(
    constraint: CExpressionConstraint,
) -> None:
    """
    Validate that input bindings are read-only expression inputs and that the
    result binding is an assignable write target.

    Input/result aliasing is allowed.  For example, x = x + y is represented
    by an input binding for x and a separate result binding for x, each using
    the same source_operand_index.
    """

    for position, binding in enumerate(constraint.input_bindings):
        if not binding.reads_value:
            raise CExpressionConstraintValidationError(
                TargetConstraintReasonCode.C_EXPRESSION_INVALID_OPERAND_BINDING,
                details={
                    "position": position,
                    "source_operand_index": binding.source_operand_index,
                },
                message=(
                    "C expression input bindings must read a value"
                ),
            )

        if binding.writes_value:
            raise CExpressionConstraintValidationError(
                TargetConstraintReasonCode.C_EXPRESSION_INVALID_OPERAND_BINDING,
                details={
                    "position": position,
                    "source_operand_index": binding.source_operand_index,
                },
                message=(
                    "C expression input bindings may not write a value; "
                    "use a separate result binding for output aliasing"
                ),
            )

        if binding.is_result_lvalue:
            raise CExpressionConstraintValidationError(
                TargetConstraintReasonCode.C_EXPRESSION_INVALID_OPERAND_BINDING,
                details={
                    "position": position,
                    "source_operand_index": binding.source_operand_index,
                },
                message=(
                    "C expression input bindings may not be result lvalues"
                ),
            )

    result = constraint.result_binding

    if not result.writes_value:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_INVALID_RESULT_BINDING,
            details={
                "source_operand_index": result.source_operand_index,
            },
            message="C expression result binding must write a value",
        )

    if not result.is_result_lvalue:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_INVALID_RESULT_BINDING,
            details={
                "source_operand_index": result.source_operand_index,
            },
            message="C expression result binding must be an assignable lvalue",
        )

    if result.reads_value:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_INVALID_RESULT_BINDING,
            details={
                "source_operand_index": result.source_operand_index,
            },
            message=(
                "C expression result binding must not also model a read; "
                "read-modify-write semantics must use a separate input "
                "binding that aliases the result source operand"
            ),
        )


def _validate_c_expression_operand_bindings(
    bindings: tuple[CExpressionOperandBinding, ...],
) -> None:
    for binding in bindings:
        if binding.source_operand_kind not in _PURE_C_EXPRESSION_OPERAND_KINDS:
            raise CExpressionConstraintValidationError(
                TargetConstraintReasonCode.C_EXPRESSION_INVALID_OPERAND_KIND,
                details={
                    "source_operand_index": binding.source_operand_index,
                    "source_operand_kind": (
                        binding.source_operand_kind.value
                    ),
                },
                message=(
                    "pure C expression operand kind is not permitted: "
                    f"{binding.source_operand_kind.value}"
                ),
            )


def _validate_result_type_consistency(
    constraint: CExpressionConstraint,
) -> None:
    if constraint.result_binding.type_contract != constraint.result_type:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_INCONSISTENT_RESULT_TYPE,
            details={
                "result_binding_width_bits": (
                    constraint.result_binding.type_contract.width_bits
                ),
                "result_type_width_bits": (
                    constraint.result_type.width_bits
                ),
                "result_binding_integer_kind": (
                    constraint.result_binding.type_contract.integer_kind.value
                ),
                "result_type_integer_kind": (
                    constraint.result_type.integer_kind.value
                ),
            },
            message=(
                "result_binding.type_contract must exactly match result_type"
            ),
        )


def _validate_operation_type_contract(
    constraint: CExpressionConstraint,
) -> None:
    operation = constraint.operation_kind
    result = constraint.result_type
    operands = constraint.input_bindings

    if operation is CExpressionOperationKind.COPY:
        _validate_copy(operands[0].type_contract, result)
        return

    if operation is CExpressionOperationKind.BIT_NOT:
        _validate_bit_not(operands[0].type_contract, result)
        return

    if operation in {
        CExpressionOperationKind.BIT_AND,
        CExpressionOperationKind.BIT_OR,
        CExpressionOperationKind.BIT_XOR,
    }:
        _validate_bitwise_binary(
            operation,
            operands[0].type_contract,
            operands[1].type_contract,
            result,
        )
        return

    if operation in {
        CExpressionOperationKind.UNSIGNED_ADD,
        CExpressionOperationKind.UNSIGNED_SUB,
        CExpressionOperationKind.UNSIGNED_MUL,
    }:
        _validate_unsigned_arithmetic(
            operation,
            operands[0].type_contract,
            operands[1].type_contract,
            result,
        )
        return

    if operation is CExpressionOperationKind.ZERO_EXTEND:
        _validate_zero_extend(operands[0].type_contract, result)
        return

    if operation is CExpressionOperationKind.TRUNCATE:
        _validate_truncate(operands[0].type_contract, result)
        return

    if operation in {
        CExpressionOperationKind.UNSIGNED_EQUAL,
        CExpressionOperationKind.UNSIGNED_NOT_EQUAL,
        CExpressionOperationKind.UNSIGNED_LESS_THAN,
        CExpressionOperationKind.UNSIGNED_LESS_EQUAL,
        CExpressionOperationKind.UNSIGNED_GREATER_THAN,
        CExpressionOperationKind.UNSIGNED_GREATER_EQUAL,
    }:
        _validate_unsigned_comparison(
            operation,
            operands[0].type_contract,
            operands[1].type_contract,
            result,
        )
        return

    raise CExpressionConstraintValidationError(
        TargetConstraintReasonCode.C_EXPRESSION_UNSUPPORTED_OPERATION,
        details={
            "operation_kind": operation.value,
        },
        message=f"unsupported C expression operation kind: {operation.value}",
    )


def _validate_copy(
    source_type: CExpressionTypeContract,
    result_type: CExpressionTypeContract,
) -> None:
    if source_type != result_type:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.COPY.value,
                "source_width_bits": source_type.width_bits,
                "result_width_bits": result_type.width_bits,
                "source_integer_kind": source_type.integer_kind.value,
                "result_integer_kind": result_type.integer_kind.value,
            },
            message=(
                "copy requires source and result type contracts to match"
            ),
        )


def _validate_bit_not(
    operand_type: CExpressionTypeContract,
    result_type: CExpressionTypeContract,
) -> None:
    if not operand_type.is_raw_bit_pattern:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.BIT_NOT.value,
                "operand_integer_kind": operand_type.integer_kind.value,
            },
            message=(
                "bit_not requires an unsigned fixed-width integer operand"
            ),
        )

    if result_type != operand_type:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.BIT_NOT.value,
                "operand_width_bits": operand_type.width_bits,
                "result_width_bits": result_type.width_bits,
            },
            message=(
                "bit_not result type must exactly match operand type"
            ),
        )


def _validate_bitwise_binary(
    operation: CExpressionOperationKind,
    left_type: CExpressionTypeContract,
    right_type: CExpressionTypeContract,
    result_type: CExpressionTypeContract,
) -> None:
    if not left_type.is_raw_bit_pattern:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "side": "left",
                "integer_kind": left_type.integer_kind.value,
            },
            message=(
                f"{operation.value} requires unsigned fixed-width operands"
            ),
        )

    if not right_type.is_raw_bit_pattern:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "side": "right",
                "integer_kind": right_type.integer_kind.value,
            },
            message=(
                f"{operation.value} requires unsigned fixed-width operands"
            ),
        )

    if left_type != right_type or result_type != left_type:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "left_width_bits": left_type.width_bits,
                "right_width_bits": right_type.width_bits,
                "result_width_bits": result_type.width_bits,
            },
            message=(
                f"{operation.value} requires identical unsigned operand "
                "and result type contracts"
            ),
        )


def _validate_unsigned_arithmetic(
    operation: CExpressionOperationKind,
    left_type: CExpressionTypeContract,
    right_type: CExpressionTypeContract,
    result_type: CExpressionTypeContract,
) -> None:
    if not left_type.is_unsigned_integer:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "side": "left",
                "integer_kind": left_type.integer_kind.value,
            },
            message=(
                f"{operation.value} requires unsigned integer operands"
            ),
        )

    if not right_type.is_unsigned_integer:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "side": "right",
                "integer_kind": right_type.integer_kind.value,
            },
            message=(
                f"{operation.value} requires unsigned integer operands"
            ),
        )

    if not result_type.is_unsigned_integer:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "result_integer_kind": result_type.integer_kind.value,
            },
            message=(
                f"{operation.value} requires an unsigned integer result"
            ),
        )

    if left_type != right_type or result_type != left_type:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "left_width_bits": left_type.width_bits,
                "right_width_bits": right_type.width_bits,
                "result_width_bits": result_type.width_bits,
            },
            message=(
                f"{operation.value} requires identical unsigned operand "
                "and result type contracts"
            ),
        )


def _validate_zero_extend(
    source_type: CExpressionTypeContract,
    result_type: CExpressionTypeContract,
) -> None:
    if not source_type.is_unsigned_integer:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.ZERO_EXTEND.value,
                "source_integer_kind": source_type.integer_kind.value,
            },
            message=(
                "zero_extend requires an unsigned integer source"
            ),
        )

    if not result_type.is_unsigned_integer:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.ZERO_EXTEND.value,
                "result_integer_kind": result_type.integer_kind.value,
            },
            message=(
                "zero_extend requires an unsigned integer result"
            ),
        )

    if result_type.width_bits <= source_type.width_bits:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.ZERO_EXTEND.value,
                "source_width_bits": source_type.width_bits,
                "result_width_bits": result_type.width_bits,
            },
            message=(
                "zero_extend requires result width to be greater than "
                "source width"
            ),
        )

def _validate_truncate(
    source_type: CExpressionTypeContract,
    result_type: CExpressionTypeContract,
) -> None:
    """
    Validate a pure bit-pattern truncation.

    Phase 6C supports only non-boolean raw bit-pattern truncation.  The
    result must be narrower and preserve the source signedness interpretation.

    This validator intentionally operates only on validated C-expression type
    contracts and does not inspect source asm, p-code, lift artifacts, or
    renderer details.
    """

    if not source_type.is_raw_bit_pattern:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.TRUNCATE.value,
                "role": "source",
                "integer_kind": source_type.integer_kind.value,
                "width_bits": source_type.width_bits,
            },
            message=(
                "truncate requires a non-boolean unsigned or signless "
                "raw-bit-pattern source type"
            ),
        )

    if not result_type.is_raw_bit_pattern:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.TRUNCATE.value,
                "role": "result",
                "integer_kind": result_type.integer_kind.value,
                "width_bits": result_type.width_bits,
            },
            message=(
                "truncate requires a non-boolean unsigned or signless "
                "raw-bit-pattern result type"
            ),
        )

    if result_type.width_bits >= source_type.width_bits:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.TRUNCATE.value,
                "source_width_bits": source_type.width_bits,
                "result_width_bits": result_type.width_bits,
            },
            message=(
                "truncate requires result width_bits to be less than "
                "source width_bits"
            ),
        )

    if result_type.signedness is not source_type.signedness:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": CExpressionOperationKind.TRUNCATE.value,
                "source_signedness": source_type.signedness.value,
                "result_signedness": result_type.signedness.value,
            },
            message=(
                "truncate requires result signedness to match "
                "source signedness"
            ),
        )


def _validate_unsigned_comparison(
    operation: CExpressionOperationKind,
    left_type: CExpressionTypeContract,
    right_type: CExpressionTypeContract,
    result_type: CExpressionTypeContract,
) -> None:
    """
    Validate a comparison whose C semantics are explicitly unsigned.

    Both operands must have exactly identical unsigned-integer contracts.
    The result must be the Phase-6C boolean contract.
    """

    if not left_type.is_unsigned_integer:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "side": "left",
                "integer_kind": left_type.integer_kind.value,
                "width_bits": left_type.width_bits,
            },
            message=(
                f"{operation.value} requires a non-boolean unsigned "
                "integer left operand"
            ),
        )

    if not right_type.is_unsigned_integer:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "side": "right",
                "integer_kind": right_type.integer_kind.value,
                "width_bits": right_type.width_bits,
            },
            message=(
                f"{operation.value} requires a non-boolean unsigned "
                "integer right operand"
            ),
        )

    if left_type != right_type:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "left_width_bits": left_type.width_bits,
                "right_width_bits": right_type.width_bits,
                "left_signedness": left_type.signedness.value,
                "right_signedness": right_type.signedness.value,
            },
            message=(
                f"{operation.value} requires identical unsigned "
                "operand type contracts"
            ),
        )

    if not result_type.is_boolean:
        raise CExpressionConstraintValidationError(
            C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE ,
            details={
                "operation_kind": operation.value,
                "result_integer_kind": result_type.integer_kind.value,
                "result_width_bits": result_type.width_bits,
            },
            message=(
                f"{operation.value} requires a boolean result type"
            ),
        )

# ---------------------------------------------------------------------------
# Construction helper.
# ---------------------------------------------------------------------------


def derive_c_expression_constraint(
    *,
    operation_kind: CExpressionOperationKind,
    input_bindings: Iterable[CExpressionOperandBinding],
    result_binding: CExpressionOperandBinding,
    result_type: CExpressionTypeContract,
    definedness: CExpressionDefinednessContract,
    requires_memory_access: bool = False,
    requires_address_computation: bool = False,
    requires_barrier: bool = False,
    requires_condition_code_read: bool = False,
    requires_condition_code_write: bool = False,
    requires_implicit_machine_state: bool = False,
) -> CExpressionConstraint:
    """
    Construct and intrinsically validate a pure C-expression constraint.

    This function is intentionally not the public Phase 6C deriver.

    It does not inspect SourceSemanticModel, TargetLoweringPlan, or
    TargetEnvironment itself.  Instead, the eventual public Phase 6C deriver
    must derive validated operation/type/definedness facts from those three
    allowed inputs and then call this helper.

    Any memory, address, barrier, condition-code, or implicit-machine-state
    requirement is rejected by CExpressionConstraint validation.
    """

    return CExpressionConstraint(
        operation_kind=operation_kind,
        input_bindings=tuple(input_bindings),
        result_binding=result_binding,
        result_type=result_type,
        definedness=definedness,
        requires_memory_access=requires_memory_access,
        requires_address_computation=requires_address_computation,
        requires_barrier=requires_barrier,
        requires_condition_code_read=requires_condition_code_read,
        requires_condition_code_write=requires_condition_code_write,
        requires_implicit_machine_state=requires_implicit_machine_state,
    )

def _is_valid_c_identifier(value: str) -> bool:
    """
    Validate a renderer-facing C identifier.

    This is intentionally only an identifier-shape check.  It does not imply
    that the identifier is globally unique or that it can be emitted without
    additional renderer-level name mangling.
    """
    return bool(
        _C_IDENTIFIER_RE.fullmatch(value)
        and value not in _C_KEYWORDS
    )
def derive_c_expression_constraints(
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    """
    Derive a structured pure-C-expression constraint contract.

    This function is deliberately fail-closed.

    It consumes only:

      * SourceSemanticModel;
      * TargetLoweringPlan;
      * TargetEnvironment.

    It does not inspect raw asm, instruction mnemonics, p-code text, lift
    artifacts, CFG artifacts, renderer internals, IR summaries, blocks, or
    TranslationRuntimeFacts implementation details.

    A successful result is produced only when SourceSemanticModel contains an
    authoritative structured SourceValueOperationModel sufficient to derive:

      * CExpressionOperationKind;
      * input operand roles and source indexes;
      * result operand role and source index;
      * input and result CExpressionTypeContract values;
      * CExpressionDefinednessContract.

    If any such fact is missing, incomplete, non-authoritative, or cannot be
    represented in the Phase-6C pure C-expression subset, this function
    rejects the candidate rather than guessing.
    """

    input_failure = _validate_public_inputs(
        source_model=source_model,
        candidate_plan=candidate_plan,
        target_environment=target_environment,
    )
    if input_failure is not None:
        return input_failure

    if candidate_plan.kind is not TargetLoweringKind.C_EXPRESSION:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_PLAN_KIND_MISMATCH
            ),
            details={
                "expected_kind": TargetLoweringKind.C_EXPRESSION.value,
                "actual_kind": candidate_plan.kind.value,
            },
        )

    environment_failure = _validate_target_environment(
        candidate_plan=candidate_plan,
        target_environment=target_environment,
    )
    if environment_failure is not None:
        return environment_failure

    feature_failure = _validate_candidate_features(
        candidate_plan=candidate_plan,
        target_environment=target_environment,
    )
    if feature_failure is not None:
        return feature_failure

    completeness_failure = _validate_source_completeness(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )
    if completeness_failure is not None:
        return completeness_failure

    shell_failure = _validate_shell_neutrality(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )
    if shell_failure is not None:
        return shell_failure

    source_category_failure = _validate_source_operation_category(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )
    if source_category_failure is not None:
        return source_category_failure

    side_effect_failure = _validate_no_memory_atomic_or_barrier_semantics(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )
    if side_effect_failure is not None:
        return side_effect_failure

    control_flow_failure = _validate_control_flow_and_runtime_semantics(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )
    if control_flow_failure is not None:
        return control_flow_failure

    machine_state_failure = _validate_machine_state_requirements(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )
    if machine_state_failure is not None:
        return machine_state_failure

    operation_or_failure = _derive_authoritative_c_expression_operation(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )
    if isinstance(
        operation_or_failure,
        TargetConstraintDerivationResult,
    ):
        return operation_or_failure

    operation = operation_or_failure

    bindings_or_failure = _derive_c_expression_bindings(
        source_model=source_model,
        candidate_plan=candidate_plan,
        operation=operation,
    )
    if isinstance(
        bindings_or_failure,
        TargetConstraintDerivationResult,
    ):
        return bindings_or_failure

    input_bindings, result_binding = bindings_or_failure

    definedness_or_failure = _derive_authoritative_c_expression_definedness(
        source_model=source_model,
        candidate_plan=candidate_plan,
        operation=operation,
    )
    if isinstance(
        definedness_or_failure,
        TargetConstraintDerivationResult,
    ):
        return definedness_or_failure

    definedness = definedness_or_failure

    try:
        constraint = derive_c_expression_constraint(
            operation_kind=operation.operation_kind,
            input_bindings=input_bindings,
            result_binding=result_binding,
            result_type=operation.result_type,
            definedness=definedness,

            # These must remain false for the pure Phase-6C subset.
            requires_memory_access=False,
            requires_address_computation=False,
            requires_barrier=False,
            requires_condition_code_read=False,
            requires_condition_code_write=False,
            requires_implicit_machine_state=False,
        )
    except CExpressionConstraintValidationError as error:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=error.reason_code,
            details=error.details,
        )

    return TargetConstraintDerivationResult.succeeded(
        target_constraint_model,
    ) 

def _failure(
    *,
    candidate_plan: TargetLoweringPlan | None,
    reason_code: TargetConstraintReasonCode,
    details: Mapping[str, TargetConstraintDetailValue] | None = None,
) -> TargetConstraintDerivationResult:
    return TargetConstraintDerivationResult.failure(
        plan_id=(
            candidate_plan.plan_id
            if isinstance(candidate_plan, TargetLoweringPlan)
            else None
        ),
        reason_codes=(reason_code,),
        details={} if details is None else details,
    )

def _validate_public_inputs(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult | None:
    if not isinstance(source_model, SourceSemanticModel):
        return _failure(
            candidate_plan=None,
            reason_code=TargetConstraintReasonCode.INVALID_SOURCE_MODEL,
            details={
                "actual_type": type(source_model).__name__,
            },
        )

    if not isinstance(candidate_plan, TargetLoweringPlan):
        return _failure(
            candidate_plan=None,
            reason_code=TargetConstraintReasonCode.INVALID_CANDIDATE_PLAN,
            details={
                "actual_type": type(candidate_plan).__name__,
            },
        )

    if not isinstance(target_environment, TargetEnvironment):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.INVALID_TARGET_ENVIRONMENT
            ),
            details={
                "actual_type": type(target_environment).__name__,
            },
        )

    return None

def _validate_target_environment(
    *,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult | None:
    """
    C expression lowering does not itself require GNU inline asm support,
    but it remains constrained by the project's fixed target profile.
    """

    if target_environment.architecture is not TargetArchitecture.X86_64:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_TARGET_UNSUPPORTED
            ),
            details={
                "architecture": target_environment.architecture.value,
            },
        )

    if target_environment.asm_dialect is not TargetAsmDialect.GNU_ATT:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_TARGET_UNSUPPORTED
            ),
            details={
                "asm_dialect": target_environment.asm_dialect.value,
            },
        )

    if target_environment.abi is not TargetAbi.SYSV_AMD64:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_TARGET_UNSUPPORTED
            ),
            details={
                "abi": target_environment.abi.value,
            },
        )

    return None

def _validate_candidate_features(
    *,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult | None:
    available = target_environment.available_features

    missing_required = (
        candidate_plan.required_features - available
    )
    if missing_required:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.PLAN_REQUIRED_FEATURE_MISSING
            ),
            details={
                "feature": sorted(missing_required)[0],
            },
        )

    forbidden_present = (
        candidate_plan.forbidden_features & available
    )
    if forbidden_present:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.PLAN_FORBIDDEN_FEATURE_PRESENT
            ),
            details={
                "feature": sorted(forbidden_present)[0],
            },
        )

    return None

def _validate_source_operation_category(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    operation_kind = source_model.operation.kind

    if operation_kind is SourceOperationKind.REGISTER_ONLY:
        return None

    if operation_kind in (
        SourceOperationKind.LOAD,
        SourceOperationKind.STORE,
        SourceOperationKind.MEMORY_READ_MODIFY_WRITE,
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_MEMORY_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    if operation_kind in (
        SourceOperationKind.ATOMIC_LOAD,
        SourceOperationKind.ATOMIC_STORE,
        SourceOperationKind.ATOMIC_READ_MODIFY_WRITE,
        SourceOperationKind.ATOMIC_COMPARE_EXCHANGE,
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_ATOMIC_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    if operation_kind in (
        SourceOperationKind.COMPILER_BARRIER,
        SourceOperationKind.HARDWARE_BARRIER,
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_BARRIER_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    if operation_kind is SourceOperationKind.CONTROL_FLOW:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_CONTROL_FLOW_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    if operation_kind is SourceOperationKind.CALL:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_CALL_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    if operation_kind is SourceOperationKind.RETURN:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_RETURN_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    if operation_kind in (
        SourceOperationKind.STACK_FRAME,
        SourceOperationKind.HELPER_REQUIRED,
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_HELPER_ABI_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    if operation_kind in (
        SourceOperationKind.OPAQUE,
        SourceOperationKind.UNKNOWN,
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERATION_UNKNOWN
            ),
            details={
                "source_operation_kind": operation_kind.value,
            },
        )

    return _failure(
        candidate_plan=candidate_plan,
        reason_code=(
            TargetConstraintReasonCode.C_EXPRESSION_OPERATION_UNSUPPORTED
        ),
        details={
            "source_operation_kind": operation_kind.value,
        },
    )

def _get_source_operation_kind(
    operation: SourceOperationModel,
) -> SourceOperationKind:
    return operation.kind

@dataclass(frozen=True)
class _DerivedCExpressionOperation:
    """
    Normalized authoritative pure-value operation facts supplied by
    SourceSemanticModel.value_operation.

    This is intentionally not yet a CExpressionConstraint operation contract.

    SourceValueOperationModel provides source-level operation kind, operand
    indexes, widths, and signedness.  It does not currently provide an
    authoritative CExpressionDefinednessContract, nor does it provide the
    complete renderer/type-lowering facts required to prove that the resulting
    C expression is defined under C semantics.

    Therefore this model may be used for validation and diagnostics, but it
    must not by itself be treated as proof that a pure C expression is safe.
    """

    operation_kind: CExpressionOperationKind

    input_source_operand_indexes: tuple[int, ...]
    result_source_operand_index: int

    input_width_bits: tuple[int, ...]
    result_width_bits: int

    input_signedness: tuple[SourceSignedness, ...]
    result_signedness: SourceSignedness


def _derive_authoritative_c_expression_operation(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> _DerivedCExpressionOperation | TargetConstraintDerivationResult:
    """
    Read and validate authoritative source-level pure-value operation facts.

    This function consumes only SourceSemanticModel.value_operation.

    It does not inspect or infer facts from:

      * raw asm;
      * instruction mnemonics;
      * p-code;
      * LiftResult or LiftedInsn;
      * CFG / Block / IR summaries;
      * register allocation;
      * source operand ordering guesses;
      * renderer behavior;
      * host C expression width;
      * TranslationRuntimeFacts implementation.

    This function does not construct CExpressionTypeContract values because
    SourceValueOperationModel does not itself provide enough information to
    prove the complete C type and conversion contract.
    """

    value_operation = source_model.value_operation

    if value_operation is None:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERATION_INCOMPLETE,
            ),
            details={
                "reason": "missing_source_value_operation",
            },
        )

    if not value_operation.complete:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERATION_INCOMPLETE,
            ),
            details={
                "reason": "source_value_operation_incomplete",
                "missing_fact_codes": tuple(
                    value_operation.missing_fact_codes
                ),
            },
        )

    # SourceValueOperationModel.__post_init__ already validates these fields.
    # The checks below are retained as a fail-closed boundary in case an
    # object was constructed through an unsafe deserialization path or future
    # model evolution weakens upstream validation.

    if not isinstance(
        value_operation.operation_kind,
        CExpressionOperationKind,
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERATION_UNKNOWN,
            ),
            details={
                "actual_type": type(
                    value_operation.operation_kind
                ).__name__,
            },
        )

    if not isinstance(
        value_operation.input_source_operand_indexes,
        tuple,
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERANDS_INCOMPLETE,
            ),
            details={
                "reason": "input_source_operand_indexes_not_tuple",
                "actual_type": type(
                    value_operation.input_source_operand_indexes
                ).__name__,
            },
        )

    if not value_operation.input_source_operand_indexes:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERANDS_INCOMPLETE,
            ),
            details={
                "reason": "empty_input_source_operand_indexes",
            },
        )

    if not all(
        isinstance(index, int)
        and not isinstance(index, bool)
        and index >= 0
        for index in value_operation.input_source_operand_indexes
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_BINDING_MISSING,
            ),
            details={
                "reason": "invalid_input_source_operand_index",
            },
        )

    if (
        not isinstance(
            value_operation.result_source_operand_index,
            int,
        )
        or isinstance(
            value_operation.result_source_operand_index,
            bool,
        )
        or value_operation.result_source_operand_index < 0
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_BINDING_MISSING,
            ),
            details={
                "reason": "invalid_result_source_operand_index",
            },
        )

    if not isinstance(value_operation.input_width_bits, tuple):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISSING,
            ),
            details={
                "reason": "input_width_bits_not_tuple",
                "actual_type": type(
                    value_operation.input_width_bits
                ).__name__,
            },
        )

    if (
        len(value_operation.input_source_operand_indexes)
        != len(value_operation.input_width_bits)
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISMATCH,
            ),
            details={
                "input_operand_count": len(
                    value_operation.input_source_operand_indexes
                ),
                "input_width_count": len(
                    value_operation.input_width_bits
                ),
            },
        )

    if not all(
        isinstance(width_bits, int)
        and not isinstance(width_bits, bool)
        and width_bits > 0
        for width_bits in value_operation.input_width_bits
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISSING,
            ),
            details={
                "reason": "invalid_input_width_bits",
            },
        )

    if (
        not isinstance(value_operation.result_width_bits, int)
        or isinstance(value_operation.result_width_bits, bool)
        or value_operation.result_width_bits <= 0
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISSING,
            ),
            details={
                "reason": "invalid_result_width_bits",
            },
        )

    if not isinstance(value_operation.input_signedness, tuple):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_SIGNEDNESS_MISSING,
            ),
            details={
                "reason": "input_signedness_not_tuple",
                "actual_type": type(
                    value_operation.input_signedness
                ).__name__,
            },
        )

    if (
        len(value_operation.input_source_operand_indexes)
        != len(value_operation.input_signedness)
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_SIGNEDNESS_MISSING,
            ),
            details={
                "input_operand_count": len(
                    value_operation.input_source_operand_indexes
                ),
                "input_signedness_count": len(
                    value_operation.input_signedness
                ),
            },
        )

    if not all(
        isinstance(signedness, SourceSignedness)
        for signedness in value_operation.input_signedness
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_SIGNEDNESS_UNSUPPORTED,
            ),
            details={
                "reason": "invalid_input_signedness",
            },
        )

    if not isinstance(
        value_operation.result_signedness,
        SourceSignedness,
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_SIGNEDNESS_UNSUPPORTED,
            ),
            details={
                "reason": "invalid_result_signedness",
                "actual_type": type(
                    value_operation.result_signedness
                ).__name__,
            },
        )

    return _DerivedCExpressionOperation(
        operation_kind=value_operation.operation_kind,
        input_source_operand_indexes=(
            value_operation.input_source_operand_indexes
        ),
        result_source_operand_index=(
            value_operation.result_source_operand_index
        ),
        input_width_bits=value_operation.input_width_bits,
        result_width_bits=value_operation.result_width_bits,
        input_signedness=value_operation.input_signedness,
        result_signedness=value_operation.result_signedness,
    )


def _derive_authoritative_c_expression_definedness(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    operation: _DerivedCExpressionOperation,
) -> CExpressionDefinednessContract | TargetConstraintDerivationResult:
    """
    Fail closed because SourceValueOperationModel currently does not contain
    an authoritative CExpressionDefinednessContract.

    Width and signedness alone are not sufficient to prove C definedness.

    In particular, this phase must not guess the legality of:

      * signed addition, subtraction, multiplication, or negation;
      * signed left shift;
      * shift count range;
      * signed division overflow, including INT_MIN / -1;
      * division or remainder by zero;
      * C integer promotions;
      * usual arithmetic conversions;
      * narrowing conversion semantics;
      * signed-to-unsigned or unsigned-to-signed conversion obligations;
      * boolean result normalization;
      * any operation-specific poison, trap, or undefined behavior rule.

    A future authoritative source model must provide either:

      1. c_expression_definedness:
             CExpressionDefinednessContract

         or

      2. sufficiently structured per-operation semantic facts from which this
         exact contract can be derived without inspecting forbidden inputs and
         without relying on renderer behavior.

    Until then, successful pure C-expression lowering is intentionally
    unavailable.
    """

    del source_model

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode
            .C_EXPRESSION_C_DEFINEDNESS_UNPROVEN,
        ),
        details={
            "operation_kind": operation.operation_kind.value,
            "reason": (
                "source_value_operation_has_no_authoritative_"
                "c_expression_definedness_contract"
            ),
        },
    )

def _derive_c_expression_bindings(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    operation: _DerivedCExpressionOperation,
) -> (
    tuple[
        tuple[CExpressionOperandBinding, ...],
        CExpressionOperandBinding,
    ]
    | TargetConstraintDerivationResult
):
    source_bindings = _get_authoritative_operand_bindings(
        source_model.operands,
    )

    binding_by_index = {
        binding.source_operand_index: binding
        for binding in source_bindings
    }

    if len(binding_by_index) != len(source_bindings):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERANDS_INCOMPLETE
            ),
            details={
                "reason": "duplicate_source_operand_index",
            },
        )

    if (
        len(operation.input_source_operand_indexes)
        != len(operation.input_types)
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERATION_INCOMPLETE
            ),
            details={
                "reason": "input_index_type_arity_mismatch",
            },
        )

    expected_arity = _expected_input_arity(
        operation.operation_kind,
    )
    if len(operation.input_source_operand_indexes) != expected_arity:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERANDS_INCOMPLETE
            ),
            details={
                "operation_kind": operation.operation_kind.value,
                "expected_input_arity": expected_arity,
                "actual_input_arity": len(
                    operation.input_source_operand_indexes
                ),
            },
        )

    if (
        operation.result_source_operand_index
        not in binding_by_index
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_BINDING_MISSING
            ),
            details={
                "source_operand_index": (
                    operation.result_source_operand_index
                ),
                "role": "result",
            },
        )

    input_bindings: list[CExpressionOperandBinding] = []

    for source_operand_index, expected_type in zip(
        operation.input_source_operand_indexes,
        operation.input_types,
        strict=True,
    ):
        source_binding = binding_by_index.get(source_operand_index)
        if source_binding is None:
            return _failure(
                candidate_plan=candidate_plan,
                reason_code=(
                    TargetConstraintReasonCode
                    .C_EXPRESSION_OPERAND_BINDING_MISSING
                ),
                details={
                    "source_operand_index": source_operand_index,
                    "role": "input",
                },
            )

        input_failure = _validate_input_operand_for_c_expression(
            source_binding=source_binding,
            expected_type=expected_type,
            candidate_plan=candidate_plan,
        )
        if input_failure is not None:
            return input_failure

        input_bindings.append(
            CExpressionOperandBinding(
                source_operand_index=source_binding.source_operand_index,
                operand_kind=source_binding.kind,
                type_contract=expected_type,

                # A C expression input binding is a value-read role.
                reads_value=True,
                writes_value=False,
                is_result_lvalue=False,
            )
        )

    result_source_binding = binding_by_index[
        operation.result_source_operand_index
    ]

    result_failure = _validate_result_operand_for_c_expression(
        source_binding=result_source_binding,
        expected_type=operation.result_type,
        candidate_plan=candidate_plan,
    )
    if result_failure is not None:
        return result_failure

    result_binding = CExpressionOperandBinding(
        source_operand_index=result_source_binding.source_operand_index,
        operand_kind=result_source_binding.kind,
        type_contract=operation.result_type,

        # Phase 6C models result assignment as a pure result lvalue write.
        #
        # If an operation semantically reads its destination, that read must
        # appear explicitly as an input binding in the authoritative source
        # value-operation contract.  It must not be inferred from generic
        # source operand metadata.
        reads_value=False,
        writes_value=True,
        is_result_lvalue=True,
    )

    return (
        tuple(input_bindings),
        result_binding,
    )

def _validate_input_operand_for_c_expression(
    *,
    source_binding: SourceOperandBinding,
    expected_type: CExpressionTypeContract,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if not source_binding.reads:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "input_not_readable",
            },
        )

    if source_binding.width_bits is None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISSING
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
            },
        )

    if source_binding.early_clobber:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "early_clobber",
            },
        )

    if source_binding.tied_to_source_operand_index is not None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "tied_operand",
            },
        )

    if source_binding.fixed_register_name is not None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_REGISTER_STATE_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "register": source_binding.fixed_register_name,
            },
        )

    if source_binding.address is not None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_MEMORY_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "address_operand",
            },
        )

    if source_binding.expression is None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_MISSING
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "missing_expression_binding",
            },
        )

    type_failure = _validate_source_operand_type_matches(
        source_binding=source_binding,
        expected_type=expected_type,
        candidate_plan=candidate_plan,
        role="input",
    )
    if type_failure is not None:
        return type_failure

    return None


def _validate_result_operand_for_c_expression(
    *,
    source_binding: SourceOperandBinding,
    expected_type: CExpressionTypeContract,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if not source_binding.writes:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "result_not_writable",
            },
        )

    if source_binding.width_bits is None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISSING
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
            },
        )

    if source_binding.early_clobber:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "early_clobber",
            },
        )

    if source_binding.tied_to_source_operand_index is not None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "tied_operand",
            },
        )

    if source_binding.fixed_register_name is not None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_REGISTER_STATE_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "register": source_binding.fixed_register_name,
            },
        )

    if source_binding.address is not None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_MEMORY_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "address_result",
            },
        )

    if source_binding.lvalue is None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_MISSING
            ),
            details={
                "source_operand_index": source_binding.source_operand_index,
                "reason": "missing_result_lvalue",
            },
        )

    type_failure = _validate_source_operand_type_matches(
        source_binding=source_binding,
        expected_type=expected_type,
        candidate_plan=candidate_plan,
        role="result",
    )
    if type_failure is not None:
        return type_failure

    return None

def _expected_input_arity(
    operation_kind: CExpressionOperationKind,
) -> int:
    if operation_kind in (
        CExpressionOperationKind.COPY,
        CExpressionOperationKind.BIT_NOT,
        CExpressionOperationKind.ZERO_EXTEND,
        CExpressionOperationKind.TRUNCATE,
    ):
        return 1

    if operation_kind in (
        CExpressionOperationKind.BIT_AND,
        CExpressionOperationKind.BIT_OR,
        CExpressionOperationKind.BIT_XOR,
        CExpressionOperationKind.UNSIGNED_ADD,
        CExpressionOperationKind.UNSIGNED_SUB,
        CExpressionOperationKind.UNSIGNED_MUL,
        CExpressionOperationKind.UNSIGNED_EQUAL,
        CExpressionOperationKind.UNSIGNED_NOT_EQUAL,
        CExpressionOperationKind.UNSIGNED_LESS_THAN,
        CExpressionOperationKind.UNSIGNED_LESS_EQUAL,
        CExpressionOperationKind.UNSIGNED_GREATER_THAN,
        CExpressionOperationKind.UNSIGNED_GREATER_EQUAL,
    ):
        return 2

    raise AssertionError(
        f"unhandled CExpressionOperationKind: {operation_kind!r}"
    )

def _derive_definedness_contract(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    operation: _DerivedCExpressionOperation,
    input_bindings: tuple[CExpressionOperandBinding, ...],
    result_binding: CExpressionOperandBinding,
) -> (
    CExpressionDefinednessContract
    | TargetConstraintDerivationResult
):
    """
    For the current CExpressionOperationKind set, no division and no shift
    operation exists. Therefore the shift/division booleans are proven
    vacuously only after operation kind and type contracts are validated.

    This function must remain fail-closed if a future operation enum adds:
      * signed arithmetic;
      * division/modulo;
      * shift;
      * pointer arithmetic;
      * floating point;
      * calls;
      * memory operations.
    """

    if operation.operation_kind not in set(CExpressionOperationKind):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_OPERATION_UNKNOWN
            ),
            details={
                "operation_kind": str(operation.operation_kind),
            },
        )

    modular_failure = _validate_modular_arithmetic_contract(
        source_model=source_model,
        candidate_plan=candidate_plan,
        operation=operation,
        input_bindings=input_bindings,
        result_binding=result_binding,
    )
    if modular_failure is not None:
        return modular_failure

    sequencing_failure = _validate_no_unsequenced_side_effects(
        source_model=source_model,
        candidate_plan=candidate_plan,
        operation=operation,
        input_bindings=input_bindings,
        result_binding=result_binding,
    )
    if sequencing_failure is not None:
        return sequencing_failure

    return CExpressionDefinednessContract(
        no_signed_overflow=True,
        no_divide_by_zero=True,
        no_invalid_shift_count=True,
        no_signed_left_shift=True,
        no_implementation_defined_signed_shift=True,
        no_unsequenced_side_effect=True,
        preserves_source_modular_arithmetic=True,
    )

def _validate_source_completeness(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    operation = source_model.operation
    operands = source_model.operands

    if not operation.complete:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .SOURCE_OPERATION_FACTS_INCOMPLETE
            ),
            details={
                "reason": "source_operation_incomplete",
            },
        )

    if not operands.complete:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .SOURCE_OPERAND_FACTS_INCOMPLETE
            ),
            details={
                "missing_fact_code": (
                    operands.missing_fact_codes[0]
                    if operands.missing_fact_codes
                    else "unknown"
                ),
            },
        )

    if operation.has_return is None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .SOURCE_OPERATION_FACTS_INCOMPLETE
            ),
            details={
                "missing_fact": "has_return",
            },
        )

    if operation.may_trap is None:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .SOURCE_OPERATION_FACTS_INCOMPLETE
            ),
            details={
                "missing_fact": "may_trap",
            },
        )

    return None

def _validate_no_memory_atomic_or_barrier_semantics(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    operation = source_model.operation

    if operation.reads_memory or operation.writes_memory:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_MEMORY_UNSUPPORTED
            ),
            details={
                "reads_memory": operation.reads_memory,
                "writes_memory": operation.writes_memory,
                "source_operation_kind": operation.kind.value,
            },
        )

    if operation.kind in (
        SourceOperationKind.ATOMIC_LOAD,
        SourceOperationKind.ATOMIC_STORE,
        SourceOperationKind.ATOMIC_READ_MODIFY_WRITE,
        SourceOperationKind.ATOMIC_COMPARE_EXCHANGE,
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_ATOMIC_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation.kind.value,
            },
        )

    if operation.kind in (
        SourceOperationKind.COMPILER_BARRIER,
        SourceOperationKind.HARDWARE_BARRIER,
    ):
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_BARRIER_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation.kind.value,
            },
        )

    return None

def _validate_control_flow_and_runtime_semantics(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    operation = source_model.operation

    if operation.has_control_flow:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_CONTROL_FLOW_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation.kind.value,
            },
        )

    if operation.has_call:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_CALL_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation.kind.value,
            },
        )

    if operation.has_return:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_RETURN_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation.kind.value,
            },
        )

    if operation.may_trap:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode.C_EXPRESSION_MAY_TRAP_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation.kind.value,
            },
        )

    if operation.requires_helper_abi_contract:
        return _failure(
            candidate_plan=candidate_plan,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_HELPER_ABI_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation.kind.value,
            },
        )

    return None

@dataclass(frozen=True)
class SourceValueOperationModel:
    operation_kind: CExpressionOperationKind

    input_source_operand_indexes: tuple[int, ...]
    result_source_operand_index: int

    input_width_bits: tuple[int, ...]
    result_width_bits: int

    input_signedness: tuple[SourceSignedness, ...]
    result_signedness: SourceSignedness

    # 建议新增：上游已经证明的 C type contract。
    input_type_contracts: tuple[CExpressionTypeContract, ...] = ()
    result_type_contract: CExpressionTypeContract | None = None

    # 建议新增：上游已经证明的 C definedness contract。
    c_expression_definedness: CExpressionDefinednessContract | None = None

    complete: bool = False
    missing_fact_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(
            self.operation_kind,
            CExpressionOperationKind,
        ):
            raise TypeError(
                "operation_kind must be "
                "CExpressionOperationKind"
            )

        if not self.input_source_operand_indexes:
            raise ValueError(
                "input_source_operand_indexes must not be empty"
            )

        if not all(
            isinstance(index, int)
            for index in self.input_source_operand_indexes
        ):
            raise TypeError(
                "input_source_operand_indexes must contain ints"
            )

        if not isinstance(self.result_source_operand_index, int):
            raise TypeError(
                "result_source_operand_index must be int"
            )

        if (
            len(self.input_source_operand_indexes)
            != len(self.input_width_bits)
        ):
            raise ValueError(
                "input_source_operand_indexes and input_width_bits "
                "must have equal length"
            )

        if (
            len(self.input_source_operand_indexes)
            != len(self.input_signedness)
        ):
            raise ValueError(
                "input_source_operand_indexes and input_signedness "
                "must have equal length"
            )

        if not all(
            isinstance(width_bits, int) and width_bits > 0
            for width_bits in self.input_width_bits
        ):
            raise ValueError(
                "input_width_bits must contain positive ints"
            )

        if (
            not isinstance(self.result_width_bits, int)
            or self.result_width_bits <= 0
        ):
            raise ValueError(
                "result_width_bits must be a positive int"
            )

        if not all(
            isinstance(signedness, SourceSignedness)
            for signedness in self.input_signedness
        ):
            raise TypeError(
                "input_signedness must contain SourceSignedness"
            )

        if not isinstance(
            self.result_signedness,
            SourceSignedness,
        ):
            raise TypeError(
                "result_signedness must be SourceSignedness"
            )

        if not isinstance(self.complete, bool):
            raise TypeError("complete must be bool")

        if not self.complete and not self.missing_fact_codes:
            raise ValueError(
                "incomplete SourceValueOperationModel must provide "
                "missing_fact_codes"
            )

def _phase6c_failure(
    *,
    plan_id: str | None,
    reason_code: TargetConstraintReasonCode,
    details: dict[str, object] | None = None,
) -> TargetConstraintDerivationResult:
    """
    Construct one deterministic fail-closed Phase 6C failure result.

    Callers must branch on reason_codes, never on details text.
    """
    return TargetConstraintDerivationResult.failure(
        plan_id=plan_id,
        reason_codes=(reason_code,),
        details={} if details is None else details,
    )


def _validate_c_expression_source_model(
    *,
    source_model: SourceSemanticModel,
    plan_id: str | None,
) -> TargetConstraintDerivationResult | None:
    """
    Validate the top-level source model object before consuming its facts.

    This helper intentionally validates only facts represented by the DTOs
    supplied to Phase 6C.  It does not inspect asm text, IR, p-code,
    instruction mnemonics, or runtime implementation internals.
    """
    if not isinstance(source_model, SourceSemanticModel):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode.INVALID_SOURCE_MODEL
            ),
            details={
                "actual_type": type(source_model).__name__,
            },
        )

    return None


def _validate_c_expression_operand_model(
    *,
    operand_model: SourceOperandModel,
    plan_id: str | None,
) -> TargetConstraintDerivationResult | None:
    """
    Validate availability of authoritative source operand facts.

    Phase 6C must fail closed when the operand model is incomplete because
    operand binding, type, width, tied-operand, and output semantics cannot
    safely be guessed.
    """
    if not isinstance(operand_model, SourceOperandModel):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode.INVALID_SOURCE_MODEL
            ),
            details={
                "field": "operands",
                "actual_type": type(operand_model).__name__,
            },
        )

    if not operand_model.complete:
        missing_fact_codes = ",".join(
            operand_model.missing_fact_codes
        )

        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERANDS_INCOMPLETE
            ),
            details={
                "missing_fact_codes": missing_fact_codes,
            },
        )

    return None


def _validate_c_expression_operation_model(
    *,
    operation_model: SourceOperationModel,
    plan_id: str | None,
) -> TargetConstraintDerivationResult | None:
    """
    Validate completeness of SourceOperationModel.

    This helper does not derive CExpressionOperationKind.  It only proves
    whether the coarse source-operation facts required for C-expression
    lowering are complete.
    """
    if not isinstance(operation_model, SourceOperationModel):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode.INVALID_SOURCE_MODEL
            ),
            details={
                "field": "operation",
                "actual_type": type(operation_model).__name__,
            },
        )

    if not operation_model.complete:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERATION_INCOMPLETE
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
                "missing_fact": "operation.complete",
            },
        )

    if operation_model.has_return is None:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .SOURCE_OPERATION_FACTS_INCOMPLETE
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
                "missing_fact": "has_return",
            },
        )

    if operation_model.may_trap is None:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .SOURCE_OPERATION_FACTS_INCOMPLETE
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
                "missing_fact": "may_trap",
            },
        )

    return None


def _validate_c_expression_operation_semantics(
    *,
    operation_model: SourceOperationModel,
    plan_id: str | None,
) -> TargetConstraintDerivationResult | None:
    """
    Reject source operation semantics that cannot be represented by the
    current pure structured C-expression subset.

    Supported C-expression candidates must be:

      * memory-neutral;
      * non-atomic;
      * non-control-flow;
      * call-free;
      * return-free;
      * known not to trap;
      * independent of a helper ABI contract.

    The caller must invoke _validate_c_expression_operation_model() first.
    """
    if operation_model.reads_memory or operation_model.writes_memory:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_MEMORY_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
                "reads_memory": operation_model.reads_memory,
                "writes_memory": operation_model.writes_memory,
            },
        )

    if operation_model.has_control_flow:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_CONTROL_FLOW_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
            },
        )

    if operation_model.has_call:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_CALL_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
            },
        )

    if operation_model.has_return:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_RETURN_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
            },
        )

    if operation_model.may_trap:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_MAY_TRAP_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
            },
        )

    if operation_model.requires_helper_abi_contract:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_HELPER_ABI_UNSUPPORTED
            ),
            details={
                "source_operation_kind": operation_model.kind.value,
            },
        )

    return None


def _validate_c_expression_input_binding(
    *,
    expression: SourceExpressionBinding | None,
    plan_id: str | None,
    source_operand_index: int,
    require_repeatable: bool,
) -> TargetConstraintDerivationResult | None:
    """
    Validate one source-level input expression binding.

    Input expressions used by C-expression lowering must have:

      * a stable expression identity;
      * an authoritative C type identity;
      * no side effects;
      * repeatability when the generated C operation may evaluate them
        more than once.

    `require_repeatable` must be True whenever a future rendering form can
    reference this expression multiple times.
    """
    if expression is None:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_MISSING
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
            },
        )

    if not isinstance(expression, SourceExpressionBinding):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
                "actual_type": type(expression).__name__,
            },
        )

    if (
        not isinstance(expression.expression_id, str)
        or not expression.expression_id.strip()
        or expression.expression_id != expression.expression_id.strip()
    ):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
                "invalid_field": "expression_id",
            },
        )

    if (
        expression.c_type_id is None
        or not isinstance(expression.c_type_id, str)
        or not expression.c_type_id.strip()
        or expression.c_type_id != expression.c_type_id.strip()
    ):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
                "missing_field": "c_type_id",
            },
        )

    if not isinstance(expression.is_side_effect_free, bool):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
                "invalid_field": "is_side_effect_free",
            },
        )

    if not expression.is_side_effect_free:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_C_DEFINEDNESS_UNPROVEN
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
                "reason": "input_expression_has_side_effects",
            },
        )

    if not isinstance(expression.is_repeatable, bool):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
                "invalid_field": "is_repeatable",
            },
        )

    if require_repeatable and not expression.is_repeatable:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_C_DEFINEDNESS_UNPROVEN
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "expression",
                "reason": "input_expression_not_repeatable",
            },
        )

    return None


def _validate_c_expression_output_binding(
    *,
    lvalue: SourceLvalueBinding | None,
    plan_id: str | None,
    source_operand_index: int,
) -> TargetConstraintDerivationResult | None:
    """
    Validate one source-level result lvalue binding.

    C-expression lowering requires a stable, typed, modifiable output lvalue.
    """
    if lvalue is None:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_MISSING
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "lvalue",
            },
        )

    if not isinstance(lvalue, SourceLvalueBinding):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "lvalue",
                "actual_type": type(lvalue).__name__,
            },
        )

    if (
        not isinstance(lvalue.lvalue_id, str)
        or not lvalue.lvalue_id.strip()
        or lvalue.lvalue_id != lvalue.lvalue_id.strip()
    ):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "lvalue",
                "invalid_field": "lvalue_id",
            },
        )

    if (
        lvalue.c_type_id is None
        or not isinstance(lvalue.c_type_id, str)
        or not lvalue.c_type_id.strip()
        or lvalue.c_type_id != lvalue.c_type_id.strip()
    ):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "lvalue",
                "missing_field": "c_type_id",
            },
        )

    if not isinstance(lvalue.is_modifiable, bool):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "lvalue",
                "invalid_field": "is_modifiable",
            },
        )

    if not lvalue.is_modifiable:
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED
            ),
            details={
                "source_operand_index": source_operand_index,
                "binding_kind": "lvalue",
                "reason": "output_lvalue_not_modifiable",
            },
        )

    return None


def _validate_c_expression_input_bindings(
    *,
    expressions: Iterable[
        tuple[int, SourceExpressionBinding | None]
    ],
    plan_id: str | None,
    require_repeatable: bool,
) -> TargetConstraintDerivationResult | None:
    """
    Validate a deterministic sequence of input expression bindings.

    The iterable must yield:

        (source_operand_index, expression_binding)

    in source semantic operand order.
    """
    for source_operand_index, expression in expressions:
        result = _validate_c_expression_input_binding(
            expression=expression,
            plan_id=plan_id,
            source_operand_index=source_operand_index,
            require_repeatable=require_repeatable,
        )
        if result is not None:
            return result

    return None


def _validate_c_expression_integer_kind(
    *,
    integer_kind: CExpressionIntegerKind,
    plan_id: str | None,
    source_operand_index: int,
    allow_boolean: bool,
) -> TargetConstraintDerivationResult | None:
    """
    Validate an abstract C integer category for a derived expression contract.

    Unsigned modular arithmetic operations require UNSIGNED_INTEGER.
    BOOLEAN is permitted only for operations whose result contract explicitly
    allows a boolean result, normally comparisons.
    """
    if not isinstance(integer_kind, CExpressionIntegerKind):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE
            ),
            details={
                "source_operand_index": source_operand_index,
                "actual_type": type(integer_kind).__name__,
            },
        )

    if integer_kind is CExpressionIntegerKind.UNSIGNED_INTEGER:
        return None

    if (
        integer_kind is CExpressionIntegerKind.BOOLEAN
        and allow_boolean
    ):
        return None

    return _phase6c_failure(
        plan_id=plan_id,
        reason_code=(
            TargetConstraintReasonCode
            .C_EXPRESSION_OPERAND_SIGNEDNESS_UNSUPPORTED
        ),
        details={
            "source_operand_index": source_operand_index,
            "integer_kind": integer_kind.value,
            "allow_boolean": allow_boolean,
        },
    )


def _validate_c_expression_source_signedness(
    *,
    signedness: SourceSignedness,
    plan_id: str | None,
    source_operand_index: int,
    allow_signless: bool,
) -> TargetConstraintDerivationResult | None:
    """
    Validate source signedness for an operation that will be rendered using
    C unsigned integer semantics.

    SIGNED is rejected because a signed source interpretation cannot be
    silently converted into unsigned modular arithmetic without a separate,
    authoritative operation-level proof.

    UNKNOWN is always rejected.

    SIGNLESS may be accepted only when the authoritative value-operation
    contract explicitly proves that signedness is irrelevant.
    """
    if not isinstance(signedness, SourceSignedness):
        return _phase6c_failure(
            plan_id=plan_id,
            reason_code=(
                TargetConstraintReasonCode
                .C_EXPRESSION_OPERAND_SIGNEDNESS_MISSING
            ),
            details={
                "source_operand_index": source_operand_index,
                "actual_type": type(signedness).__name__,
            },
        )

    if signedness is SourceSignedness.UNSIGNED:
        return None

    if (
        signedness is SourceSignedness.SIGNLESS
        and allow_signless
    ):
        return None

    if signedness is SourceSignedness.UNKNOWN:
        reason_code = (
            TargetConstraintReasonCode
            .C_EXPRESSION_OPERAND_SIGNEDNESS_MISSING
        )
    else:
        reason_code = (
            TargetConstraintReasonCode
            .C_EXPRESSION_OPERAND_SIGNEDNESS_UNSUPPORTED
        )

    return _phase6c_failure(
        plan_id=plan_id,
        reason_code=reason_code,
        details={
            "source_operand_index": source_operand_index,
            "signedness": signedness.value,
            "allow_signless": allow_signless,
        },
    )
def _validate_shell_neutrality(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> Optional[TargetConstraintDerivationResult]:
    """
    Fail closed because current source DTOs do not express shell neutrality.
    """

    del source_model

    return _failure(
        candidate_plan=candidate_plan,
        reason_code=(
            TargetConstraintReasonCode
            .C_EXPRESSION_SHELL_NEUTRALITY_UNPROVEN
        ),
        details={
            "reason": (
                "No authoritative source semantic fact proves that the "
                "candidate has no inline-asm/compiler-shell semantics."
            ),
        },
    )


def _validate_machine_state_requirements(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> Optional[TargetConstraintDerivationResult]:
    """
    Fail closed because current source DTOs do not express hidden machine-state
    or preservation requirements.
    """

    del source_model

    return _failure(
        candidate_plan=candidate_plan,
        reason_code=(
            TargetConstraintReasonCode
            .C_EXPRESSION_MACHINE_STATE_REQUIREMENTS_UNPROVEN
        ),
        details={
            "reason": (
                "No authoritative source semantic fact proves that the "
                "candidate has no hidden machine-state, fixed-register, "
                "condition-code, or preservation requirements."
            ),
        },
    )
#abstract

def _get_authoritative_operand_bindings(
    operands: SourceOperandModel,
) -> tuple[SourceOperandBinding, ...]:
    return operands.operands

__all__ = (
    "CExpressionConstraint",
    "CExpressionConstraintValidationError",
    "CExpressionOperandBinding",
    "CExpressionOperationKind",
    "CExpressionTypeContract",
    "derive_c_expression_constraints",
    "is_c_expression_operation_kind",
    "validate_c_expression_constraint",
    "validate_c_expression_operand_bindings",
)