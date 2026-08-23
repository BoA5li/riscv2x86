from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable, FrozenSet, Iterable, Mapping, Tuple, Optional

from .plan_types import (
    TargetLoweringKind,
    TargetLoweringPlan,
)
from .source_model import (
    SourceBarrierScope,
    SourceMemoryOrdering,
    SourceSemanticModel,
    SourceSignedness,
)
from .target_register_policy import (
    POLICY_VERSION,
    is_forbidden_host_stack_frame_register,
)


# ============================================================================
# Phase 6C-0: Target constraint derivation skeleton
#
# This module intentionally does NOT:
#
#   * rescan AsmFragment;
#   * rescan IRSummary / Block / CFGResult;
#   * inspect raw p-code;
#   * inspect raw asm text;
#   * infer semantics from mnemonics;
#   * infer operand bindings from shell ordering;
#   * infer operand widths from XLEN or expression text;
#   * render GNU inline asm;
#   * generate raw GNU asm constraints such as "r", "m", "+r", etc.;
#   * allocate x86 registers;
#   * approve a lowering candidate;
#   * prove source semantics equivalent to target semantics.
#
# The authoritative Phase-6 source input is SourceSemanticModel.
#
# SourceSemanticModel.runtime_facts is intentionally treated as authoritative
# but opaque in 6C-0. Later 6C subphases may consume validated runtime facts
# through a dedicated RuntimeFactStatus accessor; they must never reconstruct:
#
#   * RISC-V register -> GNU operand index;
#   * GNU operand index -> host expression width.
# ============================================================================


class TargetArchitecture(str, Enum):
    X86_64 = "x86_64"


class TargetAsmDialect(str, Enum):
    GNU_ATT = "gnu_att"


class TargetAbi(str, Enum):
    SYSV_AMD64 = "sysv_amd64"


class TargetOperandRole(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
    READ_WRITE = "read_write"


class TargetOperandClass(str, Enum):
    """
    Structured target operand classes.

    This is deliberately not raw GNU inline-asm constraint text.

    Future phases may map:

        GENERAL_REGISTER -> "r"
        MEMORY           -> "m"
        IMMEDIATE        -> "i"

    but Phase 6C-0 must not emit such strings.
    """

    GENERAL_REGISTER = "general_register"
    MEMORY = "memory"
    IMMEDIATE = "immediate"

class TargetConstraintReasonCode(str, Enum):
    """
    Stable structured reason codes for Phase 6C.

    These codes are intended for:

      * diagnostics;
      * test assertions;
      * Phase 6E candidate rejection;
      * stable reporting;
      * future audit logs.

    Callers must not depend on human-readable exception messages.

    Naming policy:

      * enum member names are stable programmatic identifiers;
      * enum values are stable serialized/reporting identifiers;
      * details provide human-readable or value-specific diagnostics;
      * callers must branch on reason codes, never on detail text.
    """

    # ------------------------------------------------------------------
    # Public input and target-environment validation.
    # ------------------------------------------------------------------

    INVALID_SOURCE_MODEL = "phase6c.invalid_source_model"
    INVALID_CANDIDATE_PLAN = "phase6c.invalid_candidate_plan"
    INVALID_TARGET_ENVIRONMENT = "phase6c.invalid_target_environment"

    UNSUPPORTED_TARGET_ARCHITECTURE = (
        "phase6c.unsupported_target_architecture"
    )
    UNSUPPORTED_ASM_DIALECT = "phase6c.unsupported_asm_dialect"
    UNSUPPORTED_TARGET_ABI = "phase6c.unsupported_target_abi"

    GNU_INLINE_ASM_UNAVAILABLE = "phase6c.gnu_inline_asm_unavailable"
    HOST_STACK_FRAME_FIXED_REGISTER_FORBIDDEN = "phase6c.host_stack_frame_fixed_register_forbidden"

    PLAN_REQUIRED_FEATURE_MISSING = (
        "phase6c.plan_required_feature_missing"
    )
    PLAN_FORBIDDEN_FEATURE_PRESENT = (
        "phase6c.plan_forbidden_feature_present"
    )

    EXPLICIT_UNSUPPORTED_PLAN = "phase6c.explicit_unsupported_plan"
    UNKNOWN_PLAN_KIND = "phase6c.unknown_plan_kind"

    # ------------------------------------------------------------------
    # Generic plan-kind implementation status.
    # ------------------------------------------------------------------

    C_STRUCTURED_NOT_IMPLEMENTED = (
        "phase6c.c_structured_not_implemented"
    )
    C_BUILTIN_NOT_IMPLEMENTED = (
        "phase6c.c_builtin_not_implemented"
    )
    X86_GNU_INLINE_ASM_NOT_IMPLEMENTED = (
        "phase6c.x86_gnu_inline_asm_not_implemented"
    )
    X86_ATOMIC_NOT_IMPLEMENTED = (
        "phase6c.x86_atomic_not_implemented"
    )
    X86_BARRIER_NOT_IMPLEMENTED = (
        "phase6c.x86_barrier_not_implemented"
    )
    HELPER_CALL_NOT_IMPLEMENTED = (
        "phase6c.helper_call_not_implemented"
    )
    PRIVILEGED_RUNTIME_REGISTRY_MISSING = (
        "phase6c.privileged_runtime_registry_missing"
    )
    PRIVILEGED_RUNTIME_CONTRACT_MISSING = (
        "phase6c.privileged_runtime_contract_missing"
    )
    PRIVILEGED_RUNTIME_SOURCE_INCOMPLETE = (
        "phase6c.privileged_runtime_source_incomplete"
    )
    PRIVILEGED_FUNCTIONAL_POLICY_DISABLED = (
        "phase6c.privileged_functional_policy_disabled"
    )
    PRIVILEGED_FUNCTIONAL_SOURCE_INCOMPLETE = (
        "phase6c.privileged_functional_source_incomplete"
    )
    PRIVILEGED_FUNCTIONAL_REGISTRY_MISSING = (
        "phase6c.privileged_functional_registry_missing"
    )
    PRIVILEGED_FUNCTIONAL_CONTRACT_MISSING = (
        "phase6c.privileged_functional_contract_missing"
    )
    STRUCTURED_CONTROL_FLOW_NOT_IMPLEMENTED = (
        "phase6c.structured_control_flow_not_implemented"
    )

    # ------------------------------------------------------------------
    # Legacy / compatibility C-expression reason codes.
    #
    # Keep these values stable for existing callers and historical reports.
    # New Phase 6C-2 C-expression derivation should prefer the more precise
    # C_EXPRESSION_* codes below whenever applicable.
    # ------------------------------------------------------------------

    C_EXPRESSION_NOT_IMPLEMENTED = (
        "phase6c.c_expression_not_implemented"
    )
    C_EXPRESSION_UNSUPPORTED_OPERATION = (
        "phase6c.c_expression_unsupported_operation"
    )
    C_EXPRESSION_CONSTRAINT_INVALID = (
        "phase6c.c_expression_constraint_invalid"
    )
    C_EXPRESSION_DEFINEDNESS_UNPROVEN = (
        "phase6c.c_expression_definedness_unproven"
    )
    C_EXPRESSION_MEMORY_EFFECT_UNSUPPORTED = (
        "phase6c.c_expression_memory_effect_unsupported"
    )
    C_EXPRESSION_BARRIER_UNSUPPORTED = (
        "phase6c.c_expression_barrier_unsupported"
    )
    C_EXPRESSION_IMPLICIT_STATE_UNSUPPORTED = (
        "phase6c.c_expression_implicit_state_unsupported"
    )
    C_EXPRESSION_CONTROL_FLOW_UNSUPPORTED = (
        "phase6c.c_expression_control_flow_unsupported"
    )
    C_EXPRESSION_CONDITION_CODES_UNSUPPORTED = (
        "phase6c.c_expression_condition_codes_unsupported"
    )
    C_EXPRESSION_BINDING_UNAVAILABLE = (
        "phase6c.c_expression_binding_unavailable"
    )
    C_EXPRESSION_TYPE_CONTRACT_UNAVAILABLE = (
        "phase6c.c_expression_type_contract_unavailable"
    )

    # ------------------------------------------------------------------
    # Phase 6C-2 structured C-expression contract validation.
    # ------------------------------------------------------------------

    C_EXPRESSION_PLAN_KIND_MISMATCH = (
        "phase6c.c_expression_plan_kind_mismatch"
    )

    C_EXPRESSION_SOURCE_INCOMPLETE = (
        "phase6c.c_expression_source_incomplete"
    )

    C_EXPRESSION_RUNTIME_FACTS_UNAVAILABLE = (
        "phase6c.c_expression_runtime_facts_unavailable"
    )

    C_EXPRESSION_OPERATION_INCOMPLETE = (
        "phase6c.c_expression_operation_incomplete"
    )

    C_EXPRESSION_OPERATION_UNSUPPORTED = (
        "phase6c.c_expression_operation_unsupported"
    )

    C_EXPRESSION_OPERATION_UNKNOWN = (
        "phase6c.c_expression_operation_unknown"
    )

    C_EXPRESSION_SHELL_NOT_NEUTRAL = (
        "phase6c.c_expression_shell_not_neutral"
    )

    C_EXPRESSION_MEMORY_UNSUPPORTED = (
        "phase6c.c_expression_memory_unsupported"
    )

    C_EXPRESSION_MEMORY_UNKNOWN = (
        "phase6c.c_expression_memory_unknown"
    )

    C_EXPRESSION_ATOMIC_UNSUPPORTED = (
        "phase6c.c_expression_atomic_unsupported"
    )

    C_EXPRESSION_CALL_UNSUPPORTED = (
        "phase6c.c_expression_call_unsupported"
    )

    C_EXPRESSION_RETURN_UNSUPPORTED = (
        "phase6c.c_expression_return_unsupported"
    )

    C_EXPRESSION_MAY_TRAP_UNSUPPORTED = (
        "phase6c.c_expression_may_trap_unsupported"
    )

    C_EXPRESSION_HELPER_ABI_UNSUPPORTED = (
        "phase6c.c_expression_helper_abi_unsupported"
    )

    C_EXPRESSION_MICROARCH_UNSUPPORTED = (
        "phase6c.c_expression_microarch_unsupported"
    )

    C_EXPRESSION_REGISTER_STATE_UNSUPPORTED = (
        "phase6c.c_expression_register_state_unsupported"
    )

    C_EXPRESSION_PRESERVATION_UNSUPPORTED = (
        "phase6c.c_expression_preservation_unsupported"
    )

    C_EXPRESSION_OPERANDS_INCOMPLETE = (
        "phase6c.c_expression_operands_incomplete"
    )

    C_EXPRESSION_OPERAND_WIDTH_MISSING = (
        "phase6c.c_expression_operand_width_missing"
    )

    C_EXPRESSION_OPERAND_WIDTH_MISMATCH = (
        "phase6c.c_expression_operand_width_mismatch"
    )

    C_EXPRESSION_OPERAND_SIGNEDNESS_MISSING = (
        "phase6c.c_expression_operand_signedness_missing"
    )

    C_EXPRESSION_OPERAND_SIGNEDNESS_UNSUPPORTED = (
        "phase6c.c_expression_operand_signedness_unsupported"
    )

    C_EXPRESSION_OPERAND_BINDING_MISSING = (
        "phase6c.c_expression_operand_binding_missing"
    )

    C_EXPRESSION_OPERAND_BINDING_UNSUPPORTED = (
        "phase6c.c_expression_operand_binding_unsupported"
    )

    C_EXPRESSION_MULTIPLE_OUTPUTS_UNSUPPORTED = (
        "phase6c.c_expression_multiple_outputs_unsupported"
    )

    C_EXPRESSION_C_DEFINEDNESS_UNPROVEN = (
        "phase6c.c_expression_c_definedness_unproven"
    )

    C_EXPRESSION_SIGNED_OVERFLOW_RISK = (
        "phase6c.c_expression_signed_overflow_risk"
    )

    C_EXPRESSION_SHIFT_SEMANTICS_UNSUPPORTED = (
        "phase6c.c_expression_shift_semantics_unsupported"
    )

    C_EXPRESSION_DIVISION_SEMANTICS_UNSUPPORTED = (
        "phase6c.c_expression_division_semantics_unsupported"
    )

    C_EXPRESSION_RESULT_CONTRACT_INVALID = (
        "phase6c.c_expression_result_contract_invalid"
    )

    # ------------------------------------------------------------------
    # Shared source-fact completeness validation.
    # ------------------------------------------------------------------

    INTERNAL_INVARIANT_VIOLATION = (
        "phase6c.internal_invariant_violation"
    )

    SOURCE_OPERAND_FACTS_INCOMPLETE = (
        "phase6c.source_operand_facts_incomplete"
    )
    SOURCE_OPERATION_FACTS_INCOMPLETE = (
        "phase6c.source_operation_facts_incomplete"
    )
    SOURCE_ATOMIC_FACTS_INCOMPLETE = (
        "phase6c.source_atomic_facts_incomplete"
    )
    SOURCE_BARRIER_FACTS_INCOMPLETE = (
        "phase6c.source_barrier_facts_incomplete"
    )
    SOURCE_IMPLICIT_STATE_FACTS_INCOMPLETE = (
        "phase6c.source_implicit_state_facts_incomplete"
    )
    SOURCE_CONTROL_FLOW_FACTS_INCOMPLETE = (
        "phase6c.source_control_flow_facts_incomplete"
    )
    SOURCE_SHELL_FACTS_INCOMPLETE = (
        "phase6c.source_shell_facts_incomplete"
    )
    SOURCE_HELPER_ABI_FACTS_INCOMPLETE = (
        "phase6c.source_helper_abi_facts_incomplete"
    )

    # ------------------------------------------------------------------
    # Shared required-fact availability validation.
    # ------------------------------------------------------------------

    OPERAND_WIDTH_UNAVAILABLE = (
        "phase6c.operand_width_unavailable"
    )
    OPERAND_BINDING_UNAVAILABLE = (
        "phase6c.operand_binding_unavailable"
    )
    ATOMIC_ORDERING_UNAVAILABLE = (
        "phase6c.atomic_ordering_unavailable"
    )
    BARRIER_SEMANTICS_UNAVAILABLE = (
        "phase6c.barrier_semantics_unavailable"
    )
    IMPLICIT_STATE_SEMANTICS_UNAVAILABLE = (
        "phase6c.implicit_state_semantics_unavailable"
    )
    C_EXPRESSION_SHELL_NEUTRALITY_UNPROVEN = (
        "c_expression_shell_neutrality_unproven"
    )

    C_EXPRESSION_MACHINE_STATE_REQUIREMENTS_UNPROVEN = (
        "c_expression_machine_state_requirements_unproven"
    )

    C_BUILTIN_PLAN_KIND_MISMATCH = "phase6c.c_builtin_plan_kind_mismatch"
    C_BUILTIN_SOURCE_INCOMPLETE = "phase6c.c_builtin_source_incomplete"
    C_BUILTIN_OPERATION_UNSUPPORTED = "phase6c.c_builtin_operation_unsupported"
    C_BUILTIN_CAPABILITY_UNAVAILABLE = "phase6c.c_builtin_capability_unavailable"
    C_BUILTIN_ATOMIC_FACTS_INCOMPLETE = "phase6c.c_builtin_atomic_facts_incomplete"
    C_BUILTIN_ATOMIC_TYPE_UNSUPPORTED = "phase6c.c_builtin_atomic_type_unsupported"
    C_BUILTIN_BARRIER_UNSUPPORTED = "phase6c.c_builtin_barrier_unsupported"
    X86_INLINE_ASM_PLAN_KIND_MISMATCH = "phase6c.x86_inline_asm_plan_kind_mismatch"
    X86_INLINE_ASM_FEATURE_UNAVAILABLE = "phase6c.x86_inline_asm_feature_unavailable"
    X86_INLINE_ASM_SOURCE_INCOMPLETE = "phase6c.x86_inline_asm_source_incomplete"
    X86_INLINE_ASM_NON_REGISTER_SEMANTICS = "phase6c.x86_inline_asm_non_register_semantics"
    X86_INLINE_ASM_CONTROL_FLOW_UNSUPPORTED = "phase6c.x86_inline_asm_control_flow_unsupported"
    X86_INLINE_ASM_IMPLICIT_STATE_UNSUPPORTED = "phase6c.x86_inline_asm_implicit_state_unsupported"
    X86_INLINE_ASM_SHELL_UNSUPPORTED = "phase6c.x86_inline_asm_shell_unsupported"
    X86_INLINE_ASM_OPERAND_UNSUPPORTED = "phase6c.x86_inline_asm_operand_unsupported"
    X86_INLINE_ASM_BINDING_INCOMPLETE = "phase6c.x86_inline_asm_binding_incomplete"
    X86_INLINE_ASM_SEMANTIC_CONTRACT_UNSUPPORTED = "phase6c.x86_inline_asm_semantic_contract_unsupported"
    X86_INLINE_ASM_OPERAND_CONTRACT_MISMATCH = "phase6c.x86_inline_asm_operand_contract_mismatch"
    X86_MEMORY_ASM_PLAN_KIND_MISMATCH = "phase6c.x86_memory_asm_plan_kind_mismatch"
    X86_MEMORY_ASM_FEATURE_UNAVAILABLE = "phase6c.x86_memory_asm_feature_unavailable"
    X86_MEMORY_ASM_SOURCE_INCOMPLETE = "phase6c.x86_memory_asm_source_incomplete"
    X86_MEMORY_ASM_HARDWARE_SEMANTICS_UNSUPPORTED = "phase6c.x86_memory_asm_hardware_semantics_unsupported"
    X86_MEMORY_ASM_CONTROL_FLOW_UNSUPPORTED = "phase6c.x86_memory_asm_control_flow_unsupported"
    X86_MEMORY_ASM_ADDRESS_BINDING_MISSING = "phase6c.x86_memory_asm_address_binding_missing"
    X86_MEMORY_ASM_ALIAS_UNKNOWN = "phase6c.x86_memory_asm_alias_unknown"

    # Phase 6C-6 keeps atomic and barrier contracts separate from ordinary
    # memory inline asm.  These reason codes are stable routing outcomes.
    X86_ATOMIC_PLAN_KIND_MISMATCH = "phase6c.x86_atomic_plan_kind_mismatch"
    X86_ATOMIC_SOURCE_INCOMPLETE = "phase6c.x86_atomic_source_incomplete"
    X86_ATOMIC_FACTS_INCOMPLETE = "phase6c.x86_atomic_facts_incomplete"
    X86_ATOMIC_FEATURE_UNAVAILABLE = "phase6c.x86_atomic_feature_unavailable"
    X86_ATOMIC_ORDERING_UNSUPPORTED = "phase6c.x86_atomic_ordering_unsupported"
    X86_BARRIER_PLAN_KIND_MISMATCH = "phase6c.x86_barrier_plan_kind_mismatch"
    X86_BARRIER_SOURCE_INCOMPLETE = "phase6c.x86_barrier_source_incomplete"
    X86_BARRIER_UNKNOWN = "phase6c.x86_barrier_unknown"
    X86_BARRIER_FEATURE_UNAVAILABLE = "phase6c.x86_barrier_feature_unavailable"
    X86_BARRIER_INSTRUCTION_STREAM_UNSUPPORTED = "phase6c.x86_barrier_instruction_stream_unsupported"
    X86_BARRIER_SEMANTICS_UNSUPPORTED = "phase6c.x86_barrier_semantics_unsupported"
    STRUCTURED_CONTROL_FLOW_PLAN_KIND_MISMATCH = "phase6c.structured_control_flow_plan_kind_mismatch"
    STRUCTURED_CONTROL_FLOW_SOURCE_INCOMPLETE = "phase6c.structured_control_flow_source_incomplete"
    STRUCTURED_CONTROL_FLOW_UNKNOWN_TARGET = "phase6c.structured_control_flow_unknown_target"
    STRUCTURED_CONTROL_FLOW_INDIRECT_UNSUPPORTED = "phase6c.structured_control_flow_indirect_unsupported"
    STRUCTURED_CONTROL_FLOW_CALL_OR_RETURN_UNSUPPORTED = "phase6c.structured_control_flow_call_or_return_unsupported"
    STRUCTURED_CONTROL_FLOW_SUCCESSORS_INCOMPLETE = "phase6c.structured_control_flow_successors_incomplete"
    STRUCTURED_CONTROL_FLOW_LABEL_BINDINGS_INCOMPLETE = "phase6c.structured_control_flow_label_bindings_incomplete"
    STRUCTURED_CONTROL_FLOW_ASM_GOTO_UNAVAILABLE = "phase6c.structured_control_flow_asm_goto_unavailable"
    STRUCTURED_CONTROL_FLOW_BRANCH_CONDITION_UNSUPPORTED = "phase6c.structured_control_flow_branch_condition_unsupported"
    STRUCTURED_CONTROL_FLOW_BRANCH_OPERAND_UNSAFE = "phase6c.structured_control_flow_branch_operand_unsafe"
    HELPER_ABI_PLAN_KIND_MISMATCH = "phase6c.helper_abi_plan_kind_mismatch"
    HELPER_ABI_SOURCE_INCOMPLETE = "phase6c.helper_abi_source_incomplete"
    HELPER_ABI_CONTRACT_INCOMPLETE = "phase6c.helper_abi_contract_incomplete"
    HELPER_ABI_RUNTIME_UNAVAILABLE = "phase6c.helper_abi_runtime_unavailable"
    HELPER_ABI_SEMANTIC_VERSION_UNAVAILABLE = "phase6c.helper_abi_semantic_version_unavailable"
    HELPER_ABI_CONTROL_FLOW_MISMATCH = "phase6c.helper_abi_control_flow_mismatch"
    HELPER_ABI_STACK_FRAME_UNSUPPORTED = "phase6c.helper_abi_stack_frame_unsupported"

def _normalize_feature_set(
    value: Iterable[str],
    *,
    field_name: str,
) -> FrozenSet[str]:
    if isinstance(value, (str, bytes)):
        raise TypeError(
            f"{field_name} must be an iterable of feature names, "
            f"not {type(value).__name__}"
        )

    normalized = tuple(value)

    invalid = tuple(
        item
        for item in normalized
        if (
            not isinstance(item, str)
            or not item.strip()
            or item != item.strip()
        )
    )
    if invalid:
        raise TypeError(
            f"{field_name} must contain non-empty stripped strings; "
            f"invalid values: {invalid!r}"
        )

    return frozenset(normalized)


def _normalize_reason_codes(
    value: Iterable[TargetConstraintReasonCode],
    *,
    field_name: str,
) -> Tuple[TargetConstraintReasonCode, ...]:
    if isinstance(value, (str, bytes)):
        raise TypeError(
            f"{field_name} must be an iterable of "
            "TargetConstraintReasonCode values"
        )

    normalized = tuple(value)

    invalid = tuple(
        item
        for item in normalized
        if not isinstance(item, TargetConstraintReasonCode)
    )
    if invalid:
        raise TypeError(
            f"{field_name} contains invalid reason codes: {invalid!r}"
        )

    if len(set(normalized)) != len(normalized):
        raise ValueError(
            f"{field_name} must not contain duplicate reason codes"
        )

    return tuple(sorted(normalized, key=lambda code: code.value))

TargetConstraintDetailValue = str | int | bool | None


def _freeze_details(
    value: Mapping[str, TargetConstraintDetailValue],
) -> Mapping[str, TargetConstraintDetailValue]:
    """
    Freeze stable machine-readable failure/success diagnostic details.

    Detail values intentionally support only scalar values that are safe for
    diagnostics, test assertions, audit logs, and straightforward structured
    serialization.

    Unsupported values such as floats, collections, arbitrary enums, and
    custom objects must be normalized by the caller before construction.
    """
    if not isinstance(value, Mapping):
        raise TypeError(
            "details must be "
            "Mapping[str, str | int | bool | None], "
            f"got {type(value).__name__}"
        )

    normalized: dict[str, TargetConstraintDetailValue] = {}

    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not key.strip()
            or key != key.strip()
        ):
            raise TypeError(
                "detail keys must be non-empty stripped strings; "
                f"got {key!r}"
            )

        if item is not None and not isinstance(
            item,
            (str, int, bool),
        ):
            raise TypeError(
                f"detail value for {key!r} must be "
                "str, int, bool, or None; "
                f"got {type(item).__name__}"
            )

        normalized[key] = item

    return MappingProxyType(dict(sorted(normalized.items())))


@dataclass(frozen=True)
class TargetConstraintDerivationResult:
    """
    Result of Phase 6C constraint derivation.

    success=True:
        constraints is present;
        reason_codes is empty.

    success=False:
        constraints is None;
        reason_codes is non-empty;
        caller must reject the candidate or keep it unavailable.

    A failed Phase 6C result must never cause fallback to:

      * raw source asm;
      * guessed GNU asm constraints;
      * generic register-only lowering;
      * inferred operand ordering;
      * inferred host expression width.

    `details` contains stable scalar diagnostics. Program logic must branch on
    `reason_codes`, never on human-readable detail text.
    """

    success: bool
    plan_id: str | None
    constraints: TargetConstraintModel | None

    reason_codes: Tuple[TargetConstraintReasonCode, ...] = ()
    details: Mapping[str, TargetConstraintDetailValue] = (
        MappingProxyType({})
    )

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            raise TypeError("success must be bool")

        if self.plan_id is not None:
            if (
                not isinstance(self.plan_id, str)
                or not self.plan_id.strip()
                or self.plan_id != self.plan_id.strip()
            ):
                raise TypeError(
                    "plan_id must be None or a non-empty stripped str"
                )

        if self.constraints is not None:
            if not isinstance(
                self.constraints,
                TargetConstraintModel,
            ):
                raise TypeError(
                    "constraints must be None or TargetConstraintModel"
                )

        normalized_codes = _normalize_reason_codes(
            self.reason_codes,
            field_name="reason_codes",
        )
        frozen_details = _freeze_details(self.details)

        if self.success:
            if self.constraints is None:
                raise ValueError(
                    "successful result requires constraints"
                )

            if normalized_codes:
                raise ValueError(
                    "successful result must not contain failure reasons"
                )

            if self.plan_id != self.constraints.plan_id:
                raise ValueError(
                    "successful result plan_id must match "
                    "constraints.plan_id"
                )
        else:
            if self.constraints is not None:
                raise ValueError(
                    "failed result must not contain constraints"
                )

            if not normalized_codes:
                raise ValueError(
                    "failed result requires at least one reason code"
                )

        object.__setattr__(self, "reason_codes", normalized_codes)
        object.__setattr__(self, "details", frozen_details)

    @classmethod
    def failure(
        cls,
        *,
        plan_id: str | None,
        reason_codes: Iterable[TargetConstraintReasonCode],
        details: (
            Mapping[str, TargetConstraintDetailValue] | None
        ) = None,
    ) -> "TargetConstraintDerivationResult":
        return cls(
            success=False,
            plan_id=plan_id,
            constraints=None,
            reason_codes=tuple(reason_codes),
            details={} if details is None else details,
        )

    @classmethod
    def succeeded(
        cls,
        constraints: TargetConstraintModel,
    ) -> "TargetConstraintDerivationResult":
        return cls(
            success=True,
            plan_id=constraints.plan_id,
            constraints=constraints,
        )

@dataclass(frozen=True)
class TargetEnvironment:
    """
    Immutable target profile consumed by Phase 6C.

    The current translator supports one fixed profile only:

        architecture = x86_64
        asm_dialect  = GNU AT&T
        abi          = SysV AMD64

    This is not runtime target discovery. It is a fixed project-level
    compilation contract.

    available_features represents the explicitly configured target feature
    set. It must not be synthesized from host CPU probing unless the compiler
    pipeline explicitly defines host probing as part of target selection.
    """

    architecture: TargetArchitecture
    asm_dialect: TargetAsmDialect
    abi: TargetAbi

    supports_gnu_inline_asm: bool = True
    supports_gnu_asm_goto: bool = False
    available_features: FrozenSet[str] = frozenset()
    builtin_capabilities: FrozenSet[str] = frozenset()
    helper_contract_capabilities: FrozenSet[str] = frozenset()
    compiler_family: str = "gnu"
    compiler_version: str = "10+"

    def __post_init__(self) -> None:
        if not isinstance(self.architecture, TargetArchitecture):
            raise TypeError(
                "TargetEnvironment.architecture must be "
                "TargetArchitecture"
            )

        if not isinstance(self.asm_dialect, TargetAsmDialect):
            raise TypeError(
                "TargetEnvironment.asm_dialect must be "
                "TargetAsmDialect"
            )

        if not isinstance(self.abi, TargetAbi):
            raise TypeError(
                "TargetEnvironment.abi must be TargetAbi"
            )

        if not isinstance(self.supports_gnu_inline_asm, bool):
            raise TypeError(
                "TargetEnvironment.supports_gnu_inline_asm must be bool"
            )
        if not isinstance(self.supports_gnu_asm_goto, bool):
            raise TypeError("TargetEnvironment.supports_gnu_asm_goto must be bool")
        if not isinstance(self.compiler_family, str) or not self.compiler_family:
            raise TypeError("TargetEnvironment.compiler_family must be a non-empty string")
        if not isinstance(self.compiler_version, str) or not self.compiler_version:
            raise TypeError("TargetEnvironment.compiler_version must be a non-empty string")

        object.__setattr__(
            self,
            "available_features",
            _normalize_feature_set(
                self.available_features,
                field_name="TargetEnvironment.available_features",
            ),
        )
        object.__setattr__(self, "builtin_capabilities", _normalize_feature_set(self.builtin_capabilities, field_name="TargetEnvironment.builtin_capabilities"))
        object.__setattr__(self, "helper_contract_capabilities", _normalize_feature_set(self.helper_contract_capabilities, field_name="TargetEnvironment.helper_contract_capabilities"))

    @classmethod
    def fixed_sysv_amd64_gnu_att(
        cls,
        *,
        available_features: Iterable[str] = ("x86:gpr_inline_asm",),
        supports_gnu_inline_asm: bool = True,
        supports_gnu_asm_goto: bool = False,
        builtin_capabilities: Iterable[str] = (),
        helper_contract_capabilities: Iterable[str] = (),
        compiler_family: str = "gnu",
        compiler_version: str = "10+",
    ) -> "TargetEnvironment":
        """
        Create the only currently supported target profile.

        The project is currently fixed to:

            x86_64 + SysV AMD64 ABI + GNU AT&T inline assembly.

        ``target:x86`` is an architecture identity derived from this fixed
        profile, not a host-CPU feature supplied by the caller.  Candidate
        plans use it to bind their proof to x86; callers still must declare
        operational capabilities such as ``x86:gpr_inline_asm`` explicitly.
        """
        normalized_features = frozenset({
            *available_features,
            "target:x86",
        })
        return cls(
            architecture=TargetArchitecture.X86_64,
            asm_dialect=TargetAsmDialect.GNU_ATT,
            abi=TargetAbi.SYSV_AMD64,
            supports_gnu_inline_asm=supports_gnu_inline_asm,
            supports_gnu_asm_goto=supports_gnu_asm_goto,
            available_features=normalized_features,
            builtin_capabilities=frozenset(builtin_capabilities),
            helper_contract_capabilities=frozenset(helper_contract_capabilities),
            compiler_family=compiler_family,
            compiler_version=compiler_version,
        )


FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT = (
    TargetEnvironment.fixed_sysv_amd64_gnu_att()
)

@dataclass(frozen=True)
class TargetOperandConstraint:
    """
    Structured target operand constraint.

    source_operand_index must originate from authoritative source semantic
    facts, ultimately derived from validated runtime facts.

    It must never be reconstructed from source shell operand ordering.
    """

    source_operand_index: int
    role: TargetOperandRole
    allowed_classes: FrozenSet[TargetOperandClass]

    tied_to_source_operand_index: int | None = None
    early_clobber: bool = False

    required_width_bits: int | None = None
    required_signedness: SourceSignedness | None = None

    requires_fixed_register: bool = False
    fixed_register_name: str | None = None
    # An explicit compiler-dialect operand class, used only when a registered
    # semantic contract requires one (for example x86 variable shift count
    # ``c`` / CL).  Renderers consume it verbatim and never infer it.
    gnu_constraint_body: str | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.source_operand_index, bool)
            or not isinstance(self.source_operand_index, int)
            or self.source_operand_index < 0
        ):
            raise TypeError(
                "source_operand_index must be a non-negative int"
            )

        if not isinstance(self.role, TargetOperandRole):
            raise TypeError(
                "role must be TargetOperandRole"
            )
        if self.gnu_constraint_body is not None and (
                not isinstance(self.gnu_constraint_body, str) or
                not self.gnu_constraint_body.strip() or
                self.gnu_constraint_body != self.gnu_constraint_body.strip()):
            raise TypeError("gnu_constraint_body must be a non-empty stripped str or None")

        normalized_classes = frozenset(self.allowed_classes)

        if not normalized_classes:
            raise ValueError(
                "allowed_classes must not be empty"
            )

        invalid_classes = tuple(
            item
            for item in normalized_classes
            if not isinstance(item, TargetOperandClass)
        )
        if invalid_classes:
            raise TypeError(
                "allowed_classes must contain TargetOperandClass values; "
                f"invalid={invalid_classes!r}"
            )

        if self.tied_to_source_operand_index is not None:
            if (
                isinstance(self.tied_to_source_operand_index, bool)
                or not isinstance(
                    self.tied_to_source_operand_index,
                    int,
                )
                or self.tied_to_source_operand_index < 0
            ):
                raise TypeError(
                    "tied_to_source_operand_index must be None or "
                    "a non-negative int"
                )

            if (
                self.tied_to_source_operand_index
                == self.source_operand_index
            ):
                raise ValueError(
                    "operand must not be tied to itself"
                )

        if not isinstance(self.early_clobber, bool):
            raise TypeError(
                "early_clobber must be bool"
            )

        if self.required_width_bits is not None:
            if (
                isinstance(self.required_width_bits, bool)
                or not isinstance(self.required_width_bits, int)
                or self.required_width_bits <= 0
            ):
                raise TypeError(
                    "required_width_bits must be None or positive int"
                )

        if self.required_signedness is not None:
            if not isinstance(
                self.required_signedness,
                SourceSignedness,
            ):
                raise TypeError(
                    "required_signedness must be None or "
                    "SourceSignedness"
                )

        if not isinstance(self.requires_fixed_register, bool):
            raise TypeError(
                "requires_fixed_register must be bool"
            )

        if self.fixed_register_name is not None:
            if not isinstance(self.fixed_register_name, str):
                raise TypeError(
                    "fixed_register_name must be None or str"
                )

            if not self.fixed_register_name.strip():
                raise ValueError(
                    "fixed_register_name must not be empty"
                )

        if (
            self.requires_fixed_register
            and self.fixed_register_name is None
        ):
            raise ValueError(
                "requires_fixed_register requires fixed_register_name"
            )

        if (
            not self.requires_fixed_register
            and self.fixed_register_name is not None
        ):
            raise ValueError(
                "fixed_register_name requires "
                "requires_fixed_register=True"
            )

        object.__setattr__(
            self,
            "allowed_classes",
            normalized_classes,
        )

@dataclass(frozen=True)
class TargetMemoryConstraint:
    """
    Structured memory / atomic / barrier target contract.

    This DTO does not emit GNU asm text.

    It records requirements that renderer/proof stages must later satisfy.
    """

    requires_memory_clobber: bool = False
    requires_atomic_ordering: bool = False
    requires_compiler_barrier: bool = False
    requires_hardware_barrier: bool = False

    atomic_success_ordering: SourceMemoryOrdering | None = None
    atomic_failure_ordering: SourceMemoryOrdering | None = None

    required_atomic_width_bits: int | None = None
    required_alignment_bytes: int | None = None

    barrier_scope: SourceBarrierScope | None = None
    requires_instruction_serialization: bool = False
    requires_speculation_control: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "requires_memory_clobber",
            "requires_atomic_ordering",
            "requires_compiler_barrier",
            "requires_hardware_barrier",
            "requires_instruction_serialization",
            "requires_speculation_control",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(
                    f"{field_name} must be bool"
                )

        for field_name in (
            "atomic_success_ordering",
            "atomic_failure_ordering",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(
                value,
                SourceMemoryOrdering,
            ):
                raise TypeError(
                    f"{field_name} must be None or "
                    "SourceMemoryOrdering"
                )

        for field_name in (
            "required_atomic_width_bits",
            "required_alignment_bytes",
        ):
            value = getattr(self, field_name)
            if value is not None:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value <= 0
                ):
                    raise TypeError(
                        f"{field_name} must be None or positive int"
                    )

        if self.barrier_scope is not None and not isinstance(
            self.barrier_scope,
            SourceBarrierScope,
        ):
            raise TypeError(
                "barrier_scope must be None or SourceBarrierScope"
            )

        if self.requires_atomic_ordering:
            if self.atomic_success_ordering is None:
                raise ValueError(
                    "atomic ordering requires "
                    "atomic_success_ordering"
                )

        if (
            self.atomic_failure_ordering is not None
            and self.atomic_success_ordering is None
        ):
            raise ValueError(
                "atomic_failure_ordering requires "
                "atomic_success_ordering"
            )
    def is_no_memory_effect(self) -> bool:
        """
        Return whether this contract represents no memory, atomic, barrier,
        serialization, or speculation-control effect whatsoever.

        This is intentionally explicit rather than implemented as:

            self == TargetMemoryConstraint()

        because equality against a default instance would become unsafe if
        defaults or fields change in a later phase.
        """
        return (
            not self.requires_memory_clobber
            and not self.requires_atomic_ordering
            and not self.requires_compiler_barrier
            and not self.requires_hardware_barrier
            and self.atomic_success_ordering is None
            and self.atomic_failure_ordering is None
            and self.required_atomic_width_bits is None
            and self.required_alignment_bytes is None
            and self.barrier_scope is None
            and not self.requires_instruction_serialization
            and not self.requires_speculation_control
        )

@dataclass(frozen=True)
class TargetControlFlowConstraint:
    """
    Structured control-flow, ABI, and implicit-state target contract.

    This DTO does not render labels, asm-goto syntax, or helper call text.
    """

    preserve_control_flow: bool = False
    preserve_asm_goto: bool = False
    preserve_retry_loop: bool = False
    requires_helper_abi_contract: bool = False

    preserve_condition_codes: bool = False
    preserve_stack_pointer: bool = False
    preserve_frame_pointer: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "preserve_control_flow",
            "preserve_asm_goto",
            "preserve_retry_loop",
            "requires_helper_abi_contract",
            "preserve_condition_codes",
            "preserve_stack_pointer",
            "preserve_frame_pointer",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(
                    f"{field_name} must be bool"
                )
    def is_simple_fallthrough(self) -> bool:
        """
        Return whether this contract represents ordinary sequential C control
        flow only.

        A Phase 6C-2 C-expression lowering cannot model asm-goto behavior,
        retry loops, helper ABI control-flow obligations, condition-code
        preservation, or explicit stack/frame preservation contracts.
        """
        return (
            not self.preserve_control_flow
            and not self.preserve_asm_goto
            and not self.preserve_retry_loop
            and not self.requires_helper_abi_contract
            and not self.preserve_condition_codes
            and not self.preserve_stack_pointer
            and not self.preserve_frame_pointer
        )

@dataclass(frozen=True)
class TargetConstraintModel:
    """
    Successful Phase 6C constraint derivation result.

    Important:

      * This is not rendered asm.
      * This is not GNU inline-asm text.
      * This is not Phase 6D proof output.
      * This does not mean the candidate is approved.
      * This must be constructed only from authoritative structured facts.

    A constraint model may describe either:

      * a target-inline-asm-oriented lowering contract; or
      * a structured C-expression lowering contract.

    It must not ambiguously describe both at once.
    """

    plan_id: str
    environment: TargetEnvironment

    operand_constraints: Tuple[TargetOperandConstraint, ...] = ()
    memory_constraint: TargetMemoryConstraint = TargetMemoryConstraint()
    control_flow_constraint: TargetControlFlowConstraint = (
        TargetControlFlowConstraint()
    )

    # Present only for a structured C-expression lowering contract.
    #
    # This is structured C semantic information, not rendered C text.
    # It must not be combined with GNU inline-asm-specific constraints.
    c_expression_constraint: object | None = None
    c_builtin_constraint: object | None = None
    x86_gnu_inline_asm_contract: object | None = None
    x86_memory_inline_asm_contract: object | None = None
    x86_atomic_contract: object | None = None
    x86_barrier_contract: object | None = None
    structured_control_flow_contract: object | None = None
    helper_abi_contract: object | None = None
    stack_rebinding_constraint: object | None = None
    virtual_private_frame_constraint: object | None = None
    abi_wrapper_constraint: object | None = None
    privileged_runtime_constraint: object | None = None
    privileged_functional_constraint: object | None = None

    preserve_volatile: bool = False
    preserve_cc_clobber: bool = False
    preserve_implicit_machine_state: bool = False
    target_register_policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.plan_id, str)
            or not self.plan_id.strip()
            or self.plan_id != self.plan_id.strip()
        ):
            raise TypeError(
                "plan_id must be a non-empty stripped str"
            )

        if not isinstance(self.environment, TargetEnvironment):
            raise TypeError(
                "environment must be TargetEnvironment"
            )

        normalized_operands = tuple(self.operand_constraints)
        if self.target_register_policy_version != POLICY_VERSION:
            raise ValueError("target_register_policy_version must be the active policy version")

        invalid_operands = tuple(
            item
            for item in normalized_operands
            if not isinstance(item, TargetOperandConstraint)
        )
        if invalid_operands:
            raise TypeError(
                "operand_constraints must contain only "
                "TargetOperandConstraint values"
            )

        indexes = tuple(
            operand.source_operand_index
            for operand in normalized_operands
        )
        if len(set(indexes)) != len(indexes):
            raise ValueError(
                "operand_constraints must not duplicate "
                "source_operand_index"
            )

        if not isinstance(
            self.memory_constraint,
            TargetMemoryConstraint,
        ):
            raise TypeError(
                "memory_constraint must be TargetMemoryConstraint"
            )

        if not isinstance(
            self.control_flow_constraint,
            TargetControlFlowConstraint,
        ):
            raise TypeError(
                "control_flow_constraint must be "
                "TargetControlFlowConstraint"
            )

        if self.c_expression_constraint is not None:
            from .c_module.phase6c_c_expression import CExpressionConstraint
            if not isinstance(self.c_expression_constraint, CExpressionConstraint):
                raise TypeError("c_expression_constraint must be CExpressionConstraint or None")
        if self.c_builtin_constraint is not None:
            from .c_module.phase6c_c_builtin import CBuiltinContract
            if not isinstance(self.c_builtin_constraint, CBuiltinContract):
                raise TypeError("c_builtin_constraint must be CBuiltinContract or None")
        if self.x86_gnu_inline_asm_contract is not None:
            from .c_module.phase6c_x86_gnu_inline_asm import X86GnuInlineAsmContract
            if not isinstance(self.x86_gnu_inline_asm_contract, X86GnuInlineAsmContract):
                raise TypeError("x86_gnu_inline_asm_contract must be X86GnuInlineAsmContract or None")
        if self.x86_memory_inline_asm_contract is not None:
            from .c_module.phase6c_x86_memory_inline_asm import X86MemoryInlineAsmContract
            if not isinstance(self.x86_memory_inline_asm_contract, X86MemoryInlineAsmContract):
                raise TypeError("x86_memory_inline_asm_contract must be X86MemoryInlineAsmContract or None")
        if self.x86_atomic_contract is not None:
            from .c_module.phase6c_x86_atomic_barrier import X86AtomicContract
            if not isinstance(self.x86_atomic_contract, X86AtomicContract):
                raise TypeError("x86_atomic_contract must be X86AtomicContract or None")
        if self.x86_barrier_contract is not None:
            from .c_module.phase6c_x86_atomic_barrier import X86BarrierContract
            if not isinstance(self.x86_barrier_contract, X86BarrierContract):
                raise TypeError("x86_barrier_contract must be X86BarrierContract or None")
        if self.structured_control_flow_contract is not None:
            from .c_module.phase6c_structured_control_flow import StructuredControlFlowContract
            if not isinstance(self.structured_control_flow_contract, StructuredControlFlowContract):
                raise TypeError("structured_control_flow_contract must be StructuredControlFlowContract or None")
        if self.helper_abi_contract is not None:
            from .c_module.phase6c_helper_abi import HelperAbiContract
            if not isinstance(self.helper_abi_contract, HelperAbiContract):
                raise TypeError("helper_abi_contract must be HelperAbiContract or None")
        if self.stack_rebinding_constraint is not None:
            from .stack_rebinding import TargetStackRebindingConstraint
            if not isinstance(self.stack_rebinding_constraint, TargetStackRebindingConstraint):
                raise TypeError("stack_rebinding_constraint must be TargetStackRebindingConstraint or None")
        if self.virtual_private_frame_constraint is not None:
            from .virtual_private_frame import TargetVirtualPrivateFrameConstraint
            if not isinstance(self.virtual_private_frame_constraint, TargetVirtualPrivateFrameConstraint):
                raise TypeError("virtual_private_frame_constraint must be TargetVirtualPrivateFrameConstraint or None")
        if self.abi_wrapper_constraint is not None:
            from .abi_wrapper import TargetAbiWrapperConstraint
            if not isinstance(self.abi_wrapper_constraint, TargetAbiWrapperConstraint):
                raise TypeError("abi_wrapper_constraint must be TargetAbiWrapperConstraint or None")
        if self.privileged_runtime_constraint is not None:
            from .privileged_runtime_contracts import TargetPrivilegedRuntimeConstraint
            if not isinstance(
                self.privileged_runtime_constraint,
                TargetPrivilegedRuntimeConstraint,
            ):
                raise TypeError(
                    "privileged_runtime_constraint must be "
                    "TargetPrivilegedRuntimeConstraint or None"
                )
        if self.privileged_functional_constraint is not None:
            from .privileged_functional_contracts import (
                TargetPrivilegedFunctionalFallbackConstraint,
            )
            if not isinstance(
                self.privileged_functional_constraint,
                TargetPrivilegedFunctionalFallbackConstraint,
            ):
                raise TypeError(
                    "privileged_functional_constraint must be "
                    "TargetPrivilegedFunctionalFallbackConstraint or None"
                )
        if self.c_expression_constraint is not None and self.c_builtin_constraint is not None:
            raise ValueError("target constraints cannot contain both C expression and C builtin contracts")
        specialized_contracts = (
            self.c_expression_constraint,
            self.c_builtin_constraint,
            self.x86_gnu_inline_asm_contract,
            self.x86_memory_inline_asm_contract,
            self.x86_atomic_contract,
            self.x86_barrier_contract,
            self.structured_control_flow_contract,
            self.helper_abi_contract,
            self.stack_rebinding_constraint,
            self.virtual_private_frame_constraint,
            self.abi_wrapper_constraint,
            self.privileged_runtime_constraint,
            self.privileged_functional_constraint,
        )
        if sum(contract is not None for contract in specialized_contracts) > 1:
            raise ValueError("target constraints must contain exactly one lowering contract")

        for field_name in (
            "preserve_volatile",
            "preserve_cc_clobber",
            "preserve_implicit_machine_state",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(
                    f"{field_name} must be bool"
                )

        if self.c_expression_constraint is not None:
            if normalized_operands:
                raise ValueError(
                    "C expression target constraints must not contain "
                    "GNU asm operand constraints"
                )

            if self.preserve_volatile:
                raise ValueError(
                    "C expression target constraints must not preserve "
                    "volatile asm semantics"
                )

            if self.preserve_cc_clobber:
                raise ValueError(
                    "C expression target constraints must not preserve "
                    "condition-code clobbers"
                )

            if self.preserve_implicit_machine_state:
                raise ValueError(
                    "C expression target constraints must not preserve "
                    "implicit machine state"
                )

            if not self.memory_constraint.is_no_memory_effect():
                raise ValueError(
                    "C expression target constraints must be memory-free"
                )

            if not self.control_flow_constraint.is_simple_fallthrough():
                raise ValueError(
                    "C expression target constraints must use simple "
                    "fallthrough control flow"
                )

        object.__setattr__(
            self,
            "operand_constraints",
            normalized_operands,
        )

def _environment_precheck(
    *,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult | None:
    """
    Fixed target-profile compatibility gate.

    This is the reduced form of the earlier generic target capability check.

    It is intentionally static:

      * no host CPU probing;
      * no multi-target selection;
      * no compiler auto-detection;
      * no silent target fallback.

    The current project accepts only:

        x86_64 + GNU AT&T + SysV AMD64.
    """

    if target_environment.architecture is not TargetArchitecture.X86_64:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.UNSUPPORTED_TARGET_ARCHITECTURE,
            ),
            details={
                "architecture": target_environment.architecture.value,
            },
        )

    if target_environment.asm_dialect is not TargetAsmDialect.GNU_ATT:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.UNSUPPORTED_ASM_DIALECT,
            ),
            details={
                "asm_dialect": target_environment.asm_dialect.value,
            },
        )

    if target_environment.abi is not TargetAbi.SYSV_AMD64:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.UNSUPPORTED_TARGET_ABI,
            ),
            details={
                "abi": target_environment.abi.value,
            },
        )

    inline_asm_kinds = frozenset(
        {
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            TargetLoweringKind.X86_ATOMIC,
            TargetLoweringKind.X86_BARRIER,
        }
    )

    if (
        candidate_plan.kind in inline_asm_kinds
        and not target_environment.supports_gnu_inline_asm
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.GNU_INLINE_ASM_UNAVAILABLE,
            ),
        )

    missing_features = (
        candidate_plan.required_features
        - target_environment.available_features
    )
    if missing_features:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PLAN_REQUIRED_FEATURE_MISSING,
            ),
            details={
                "missing_features": ",".join(sorted(missing_features)),
            },
        )

    forbidden_present = (
        candidate_plan.forbidden_features
        & target_environment.available_features
    )
    if forbidden_present:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PLAN_FORBIDDEN_FEATURE_PRESENT,
            ),
            details={
                "forbidden_features_present": ",".join(
                    sorted(forbidden_present)
                ),
            },
        )

    return None


def _not_implemented(
    *,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
    reason_code: TargetConstraintReasonCode,
) -> TargetConstraintDerivationResult:
    precheck = _environment_precheck(
        candidate_plan=candidate_plan,
        target_environment=target_environment,
    )
    if precheck is not None:
        return precheck

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(reason_code,),
        details={
            "plan_kind": candidate_plan.kind.value,
        },
    )

def _derive_c_expression_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    """
    Derive a pure Phase 6C-2 structured C-expression contract.

    This path is fail-closed:

      * no fallback to GNU inline asm;
      * no inference from raw asm or IR text;
      * no guessed source operand order;
      * no inferred host expression width;
      * no unsupported side effect may be silently ignored.
    """
    if candidate_plan.kind is not TargetLoweringKind.C_EXPRESSION:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.C_EXPRESSION_PLAN_KIND_MISMATCH,
            ),
            details={
                "expected_plan_kind": (
                    TargetLoweringKind.C_EXPRESSION.value
                ),
                "actual_plan_kind": candidate_plan.kind.value,
            },
        )

    precheck_failure = _environment_precheck(
        candidate_plan=candidate_plan,
        target_environment=target_environment,
    )
    if precheck_failure is not None:
        return precheck_failure

    from .c_module.phase6c_c_expression import derive_c_expression_constraints
    return derive_c_expression_constraints(
        source_model, candidate_plan, target_environment
    )

def _derive_c_structured_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    del source_model

    return _not_implemented(
        candidate_plan=candidate_plan,
        target_environment=target_environment,
        reason_code=(
            TargetConstraintReasonCode.C_STRUCTURED_NOT_IMPLEMENTED
        ),
    )


def _derive_c_builtin_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    from .c_module.phase6c_c_builtin import derive_c_builtin_constraints
    return derive_c_builtin_constraints(source_model, candidate_plan, target_environment)


def _derive_stack_address_rebinding_0(*, source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: TargetEnvironment) -> TargetConstraintDerivationResult:
    from .stack_rebinding import TargetStackRebindingAccess, TargetStackRebindingConstraint
    frame = source_model.stack_frame
    shell = source_model.shell
    shell_safe = not any((shell.is_volatile, shell.has_memory_clobber, shell.has_cc_clobber,
                          shell.has_asm_goto, shell.has_early_clobber,
                          shell.has_tied_operands, shell.has_control_flow_surface))
    if frame is None or not frame.stack_address_rebinding_eligible or not shell_safe:
        return TargetConstraintDerivationResult.failure(plan_id=candidate_plan.plan_id, reason_codes=(TargetConstraintReasonCode.C_STRUCTURED_NOT_IMPLEMENTED,), details={"reason": "stack-rebinding-ineligible"})
    accesses = tuple(TargetStackRebindingAccess(x.source_block_address, x.source_operation_index, x.c_lvalue_binding_id, x.target_object_offset_bytes, x.width_bits, x.access, x.value_operand_index) for x in frame.rebinding_accesses)
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id, environment=target_environment,
        stack_rebinding_constraint=TargetStackRebindingConstraint(accesses), memory_constraint=TargetMemoryConstraint(), control_flow_constraint=TargetControlFlowConstraint()))

def _derive_virtual_private_frame_0(*, source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: TargetEnvironment) -> TargetConstraintDerivationResult:
    from .virtual_private_frame import TargetVirtualPrivateFrameAccess, TargetVirtualPrivateFrameConstraint
    frame=source_model.stack_frame; private=None if frame is None else frame.virtual_private_frame
    shell=source_model.shell
    shell_safe=not any((shell.is_volatile,shell.has_memory_clobber,shell.has_cc_clobber,shell.has_asm_goto,shell.has_early_clobber,shell.has_tied_operands,shell.has_control_flow_surface))
    if private is None or not frame.virtual_private_frame_eligible or not shell_safe:
        return TargetConstraintDerivationResult.failure(plan_id=candidate_plan.plan_id,reason_codes=(TargetConstraintReasonCode.C_STRUCTURED_NOT_IMPLEMENTED,),details={"reason":"virtual-private-frame-ineligible"})
    accesses=tuple(TargetVirtualPrivateFrameAccess(x.source_block_address,x.source_operation_index,x.virtual_offset_bytes,x.width_bits,x.access,x.value_operand_index,x.signed_load) for x in private.accesses)
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,environment=target_environment,virtual_private_frame_constraint=TargetVirtualPrivateFrameConstraint(private.frame_size_bytes,private.required_alignment_bytes,accesses),memory_constraint=TargetMemoryConstraint(),control_flow_constraint=TargetControlFlowConstraint()))


def _derive_x86_gnu_inline_asm_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    """
    Future implementation requirements:

      * consume source_model.shell only as structured shell model;
      * consume authoritative runtime facts through RuntimeFactStatus;
      * use TranslationRuntimeFacts.rv_to_operand_index;
      * use TranslationRuntimeFacts.operand_width_bits;
      * do not derive bindings from operand order;
      * do not derive width from xlen;
      * do not infer memory/clobbers from raw asm mnemonics.
    """
    if source_model.operation.reads_memory or source_model.operation.writes_memory or source_model.memory.reads_memory or source_model.memory.writes_memory:
        from .c_module.phase6c_x86_memory_inline_asm import derive_x86_memory_inline_asm_constraints
        return derive_x86_memory_inline_asm_constraints(source_model, candidate_plan, target_environment)
    from .c_module.phase6c_x86_gnu_inline_asm import derive_x86_gnu_inline_asm_constraints
    return derive_x86_gnu_inline_asm_constraints(source_model, candidate_plan, target_environment)


def _derive_x86_atomic_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    from .c_module.phase6c_x86_atomic_barrier import (
        derive_x86_atomic_constraints,
    )
    return derive_x86_atomic_constraints(
        source_model, candidate_plan, target_environment
    )


def _derive_x86_barrier_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    from .c_module.phase6c_x86_atomic_barrier import (
        derive_x86_barrier_constraints,
    )
    return derive_x86_barrier_constraints(
        source_model, candidate_plan, target_environment
    )


def _derive_helper_call_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    """
    Future helper-call lowering must obey SysV AMD64 ABI explicitly.

    This includes, at minimum:

      * argument register assignment;
      * caller/callee-saved register treatment;
      * stack alignment;
      * red-zone policy;
      * return-value convention;
      * clobber model;
      * memory and control-flow proof obligations.
    """
    from .c_module.phase6c_helper_abi import derive_helper_abi_constraints
    return derive_helper_abi_constraints(
        source_model, candidate_plan, target_environment
    )


def _derive_structured_control_flow_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    from .c_module.phase6c_structured_control_flow import (
        derive_structured_control_flow_constraints,
    )
    return derive_structured_control_flow_constraints(
        source_model, candidate_plan, target_environment
    )


def _derive_explicit_unsupported_0(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment,
) -> TargetConstraintDerivationResult:
    del source_model
    del target_environment

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.EXPLICIT_UNSUPPORTED_PLAN,
        ),
        details={
            "plan_kind": candidate_plan.kind.value,
        },
    )

def _derive_abi_wrapper_0(*, source_model, candidate_plan, target_environment, abi_wrapper_registry=None):
    from .abi_wrapper import TargetAbiWrapperArgument, TargetAbiWrapperConstraint, TargetAbiWrapperReturn
    from .abi_effects import TargetAbiWrapperRegistry
    if abi_wrapper_registry is None: abi_wrapper_registry=TargetAbiWrapperRegistry()
    effects=source_model.abi_effects
    contract=abi_wrapper_registry.resolve(effects, target_environment.abi.value) if effects else None
    if contract is None:
        return TargetConstraintDerivationResult.failure(plan_id=candidate_plan.plan_id,reason_codes=(TargetConstraintReasonCode.MISSING_SEMANTIC_CONTRACT,),details={"route":"exact_abi_wrapper"})
    call=effects.calls[0]
    args=tuple(TargetAbiWrapperArgument(i,n,loc.width_bits or 0,contract.argument_types[n],loc.signedness) for n,(i,loc) in enumerate(zip(contract.argument_operand_indexes,call.arguments)))
    returns=tuple(TargetAbiWrapperReturn(i,n,loc.width_bits or 0,contract.return_types[n],loc.signedness) for n,(i,loc) in enumerate(zip(contract.return_operand_indexes,call.returns)))
    c=TargetAbiWrapperConstraint(contract,args,returns,call.stack_alignment_bytes or 0,getattr(abi_wrapper_registry,"version","") )
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,environment=target_environment,abi_wrapper_constraint=c,memory_constraint=TargetMemoryConstraint(),control_flow_constraint=TargetControlFlowConstraint()))


def _derive_privileged_runtime_0(
    *, source_model, candidate_plan, target_environment,
    privileged_runtime_registry=None,
):
    from .privileged_runtime_contracts import (
        PrivilegedRuntimeRegistry,
        TargetPrivilegedRuntimeConstraint,
        privileged_source_identity,
        target_environment_identity,
    )
    source = source_model.privileged_state
    if (
        source is None or not source.strict_translation_eligible
        or source.state is None or not source.state.present
        or source.requires_whole_function_lowering
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PRIVILEGED_RUNTIME_SOURCE_INCOMPLETE,
            ),
        )
    if not isinstance(privileged_runtime_registry, PrivilegedRuntimeRegistry):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PRIVILEGED_RUNTIME_REGISTRY_MISSING,
            ),
        )
    contract = privileged_runtime_registry.resolve(source, target_environment)
    if contract is None or not contract.complete:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PRIVILEGED_RUNTIME_CONTRACT_MISSING,
            ),
        )
    constraint = TargetPrivilegedRuntimeConstraint(
        runtime_contract=contract,
        source_privileged_identity=privileged_source_identity(source),
        target_environment_id=target_environment_identity(target_environment),
        registry_version=privileged_runtime_registry.version,
    )
    shell = source_model.shell
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(
        plan_id=candidate_plan.plan_id,
        environment=target_environment,
        privileged_runtime_constraint=constraint,
        preserve_volatile=(
            not shell.is_volatile or contract.preserves_volatile_execution
        ),
        preserve_cc_clobber=(
            not shell.has_cc_clobber or contract.preserves_cc_clobber
        ),
        memory_constraint=TargetMemoryConstraint(
            requires_memory_clobber=(
                shell.has_memory_clobber
                and contract.preserves_compiler_memory_ordering
            ),
            requires_compiler_barrier=(
                shell.has_memory_clobber
                and contract.preserves_compiler_memory_ordering
            ),
        ),
        control_flow_constraint=TargetControlFlowConstraint(
            preserve_control_flow=contract.preserves_control_flow,
            requires_helper_abi_contract=False,
        ),
    ))


def _derive_privileged_functional_0(
    *, source_model, candidate_plan, target_environment,
    privileged_functional_registry=None,
    privileged_functional_policy=None,
):
    from .functional_observability import FunctionalFallbackPossibility
    from .privileged_functional_contracts import (
        PrivilegedFunctionalFallbackPolicy,
        PrivilegedFunctionalFallbackRegistry,
        TargetPrivilegedFunctionalFallbackConstraint,
        functional_observability_identity,
    )
    from .privileged_runtime_contracts import (
        privileged_source_identity,
        target_environment_identity,
    )
    if (
        not isinstance(privileged_functional_policy,
                       PrivilegedFunctionalFallbackPolicy)
        or not privileged_functional_policy.enabled
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_POLICY_DISABLED,
            ),
        )
    source = source_model.privileged_state
    if (
        source is None or not source.complete or source.reason_codes
        or source.state is None or not source.state.present
        or not source.state.complete or source.state.missing_fact_codes
        or source.observability is None or not source.observability.complete
        or source.observability.missing_fact_codes
        or source.observability.fallback_possibility is not
            FunctionalFallbackPossibility.POSSIBLE_WITH_EXACT_TARGET_CONTRACT
        or not source.functional_fallback_possible
        or source.requires_whole_function_lowering
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_SOURCE_INCOMPLETE,
            ),
        )
    if not isinstance(
        privileged_functional_registry, PrivilegedFunctionalFallbackRegistry
    ):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_REGISTRY_MISSING,
            ),
        )
    contract = privileged_functional_registry.resolve(source, target_environment)
    if contract is None or not contract.complete:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_CONTRACT_MISSING,
            ),
        )
    constraint = TargetPrivilegedFunctionalFallbackConstraint(
        fallback_contract=contract,
        source_privileged_identity=privileged_source_identity(source),
        source_observability_identity=functional_observability_identity(
            source.observability
        ),
        target_environment_id=target_environment_identity(target_environment),
        registry_version=privileged_functional_registry.version,
        policy_identity=privileged_functional_policy.identity,
    )
    shell = source_model.shell
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(
        plan_id=candidate_plan.plan_id,
        environment=target_environment,
        privileged_functional_constraint=constraint,
        preserve_volatile=(
            not shell.is_volatile or contract.preserves_volatile_execution
        ),
        preserve_cc_clobber=(
            not shell.has_cc_clobber or contract.preserves_cc_clobber
        ),
        memory_constraint=TargetMemoryConstraint(
            requires_memory_clobber=(
                shell.has_memory_clobber
                and contract.preserves_compiler_memory_ordering
            ),
            requires_compiler_barrier=(
                shell.has_memory_clobber
                and contract.preserves_compiler_memory_ordering
            ),
        ),
        control_flow_constraint=TargetControlFlowConstraint(
            preserve_control_flow=contract.preserves_termination,
        ),
    ))


_Deriver = Callable[
    [
        SourceSemanticModel,
        TargetLoweringPlan,
        TargetEnvironment,
    ],
    TargetConstraintDerivationResult,
]


def _adapt_deriver(
    function: Callable[..., TargetConstraintDerivationResult],
) -> _Deriver:
    def wrapped(
        source_model: SourceSemanticModel,
        candidate_plan: TargetLoweringPlan,
        target_environment: TargetEnvironment,
    ) -> TargetConstraintDerivationResult:
        return function(
            source_model=source_model,
            candidate_plan=candidate_plan,
            target_environment=target_environment,
        )

    return wrapped


_PLAN_KIND_DISPATCH: Mapping[TargetLoweringKind, _Deriver] = (
    MappingProxyType(
        {
            TargetLoweringKind.C_EXPRESSION: _adapt_deriver(
                _derive_c_expression_0
            ),
            TargetLoweringKind.C_STRUCTURED: _adapt_deriver(
                _derive_c_structured_0
            ),
            TargetLoweringKind.C_BUILTIN: _adapt_deriver(
                _derive_c_builtin_0
            ),
            TargetLoweringKind.X86_GNU_INLINE_ASM: _adapt_deriver(
                _derive_x86_gnu_inline_asm_0
            ),
            TargetLoweringKind.X86_ATOMIC: _adapt_deriver(
                _derive_x86_atomic_0
            ),
            TargetLoweringKind.X86_BARRIER: _adapt_deriver(
                _derive_x86_barrier_0
            ),
            TargetLoweringKind.HELPER_CALL: _adapt_deriver(
                _derive_helper_call_0
            ),
            TargetLoweringKind.STRUCTURED_CONTROL_FLOW: _adapt_deriver(
                _derive_structured_control_flow_0
            ),
            TargetLoweringKind.STACK_ADDRESS_REBINDING: _adapt_deriver(
                _derive_stack_address_rebinding_0
            ),
            TargetLoweringKind.VIRTUAL_PRIVATE_FRAME: _adapt_deriver(
                _derive_virtual_private_frame_0
            ),
            TargetLoweringKind.ABI_WRAPPER_CALL: _adapt_deriver(_derive_abi_wrapper_0),
            TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER: _adapt_deriver(
                _derive_privileged_runtime_0
            ),
            TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK: _adapt_deriver(
                _derive_explicit_unsupported_0
            ),
            TargetLoweringKind.UNSUPPORTED: _adapt_deriver(
                _derive_explicit_unsupported_0
            ),
        }
    )
)


def _validate_dispatch_coverage() -> None:
    """
    Prevent enum expansion from silently falling into an implicit fallback.
    """
    enum_kinds = frozenset(TargetLoweringKind)
    dispatch_kinds = frozenset(_PLAN_KIND_DISPATCH)

    missing = enum_kinds - dispatch_kinds
    unexpected = dispatch_kinds - enum_kinds

    if missing or unexpected:
        raise RuntimeError(
            "Phase 6C dispatch coverage invariant violated: "
            f"missing={tuple(sorted(kind.value for kind in missing))!r}, "
            f"unexpected={tuple(sorted(kind.value for kind in unexpected))!r}"
        )


_validate_dispatch_coverage()

def _validate_result_invariants(
    *,
    candidate_plan: TargetLoweringPlan,
    result: TargetConstraintDerivationResult,
) -> TargetConstraintDerivationResult:
    """
    Validate cross-object Phase 6C result invariants.

    TargetConstraintModel.__post_init__ validates intrinsic model invariants.
    This function validates consistency between the candidate plan and the
    derivation result.
    """
    if result.plan_id != candidate_plan.plan_id:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
            ),
            details={
                "invariant": "result_plan_id_mismatch",
            },
        )

    if not result.success:
        if result.constraints is not None:
            return TargetConstraintDerivationResult.failure(
                plan_id=candidate_plan.plan_id,
                reason_codes=(
                    TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
                ),
                details={
                    "invariant": (
                        "failed_result_must_not_carry_constraints"
                    ),
                },
            )

        return result

    if result.constraints is None:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
            ),
            details={
                "invariant": "successful_result_has_no_constraints",
            },
        )

    constraints = result.constraints

    # This is intentionally global rather than A/B-specific.  A target
    # inline-asm route may not pin the compiler-owned stack/frame pointer.
    forbidden = tuple(
        item for item in constraints.operand_constraints
        if item.requires_fixed_register
        and is_forbidden_host_stack_frame_register(item.fixed_register_name)
    )
    if forbidden:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.HOST_STACK_FRAME_FIXED_REGISTER_FORBIDDEN,
            ),
            details={
                "fixed_register": forbidden[0].fixed_register_name,
                "target_register_policy_version": POLICY_VERSION,
            },
        )

    if constraints.plan_id != candidate_plan.plan_id:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
            ),
            details={
                "invariant": "constraint_plan_id_mismatch",
            },
        )

    is_c_expression_plan = (
        candidate_plan.kind is TargetLoweringKind.C_EXPRESSION
    )
    has_c_expression_constraint = (
        constraints.c_expression_constraint is not None
    )

    if is_c_expression_plan and not has_c_expression_constraint:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
            ),
            details={
                "invariant": (
                    "c_expression_plan_requires_c_expression_constraint"
                ),
            },
        )

    if not is_c_expression_plan and has_c_expression_constraint:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
            ),
            details={
                "invariant": (
                    "non_c_expression_plan_must_not_carry_"
                    "c_expression_constraint"
                ),
            },
        )

    if has_c_expression_constraint:
        try:
            validate_c_expression_constraint(
                constraints.c_expression_constraint
            )
        except (
            CExpressionConstraintValidationError,
            TypeError,
            ValueError,
        ) as exc:
            return _c_expression_constraint_failure(
                candidate_plan=candidate_plan,
                exc=exc,
            )

        if constraints.operand_constraints:
            return TargetConstraintDerivationResult.failure(
                plan_id=candidate_plan.plan_id,
                reason_codes=(
                    TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
                ),
                details={
                    "invariant": (
                        "c_expression_constraints_must_not_have_"
                        "asm_operand_constraints"
                    ),
                },
            )

        if not constraints.memory_constraint.is_no_memory_effect():
            return TargetConstraintDerivationResult.failure(
                plan_id=candidate_plan.plan_id,
                reason_codes=(
                    TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
                ),
                details={
                    "invariant": (
                        "c_expression_constraints_must_have_"
                        "no_memory_effect"
                    ),
                },
            )

        if not constraints.control_flow_constraint.is_simple_fallthrough():
            return TargetConstraintDerivationResult.failure(
                plan_id=candidate_plan.plan_id,
                reason_codes=(
                    TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
                ),
                details={
                    "invariant": (
                        "c_expression_constraints_must_have_"
                        "simple_fallthrough"
                    ),
                },
            )

        if constraints.preserve_volatile:
            return TargetConstraintDerivationResult.failure(
                plan_id=candidate_plan.plan_id,
                reason_codes=(
                    TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
                ),
                details={
                    "invariant": (
                        "c_expression_constraints_must_not_preserve_"
                        "volatile_inline_asm_semantics"
                    ),
                },
            )

        if constraints.preserve_cc_clobber:
            return TargetConstraintDerivationResult.failure(
                plan_id=candidate_plan.plan_id,
                reason_codes=(
                    TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
                ),
                details={
                    "invariant": (
                        "c_expression_constraints_must_not_preserve_"
                        "cc_clobber"
                    ),
                },
            )

        if constraints.preserve_implicit_machine_state:
            return TargetConstraintDerivationResult.failure(
                plan_id=candidate_plan.plan_id,
                reason_codes=(
                    TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
                ),
                details={
                    "invariant": (
                        "c_expression_constraints_must_not_preserve_"
                        "implicit_machine_state"
                    ),
                },
            )

    return result

def derive_target_constraints(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
    target_environment: TargetEnvironment = (
        FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT
    ),
    abi_wrapper_registry=None,
    privileged_runtime_registry=None,
    privileged_functional_registry=None,
    privileged_functional_policy=None,
) -> TargetConstraintDerivationResult:
    """
    Phase 6C public entry point.

    Pipeline contract:

        Phase 6B:
            generate_candidate_plans(source_model)

        Phase 6C:
            derive_target_constraints(
                source_model=source_model,
                candidate_plan=plan,
            )

        Phase 6D:
            prove source semantics == target lowering semantics

        Phase 6E:
            select only candidates approved by 6C + 6D

    This function does not select a candidate and does not approve one.

    All currently unimplemented plan kinds fail closed with a structured,
    stable reason code.
    """
    if not isinstance(source_model, SourceSemanticModel):
        return TargetConstraintDerivationResult.failure(
            plan_id=None,
            reason_codes=(
                TargetConstraintReasonCode.INVALID_SOURCE_MODEL,
            ),
            details={
                "actual_type": type(source_model).__name__,
            },
        )

    if not isinstance(candidate_plan, TargetLoweringPlan):
        return TargetConstraintDerivationResult.failure(
            plan_id=None,
            reason_codes=(
                TargetConstraintReasonCode.INVALID_CANDIDATE_PLAN,
            ),
            details={
                "actual_type": type(candidate_plan).__name__,
            },
        )

    if not isinstance(target_environment, TargetEnvironment):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.INVALID_TARGET_ENVIRONMENT,
            ),
            details={
                "actual_type": type(target_environment).__name__,
            },
        )

    if candidate_plan.kind is TargetLoweringKind.ABI_WRAPPER_CALL:
        result=_derive_abi_wrapper_0(source_model=source_model,candidate_plan=candidate_plan,target_environment=target_environment,abi_wrapper_registry=abi_wrapper_registry)
        return _validate_result_invariants(candidate_plan=candidate_plan,result=result)
    if candidate_plan.kind is TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER:
        result = _derive_privileged_runtime_0(
            source_model=source_model,
            candidate_plan=candidate_plan,
            target_environment=target_environment,
            privileged_runtime_registry=privileged_runtime_registry,
        )
        return _validate_result_invariants(
            candidate_plan=candidate_plan, result=result
        )
    if candidate_plan.kind is TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK:
        result = _derive_privileged_functional_0(
            source_model=source_model,
            candidate_plan=candidate_plan,
            target_environment=target_environment,
            privileged_functional_registry=privileged_functional_registry,
            privileged_functional_policy=privileged_functional_policy,
        )
        return _validate_result_invariants(
            candidate_plan=candidate_plan, result=result
        )
    deriver = _PLAN_KIND_DISPATCH.get(candidate_plan.kind)
    if deriver is None:
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.UNKNOWN_PLAN_KIND,
            ),
            details={
                "actual_kind": str(candidate_plan.kind),
            },
        )

    result = deriver(
        source_model,
        candidate_plan,
        target_environment,
    )

    return _validate_result_invariants(
        candidate_plan=candidate_plan,
        result=result,
    )


__all__ = (
    "FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT",
    "TargetAbi",
    "TargetArchitecture",
    "TargetAsmDialect",
    "TargetConstraintDerivationResult",
    "TargetConstraintModel",
    "TargetConstraintReasonCode",
    "TargetControlFlowConstraint",
    "TargetEnvironment",
    "TargetMemoryConstraint",
    "TargetOperandClass",
    "TargetOperandConstraint",
    "TargetOperandRole",
    "derive_target_constraints",
)

# ---------------------------------------------------------------------------
# Deprecated private C-expression compatibility helpers below this marker are
# not part of the Phase 6C public dispatch and must not be used by new code.
# The authoritative implementation is c_module.phase6c_c_expression.
# They remain temporarily for source compatibility only; Phase 6C dispatch
# reaches the module implementation exclusively through _derive_c_expression_0.
# ---------------------------------------------------------------------------

def _reject_if_operand_facts_incomplete(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if source_model.operands.complete:
        return None

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.SOURCE_OPERAND_FACTS_INCOMPLETE,
        ),
        details={
            "missing_fact_codes": ",".join(
                source_model.operands.missing_fact_codes
            ),
        },
    )


def _reject_if_operation_facts_incomplete(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if source_model.operation.complete:
        return None

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.SOURCE_OPERATION_FACTS_INCOMPLETE,
        ),
    )


def _reject_if_atomic_facts_incomplete(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if source_model.atomic.complete:
        return None

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.SOURCE_ATOMIC_FACTS_INCOMPLETE,
        ),
    )


def _reject_if_barrier_facts_incomplete(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if source_model.barrier.complete:
        return None

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.SOURCE_BARRIER_FACTS_INCOMPLETE,
        ),
    )


def _reject_if_implicit_state_facts_incomplete(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if source_model.implicit_state.complete:
        return None

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.SOURCE_IMPLICIT_STATE_FACTS_INCOMPLETE,
        ),
    )


def _reject_if_control_flow_facts_incomplete(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> TargetConstraintDerivationResult | None:
    if source_model.control_flow.cfg_ok:
        return None

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.SOURCE_CONTROL_FLOW_FACTS_INCOMPLETE,
        ),
        details={
            "cfg_error": source_model.control_flow.cfg_error,
        },
    )

def _c_expression_constraint_failure(
    *,
    candidate_plan: TargetLoweringPlan,
    exc: BaseException,
) -> TargetConstraintDerivationResult:
    """
    Convert C-expression derivation and intrinsic-validation failures into a
    fail-closed Phase 6C result.

    Classification rules:

      * CExpressionConstraintValidationError with an explicit reason code:
        preserve the exact C-expression reason code and structured details.

      * Legacy/unclassified CExpressionConstraintValidationError:
        classify as C_EXPRESSION_CONSTRAINT_INVALID.

      * TypeError / ValueError raised outside the classified domain-error
        protocol:
        treat as INTERNAL_INVARIANT_VIOLATION rather than pretending that the
        candidate merely lacks a valid C-expression contract.

      * Any unexpected exception:
        also treat as INTERNAL_INVARIANT_VIOLATION.

    Exception text is intentionally not used as a semantic interface.
    """

    base_details: dict[str, TargetConstraintDetailValue] = {
        "stage": "c_expression_constraint_derivation",
        "exception_type": type(exc).__name__,
    }

    if isinstance(exc, CExpressionConstraintValidationError):
        reason_code = exc.reason_code

        details = dict(exc.details)
        details.update(base_details)

        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(reason_code,),
            details=details,
        )

    if isinstance(exc, (TypeError, ValueError)):
        return TargetConstraintDerivationResult.failure(
            plan_id=candidate_plan.plan_id,
            reason_codes=(
                TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
            ),
            details={
                **base_details,
                "component": "c_expression_derivation",
                "failure_class": "unexpected_type_or_value_error",
            },
        )

    return TargetConstraintDerivationResult.failure(
        plan_id=candidate_plan.plan_id,
        reason_codes=(
            TargetConstraintReasonCode.INTERNAL_INVARIANT_VIOLATION,
        ),
        details={
            **base_details,
            "component": "c_expression_derivation",
            "failure_class": "unexpected_exception",
        },
    )

def _build_c_expression_constraint_from_authoritative_facts(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> CExpressionConstraint:
    """
    Build a typed structured-C expression constraint solely from authoritative
    SourceSemanticModel facts.

    This function must not inspect:

      * candidate_plan.metadata for source semantics;
      * source_model.xlen as an operand-width fallback;
      * raw asm, mnemonic, instruction, or IR text;
      * runtime-fact implementation details;
      * host Python or C integer widths.

    Any unavailable or unsupported semantic fact must raise
    CExpressionConstraintValidationError with a stable Phase 6C reason code.
    """
    if candidate_plan.kind is not TargetLoweringKind.C_EXPRESSION:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_PLAN_KIND_MISMATCH,
            details={
                "expected_plan_kind": (
                    TargetLoweringKind.C_EXPRESSION.value
                ),
                "actual_plan_kind": candidate_plan.kind.value,
            },
        )

    _require_c_expression_source_eligibility(
        source_model=source_model,
        candidate_plan=candidate_plan,
    )

    operation_kind = _map_source_operation_to_c_expression_operation(
        source_model.operation
    )

    result_source_operand = source_model.operands.result
    input_source_operands = source_model.operands.inputs

    if result_source_operand is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_RESULT_CONTRACT_INVALID,
            details={
                "missing_fact": "source_model.operands.result",
            },
        )

    if not input_source_operands:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERAND_BINDING_MISSING,
            details={
                "missing_fact": "source_model.operands.inputs",
            },
        )

    result_type = _build_c_expression_type_contract(
        operand=result_source_operand,
        role="result",
    )

    operand_bindings = tuple(
        _build_c_expression_operand_binding(
            operand=operand,
            ordinal=index,
        )
        for index, operand in enumerate(input_source_operands)
    )

    constraint = CExpressionConstraint(
        plan_id=candidate_plan.plan_id,
        operation_kind=operation_kind,
        result_type=result_type,
        operands=operand_bindings,
    )

    validate_c_expression_constraint(constraint)
    return constraint

def _require_c_expression_source_eligibility(
    *,
    source_model: SourceSemanticModel,
    candidate_plan: TargetLoweringPlan,
) -> None:
    if not source_model.shell.is_neutral:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_SHELL_NOT_NEUTRAL,
            details={
                "shell_kind": source_model.shell.kind.value,
            },
        )

    if source_model.memory_effect is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_MEMORY_UNKNOWN,
            details={
                "missing_fact": "source_model.memory_effect",
            },
        )

    if not source_model.memory_effect.is_no_memory_effect():
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_MEMORY_UNSUPPORTED,
            details={
                "memory_effect_kind": (
                    source_model.memory_effect.kind.value
                ),
            },
        )

    if source_model.atomic_effect:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_ATOMIC_UNSUPPORTED,
            details={
                "atomic_effect": True,
            },
        )

    if source_model.barrier_effect:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_BARRIER_UNSUPPORTED,
            details={
                "barrier_effect": True,
            },
        )

    if not source_model.control_flow.is_simple_fallthrough():
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_CONTROL_FLOW_UNSUPPORTED,
            details={
                "control_flow_kind": (
                    source_model.control_flow.kind.value
                ),
            },
        )

    if source_model.helper_abi is not None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_HELPER_ABI_UNSUPPORTED,
            details={
                "helper_abi_id": source_model.helper_abi.identifier,
            },
        )

    if source_model.operands.output_count > 1:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_MULTIPLE_OUTPUTS_UNSUPPORTED,
            details={
                "output_count": source_model.operands.output_count,
            },
        )
        
# C-expression mapping lives in phase6c_c_expression.py.  Keep this legacy
# name inert so old private helpers cannot become a second semantic source.
_SOURCE_TO_C_EXPRESSION_OPERATION: Mapping[object, object] = {}

def _map_source_operation_to_c_expression_operation(
    operation: SourceOperation | None,
) -> CExpressionOperationKind:
    if operation is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERATION_INCOMPLETE,
            details={
                "missing_fact": "source_model.operation",
            },
        )

    if not isinstance(operation.kind, SourceOperationKind):
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERATION_UNKNOWN,
            details={
                "operation_kind_type": type(operation.kind).__name__,
            },
        )

    mapping: Mapping[
        SourceOperationKind,
        CExpressionOperationKind,
    ] = {
        SourceOperationKind.ADD: CExpressionOperationKind.ADD,
        SourceOperationKind.SUB: CExpressionOperationKind.SUB,
        SourceOperationKind.BIT_AND: CExpressionOperationKind.BIT_AND,
        SourceOperationKind.BIT_OR: CExpressionOperationKind.BIT_OR,
        SourceOperationKind.BIT_XOR: CExpressionOperationKind.BIT_XOR,
    }

    try:
        return mapping[operation.kind]
    except KeyError:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERATION_UNSUPPORTED,
            details={
                "source_operation_kind": operation.kind.value,
            },
        ) from None

def _build_c_expression_type_contract(
    *,
    operand: SourceOperand,
    role: str,
) -> CExpressionTypeContract:
    if operand.width_bits is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISSING,
            details={
                "role": role,
                "source_operand_index": operand.index,
            },
        )

    if (
        isinstance(operand.width_bits, bool)
        or not isinstance(operand.width_bits, int)
        or operand.width_bits <= 0
    ):
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_RESULT_CONTRACT_INVALID,
            details={
                "role": role,
                "source_operand_index": operand.index,
                "invalid_field": "width_bits",
            },
        )

    if operand.signedness is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERAND_SIGNEDNESS_MISSING,
            details={
                "role": role,
                "source_operand_index": operand.index,
            },
        )

    if operand.signedness not in (
        SourceSignedness.SIGNED,
        SourceSignedness.UNSIGNED,
    ):
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_RESULT_CONTRACT_INVALID,
            details={
                "role": role,
                "source_operand_index": operand.index,
                "invalid_field": "signedness",
            },
        )

    return CExpressionTypeContract(
        width_bits=operand.width_bits,
        signedness=operand.signedness,
    )

def _build_c_expression_operand_binding(
    *,
    operand: SourceOperand,
    ordinal: int,
) -> CExpressionOperandBinding:
    if operand.binding is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERAND_BINDING_MISSING,
            details={
                "operand_ordinal": ordinal,
                "source_operand_index": operand.index,
            },
        )

    if operand.width_bits is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERAND_WIDTH_MISSING,
            details={
                "operand_ordinal": ordinal,
                "source_operand_index": operand.index,
            },
        )

    if operand.signedness is None:
        raise CExpressionConstraintValidationError(
            TargetConstraintReasonCode.C_EXPRESSION_OPERAND_SIGNEDNESS_MISSING,
            details={
                "operand_ordinal": ordinal,
                "source_operand_index": operand.index,
            },
        )

    return CExpressionOperandBinding(
        ordinal=ordinal,
        source_operand_index=operand.index,
        binding=operand.binding,
        type_contract=CExpressionTypeContract(
            width_bits=operand.width_bits,
            signedness=operand.signedness,
        ),
    )
