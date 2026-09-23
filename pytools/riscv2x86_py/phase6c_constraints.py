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
    PRIVILEGED_EFFECT_MAPPING_MISSING = "phase6c.privileged_effect_mapping_missing"
    PRIVILEGED_EFFECT_MAPPING_AMBIGUOUS = "phase6c.privileged_effect_mapping_ambiguous"
    PRIVILEGED_RUNTIME_PROFILE_MISMATCH = "phase6c.privileged_runtime_profile_mismatch"
    PRIVILEGED_RUNTIME_VERSION_MISMATCH = "phase6c.privileged_runtime_version_mismatch"
    PRIVILEGED_MMU_SCOPE_INCOMPLETE = "phase6c.privileged_mmu_scope_incomplete"
    PRIVILEGED_RENDERER_CONTRACT_INCOMPLETE = "phase6c.privileged_renderer_contract_incomplete"
    PRIVILEGED_SHELL_UNSUPPORTED = "phase6c.privileged_shell_unsupported"
    PRIVILEGED_IGNORED_STATE_MISMATCH = "phase6c.privileged_ignored_state_mismatch"
    PRIVILEGED_RUNTIME_SOURCE_INCOMPLETE = (
        "phase6c.privileged_runtime_source_incomplete"
    )
    PRIVILEGED_PLAN_CLASS_MISMATCH = (
        "phase6c.privileged_plan_class_mismatch"
    )
    PRIVILEGED_STATE_MACHINE_NEEDS_ROUTE = (
        "phase6c.privileged_state_machine_needs_route"
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
            if not isinstance(self.fixed_register_name, str)5ën-¢G§²ÚîÆ­yØ€€€€€€€€€€€…¹¹½ÐÍ•±˜¹É•ÅÕ¥É•Í}ÍÁ•Õ±…Ñ¥½¹}½¹ÑÉ½°(€€€€€€€€¤()‘…Ñ…±…ÍÌ¡™É½é•¸õQÉÕ”¤)±…ÍÌQ…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ðè(€€€€ˆˆˆ(€€€MÑÉÕÑÕÉ•½¹ÑÉ½°µ™±½Ü°	$°…¹¥µÁ±¥¥ÐµÍÑ…Ñ”Ñ…É•Ð½¹ÑÉ…Ð¸((€€€Q¡¥ÌQ<‘½•Ì¹½ÐÉ•¹‘•È±…‰•±Ì°…Í´µ½Ñ¼Íå¹Ñ…à°½È¡•±Á•È…±°Ñ•áÐ¸(€€€€ˆˆˆ((€€€ÁÉ•Í•ÉÙ•}½¹ÑÉ½±}™±½Üè‰½½°€ô…±Í”(€€€ÁÉ•Í•ÉÙ•}…Íµ}½Ñ¼è‰½½°€ô…±Í”(€€€ÁÉ•Í•ÉÙ•}É•ÑÉå}±½½Àè‰½½°€ô…±Í”(€€€É•ÅÕ¥É•Í}¡•±Á•É}…‰¥}½¹ÑÉ…Ðè‰½½°€ô…±Í”((€€€ÁÉ•Í•ÉÙ•}½¹‘¥Ñ¥½¹}½‘•Ìè‰½½°€ô…±Í”(€€€ÁÉ•Í•ÉÙ•}ÍÑ…­}Á½¥¹Ñ•Èè‰½½°€ô…±Í”(€€€ÁÉ•Í•ÉÙ•}™É…µ•}Á½¥¹Ñ•Èè‰½½°€ô…±Í”((€€€‘•˜}}Á½ÍÑ}¥¹¥Ñ}|¡Í•±˜¤€´ø9½¹”è(€€€€€€€™½È™¥•±‘}¹…µ”¥¸€ (€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}½¹ÑÉ½±}™±½Üˆ°(€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}…Íµ}½Ñ¼ˆ°(€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}É•ÑÉå}±½½Àˆ°(€€€€€€€€€€€€‰É•ÅÕ¥É•Í}¡•±Á•É}…‰¥}½¹ÑÉ…Ðˆ°(€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}½¹‘¥Ñ¥½¹}½‘•Ìˆ°(€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}ÍÑ…­}Á½¥¹Ñ•Èˆ°(€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}™É…µ•}Á½¥¹Ñ•Èˆ°(€€€€€€€€¤è(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡•Ñ…ÑÑÈ¡Í•±˜°™¥•±‘}¹…µ”¤°‰½½°¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€˜‰í™¥•±‘}¹…µ•ôµÕÍÐ‰”‰½½°ˆ(€€€€€€€€€€€€€€€€¤(€€€‘•˜¥Í}Í¥µÁ±•}™…±±Ñ¡É½Õ ¡Í•±˜¤€´ø‰½½°è(€€€€€€€€ˆˆˆ(€€€€€€€I•ÑÕÉ¸Ý¡•Ñ¡•ÈÑ¡¥Ì½¹ÑÉ…ÐÉ•ÁÉ•Í•¹ÑÌ½É‘¥¹…ÉäÍ•ÅÕ•¹Ñ¥…°½¹ÑÉ½°(€€€€€€€™±½Ü½¹±ä¸((€€€€€€€A¡…Í”€Ù´Èµ•áÁÉ•ÍÍ¥½¸±½Ý•É¥¹œ…¹¹½Ðµ½‘•°…Í´µ½Ñ¼‰•¡…Ù¥½È°(€€€€€€€É•ÑÉä±½½ÁÌ°¡•±Á•È	$½¹ÑÉ½°µ™±½Ü½‰±¥…Ñ¥½¹Ì°½¹‘¥Ñ¥½¸µ½‘”(€€€€€€€ÁÉ•Í•ÉÙ…Ñ¥½¸°½È•áÁ±¥¥ÐÍÑ…¬½™É…µ”ÁÉ•Í•ÉÙ…Ñ¥½¸½¹ÑÉ…ÑÌ¸(€€€€€€€€ˆˆˆ(€€€€€€€É•ÑÕÉ¸€ (€€€€€€€€€€€¹½ÐÍ•±˜¹ÁÉ•Í•ÉÙ•}½¹ÑÉ½±}™±½Ü(€€€€€€€€€€€…¹¹½ÐÍ•±˜¹ÁÉ•Í•ÉÙ•}…Íµ}½Ñ¼(€€€€€€€€€€€…¹¹½ÐÍ•±˜¹ÁÉ•Í•ÉÙ•}É•ÑÉå}±½½À(€€€€€€€€€€€…¹¹½ÐÍ•±˜¹É•ÅÕ¥É•Í}¡•±Á•É}…‰¥}½¹ÑÉ…Ð(€€€€€€€€€€€…¹¹½ÐÍ•±˜¹ÁÉ•Í•ÉÙ•}½¹‘¥Ñ¥½¹}½‘•Ì(€€€€€€€€€€€…¹¹½ÐÍ•±˜¹ÁÉ•Í•ÉÙ•}ÍÑ…­}Á½¥¹Ñ•È(€€€€€€€€€€€…¹¹½ÐÍ•±˜¹ÁÉ•Í•ÉÙ•}™É…µ•}Á½¥¹Ñ•È(€€€€€€€€¤()‘…Ñ…±…ÍÌ¡™É½é•¸õQÉÕ”¤)±…ÍÌQ…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•°è(€€€€ˆˆˆ(€€€MÕ•ÍÍ™Õ°A¡…Í”€Ù½¹ÍÑÉ…¥¹Ð‘•É¥Ù…Ñ¥½¸É•ÍÕ±Ð¸((€€€%µÁ½ÉÑ…¹Ðè((€€€€€€¨Q¡¥Ì¥Ì¹½ÐÉ•¹‘•É•…Í´¸(€€€€€€¨Q¡¥Ì¥Ì¹½Ð9T¥¹±¥¹”µ…Í´Ñ•áÐ¸(€€€€€€¨Q¡¥Ì¥Ì¹½ÐA¡…Í”€ÙÁÉ½½˜½ÕÑÁÕÐ¸(€€€€€€¨Q¡¥Ì‘½•Ì¹½Ðµ•…¸Ñ¡”…¹‘¥‘…Ñ”¥Ì…ÁÁÉ½Ù•¸(€€€€€€¨Q¡¥ÌµÕÍÐ‰”½¹ÍÑÉÕÑ•½¹±ä™É½´…ÕÑ¡½É¥Ñ…Ñ¥Ù”ÍÑÉÕÑÕÉ•™…ÑÌ¸((€€€½¹ÍÑÉ…¥¹Ðµ½‘•°µ…ä‘•ÍÉ¥‰”•¥Ñ¡•Èè((€€€€€€¨„Ñ…É•Ðµ¥¹±¥¹”µ…Í´µ½É¥•¹Ñ•±½Ý•É¥¹œ½¹ÑÉ…Ðì½È(€€€€€€¨„ÍÑÉÕÑÕÉ•µ•áÁÉ•ÍÍ¥½¸±½Ý•É¥¹œ½¹ÑÉ…Ð¸((€€€%ÐµÕÍÐ¹½Ð…µ‰¥Õ½ÕÍ±ä‘•ÍÉ¥‰”‰½Ñ …Ð½¹”¸(€€€€ˆˆˆ((€€€Á±…¹}¥èÍÑÈ(€€€•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð((€€€½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌèQÕÁ±•mQ…É•Ñ=Á•É…¹‘½¹ÍÑÉ…¥¹Ð°€¸¸¹t€ô€ ¤(€€€µ•µ½Éå}½¹ÍÑÉ…¥¹ÐèQ…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð€ôQ…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð ¤(€€€½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐèQ…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð€ô€ (€€€€€€€Q…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð ¤(€€€€¤((€€€€ŒAÉ•Í•¹Ð½¹±ä™½È„ÍÑÉÕÑÕÉ•µ•áÁÉ•ÍÍ¥½¸±½Ý•É¥¹œ½¹ÑÉ…Ð¸(€€€€Œ(€€€€ŒQ¡¥Ì¥ÌÍÑÉÕÑÕÉ•Í•µ…¹Ñ¥Œ¥¹™½Éµ…Ñ¥½¸°¹½ÐÉ•¹‘•É•Ñ•áÐ¸(€€€€Œ%ÐµÕÍÐ¹½Ð‰”½µ‰¥¹•Ý¥Ñ 9T¥¹±¥¹”µ…Í´µÍÁ•¥™¥Œ½¹ÍÑÉ…¥¹ÑÌ¸(€€€}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ààÙ}¹Õ}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ààÙ}µ•µ½Éå}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ààÙ}…Ñ½µ¥}½¹ÑÉ…Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ààÙ}‰…ÉÉ¥•É}½¹ÑÉ…Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý}½¹ÑÉ…Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€¡•±Á•É}…‰¥}½¹ÑÉ…Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ÍÑ…­}É•‰¥¹‘¥¹}½¹ÍÑÉ…¥¹Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•}½¹ÍÑÉ…¥¹Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€…‰¥}ÝÉ…ÁÁ•É}½¹ÍÑÉ…¥¹Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÍÑÉ…¥¹Ðè½‰©•Ðð9½¹”€ô9½¹”(€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÍÑÉ…¥¹Ðè½‰©•Ðð9½¹”€ô9½¹”((€€€ÁÉ•Í•ÉÙ•}Ù½±…Ñ¥±”è‰½½°€ô…±Í”(€€€ÁÉ•Í•ÉÙ•}}±½‰‰•Èè‰½½°€ô…±Í”(€€€ÁÉ•Í•ÉÙ•}¥µÁ±¥¥Ñ}µ…¡¥¹•}ÍÑ…Ñ”è‰½½°€ô…±Í”(€€€Ñ…É•Ñ}É•¥ÍÑ•É}Á½±¥å}Ù•ÉÍ¥½¸èÍÑÈ€ôA=1%e}YIM%=8((€€€‘•˜}}Á½ÍÑ}¥¹¥Ñ}|¡Í•±˜¤€´ø9½¹”è(€€€€€€€¥˜€ (€€€€€€€€€€€¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹Á±…¹}¥°ÍÑÈ¤(€€€€€€€€€€€½È¹½ÐÍ•±˜¹Á±…¹}¥¹ÍÑÉ¥À ¤(€€€€€€€€€€€½ÈÍ•±˜¹Á±…¹}¥€„ôÍ•±˜¹Á±…¹}¥¹ÍÑÉ¥À ¤(€€€€€€€€¤è(€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€‰Á±…¹}¥µÕÍÐ‰”„¹½¸µ•µÁÑäÍÑÉ¥ÁÁ•ÍÑÈˆ(€€€€€€€€€€€€¤((€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹•¹Ù¥É½¹µ•¹Ð°Q…É•Ñ¹Ù¥É½¹µ•¹Ð¤è(€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€‰•¹Ù¥É½¹µ•¹ÐµÕÍÐ‰”Q…É•Ñ¹Ù¥É½¹µ•¹Ðˆ(€€€€€€€€€€€€¤((€€€€€€€¹½Éµ…±¥é•‘}½Á•É…¹‘Ì€ôÑÕÁ±”¡Í•±˜¹½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌ¤(€€€€€€€¥˜Í•±˜¹Ñ…É•Ñ}É•¥ÍÑ•É}Á½±¥å}Ù•ÉÍ¥½¸€„ôA=1%e}YIM%=8è(€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰Ñ…É•Ñ}É•¥ÍÑ•É}Á½±¥å}Ù•ÉÍ¥½¸µÕÍÐ‰”Ñ¡”…Ñ¥Ù”Á½±¥äÙ•ÉÍ¥½¸ˆ¤((€€€€€€€¥¹Ù…±¥‘}½Á•É…¹‘Ì€ôÑÕÁ±” (€€€€€€€€€€€¥Ñ•´(€€€€€€€€€€€™½È¥Ñ•´¥¸¹½Éµ…±¥é•‘}½Á•É…¹‘Ì(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡¥Ñ•´°Q…É•Ñ=Á•É…¹‘½¹ÍÑÉ…¥¹Ð¤(€€€€€€€€¤(€€€€€€€¥˜¥¹Ù…±¥‘}½Á•É…¹‘Ìè(€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€‰½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌµÕÍÐ½¹Ñ…¥¸½¹±ä€ˆ(€€€€€€€€€€€€€€€€‰Q…É•Ñ=Á•É…¹‘½¹ÍÑÉ…¥¹ÐÙ…±Õ•Ìˆ(€€€€€€€€€€€€¤((€€€€€€€¥¹‘•á•Ì€ôÑÕÁ±” (€€€€€€€€€€€½Á•É…¹¹Í½ÕÉ•}½Á•É…¹‘}¥¹‘•à(€€€€€€€€€€€™½È½Á•É…¹¥¸¹½Éµ…±¥é•‘}½Á•É…¹‘Ì(€€€€€€€€¤(€€€€€€€¥˜±•¸¡Í•Ð¡¥¹‘•á•Ì¤¤€„ô±•¸¡¥¹‘•á•Ì¤è(€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È (€€€€€€€€€€€€€€€€‰½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌµÕÍÐ¹½Ð‘ÕÁ±¥…Ñ”€ˆ(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆ(€€€€€€€€€€€€¤((€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹” (€€€€€€€€€€€Í•±˜¹µ•µ½Éå}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Q…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð°(€€€€€€€€¤è(€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€‰µ•µ½Éå}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”Q…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ðˆ(€€€€€€€€€€€€¤((€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹” (€€€€€€€€€€€Í•±˜¹½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Q…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð°(€€€€€€€€¤è(€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€‰½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”€ˆ(€€€€€€€€€€€€€€€€‰Q…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ðˆ(€€€€€€€€€€€€¤((€€€€€€€¥˜Í•±˜¹}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}}•áÁÉ•ÍÍ¥½¸¥µÁ½ÉÐáÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð°áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}}‰Õ¥±Ñ¥¸¥µÁ½ÉÐ	Õ¥±Ñ¥¹½¹ÑÉ…Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹Ð°	Õ¥±Ñ¥¹½¹ÑÉ…Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”	Õ¥±Ñ¥¹½¹ÑÉ…Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹ààÙ}¹Õ}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}¹Õ}¥¹±¥¹•}…Í´¥µÁ½ÉÐ`àÙ¹Õ%¹±¥¹•Íµ½¹ÑÉ…Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹ààÙ}¹Õ}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ð°`àÙ¹Õ%¹±¥¹•Íµ½¹ÑÉ…Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰ààÙ}¹Õ}¥¹±¥¹•}…Íµ}½¹ÑÉ…ÐµÕÍÐ‰”`àÙ¹Õ%¹±¥¹•Íµ½¹ÑÉ…Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹ààÙ}µ•µ½Éå}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}µ•µ½Éå}¥¹±¥¹•}…Í´¥µÁ½ÉÐ`àÙ5•µ½Éå%¹±¥¹•Íµ½¹ÑÉ…Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹ààÙ}µ•µ½Éå}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ð°`àÙ5•µ½Éå%¹±¥¹•Íµ½¹ÑÉ…Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰ààÙ}µ•µ½Éå}¥¹±¥¹•}…Íµ}½¹ÑÉ…ÐµÕÍÐ‰”`àÙ5•µ½Éå%¹±¥¹•Íµ½¹ÑÉ…Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹ààÙ}…Ñ½µ¥}½¹ÑÉ…Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}…Ñ½µ¥}‰…ÉÉ¥•È¥µÁ½ÉÐ`àÙÑ½µ¥½¹ÑÉ…Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹ààÙ}…Ñ½µ¥}½¹ÑÉ…Ð°`àÙÑ½µ¥½¹ÑÉ…Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰ààÙ}…Ñ½µ¥}½¹ÑÉ…ÐµÕÍÐ‰”`àÙÑ½µ¥½¹ÑÉ…Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹ààÙ}‰…ÉÉ¥•É}½¹ÑÉ…Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}…Ñ½µ¥}‰…ÉÉ¥•È¥µÁ½ÉÐ`àÙ	…ÉÉ¥•É½¹ÑÉ…Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹ààÙ}‰…ÉÉ¥•É}½¹ÑÉ…Ð°`àÙ	…ÉÉ¥•É½¹ÑÉ…Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰ààÙ}‰…ÉÉ¥•É}½¹ÑÉ…ÐµÕÍÐ‰”`àÙ	…ÉÉ¥•É½¹ÑÉ…Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý}½¹ÑÉ…Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ü¥µÁ½ÉÐMÑÉÕÑÕÉ•‘½¹ÑÉ½±±½Ý½¹ÑÉ…Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý}½¹ÑÉ…Ð°MÑÉÕÑÕÉ•‘½¹ÑÉ½±±½Ý½¹ÑÉ…Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý}½¹ÑÉ…ÐµÕÍÐ‰”MÑÉÕÑÕÉ•‘½¹ÑÉ½±±½Ý½¹ÑÉ…Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹¡•±Á•É}…‰¥}½¹ÑÉ…Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}¡•±Á•É}…‰¤¥µÁ½ÉÐ!•±Á•É‰¥½¹ÑÉ…Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹¡•±Á•É}…‰¥}½¹ÑÉ…Ð°!•±Á•É‰¥½¹ÑÉ…Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰¡•±Á•É}…‰¥}½¹ÑÉ…ÐµÕÍÐ‰”!•±Á•É‰¥½¹ÑÉ…Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹ÍÑ…­}É•‰¥¹‘¥¹}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹ÍÑ…­}É•‰¥¹‘¥¹œ¥µÁ½ÉÐQ…É•ÑMÑ…­I•‰¥¹‘¥¹½¹ÍÑÉ…¥¹Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹ÍÑ…­}É•‰¥¹‘¥¹}½¹ÍÑÉ…¥¹Ð°Q…É•ÑMÑ…­I•‰¥¹‘¥¹½¹ÍÑÉ…¥¹Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰ÍÑ…­}É•‰¥¹‘¥¹}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”Q…É•ÑMÑ…­I•‰¥¹‘¥¹½¹ÍÑÉ…¥¹Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ”¥µÁ½ÉÐQ…É•ÑY¥ÉÑÕ…±AÉ¥Ù…Ñ•É…µ•½¹ÍÑÉ…¥¹Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•}½¹ÍÑÉ…¥¹Ð°Q…É•ÑY¥ÉÑÕ…±AÉ¥Ù…Ñ•É…µ•½¹ÍÑÉ…¥¹Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”Q…É•ÑY¥ÉÑÕ…±AÉ¥Ù…Ñ•É…µ•½¹ÍÑÉ…¥¹Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹…‰¥}ÝÉ…ÁÁ•É}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹…‰¥}ÝÉ…ÁÁ•È¥µÁ½ÉÐQ…É•Ñ‰¥]É…ÁÁ•É½¹ÍÑÉ…¥¹Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í•±˜¹…‰¥}ÝÉ…ÁÁ•É}½¹ÍÑÉ…¥¹Ð°Q…É•Ñ‰¥]É…ÁÁ•É½¹ÍÑÉ…¥¹Ð¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È ‰…‰¥}ÝÉ…ÁÁ•É}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”Q…É•Ñ‰¥]É…ÁÁ•É½¹ÍÑÉ…¥¹Ð½È9½¹”ˆ¤(€€€€€€€¥˜Í•±˜¹ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÑÉ…ÑÌ¥µÁ½ÉÐQ…É•ÑAÉ¥Ù¥±••‘IÕ¹Ñ¥µ•½¹ÍÑÉ…¥¹Ð(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹” (€€€€€€€€€€€€€€€Í•±˜¹ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘IÕ¹Ñ¥µ•½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€€¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”€ˆ(€€€€€€€€€€€€€€€€€€€€‰Q…É•ÑAÉ¥Ù¥±••‘IÕ¹Ñ¥µ•½¹ÍÑÉ…¥¹Ð½È9½¹”ˆ(€€€€€€€€€€€€€€€€¤(€€€€€€€¥˜Í•±˜¹ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€™É½´€¹ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÑÉ…ÑÌ¥µÁ½ÉÐ€ (€€€€€€€€€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€€¤(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹” (€€€€€€€€€€€€€€€Í•±˜¹ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€€¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÍÑÉ…¥¹ÐµÕÍÐ‰”€ˆ(€€€€€€€€€€€€€€€€€€€€‰Q…É•ÑAÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­½¹ÍÑÉ…¥¹Ð½È9½¹”ˆ(€€€€€€€€€€€€€€€€¤(€€€€€€€¥˜Í•±˜¹}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”…¹Í•±˜¹}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌ…¹¹½Ð½¹Ñ…¥¸‰½Ñ •áÁÉ•ÍÍ¥½¸…¹‰Õ¥±Ñ¥¸½¹ÑÉ…ÑÌˆ¤(€€€€€€€ÍÁ•¥…±¥é•‘}½¹ÑÉ…ÑÌ€ô€ (€€€€€€€€€€€Í•±˜¹}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Í•±˜¹}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Í•±˜¹ààÙ}¹Õ}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ð°(€€€€€€€€€€€Í•±˜¹ààÙ}µ•µ½Éå}¥¹±¥¹•}…Íµ}½¹ÑÉ…Ð°(€€€€€€€€€€€Í•±˜¹ààÙ}…Ñ½µ¥}½¹ÑÉ…Ð°(€€€€€€€€€€€Í•±˜¹ààÙ}‰…ÉÉ¥•É}½¹ÑÉ…Ð°(€€€€€€€€€€€Í•±˜¹ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý}½¹ÑÉ…Ð°(€€€€€€€€€€€Í•±˜¹¡•±Á•É}…‰¥}½¹ÑÉ…Ð°(€€€€€€€€€€€Í•±˜¹ÍÑ…­}É•‰¥¹‘¥¹}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Í•±˜¹Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Í•±˜¹…‰¥}ÝÉ…ÁÁ•É}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Í•±˜¹ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€€€€Í•±˜¹ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÍÑÉ…¥¹Ð°(€€€€€€€€¤(€€€€€€€¥˜ÍÕ´¡½¹ÑÉ…Ð¥Ì¹½Ð9½¹”™½È½¹ÑÉ…Ð¥¸ÍÁ•¥…±¥é•‘}½¹ÑÉ…ÑÌ¤€ø€Äè(€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È ‰Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌµÕÍÐ½¹Ñ…¥¸•á…Ñ±ä½¹”±½Ý•É¥¹œ½¹ÑÉ…Ðˆ¤((€€€€€€€™½È™¥•±‘}¹…µ”¥¸€ (€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}Ù½±…Ñ¥±”ˆ°(€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}}±½‰‰•Èˆ°(€€€€€€€€€€€€‰ÁÉ•Í•ÉÙ•}¥µÁ±¥¥Ñ}µ…¡¥¹•}ÍÑ…Ñ”ˆ°(€€€€€€€€¤è(€€€€€€€€€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡•Ñ…ÑÑÈ¡Í•±˜°™¥•±‘}¹…µ”¤°‰½½°¤è(€€€€€€€€€€€€€€€É…¥Í”QåÁ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€˜‰í™¥•±‘}¹…µ•ôµÕÍÐ‰”‰½½°ˆ(€€€€€€€€€€€€€€€€¤((€€€€€€€¥˜Í•±˜¹}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”è(€€€€€€€€€€€¥˜¹½Éµ…±¥é•‘}½Á•É…¹‘Ìè(€€€€€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰•áÁÉ•ÍÍ¥½¸Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌµÕÍÐ¹½Ð½¹Ñ…¥¸€ˆ(€€€€€€€€€€€€€€€€€€€€‰9T…Í´½Á•É…¹½¹ÍÑÉ…¥¹ÑÌˆ(€€€€€€€€€€€€€€€€¤((€€€€€€€€€€€¥˜Í•±˜¹ÁÉ•Í•ÉÙ•}Ù½±…Ñ¥±”è(€€€€€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰•áÁÉ•ÍÍ¥½¸Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌµÕÍÐ¹½ÐÁÉ•Í•ÉÙ”€ˆ(€€€€€€€€€€€€€€€€€€€€‰Ù½±…Ñ¥±”…Í´Í•µ…¹Ñ¥Ìˆ(€€€€€€€€€€€€€€€€¤((€€€€€€€€€€€¥˜Í•±˜¹ÁÉ•Í•ÉÙ•}}±½‰‰•Èè(€€€€€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰•áÁÉ•ÍÍ¥½¸Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌµÕÍÐ¹½ÐÁÉ•Í•ÉÙ”€ˆ(€€€€€€€€€€€€€€€€€€€€‰½¹‘¥Ñ¥½¸µ½‘”±½‰‰•ÉÌˆ(€€€€€€€€€€€€€€€€¤((€€€€€€€€€€€¥˜Í•±˜¹ÁÉ•Í•ÉÙ•}¥µÁ±¥¥Ñ}µ…¡¥¹•}ÍÑ…Ñ”è(€€€€€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰•áÁÉ•ÍÍ¥½¸Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌµÕÍÐ¹½ÐÁÉ•Í•ÉÙ”€ˆ(€€€€€€€€€€€€€€€€€€€€‰¥µÁ±¥¥Ðµ…¡¥¹”ÍÑ…Ñ”ˆ(€€€€€€€€€€€€€€€€¤((€€€€€€€€€€€¥˜¹½ÐÍ•±˜¹µ•µ½Éå}½¹ÍÑÉ…¥¹Ð¹¥Í}¹½}µ•µ½Éå}•™™•Ð ¤è(€€€€€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰•áÁÉ•ÍÍ¥½¸Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌµÕÍÐ‰”µ•µ½Éäµ™É•”ˆ(€€€€€€€€€€€€€€€€¤((€€€€€€€€€€€¥˜¹½ÐÍ•±˜¹½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹Ð¹¥Í}Í¥µÁ±•}™…±±Ñ¡É½Õ  ¤è(€€€€€€€€€€€€€€€É…¥Í”Y…±Õ•ÉÉ½È (€€€€€€€€€€€€€€€€€€€€‰•áÁÉ•ÍÍ¥½¸Ñ…É•Ð½¹ÍÑÉ…¥¹ÑÌµÕÍÐÕÍ”Í¥µÁ±”€ˆ(€€€€€€€€€€€€€€€€€€€€‰™…±±Ñ¡É½Õ ½¹ÑÉ½°™±½Üˆ(€€€€€€€€€€€€€€€€¤((€€€€€€€½‰©•Ð¹}}Í•Ñ…ÑÑÉ}| (€€€€€€€€€€€Í•±˜°(€€€€€€€€€€€€‰½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌˆ°(€€€€€€€€€€€¹½Éµ…±¥é•‘}½Á•É…¹‘Ì°(€€€€€€€€¤()‘•˜}•¹Ù¥É½¹µ•¹Ñ}ÁÉ•¡•¬ (€€€€¨°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðð9½¹”è(€€€€ˆˆˆ(€€€¥á•Ñ…É•ÐµÁÉ½™¥±”½µÁ…Ñ¥‰¥±¥Ñä…Ñ”¸((€€€Q¡¥Ì¥ÌÑ¡”É•‘Õ•™½É´½˜Ñ¡”•…É±¥•È•¹•É¥ŒÑ…É•Ð…Á…‰¥±¥Ñä¡•¬¸((€€€%Ð¥Ì¥¹Ñ•¹Ñ¥½¹…±±äÍÑ…Ñ¥Œè((€€€€€€¨¹¼¡½ÍÐATÁÉ½‰¥¹œì(€€€€€€¨¹¼µÕ±Ñ¤µÑ…É•ÐÍ•±•Ñ¥½¸ì(€€€€€€¨¹¼½µÁ¥±•È…ÕÑ¼µ‘•Ñ•Ñ¥½¸ì(€€€€€€¨¹¼Í¥±•¹ÐÑ…É•Ð™…±±‰…¬¸((€€€Q¡”ÕÉÉ•¹ÐÁÉ½©•Ð…•ÁÑÌ½¹±äè((€€€€€€€ààÙ|ØÐ€¬9TP™P€¬MåÍX5ØÐ¸(€€€€ˆˆˆ((€€€¥˜Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…É¡¥Ñ•ÑÕÉ”¥Ì¹½ÐQ…É•ÑÉ¡¥Ñ•ÑÕÉ”¹`àÙ|ØÐè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹U9MUAA=IQ}QIQ}I!%QQUI°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…É¡¥Ñ•ÑÕÉ”ˆèÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…É¡¥Ñ•ÑÕÉ”¹Ù…±Õ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…Íµ}‘¥…±•Ð¥Ì¹½ÐQ…É•ÑÍµ¥…±•Ð¹9U}QPè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹U9MUAA=IQ}M5}%1P°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…Íµ}‘¥…±•ÐˆèÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…Íµ}‘¥…±•Ð¹Ù…±Õ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…‰¤¥Ì¹½ÐQ…É•Ñ‰¤¹MeMY}5ØÐè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹U9MUAA=IQ}QIQ}	$°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…‰¤ˆèÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…‰¤¹Ù…±Õ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥¹±¥¹•}…Íµ}­¥¹‘Ì€ô™É½é•¹Í•Ð (€€€€€€€ì(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹`àÙ}9U}%91%9}M4°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹`àÙ}Q=5%°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹`àÙ}	II%H°(€€€€€€€ô(€€€€¤((€€€¥˜€ (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥¸¥¹±¥¹•}…Íµ}­¥¹‘Ì(€€€€€€€…¹¹½ÐÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹ÍÕÁÁ½ÉÑÍ}¹Õ}¥¹±¥¹•}…Í´(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹9U}%91%9}M5}U9Y%1	1°(€€€€€€€€€€€€¤°(€€€€€€€€¤((€€€µ¥ÍÍ¥¹}™•…ÑÕÉ•Ì€ô€ (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸¹É•ÅÕ¥É•‘}™•…ÑÕÉ•Ì(€€€€€€€€´Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…Ù…¥±…‰±•}™•…ÑÕÉ•Ì(€€€€¤(€€€¥˜µ¥ÍÍ¥¹}™•…ÑÕÉ•Ìè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹A19}IEU%I}QUI}5%MM%9°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰µ¥ÍÍ¥¹}™•…ÑÕÉ•Ìˆè€ˆ°ˆ¹©½¥¸¡Í½ÉÑ•¡µ¥ÍÍ¥¹}™•…ÑÕÉ•Ì¤¤°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€™½É‰¥‘‘•¹}ÁÉ•Í•¹Ð€ô€ (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸¹™½É‰¥‘‘•¹}™•…ÑÕÉ•Ì(€€€€€€€€˜Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…Ù…¥±…‰±•}™•…ÑÕÉ•Ì(€€€€¤(€€€¥˜™½É‰¥‘‘•¹}ÁÉ•Í•¹Ðè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹A19}=I	%9}QUI}AIM9P°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰™½É‰¥‘‘•¹}™•…ÑÕÉ•Í}ÁÉ•Í•¹Ðˆè€ˆ°ˆ¹©½¥¸ (€€€€€€€€€€€€€€€€€€€Í½ÉÑ•¡™½É‰¥‘‘•¹}ÁÉ•Í•¹Ð¤(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€É•ÑÕÉ¸9½¹”(()‘•˜}¹½Ñ}¥µÁ±•µ•¹Ñ• (€€€€¨°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(€€€É•…Í½¹}½‘”èQ…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€ÁÉ•¡•¬€ô}•¹Ù¥É½¹µ•¹Ñ}ÁÉ•¡•¬ (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€¤(€€€¥˜ÁÉ•¡•¬¥Ì¹½Ð9½¹”è(€€€€€€€É•ÑÕÉ¸ÁÉ•¡•¬((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô¡É•…Í½¹}½‘”°¤°(€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€‰Á±…¹}­¥¹ˆè…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¹Ù…±Õ”°(€€€€€€€ô°(€€€€¤()‘•˜}‘•É¥Ù•}}•áÁÉ•ÍÍ¥½¹|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€€ˆˆˆ(€€€•É¥Ù”„ÁÕÉ”A¡…Í”€Ù´ÈÍÑÉÕÑÕÉ•µ•áÁÉ•ÍÍ¥½¸½¹ÑÉ…Ð¸((€€€Q¡¥ÌÁ…Ñ ¥Ì™…¥°µ±½Í•è((€€€€€€¨¹¼™…±±‰…¬Ñ¼9T¥¹±¥¹”…Í´ì(€€€€€€¨¹¼¥¹™•É•¹”™É½´É…Ü…Í´½È%HÑ•áÐì(€€€€€€¨¹¼Õ•ÍÍ•Í½ÕÉ”½Á•É…¹½É‘•Èì(€€€€€€¨¹¼¥¹™•ÉÉ•¡½ÍÐ•áÁÉ•ÍÍ¥½¸Ý¥‘Ñ ì(€€€€€€¨¹¼Õ¹ÍÕÁÁ½ÉÑ•Í¥‘”•™™•Ðµ…ä‰”Í¥±•¹Ñ±ä¥¹½É•¸(€€€€ˆˆˆ(€€€¥˜…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥Ì¹½ÐQ…É•Ñ1½Ý•É¥¹-¥¹¹}aAIMM%=8è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}A19}-%9}5%M5Q °(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰•áÁ•Ñ•‘}Á±…¹}­¥¹ˆè€ (€€€€€€€€€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹}aAIMM%=8¹Ù…±Õ”(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€€‰…ÑÕ…±}Á±…¹}­¥¹ˆè…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¹Ù…±Õ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€ÁÉ•¡•­}™…¥±ÕÉ”€ô}•¹Ù¥É½¹µ•¹Ñ}ÁÉ•¡•¬ (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€¤(€€€¥˜ÁÉ•¡•­}™…¥±ÕÉ”¥Ì¹½Ð9½¹”è(€€€€€€€É•ÑÕÉ¸ÁÉ•¡•­}™…¥±ÕÉ”((€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}}•áÁÉ•ÍÍ¥½¸¥µÁ½ÉÐ‘•É¥Ù•}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÌ(€€€É•ÑÕÉ¸‘•É¥Ù•}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÌ (€€€€€€€Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð(€€€€¤()‘•˜}‘•É¥Ù•}}ÍÑÉÕÑÕÉ•‘|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€‘•°Í½ÕÉ•}µ½‘•°((€€€É•ÑÕÉ¸}¹½Ñ}¥µÁ±•µ•¹Ñ• (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€€€€É•…Í½¹}½‘”ô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}MQIUQUI}9=Q}%5A159Q(€€€€€€€€¤°(€€€€¤(()‘•˜}‘•É¥Ù•}}‰Õ¥±Ñ¥¹|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}}‰Õ¥±Ñ¥¸¥µÁ½ÉÐ‘•É¥Ù•}}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹ÑÌ(€€€É•ÑÕÉ¸‘•É¥Ù•}}‰Õ¥±Ñ¥¹}½¹ÍÑÉ…¥¹ÑÌ¡Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤(()‘•˜}‘•É¥Ù•}ÍÑ…­}…‘‘É•ÍÍ}É•‰¥¹‘¥¹|À ¨°Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€™É½´€¹ÍÑ…­}É•‰¥¹‘¥¹œ¥µÁ½ÉÐQ…É•ÑMÑ…­I•‰¥¹‘¥¹•ÍÌ°Q…É•ÑMÑ…­I•‰¥¹‘¥¹½¹ÍÑÉ…¥¹Ð(€€€™É…µ”€ôÍ½ÕÉ•}µ½‘•°¹ÍÑ…­}™É…µ”(€€€Í¡•±°€ôÍ½ÕÉ•}µ½‘•°¹Í¡•±°(€€€Í¡•±±}Í…™”€ô¹½Ð…¹ä ¡Í¡•±°¹¥Í}Ù½±…Ñ¥±”°Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È°Í¡•±°¹¡…Í}}±½‰‰•È°(€€€€€€€€€€€€€€€€€€€€€€€€€Í¡•±°¹¡…Í}…Íµ}½Ñ¼°Í¡•±°¹¡…Í}•…É±å}±½‰‰•È°(€€€€€€€€€€€€€€€€€€€€€€€€€Í¡•±°¹¡…Í}Ñ¥•‘}½Á•É…¹‘Ì°Í¡•±°¹¡…Í}½¹ÑÉ½±}™±½Ý}ÍÕÉ™…”¤¤(€€€¥˜™É…µ”¥Ì9½¹”½È¹½Ð™É…µ”¹ÍÑ…­}…‘‘É•ÍÍ}É•‰¥¹‘¥¹}•±¥¥‰±”½È¹½ÐÍ¡•±±}Í…™”è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ”¡Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}MQIUQUI}9=Q}%5A159Q°¤°‘•Ñ…¥±Ìõì‰É•…Í½¸ˆè€‰ÍÑ…¬µÉ•‰¥¹‘¥¹œµ¥¹•±¥¥‰±”‰ô¤(€€€…•ÍÍ•Ì€ôÑÕÁ±”¡Q…É•ÑMÑ…­I•‰¥¹‘¥¹•ÍÌ¡à¹Í½ÕÉ•}‰±½­}…‘‘É•ÍÌ°à¹Í½ÕÉ•}½Á•É…Ñ¥½¹}¥¹‘•à°à¹}±Ù…±Õ•}‰¥¹‘¥¹}¥°à¹Ñ…É•Ñ}½‰©•Ñ}½™™Í•Ñ}‰åÑ•Ì°à¹Ý¥‘Ñ¡}‰¥ÑÌ°à¹…•ÍÌ°à¹Ù…±Õ•}½Á•É…¹‘}¥¹‘•à¤™½Èà¥¸™É…µ”¹É•‰¥¹‘¥¹}…•ÍÍ•Ì¤(€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹ÍÕ••‘•¡Q…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•°¡Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€€€€ÍÑ…­}É•‰¥¹‘¥¹}½¹ÍÑÉ…¥¹ÐõQ…É•ÑMÑ…­I•‰¥¹‘¥¹½¹ÍÑÉ…¥¹Ð¡…•ÍÍ•Ì¤°µ•µ½Éå}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð ¤°½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð ¤¤¤()‘•˜}‘•É¥Ù•}Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•|À ¨°Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€™É½´€¹Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ”¥µÁ½ÉÐQ…É•ÑY¥ÉÑÕ…±AÉ¥Ù…Ñ•É…µ••ÍÌ°Q…É•ÑY¥ÉÑÕ…±AÉ¥Ù…Ñ•É…µ•½¹ÍÑÉ…¥¹Ð(€€€™É…µ”õÍ½ÕÉ•}µ½‘•°¹ÍÑ…­}™É…µ”ìÁÉ¥Ù…Ñ”õ9½¹”¥˜™É…µ”¥Ì9½¹”•±Í”™É…µ”¹Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ”(€€€Í¡•±°õÍ½ÕÉ•}µ½‘•°¹Í¡•±°(€€€Í¡•±±}Í…™”õ¹½Ð…¹ä ¡Í¡•±°¹¥Í}Ù½±…Ñ¥±”±Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È±Í¡•±°¹¡…Í}}±½‰‰•È±Í¡•±°¹¡…Í}…Íµ}½Ñ¼±Í¡•±°¹¡…Í}•…É±å}±½‰‰•È±Í¡•±°¹¡…Í}Ñ¥•‘}½Á•É…¹‘Ì±Í¡•±°¹¡…Í}½¹ÑÉ½±}™±½Ý}ÍÕÉ™…”¤¤(€€€¥˜ÁÉ¥Ù…Ñ”¥Ì9½¹”½È¹½Ð™É…µ”¹Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•}•±¥¥‰±”½È¹½ÐÍ¡•±±}Í…™”è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ”¡Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥±É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}MQIUQUI}9=Q}%5A159Q°¤±‘•Ñ…¥±Ìõì‰É•…Í½¸ˆè‰Ù¥ÉÑÕ…°µÁÉ¥Ù…Ñ”µ™É…µ”µ¥¹•±¥¥‰±”‰ô¤(€€€…•ÍÍ•ÌõÑÕÁ±”¡Q…É•ÑY¥ÉÑÕ…±AÉ¥Ù…Ñ•É…µ••ÍÌ¡à¹Í½ÕÉ•}‰±½­}…‘‘É•ÍÌ±à¹Í½ÕÉ•}½Á•É…Ñ¥½¹}¥¹‘•à±à¹Ù¥ÉÑÕ…±}½™™Í•Ñ}‰åÑ•Ì±à¹Ý¥‘Ñ¡}‰¥ÑÌ±à¹…•ÍÌ±à¹Ù…±Õ•}½Á•É…¹‘}¥¹‘•à±à¹Í¥¹•‘}±½…¤™½Èà¥¸ÁÉ¥Ù…Ñ”¹…•ÍÍ•Ì¤(€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹ÍÕ••‘•¡Q…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•°¡Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥±•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð±Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•}½¹ÍÑÉ…¥¹ÐõQ…É•ÑY¥ÉÑÕ…±AÉ¥Ù…Ñ•É…µ•½¹ÍÑÉ…¥¹Ð¡ÁÉ¥Ù…Ñ”¹™É…µ•}Í¥é•}‰åÑ•Ì±ÁÉ¥Ù…Ñ”¹É•ÅÕ¥É•‘}…±¥¹µ•¹Ñ}‰åÑ•Ì±…•ÍÍ•Ì¤±µ•µ½Éå}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð ¤±½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð ¤¤¤(()‘•˜}‘•É¥Ù•}ààÙ}¹Õ}¥¹±¥¹•}…Íµ|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€€ˆˆˆ(€€€ÕÑÕÉ”¥µÁ±•µ•¹Ñ…Ñ¥½¸É•ÅÕ¥É•µ•¹ÑÌè((€€€€€€¨½¹ÍÕµ”Í½ÕÉ•}µ½‘•°¹Í¡•±°½¹±ä…ÌÍÑÉÕÑÕÉ•Í¡•±°µ½‘•°ì(€€€€€€¨½¹ÍÕµ”…ÕÑ¡½É¥Ñ…Ñ¥Ù”ÉÕ¹Ñ¥µ”™…ÑÌÑ¡É½Õ IÕ¹Ñ¥µ•…ÑMÑ…ÑÕÌì(€€€€€€¨ÕÍ”QÉ…¹Í±…Ñ¥½¹IÕ¹Ñ¥µ•…ÑÌ¹ÉÙ}Ñ½}½Á•É…¹‘}¥¹‘•àì(€€€€€€¨ÕÍ”QÉ…¹Í±…Ñ¥½¹IÕ¹Ñ¥µ•…ÑÌ¹½Á•É…¹‘}Ý¥‘Ñ¡}‰¥ÑÌì(€€€€€€¨‘¼¹½Ð‘•É¥Ù”‰¥¹‘¥¹Ì™É½´½Á•É…¹½É‘•Èì(€€€€€€¨‘¼¹½Ð‘•É¥Ù”Ý¥‘Ñ ™É½´á±•¸ì(€€€€€€¨‘¼¹½Ð¥¹™•Èµ•µ½Éä½±½‰‰•ÉÌ™É½´É…Ü…Í´µ¹•µ½¹¥Ì¸(€€€€ˆˆˆ(€€€¥˜Í½ÕÉ•}µ½‘•°¹½Á•É…Ñ¥½¸¹É•…‘Í}µ•µ½Éä½ÈÍ½ÕÉ•}µ½‘•°¹½Á•É…Ñ¥½¸¹ÝÉ¥Ñ•Í}µ•µ½Éä½ÈÍ½ÕÉ•}µ½‘•°¹µ•µ½Éä¹É•…‘Í}µ•µ½Éä½ÈÍ½ÕÉ•}µ½‘•°¹µ•µ½Éä¹ÝÉ¥Ñ•Í}µ•µ½Éäè(€€€€€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}µ•µ½Éå}¥¹±¥¹•}…Í´¥µÁ½ÉÐ‘•É¥Ù•}ààÙ}µ•µ½Éå}¥¹±¥¹•}…Íµ}½¹ÍÑÉ…¥¹ÑÌ(€€€€€€€É•ÑÕÉ¸‘•É¥Ù•}ààÙ}µ•µ½Éå}¥¹±¥¹•}…Íµ}½¹ÍÑÉ…¥¹ÑÌ¡Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤(€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}¹Õ}¥¹±¥¹•}…Í´¥µÁ½ÉÐ‘•É¥Ù•}ààÙ}¹Õ}¥¹±¥¹•}…Íµ}½¹ÍÑÉ…¥¹ÑÌ(€€€É•ÑÕÉ¸‘•É¥Ù•}ààÙ}¹Õ}¥¹±¥¹•}…Íµ}½¹ÍÑÉ…¥¹ÑÌ¡Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤(()‘•˜}‘•É¥Ù•}ààÙ}…Ñ½µ¥|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}…Ñ½µ¥}‰…ÉÉ¥•È¥µÁ½ÉÐ€ (€€€€€€€‘•É¥Ù•}ààÙ}…Ñ½µ¥}½¹ÍÑÉ…¥¹ÑÌ°(€€€€¤(€€€É•ÑÕÉ¸‘•É¥Ù•}ààÙ}…Ñ½µ¥}½¹ÍÑÉ…¥¹ÑÌ (€€€€€€€Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð(€€€€¤(()‘•˜}‘•É¥Ù•}ààÙ}‰…ÉÉ¥•É|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ààÙ}…Ñ½µ¥}‰…ÉÉ¥•È¥µÁ½ÉÐ€ (€€€€€€€‘•É¥Ù•}ààÙ}‰…ÉÉ¥•É}½¹ÍÑÉ…¥¹ÑÌ°(€€€€¤(€€€É•ÑÕÉ¸‘•É¥Ù•}ààÙ}‰…ÉÉ¥•É}½¹ÍÑÉ…¥¹ÑÌ (€€€€€€€Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð(€€€€¤(()‘•˜}‘•É¥Ù•}¡•±Á•É}…±±|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€€ˆˆˆ(€€€ÕÑÕÉ”¡•±Á•Èµ…±°±½Ý•É¥¹œµÕÍÐ½‰•äMåÍX5ØÐ	$•áÁ±¥¥Ñ±ä¸((€€€Q¡¥Ì¥¹±Õ‘•Ì°…Ðµ¥¹¥µÕ´è((€€€€€€¨…ÉÕµ•¹ÐÉ•¥ÍÑ•È…ÍÍ¥¹µ•¹Ðì(€€€€€€¨…±±•È½…±±•”µÍ…Ù•É•¥ÍÑ•ÈÑÉ•…Ñµ•¹Ðì(€€€€€€¨ÍÑ…¬…±¥¹µ•¹Ðì(€€€€€€¨É•µé½¹”Á½±¥äì(€€€€€€¨É•ÑÕÉ¸µÙ…±Õ”½¹Ù•¹Ñ¥½¸ì(€€€€€€¨±½‰‰•Èµ½‘•°ì(€€€€€€¨µ•µ½Éä…¹½¹ÑÉ½°µ™±½ÜÁÉ½½˜½‰±¥…Ñ¥½¹Ì¸(€€€€ˆˆˆ(€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}¡•±Á•É}…‰¤¥µÁ½ÉÐ‘•É¥Ù•}¡•±Á•É}…‰¥}½¹ÍÑÉ…¥¹ÑÌ(€€€É•ÑÕÉ¸‘•É¥Ù•}¡•±Á•É}…‰¥}½¹ÍÑÉ…¥¹ÑÌ (€€€€€€€Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð(€€€€¤(()‘•˜}‘•É¥Ù•}ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€™É½´€¹}µ½‘Õ±”¹Á¡…Í”Ù}ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ü¥µÁ½ÉÐ€ (€€€€€€€‘•É¥Ù•}ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÑÌ°(€€€€¤(€€€É•ÑÕÉ¸‘•É¥Ù•}ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÑÌ (€€€€€€€Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð(€€€€¤(()‘•˜}‘•É¥Ù•}•áÁ±¥¥Ñ}Õ¹ÍÕÁÁ½ÉÑ•‘|À (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€‘•°Í½ÕÉ•}µ½‘•°(€€€‘•°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹aA1%%Q}U9MUAA=IQ}A18°(€€€€€€€€¤°(€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€‰Á±…¹}­¥¹ˆè…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¹Ù…±Õ”°(€€€€€€€ô°(€€€€¤()‘•˜}‘•É¥Ù•}…‰¥}ÝÉ…ÁÁ•É|À ¨°Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉäõ9½¹”¤è(€€€™É½´€¹…‰¥}ÝÉ…ÁÁ•È¥µÁ½ÉÐQ…É•Ñ‰¥]É…ÁÁ•ÉÉÕµ•¹Ð°Q…É•Ñ‰¥]É…ÁÁ•É½¹ÍÑÉ…¥¹Ð°Q…É•Ñ‰¥]É…ÁÁ•ÉI•ÑÕÉ¸(€€€™É½´€¹…‰¥}•™™•ÑÌ¥µÁ½ÉÐQ…É•Ñ‰¥]É…ÁÁ•ÉI•¥ÍÑÉä(€€€¥˜…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉä¥Ì9½¹”è…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉäõQ…É•Ñ‰¥]É…ÁÁ•ÉI•¥ÍÑÉä ¤(€€€•™™•ÑÌõÍ½ÕÉ•}µ½‘•°¹…‰¥}•™™•ÑÌ(€€€½¹ÑÉ…Ðõ…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉä¹É•Í½±Ù”¡•™™•ÑÌ°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¹…‰¤¹Ù…±Õ”¤¥˜•™™•ÑÌ•±Í”9½¹”(€€€¥˜½¹ÑÉ…Ð¥Ì9½¹”è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ”¡Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥±É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹5%MM%9}M59Q%}=9QIP°¤±‘•Ñ…¥±Ìõì‰É½ÕÑ”ˆè‰•á…Ñ}…‰¥}ÝÉ…ÁÁ•È‰ô¤(€€€…±°õ•™™•ÑÌ¹…±±ÍlÁt(€€€…ÉÌõÑÕÁ±”¡Q…É•Ñ‰¥]É…ÁÁ•ÉÉÕµ•¹Ð¡¤±¸±±½Œ¹Ý¥‘Ñ¡}‰¥ÑÌ½È€À±½¹ÑÉ…Ð¹…ÉÕµ•¹Ñ}ÑåÁ•Ím¹t±±½Œ¹Í¥¹•‘¹•ÍÌ¤™½È¸°¡¤±±½Œ¤¥¸•¹Õµ•É…Ñ”¡é¥À¡½¹ÑÉ…Ð¹…ÉÕµ•¹Ñ}½Á•É…¹‘}¥¹‘•á•Ì±…±°¹…ÉÕµ•¹ÑÌ¤¤¤(€€€É•ÑÕÉ¹ÌõÑÕÁ±”¡Q…É•Ñ‰¥]É…ÁÁ•ÉI•ÑÕÉ¸¡¤±¸±±½Œ¹Ý¥‘Ñ¡}‰¥ÑÌ½È€À±½¹ÑÉ…Ð¹É•ÑÕÉ¹}ÑåÁ•Ím¹t±±½Œ¹Í¥¹•‘¹•ÍÌ¤™½È¸°¡¤±±½Œ¤¥¸•¹Õµ•É…Ñ”¡é¥À¡½¹ÑÉ…Ð¹É•ÑÕÉ¹}½Á•É…¹‘}¥¹‘•á•Ì±…±°¹É•ÑÕÉ¹Ì¤¤¤(€€€ŒõQ…É•Ñ‰¥]É…ÁÁ•É½¹ÍÑÉ…¥¹Ð¡½¹ÑÉ…Ð±…ÉÌ±É•ÑÕÉ¹Ì±…±°¹ÍÑ…­}…±¥¹µ•¹Ñ}‰åÑ•Ì½È€À±•Ñ…ÑÑÈ¡…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉä°‰Ù•ÉÍ¥½¸ˆ°ˆˆ¤€¤(€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹ÍÕ••‘•¡Q…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•°¡Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥±•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð±…‰¥}ÝÉ…ÁÁ•É}½¹ÍÑÉ…¥¹ÐõŒ±µ•µ½Éå}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð ¤±½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð ¤¤¤(()‘•˜}ÁÉ¥Ù¥±••‘}•™™•Ñ}¥¹Ù•¹Ñ½Éä¡ÍÑ…Ñ”¤è(€€€™É½´€¹ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÑÉ…ÑÌ¥µÁ½ÉÐÍ½ÕÉ•}•™™•Ñ}¥(€€€É•ÑÕÉ¸ì(€€€€€€€€‰ÍÈˆèÑÕÁ±”¡Í½ÕÉ•}•™™•Ñ}¥ ‰ÍÈˆ°à¹‰±½­}…‘‘É•ÍÌ°à¹½Á•É…Ñ¥½¹}¥¹‘•à¤™½Èà¥¸ÍÑ…Ñ”¹ÍÉ}•™™•ÑÌ¤°(€€€€€€€€‰ÑÉ…ÀˆèÑÕÁ±”¡Í½ÕÉ•}•™™•Ñ}¥ ‰ÑÉ…Àˆ°à¹‰±½­}…‘‘É•ÍÌ°à¹½Á•É…Ñ¥½¹}¥¹‘•à¤™½Èà¥¸ÍÑ…Ñ”¹ÑÉ…Á}•™™•ÑÌ¤°(€€€€€€€€‰¥¹Ñ•ÉÉÕÁÐˆèÑÕÁ±”¡Í½ÕÉ•}•™™•Ñ}¥ ‰¥¹Ñ•ÉÉÕÁÐˆ°à¹‰±½­}…‘‘É•ÍÌ°à¹½Á•É…Ñ¥½¹}¥¹‘•à¤™½Èà¥¸ÍÑ…Ñ”¹¥¹Ñ•ÉÉÕÁÑ}•™™•ÑÌ¤°(€€€€€€€€‰…‘‘É•ÍÍ}ÑÉ…¹Í±…Ñ¥½¸ˆèÑÕÁ±”¡Í½ÕÉ•}•™™•Ñ}¥ ‰…‘‘É•ÍÌµÑÉ…¹Í±…Ñ¥½¸ˆ°à¹‰±½­}…‘‘É•ÍÌ°à¹½Á•É…Ñ¥½¹}¥¹‘•à¤™½Èà¥¸ÍÑ…Ñ”¹…‘‘É•ÍÍ}ÑÉ…¹Í±…Ñ¥½¹}•™™•ÑÌ¤°(€€€€€€€€‰Ù¥ÉÑÕ…±¥é…Ñ¥½¸ˆèÑÕÁ±”¡Í½ÕÉ•}•™™•Ñ}¥ ‰Ù¥ÉÑÕ…±¥é…Ñ¥½¸ˆ°à¹‰±½­}…‘‘É•ÍÌ°à¹½Á•É…Ñ¥½¹}¥¹‘•à¤™½Èà¥¸ÍÑ…Ñ”¹Ù¥ÉÑÕ…±¥é…Ñ¥½¹}•™™•ÑÌ¤°(€€€€€€€€‰‘•‰ÕœˆèÑÕÁ±”¡Í½ÕÉ•}•™™•Ñ}¥ ‰‘•‰Õœˆ°à¹‰±½­}…‘‘É•ÍÌ°à¹½Á•É…Ñ¥½¹}¥¹‘•à¤™½Èà¥¸ÍÑ…Ñ”¹‘•‰Õ}•™™•ÑÌ¤°(€€€ô(()‘•˜}µ…ÁÁ¥¹}½Ù•É…•}™…¥±ÕÉ”¡ÍÑ…Ñ”°½¹ÑÉ…Ð¤è(€€€¥¹Ù•¹Ñ½Éä€ô}ÁÉ¥Ù¥±••‘}•™™•Ñ}¥¹Ù•¹Ñ½Éä¡ÍÑ…Ñ”¤(€€€µ…ÁÁ¥¹}¹…µ•Ì€ôì(€€€€€€€€‰ÍÈˆè€‰ÍÉ}µ…ÁÁ¥¹Ìˆ°€‰ÑÉ…Àˆè€‰ÑÉ…Á}µ…ÁÁ¥¹Ìˆ°(€€€€€€€€‰¥¹Ñ•ÉÉÕÁÐˆè€‰¥¹Ñ•ÉÉÕÁÑ}µ…ÁÁ¥¹Ìˆ°(€€€€€€€€‰…‘‘É•ÍÍ}ÑÉ…¹Í±…Ñ¥½¸ˆè€‰…‘‘É•ÍÍ}ÑÉ…¹Í±…Ñ¥½¹}µ…ÁÁ¥¹Ìˆ°(€€€€€€€€‰Ù¥ÉÑÕ…±¥é…Ñ¥½¸ˆè€‰Ù¥ÉÑÕ…±¥é…Ñ¥½¹}µ…ÁÁ¥¹Ìˆ°€‰‘•‰Õœˆè€‰‘•‰Õ}µ…ÁÁ¥¹Ìˆ°(€€€ô(€€€µ¥ÍÍ¥¹œ€ômt(€€€…µ‰¥Õ½ÕÌ€ômt(€€€™½È­¥¹°•áÁ•Ñ•‘}¥‘Ì¥¸¥¹Ù•¹Ñ½Éä¹¥Ñ•µÌ ¤è(€€€€€€€…ÑÕ…°€ôÑÕÁ±”¡•Ñ…ÑÑÈ¡à°€‰Í½ÕÉ•}•™™•Ñ}¥ˆ°9½¹”¤™½Èà¥¸•Ñ…ÑÑÈ¡½¹ÑÉ…Ð°µ…ÁÁ¥¹}¹…µ•Ím­¥¹‘t¤¤(€€€€€€€™½È•™™•Ñ}¥¥¸•áÁ•Ñ•‘}¥‘Ìè(€€€€€€€€€€€½Õ¹Ð€ô…ÑÕ…°¹½Õ¹Ð¡•™™•Ñ}¥¤(€€€€€€€€€€€¥˜½Õ¹Ð€ôô€Àèµ¥ÍÍ¥¹œ¹…ÁÁ•¹¡•™™•Ñ}¥¤(€€€€€€€€€€€•±¥˜½Õ¹Ð€„ô€Äè…µ‰¥Õ½ÕÌ¹…ÁÁ•¹¡•™™•Ñ}¥¤(€€€€€€€¥˜…¹ä¡•™™•Ñ}¥¹½Ð¥¸•áÁ•Ñ•‘}¥‘Ì™½È•™™•Ñ}¥¥¸…ÑÕ…°¤è(€€€€€€€€€€€…µ‰¥Õ½ÕÌ¹•áÑ•¹¡•™™•Ñ}¥™½È•™™•Ñ}¥¥¸…ÑÕ…°¥˜•™™•Ñ}¥¹½Ð¥¸•áÁ•Ñ•‘}¥‘Ì¤(€€€¥˜µ¥ÍÍ¥¹œè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}Q}5AA%9}5%MM%9°ÑÕÁ±”¡Í½ÉÑ•¡Í•Ð¡µ¥ÍÍ¥¹œ¤¤¤(€€€¥˜…µ‰¥Õ½ÕÌè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}Q}5AA%9}5	%U=UL°ÑÕÁ±”¡Í½ÉÑ•¡Í•Ð¡…µ‰¥Õ½ÕÌ¤¤¤(€€€É•ÑÕÉ¸9½¹”(()‘•˜}µµÕ}Í½Á•}½µÁ±•Ñ”¡ÍÑ…Ñ”¤è(€€€™É½´€¹ÁÉ¥Ù¥±••‘}ÍÑ…Ñ•}…¹…±åÍ¥Ì¥µÁ½ÉÐ‘‘É•ÍÍQÉ…¹Í±…Ñ¥½¹™™•Ñ-¥¹(€€€™½È•™™•Ð¥¸ÍÑ…Ñ”¹…‘‘É•ÍÍ}ÑÉ…¹Í±…Ñ¥½¹}•™™•ÑÌè(€€€€€€€¥˜¹½Ð•™™•Ð¹½µÁ±•Ñ”è(€€€€€€€€€€€É•ÑÕÉ¸…±Í”(€€€€€€€¥˜•™™•Ð¹­¥¹¥Ì‘‘É•ÍÍQÉ…¹Í±…Ñ¥½¹™™•Ñ-¥¹¹Q1	}%9Y1%Q%=8…¹€ (€€€€€€€€€€€•™™•Ð¹Ù¥ÉÑÕ…±}…‘‘É•ÍÍ}Í½Á”¥Ì9½¹”(€€€€€€€€€€€½È•™™•Ð¹…‘‘É•ÍÍ}ÍÁ…•}¥‘•¹Ñ¥Ñä¥Ì9½¹”(€€€€€€€€€€€½È•™™•Ð¹Íå¹¡É½¹¥é…Ñ¥½¹}Í½Á”¥Ì9½¹”(€€€€€€€€€€€½È•™™•Ð¹Í¡½½Ñ‘½Ý¹}É•ÅÕ¥É•¥Ì9½¹”(€€€€€€€€¤è(€€€€€€€€€€€É•ÑÕÉ¸…±Í”(€€€É•ÑÕÉ¸QÉÕ”(()‘•˜}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•|À (€€€€¨°Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉäõ9½¹”°(¤è(€€€™É½´€¹ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÑÉ…ÑÌ¥µÁ½ÉÐ€ (€€€€€€€AÉ¥Ù¥±••‘IÕ¹Ñ¥µ•I•¥ÍÑÉä°(€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘IÕ¹Ñ¥µ•½¹ÍÑÉ…¥¹Ð°(€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘M¡•±±½¹ÍÑÉ…¥¹Ð°(€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘5•µ½Éå½¹ÍÑÉ…¥¹Ð°(€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð°(€€€€€€€ÁÉ¥Ù¥±••‘}Í½ÕÉ•}¥‘•¹Ñ¥Ñä°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ñ}¥‘•¹Ñ¥Ñä°(€€€€¤(€€€Í½ÕÉ”€ôÍ½ÕÉ•}µ½‘•°¹ÁÉ¥Ù¥±••‘}ÍÑ…Ñ”(€€€™É½´€¹ÁÉ¥Ù¥±••‘}ÍÑ…Ñ•}…¹…±åÍ¥Ì¥µÁ½ÉÐAÉ¥Ù¥±••‘M•µ…¹Ñ¥±…ÍÌ(€€€Í•µ…¹Ñ¥}±…ÍÍ•Ì€ô€ (€€€€€€€™É½é•¹Í•Ð ¤¥˜Í½ÕÉ”¥Ì9½¹”(€€€€€€€•±Í”™É½é•¹Í•Ð¡Í½ÕÉ”¹Í•µ…¹Ñ¥}±…ÍÍ•Ì¤(€€€€¤(€€€•áÁ•Ñ•‘}±…ÍÍ•Ì€ôì(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹=U9QI}=	MIYQ%=9}AQHè™É½é•¹Í•Ð¡ì(€€€€€€€€€€€AÉ¥Ù¥±••‘M•µ…¹Ñ¥±…ÍÌ¹=U9QI}=	MIYQ%=8(€€€€€€€ô¤°(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹MeM11}=I}MIY%}	%}AQHè™É½é•¹Í•Ð¡ì(€€€€€€€€€€€AÉ¥Ù¥±••‘M•µ…¹Ñ¥±…ÍÌ¹QIA}MIY%(€€€€€€€ô¤°(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}Y9Q}AQHè™É½é•¹Í•Ð¡ì(€€€€€€€€€€€AÉ¥Ù¥±••‘M•µ…¹Ñ¥±…ÍÌ¹%9QIIUAQ}Y9P(€€€€€€€ô¤°(€€€ô(€€€•áÁ•Ñ•€ô•áÁ•Ñ•‘}±…ÍÍ•Ì¹•Ð¡…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¤(€€€µµÕ}±…ÍÍ•Ì€ô™É½é•¹Í•Ð¡ì(€€€€€€€AÉ¥Ù¥±••‘M•µ…¹Ñ¥±…ÍÌ¹IMM}QI9M1Q%=9}MQQ°(€€€€€€€AÉ¥Ù¥±••‘M•µ…¹Ñ¥±…ÍÌ¹Q1	}5%9Q99°(€€€ô¤(€€€±…ÍÍ}µ…Ñ¡•Ì€ô€ (€€€€€€€Í•µ…¹Ñ¥}±…ÍÍ•Ì€ôô•áÁ•Ñ•¥˜•áÁ•Ñ•¥Ì¹½Ð9½¹”(€€€€€€€•±Í”€ (€€€€€€€€€€€‰½½°¡Í•µ…¹Ñ¥}±…ÍÍ•Ì¤…¹Í•µ…¹Ñ¥}±…ÍÍ•Ì€ðôµµÕ}±…ÍÍ•Ì(€€€€€€€€€€€¥˜…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥ÌQ…É•Ñ1½Ý•É¥¹-¥¹¹55U}IU9Q%5}AQH(€€€€€€€€€€€•±Í”…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥ÌQ…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}IU9Q%5}AQH(€€€€€€€€¤(€€€€¤(€€€¥˜¹½Ð±…ÍÍ}µ…Ñ¡•Ìè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}A19}1MM}5%M5Q °(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€¥˜€ (€€€€€€€Í½ÕÉ”¥Ì9½¹”½È¹½ÐÍ½ÕÉ”¹ÍÑÉ¥Ñ}ÑÉ…¹Í±…Ñ¥½¹}•±¥¥‰±”(€€€€€€€½ÈÍ½ÕÉ”¹ÍÑ…Ñ”¥Ì9½¹”½È¹½ÐÍ½ÕÉ”¹ÍÑ…Ñ”¹ÁÉ•Í•¹Ð(€€€€€€€½ÈÍ½ÕÉ”¹É•ÅÕ¥É•Í}Ý¡½±•}™Õ¹Ñ¥½¹}±½Ý•É¥¹œ(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}IU9Q%5}M=UI}%9=5A1Q°(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉä°AÉ¥Ù¥±••‘IÕ¹Ñ¥µ•I•¥ÍÑÉä¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}IU9Q%5}I%MQIe}5%MM%9°(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€½¹ÑÉ…Ð€ôÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉä¹É•Í½±Ù”¡Í½ÕÉ”°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤(€€€¥˜½¹ÑÉ…Ð¥Ì9½¹”½È¹½Ð½¹ÑÉ…Ð¹½µÁ±•Ñ”è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}IU9Q%5}=9QIQ}5%MM%9°(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€ÍÑ…Ñ”€ôÍ½ÕÉ”¹ÍÑ…Ñ”(€€€¥˜€ (€€€€€€€½¹ÑÉ…Ð¹Í½ÕÉ•}•á•ÕÑ¥½¹}ÁÉ½™¥±”€„ôÍÑ…Ñ”¹•á•ÕÑ¥½¹}ÁÉ½™¥±”¹Ù…±Õ”(€€€€€€€½È½¹ÑÉ…Ð¹Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”€„ôÍÑ…Ñ”¹Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”¹Ù…±Õ”(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}IU9Q%5}AI=%1}5%M5Q °¤°(€€€€€€€€¤(€€€¥˜€ (€€€€€€€ÍÑ…Ñ”¹Ñ…É•Ñ}ÉÕ¹Ñ¥µ•}½¹ÑÉ…Ñ}Í•Ñ}¥¥Ì¹½Ð9½¹”(€€€€€€€…¹ÍÑ…Ñ”¹Ñ…É•Ñ}ÉÕ¹Ñ¥µ•}½¹ÑÉ…Ñ}Í•Ñ}¥€„ô½¹ÑÉ…Ð¹ÉÕ¹Ñ¥µ•}½¹ÑÉ…Ñ}Í•Ñ}¥(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}IU9Q%5}YIM%=9}5%M5Q °¤°(€€€€€€€€¤(€€€½Ù•É…”€ô}µ…ÁÁ¥¹}½Ù•É…•}™…¥±ÕÉ”¡ÍÑ…Ñ”°½¹ÑÉ…Ð¤(€€€¥˜½Ù•É…”¥Ì¹½Ð9½¹”è(€€€€€€€É•…Í½¸°•™™•Ñ}¥‘Ì€ô½Ù•É…”(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°É•…Í½¹}½‘•Ìô¡É•…Í½¸°¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì‰•™™•Ñ}¥‘Ìˆè€ˆ°ˆ¹©½¥¸¡•™™•Ñ}¥‘Ì¥ô°(€€€€€€€€¤(€€€¥˜¹½Ð}µµÕ}Í½Á•}½µÁ±•Ñ”¡ÍÑ…Ñ”¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}55U}M=A}%9=5A1Q°¤°(€€€€€€€€¤(€€€¥˜¹½Ð½¹ÑÉ…Ð¹ÉÕ¹Ñ¥µ•}Íåµ‰½°¹ÍÑÉ¥À ¤½È¹½Ð½¹ÑÉ…Ð¹É•¹‘•É•É}½¹ÑÉ…Ñ}¥¹ÍÑÉ¥À ¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}I9II}=9QIQ}%9=5A1Q°¤°(€€€€€€€€¤(€€€Í¡•±°€ôÍ½ÕÉ•}µ½‘•°¹Í¡•±°(€€€¥˜€ (€€€€€€€€¡Í¡•±°¹¥Í}Ù½±…Ñ¥±”…¹¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Ù½±…Ñ¥±•}•á•ÕÑ¥½¸¤(€€€€€€€½È€¡Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È…¹¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ¤(€€€€€€€½È€¡Í¡•±°¹¡…Í}}±½‰‰•È…¹¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}}±½‰‰•È¤(€€€€€€€½È¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Í¡•±°(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}M!11}U9MUAA=IQ°¤°(€€€€€€€€¤(€€€½¹ÍÑÉ…¥¹Ð€ôQ…É•ÑAÉ¥Ù¥±••‘IÕ¹Ñ¥µ•½¹ÍÑÉ…¥¹Ð (€€€€€€€ÉÕ¹Ñ¥µ•}½¹ÑÉ…Ðõ½¹ÑÉ…Ð°(€€€€€€€Í½ÕÉ•}ÁÉ¥Ù¥±••‘}¥‘•¹Ñ¥ÑäõÁÉ¥Ù¥±••‘}Í½ÕÉ•}¥‘•¹Ñ¥Ñä¡Í½ÕÉ”¤°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ñ}¥õÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ñ}¥‘•¹Ñ¥Ñä¡Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤°(€€€€€€€É•¥ÍÑÉå}Ù•ÉÍ¥½¸õÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉä¹Ù•ÉÍ¥½¸°(€€€€€€€µ…ÁÁ¥¹}É•¥ÍÑÉå}Ù•ÉÍ¥½¸õÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉä¹µ…ÁÁ¥¹}É•¥ÍÑÉ¥•Ì¹Ù•ÉÍ¥½¸°(€€€€€€€½¹ÑÉ…Ñ}¥õ½¹ÑÉ…Ð¹½¹ÑÉ…Ñ}¥°(€€€€€€€½¹ÑÉ…Ñ}Ù•ÉÍ¥½¸õ½¹ÑÉ…Ð¹Í•µ…¹Ñ¥}Ù•ÉÍ¥½¸°(€€€€€€€Í½ÕÉ•}•á•ÕÑ¥½¹}ÁÉ½™¥±”õ½¹ÑÉ…Ð¹Í½ÕÉ•}•á•ÕÑ¥½¹}ÁÉ½™¥±”°(€€€€€€€Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”õ½¹ÑÉ…Ð¹Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”°(€€€€€€€ÍÉ}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹ÍÉ}µ…ÁÁ¥¹Ì°(€€€€€€€ÑÉ…Á}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹ÑÉ…Á}µ…ÁÁ¥¹Ì°(€€€€€€€¥¹Ñ•ÉÉÕÁÑ}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹¥¹Ñ•ÉÉÕÁÑ}µ…ÁÁ¥¹Ì°(€€€€€€€…‘‘É•ÍÍ}ÑÉ…¹Í±…Ñ¥½¹}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹…‘‘É•ÍÍ}ÑÉ…¹Í±…Ñ¥½¹}µ…ÁÁ¥¹Ì°(€€€€€€€Ù¥ÉÑÕ…±¥é…Ñ¥½¹}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹Ù¥ÉÑÕ…±¥é…Ñ¥½¹}µ…ÁÁ¥¹Ì°(€€€€€€€‘•‰Õ}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹‘•‰Õ}µ…ÁÁ¥¹Ì°(€€€€€€€Í¡•±±}½¹ÍÑÉ…¥¹ÐõQ…É•ÑAÉ¥Ù¥±••‘M¡•±±½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Ù½±…Ñ¥±•}•á•ÕÑ¥½¸°(€€€€€€€€€€€½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ°(€€€€€€€€€€€½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}}±½‰‰•È°QÉÕ”°(€€€€€€€€¤°(€€€€€€€µ•µ½Éå}½¹ÍÑÉ…¥¹ÐõQ…É•ÑAÉ¥Ù¥±••‘5•µ½Éå½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}µ•µ½Éå}•™™•ÑÌ°(€€€€€€€€€€€½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ°QÉÕ”°(€€€€€€€€¤°(€€€€€€€½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐõQ…É•ÑAÉ¥Ù¥±••‘½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}ÑÉ…Á}‰•¡…Ù¥½È°½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½¹ÑÉ½±}™±½Ü°(€€€€€€€€€€€½¹ÑÉ…Ð¹µ…å}É•ÑÕÉ¸°½¹ÑÉ…Ð¹µ…å}Õ¹Ý¥¹°QÉÕ”°(€€€€€€€€¤°(€€€€€€€¥¹½É•‘}Í½ÕÉ•}ÍÑ…Ñ”ô ¤°(€€€€€€€½‰Í•ÉÙ…‰±•}•™™•Ñ}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹½‰Í•ÉÙ…‰±•}•™™•Ñ}µ…ÁÁ¥¹Ì°(€€€€€€€ÉÕ¹Ñ¥µ•}Íåµ‰½±}½É}¥¹ÑÉ¥¹Í¥Œõ½¹ÑÉ…Ð¹ÉÕ¹Ñ¥µ•}Íåµ‰½°°(€€€€€€€É•ÅÕ¥É•‘}¡•…‘•ÉÌõ½¹ÑÉ…Ð¹É•ÅÕ¥É•‘}¡•…‘•ÉÌ°(€€€€€€€É•ÅÕ¥É•‘}±¥‰É…É¥•Ìõ½¹ÑÉ…Ð¹É•ÅÕ¥É•‘}±¥‰É…É¥•Ì°(€€€€€€€É•ÅÕ¥É•‘}…Á…‰¥±¥Ñ¥•Ìõ½¹ÑÉ…Ð¹É•ÅÕ¥É•‘}…Á…‰¥±¥Ñ¥•Ì°(€€€€€€€™Õ¹Ñ¥½¹…±}™…±±‰…¬õ…±Í”°(€€€€€€€½µÁ±•Ñ”õQÉÕ”°(€€€€¤(€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹ÍÕ••‘•¡Q…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•° (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€€€€ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÍÑÉ…¥¹Ðõ½¹ÍÑÉ…¥¹Ð°(€€€€€€€ÁÉ•Í•ÉÙ•}Ù½±…Ñ¥±”ô (€€€€€€€€€€€¹½ÐÍ¡•±°¹¥Í}Ù½±…Ñ¥±”½È½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Ù½±…Ñ¥±•}•á•ÕÑ¥½¸(€€€€€€€€¤°(€€€€€€€ÁÉ•Í•ÉÙ•}}±½‰‰•Èô (€€€€€€€€€€€¹½ÐÍ¡•±°¹¡…Í}}±½‰‰•È½È½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}}±½‰‰•È(€€€€€€€€¤°(€€€€€€€µ•µ½Éå}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€É•ÅÕ¥É•Í}µ•µ½Éå}±½‰‰•Èô (€€€€€€€€€€€€€€€Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È(€€€€€€€€€€€€€€€…¹½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ(€€€€€€€€€€€€¤°(€€€€€€€€€€€É•ÅÕ¥É•Í}½µÁ¥±•É}‰…ÉÉ¥•Èô (€€€€€€€€€€€€€€€Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È(€€€€€€€€€€€€€€€…¹½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ(€€€€€€€€€€€€¤°(€€€€€€€€¤°(€€€€€€€½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€ÁÉ•Í•ÉÙ•}½¹ÑÉ½±}™±½Üõ½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½¹ÑÉ½±}™±½Ü°(€€€€€€€€€€€É•ÅÕ¥É•Í}¡•±Á•É}…‰¥}½¹ÑÉ…Ðõ…±Í”°(€€€€€€€€¤°(€€€€¤¤(()‘•˜}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±|À (€€€€¨°Í½ÕÉ•}µ½‘•°°…¹‘¥‘…Ñ•}Á±…¸°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}É•¥ÍÑÉäõ9½¹”°(€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}Á½±¥äõ9½¹”°(¤è(€€€™É½´€¹™Õ¹Ñ¥½¹…±}½‰Í•ÉÙ…‰¥±¥Ñä¥µÁ½ÉÐÕ¹Ñ¥½¹…±…±±‰…­A½ÍÍ¥‰¥±¥Ñä(€€€™É½´€¹ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÑÉ…ÑÌ¥µÁ½ÉÐ€ (€€€€€€€AÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­A½±¥ä°(€€€€€€€AÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­I•¥ÍÑÉä°(€€€€€€€Q…É•ÑAÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­½¹ÍÑÉ…¥¹Ð°(€€€€€€€™Õ¹Ñ¥½¹…±}½‰Í•ÉÙ…‰¥±¥Ñå}¥‘•¹Ñ¥Ñä°(€€€€¤(€€€™É½´€¹ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}½¹ÑÉ…ÑÌ¥µÁ½ÉÐ€ (€€€€€€€ÁÉ¥Ù¥±••‘}Í½ÕÉ•}¥‘•¹Ñ¥Ñä°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ñ}¥‘•¹Ñ¥Ñä°(€€€€¤(€€€¥˜€ (€€€€€€€¹½Ð¥Í¥¹ÍÑ…¹”¡ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}Á½±¥ä°(€€€€€€€€€€€€€€€€€€€€€€AÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­A½±¥ä¤(€€€€€€€½È¹½ÐÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}Á½±¥ä¹•¹…‰±•(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}U9Q%=91}A=1%e}%M	1°(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€Í½ÕÉ”€ôÍ½ÕÉ•}µ½‘•°¹ÁÉ¥Ù¥±••‘}ÍÑ…Ñ”(€€€¥˜€ (€€€€€€€Í½ÕÉ”¥Ì9½¹”½È¹½ÐÍ½ÕÉ”¹½µÁ±•Ñ”½ÈÍ½ÕÉ”¹É•…Í½¹}½‘•Ì(€€€€€€€½ÈÍ½ÕÉ”¹ÍÑ…Ñ”¥Ì9½¹”½È¹½ÐÍ½ÕÉ”¹ÍÑ…Ñ”¹ÁÉ•Í•¹Ð(€€€€€€€½È¹½ÐÍ½ÕÉ”¹ÍÑ…Ñ”¹½µÁ±•Ñ”½ÈÍ½ÕÉ”¹ÍÑ…Ñ”¹µ¥ÍÍ¥¹}™…Ñ}½‘•Ì(€€€€€€€½ÈÍ½ÕÉ”¹½‰Í•ÉÙ…‰¥±¥Ñä¥Ì9½¹”½È¹½ÐÍ½ÕÉ”¹½‰Í•ÉÙ…‰¥±¥Ñä¹½µÁ±•Ñ”(€€€€€€€½ÈÍ½ÕÉ”¹½‰Í•ÉÙ…‰¥±¥Ñä¹µ¥ÍÍ¥¹}™…Ñ}½‘•Ì(€€€€€€€½ÈÍ½ÕÉ”¹½‰Í•ÉÙ…‰¥±¥Ñä¹™…±±‰…­}Á½ÍÍ¥‰¥±¥Ñä¥Ì¹½Ð(€€€€€€€€€€€Õ¹Ñ¥½¹…±…±±‰…­A½ÍÍ¥‰¥±¥Ñä¹A=MM%	1}]%Q!}aQ}QIQ}=9QIP(€€€€€€€½È¹½ÐÍ½ÕÉ”¹™Õ¹Ñ¥½¹…±}™…±±‰…­}Á½ÍÍ¥‰±”(€€€€€€€½ÈÍ½ÕÉ”¹É•ÅÕ¥É•Í}Ý¡½±•}™Õ¹Ñ¥½¹}±½Ý•É¥¹œ(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}U9Q%=91}M=UI}%9=5A1Q°(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹” (€€€€€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}É•¥ÍÑÉä°AÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­I•¥ÍÑÉä(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}U9Q%=91}I%MQIe}5%MM%9°(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€½¹ÑÉ…Ð€ôÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}É•¥ÍÑÉä¹É•Í½±Ù”¡Í½ÕÉ”°Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤(€€€¥˜½¹ÑÉ…Ð¥Ì9½¹”½È¹½Ð½¹ÑÉ…Ð¹½µÁ±•Ñ”è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}U9Q%=91}=9QIQ}5%MM%9°(€€€€€€€€€€€€¤°(€€€€€€€€¤(€€€•áÁ•Ñ•‘}ÁÉ•Í•ÉÙ•€ôÑÕÁ±”¡…¹‘¥‘…Ñ•}Á±…¸¹µ•Ñ…‘…Ñ„¹•Ð (€€€€€€€€‰ÁÉ•Í•ÉÙ•‘}•¹Ù¥É½¹µ•¹Ñ}Í•µ…¹Ñ¥Ìˆ°€ ¤(€€€€¤¤(€€€•áÁ•Ñ•‘}¹½Ñ}ÁÉ•Í•ÉÙ•€ôÑÕÁ±”¡…¹‘¥‘…Ñ•}Á±…¸¹µ•Ñ…‘…Ñ„¹•Ð (€€€€€€€€‰¹½Ñ}ÁÉ•Í•ÉÙ•‘}•¹Ù¥É½¹µ•¹Ñ}Í•µ…¹Ñ¥Ìˆ°€ ¤(€€€€¤¤(€€€¥˜€ (€€€€€€€•áÁ•Ñ•‘}ÁÉ•Í•ÉÙ•(€€€€€€€…¹½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•‘}•¹Ù¥É½¹µ•¹Ñ}Í•µ…¹Ñ¥Ì€„ô•áÁ•Ñ•‘}ÁÉ•Í•ÉÙ•(€€€€¤½È€ (€€€€€€€•áÁ•Ñ•‘}¹½Ñ}ÁÉ•Í•ÉÙ•(€€€€€€€…¹½¹ÑÉ…Ð¹¹½Ñ}ÁÉ•Í•ÉÙ•‘}•¹Ù¥É½¹µ•¹Ñ}Í•µ…¹Ñ¥Ì€„ô•áÁ•Ñ•‘}¹½Ñ}ÁÉ•Í•ÉÙ•(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}U9Q%=91}=9QIQ}5%MM%9°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì‰É•…Í½¸ˆè€‰™Õ¹Ñ¥½¹…°µ•¹Ù¥É½¹µ•¹ÐµÁÉ•Í•ÉÙ…Ñ¥½¸µ‰½Õ¹‘…Éäµµ¥Íµ…Ñ ‰ô°(€€€€€€€€¤(€€€ÍÑ…Ñ”€ôÍ½ÕÉ”¹ÍÑ…Ñ”(€€€¥˜€ (€€€€€€€½¹ÑÉ…Ð¹Í½ÕÉ•}•á•ÕÑ¥½¹}ÁÉ½™¥±”€„ôÍÑ…Ñ”¹•á•ÕÑ¥½¹}ÁÉ½™¥±”¹Ù…±Õ”(€€€€€€€½È½¹ÑÉ…Ð¹Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”€„ôÍÑ…Ñ”¹Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”¹Ù…±Õ”(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}IU9Q%5}AI=%1}5%M5Q °¤°(€€€€€€€€¤(€€€‘•±…É•‘}¥¹½É•€ôÑÕÁ±”¡Í½ÉÑ•¡¥Ñ•´¹ÍÑ…Ñ•}¥™½È¥Ñ•´¥¸Í½ÕÉ”¹½‰Í•ÉÙ…‰¥±¥Ñä¹¥¹½É•‘}ÍÑ…Ñ•Ì¤¤(€€€¥˜½¹ÑÉ…Ð¹¥¹½É•‘}ÍÑ…Ñ•}¥‘Ì€„ô‘•±…É•‘}¥¹½É•è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}%9=I}MQQ}5%M5Q °¤°(€€€€€€€€¤(€€€¥˜¹½Ð½¹ÑÉ…Ð¹¥µÁ±•µ•¹Ñ…Ñ¥½¹}¥¹ÍÑÉ¥À ¤½È¹½Ð½¹ÑÉ…Ð¹É•¹‘•É•É}½¹ÑÉ…Ñ}¥¹ÍÑÉ¥À ¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}I9II}=9QIQ}%9=5A1Q°¤°(€€€€€€€€¤(€€€Í¡•±°€ôÍ½ÕÉ•}µ½‘•°¹Í¡•±°(€€€¥˜€ (€€€€€€€€¡Í¡•±°¹¥Í}Ù½±…Ñ¥±”…¹¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Ù½±…Ñ¥±•}•á•ÕÑ¥½¸¤(€€€€€€€½È€¡Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È…¹¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ¤(€€€€€€€½È€¡Í¡•±°¹¡…Í}}±½‰‰•È…¹¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}}±½‰‰•È¤(€€€€€€€½È¹½Ð½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Í¡•±°(€€€€¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}M!11}U9MUAA=IQ°¤°(€€€€€€€€¤(€€€½¹ÍÑÉ…¥¹Ð€ôQ…É•ÑAÉ¥Ù¥±••‘Õ¹Ñ¥½¹…±…±±‰…­½¹ÍÑÉ…¥¹Ð (€€€€€€€™…±±‰…­}½¹ÑÉ…Ðõ½¹ÑÉ…Ð°(€€€€€€€Í½ÕÉ•}ÁÉ¥Ù¥±••‘}¥‘•¹Ñ¥ÑäõÁÉ¥Ù¥±••‘}Í½ÕÉ•}¥‘•¹Ñ¥Ñä¡Í½ÕÉ”¤°(€€€€€€€Í½ÕÉ•}½‰Í•ÉÙ…‰¥±¥Ñå}¥‘•¹Ñ¥Ñäõ™Õ¹Ñ¥½¹…±}½‰Í•ÉÙ…‰¥±¥Ñå}¥‘•¹Ñ¥Ñä (€€€€€€€€€€€Í½ÕÉ”¹½‰Í•ÉÙ…‰¥±¥Ñä(€€€€€€€€¤°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ñ}¥õÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ñ}¥‘•¹Ñ¥Ñä¡Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤°(€€€€€€€É•¥ÍÑÉå}Ù•ÉÍ¥½¸õÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}É•¥ÍÑÉä¹Ù•ÉÍ¥½¸°(€€€€€€€Á½±¥å}¥‘•¹Ñ¥ÑäõÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}Á½±¥ä¹¥‘•¹Ñ¥Ñä°(€€€€€€€Í½ÕÉ•}•á•ÕÑ¥½¹}ÁÉ½™¥±”õ½¹ÑÉ…Ð¹Í½ÕÉ•}•á•ÕÑ¥½¹}ÁÉ½™¥±”°(€€€€€€€Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”õ½¹ÑÉ…Ð¹Ñ…É•Ñ}•á•ÕÑ¥½¹}µ½‘”°(€€€€€€€¥¹½É•‘}Í½ÕÉ•}ÍÑ…Ñ”õ½¹ÑÉ…Ð¹¥¹½É•‘}ÍÑ…Ñ•}¥‘Ì°(€€€€€€€½‰Í•ÉÙ…‰±•}•™™•Ñ}µ…ÁÁ¥¹Ìõ½¹ÑÉ…Ð¹½‰Í•ÉÙ…‰±•}•™™•Ñ}µ…ÁÁ¥¹Ì°(€€€€€€€ÉÕ¹Ñ¥µ•}Íåµ‰½±}½É}¥¹ÑÉ¥¹Í¥Œõ½¹ÑÉ…Ð¹¥µÁ±•µ•¹Ñ…Ñ¥½¹}¥°(€€€€€€€É•ÅÕ¥É•‘}¡•…‘•ÉÌõ½¹ÑÉ…Ð¹É•ÅÕ¥É•‘}¡•…‘•ÉÌ°(€€€€€€€É•ÅÕ¥É•‘}±¥‰É…É¥•Ìô  ¤¥˜½¹ÑÉ…Ð¹É•ÅÕ¥É•‘}±¥‰É…Éä¥Ì9½¹”•±Í”€¡½¹ÑÉ…Ð¹É•ÅÕ¥É•‘}±¥‰É…Éä°¤¤°(€€€€€€€É•ÅÕ¥É•‘}…Á…‰¥±¥Ñ¥•Ìô¡½¹ÑÉ…Ð¹É•ÅÕ¥É•‘}Ñ…É•Ñ}…Á…‰¥±¥Ñä°¤°(€€€€€€€™Õ¹Ñ¥½¹…±}™…±±‰…¬õQÉÕ”°(€€€€€€€½µÁ±•Ñ”õQÉÕ”°(€€€€¤(€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹ÍÕ••‘•¡Q…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•° (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}½¹ÍÑÉ…¥¹Ðõ½¹ÍÑÉ…¥¹Ð°(€€€€€€€ÁÉ•Í•ÉÙ•}Ù½±…Ñ¥±”ô (€€€€€€€€€€€¹½ÐÍ¡•±°¹¥Í}Ù½±…Ñ¥±”½È½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Ù½±…Ñ¥±•}•á•ÕÑ¥½¸(€€€€€€€€¤°(€€€€€€€ÁÉ•Í•ÉÙ•}}±½‰‰•Èô (€€€€€€€€€€€¹½ÐÍ¡•±°¹¡…Í}}±½‰‰•È½È½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}}±½‰‰•È(€€€€€€€€¤°(€€€€€€€µ•µ½Éå}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€É•ÅÕ¥É•Í}µ•µ½Éå}±½‰‰•Èô (€€€€€€€€€€€€€€€Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È(€€€€€€€€€€€€€€€…¹½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ(€€€€€€€€€€€€¤°(€€€€€€€€€€€É•ÅÕ¥É•Í}½µÁ¥±•É}‰…ÉÉ¥•Èô (€€€€€€€€€€€€€€€Í¡•±°¹¡…Í}µ•µ½Éå}±½‰‰•È(€€€€€€€€€€€€€€€…¹½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}½µÁ¥±•É}µ•µ½Éå}½É‘•É¥¹œ(€€€€€€€€€€€€¤°(€€€€€€€€¤°(€€€€€€€½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹ÐõQ…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€ÁÉ•Í•ÉÙ•}½¹ÑÉ½±}™±½Üõ½¹ÑÉ…Ð¹ÁÉ•Í•ÉÙ•Í}Ñ•Éµ¥¹…Ñ¥½¸°(€€€€€€€€¤°(€€€€¤¤(()}•É¥Ù•È€ô…±±…‰±•l(€€€l(€€€€€€€M½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€€€€€Q…É•Ñ1½Ý•É¥¹A±…¸°(€€€€€€€Q…É•Ñ¹Ù¥É½¹µ•¹Ð°(€€€t°(€€€Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð°)t(()‘•˜}…‘…ÁÑ}‘•É¥Ù•È (€€€™Õ¹Ñ¥½¸è…±±…‰±•l¸¸¸°Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ñt°(¤€´ø}•É¥Ù•Èè(€€€‘•˜ÝÉ…ÁÁ• (€€€€€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€€€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð°(€€€€¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€€€€€É•ÑÕÉ¸™Õ¹Ñ¥½¸ (€€€€€€€€€€€Í½ÕÉ•}µ½‘•°õÍ½ÕÉ•}µ½‘•°°(€€€€€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€€€€€¤((€€€É•ÑÕÉ¸ÝÉ…ÁÁ•(()}A19}-%9}%MAQ è5…ÁÁ¥¹mQ…É•Ñ1½Ý•É¥¹-¥¹°}•É¥Ù•Ét€ô€ (€€€5…ÁÁ¥¹AÉ½áåQåÁ” (€€€€€€€ì(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹}aAIMM%=8è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}}•áÁÉ•ÍÍ¥½¹|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹}MQIUQUIè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}}ÍÑÉÕÑÕÉ•‘|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹}	U%1Q%8è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}}‰Õ¥±Ñ¥¹|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹`àÙ}9U}%91%9}M4è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ààÙ}¹Õ}¥¹±¥¹•}…Íµ|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹`àÙ}Q=5%è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ààÙ}…Ñ½µ¥|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹`àÙ}	II%Hè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ààÙ}‰…ÉÉ¥•É|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹!1AI}10è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}¡•±Á•É}…±±|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹MQIUQUI}=9QI=1}1=\è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ÍÑÉÕÑÕÉ•‘}½¹ÑÉ½±}™±½Ý|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹MQ-}IMM}I	%9%9è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ÍÑ…­}…‘‘É•ÍÍ}É•‰¥¹‘¥¹|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹Y%IQU1}AI%YQ}I5è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}Ù¥ÉÑÕ…±}ÁÉ¥Ù…Ñ•}™É…µ•|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹	%}]IAAI}10è}…‘…ÁÑ}‘•É¥Ù•È¡}‘•É¥Ù•}…‰¥}ÝÉ…ÁÁ•É|À¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹=U9QI}=	MIYQ%=9}AQHè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹MeM11}=I}MIY%}	%}AQHè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}Y9Q}AQHè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹55U}IU9Q%5}AQHè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}IU9Q%5}AQHè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}MQQ}5!%9è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}•áÁ±¥¥Ñ}Õ¹ÍÕÁÁ½ÉÑ•‘|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}U9Q%=91}11	,è}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}•áÁ±¥¥Ñ}Õ¹ÍÕÁÁ½ÉÑ•‘|À(€€€€€€€€€€€€¤°(€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹U9MUAA=IQè}…‘…ÁÑ}‘•É¥Ù•È (€€€€€€€€€€€€€€€}‘•É¥Ù•}•áÁ±¥¥Ñ}Õ¹ÍÕÁÁ½ÉÑ•‘|À(€€€€€€€€€€€€¤°(€€€€€€€ô(€€€€¤(¤(()‘•˜}Ù…±¥‘…Ñ•}‘¥ÍÁ…Ñ¡}½Ù•É…” ¤€´ø9½¹”è(€€€€ˆˆˆ(€€€AÉ•Ù•¹Ð•¹Õ´•áÁ…¹Í¥½¸™É½´Í¥±•¹Ñ±ä™…±±¥¹œ¥¹Ñ¼…¸¥µÁ±¥¥Ð™…±±‰…¬¸(€€€€ˆˆˆ(€€€•¹Õµ}­¥¹‘Ì€ô™É½é•¹Í•Ð¡Q…É•Ñ1½Ý•É¥¹-¥¹¤(€€€‘¥ÍÁ…Ñ¡}­¥¹‘Ì€ô™É½é•¹Í•Ð¡}A19}-%9}%MAQ ¤((€€€µ¥ÍÍ¥¹œ€ô•¹Õµ}­¥¹‘Ì€´‘¥ÍÁ…Ñ¡}­¥¹‘Ì(€€€Õ¹•áÁ•Ñ•€ô‘¥ÍÁ…Ñ¡}­¥¹‘Ì€´•¹Õµ}­¥¹‘Ì((€€€¥˜µ¥ÍÍ¥¹œ½ÈÕ¹•áÁ•Ñ•è(€€€€€€€É…¥Í”IÕ¹Ñ¥µ•ÉÉ½È (€€€€€€€€€€€€‰A¡…Í”€Ù‘¥ÍÁ…Ñ ½Ù•É…”¥¹Ù…É¥…¹ÐÙ¥½±…Ñ•è€ˆ(€€€€€€€€€€€˜‰µ¥ÍÍ¥¹œõíÑÕÁ±”¡Í½ÉÑ•¡­¥¹¹Ù…±Õ”™½È­¥¹¥¸µ¥ÍÍ¥¹œ¤¤…Éô°€ˆ(€€€€€€€€€€€˜‰Õ¹•áÁ•Ñ•õíÑÕÁ±”¡Í½ÉÑ•¡­¥¹¹Ù…±Õ”™½È­¥¹¥¸Õ¹•áÁ•Ñ•¤¤…Éôˆ(€€€€€€€€¤(()}Ù…±¥‘…Ñ•}‘¥ÍÁ…Ñ¡}½Ù•É…” ¤()‘•˜}Ù…±¥‘…Ñ•}É•ÍÕ±Ñ}¥¹Ù…É¥…¹ÑÌ (€€€€¨°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€É•ÍÕ±ÐèQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€€ˆˆˆ(€€€Y…±¥‘…Ñ”É½ÍÌµ½‰©•ÐA¡…Í”€ÙÉ•ÍÕ±Ð¥¹Ù…É¥…¹ÑÌ¸((€€€Q…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•°¹}}Á½ÍÑ}¥¹¥Ñ}|Ù…±¥‘…Ñ•Ì¥¹ÑÉ¥¹Í¥Œµ½‘•°¥¹Ù…É¥…¹ÑÌ¸(€€€Q¡¥Ì™Õ¹Ñ¥½¸Ù…±¥‘…Ñ•Ì½¹Í¥ÍÑ•¹ä‰•ÑÝ••¸Ñ¡”…¹‘¥‘…Ñ”Á±…¸…¹Ñ¡”(€€€‘•É¥Ù…Ñ¥½¸É•ÍÕ±Ð¸(€€€€ˆˆˆ(€€€¥˜É•ÍÕ±Ð¹Á±…¹}¥€„ô…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€‰É•ÍÕ±Ñ}Á±…¹}¥‘}µ¥Íµ…Ñ ˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½ÐÉ•ÍÕ±Ð¹ÍÕ•ÍÌè(€€€€€€€¥˜É•ÍÕ±Ð¹½¹ÍÑÉ…¥¹ÑÌ¥Ì¹½Ð9½¹”è(€€€€€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€€€€€‰™…¥±•‘}É•ÍÕ±Ñ}µÕÍÑ}¹½Ñ}…ÉÉå}½¹ÍÑÉ…¥¹ÑÌˆ(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€€¤((€€€€€€€É•ÑÕÉ¸É•ÍÕ±Ð((€€€¥˜É•ÍÕ±Ð¹½¹ÍÑÉ…¥¹ÑÌ¥Ì9½¹”è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€‰ÍÕ•ÍÍ™Õ±}É•ÍÕ±Ñ}¡…Í}¹½}½¹ÍÑÉ…¥¹ÑÌˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€½¹ÍÑÉ…¥¹ÑÌ€ôÉ•ÍÕ±Ð¹½¹ÍÑÉ…¥¹ÑÌ((€€€€ŒQ¡¥Ì¥Ì¥¹Ñ•¹Ñ¥½¹…±±ä±½‰…°É…Ñ¡•ÈÑ¡…¸½µÍÁ•¥™¥Œ¸€Ñ…É•Ð(€€€€Œ¥¹±¥¹”µ…Í´É½ÕÑ”µ…ä¹½ÐÁ¥¸Ñ¡”½µÁ¥±•Èµ½Ý¹•ÍÑ…¬½™É…µ”Á½¥¹Ñ•È¸(€€€™½É‰¥‘‘•¸€ôÑÕÁ±” (€€€€€€€¥Ñ•´™½È¥Ñ•´¥¸½¹ÍÑÉ…¥¹ÑÌ¹½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌ(€€€€€€€¥˜¥Ñ•´¹É•ÅÕ¥É•Í}™¥á•‘}É•¥ÍÑ•È(€€€€€€€…¹¥Í}™½É‰¥‘‘•¹}¡½ÍÑ}ÍÑ…­}™É…µ•}É•¥ÍÑ•È¡¥Ñ•´¹™¥á•‘}É•¥ÍÑ•É}¹…µ”¤(€€€€¤(€€€¥˜™½É‰¥‘‘•¸è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹!=MQ}MQ-}I5}%a}I%MQI}=I	%8°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰™¥á•‘}É•¥ÍÑ•Èˆè™½É‰¥‘‘•¹lÁt¹™¥á•‘}É•¥ÍÑ•É}¹…µ”°(€€€€€€€€€€€€€€€€‰Ñ…É•Ñ}É•¥ÍÑ•É}Á½±¥å}Ù•ÉÍ¥½¸ˆèA=1%e}YIM%=8°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜½¹ÍÑÉ…¥¹ÑÌ¹Á±…¹}¥€„ô…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€‰½¹ÍÑÉ…¥¹Ñ}Á±…¹}¥‘}µ¥Íµ…Ñ ˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥Í}}•áÁÉ•ÍÍ¥½¹}Á±…¸€ô€ (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥ÌQ…É•Ñ1½Ý•É¥¹-¥¹¹}aAIMM%=8(€€€€¤(€€€¡…Í}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð€ô€ (€€€€€€€½¹ÍÑÉ…¥¹ÑÌ¹}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð¥Ì¹½Ð9½¹”(€€€€¤((€€€¥˜¥Í}}•áÁÉ•ÍÍ¥½¹}Á±…¸…¹¹½Ð¡…Í}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ðè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}Á±…¹}É•ÅÕ¥É•Í}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ðˆ(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½Ð¥Í}}•áÁÉ•ÍÍ¥½¹}Á±…¸…¹¡…Í}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ðè(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€‰¹½¹}}•áÁÉ•ÍÍ¥½¹}Á±…¹}µÕÍÑ}¹½Ñ}…ÉÉå|ˆ(€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ðˆ(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¡…Í}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ðè(€€€€€€€ÑÉäè(€€€€€€€€€€€Ù…±¥‘…Ñ•}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð (€€€€€€€€€€€€€€€½¹ÍÑÉ…¥¹ÑÌ¹}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð(€€€€€€€€€€€€¤(€€€€€€€•á•ÁÐ€ (€€€€€€€€€€€áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È°(€€€€€€€€€€€QåÁ•ÉÉ½È°(€€€€€€€€€€€Y…±Õ•ÉÉ½È°(€€€€€€€€¤…Ì•áŒè(€€€€€€€€€€€É•ÑÕÉ¸}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ñ}™…¥±ÕÉ” (€€€€€€€€€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€€€€€€€€€•áŒõ•áŒ°(€€€€€€€€€€€€¤((€€€€€€€¥˜½¹ÍÑÉ…¥¹ÑÌ¹½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌè(€€€€€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÍ}µÕÍÑ}¹½Ñ}¡…Ù•|ˆ(€€€€€€€€€€€€€€€€€€€€€€€€‰…Íµ}½Á•É…¹‘}½¹ÍÑÉ…¥¹ÑÌˆ(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€€¤((€€€€€€€¥˜¹½Ð½¹ÍÑÉ…¥¹ÑÌ¹µ•µ½Éå}½¹ÍÑÉ…¥¹Ð¹¥Í}¹½}µ•µ½Éå}•™™•Ð ¤è(€€€€€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÍ}µÕÍÑ}¡…Ù•|ˆ(€€€€€€€€€€€€€€€€€€€€€€€€‰¹½}µ•µ½Éå}•™™•Ðˆ(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€€¤((€€€€€€€¥˜¹½Ð½¹ÍÑÉ…¥¹ÑÌ¹½¹ÑÉ½±}™±½Ý}½¹ÍÑÉ…¥¹Ð¹¥Í}Í¥µÁ±•}™…±±Ñ¡É½Õ  ¤è(€€€€€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÍ}µÕÍÑ}¡…Ù•|ˆ(€€€€€€€€€€€€€€€€€€€€€€€€‰Í¥µÁ±•}™…±±Ñ¡É½Õ ˆ(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€€¤((€€€€€€€¥˜½¹ÍÑÉ…¥¹ÑÌ¹ÁÉ•Í•ÉÙ•}Ù½±…Ñ¥±”è(€€€€€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÍ}µÕÍÑ}¹½Ñ}ÁÉ•Í•ÉÙ•|ˆ(€€€€€€€€€€€€€€€€€€€€€€€€‰Ù½±…Ñ¥±•}¥¹±¥¹•}…Íµ}Í•µ…¹Ñ¥Ìˆ(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€€¤((€€€€€€€¥˜½¹ÍÑÉ…¥¹ÑÌ¹ÁÉ•Í•ÉÙ•}}±½‰‰•Èè(€€€€€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÍ}µÕÍÑ}¹½Ñ}ÁÉ•Í•ÉÙ•|ˆ(€€€€€€€€€€€€€€€€€€€€€€€€‰}±½‰‰•Èˆ(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€€¤((€€€€€€€¥˜½¹ÍÑÉ…¥¹ÑÌ¹ÁÉ•Í•ÉÙ•}¥µÁ±¥¥Ñ}µ…¡¥¹•}ÍÑ…Ñ”è(€€€€€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€€€€€‰¥¹Ù…É¥…¹Ðˆè€ (€€€€€€€€€€€€€€€€€€€€€€€€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹ÑÍ}µÕÍÑ}¹½Ñ}ÁÉ•Í•ÉÙ•|ˆ(€€€€€€€€€€€€€€€€€€€€€€€€‰¥µÁ±¥¥Ñ}µ…¡¥¹•}ÍÑ…Ñ”ˆ(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô°(€€€€€€€€€€€€¤((€€€É•ÑÕÉ¸É•ÍÕ±Ð()‘•˜‘•É¥Ù•}Ñ…É•Ñ}½¹ÍÑÉ…¥¹ÑÌ (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐèQ…É•Ñ¹Ù¥É½¹µ•¹Ð€ô€ (€€€€€€€%a}MeMY}5ØÑ}9U}QQ}9Y%I=959P(€€€€¤°(€€€…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉäõ9½¹”°(€€€ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉäõ9½¹”°(€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}É•¥ÍÑÉäõ9½¹”°(€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}Á½±¥äõ9½¹”°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€€ˆˆˆ(€€€A¡…Í”€ÙÁÕ‰±¥Œ•¹ÑÉäÁ½¥¹Ð¸((€€€A¥Á•±¥¹”½¹ÑÉ…Ðè((€€€€€€€A¡…Í”€Ùè(€€€€€€€€€€€•¹•É…Ñ•}…¹‘¥‘…Ñ•}Á±…¹Ì¡Í½ÕÉ•}µ½‘•°¤((€€€€€€€A¡…Í”€Ùè(€€€€€€€€€€€‘•É¥Ù•}Ñ…É•Ñ}½¹ÍÑÉ…¥¹ÑÌ (€€€€€€€€€€€€€€€Í½ÕÉ•}µ½‘•°õÍ½ÕÉ•}µ½‘•°°(€€€€€€€€€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õÁ±…¸°(€€€€€€€€€€€€¤((€€€€€€€A¡…Í”€Ùè(€€€€€€€€€€€ÁÉ½Ù”Í½ÕÉ”Í•µ…¹Ñ¥Ì€ôôÑ…É•Ð±½Ý•É¥¹œÍ•µ…¹Ñ¥Ì((€€€€€€€A¡…Í”€Ùè(€€€€€€€€€€€Í•±•Ð½¹±ä…¹‘¥‘…Ñ•Ì…ÁÁÉ½Ù•‰ä€Ù€¬€Ù((€€€Q¡¥Ì™Õ¹Ñ¥½¸‘½•Ì¹½ÐÍ•±•Ð„…¹‘¥‘…Ñ”…¹‘½•Ì¹½Ð…ÁÁÉ½Ù”½¹”¸((€€€±°ÕÉÉ•¹Ñ±äÕ¹¥µÁ±•µ•¹Ñ•Á±…¸­¥¹‘Ì™…¥°±½Í•Ý¥Ñ „ÍÑÉÕÑÕÉ•°(€€€ÍÑ…‰±”É•…Í½¸½‘”¸(€€€€ˆˆˆ(€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Í½ÕÉ•}µ½‘•°°M½ÕÉ•M•µ…¹Ñ¥5½‘•°¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ9½¹”°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9Y1%}M=UI}5=0°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…ÑÕ…±}ÑåÁ”ˆèÑåÁ”¡Í½ÕÉ•}µ½‘•°¤¹}}¹…µ•}|°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡…¹‘¥‘…Ñ•}Á±…¸°Q…É•Ñ1½Ý•É¥¹A±…¸¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ9½¹”°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9Y1%}9%Q}A18°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…ÑÕ…±}ÑåÁ”ˆèÑåÁ”¡…¹‘¥‘…Ñ•}Á±…¸¤¹}}¹…µ•}|°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°Q…É•Ñ¹Ù¥É½¹µ•¹Ð¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9Y1%}QIQ}9Y%I=959P°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…ÑÕ…±}ÑåÁ”ˆèÑåÁ”¡Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð¤¹}}¹…µ•}|°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥ÌQ…É•Ñ1½Ý•É¥¹-¥¹¹	%}]IAAI}10è(€€€€€€€É•ÍÕ±Ðõ}‘•É¥Ù•}…‰¥}ÝÉ…ÁÁ•É|À¡Í½ÕÉ•}µ½‘•°õÍ½ÕÉ•}µ½‘•°±…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸±Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð±…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉäõ…‰¥}ÝÉ…ÁÁ•É}É•¥ÍÑÉä¤(€€€€€€€É•ÑÕÉ¸}Ù…±¥‘…Ñ•}É•ÍÕ±Ñ}¥¹Ù…É¥…¹ÑÌ¡…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸±É•ÍÕ±ÐõÉ•ÍÕ±Ð¤(€€€¥˜…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥¸ì(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹=U9QI}=	MIYQ%=9}AQH°(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹MeM11}=I}MIY%}	%}AQH°(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}Y9Q}AQH°(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹55U}IU9Q%5}AQH°(€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}IU9Q%5}AQH°(€€€ôè(€€€€€€€É•ÍÕ±Ð€ô}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•|À (€€€€€€€€€€€Í½ÕÉ•}µ½‘•°õÍ½ÕÉ•}µ½‘•°°(€€€€€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€€€€€€€€ÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉäõÁÉ¥Ù¥±••‘}ÉÕ¹Ñ¥µ•}É•¥ÍÑÉä°(€€€€€€€€¤(€€€€€€€É•ÑÕÉ¸}Ù…±¥‘…Ñ•}É•ÍÕ±Ñ}¥¹Ù…É¥…¹ÑÌ (€€€€€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°É•ÍÕ±ÐõÉ•ÍÕ±Ð(€€€€€€€€¤(€€€¥˜…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥ÌQ…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}MQQ}5!%9è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹AI%Y%1}MQQ}5!%9}9M}I=UQ°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì‰É½ÕÑ”ˆè€‰Ý¡½±•}™Õ¹Ñ¥½¹}ÁÉ¥Ù¥±••‘}ÍÑ…Ñ•}µ…¡¥¹”‰ô°(€€€€€€€€¤(€€€¥˜…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥ÌQ…É•Ñ1½Ý•É¥¹-¥¹¹AI%Y%1}U9Q%=91}11	,è(€€€€€€€É•ÍÕ±Ð€ô}‘•É¥Ù•}ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±|À (€€€€€€€€€€€Í½ÕÉ•}µ½‘•°õÍ½ÕÉ•}µ½‘•°°(€€€€€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹ÐõÑ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€€€€€€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}É•¥ÍÑÉäõÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}É•¥ÍÑÉä°(€€€€€€€€€€€ÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}Á½±¥äõÁÉ¥Ù¥±••‘}™Õ¹Ñ¥½¹…±}Á½±¥ä°(€€€€€€€€¤(€€€€€€€É•ÑÕÉ¸}Ù…±¥‘…Ñ•}É•ÍÕ±Ñ}¥¹Ù…É¥…¹ÑÌ (€€€€€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°É•ÍÕ±ÐõÉ•ÍÕ±Ð(€€€€€€€€¤(€€€‘•É¥Ù•È€ô}A19}-%9}%MAQ ¹•Ð¡…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¤(€€€¥˜‘•É¥Ù•È¥Ì9½¹”è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹U9-9=]9}A19}-%9°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…ÑÕ…±}­¥¹ˆèÍÑÈ¡…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¤°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€É•ÍÕ±Ð€ô‘•É¥Ù•È (€€€€€€€Í½ÕÉ•}µ½‘•°°(€€€€€€€…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€Ñ…É•Ñ}•¹Ù¥É½¹µ•¹Ð°(€€€€¤((€€€É•ÑÕÉ¸}Ù…±¥‘…Ñ•}É•ÍÕ±Ñ}¥¹Ù…É¥…¹ÑÌ (€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€€€€É•ÍÕ±ÐõÉ•ÍÕ±Ð°(€€€€¤(()}}…±±}|€ô€ (€€€€‰%a}MeMY}5ØÑ}9U}QQ}9Y%I=959Pˆ°(€€€€‰Q…É•Ñ‰¤ˆ°(€€€€‰Q…É•ÑÉ¡¥Ñ•ÑÕÉ”ˆ°(€€€€‰Q…É•ÑÍµ¥…±•Ðˆ°(€€€€‰Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðˆ°(€€€€‰Q…É•Ñ½¹ÍÑÉ…¥¹Ñ5½‘•°ˆ°(€€€€‰Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”ˆ°(€€€€‰Q…É•Ñ½¹ÑÉ½±±½Ý½¹ÍÑÉ…¥¹Ðˆ°(€€€€‰Q…É•Ñ¹Ù¥É½¹µ•¹Ðˆ°(€€€€‰Q…É•Ñ5•µ½Éå½¹ÍÑÉ…¥¹Ðˆ°(€€€€‰Q…É•Ñ=Á•É…¹‘±…ÍÌˆ°(€€€€‰Q…É•Ñ=Á•É…¹‘½¹ÍÑÉ…¥¹Ðˆ°(€€€€‰Q…É•Ñ=Á•É…¹‘I½±”ˆ°(€€€€‰‘•É¥Ù•}Ñ…É•Ñ}½¹ÍÑÉ…¥¹ÑÌˆ°(¤((Œ€´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´(Œ•ÁÉ•…Ñ•ÁÉ¥Ù…Ñ”µ•áÁÉ•ÍÍ¥½¸½µÁ…Ñ¥‰¥±¥Ñä¡•±Á•ÉÌ‰•±½ÜÑ¡¥Ìµ…É­•È…É”(Œ¹½ÐÁ…ÉÐ½˜Ñ¡”A¡…Í”€ÙÁÕ‰±¥Œ‘¥ÍÁ…Ñ …¹µÕÍÐ¹½Ð‰”ÕÍ•‰ä¹•Ü½‘”¸(ŒQ¡”…ÕÑ¡½É¥Ñ…Ñ¥Ù”¥µÁ±•µ•¹Ñ…Ñ¥½¸¥Ì}µ½‘Õ±”¹Á¡…Í”Ù}}•áÁÉ•ÍÍ¥½¸¸(ŒQ¡•äÉ•µ…¥¸Ñ•µÁ½É…É¥±ä™½ÈÍ½ÕÉ”½µÁ…Ñ¥‰¥±¥Ñä½¹±äìA¡…Í”€Ù‘¥ÍÁ…Ñ (ŒÉ•…¡•ÌÑ¡”µ½‘Õ±”¥µÁ±•µ•¹Ñ…Ñ¥½¸•á±ÕÍ¥Ù•±äÑ¡É½Õ }‘•É¥Ù•}}•áÁÉ•ÍÍ¥½¹|À¸(Œ€´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´()‘•˜}É•©•Ñ}¥™}½Á•É…¹‘}™…ÑÍ}¥¹½µÁ±•Ñ” (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðð9½¹”è(€€€¥˜Í½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹½µÁ±•Ñ”è(€€€€€€€É•ÑÕÉ¸9½¹”((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹M=UI}=AI9}QM}%9=5A1Q°(€€€€€€€€¤°(€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€‰µ¥ÍÍ¥¹}™…Ñ}½‘•Ìˆè€ˆ°ˆ¹©½¥¸ (€€€€€€€€€€€€€€€Í½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹µ¥ÍÍ¥¹}™…Ñ}½‘•Ì(€€€€€€€€€€€€¤°(€€€€€€€ô°(€€€€¤(()‘•˜}É•©•Ñ}¥™}½Á•É…Ñ¥½¹}™…ÑÍ}¥¹½µÁ±•Ñ” (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðð9½¹”è(€€€¥˜Í½ÕÉ•}µ½‘•°¹½Á•É…Ñ¥½¸¹½µÁ±•Ñ”è(€€€€€€€É•ÑÕÉ¸9½¹”((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹M=UI}=AIQ%=9}QM}%9=5A1Q°(€€€€€€€€¤°(€€€€¤(()‘•˜}É•©•Ñ}¥™}…Ñ½µ¥}™…ÑÍ}¥¹½µÁ±•Ñ” (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðð9½¹”è(€€€¥˜Í½ÕÉ•}µ½‘•°¹…Ñ½µ¥Œ¹½µÁ±•Ñ”è(€€€€€€€É•ÑÕÉ¸9½¹”((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹M=UI}Q=5%}QM}%9=5A1Q°(€€€€€€€€¤°(€€€€¤(()‘•˜}É•©•Ñ}¥™}‰…ÉÉ¥•É}™…ÑÍ}¥¹½µÁ±•Ñ” (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðð9½¹”è(€€€¥˜Í½ÕÉ•}µ½‘•°¹‰…ÉÉ¥•È¹½µÁ±•Ñ”è(€€€€€€€É•ÑÕÉ¸9½¹”((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹M=UI}	II%I}QM}%9=5A1Q°(€€€€€€€€¤°(€€€€¤(()‘•˜}É•©•Ñ}¥™}¥µÁ±¥¥Ñ}ÍÑ…Ñ•}™…ÑÍ}¥¹½µÁ±•Ñ” (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðð9½¹”è(€€€¥˜Í½ÕÉ•}µ½‘•°¹¥µÁ±¥¥Ñ}ÍÑ…Ñ”¹½µÁ±•Ñ”è(€€€€€€€É•ÑÕÉ¸9½¹”((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹M=UI}%5A1%%Q}MQQ}QM}%9=5A1Q°(€€€€€€€€¤°(€€€€¤(()‘•˜}É•©•Ñ}¥™}½¹ÑÉ½±}™±½Ý}™…ÑÍ}¥¹½µÁ±•Ñ” (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðð9½¹”è(€€€¥˜Í½ÕÉ•}µ½‘•°¹½¹ÑÉ½±}™±½Ü¹™}½¬è(€€€€€€€É•ÑÕÉ¸9½¹”((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹M=UI}=9QI=1}1=]}QM}%9=5A1Q°(€€€€€€€€¤°(€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€‰™}•ÉÉ½ÈˆèÍ½ÕÉ•}µ½‘•°¹½¹ÑÉ½±}™±½Ü¹™}•ÉÉ½È°(€€€€€€€ô°(€€€€¤()‘•˜}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ñ}™…¥±ÕÉ” (€€€€¨°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(€€€•áŒè	…Í•á•ÁÑ¥½¸°(¤€´øQ…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ðè(€€€€ˆˆˆ(€€€½¹Ù•ÉÐµ•áÁÉ•ÍÍ¥½¸‘•É¥Ù…Ñ¥½¸…¹¥¹ÑÉ¥¹Í¥ŒµÙ…±¥‘…Ñ¥½¸™…¥±ÕÉ•Ì¥¹Ñ¼„(€€€™…¥°µ±½Í•A¡…Í”€ÙÉ•ÍÕ±Ð¸((€€€±…ÍÍ¥™¥…Ñ¥½¸ÉÕ±•Ìè((€€€€€€¨áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½ÈÝ¥Ñ …¸•áÁ±¥¥ÐÉ•…Í½¸½‘”è(€€€€€€€ÁÉ•Í•ÉÙ”Ñ¡”•á…Ðµ•áÁÉ•ÍÍ¥½¸É•…Í½¸½‘”…¹ÍÑÉÕÑÕÉ•‘•Ñ…¥±Ì¸((€€€€€€¨1•…ä½Õ¹±…ÍÍ¥™¥•áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½Èè(€€€€€€€±…ÍÍ¥™ä…Ì}aAIMM%=9}=9MQI%9Q}%9Y1%¸((€€€€€€¨QåÁ•ÉÉ½È€¼Y…±Õ•ÉÉ½ÈÉ…¥Í•½ÕÑÍ¥‘”Ñ¡”±…ÍÍ¥™¥•‘½µ…¥¸µ•ÉÉ½È(€€€€€€€ÁÉ½Ñ½½°è(€€€€€€€ÑÉ•…Ð…Ì%9QI91}%9YI%9Q}Y%=1Q%=8É…Ñ¡•ÈÑ¡…¸ÁÉ•Ñ•¹‘¥¹œÑ¡…ÐÑ¡”(€€€€€€€…¹‘¥‘…Ñ”µ•É•±ä±…­Ì„Ù…±¥µ•áÁÉ•ÍÍ¥½¸½¹ÑÉ…Ð¸((€€€€€€¨¹äÕ¹•áÁ•Ñ••á•ÁÑ¥½¸è(€€€€€€€…±Í¼ÑÉ•…Ð…Ì%9QI91}%9YI%9Q}Y%=1Q%=8¸((€€€á•ÁÑ¥½¸Ñ•áÐ¥Ì¥¹Ñ•¹Ñ¥½¹…±±ä¹½ÐÕÍ•…Ì„Í•µ…¹Ñ¥Œ¥¹Ñ•É™…”¸(€€€€ˆˆˆ((€€€‰…Í•}‘•Ñ…¥±Ìè‘¥ÑmÍÑÈ°Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•Ñ…¥±Y…±Õ•t€ôì(€€€€€€€€‰ÍÑ…”ˆè€‰}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ñ}‘•É¥Ù…Ñ¥½¸ˆ°(€€€€€€€€‰•á•ÁÑ¥½¹}ÑåÁ”ˆèÑåÁ”¡•áŒ¤¹}}¹…µ•}|°(€€€ô((€€€¥˜¥Í¥¹ÍÑ…¹”¡•áŒ°áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È¤è(€€€€€€€É•…Í½¹}½‘”€ô•áŒ¹É•…Í½¹}½‘”((€€€€€€€‘•Ñ…¥±Ì€ô‘¥Ð¡•áŒ¹‘•Ñ…¥±Ì¤(€€€€€€€‘•Ñ…¥±Ì¹ÕÁ‘…Ñ”¡‰…Í•}‘•Ñ…¥±Ì¤((€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô¡É•…Í½¹}½‘”°¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõ‘•Ñ…¥±Ì°(€€€€€€€€¤((€€€¥˜¥Í¥¹ÍÑ…¹”¡•áŒ°€¡QåÁ•ÉÉ½È°Y…±Õ•ÉÉ½È¤¤è(€€€€€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€€€€€¤°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€¨©‰…Í•}‘•Ñ…¥±Ì°(€€€€€€€€€€€€€€€€‰½µÁ½¹•¹Ðˆè€‰}•áÁÉ•ÍÍ¥½¹}‘•É¥Ù…Ñ¥½¸ˆ°(€€€€€€€€€€€€€€€€‰™…¥±ÕÉ•}±…ÍÌˆè€‰Õ¹•áÁ•Ñ•‘}ÑåÁ•}½É}Ù…±Õ•}•ÉÉ½Èˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€É•ÑÕÉ¸Q…É•Ñ½¹ÍÑÉ…¥¹Ñ•É¥Ù…Ñ¥½¹I•ÍÕ±Ð¹™…¥±ÕÉ” (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€É•…Í½¹}½‘•Ìô (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹%9QI91}%9YI%9Q}Y%=1Q%=8°(€€€€€€€€¤°(€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€¨©‰…Í•}‘•Ñ…¥±Ì°(€€€€€€€€€€€€‰½µÁ½¹•¹Ðˆè€‰}•áÁÉ•ÍÍ¥½¹}‘•É¥Ù…Ñ¥½¸ˆ°(€€€€€€€€€€€€‰™…¥±ÕÉ•}±…ÍÌˆè€‰Õ¹•áÁ•Ñ•‘}•á•ÁÑ¥½¸ˆ°(€€€€€€€ô°(€€€€¤()‘•˜}‰Õ¥±‘}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ñ}™É½µ}…ÕÑ¡½É¥Ñ…Ñ¥Ù•}™…ÑÌ (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´øáÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹Ðè(€€€€ˆˆˆ(€€€	Õ¥±„ÑåÁ•ÍÑÉÕÑÕÉ•µ•áÁÉ•ÍÍ¥½¸½¹ÍÑÉ…¥¹ÐÍ½±•±ä™É½´…ÕÑ¡½É¥Ñ…Ñ¥Ù”(€€€M½ÕÉ•M•µ…¹Ñ¥5½‘•°™…ÑÌ¸((€€€Q¡¥Ì™Õ¹Ñ¥½¸µÕÍÐ¹½Ð¥¹ÍÁ•Ðè((€€€€€€¨…¹‘¥‘…Ñ•}Á±…¸¹µ•Ñ…‘…Ñ„™½ÈÍ½ÕÉ”Í•µ…¹Ñ¥Ìì(€€€€€€¨Í½ÕÉ•}µ½‘•°¹á±•¸…Ì…¸½Á•É…¹µÝ¥‘Ñ ™…±±‰…¬ì(€€€€€€¨É…Ü…Í´°µ¹•µ½¹¥Œ°¥¹ÍÑÉÕÑ¥½¸°½È%HÑ•áÐì(€€€€€€¨ÉÕ¹Ñ¥µ”µ™…Ð¥µÁ±•µ•¹Ñ…Ñ¥½¸‘•Ñ…¥±Ìì(€€€€€€¨¡½ÍÐAåÑ¡½¸½È¥¹Ñ••ÈÝ¥‘Ñ¡Ì¸((€€€¹äÕ¹…Ù…¥±…‰±”½ÈÕ¹ÍÕÁÁ½ÉÑ•Í•µ…¹Ñ¥Œ™…ÐµÕÍÐÉ…¥Í”(€€€áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½ÈÝ¥Ñ „ÍÑ…‰±”A¡…Í”€ÙÉ•…Í½¸½‘”¸(€€€€ˆˆˆ(€€€¥˜…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¥Ì¹½ÐQ…É•Ñ1½Ý•É¥¹-¥¹¹}aAIMM%=8è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}A19}-%9}5%M5Q °(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰•áÁ•Ñ•‘}Á±…¹}­¥¹ˆè€ (€€€€€€€€€€€€€€€€€€€Q…É•Ñ1½Ý•É¥¹-¥¹¹}aAIMM%=8¹Ù…±Õ”(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€€‰…ÑÕ…±}Á±…¹}­¥¹ˆè…¹‘¥‘…Ñ•}Á±…¸¹­¥¹¹Ù…±Õ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€}É•ÅÕ¥É•}}•áÁÉ•ÍÍ¥½¹}Í½ÕÉ•}•±¥¥‰¥±¥Ñä (€€€€€€€Í½ÕÉ•}µ½‘•°õÍ½ÕÉ•}µ½‘•°°(€€€€€€€…¹‘¥‘…Ñ•}Á±…¸õ…¹‘¥‘…Ñ•}Á±…¸°(€€€€¤((€€€½Á•É…Ñ¥½¹}­¥¹€ô}µ…Á}Í½ÕÉ•}½Á•É…Ñ¥½¹}Ñ½}}•áÁÉ•ÍÍ¥½¹}½Á•É…Ñ¥½¸ (€€€€€€€Í½ÕÉ•}µ½‘•°¹½Á•É…Ñ¥½¸(€€€€¤((€€€É•ÍÕ±Ñ}Í½ÕÉ•}½Á•É…¹€ôÍ½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹É•ÍÕ±Ð(€€€¥¹ÁÕÑ}Í½ÕÉ•}½Á•É…¹‘Ì€ôÍ½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹¥¹ÁÕÑÌ((€€€¥˜É•ÍÕ±Ñ}Í½ÕÉ•}½Á•É…¹¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}IMU1Q}=9QIQ}%9Y1%°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰µ¥ÍÍ¥¹}™…Ðˆè€‰Í½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹É•ÍÕ±Ðˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½Ð¥¹ÁÕÑ}Í½ÕÉ•}½Á•É…¹‘Ìè(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AI9}	%9%9}5%MM%9°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰µ¥ÍÍ¥¹}™…Ðˆè€‰Í½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹¥¹ÁÕÑÌˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€É•ÍÕ±Ñ}ÑåÁ”€ô}‰Õ¥±‘}}•áÁÉ•ÍÍ¥½¹}ÑåÁ•}½¹ÑÉ…Ð (€€€€€€€½Á•É…¹õÉ•ÍÕ±Ñ}Í½ÕÉ•}½Á•É…¹°(€€€€€€€É½±”ô‰É•ÍÕ±Ðˆ°(€€€€¤((€€€½Á•É…¹‘}‰¥¹‘¥¹Ì€ôÑÕÁ±” (€€€€€€€}‰Õ¥±‘}}•áÁÉ•ÍÍ¥½¹}½Á•É…¹‘}‰¥¹‘¥¹œ (€€€€€€€€€€€½Á•É…¹õ½Á•É…¹°(€€€€€€€€€€€½É‘¥¹…°õ¥¹‘•à°(€€€€€€€€¤(€€€€€€€™½È¥¹‘•à°½Á•É…¹¥¸•¹Õµ•É…Ñ”¡¥¹ÁÕÑ}Í½ÕÉ•}½Á•É…¹‘Ì¤(€€€€¤((€€€½¹ÍÑÉ…¥¹Ð€ôáÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹Ð (€€€€€€€Á±…¹}¥õ…¹‘¥‘…Ñ•}Á±…¸¹Á±…¹}¥°(€€€€€€€½Á•É…Ñ¥½¹}­¥¹õ½Á•É…Ñ¥½¹}­¥¹°(€€€€€€€É•ÍÕ±Ñ}ÑåÁ”õÉ•ÍÕ±Ñ}ÑåÁ”°(€€€€€€€½Á•É…¹‘Ìõ½Á•É…¹‘}‰¥¹‘¥¹Ì°(€€€€¤((€€€Ù…±¥‘…Ñ•}}•áÁÉ•ÍÍ¥½¹}½¹ÍÑÉ…¥¹Ð¡½¹ÍÑÉ…¥¹Ð¤(€€€É•ÑÕÉ¸½¹ÍÑÉ…¥¹Ð()‘•˜}É•ÅÕ¥É•}}•áÁÉ•ÍÍ¥½¹}Í½ÕÉ•}•±¥¥‰¥±¥Ñä (€€€€¨°(€€€Í½ÕÉ•}µ½‘•°èM½ÕÉ•M•µ…¹Ñ¥5½‘•°°(€€€…¹‘¥‘…Ñ•}Á±…¸èQ…É•Ñ1½Ý•É¥¹A±…¸°(¤€´ø9½¹”è(€€€¥˜¹½ÐÍ½ÕÉ•}µ½‘•°¹Í¡•±°¹¥Í}¹•ÕÑÉ…°è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}M!11}9=Q}9UQI0°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰Í¡•±±}­¥¹ˆèÍ½ÕÉ•}µ½‘•°¹Í¡•±°¹­¥¹¹Ù…±Õ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜Í½ÕÉ•}µ½‘•°¹µ•µ½Éå}•™™•Ð¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}55=Ie}U9-9=]8°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰µ¥ÍÍ¥¹}™…Ðˆè€‰Í½ÕÉ•}µ½‘•°¹µ•µ½Éå}•™™•Ðˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½ÐÍ½ÕÉ•}µ½‘•°¹µ•µ½Éå}•™™•Ð¹¥Í}¹½}µ•µ½Éå}•™™•Ð ¤è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}55=Ie}U9MUAA=IQ°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰µ•µ½Éå}•™™•Ñ}­¥¹ˆè€ (€€€€€€€€€€€€€€€€€€€Í½ÕÉ•}µ½‘•°¹µ•µ½Éå}•™™•Ð¹­¥¹¹Ù…±Õ”(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜Í½ÕÉ•}µ½‘•°¹…Ñ½µ¥}•™™•Ðè(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}Q=5%}U9MUAA=IQ°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰…Ñ½µ¥}•™™•ÐˆèQÉÕ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜Í½ÕÉ•}µ½‘•°¹‰…ÉÉ¥•É}•™™•Ðè(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}	II%I}U9MUAA=IQ°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰‰…ÉÉ¥•É}•™™•ÐˆèQÉÕ”°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½ÐÍ½ÕÉ•}µ½‘•°¹½¹ÑÉ½±}™±½Ü¹¥Í}Í¥µÁ±•}™…±±Ñ¡É½Õ  ¤è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=9QI=1}1=]}U9MUAA=IQ°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰½¹ÑÉ½±}™±½Ý}­¥¹ˆè€ (€€€€€€€€€€€€€€€€€€€Í½ÕÉ•}µ½‘•°¹½¹ÑÉ½±}™±½Ü¹­¥¹¹Ù…±Õ”(€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜Í½ÕÉ•}µ½‘•°¹¡•±Á•É}…‰¤¥Ì¹½Ð9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}!1AI}	%}U9MUAA=IQ°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰¡•±Á•É}…‰¥}¥ˆèÍ½ÕÉ•}µ½‘•°¹¡•±Á•É}…‰¤¹¥‘•¹Ñ¥™¥•È°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜Í½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹½ÕÑÁÕÑ}½Õ¹Ð€ø€Äè(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}5U1Q%A1}=UQAUQM}U9MUAA=IQ°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰½ÕÑÁÕÑ}½Õ¹ÐˆèÍ½ÕÉ•}µ½‘•°¹½Á•É…¹‘Ì¹½ÕÑÁÕÑ}½Õ¹Ð°(€€€€€€€€€€€ô°(€€€€€€€€¤(€€€€€€€€(Œµ•áÁÉ•ÍÍ¥½¸µ…ÁÁ¥¹œ±¥Ù•Ì¥¸Á¡…Í”Ù}}•áÁÉ•ÍÍ¥½¸¹Áä¸€-••ÀÑ¡¥Ì±•…ä(Œ¹…µ”¥¹•ÉÐÍ¼½±ÁÉ¥Ù…Ñ”¡•±Á•ÉÌ…¹¹½Ð‰•½µ”„Í•½¹Í•µ…¹Ñ¥ŒÍ½ÕÉ”¸)}M=UI}Q=}}aAIMM%=9}=AIQ%=8è5…ÁÁ¥¹m½‰©•Ð°½‰©•Ñt€ôíô()‘•˜}µ…Á}Í½ÕÉ•}½Á•É…Ñ¥½¹}Ñ½}}•áÁÉ•ÍÍ¥½¹}½Á•É…Ñ¥½¸ (€€€½Á•É…Ñ¥½¸èM½ÕÉ•=Á•É…Ñ¥½¸ð9½¹”°(¤€´øáÁÉ•ÍÍ¥½¹=Á•É…Ñ¥½¹-¥¹è(€€€¥˜½Á•É…Ñ¥½¸¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AIQ%=9}%9=5A1Q°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰µ¥ÍÍ¥¹}™…Ðˆè€‰Í½ÕÉ•}µ½‘•°¹½Á•É…Ñ¥½¸ˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜¹½Ð¥Í¥¹ÍÑ…¹”¡½Á•É…Ñ¥½¸¹­¥¹°M½ÕÉ•=Á•É…Ñ¥½¹-¥¹¤è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AIQ%=9}U9-9=]8°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰½Á•É…Ñ¥½¹}­¥¹‘}ÑåÁ”ˆèÑåÁ”¡½Á•É…Ñ¥½¸¹­¥¹¤¹}}¹…µ•}|°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€µ…ÁÁ¥¹œè5…ÁÁ¥¹l(€€€€€€€M½ÕÉ•=Á•É…Ñ¥½¹-¥¹°(€€€€€€€áÁÉ•ÍÍ¥½¹=Á•É…Ñ¥½¹-¥¹°(€€€t€ôì(€€€€€€€M½ÕÉ•=Á•É…Ñ¥½¹-¥¹¹èáÁÉ•ÍÍ¥½¹=Á•É…Ñ¥½¹-¥¹¹°(€€€€€€€M½ÕÉ•=Á•É…Ñ¥½¹-¥¹¹MUèáÁÉ•ÍÍ¥½¹=Á•É…Ñ¥½¹-¥¹¹MU°(€€€€€€€M½ÕÉ•=Á•É…Ñ¥½¹-¥¹¹	%Q}9èáÁÉ•ÍÍ¥½¹=Á•É…Ñ¥½¹-¥¹¹	%Q}9°(€€€€€€€M½ÕÉ•=Á•É…Ñ¥½¹-¥¹¹	%Q}=HèáÁÉ•ÍÍ¥½¹=Á•É…Ñ¥½¹-¥¹¹	%Q}=H°(€€€€€€€M½ÕÉ•=Á•É…Ñ¥½¹-¥¹¹	%Q}a=HèáÁÉ•ÍÍ¥½¹=Á•É…Ñ¥½¹-¥¹¹	%Q}a=H°(€€€ô((€€€ÑÉäè(€€€€€€€É•ÑÕÉ¸µ…ÁÁ¥¹m½Á•É…Ñ¥½¸¹­¥¹‘t(€€€•á•ÁÐ-•åÉÉ½Èè(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AIQ%=9}U9MUAA=IQ°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…Ñ¥½¹}­¥¹ˆè½Á•É…Ñ¥½¸¹­¥¹¹Ù…±Õ”°(€€€€€€€€€€€ô°(€€€€€€€€¤™É½´9½¹”()‘•˜}‰Õ¥±‘}}•áÁÉ•ÍÍ¥½¹}ÑåÁ•}½¹ÑÉ…Ð (€€€€¨°(€€€½Á•É…¹èM½ÕÉ•=Á•É…¹°(€€€É½±”èÍÑÈ°(¤€´øáÁÉ•ÍÍ¥½¹QåÁ•½¹ÑÉ…Ðè(€€€¥˜½Á•É…¹¹Ý¥‘Ñ¡}‰¥ÑÌ¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AI9}]%Q!}5%MM%9°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰É½±”ˆèÉ½±”°(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆè½Á•É…¹¹¥¹‘•à°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜€ (€€€€€€€¥Í¥¹ÍÑ…¹”¡½Á•É…¹¹Ý¥‘Ñ¡}‰¥ÑÌ°‰½½°¤(€€€€€€€½È¹½Ð¥Í¥¹ÍÑ…¹”¡½Á•É…¹¹Ý¥‘Ñ¡}‰¥ÑÌ°¥¹Ð¤(€€€€€€€½È½Á•É…¹¹Ý¥‘Ñ¡}‰¥ÑÌ€ðô€À(€€€€¤è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}IMU1Q}=9QIQ}%9Y1%°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰É½±”ˆèÉ½±”°(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆè½Á•É…¹¹¥¹‘•à°(€€€€€€€€€€€€€€€€‰¥¹Ù…±¥‘}™¥•±ˆè€‰Ý¥‘Ñ¡}‰¥ÑÌˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜½Á•É…¹¹Í¥¹•‘¹•ÍÌ¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AI9}M%99MM}5%MM%9°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰É½±”ˆèÉ½±”°(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆè½Á•É…¹¹¥¹‘•à°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜½Á•É…¹¹Í¥¹•‘¹•ÍÌ¹½Ð¥¸€ (€€€€€€€M½ÕÉ•M¥¹•‘¹•ÍÌ¹M%9°(€€€€€€€M½ÕÉ•M¥¹•‘¹•ÍÌ¹U9M%9°(€€€€¤è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}IMU1Q}=9QIQ}%9Y1%°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰É½±”ˆèÉ½±”°(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆè½Á•É…¹¹¥¹‘•à°(€€€€€€€€€€€€€€€€‰¥¹Ù…±¥‘}™¥•±ˆè€‰Í¥¹•‘¹•ÍÌˆ°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€É•ÑÕÉ¸áÁÉ•ÍÍ¥½¹QåÁ•½¹ÑÉ…Ð (€€€€€€€Ý¥‘Ñ¡}‰¥ÑÌõ½Á•É…¹¹Ý¥‘Ñ¡}‰¥ÑÌ°(€€€€€€€Í¥¹•‘¹•ÍÌõ½Á•É…¹¹Í¥¹•‘¹•ÍÌ°(€€€€¤()‘•˜}‰Õ¥±‘}}•áÁÉ•ÍÍ¥½¹}½Á•É…¹‘}‰¥¹‘¥¹œ (€€€€¨°(€€€½Á•É…¹èM½ÕÉ•=Á•É…¹°(€€€½É‘¥¹…°è¥¹Ð°(¤€´øáÁÉ•ÍÍ¥½¹=Á•É…¹‘	¥¹‘¥¹œè(€€€¥˜½Á•É…¹¹‰¥¹‘¥¹œ¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AI9}	%9%9}5%MM%9°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰½Á•É…¹‘}½É‘¥¹…°ˆè½É‘¥¹…°°(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆè½Á•É…¹¹¥¹‘•à°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜½Á•É…¹¹Ý¥‘Ñ¡}‰¥ÑÌ¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AI9}]%Q!}5%MM%9°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰½Á•É…¹‘}½É‘¥¹…°ˆè½É‘¥¹…°°(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆè½Á•É…¹¹¥¹‘•à°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€¥˜½Á•É…¹¹Í¥¹•‘¹•ÍÌ¥Ì9½¹”è(€€€€€€€É…¥Í”áÁÉ•ÍÍ¥½¹½¹ÍÑÉ…¥¹ÑY…±¥‘…Ñ¥½¹ÉÉ½È (€€€€€€€€€€€Q…É•Ñ½¹ÍÑÉ…¥¹ÑI•…Í½¹½‘”¹}aAIMM%=9}=AI9}M%99MM}5%MM%9°(€€€€€€€€€€€‘•Ñ…¥±Ìõì(€€€€€€€€€€€€€€€€‰½Á•É…¹‘}½É‘¥¹…°ˆè½É‘¥¹…°°(€€€€€€€€€€€€€€€€‰Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àˆè½Á•É…¹¹¥¹‘•à°(€€€€€€€€€€€ô°(€€€€€€€€¤((€€€É•ÑÕÉ¸áÁÉ•ÍÍ¥½¹=Á•É…¹‘	¥¹‘¥¹œ (€€€€€€€½É‘¥¹…°õ½É‘¥¹…°°(€€€€€€€Í½ÕÉ•}½Á•É…¹‘}¥¹‘•àõ½Á•É…¹¹¥¹‘•à°(€€€€€€€‰¥¹‘¥¹œõ½Á•É…¹¹‰¥¹‘¥¹œ°(€€€€€€€ÑåÁ•}½¹ÑÉ…ÐõáÁÉ•ÍÍ¥½¹QåÁ•½¹ÑÉ…Ð (€€€€€€€€€€€Ý¥‘Ñ¡}‰¥ÑÌõ½Á•É…¹¹Ý¥‘Ñ¡}‰¥ÑÌ°(€€€€€€€€€€€Í¥¹•‘¹•ÍÌõ½Á•É…¹¹Í¥¹•‘¹•ÍÌ°(€€€€€€€€¤°(€€€€¤