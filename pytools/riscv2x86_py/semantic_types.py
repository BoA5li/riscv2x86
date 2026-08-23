from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Iterable, Tuple


class PreservationLevel(str, Enum):
    """
    SourceSemanticModel 所需的语义保留等级。

    该等级描述 source semantic model 的 coarse preservation routing，
    而不是：

      * 翻译成功率；
      * 某个 target plan 已被证明正确；
      * 某段代码已经可以安全生成；
      * 某个 lowering strategy 已经被允许。

    Preservation level 的最终派生职责属于 preservation.py：

        features + reasons + reason_codes
                    ↓
        derive_preservation_decision(...)
                    ↓
        PreservationDecision

    等级含义：

      A:
        未检测到需要 B/C/D 路由的特殊 preservation semantic。

        常见例子包括普通整数运算、普通内存读写等。

        A 不表示自动批准 generic lowering。
        后续仍必须通过 candidate plan generation、target constraint
        derivation 和 semantic proof gate。

      B:
        stack、frame、ABI、compiler shell、inline asm、volatile、clobber、
        operand constraint、operand binding 等语义。

        这些语义不能仅按照普通 C 表达式等价进行 lowering。

      C:
        控制流敏感语义，例如 internal branch、asm goto、多个退出路径、
        indirect control flow、external control flow、call / return /
        tail-call 等。

        需要 CFG-aware target plan 与控制流重建。

      D:
        微架构敏感操作意图、atomic、barrier、未知 p-code、未知 barrier、
        unresolved source register identity、source semantic summary 不完整
        等高风险或 fail-closed source semantic 状态。

        D 不允许静默退化为普通 C 或普通 x86 instruction sequence。
        它可能要求拒绝翻译，也可能要求采用经过证明的专用 target plan。

    注意：

      runtime fact 不完整、operand binding 不完整、operand width 未证明等
      状态，通常属于 candidate-plan / proof gate 的约束。

      它们可以作为 SemanticFeature 被 SourceSemanticModel 记录，
      但是否提高 preservation level 必须仅由 preservation.py 的
      分类规则决定。
    """

    A = "A"
    B = "B"
    C = "C"
    D = "D"

    @property
    def rank(self) -> int:
        """
        数值越高，表示 preservation routing 要求越强。
        """
        return _PRESERVATION_LEVEL_RANK[self]

    def is_at_least(self, other: "PreservationLevel") -> bool:
        """
        当前 level 是否不低于 other。
        """
        return self.rank >= other.rank

    @property
    def requires_target_specific_lowering(self) -> bool:
        """
        是否通常需要 target-aware lowering。

        A 级不表示 target-independent lowering 已被批准；
        它仅表示 decision 中没有检测到 B/C/D preservation routing
        requirement。
        """
        return self is not PreservationLevel.A

    @property
    def is_fail_closed_level(self) -> bool:
        """
        D 级表示不能无证明地进入普通 generic lowering 路径。
        """
        return self is PreservationLevel.D


_PRESERVATION_LEVEL_RANK = {
    PreservationLevel.A: 0,
    PreservationLevel.B: 1,
    PreservationLevel.C: 2,
    PreservationLevel.D: 3,
}

class SemanticFeature(str, Enum):
    """
    SourceSemanticModel 中记录的 source semantic feature。

    该枚举仅表达 source-side semantic facts、source semantic uncertainty
    和 analysis completeness 状态；不得承载 target register mapping、
    target lowering strategy 或 candidate-plan 选择。
    """

    # ------------------------------------------------------------------
    # Ordinary architectural / data semantics.
    # ------------------------------------------------------------------

    INTEGER = "integer"

    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"

    MEMORY_BARRIER = "memory_barrier"
    INSTRUCTION_BARRIER = "instruction_barrier"
    UNKNOWN_BARRIER = "unknown_barrier"

    ATOMIC_OPERATION = "atomic_operation"

    # ------------------------------------------------------------------
    # Privileged execution and environment state.
    # ------------------------------------------------------------------

    PRIVILEGED_STATE = "privileged_state"
    CSR_ACCESS = "csr_access"
    READ_ONLY_COUNTER_CSR = "read_only_counter_csr"
    PRIVILEGED_TRAP = "privileged_trap"
    PRIVILEGE_RETURN = "privilege_return"
    INTERRUPT_STATE = "interrupt_state"
    ADDRESS_TRANSLATION_STATE = "address_translation_state"
    VIRTUALIZATION_STATE = "virtualization_state"
    DEBUG_STATE = "debug_state"
    PRIVILEGED_STATE_INCOMPLETE = "privileged_state_incomplete"
    FUNCTIONAL_OBSERVABILITY_INCOMPLETE = (
        "functional_observability_incomplete"
    )
    FUNCTIONAL_PRIVILEGED_FALLBACK_POSSIBLE = (
        "functional_privileged_fallback_possible"
    )
    IGNORED_PRIVILEGED_STATE = "ignored_privileged_state"
    COUNTER_OBSERVATION = "counter_observation"
    FPU_ARCHITECTURAL_STATE = "fpu_architectural_state"
    PRIVILEGED_CSR_STATE = "privileged_csr_state"
    TLB_MAINTENANCE = "tlb_maintenance"
    TRAP_SERVICE = "trap_service"
    PMP_STATE = "pmp_state"
    FUNCTIONAL_FALLBACK_REQUESTED = "functional_fallback_requested"
    FUNCTIONAL_ARCHITECTURE_STATE_NOT_PRESERVED = (
        "functional_architecture_state_not_preserved"
    )
    FUNCTIONAL_MICROARCHITECTURE_NOT_PRESERVED = (
        "functional_microarchitecture_not_preserved"
    )

    # ------------------------------------------------------------------
    # Stack / ABI / register-role semantics.
    # ------------------------------------------------------------------

    STACK_POINTER_ACCESS = "stack_pointer_access"
    FRAME_POINTER_ACCESS = "frame_pointer_access"
    STACK_LAYOUT = "stack_layout"

    UNRESOLVED_REGISTER_IDENTITY = "unresolved_register_identity"

    # ------------------------------------------------------------------
    # Compiler shell / GNU GCC-Clang inline asm semantics.
    # ------------------------------------------------------------------

        # ------------------------------------------------------------------
    # Compiler shell / GNU GCC-Clang inline asm semantics.
    # ------------------------------------------------------------------

    INLINE_ASM = "inline_asm"
    VOLATILE_ASM = "volatile_asm"

    # The asm fragment has one or more GNU inline-asm operands.
    #
    # This is intentionally distinct from ASM_INPUT_OPERAND and
    # ASM_OUTPUT_OPERAND. A source summary may establish that operands
    # exist without safely classifying every operand as input or output.
    ASM_OPERANDS = "asm_operands"

    ASM_INPUT_OPERAND = "asm_input_operand"
    ASM_OUTPUT_OPERAND = "asm_output_operand"
    ASM_OPERAND_CONSTRAINT = "asm_operand_constraint"

    ASM_CLOBBER = "asm_clobber"
    MEMORY_CLOBBER = "memory_clobber"
    CONDITION_CODE_CLOBBER = "condition_code_clobber"

    # GNU inline-asm constraint semantics.
    EARLY_CLOBBER = "early_clobber"
    TIED_OPERANDS = "tied_operands"

    # Source metadata describing operand bindings. This must not be
    # confused with target-side register allocation.
    OPERAND_BINDING_METADATA = "operand_binding_metadata"

    EXPLICIT_OPERAND_BINDING = "explicit_operand_binding"
    MATERIALIZED_OPERAND_BINDING = "materialized_operand_binding"
    PROVEN_OPERAND_WIDTH = "proven_operand_width"

    # ------------------------------------------------------------------
    # Control-flow semantics.
    # ------------------------------------------------------------------

    INTERNAL_BRANCH = "internal_branch"
    CALL_OR_RETURN = "call_or_return"
    RETURN = "return"
    TAIL_CALL = "tail_call"

    INDIRECT_CONTROL_FLOW = "indirect_control_flow"
    UNKNOWN_CONTROL_FLOW_TARGET = "unknown_control_flow_target"

    ASM_GOTO = "asm_goto"
    EXTERNAL_CONTROL_FLOW = "external_control_flow"
    MULTIPLE_EXITS = "multiple_exits"
    NON_LOCAL_CONTROL_DEPENDENCY = "non_local_control_dependency"
    CFG_INCOMPLETE = "cfg_incomplete"

    LOCAL_LABEL = "local_label"

    # ------------------------------------------------------------------
    # Microarchitecture / experimental-intent semantics.
    # ------------------------------------------------------------------

    MICROARCH_SENSITIVE = "microarch_sensitive"

    TIMING_SOURCE = "timing_source"
    CACHE_OPERATION = "cache_operation"
    SPECULATION_CONTROL = "speculation_control"
    EXPERIMENT_RETRY_LOOP = "experiment_retry_loop"

    # ------------------------------------------------------------------
    # Analysis completeness / source-summary completeness.
    # ------------------------------------------------------------------

    UNKNOWN_PCODE = "unknown_pcode"

    # Structured semantic analysis cannot safely prove absence of one or
    # more preservation-sensitive source semantics.
    #
    # preservation.py must route this feature to D-level fail-closed handling.
    INCOMPLETE_SEMANTIC_SUMMARY = "incomplete_semantic_summary"

    # ------------------------------------------------------------------
    # Runtime facts / operand binding / proof-gating status.
    # ------------------------------------------------------------------

    RUNTIME_FACTS_UNAVAILABLE = "runtime_facts_unavailable"
    INVALID_RUNTIME_FACTS = "invalid_runtime_facts"

    INCOMPLETE_OPERAND_BINDING = "incomplete_operand_binding"
    INCOMPLETE_OUTPUT_BINDING = "incomplete_output_binding"
    INCOMPLETE_OPERAND_WIDTH = "incomplete_operand_width"

@dataclass(frozen=True)
class PreservationDecision:
    """
    SourceSemanticModel 的派生 preservation classification result。

    本对象是不可变的共享 DTO，只承载已派生的结果：

      * level:
          preservation.py 基于 SourceSemanticModel.features 派生的
          coarse preservation routing level。

      * reasons:
          面向日志、诊断和用户展示的自然语言原因。

      * reason_codes:
          面向程序处理、测试、统计和稳定诊断的机器可读原因码。

      * features:
          SourceSemanticModel 已收集、并用于派生本 decision 的 feature 集。

    本对象不应：

      * 重新读取 IRSummary、Block[]、CFGResult、AsmFragment 或
        TranslationRuntimeFacts；
      * 执行 feature -> preservation level 分类；
      * 保存 RISC-V -> x86 register mapping；
      * 选择 x86 target register；
      * 选择 lowering plan；
      * 证明 target plan 正确；
      * 决定某 candidate plan 是否可生成。

    这些职责分别属于 source_model.py、preservation.py、Phase 6B-6F
    的 target planning / proof / rendering 流程。
    """

    level: PreservationLevel
    reasons: Tuple[str, ...] = ()
    reason_codes: Tuple[str, ...] = ()
    features: FrozenSet[SemanticFeature] = frozenset()

    def __post_init__(self) -> None:
        """
        规范化容器并验证共享 DTO 的基础类型不变式。

        dataclass(frozen=True) 只阻止属性重新绑定；如果调用方传入 list/set，
        外部对象仍可能被修改。因此必须复制为 tuple / frozenset。
        """
        if not isinstance(self.level, PreservationLevel):
            raise TypeError(
                "PreservationDecision.level must be a PreservationLevel, "
                f"got {type(self.level).__name__}"
            )

        if isinstance(self.reasons, str):
            raise TypeError(
                "PreservationDecision.reasons must be an iterable of str, not str"
            )

        if isinstance(self.reason_codes, str):
            raise TypeError(
                "PreservationDecision.reason_codes must be an iterable of str, not str"
            )

        normalized_reasons = tuple(self.reasons)
        normalized_reason_codes = tuple(self.reason_codes)
        normalized_features = frozenset(self.features)

        invalid_reasons = tuple(
            reason
            for reason in normalized_reasons
            if not isinstance(reason, str)
        )
        if invalid_reasons:
            raise TypeError(
                "PreservationDecision.reasons must contain only str values, "
                f"got invalid values: {invalid_reasons!r}"
            )

        invalid_reason_codes = tuple(
            code
            for code in normalized_reason_codes
            if not isinstance(code, str)
        )
        if invalid_reason_codes:
            raise TypeError(
                "PreservationDecision.reason_codes must contain only str values, "
                f"got invalid values: {invalid_reason_codes!r}"
            )

        invalid_features = tuple(
            feature
            for feature in normalized_features
            if not isinstance(feature, SemanticFeature)
        )
        if invalid_features:
            raise TypeError(
                "PreservationDecision.features must contain only SemanticFeature "
                f"values, got invalid values: {invalid_features!r}"
            )

        object.__setattr__(self, "reasons", normalized_reasons)
        object.__setattr__(self, "reason_codes", normalized_reason_codes)
        object.__setattr__(self, "features", normalized_features)

    def has(self, feature: SemanticFeature) -> bool:
        """
        是否包含指定 semantic feature。
        """
        return feature in self.features

    def has_any(self, features: Iterable[SemanticFeature]) -> bool:
        """
        是否包含给定 feature iterable 中的任意一个 feature。
        """
        return any(feature in self.features for feature in features)

    def has_all(self, features: Iterable[SemanticFeature]) -> bool:
        """
        是否包含给定 feature iterable 中的全部 feature。

        对空 iterable 返回 True，符合 all() 的标准语义。
        """
        return all(feature in self.features for feature in features)

    @property
    def requires_target_specific_lowering(self) -> bool:
        """
        该 decision 的 level 是否通常要求 target-aware lowering。

        返回 False 不等于 generic lowering 已获批准。
        A 级 fragment 仍必须经过后续 candidate plan、target constraint
        和 semantic proof 流程。
        """
        return self.level.requires_target_specific_lowering

    @property
    def is_fail_closed_level(self) -> bool:
        """
        是否处于 D 级 fail-closed preservation routing。

        D 级不可静默退化为普通 C 或普通 x86 instruction sequence。
        是否可翻译以及如何翻译，必须由后续经过证明的专用 target plan 决定。
        """
        return self.level.is_fail_closed_level
