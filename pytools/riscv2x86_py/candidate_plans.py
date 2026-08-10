from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Tuple
from .source_model import SourceSemanticModel

from .plan_types import (
    PlanPriorityTier,
    PlanRequirement,
    TargetLoweringFamily,
    TargetLoweringKind,
    TargetLoweringPlan,
)


@dataclass(frozen=True)
class Phase6BCandidateFacts:
    """
    Phase 6B candidate generation 所需的、已经由 SourceSemanticModel
    归纳完成的语义事实。

    重要边界：

      * 本对象不保存 rendered asm、GNU asm constraint 或 proof result；
      * 本对象不是 Phase 6D approval result；
      * 所有 bool 均应来自 SourceSemanticModel 的 authoritative semantic
        analysis，而不是 candidate generator 的文本猜测；
      * 不确定状态必须显式编码为 False / unknown 对应字段，而不是默认
        乐观地视为安全。

    SourceSemanticModel 可通过属性：

        source_model.phase6b_candidate_facts

    暴露本对象。
    """

    # ------------------------------------------------------------------
    # 全局模型状态与 fail-closed 状态。
    # ------------------------------------------------------------------

    # SourceSemanticModel 是否已完成并通过 Phase 6B 所依赖的一致性检查。
    model_is_consistent: bool

    # 是否存在明确要求 Phase 6B 不生成任何 candidate 的全局状态。
    has_global_fail_closed_state: bool

    # 是否存在 opaque / unmodelled / parser-recovery / ambiguous semantics。
    has_opaque_semantics: bool
    has_unmodelled_semantics: bool

    # Source-level operand binding、operand width、memory effect 等是否完整。
    operand_bindings_are_authoritative: bool
    operand_widths_are_authoritative: bool

    # ------------------------------------------------------------------
    # Target / microarchitecture 分类。
    # ------------------------------------------------------------------

    # 当前 candidate generation 是否允许产生 x86-specific plan。
    target_is_x86: bool

    # microarchitecture 分类是否已知。False 表示 unknown microarch。
    microarch_classification_is_known: bool

    # 当前 source asm 是否具有 microarchitecture-sensitive intent。
    has_microarch_sensitive_semantics: bool

    # ------------------------------------------------------------------
    # ABI、stack、frame。
    # ------------------------------------------------------------------

    has_stack_sensitive_semantics: bool
    has_frame_sensitive_semantics: bool

    # ------------------------------------------------------------------
    # CFG、call、return、branch、asm-goto。
    # ------------------------------------------------------------------

    has_control_flow_semantics: bool
    has_asm_goto_semantics: bool
    has_call_semantics: bool
    has_return_semantics: bool
    has_branch_semantics: bool

    # ------------------------------------------------------------------
    # Atomic、barrier、memory。
    # ------------------------------------------------------------------

    has_atomic_semantics: bool
    has_barrier_semantics: bool

    # 非 atomic 的 memory read / write / memory clobber effect。
    has_non_atomic_memory_semantics: bool

    # ------------------------------------------------------------------
    # Shell 分类。
    # ------------------------------------------------------------------

    # source asm shell / dialect classification 是否确定。
    shell_semantics_are_known: bool

    # True 代表 candidate 可将 source 视为 shell-neutral。
    #
    # shell_semantics_are_known 为 False 时，本值必须为 False。
    is_shell_neutral: bool

    # ------------------------------------------------------------------
    # C lowering eligibility。
    # ------------------------------------------------------------------

    # source-level C semantics 是否可被证明为 defined C semantics。
    c_semantics_are_defined: bool

    # 该 source 是否已经被 SemanticModel 判定为可表达为 pure C expression。
    #
    # 即使此项为 True，candidate plan 仍只表达“候选”；Phase 6D 必须继续
    # 验证实际 operand binding、width、side effect 和 ordering。
    c_expression_eligible: bool

    # 是否可表达为 structured C statement/block。
    c_structured_eligible: bool

    def __post_init__(self) -> None:
        for field_name, value in self.__dict__.items():
            if not isinstance(value, bool):
                raise TypeError(
                    "Phase6BCandidateFacts."
                    f"{field_name} must be bool, got "
                    f"{type(value).__name__}"
                )

        if (
            not self.shell_semantics_are_known
            and self.is_shell_neutral
        ):
            raise ValueError(
                "is_shell_neutral cannot be True when "
                "shell_semantics_are_known is False"
            )

        if (
            self.c_expression_eligible
            and not self.c_semantics_are_defined
        ):
            raise ValueError(
                "c_expression_eligible requires "
                "c_semantics_are_defined"
            )

        if (
            self.c_expression_eligible
            and not self.is_shell_neutral
        ):
            raise ValueError(
                "c_expression_eligible requires shell-neutral semantics"
            )

    @property
    def requires_microarch_specialization(self) -> bool:
        """
        unknown microarch 与明确 microarch-sensitive intent 都不能落入
        generic C-expression / generic register-only 路径。
        """
        return (
            not self.microarch_classification_is_known
            or self.has_microarch_sensitive_semantics
        )

    @property
    def is_stack_or_frame_sensitive(self) -> bool:
        return (
            self.has_stack_sensitive_semantics
            or self.has_frame_sensitive_semantics
        )

    @property
    def requires_control_flow_lowering(self) -> bool:
        return any(
            (
                self.has_control_flow_semantics,
                self.has_asm_goto_semantics,
                self.has_call_semantics,
                self.has_return_semantics,
                self.has_branch_semantics,
            )
        )



def _facts_from(
    source_model: SourceSemanticModel,
) -> Phase6BCandidateFacts:
    """
    不从 raw asm text、mnemonic 或 GNU asm template 推测语义。

    Phase 6B 只消费 SourceSemanticModel 已经归纳出的 authoritative facts。
    缺失事实是模型集成错误，不应被默默转换成乐观 candidate。
    """
    try:
        facts = source_model.phase6b_candidate_facts
    except AttributeError as exc:
        raise TypeError(
            "SourceSemanticModel must expose "
            "phase6b_candidate_facts: Phase6BCandidateFacts"
        ) from exc

    if not isinstance(facts, Phase6BCandidateFacts):
        raise TypeError(
            "source_model.phase6b_candidate_facts must be "
            "Phase6BCandidateFacts, got "
            f"{type(facts).__name__}"
        )

    return facts


def _has_global_fail_closed_state(
    facts: Phase6BCandidateFacts,
) -> bool:
    """
    这些状态下返回空 tuple，而不是猜测性地生成 UNSUPPORTED 以外的 plan。

    空 candidate set 的含义是：Phase 6B 尚不具备安全生成任何 lowering
    candidate 的前提。调用方应保留 source、报告诊断，或进入项目定义的
    fail-closed fallback。
    """
    return any(
        (
            not facts.model_is_consistent,
            facts.has_global_fail_closed_state,
            facts.has_opaque_semantics,
            facts.has_unmodelled_semantics,
            not facts.operand_bindings_are_authoritative,
            not facts.operand_widths_are_authoritative,
            not facts.shell_semantics_are_known,
        )
    )


def _plan(
    *,
    plan_id: str,
    kind: TargetLoweringKind,
    family: TargetLoweringFamily,
    priority_tier: PlanPriorityTier,
    deterministic_rank: int,
    required_features: frozenset[str] = frozenset(),
    requirements: frozenset[PlanRequirement] = frozenset(),
    metadata: Mapping[str, object] | None = None,
    rationale: Tuple[str, ...] = (),
    reason_codes: Tuple[str, ...] = (),
) -> TargetLoweringPlan:
    """
    Phase 6B plan construction 的唯一入口。

    注意 metadata 仅保存 structured semantic strategy data，绝不保存：

      * asm template / mnemonic / rendered C 或 asm；
      * GNU asm outputs / inputs / clobbers；
      * target constraints；
      * register allocation；
      * approval / proof result。
    """
    return TargetLoweringPlan(
        plan_id=plan_id,
        kind=kind,
        family=family,
        priority_tier=priority_tier,
        deterministic_rank=deterministic_rank,
        required_features=required_features,
        requirements=requirements,
        metadata={} if metadata is None else metadata,
        rationale=rationale,
        reason_codes=reason_codes,
    )


def _unsupported_candidate(
    *,
    reason_code: str,
    rationale: str,
) -> TargetLoweringPlan:
    """
    用于“模型已知但当前 Phase 6B 没有安全 lowering family”的情形。

    这不是 approved plan，也不应被 Phase 6E 当作可选最终 lowering。
    """
    return _plan(
        plan_id=f"unsupported.{reason_code}",
        kind=TargetLoweringKind.UNSUPPORTED,
        family=TargetLoweringFamily.UNSUPPORTED,
        priority_tier=PlanPriorityTier.UNSUPPORTED,
        deterministic_rank=0,
        metadata={
            "unsupported_category": reason_code,
        },
        rationale=(rationale,),
        reason_codes=(reason_code,),
    )


def _x86_requirements(
    *,
    preserve_memory: bool = False,
    preserve_cc: bool = False,
    preserve_microarch: bool = False,
) -> frozenset[PlanRequirement]:
    requirements = {
        PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,
        PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS,
        PlanRequirement.PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY,
    }

    if preserve_memory:
        requirements.add(PlanRequirement.PRESERVE_MEMORY_CLOBBER)

    if preserve_cc:
        requirements.add(PlanRequirement.PRESERVE_CC_CLOBBER)

    if preserve_microarch:
        requirements.add(PlanRequirement.PRESERVE_MICROARCH_INTENT)

    return frozenset(requirements)


def _generate_microarch_candidates(
    facts: Phase6BCandidateFacts,
) -> list[TargetLoweringPlan]:
    """
    microarch-sensitive 或 unknown-microarch source 不得生成 generic C plan。

    当前 TargetLoweringPlan 的 PlanRequirement 尚未提供专门的
    PRESERVE_ASM_SHELL_SEMANTICS requirement，因此 shell-aware source 不在
    此处猜测性 lower；shell-neutral 的 microarch-sensitive source 仅生成
    target-specific candidate，交给 6C/6D 推导约束与证明。
    """
    if not facts.target_is_x86:
        return [
            _unsupported_candidate(
                reason_code="microarch-specialization-non-x86",
                rationale=(
                    "Microarchitecture-sensitive or unknown-microarchitecture "
                    "semantics require a target-specific lowering family."
                ),
            )
        ]

    return [
        _plan(
            plan_id="x86.microarch.specialized-inline-asm",
            kind=TargetLoweringKind.X86_GNU_INLINE_ASM,
            family=TargetLoweringFamily.X86_INLINE_ASM,
            priority_tier=PlanPriorityTier.X86_INLINE_ASM,
            deterministic_rank=10,
            required_features=frozenset({"target:x86"}),
            requirements=_x86_requirements(
                preserve_memory=facts.has_non_atomic_memory_semantics,
                preserve_cc=True,
                preserve_microarch=True,
            ),
            metadata={
                "strategy": "microarch_specialized",
                "microarch_classification_known": (
                    facts.microarch_classification_is_known
                ),
            },
            rationale=(
                "Generic C lowering is excluded because source semantics "
                "carry microarchitecture-sensitive intent or the "
                "microarchitecture classification is unknown.",
            ),
            reason_codes=("microarch-specialization-required",),
        )
    ]


def _generate_abi_aware_candidates(
    facts: Phase6BCandidateFacts,
) -> list[TargetLoweringPlan]:
    """
    stack/frame-sensitive source 不允许落回 generic register-only lowering。
    """
    return [
        _plan(
            plan_id="helper.abi-aware-stack-frame",
            kind=TargetLoweringKind.HELPER_CALL,
            family=TargetLoweringFamily.HELPER,
            priority_tier=PlanPriorityTier.HELPER,
            deterministic_rank=10,
            requirements=frozenset(
                {
                    PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,
                    PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS,
                    PlanRequirement.PRESERVE_STACK_FRAME,
                    PlanRequirement.PROVE_HELPER_ABI_CONTRACT,
                    PlanRequirement.PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY,
                }
            ),
            metadata={
                "strategy": "abi_aware_helper",
                "stack_sensitive": facts.has_stack_sensitive_semantics,
                "frame_sensitive": facts.has_frame_sensitive_semantics,
            },
            rationale=(
                "Stack/frame-sensitive semantics require an explicit helper "
                "ABI contract and may not be lowered through generic C or "
                "generic register-only inline asm paths.",
            ),
            reason_codes=("stack-or-frame-sensitive",),
        )
    ]


def _generate_cfg_candidates(
    facts: Phase6BCandidateFacts,
) -> list[TargetLoweringPlan]:
    requirements = {
        PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,
        PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS,
        PlanRequirement.PRESERVE_CONTROL_FLOW,
    }

    if facts.has_asm_goto_semantics:
        requirements.add(PlanRequirement.PRESERVE_ASM_GOTO)

    return [
        _plan(
            plan_id="structured.control-flow",
            kind=TargetLoweringKind.STRUCTURED_CONTROL_FLOW,
            family=TargetLoweringFamily.STRUCTURED_CFG,
            priority_tier=PlanPriorityTier.STRUCTURED_CFG,
            deterministic_rank=10,
            requirements=frozenset(requirements),
            metadata={
                "strategy": "structured_control_flow",
                "has_asm_goto": facts.has_asm_goto_semantics,
                "has_call": facts.has_call_semantics,
                "has_return": facts.has_return_semantics,
                "has_branch": facts.has_branch_semantics,
            },
            rationale=(
                "Control-flow-bearing semantics require a structured CFG "
                "lowering and cannot fall through to generic expression, "
                "memory, or register-only generators.",
            ),
            reason_codes=("control-flow-lowering-required",),
        ),
        _plan(
            plan_id="helper.control-flow-contract",
            kind=TargetLoweringKind.HELPER_CALL,
            family=TargetLoweringFamily.HELPER,
            priority_tier=PlanPriorityTier.HELPER,
            deterministic_rank=20,
            requirements=frozenset(
                {
                    *requirements,
                    PlanRequirement.PROVE_HELPER_ABI_CONTRACT,
                }
            ),
            metadata={
                "strategy": "control_flow_helper",
                "has_asm_goto": facts.has_asm_goto_semantics,
            },
            rationale=(
                "A helper candidate is retained only as an ABI- and "
                "control-flow-proof-obligated alternative.",
            ),
            reason_codes=("control-flow-helper-candidate",),
        ),
    ]


def _generate_atomic_candidates(
    facts: Phase6BCandidateFacts,
) -> list[TargetLoweringPlan]:
    candidates = [
        _plan(
            plan_id="c-builtin.atomic",
            kind=TargetLoweringKind.C_BUILTIN,
            family=TargetLoweringFamily.C_BUILTIN,
            priority_tier=PlanPriorityTier.C_BUILTIN,
            deterministic_rank=10,
            required_features=frozenset({"compiler:atomic-builtin"}),
            requirements=frozenset(
                {
                    PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,
                    PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS,
                    PlanRequirement.PRESERVE_ATOMIC_ORDERING,
                    PlanRequirement.PRESERVE_MEMORY_ORDERING,
                    PlanRequirement.PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY,
                    PlanRequirement.PROVE_DEFINED_C_SEMANTICS,
                }
            ),
            metadata={
                "strategy": "compiler_atomic_builtin",
            },
            rationale=(
                "Atomic semantics require preservation of atomic and memory "
                "ordering; this candidate is not an approval of any "
                "particular builtin spelling.",
            ),
            reason_codes=("atomic-lowering-required",),
        )
    ]

    if facts.target_is_x86:
        candidates.append(
            _plan(
                plan_id="x86.atomic",
                kind=TargetLoweringKind.X86_ATOMIC,
                family=TargetLoweringFamily.X86_ATOMIC,
                priority_tier=PlanPriorityTier.X86_ATOMIC_OR_BARRIER,
                deterministic_rank=20,
                required_features=frozenset({"target:x86"}),
                requirements=frozenset(
                    {
                        *_x86_requirements(
                            preserve_memory=True,
                            preserve_cc=True,
                        ),
                        PlanRequirement.PRESERVE_ATOMIC_ORDERING,
                        PlanRequirement.PRESERVE_MEMORY_ORDERING,
                    }
                ),
                metadata={
                    "strategy": "x86_atomic",
                },
                rationale=(
                    "Target-specific atomic lowering remains subject to "
                    "Phase 6C constraints and Phase 6D ordering proof.",
                ),
                reason_codes=("x86-atomic-candidate",),
            )
        )

    return candidates


def _generate_barrier_candidates(
    facts: Phase6BCandidateFacts,
) -> list[TargetLoweringPlan]:
    candidates = [
        _plan(
            plan_id="c-builtin.barrier",
            kind=TargetLoweringKind.C_BUILTIN,
            family=TargetLoweringFamily.C_BUILTIN,
            priority_tier=PlanPriorityTier.C_BUILTIN,
            deterministic_rank=20,
            required_features=frozenset({"compiler:barrier-builtin"}),
            requirements=frozenset(
                {
                    PlanRequirement.PRESERVE_MEMORY_ORDERING,
                    PlanRequirement.PROVE_DEFINED_C_SEMANTICS,
                }
            ),
            metadata={
                "strategy": "compiler_barrier_builtin",
            },
            rationale=(
                "Barrier semantics require preservation of ordering and may "
                "not be reduced to an ordinary C expression.",
            ),
            reason_codes=("barrier-lowering-required",),
        )
    ]

    if facts.target_is_x86:
        candidates.append(
            _plan(
                plan_id="x86.barrier",
                kind=TargetLoweringKind.X86_BARRIER,
                family=TargetLoweringFamily.X86_BARRIER,
                priority_tier=PlanPriorityTier.X86_ATOMIC_OR_BARRIER,
                deterministic_rank=30,
                required_features=frozenset({"target:x86"}),
                requirements=frozenset(
                    {
                        *_x86_requirements(
                            preserve_memory=True,
                            preserve_cc=True,
                        ),
                        PlanRequirement.PRESERVE_MEMORY_ORDERING,
                    }
                ),
                metadata={
                    "strategy": "x86_barrier",
                },
                rationale=(
                    "Target-specific barrier lowering remains subject to "
                    "Phase 6C constraints and Phase 6D ordering proof.",
                ),
                reason_codes=("x86-barrier-candidate",),
            )
        )

    return candidates


def _generate_memory_candidates(
    facts: Phase6BCandidateFacts,
) -> list[TargetLoweringPlan]:
    candidates: list[TargetLoweringPlan] = []

    if facts.c_structured_eligible and facts.c_semantics_are_defined:
        candidates.append(
            _plan(
                plan_id="c-structured.memory",
                kind=TargetLoweringKind.C_STRUCTURED,
                family=TargetLoweringFamily.PURE_C,
                priority_tier=PlanPriorityTier.PURE_C,
                deterministic_rank=20,
                requirements=frozenset(
                    {
                        PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,
                        PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS,
                        PlanRequirement.PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY,
                        PlanRequirement.PROVE_DEFINED_C_SEMANTICS,
                    }
                ),
                metadata={
                    "strategy": "structured_c_memory",
                },
                rationale=(
                    "Non-atomic memory semantics may use structured C only "
                    "when SourceSemanticModel has established defined C "
                    "semantics.",
                ),
                reason_codes=("structured-memory-candidate",),
            )
        )

    if facts.target_is_x86:
        candidates.append(
            _plan(
                plan_id="x86.memory-inline-asm",
                kind=TargetLoweringKind.X86_GNU_INLINE_ASM,
                family=TargetLoweringFamily.X86_INLINE_ASM,
                priority_tier=PlanPriorityTier.X86_INLINE_ASM,
                deterministic_rank=30,
                required_features=frozenset({"target:x86"}),
                requirements=_x86_requirements(
                    preserve_memory=True,
                    preserve_cc=True,
                ),
                metadata={
                    "strategy": "x86_memory_inline_asm",
                },
                rationale=(
                    "Memory semantics require Phase 6C derivation of memory "
                    "effects and Phase 6D proof of observable behavior.",
                ),
                reason_codes=("memory-inline-asm-candidate",),
            )
        )

    if not candidates:
        candidates.append(
            _unsupported_candidate(
                reason_code="memory-no-safe-family",
                rationale=(
                    "Memory semantics exist, but neither structured C nor a "
                    "supported target-specific candidate family is available."
                ),
            )
        )

    return candidates


def _generate_register_only_candidates(
    facts: Phase6BCandidateFacts,
) -> list[TargetLoweringPlan]:
    candidates: list[TargetLoweringPlan] = []

    # C_EXPRESSION 只能在所有普通路径条件均已满足时产生。
    if (
        facts.is_shell_neutral
        and facts.c_expression_eligible
        and facts.c_semantics_are_defined
    ):
        candidates.append(
            _plan(
                plan_id="c-expression.register-only",
                kind=TargetLoweringKind.C_EXPRESSION,
                family=TargetLoweringFamily.PURE_C,
                priority_tier=PlanPriorityTier.PURE_C,
                deterministic_rank=10,
                requirements=frozenset(
                    {
                        PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,
                        PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS,
                        PlanRequirement.PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY,
                        PlanRequirement.PROVE_DEFINED_C_SEMANTICS,
                    }
                ),
                metadata={
                    "strategy": "pure_c_expression",
                    "shell_neutral": True,
                },
                rationale=(
                    "Pure C expression is considered only for shell-neutral, "
                    "register-only, defined-C semantics.",
                ),
                reason_codes=("pure-c-expression-candidate",),
            )
        )

    if facts.target_is_x86:
        candidates.append(
            _plan(
                plan_id="x86.register-only-inline-asm",
                kind=TargetLoweringKind.X86_GNU_INLINE_ASM,
                family=TargetLoweringFamily.X86_INLINE_ASM,
                priority_tier=PlanPriorityTier.X86_INLINE_ASM,
                deterministic_rank=40,
                required_features=frozenset({"target:x86"}),
                requirements=_x86_requirements(preserve_cc=True),
                metadata={
                    "strategy": "x86_register_only_inline_asm",
                    "renderer_semantic_contract_id": "x86.gnu-att.gpr.rw-binary.v1",
                },
                rationale=(
                    "Register-only x86 inline asm remains a candidate until "
                    "constraints and semantic equivalence are proven."
                ),
                reason_codes=("x86-register-only-candidate",),
            )
        )

    if not candidates:
        candidates.append(
            _unsupported_candidate(
                reason_code="register-only-no-safe-family",
                rationale=(
                    "No pure-C eligibility and no supported target-specific "
                    "register-only lowering family are available."
                ),
            )
        )

    return candidates


def _stable_sort_and_freeze(
    candidates: list[TargetLoweringPlan],
) -> tuple[TargetLoweringPlan, ...]:
    """
    按 plan_id 去重，并使用 TargetLoweringPlan.sort_key 做稳定排序。

    同一 plan_id 若对应不同 plan content，说明 generator 内部产生了不一致
    candidate；这必须是实现错误，而不是静默地选择其中一个。
    """
    by_plan_id: dict[str, TargetLoweringPlan] = {}

    for candidate in candidates:
        previous = by_plan_id.get(candidate.plan_id)

        if previous is None:
            by_plan_id[candidate.plan_id] = candidate
            continue

        if previous != candidate:
            raise ValueError(
                "Conflicting Phase 6B candidates share plan_id "
                f"{candidate.plan_id!r}"
            )

    return tuple(
        sorted(
            by_plan_id.values(),
            key=lambda candidate: candidate.sort_key,
        )
    )


def generate_candidate_plans(
    source_model: SourceSemanticModel,
) -> tuple[TargetLoweringPlan, ...]:
    """
    生成 Phase 6B candidate target-lowering plans。

    本函数的输出只是候选集，不是最终 lowering selection：

      Phase 6B:
          generate_candidate_plans()

      Phase 6C:
          derive target constraints for each candidate

      Phase 6D:
          prove source semantics == target lowering semantics

      Phase 6E:
          sort/select only approved candidates

    高风险路径采用优先分派和早返回，保证 generic generator 不会把不安全的
    C_EXPRESSION 或 register-only candidate 重新加入候选集。
    """
    facts = _facts_from(source_model)

    # 1. 验证 SourceSemanticModel 依赖状态一致性；
    # 2. 全局 fail-closed gate。
    if _has_global_fail_closed_state(facts):
        return ()

    # shell-aware source 在当前 PlanRequirement 模型中没有专用
    # PRESERVE_ASM_SHELL_SEMANTICS obligation，因此显式 fail closed。
    #
    # 若后续扩展 PlanRequirement 并实现 shell-aware Phase 6C/6D proof，
    # 可在此处增加专用 shell-aware x86 candidate generator。
    if not facts.is_shell_neutral:
        return _stable_sort_and_freeze(
            [
                _unsupported_candidate(
                    reason_code="shell-aware-lowering-unavailable",
                    rationale=(
                        "Source semantics are shell-aware; no shell-aware "
                        "proof obligation exists in the current candidate "
                        "plan contract, so generic lowering is forbidden."
                    ),
                )
            ]
        )

    # 3. microarch-sensitive / unknown-microarch。
    if facts.requires_microarch_specialization:
        return _stable_sort_and_freeze(
            _generate_microarch_candidates(facts)
        )

    # 4. stack/frame-sensitive。
    if facts.is_stack_or_frame_sensitive:
        return _stable_sort_and_freeze(
            _generate_abi_aware_candidates(facts)
        )

    # 5. CFG / asm-goto / call / return / branch。
    if facts.requires_control_flow_lowering:
        return _stable_sort_and_freeze(
            _generate_cfg_candidates(facts)
        )

    # 6. atomic / barrier。
    #
    # atomic 优先于 barrier：atomic semantics 通常携带比普通 barrier 更强的
    # ordering 与 read-modify-write proof obligation。
    if facts.has_atomic_semantics:
        return _stable_sort_and_freeze(
            _generate_atomic_candidates(facts)
        )

    if facts.has_barrier_semantics:
        return _stable_sort_and_freeze(
            _generate_barrier_candidates(facts)
        )

    # 7. 普通 non-atomic memory read/write。
    if facts.has_non_atomic_memory_semantics:
        return _stable_sort_and_freeze(
            _generate_memory_candidates(facts)
        )

    # 8/9/10. shell-neutral register-only normal path。
    return _stable_sort_and_freeze(
        _generate_register_only_candidates(facts)
    )
