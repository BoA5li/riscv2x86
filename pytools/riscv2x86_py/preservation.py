from __future__ import annotations

from collections.abc import Set as AbstractSet, Sequence

from .semantic_types import (
    PreservationDecision,
    PreservationLevel,
    SemanticFeature,
)


# ---------------------------------------------------------------------------
# Preservation-level feature taxonomy
# ---------------------------------------------------------------------------
#
# preservation.py 只根据 SourceSemanticModel 已收集的 feature 进行分类。
#
# 它不得重新读取：
#   * IRSummary
#   * Block[]
#   * CFGResult
#   * AsmFragment
#   * TranslationRuntimeFacts
#
# 新增 SemanticFeature 时必须显式加入以下某一分类：
#
#   * _D_FEATURES
#   * _C_FEATURES
#   * _B_FEATURES
#   * _A_FEATURES
#   * _PLAN_GATING_FEATURES
#
# 如果遗漏分类，derive_preservation_decision() 必须 fail-closed，
# 将该 feature 视为 D 级风险，而不能默认落入 A。
#
# 注意：
#
# _PLAN_GATING_FEATURES 表示 runtime facts、operand binding、operand width
# 等候选计划生成与 proof gate 所需的事实状态。
#
# 它们默认不改变 source semantic preservation level；后续 CandidatePlan /
# target constraint / proof gate 必须根据这些 feature reject、defer，或禁止
# 依赖相应 runtime fact 的 target lowering。
# ---------------------------------------------------------------------------


_D_FEATURES = frozenset(
    {
        # -------------------------------------------------------------------
        # Microarchitecture-sensitive and experimental-intent semantics.
        # -------------------------------------------------------------------
        SemanticFeature.MICROARCH_SENSITIVE,
        SemanticFeature.TIMING_SOURCE,
        SemanticFeature.CACHE_OPERATION,
        SemanticFeature.SPECULATION_CONTROL,
        SemanticFeature.EXPERIMENT_RETRY_LOOP,

        # -------------------------------------------------------------------
        # Ordering / synchronization / atomic semantics.
        #
        # 在具备经过 semantic proof 的 atomic/fence/barrier target plan 前，
        # 不允许这些 feature 静默落入 legacy Level-A generic lowering。
        # -------------------------------------------------------------------
        SemanticFeature.MEMORY_BARRIER,
        SemanticFeature.INSTRUCTION_BARRIER,
        SemanticFeature.UNKNOWN_BARRIER,
        SemanticFeature.ATOMIC_OPERATION,
        SemanticFeature.INCOMPLETE_SEMANTIC_SUMMARY,

        # Privileged state always requires a dedicated target environment or
        # runtime contract.  A functional-fallback possibility is tracked
        # separately and never weakens this strict preservation route.
        SemanticFeature.PRIVILEGED_STATE,
        SemanticFeature.CSR_ACCESS,
        SemanticFeature.READ_ONLY_COUNTER_CSR,
        SemanticFeature.PRIVILEGED_TRAP,
        SemanticFeature.PRIVILEGE_RETURN,
        SemanticFeature.INTERRUPT_STATE,
        SemanticFeature.ADDRESS_TRANSLATION_STATE,
        SemanticFeature.VIRTUALIZATION_STATE,
        SemanticFeature.DEBUG_STATE,
        SemanticFeature.PRIVILEGED_STATE_INCOMPLETE,
        SemanticFeature.FUNCTIONAL_OBSERVABILITY_INCOMPLETE,

        # -------------------------------------------------------------------
        # Analysis or semantic-summary incompleteness that prevents safe
        # generic semantic preservation.
        # -------------------------------------------------------------------
        SemanticFeature.UNRESOLVED_REGISTER_IDENTITY,
        SemanticFeature.UNKNOWN_PCODE,

        # Source-model collection records every incomplete summary with the
        # single, versioned INCOMPLETE_SEMANTIC_SUMMARY feature.  The
        # detailed field remains in its stable reason code; it must not be
        # represented by stale, non-existent enum variants here.
    }
)


_C_FEATURES = frozenset(
    {
        # -------------------------------------------------------------------
        # Structured and non-structured control-flow semantics.
        #
        # These features require CFG-aware target planning and control-flow
        # reconstruction.  They must not be treated as plain expression-level
        # semantics.
        # -------------------------------------------------------------------
        SemanticFeature.INTERNAL_BRANCH,
        SemanticFeature.CALL_OR_RETURN,
        SemanticFeature.RETURN,
        SemanticFeature.TAIL_CALL,

        SemanticFeature.INDIRECT_CONTROL_FLOW,
        SemanticFeature.UNKNOWN_CONTROL_FLOW_TARGET,

        SemanticFeature.ASM_GOTO,
        SemanticFeature.EXTERNAL_CONTROL_FLOW,
        SemanticFeature.MULTIPLE_EXITS,
        SemanticFeature.NON_LOCAL_CONTROL_DEPENDENCY,
        SemanticFeature.CFG_INCOMPLETE,

        # A local label by itself represents control-flow structure and should
        # remain visible to CFG-aware planning.  ASM_GOTO and branch-related
        # features will naturally take the same C route.
        SemanticFeature.LOCAL_LABEL,
    }
)


_B_FEATURES = frozenset(
    {
        SemanticFeature.STACK_POINTER_ACCESS,
        SemanticFeature.FRAME_POINTER_ACCESS,
        SemanticFeature.STACK_LAYOUT,

        SemanticFeature.INLINE_ASM,
        SemanticFeature.VOLATILE_ASM,

        SemanticFeature.ASM_OPERANDS,
        SemanticFeature.ASM_INPUT_OPERAND,
        SemanticFeature.ASM_OUTPUT_OPERAND,
        SemanticFeature.ASM_OPERAND_CONSTRAINT,

        SemanticFeature.ASM_CLOBBER,
        SemanticFeature.MEMORY_CLOBBER,
        SemanticFeature.CONDITION_CODE_CLOBBER,

        SemanticFeature.EARLY_CLOBBER,
        SemanticFeature.TIED_OPERANDS,

        SemanticFeature.OPERAND_BINDING_METADATA,
        SemanticFeature.EXPLICIT_OPERAND_BINDING,
        SemanticFeature.MATERIALIZED_OPERAND_BINDING,
        SemanticFeature.PROVEN_OPERAND_WIDTH,
    }
)


_A_FEATURES = frozenset(
    {
        # -------------------------------------------------------------------
        # Ordinary architectural data semantics.
        #
        # A-level does not mean "automatically safe to lower".
        # It only means no B/C/D preservation routing feature was detected.
        # Candidate generation and semantic proof remain mandatory.
        # -------------------------------------------------------------------
        SemanticFeature.INTEGER,
        SemanticFeature.MEMORY_READ,
        SemanticFeature.MEMORY_WRITE,

        # PROVEN_OPERAND_WIDTH is a positive proof fact.  Its presence alone
        # must not elevate preservation routing.  Conversely, absence or
        # incompleteness is represented by INCOMPLETE_OPERAND_WIDTH in the
        # plan-gating feature set below.
        SemanticFeature.PROVEN_OPERAND_WIDTH,
    }
)


_PLAN_GATING_FEATURES = frozenset(
    {
        # -------------------------------------------------------------------
        # Runtime-fact availability and validity.
        #
        # These do not automatically alter source semantic preservation level.
        # They must be consumed by CandidatePlan generation, target constraint
        # derivation, and semantic proof gates.
        # -------------------------------------------------------------------
        SemanticFeature.RUNTIME_FACTS_UNAVAILABLE,
        SemanticFeature.INVALID_RUNTIME_FACTS,

        # -------------------------------------------------------------------
        # Operand binding / output binding / width proof completeness.
        #
        # These facts may reject or defer a candidate plan that relies on them,
        # but they are not by themselves a source-semantic D classification.
        # -------------------------------------------------------------------
        SemanticFeature.INCOMPLETE_OPERAND_BINDING,
        SemanticFeature.INCOMPLETE_OUTPUT_BINDING,
        SemanticFeature.INCOMPLETE_OPERAND_WIDTH,
        SemanticFeature.FUNCTIONAL_PRIVILEGED_FALLBACK_POSSIBLE,
        SemanticFeature.IGNORED_PRIVILEGED_STATE,
    }
)


_EXPLICITLY_CLASSIFIED_FEATURES = frozenset(
    _D_FEATURES
    | _C_FEATURES
    | _B_FEATURES
    | _A_FEATURES
    | _PLAN_GATING_FEATURES
)


def _feature_display_name(feature: object) -> str:
    """
    Return a deterministic diagnostic representation for a feature.

    The normal input is SemanticFeature.  The fallback representation keeps
    diagnostics useful even if an invalid object reaches this function.
    """
    if isinstance(feature, SemanticFeature):
        return feature.value

    return repr(feature)


def _unclassified_features(
    features: frozenset[SemanticFeature],
) -> frozenset[SemanticFeature]:
    """
    Return features which have not been assigned an explicit taxonomy class.

    Such features are treated as D-level risk by the caller.  This is
    intentional fail-closed behavior: adding a new semantic feature must not
    silently weaken preservation classification.
    """
    return frozenset(features - _EXPLICITLY_CLASSIFIED_FEATURES)


def derive_preservation_decision(
    *,
    features: AbstractSet[SemanticFeature],
    reasons: Sequence[str],
    reason_codes: Sequence[str],
) -> PreservationDecision:
    """
    Derive a coarse preservation classification from already-collected
    source semantic features.

    This is a pure Phase-6A classification step.  It must not inspect or
    reconstruct semantics from:

      * IRSummary;
      * Block[];
      * CFGResult;
      * AsmFragment;
      * TranslationRuntimeFacts;
      * raw assembly text;
      * mnemonics;
      * target-specific lowering details.

    Classification precedence:

        D > C > B > A

    Unknown or unclassified SemanticFeature values are fail-closed and force
    PreservationLevel.D.

    Runtime-fact and operand-binding incompleteness remain plan-gating facts.
    They do not independently alter preservation level unless a future,
    explicitly documented project policy changes that behavior.

    Important:
        PreservationLevel.A is not an approval to lower the fragment.
        Candidate-plan generation, target-constraint derivation, and semantic
        proof remain required in later Phase-6 stages.
    """
    normalized_features = frozenset(features)
    normalized_reasons = tuple(str(reason) for reason in reasons)
    normalized_reason_codes = tuple(str(code) for code in reason_codes)

    unclassified = _unclassified_features(normalized_features)

    if unclassified:
        feature_names = ", ".join(
            sorted(_feature_display_name(feature) for feature in unclassified)
        )

        normalized_reasons += (
            "unclassified semantic feature(s) require fail-closed "
            f"preservation handling: {feature_names}",
        )
        normalized_reason_codes += (
            "TR_UNCLASSIFIED_SEMANTIC_FEATURE",
        )

    if normalized_features & _D_FEATURES or unclassified:
        level = PreservationLevel.D
    elif normalized_features & _C_FEATURES:
        level = PreservationLevel.C
    elif normalized_features & _B_FEATURES:
        level = PreservationLevel.B
    else:
        # This covers:
        #
        #   * only _A_FEATURES;
        #   * only _PLAN_GATING_FEATURES;
        #   * no feature.
        #
        # In particular, runtime fact / binding / width incompleteness does
        # not itself raise preservation level.  CandidatePlan and proof gates
        # must still reject or defer plans that require unavailable facts.
        level = PreservationLevel.A

    return PreservationDecision(
        level=level,
        reasons=normalized_reasons,
        reason_codes=normalized_reason_codes,
        features=normalized_features,
    )
