from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, ClassVar, FrozenSet, Iterable, Mapping, Tuple


class TargetLoweringKind(str, Enum):
    """
    Phase 6B 产生的候选 target-lowering strategy。

    注意：
      * 这不是最终 rendered C / GNU asm text；
      * 这不是具体 x86 instruction；
      * 这不包含 target constraint、register allocation 或 proof result；
      * 它只表达某类可供后续 6C/6D 消费的 lowering 语义策略。
    """

    # 无需 target inline asm 的纯 C / structured expression replacement。
    C_EXPRESSION = "c_expression"

    # structured C statement / block replacement。
    C_STRUCTURED = "c_structured"

    # C compiler builtin / intrinsic replacement。
    C_BUILTIN = "c_builtin"

    # x86 GNU inline asm，普通 register / ALU / memory-capable lowering。
    X86_GNU_INLINE_ASM = "x86_gnu_inline_asm"

    # x86 atomic instruction 或受约束的 atomic inline asm lowering。
    X86_ATOMIC = "x86_atomic"

    # x86 fence / barrier-specific lowering。
    X86_BARRIER = "x86_barrier"

    # 需要 helper ABI contract 的 helper-call lowering。
    HELPER_CALL = "helper_call"

    # 对 structured multi-block CFG 的 future plan family。
    STRUCTURED_CONTROL_FLOW = "structured_control_flow"

    # Rebind a proven, non-escaping logical RISC-V stack access to an
    # authoritative C object.  This never means using the host stack.
    STACK_ADDRESS_REBINDING = "stack_address_rebinding"
    VIRTUAL_PRIVATE_FRAME = "virtual_private_frame"

    # 显式保留 unsupported，而不是猜测性 lower。
    UNSUPPORTED = "unsupported"


class TargetLoweringFamily(str, Enum):
    """
    用于候选预排序、proof policy routing 和诊断统计的粗粒度 family。
    """

    PURE_C = "pure_c"
    C_BUILTIN = "c_builtin"
    X86_INLINE_ASM = "x86_inline_asm"
    X86_ATOMIC = "x86_atomic"
    X86_BARRIER = "x86_barrier"
    HELPER = "helper"
    STRUCTURED_CFG = "structured_cfg"
    STACK_ADDRESS_REBINDING = "stack_address_rebinding"
    VIRTUAL_PRIVATE_FRAME = "virtual_private_frame"
    UNSUPPORTED = "unsupported"


class PlanPriorityTier(int, Enum):
    """
    只表达 Phase 6B candidate 的预排序 tier。

    最终选择必须在 Phase 6E 完成：

      1. Phase 6B 生成 candidate plans；
      2. Phase 6C 为每个 candidate 推导 target constraints；
      3. Phase 6D 对 candidate + constraints 执行 semantic proof；
      4. Phase 6E 仅在 approved candidates 中按固定 deterministic
         ordering 选择最终 plan。

    因此，本枚举不是 approval、proof 或 final-selection result。
    """

    PURE_C = 10
    C_BUILTIN = 20
    X86_INLINE_ASM = 30
    X86_ATOMIC_OR_BARRIER = 40
    HELPER = 50
    STRUCTURED_CFG = 60
    STACK_ADDRESS_REBINDING = 25
    VIRTUAL_PRIVATE_FRAME = 20
    UNSUPPORTED = 1000


class PlanRequirement(str, Enum):
    """
    Phase 6B 对后续 Phase 6C / 6D 提出的 requirement。

    这些 requirement：

      * 不是 GNU asm constraint；
      * 不是 target register allocation；
      * 不是 proof result；
      * 不是 candidate approval；
      * 只声明后续阶段必须推导、验证或保留的语义条件。
    """

    AUTHORITATIVE_OPERAND_BINDINGS = (
        "authoritative_operand_bindings"
    )
    AUTHORITATIVE_OPERAND_WIDTHS = (
        "authoritative_operand_widths"
    )

    PRESERVE_VOLATILE = "preserve_volatile"
    PRESERVE_MEMORY_CLOBBER = "preserve_memory_clobber"
    PRESERVE_CC_CLOBBER = "preserve_cc_clobber"

    PRESERVE_MEMORY_ORDERING = "preserve_memory_ordering"
    PRESERVE_ATOMIC_ORDERING = "preserve_atomic_ordering"
    PRESERVE_CONTROL_FLOW = "preserve_control_flow"
    PRESERVE_ASM_GOTO = "preserve_asm_goto"
    PRESERVE_STACK_FRAME = "preserve_stack_frame"
    AUTHORITATIVE_STACK_ACCESS_BINDINGS = "authoritative_stack_access_bindings"
    PRESERVE_STACK_LAYOUT = "preserve_stack_layout"
    PRESERVE_STACK_ALIGNMENT = "preserve_stack_alignment"
    PROVE_NO_STACK_ADDRESS_ESCAPE = "prove_no_stack_address_escape"
    PROVE_NO_HOST_STACK_POINTER_MUTATION = "prove_no_host_stack_pointer_mutation"
    PROVE_STACK_OBJECT_BOUNDS = "prove_stack_object_bounds"
    PROVE_STATIC_BALANCED_PRIVATE_FRAME = "prove_static_balanced_private_frame"
    PROVE_FRAME_LAYOUT_COMPLETE = "prove_frame_layout_complete"
    PROVE_FRAME_ACCESS_BOUNDS = "prove_frame_access_bounds"
    PROVE_PRIVATE_FRAME_INITIALIZATION = "prove_private_frame_initialization"
    PROVE_NO_REAL_STACK_IDENTITY = "prove_no_real_stack_identity"
    PROVE_NO_EXPLICIT_HOST_STACK_POINTER_MUTATION = "prove_no_explicit_host_stack_pointer_mutation"
    PROVE_PRIVATE_FRAME_VALUE_FLOW = "prove_private_frame_value_flow"
    PRESERVE_PRIVATE_FRAME_ALIGNMENT = "preserve_private_frame_alignment"

    PRESERVE_MICROARCH_INTENT = "preserve_microarch_intent"
    PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY = (
        "prove_source_target_width_compatibility"
    )
    PROVE_DEFINED_C_SEMANTICS = "prove_defined_c_semantics"
    PROVE_HELPER_ABI_CONTRACT = "prove_helper_abi_contract"


_KIND_TO_FAMILY: Mapping[
    TargetLoweringKind,
    TargetLoweringFamily,
] = MappingProxyType(
    {
        TargetLoweringKind.C_EXPRESSION:
            TargetLoweringFamily.PURE_C,
        TargetLoweringKind.C_STRUCTURED:
            TargetLoweringFamily.PURE_C,
        TargetLoweringKind.C_BUILTIN:
            TargetLoweringFamily.C_BUILTIN,
        TargetLoweringKind.X86_GNU_INLINE_ASM:
            TargetLoweringFamily.X86_INLINE_ASM,
        TargetLoweringKind.X86_ATOMIC:
            TargetLoweringFamily.X86_ATOMIC,
        TargetLoweringKind.X86_BARRIER:
            TargetLoweringFamily.X86_BARRIER,
        TargetLoweringKind.HELPER_CALL:
            TargetLoweringFamily.HELPER,
        TargetLoweringKind.STRUCTURED_CONTROL_FLOW:
            TargetLoweringFamily.STRUCTURED_CFG,
        TargetLoweringKind.STACK_ADDRESS_REBINDING:
            TargetLoweringFamily.STACK_ADDRESS_REBINDING,
        TargetLoweringKind.VIRTUAL_PRIVATE_FRAME:
            TargetLoweringFamily.VIRTUAL_PRIVATE_FRAME,
        TargetLoweringKind.UNSUPPORTED:
            TargetLoweringFamily.UNSUPPORTED,
    }
)

_FAMILY_TO_PRIORITY_TIER: Mapping[
    TargetLoweringFamily,
    PlanPriorityTier,
] = MappingProxyType(
    {
        TargetLoweringFamily.PURE_C:
            PlanPriorityTier.PURE_C,
        TargetLoweringFamily.C_BUILTIN:
            PlanPriorityTier.C_BUILTIN,
        TargetLoweringFamily.X86_INLINE_ASM:
            PlanPriorityTier.X86_INLINE_ASM,
        TargetLoweringFamily.X86_ATOMIC:
            PlanPriorityTier.X86_ATOMIC_OR_BARRIER,
        TargetLoweringFamily.X86_BARRIER:
            PlanPriorityTier.X86_ATOMIC_OR_BARRIER,
        TargetLoweringFamily.HELPER:
            PlanPriorityTier.HELPER,
        TargetLoweringFamily.STRUCTURED_CFG:
            PlanPriorityTier.STRUCTURED_CFG,
        TargetLoweringFamily.STACK_ADDRESS_REBINDING:
            PlanPriorityTier.STACK_ADDRESS_REBINDING,
        TargetLoweringFamily.VIRTUAL_PRIVATE_FRAME:
            PlanPriorityTier.VIRTUAL_PRIVATE_FRAME,
        TargetLoweringFamily.UNSUPPORTED:
            PlanPriorityTier.UNSUPPORTED,
    }
)

# 这些 key 代表不属于 Phase 6B plan 的内容。尤其是：
#
#   * target constraints 应由 Phase 6C 推导；
#   * approved / proof result 应由 Phase 6D 产生；
#   * asm template、mnemonic、instruction text 和 rendered text 不可被
#     偷渡进 Phase 6B metadata。
#
# metadata 是 plan-specific structured semantic metadata，不是后续阶段 DTO
# 的旁路存储位置。
_FORBIDDEN_METADATA_KEYS: FrozenSet[str] = frozenset(
    {
        "approved",
        "approval",
        "proof",
        "proof_result",
        "proofresult",
        "constraints",
        "constraint",
        "target_constraints",
        "targetconstraints",
        "gnu_asm_constraints",
        "gnuasmconstraints",
        "outputs",
        "inputs",
        "clobbers",
        "volatile",
        "asm_template",
        "asmtemplate",
        "template",
        "raw_asm",
        "rawasm",
        "raw_asm_text",
        "rawasmtext",
        "rendered_asm",
        "renderedasm",
        "rendered_text",
        "renderedtext",
        "mnemonic",
        "instruction",
        "instructions",
        "x86_code",
        "x86code",
        "register_allocation",
        "registerallocation",
        "target_register",
        "targetregister",
        "operand_constraints",
        "operandconstraints",
    }
)


def _normalized_metadata_key(key: str) -> str:
    """
    将 metadata key 规范化以检查 Phase 6B 边界。

    此规范化只用于拒绝明显不允许的字段；它不改变调用方原始 key，
    因而不会损失 plan-specific metadata 的语义。
    """
    return (
        key.strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def _require_non_string_iterable(
    value: Iterable[Any],
    *,
    field_name: str,
) -> Iterable[Any]:
    if isinstance(value, (str, bytes)):
        raise TypeError(
            f"{field_name} must be an iterable of values, not "
            f"{type(value).__name__}"
        )
    return value


def _normalize_string_set(
    value: Iterable[str],
    *,
    field_name: str,
) -> FrozenSet[str]:
    items = tuple(
        _require_non_string_iterable(value, field_name=field_name)
    )

    invalid = tuple(
        item
        for item in items
        if not isinstance(item, str)
        or not item.strip()
        or item != item.strip()
    )
    if invalid:
        raise TypeError(
            f"{field_name} must contain only non-empty stripped str values; "
            f"invalid values: {invalid!r}"
        )

    return frozenset(items)


def _normalize_requirements(
    value: Iterable[PlanRequirement],
) -> FrozenSet[PlanRequirement]:
    items = tuple(
        _require_non_string_iterable(
            value,
            field_name="TargetLoweringPlan.requirements",
        )
    )

    invalid = tuple(
        item
        for item in items
        if not isinstance(item, PlanRequirement)
    )
    if invalid:
        raise TypeError(
            "TargetLoweringPlan.requirements must contain only "
            "PlanRequirement values; "
            f"invalid values: {invalid!r}"
        )

    return frozenset(items)


def _normalize_string_tuple(
    value: Iterable[str],
    *,
    field_name: str,
) -> Tuple[str, ...]:
    items = tuple(
        _require_non_string_iterable(value, field_name=field_name)
    )

    invalid = tuple(
        item
        for item in items
        if not isinstance(item, str)
        or not item.strip()
        or item != item.strip()
    )
    if invalid:
        raise TypeError(
            f"{field_name} must contain only non-empty stripped str values; "
            f"invalid values: {invalid!r}"
        )

    return items


def _normalize_reason_codes(
    value: Iterable[str],
    *,
    field_name: str,
) -> Tuple[str, ...]:
    """Normalize stable plan diagnostic codes without using their messages."""
    return _normalize_string_tuple(value, field_name=field_name)


def _freeze_metadata_value(
    value: Any,
    *,
    path: str,
) -> Any:
    """
    将 metadata 深度冻结为只读 structured data。

    可接受的 metadata value 仅包括：

      * None；
      * bool / int / float / str；
      * tuple / list；
      * frozenset / set；
      * Mapping[str, ...]。

    这避免把可变业务对象、rendering object、constraint object 或
    proof-result object 存放到 Phase 6B candidate plan 中。
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}

        for key, nested_value in value.items():
            if (
                    not isinstance(key, str)
                    or not key.strip()
                    or key != key.strip()
                ):
                raise TypeError(
                    f"{path} mapping keys must be non-empty str values; "
                    f"got {key!r}"
                )

            normalized_key = _normalized_metadata_key(key)
            if normalized_key in _FORBIDDEN_METADATA_KEYS:
                raise ValueError(
                    f"{path}.{key} is not permitted in Phase 6B plan "
                    "metadata: target constraints, rendered asm/code, "
                    "register allocation, proof results, and approval "
                    "state belong to later phases"
                )

            normalized[key] = _freeze_metadata_value(
                nested_value,
                path=f"{path}.{key}",
            )

        return MappingProxyType(normalized)

    if isinstance(value, (tuple, list)):
        return tuple(
            _freeze_metadata_value(
                item,
                path=f"{path}[{index}]",
            )
            for index, item in enumerate(value)
        )

    if isinstance(value, (frozenset, set)):
        return frozenset(
            _freeze_metadata_value(
                item,
                path=f"{path}[]",
            )
            for item in value
        )

    raise TypeError(
        f"{path} contains unsupported metadata value of type "
        f"{type(value).__name__}; metadata must contain only immutable "
        "structured scalar, sequence, set, and mapping values"
    )


def _freeze_metadata(metadata: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(metadata, Mapping):
        raise TypeError(
            "TargetLoweringPlan.metadata must be a Mapping[str, object], "
            f"got {type(metadata).__name__}"
        )

    frozen = _freeze_metadata_value(
        metadata,
        path="TargetLoweringPlan.metadata",
    )

    # _freeze_metadata_value() returns MappingProxyType for Mapping input.
    assert isinstance(frozen, Mapping)
    return frozen


def _metadata_hashable(value: Any) -> Any:
    """
    构造 metadata 的 hashable immutable representation。

    TargetLoweringPlan 是 frozen DTO，且 metadata 被深度冻结；显式实现
    hash 可避免 MappingProxyType 本身不可 hash 的问题。
    """
    if isinstance(value, Mapping):
        return tuple(
            sorted(
                (
                    key,
                    _metadata_hashable(nested_value),
                )
                for key, nested_value in value.items()
            )
        )

    if isinstance(value, tuple):
        return tuple(_metadata_hashable(item) for item in value)

    if isinstance(value, frozenset):
        return frozenset(_metadata_hashable(item) for item in value)

    return value

@dataclass(frozen=True)
class TargetLoweringPlan:
    """
    Phase 6B candidate target-lowering plan。

    本对象只表达“可能采用的 lowering strategy”。它不包含：

      * GNU asm outputs / inputs / clobbers；
      * volatile 标记；
      * target constraints；
      * x86 register allocation；
      * GNU asm constraint text；
      * asm template、mnemonic 或 rendered C / asm text；
      * Phase 6D proof result；
      * approved / rejected 状态。

    正确的数据流必须是：

        candidate_plan = TargetLoweringPlan(...)

        constraints = derive_target_constraints(
            source_model=source_model,
            candidate_plan=candidate_plan,
        )

        proof = run_semantic_proof_gate(
            source_model=source_model,
            candidate_plan=candidate_plan,
            constraints=constraints,
        )

        if proof.approved:
            ...

    metadata 只允许存储 plan-specific 的 immutable structured semantic
    metadata，例如 builtin family、helper ABI identifier、atomic semantic
    mode 或 structured-C lowering shape。它不得成为保存 Phase 6C/6D/6F
    数据的旁路。
    """

    plan_id: str
    kind: TargetLoweringKind
    family: TargetLoweringFamily

    priority_tier: PlanPriorityTier
    deterministic_rank: int

    required_features: FrozenSet[str] = frozenset()
    forbidden_features: FrozenSet[str] = frozenset()

    requirements: FrozenSet[PlanRequirement] = frozenset()

    metadata: Mapping[str, object] = field(default_factory=dict)

    rationale: Tuple[str, ...] = ()
    reason_codes: Tuple[str, ...] = ()

    _KIND_TO_FAMILY: ClassVar[
        Mapping[TargetLoweringKind, TargetLoweringFamily]
    ] = _KIND_TO_FAMILY

    _FAMILY_TO_PRIORITY_TIER: ClassVar[
        Mapping[TargetLoweringFamily, PlanPriorityTier]
    ] = _FAMILY_TO_PRIORITY_TIER

    def __post_init__(self) -> None:
        if (
            not isinstance(self.plan_id, str)
            or not self.plan_id.strip()
            or self.plan_id != self.plan_id.strip()
        ):
            raise TypeError(
                "TargetLoweringPlan.plan_id must be a non-empty stripped str"
            )

        if not isinstance(self.kind, TargetLoweringKind):
            raise TypeError(
                "TargetLoweringPlan.kind must be a TargetLoweringKind, "
                f"got {type(self.kind).__name__}"
            )

        if not isinstance(self.family, TargetLoweringFamily):
            raise TypeError(
                "TargetLoweringPlan.family must be a TargetLoweringFamily, "
                f"got {type(self.family).__name__}"
            )

        if not isinstance(self.priority_tier, PlanPriorityTier):
            raise TypeError(
                "TargetLoweringPlan.priority_tier must be a PlanPriorityTier, "
                f"got {type(self.priority_tier).__name__}"
            )

        if (
            isinstance(self.deterministic_rank, bool)
            or not isinstance(self.deterministic_rank, int)
            or self.deterministic_rank < 0
        ):
            raise TypeError(
                "TargetLoweringPlan.deterministic_rank must be a "
                "non-negative int"
            )

        expected_family = self._KIND_TO_FAMILY[self.kind]
        if self.family is not expected_family:
            raise ValueError(
                "TargetLoweringPlan.kind/family mismatch: "
                f"kind {self.kind.value!r} requires family "
                f"{expected_family.value!r}, got {self.family.value!r}"
            )

        expected_tier = self._FAMILY_TO_PRIORITY_TIER[self.family]
        if self.priority_tier is not expected_tier:
            raise ValueError(
                "TargetLoweringPlan.family/priority_tier mismatch: "
                f"family {self.family.value!r} requires tier "
                f"{expected_tier.name!r}, got {self.priority_tier.name!r}"
            )

        normalized_required_features = _normalize_string_set(
            self.required_features,
            field_name="TargetLoweringPlan.required_features",
        )
        normalized_forbidden_features = _normalize_string_set(
            self.forbidden_features,
            field_name="TargetLoweringPlan.forbidden_features",
        )

        overlap = (
            normalized_required_features
            & normalized_forbidden_features
        )
        if overlap:
            raise ValueError(
                "TargetLoweringPlan.required_features and "
                "forbidden_features must be disjoint; "
                f"overlap: {tuple(sorted(overlap))!r}"
            )

        normalized_requirements = _normalize_requirements(
            self.requirements
        )
        frozen_metadata = _freeze_metadata(self.metadata)
        normalized_rationale = _normalize_string_tuple(
            self.rationale,
            field_name="TargetLoweringPlan.rationale",
        )
        normalized_reason_codes = _normalize_reason_codes(
            self.reason_codes,
            field_name="reason_codes",
        )

        object.__setattr__(
            self,
            "required_features",
            normalized_required_features,
        )
        object.__setattr__(
            self,
            "forbidden_features",
            normalized_forbidden_features,
        )
        object.__setattr__(
            self,
            "requirements",
            normalized_requirements,
        )
        object.__setattr__(
            self,
            "metadata",
            frozen_metadata,
        )
        object.__setattr__(
            self,
            "rationale",
            normalized_rationale,
        )
        object.__setattr__(
            self,
            "reason_codes",
            normalized_reason_codes,
        )

    @property
    def sort_key(self) -> Tuple[int, int, str]:
        """
        Phase 6E 可使用的稳定候选排序键。

        此排序键不代表 approved 状态。Phase 6E 必须先过滤掉未通过
        Phase 6D semantic proof 的 candidate，再使用该 key 选择结果。
        """
        return (
            int(self.priority_tier),
            self.deterministic_rank,
            self.plan_id,
        )

    @property
    def is_unsupported(self) -> bool:
        """
        是否为显式 unsupported candidate。

        UNSUPPORTED 仍是一个合法 Phase 6B candidate，用于 fail-closed
        diagnostics；它不表示任何 lowering 已获批准。
        """
        return self.kind is TargetLoweringKind.UNSUPPORTED

    def requires(
        self,
        requirement: PlanRequirement,
    ) -> bool:
        """
        返回该 candidate 是否声明了指定的后续 requirement。
        """
        if not isinstance(requirement, PlanRequirement):
            raise TypeError(
                "requirement must be a PlanRequirement, "
                f"got {type(requirement).__name__}"
            )
        return requirement in self.requirements

    def supports_features(
        self,
        available_features: Iterable[str],
    ) -> bool:
        """
        仅执行 candidate feature gate，不执行 semantic proof。

        返回 True 表示：

          * required_features 均存在；
          * forbidden_features 均不存在。

        返回 True 不等于该 plan 已被证明正确，更不等于 approved。
        """
        available = _normalize_string_set(
            available_features,
            field_name="available_features",
        )
        return (
            self.required_features <= available
            and not (self.forbidden_features & available)
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.plan_id,
                self.kind,
                self.family,
                self.priority_tier,
                self.deterministic_rank,
                self.required_features,
                self.forbidden_features,
                self.requirements,
                _metadata_hashable(self.metadata),
                self.rationale,
                self.reason_codes,
            )
        )
