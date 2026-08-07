from __future__ import annotations

from collections.abc import Iterable, Mapping as ABCMapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

try:
    from .runtime_facts import TranslationRuntimeFacts
except ImportError:  # pragma: no cover - direct-module compatibility
    from runtime_facts import TranslationRuntimeFacts


def _text(value: Any) -> str:
    """
    将边界值转换为稳定字符串。

    None -> ""
    其他值 -> str(value)
    """
    if value is None:
        return ""
    return str(value)


def _normalized_register_name(value: Any) -> str:
    """
    规范化 runtime fact 中的 RISC-V register key。

    这里只去除首尾空白，不做 lower() 或 ABI alias 自动转换。

    原因：
      * runtime facts 是 authoritative mapping；
      * "a0"、"x10"、某些上游自定义 register token 是否等价，
        不应由本模块擅自猜测；
      * register canonicalization 若有需要，应由产生
        TranslationRuntimeFacts 的 assembler normalization 阶段完成。
    """
    return _text(value).strip()


def _deduplicated_messages(messages: Iterable[str]) -> Tuple[str, ...]:
    """
    去重但保留错误出现顺序，便于稳定测试与日志输出。
    """
    seen: set[str] = set()
    result: list[str] = []

    for message in messages:
        if message not in seen:
            seen.add(message)
            result.append(message)

    return tuple(result)


def _is_valid_nonnegative_index(value: Any) -> bool:
    """
    GNU operand index 必须是非负整数。

    注意：Python 中 bool 是 int 的子类，因此必须显式排除 True / False。
    """
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def _is_valid_width_bits(value: Any) -> bool:
    """
    host expression 的位宽必须是正整数。

    不在此处限制 width 必须为 8/16/32/64/128 等固定值，因为：

      * 某些前端、中间表达式或 vector/scalar extension 可能使用其他宽度；
      * width 的 target-side 可 lowering 性属于后续 target planner；
      * 本模块只验证 runtime facts 的基本结构，不实施 x86 policy。
    """
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    )


@dataclass(frozen=True)
class RuntimeFactStatus:
    """
    TranslationRuntimeFacts 的不可变 Phase-6A runtime snapshot。

    该模型保存 authoritative runtime facts 的可用性和结构有效性。

    authoritative facts：

      rv_to_operand_index:
          由 assembler normalization 产生的：

              RISC-V register -> GNU operand index

          例如：

              {
                  "a0": 0,
                  "a1": 1,
                  "sp": 2,
              }

      operand_width_bits:
          由 host AST / type analysis 产生的：

              GNU operand index -> host expression width in bits

          例如：

              {
                  0: 64,
                  1: 32,
                  2: 64,
              }

    本模块绝不：

      * 根据 AsmFragment.outputs / inputs 的顺序生成 binding；
      * 根据 p-code 寄存器出现顺序生成 binding；
      * 根据 RISC-V XLEN 推断 host expression width；
      * 根据 fragment.operandBindings JSON 替代 runtime authoritative facts；
      * 推导 RISC-V -> x86 register mapping；
      * 决定某一 x86 target plan 是否满足 ABI / constraint / width 要求。

    “当前 fragment 使用的寄存器是否全部有 binding”这类完整性检查，
    必须由 source_model.py 在已经知道 source IR/p-code register usage 后执行。
    """

    rv_to_operand_index: Mapping[str, int]
    operand_width_bits: Mapping[int, int]
    provenance: str

    has_register_operand_bindings: bool
    has_operand_width_facts: bool

    structural_errors: Tuple[str, ...]

    @property
    def structurally_valid(self) -> bool:
        """
        runtime facts 自身是否没有结构错误。

        注意：

          structurally_valid == True

        不代表它已足以翻译任何 fragment。它只代表：

          * 当前已提供的键和值符合基本类型/范围约束；
          * 没有发生规范化 key 冲突；
          * mapping 容器本身可读取。

        若 source p-code 使用了 "a0"，但 rv_to_operand_index 中没有 "a0"，
        应由 source_model.py 产生 INCOMPLETE_OPERAND_BINDING，而不是在这里
        将整个 RuntimeFactStatus 判定为结构非法。
        """
        return not self.structural_errors

    @property
    def has_any_facts(self) -> bool:
        """
        是否至少存在一种 runtime fact。
        """
        return (
            self.has_register_operand_bindings
            or self.has_operand_width_facts
        )

    @property
    def has_complete_fact_categories(self) -> bool:
        """
        是否同时具有 register binding 与 operand width 两类 facts。

        这仅表示两个类别都非空，并不表示某个特定 fragment 所需的全部项齐全。
        """
        return (
            self.has_register_operand_bindings
            and self.has_operand_width_facts
        )

    @property
    def is_runtime_fact_unavailable(self) -> bool:
        """
        是否完全未提供可用 runtime facts。

        空映射本身不是 structural error；它表达的是“没有可用 facts”。
        source_model.py 应根据 fragment 实际是否需要 bindings/widths 决定
        是否升级为 fail-closed semantic feature。
        """
        return not self.has_any_facts

    @property
    def is_usable_snapshot(self) -> bool:
        """
        runtime snapshot 是否可供后续 source-model completeness 检查使用。

        结构非法时，不应继续依赖其中的部分 mapping 做 lowering。
        """
        return self.structurally_valid

    def operand_index_for_register(
        self,
        register_name: str,
    ) -> Optional[int]:
        """
        返回指定 RISC-V register 的 authoritative GNU operand index。

        若不存在，则返回 None。

        不会：
          * 根据 operand 顺序猜测 index；
          * 根据 ABI alias 自动转换名称；
          * 根据 x10/a0 关系自动补全映射。

        调用方应将 None 作为缺失 authoritative fact 处理。
        """
        normalized = _normalized_register_name(register_name)
        if not normalized:
            return None

        return self.rv_to_operand_index.get(normalized)

    def has_operand_binding_for_register(
        self,
        register_name: str,
    ) -> bool:
        """
        指定 RISC-V register 是否存在 authoritative GNU operand binding。
        """
        return self.operand_index_for_register(register_name) is not None

    def width_bits_for_operand(
        self,
        operand_index: int,
    ) -> Optional[int]:
        """
        返回指定 GNU operand index 的 authoritative host expression width。

        若不存在或 index 非法，则返回 None。

        不使用 RISC-V XLEN、C sizeof(long)、表达式文本或 target ABI 猜测宽度。
        """
        if not _is_valid_nonnegative_index(operand_index):
            return None

        return self.operand_width_bits.get(operand_index)

    def has_width_fact_for_operand(
        self,
        operand_index: int,
    ) -> bool:
        """
        指定 GNU operand index 是否有 authoritative width fact。
        """
        return self.width_bits_for_operand(operand_index) is not None

    def width_bits_for_register(
        self,
        register_name: str,
    ) -> Optional[int]:
        """
        经由 authoritative register -> operand index mapping 查询该 register
        对应宿主表达式的 width。

        以下任一步缺失均返回 None：

          1. register 没有 rv_to_operand_index binding；
          2. operand index 没有 operand_width_bits fact；
          3. register_name 为空。

        该函数不代表 target-side physical register width。
        它返回的是 source host expression 的 authoritative width。
        """
        operand_index = self.operand_index_for_register(register_name)
        if operand_index is None:
            return None

        return self.width_bits_for_operand(operand_index)

    def missing_operand_bindings(
        self,
        registers: Iterable[str],
    ) -> Tuple[str, ...]:
        """
        返回缺失 authoritative operand binding 的 register 名称。

        输出顺序遵循输入顺序，重复 register 会被去重。

        该函数只协助 source_model.py 做 completeness 检查；
        不自行产生 SemanticFeature 或 PreservationDecision。
        """
        missing: list[str] = []
        seen: set[str] = set()

        for register in registers:
            normalized = _normalized_register_name(register)
            if not normalized or normalized in seen:
                continue

            seen.add(normalized)

            if not self.has_operand_binding_for_register(normalized):
                missing.append(normalized)

        return tuple(missing)

    def missing_width_facts_for_operands(
        self,
        operand_indices: Iterable[int],
    ) -> Tuple[int, ...]:
        """
        返回缺失 authoritative width facts 的 operand index。

        非法 operand index 不被静默转换；它们会作为缺失项保留。
        结构非法的 runtime fact 输入应已经通过 structural_errors 体现。
        """
        missing: list[int] = []
        seen: set[int] = set()

        for operand_index in operand_indices:
            if not _is_valid_nonnegative_index(operand_index):
                continue

            if operand_index in seen:
                continue

            seen.add(operand_index)

            if not self.has_width_fact_for_operand(operand_index):
                missing.append(operand_index)

        return tuple(missing)

    def missing_width_facts_for_registers(
        self,
        registers: Iterable[str],
    ) -> Tuple[str, ...]:
        """
        返回 register binding 已存在、但其关联 operand 缺少 width fact 的
        RISC-V register 名称。

        没有 register binding 的项不在本函数结果中，因为它们应由：

            missing_operand_bindings(...)

        单独报告，避免将“binding 缺失”和“width 缺失”混为一类错误。
        """
        missing: list[str] = []
        seen: set[str] = set()

        for register in registers:
            normalized = _normalized_register_name(register)
            if not normalized or normalized in seen:
                continue

            seen.add(normalized)

            operand_index = self.operand_index_for_register(normalized)
            if operand_index is None:
                continue

            if not self.has_width_fact_for_operand(operand_index):
                missing.append(normalized)

        return tuple(missing)

    @classmethod
    def from_runtime_facts(
        cls,
        facts: TranslationRuntimeFacts,
    ) -> "RuntimeFactStatus":
        """
        从 TranslationRuntimeFacts 构造不可变、结构验证后的 runtime snapshot。

        验证内容：

          * rv_to_operand_index 与 operand_width_bits 是否为 mapping；
          * RISC-V register name 是否为空；
          * GNU operand index 是否为非负整数；
          * width 是否为正整数；
          * register name 在 trim 后是否发生冲突；
          * 同一个规范化 register 是否映射到不同 operand index。

        不验证内容：

          * register 名称是否是合法 RISC-V ABI 名称；
          * x10 与 a0 是否等价；
          * operand index 是否真的对应 fragment.outputs / inputs；
          * operand width 是否符合 source AST；
          * operand width 是否可在 x86 上实现；
          * source fragment 是否使用了某个缺失 register；
          * runtime facts 与 AsmFragment.operandBindings 是否一致。

        后续验证职责：

          * source_model.py：
              对照 p-code/IR 实际 register usage 检查 binding/width completeness；

          * preservation.py：
              将 source model 中收集到的 incomplete/invalid 状态转换为
              PreservationDecision；

          * Phase 6C/6D：
              验证 target constraint、ABI、target width、x86 lowering 等。
        """
        errors: list[str] = []

        raw_rv_map: Mapping[Any, Any] = {}
        raw_width_map: Mapping[Any, Any] = {}

        if facts is None:
            errors.append("TranslationRuntimeFacts is None")
            provenance = ""
        else:
            provenance = _text(getattr(facts, "provenance", "")).strip()

            raw_rv_value = getattr(
                facts,
                "rv_to_operand_index",
                None,
            )
            raw_width_value = getattr(
                facts,
                "operand_width_bits",
                None,
            )

            if raw_rv_value is None:
                raw_rv_map = {}
            elif isinstance(raw_rv_value, ABCMapping):
                raw_rv_map = raw_rv_value
            else:
                errors.append(
                    "runtime facts field rv_to_operand_index must be a mapping, "
                    f"got {type(raw_rv_value).__name__}"
                )

            if raw_width_value is None:
                raw_width_map = {}
            elif isinstance(raw_width_value, ABCMapping):
                raw_width_map = raw_width_value
            else:
                errors.append(
                    "runtime facts field operand_width_bits must be a mapping, "
                    f"got {type(raw_width_value).__name__}"
                )

        rv_map: dict[str, int] = {}
        width_map: dict[int, int] = {}

        # 保存规范化前的 key，用于报告 " a0 " 与 "a0" 之类的冲突。
        normalized_register_sources: dict[str, Any] = {}

        for raw_register, raw_operand_index in raw_rv_map.items():
            register = _normalized_register_name(raw_register)

            if not register:
                errors.append(
                    "runtime facts contain an empty RISC-V register name "
                    f"for operand index {raw_operand_index!r}"
                )
                continue

            if not _is_valid_nonnegative_index(raw_operand_index):
                errors.append(
                    "runtime facts contain an invalid GNU operand index "
                    f"for register {register!r}: {raw_operand_index!r}"
                )
                continue

            previous_source = normalized_register_sources.get(register)
            previous_index = rv_map.get(register)

            if previous_source is not None:
                if previous_index != raw_operand_index:
                    errors.append(
                        "runtime facts contain conflicting operand bindings "
                        f"for normalized register {register!r}: "
                        f"{previous_index!r} from {previous_source!r}, "
                        f"{raw_operand_index!r} from {raw_register!r}"
                    )
                else:
                    errors.append(
                        "runtime facts contain duplicate normalized register "
                        f"binding for {register!r}: "
                        f"{previous_source!r} and {raw_register!r}"
                    )
                continue

            normalized_register_sources[register] = raw_register
            rv_map[register] = raw_operand_index

        for raw_operand_index, raw_width_bits in raw_width_map.items():
            if not _is_valid_nonnegative_index(raw_operand_index):
                errors.append(
                    "runtime facts contain an invalid width-map GNU operand "
                    f"index: {raw_operand_index!r}"
                )
                continue

            if not _is_valid_width_bits(raw_width_bits):
                errors.append(
                    "runtime facts contain an invalid host expression width "
                    f"for GNU operand {raw_operand_index!r}: "
                    f"{raw_width_bits!r}"
                )
                continue

            width_map[raw_operand_index] = raw_width_bits

        return cls(
            rv_to_operand_index=MappingProxyType(dict(rv_map)),
            operand_width_bits=MappingProxyType(dict(width_map)),
            provenance=provenance,
            has_register_operand_bindings=bool(rv_map),
            has_operand_width_facts=bool(width_map),
            structural_errors=_deduplicated_messages(errors),
        )
