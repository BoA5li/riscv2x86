from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Tuple

try:
    from .schema import AsmFragment, AsmOperand
except ImportError:  # pragma: no cover - direct-module compatibility
    from schema import AsmFragment, AsmOperand


def _text(value: Any) -> str:
    """
    将 schema / JSON 边界上的可选值转换为稳定字符串。

    None -> ""
    其他值 -> str(value)

    注意：
      这里不对约束字符串、symbolic name 或 expression text 做语义修改；
      因为它们可能需要在 shell-equivalence proof 中保留原始形式。
    """
    if value is None:
        return ""
    return str(value)


def _stripped_text(value: Any) -> str:
    """
    将可选文本转换为去除首尾空白的稳定字符串。
    """
    return _text(value).strip()


def _normalized_clobber(value: str) -> str:
    """
    用于 clobber 分类的规范化名称。

    GCC/Clang 中常见 special clobber 为：

        "memory"
        "cc"

    对于检测而言大小写不应造成差异，因此使用 lower()。
    但 SourceShellModel.clobbers 仍保留原始（trimmed）文本，
    以便 shell-equivalence proof 或诊断输出使用。
    """
    return value.strip().lower()


def _unique_preserving_order(values: Iterable[str]) -> Tuple[str, ...]:
    """
    去重但保留首次出现顺序。

    对 goto label、register key 这类集合型语义，重复项不增加语义；
    但保留原始相对顺序有助于稳定日志和测试。
    """
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)

    return tuple(result)


def _extract_declared_operand_binding_registers(
    operand_bindings: Any,
) -> Tuple[str, ...]:
    """
    从 fragment.operandBindings 中提取显式声明的 RISC-V register key。

    已知 JSON 结构示例：

        {
          "operandBindings": {
            "rvToOperand": {
              "a0": {
                "expression": "result",
                "widthBits": 64
              }
            }
          }
        }

    或某些上游序列化格式可能直接使用：

        {
          "rvToOperand": {
            "a0": {...}
          }
        }

    该函数只提取“声明了哪些 register key”，不读取其中的 GNU operand
    index，也不把它当作 TranslationRuntimeFacts.rv_to_operand_index。

    原因：

      * fragment.operandBindings 是 JSON / fragment 级描述；
      * runtime facts 必须来自 assembler normalization；
      * lowerer 不允许从 serialized fragment JSON 恢复 runtime mapping。
    """
    if not isinstance(operand_bindings, Mapping):
        return ()

    rv_to_operand: Any = None

    nested = operand_bindings.get("operandBindings")
    if isinstance(nested, Mapping):
        rv_to_operand = nested.get("rvToOperand")

    if rv_to_operand is None:
        rv_to_operand = operand_bindings.get("rvToOperand")

    if not isinstance(rv_to_operand, Mapping):
        return ()

    registers = (
        _stripped_text(register)
        for register in rv_to_operand.keys()
    )

    return _unique_preserving_order(
        register
        for register in registers
        if register
    )


@dataclass(frozen=True)
class SourceAsmOperandModel:
    """
    单个源 GCC/Clang inline-asm operand 的 shell-level semantic snapshot。

    本模型记录的是 source compiler-shell 语义，不是 target constraint。

    例如，constraint 中可能出现：

        "=r"
        "+r"
        "r"
        "m"
        "i"
        "0"
        "&=r"

    这些 constraint 的 x86 target-side 重写、tied operand 编号重建、
    early-clobber 保留、operand modifier 处理等，必须由后续
    TargetConstraintModel / X86 lowering 阶段处理。

    这里绝不能：
      * 根据 operand 所在 outputs / inputs 列表的位置猜测 RISC-V register；
      * 根据 constraint 中的数字猜测 runtime register binding；
      * 将 source operand index 当成 target operand index；
      * 推断 x86 寄存器名。
    """

    constraint: str
    expr_text: str
    symbolic_name: str

    is_output: bool
    is_tied: bool
    is_early_clobber: bool

    @property
    def has_constraint(self) -> bool:
        """
        operand 是否携带约束文本。
        """
        return bool(self.constraint)

    @property
    def has_expression(self) -> bool:
        """
        operand 是否携带宿主表达式文本。
        """
        return bool(self.expr_text)

    @property
    def has_symbolic_name(self) -> bool:
        """
        operand 是否携带 GNU named operand 名称。
        """
        return bool(self.symbolic_name)

    @classmethod
    def from_operand(cls, operand: AsmOperand) -> "SourceAsmOperandModel":
        """
        从 schema.AsmOperand 构造不可变 shell snapshot。

        当前依赖的 AsmOperand 字段为：

            constraint
            exprText
            symbolicName
            isOutput
            isTied
            isEarlyClobber
        """
        return cls(
            constraint=_text(getattr(operand, "constraint", "")),
            expr_text=_text(getattr(operand, "exprText", "")),
            symbolic_name=_text(getattr(operand, "symbolicName", "")),
            is_output=bool(getattr(operand, "isOutput", False)),
            is_tied=bool(getattr(operand, "isTied", False)),
            is_early_clobber=bool(
                getattr(operand, "isEarlyClobber", False)
            ),
        )


@dataclass(frozen=True)
class SourceShellModel:
    """
    编译器外壳语义快照。

    SourceShellModel 是从 AsmFragment 派生的 immutable snapshot，供后续：

      * candidate plan generation；
      * target constraint derivation；
      * shell-equivalence proof；
      * Phase 7 validation metadata；
      * SourceSemanticModel 构造过程中的 shell semantic collection。

    它不负责：

      * 收集完整 source semantic feature；
      * 导出 PreservationDecision；
      * 验证 TranslationRuntimeFacts；
      * 构造 RISC-V -> x86 register mapping；
      * 推导 x86 GNU asm constraint；
      * 从 operand 顺序猜测 register binding；
      * 从 rawAsmText 猜测 CFG 或控制流。

    对控制流、局部标签、asm goto 等信息，必须信任 AsmFragment 中的
    normalized metadata，而不是尝试在此处解析 rawAsmText。
    """

    # ------------------------------------------------------------------
    # Fragment 基础 shell 属性。
    # ------------------------------------------------------------------

    kind: str
    raw_asm_present: bool

    # ------------------------------------------------------------------
    # GCC/Clang inline asm operands。
    # ------------------------------------------------------------------

    outputs: Tuple[SourceAsmOperandModel, ...]
    inputs: Tuple[SourceAsmOperandModel, ...]
    clobbers: Tuple[str, ...]
    normalized_clobbers: Tuple[str, ...]

    # ------------------------------------------------------------------
    # Inline asm 外壳语义。
    # ------------------------------------------------------------------

    is_volatile: bool

    has_asm_goto: bool
    goto_labels: Tuple[str, ...]
    # (asm target spelling, C label, exit code), copied from the frontend.
    goto_edges: Tuple[Tuple[str, str, int], ...]

    has_local_labels: bool
    has_external_control_flow: bool
    has_multiple_exits: bool
    has_non_local_control_dependency: bool

    has_retry_loop: bool

    # ------------------------------------------------------------------
    # Operand / clobber 派生属性。
    # ------------------------------------------------------------------

    has_early_clobber: bool
    has_tied_operands: bool

    has_memory_clobber: bool
    has_cc_clobber: bool

    # ------------------------------------------------------------------
    # Serialized fragment binding metadata 的存在性快照。
    #
    # 注意：
    # 这些不是 runtime authoritative mapping。
    # ------------------------------------------------------------------

    has_explicit_operand_bindings: bool
    declared_operand_binding_registers: Tuple[str, ...]

    has_materialized_operand_bindings: bool
    materialized_operand_binding_count: int

    has_output_bindings: bool
    output_binding_count: int

    # ------------------------------------------------------------------
    # 便捷属性。
    # ------------------------------------------------------------------

    @property
    def all_operands(self) -> Tuple[SourceAsmOperandModel, ...]:
        """
        按 source shell 中的 outputs + inputs 顺序返回所有 operands。

        该顺序仅用于 shell snapshot、日志、proof 和约束重建；
        不允许用于推导 RISC-V register -> GNU operand index。
        """
        return self.outputs + self.inputs

    @property
    def has_operands(self) -> bool:
        """
        是否具有 input 或 output operands。
        """
        return bool(self.outputs or self.inputs)

    @property
    def output_count(self) -> int:
        """
        source output operand 数量。
        """
        return len(self.outputs)

    @property
    def input_count(self) -> int:
        """
        source input operand 数量。
        """
        return len(self.inputs)

    @property
    def has_clobbers(self) -> bool:
        """
        是否存在任何 clobber。
        """
        return bool(self.clobbers)

    @property
    def has_control_flow_surface(self) -> bool:
        """
        是否具有需要控制流保留的 shell-level surface。

        注意：
        这只是 shell-level 指示，不替代 CFGResult 或 Block/IRSummary 的
        控制流语义分析。
        """
        return any(
            (
                self.has_asm_goto,
                self.has_local_labels,
                self.has_external_control_flow,
                self.has_multiple_exits,
                self.has_non_local_control_dependency,
                bool(self.goto_labels),
            )
        )

    @property
    def requires_shell_aware_lowering(self) -> bool:
        """
        是否不能被当作普通纯表达式直接 lower。

        下列情况通常必须保留 compiler shell 语义：

          * volatile asm；
          * input/output operands；
          * clobbers；
          * asm goto / goto labels；
          * local/external/nonlocal control flow；
          * early-clobber；
          * tied operands；
          * output bindings；
          * 显式 operand binding metadata。
        """
        return any(
            (
                self.is_volatile,
                self.has_operands,
                self.has_clobbers,
                self.has_control_flow_surface,
                self.has_early_clobber,
                self.has_tied_operands,
                self.has_output_bindings,
                self.has_explicit_operand_bindings,
                self.has_materialized_operand_bindings,
            )
        )

    @property
    def has_declared_operand_binding_metadata(self) -> bool:
        """
        fragment JSON 中是否存在显式 operand binding metadata。

        这只意味着 fragment 声明了 binding 信息；
        不表示 runtime facts 已验证、完整或可用于 lowering。
        """
        return (
            self.has_explicit_operand_bindings
            or self.has_materialized_operand_bindings
            or self.has_output_bindings
        )

    def has_clobber(self, name: str) -> bool:
        """
        检查是否存在指定 clobber。

        比较时采用 strip + lower 规范化。例如：

            model.has_clobber("memory")
            model.has_clobber(" MEMORY ")
            model.has_clobber("cc")
        """
        normalized = _normalized_clobber(name)
        return normalized in self.normalized_clobbers

    @classmethod
    def from_fragment(cls, fragment: AsmFragment) -> "SourceShellModel":
        """
        从 AsmFragment 构造 SourceShellModel。

        authoritative source shell 字段包括：

            kind
            rawAsmText
            outputs
            inputs
            clobbers
            gotoLabels
            isVolatile
            hasRetryLoop
            hasAsmGoto
            hasLocalLabels
            hasExternalControlFlow
            hasMultipleExits
            hasNonLocalControlDependency
            outputBindings
            materializedOperandBindings
            operandBindings

        特别说明：

          1. gotoLabels / hasAsmGoto：
             使用 fragment 已规范化字段，不解析 rawAsmText。

          2. operandBindings：
             只记录“显式 binding metadata 是否存在”和声明的 register key；
             不将其视为 runtime authoritative rv_to_operand_index。

          3. operand_width_bits：
             虽存在于 AsmFragment，但不应作为 runtime width facts 使用。
             真正 authoritative width 必须来自：

                 TranslationRuntimeFacts.operand_width_bits

          4. outputs / inputs 顺序：
             可以被快照保留，但不得用于推导 register mapping。
        """
        outputs = tuple(
            SourceAsmOperandModel.from_operand(operand)
            for operand in (fragment.outputs or [])
        )

        inputs = tuple(
            SourceAsmOperandModel.from_operand(operand)
            for operand in (fragment.inputs or [])
        )

        clobbers = tuple(
            clobber
            for clobber in (
                _stripped_text(value)
                for value in (fragment.clobbers or [])
            )
            if clobber
        )

        normalized_clobbers = _unique_preserving_order(
            _normalized_clobber(clobber)
            for clobber in clobbers
            if _normalized_clobber(clobber)
        )

        goto_labels = _unique_preserving_order(
            label
            for label in (
                _stripped_text(value)
                for value in (fragment.gotoLabels or [])
            )
            if label
        )
        goto_edges = tuple(
            (str(getattr(edge, "asmTarget", "")).strip(),
             str(getattr(edge, "cLabel", "")).strip(),
             int(getattr(edge, "exitCode", -1)))
            for edge in (getattr(fragment, "gotoEdges", ()) or ())
            if str(getattr(edge, "asmTarget", "")).strip()
            and str(getattr(edge, "cLabel", "")).strip()
            and isinstance(getattr(edge, "exitCode", None), int)
        )

        all_operands = outputs + inputs

        operand_bindings = getattr(fragment, "operandBindings", None)
        declared_binding_registers = (
            _extract_declared_operand_binding_registers(operand_bindings)
        )

        output_bindings = getattr(fragment, "outputBindings", None) or []
        materialized_bindings = (
            getattr(fragment, "materializedOperandBindings", None) or []
        )

        return cls(
            kind=_stripped_text(getattr(fragment, "kind", "")),
            raw_asm_present=bool(fragment.has_asm_text()),

            outputs=outputs,
            inputs=inputs,
            clobbers=clobbers,
            normalized_clobbers=normalized_clobbers,

            is_volatile=bool(getattr(fragment, "isVolatile", False)),

            has_asm_goto=bool(
                getattr(fragment, "hasAsmGoto", False) or goto_labels
            ),
            goto_labels=goto_labels,
            goto_edges=goto_edges,

            has_local_labels=bool(
                getattr(fragment, "hasLocalLabels", False)
            ),
            has_external_control_flow=bool(
                getattr(fragment, "hasExternalControlFlow", False)
            ),
            has_multiple_exits=bool(
                getattr(fragment, "hasMultipleExits", False)
            ),
            has_non_local_control_dependency=bool(
                getattr(fragment, "hasNonLocalControlDependency", False)
            ),

            has_retry_loop=bool(
                getattr(fragment, "hasRetryLoop", False)
            ),

            has_early_clobber=any(
                operand.is_early_clobber
                for operand in all_operands
            ),
            has_tied_operands=any(
                operand.is_tied
                for operand in all_operands
            ),

            has_memory_clobber="memory" in normalized_clobbers,
            has_cc_clobber="cc" in normalized_clobbers,

            has_explicit_operand_bindings=bool(
                declared_binding_registers
            ),
            declared_operand_binding_registers=declared_binding_registers,

            has_materialized_operand_bindings=bool(
                materialized_bindings
            ),
            materialized_operand_binding_count=len(
                materialized_bindings
            ),

            has_output_bindings=bool(output_bindings),
            output_binding_count=len(output_bindings),
        )
