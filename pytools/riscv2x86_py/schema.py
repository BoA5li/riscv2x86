from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Tuple
import json
#from translation_runtime_facts import TranslationRuntimeFacts
from .runtime_facts import (
    TranslationRuntimeFacts,
    translation_runtime_facts_to_dict,
    translation_runtime_facts_from_dict
)


@dataclass
class AsmOperand:
    constraint: str = ""
    exprText: str = ""
    symbolicName: str = ""
    isOutput: bool = False
    isTied: bool = False
    isEarlyClobber: bool = False


@dataclass
class OutputBinding:
    outputIndex: int = 0
    sinkKind: str = ""
    sinkOpIndex: Optional[int] = None
    aluExpr: Optional[str] = None


@dataclass
class AsmSymbolRef:
    """
    Phase 4: PIC / %pcrel_hi / %pcrel_lo / la 支持。
    描述 inline asm 字面中出现的一个外部符号。
    """
    asmName: str = ""
    cName: str = ""
    addrTaken: bool = True


@dataclass
class AsmGotoEdge:
    """
    inline asm 中 asm goto 的一个出口映射。

    asmTarget:
        asm 模板里出现的 goto 目标引用，如 "%l0" / "%l[slow]"

    cLabel:
        外层 C 语句中的真实 label 名称

    exitCode:
        phase7 在 x86 inline asm 包装时写入的出口编号
    """
    asmTarget: str = ""
    cLabel: str = ""
    exitCode: int = 0


@dataclass
class AsmControlFlowSurface:
    """
    Phase 7: 对 inline asm 的“控制流表面”做显式建模。

    这不是 lift 后的 CFG summary，而是“源码中的 asm 片段对宿主 C
    的控制流接口”。
    """
    style: str = "Unknown"  # StraightLine / LocalCFG / AsmGoto / NonLocal / CallLike
    localLabels: List[str] = field(default_factory=list)
    branchTargets: List[str] = field(default_factory=list)
    exitTargets: List[str] = field(default_factory=list)

    hasFallthrough: bool = True
    hasAsmGoto: bool = False
    hasMultipleExits: bool = False
    hasIndirectBranch: bool = False
    hasCallLike: bool = False
    hasReturnLike: bool = False
    hasNonLocalControl: bool = False

    explain: str = ""


@dataclass
class AsmMicroArchIntent:
    """
    Phase 7/8: 微架构语义保持意图。

    用来表达该 fragment 是否只要求 ISA 级一致，
    还是要求更强的实验/侧信道保持。
    """
    level: str = "A"  # A/B/C/D
    preserveExperiment: bool = False
    preserveControlFlowShape: bool = False
    preserveBranchPredictorShape: bool = False
    preserveCacheFootprint: bool = False
    preserveAtomicRetryShape: bool = False
    preserveFenceShape: bool = False
    preserveTimingSource: bool = False

    tags: List[str] = field(default_factory=list)
    explain: str = ""

@dataclass(frozen=True)
class MaterializedOperandBinding:
    """
    记录 Phase 3 中 GNU inline asm operand 被物化为 RISC-V 临时寄存器时的来源。

    例如：

        原始 asm:
            add %0, %1, %2

        renderer/materializer 输出:
            add a0, a1, a2

        则应记录：
            a0 -> %0
            a1 -> %1
            a2 -> %2
    """
    rvRegister: str
    operandPlaceholder: str
    operandIndex: int
    role: str   # "output" / "input"

@dataclass
class AsmFragment:
    kind: str = "InlineExtended"
    rawAsmText: str = ""

    # GCC/Clang inline asm operand descriptors.
    outputs: List[AsmOperand] = field(default_factory=list)
    inputs: List[AsmOperand] = field(default_factory=list)

    clobbers: List[str] = field(default_factory=list)
    gotoLabels: List[str] = field(default_factory=list)
    isVolatile: bool = False

    fileName: str = ""
    line: int = 0
    column: int = 0
    beginOffset: int = 0
    endOffset: int = 0
    enclosingFunction: str = ""

    id: str = ""
    fragmentId: str = ""

    predecessorFragmentId: Optional[str] = None
    successorFragmentId: Optional[str] = None

    outputBindings: List[OutputBinding] = field(default_factory=list)

    hasRetryLoop: bool = False

    symbols: List[AsmSymbolRef] = field(default_factory=list)

    hasAsmGoto: bool = False
    hasLocalLabels: bool = False
    hasExternalControlFlow: bool = False
    hasMultipleExits: bool = False
    hasNonLocalControlDependency: bool = False
    controlFlowSurface: str = ""

    microarchSensitive: bool = False
    microarchReasons: List[str] = field(default_factory=list)

    gotoEdges: List[AsmGotoEdge] = field(default_factory=list)
    controlFlow: Optional[AsmControlFlowSurface] = None
    microArch: Optional[AsmMicroArchIntent] = None

    # assembler normalization 阶段产出的 register -> GNU operand index 映射。
    # 该字段仍然保留，用于已有的 operand 物化、约束验证和一致性检查。
    materializedOperandBindings: list[MaterializedOperandBinding] = field(
        default_factory=list
    )

    # 显式 register -> 宿主表达式绑定。
    #
    # JSON 结构：
    #
    # {
    #   "operandBindings": {
    #     "rvToOperand": {
    #       "a0": {
    #         "expression": "result",
    #         "widthBits": 64
    #       }
    #     }
    #   }
    # }
    #
    # 这是 normalized p-code -> x86 lowerer 唯一允许使用的
    # RISC-V register -> C expression 映射来源。
    #
    # 不允许 lowerer 从 outputs / inputs 的顺序、GNU operand index，
    # 或 p-code 中寄存器出现顺序猜测该映射。
    operandBindings: Dict[str, Any] = field(default_factory=dict)
    operand_width_bits: Dict[int, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.fragmentId and not self.id:
            self.id = self.fragmentId
        elif self.id and not self.fragmentId:
            self.fragmentId = self.id

    def has_asm_text(self) -> bool:
        return bool((self.rawAsmText or "").strip())

@dataclass
class Finding:
    # 前端分类信息。
    category: str = "NeedsAsmTranslation"
    description: str = ""

    # InlineAsm / AsmGoto / Function / Statement 等。
    subjectKind: str = ""

    # 源码重写信息。
    hasRewriteRange: bool = False
    rewriteBeginOffset: int = 0
    rewriteEndOffset: int = 0
    rawSourceText: str = ""

    # finding 的基础 source location。
    fileName: str = ""
    line: int = 0
    column: int = 0

    # 前端抽取的 asm fragment。
    fragment: Optional[AsmFragment] = None

    # 前端或后端给出的建议替换内容。
    suggestedReplacement: str = ""
    ruleName: str = ""

    # Phase 4：assemble 结果。
    machineCodeHex: str = ""

    # Phase 5：lifting 结果。
    pcodeText: str = ""

    # Phase 6 / 7：翻译结果。
    translationKind: str = ""

    # Phase 8：验证结果。
    verificationStatus: str = ""
    verificationDetail: str = ""

    # 附加诊断信息。
    notes: List[str] = field(default_factory=list)

    # preservationLevel:
    #   Exact / Conservative / Unsupported / NeedsManualReview
    #
    # preservationRoute:
    #   PureC / X86InlineAsm / HelperFunction / Deferred
    preservationLevel: str = ""
    preservationRoute: str = ""

    # Phase 3 ~ Phase 6：
    #
    # 该字段必须在 Phase 4 assemble + facts build 成功后、Phase 5 lift /
    # Phase 6 translate 之前回填。
    #
    # finding 输出为 JSON 时使用 camelCase：
    #   translationRuntimeFacts.rvToOperandIndex
    #   translationRuntimeFacts.operandWidthBits
    translationRuntimeFacts: TranslationRuntimeFacts | None = None

    def enters_asm_pipeline(self) -> bool:
        """
        只有携带非空 asm 文本的 fragment 才进入 Phase 4 assemble。

        普通 C finding、缺失 fragment 的 finding、仅分类但未提取 asm
        的 finding，不应该错误进入 assembler/lifter 支线。
        """
        return bool(
            self.fragment is not None
            and (self.fragment.rawAsmText or "").strip()
        )

    def needs_asm_translation(self) -> bool:
        return self.category == "NeedsAsmTranslation"

    def has_asm_fragment(self) -> bool:
        return self.fragment is not None and self.fragment.has_asm_text()

    def to_dict(self) -> Dict[str, Any]:
        """
        将 Finding 序列化为 report / JSON 使用的字典。

        dataclasses.asdict() 会将 TranslationRuntimeFacts 输出为内部
        snake_case 字段：

            {
                "rv_to_operand_index": ...,
                "operand_width_bits": ...,
            }

        但 report schema 要求使用 camelCase，因此必须显式覆盖
        translationRuntimeFacts 字段。
        """
        result = asdict(self)

        result["translationRuntimeFacts"] = (
            translation_runtime_facts_to_dict(
                self.translationRuntimeFacts
            )
            if self.translationRuntimeFacts is not None
            else None
        )

        return result
        
@dataclass
class TranslationOutput:
    kind: str
    replacement: str
    route: str = ""
    notes: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)

    # ===== Phase 8 structured contract =====
    preservationLevel: str = ""
    preservationRoute: str = ""
    buildFamily: str = ""

    # phase8/report/verify 用的 reason code
    reasonCodes: List[str] = field(default_factory=list)

    requiresBuildCheck: bool = True
    requiresBlockProof: bool = False
    requiresPathValidation: bool = False

    metadata: Dict[str, Any] = field(default_factory=dict)

    def normalized_level(self) -> str:
        return _normalize_preservation_level(self.preservationLevel)

    def normalized_route(self) -> str:
        return _normalize_preservation_route(self.preservationRoute)

    def normalized_build_family(self) -> str:
        return _normalize_output_build_family(
            self.kind,
            self.replacement,
            explicit=self.buildFamily,
        )




def _op_from(d: Dict[str, Any]) -> AsmOperand:
    """从 JSON dict 恢复 AsmOperand，忽略未知字段。"""
    defaults = AsmOperand()
    return AsmOperand(
        **{
            k: d.get(k, getattr(defaults, k))
            for k in AsmOperand.__dataclass_fields__
        }
    )


def _binding_from(d: Dict[str, Any]) -> OutputBinding:
    """从 JSON dict 恢复 OutputBinding，忽略未知字段。"""
    defaults = OutputBinding()
    return OutputBinding(
        **{
            k: d.get(k, getattr(defaults, k))
            for k in OutputBinding.__dataclass_fields__
        }
    )


def _sym_from(d: Dict[str, Any]) -> AsmSymbolRef:
    """从 JSON dict 恢复 AsmSymbolRef，忽略未知字段。"""
    defaults = AsmSymbolRef()
    return AsmSymbolRef(
        **{
            k: d.get(k, getattr(defaults, k))
            for k in AsmSymbolRef.__dataclass_fields__
        }
    )


def _goto_edge_from(d: Dict[str, Any]) -> AsmGotoEdge:
    """从 JSON dict 恢复 AsmGotoEdge，忽略未知字段。"""
    defaults = AsmGotoEdge()
    return AsmGotoEdge(
        **{
            k: d.get(k, getattr(defaults, k))
            for k in AsmGotoEdge.__dataclass_fields__
        }
    )


def _cfg_surface_from(d: Dict[str, Any]) -> AsmControlFlowSurface:
    """从 JSON dict 恢复 AsmControlFlowSurface，忽略未知字段。"""
    defaults = AsmControlFlowSurface()
    return AsmControlFlowSurface(
        **{
            k: d.get(k, getattr(defaults, k))
            for k in AsmControlFlowSurface.__dataclass_fields__
        }
    )


def _micro_from(d: Dict[str, Any]) -> AsmMicroArchIntent:
    """从 JSON dict 恢复 AsmMicroArchIntent，忽略未知字段。"""
    defaults = AsmMicroArchIntent()
    return AsmMicroArchIntent(
        **{
            k: d.get(k, getattr(defaults, k))
            for k in AsmMicroArchIntent.__dataclass_fields__
        }
    )
def _operand_width_bits_from(raw: Any) -> Dict[int, int]:
    """
    从 JSON fragment.operandWidthBits 恢复：

        GNU operand index -> host C/C++ type width in bits

    JSON object 的 key 必然是字符串，例如：

        {
            "0": 64,
            "1": 64,
            "2": 32
        }

    恢复后必须成为：

        {
            0: 64,
            1: 64,
            2: 32
        }

    该字段是 host AST/type analysis 提供的源级事实，不能在 Python
    pipeline 中由 xlen、寄存器名、p-code varnode size 或 operand 顺序推导。
    """
    if raw is None:
        return {}

    if not isinstance(raw, dict):
        raise ValueError(
            "fragment.operandWidthBits must be a JSON object "
            "(GNU operand index -> host type width in bits)"
        )

    result: Dict[int, int] = {}

    for raw_index, raw_width in raw.items():
        # JSON object key 通常是 str；测试或内部调用也允许 int。
        if isinstance(raw_index, bool) or not isinstance(raw_index, (str, int)):
            raise ValueError(
                "fragment.operandWidthBits contains an invalid GNU operand "
                f"index: {raw_index!r}"
            )

        try:
            operand_index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "fragment.operandWidthBits contains an invalid GNU operand "
                f"index: {raw_index!r}"
            ) from exc

        if operand_index < 0:
            raise ValueError(
                "fragment.operandWidthBits GNU operand index must be "
                f"non-negative: {operand_index!r}"
            )

        # bool 是 int 的子类，因此必须显式排除。
        #
        # 宽度必须由 C++ AST/type analysis 以 JSON number 导出；
        # 不接受 "64" 这样的字符串，以免掩盖 schema/exporter 错误。
        if isinstance(raw_width, bool) or not isinstance(raw_width, int):
            raise ValueError(
                "fragment.operandWidthBits width for GNU operand "
                f"%{operand_index} must be an integer, got {raw_width!r}"
            )

        if raw_width <= 0:
            raise ValueError(
                "fragment.operandWidthBits width for GNU operand "
                f"%{operand_index} must be positive, got {raw_width!r}"
            )

        if operand_index in result:
            raise ValueError(
                "fragment.operandWidthBits contains duplicate normalized "
                f"GNU operand index %{operand_index}"
            )

        result[operand_index] = raw_width

    return result

def _frag_from(d: Dict[str, Any]) -> AsmFragment:
    """
    从标准 fragment dict 恢复 AsmFragment。

    同时兼容：
      - rawAsmText
      - asmText（某些旧前端版本的字段名）
      - id / fragmentId 的双向兼容
      - operandWidthBits（C++ JSON exporter 使用的 camelCase 名称）
      - operand_width_bits（Python/internal/旧数据兼容名称）
    """
    f = AsmFragment()

    for k in AsmFragment.__dataclass_fields__:
        if k in ("outputs", "inputs"):
            raw_items = d.get(k, [])
            if isinstance(raw_items, list):
                setattr(
                    f,
                    k,
                    [
                        _op_from(x)
                        for x in raw_items
                        if isinstance(x, dict)
                    ],
                )

        elif k == "outputBindings":
            raw_items = d.get(k, [])
            if isinstance(raw_items, list):
                setattr(
                    f,
                    k,
                    [
                        _binding_from(x)
                        for x in raw_items
                        if isinstance(x, dict)
                    ],
                )

        elif k == "symbols":
            raw_items = d.get(k, [])
            if isinstance(raw_items, list):
                setattr(
                    f,
                    k,
                    [
                        _sym_from(x)
                        for x in raw_items
                        if isinstance(x, dict)
                    ],
                )

        elif k == "gotoEdges":
            raw_items = d.get(k, [])
            if isinstance(raw_items, list):
                setattr(
                    f,
                    k,
                    [
                        _goto_edge_from(x)
                        for x in raw_items
                        if isinstance(x, dict)
                    ],
                )

        elif k == "controlFlow":
            raw_cfg = d.get(k)
            if isinstance(raw_cfg, dict):
                setattr(f, k, _cfg_surface_from(raw_cfg))

        elif k == "microArch":
            raw_micro = d.get(k)
            if isinstance(raw_micro, dict):
                setattr(f, k, _micro_from(raw_micro))

        elif k == "operand_width_bits":
            # C++ Report.cpp 导出的标准 JSON 字段名是 operandWidthBits。
            #
            # 兼容 Python/internal/旧数据直接使用 operand_width_bits 的情况。
            #
            # 若两个字段同时存在，camelCase 的 exporter 字段优先，
            # 因为它代表标准前端输出 schema。
            if "operandWidthBits" in d:
                raw_widths = d.get("operandWidthBits")
            else:
                raw_widths = d.get("operand_width_bits")

            setattr(f, k, _operand_width_bits_from(raw_widths))

        elif k in d:
            setattr(f, k, d[k])

    if not f.rawAsmText and isinstance(d.get("asmText"), str):
        f.rawAsmText = d["asmText"]

    if not f.fragmentId and f.id:
        f.fragmentId = f.id

    if not f.id and f.fragmentId:
        f.id = f.fragmentId

    return f
    
def _legacy_asm_text_to_fragment_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    将旧版扁平报告中的 finding 转换成 fragment dict。

    legacy 格式示例：

    {
      "category": "NeedsAsmTranslation",
      "file": "legacy.c",
      "line": 12,
      "id": "legacy-frag",
      "asmText": "add a0, a1, a2",
      "outputs": [...],
      "inputs": [...],
      "clobbers": ["memory"],
      "hasAsmGoto": true,
      "gotoEdges": [...],
      "controlFlow": {...},
      "microArch": {...}
    }

    这些字段原本都位于 finding 顶层，而新格式应位于：

    {
      "fragment": {
        "rawAsmText": "...",
        ...
      }
    }

    本函数只负责构造可被 _frag_from() 统一解析的 dict。
    """
    fragment_data = dict(d)

    # asmText 是 legacy 字段；rawAsmText 是当前标准字段。
    fragment_data.setdefault("rawAsmText", d.get("asmText", ""))

    # legacy finding 使用 file；fragment 使用 fileName。
    fragment_data.setdefault("fileName", d.get("file", ""))

    # id / fragmentId 兼容。
    fragment_data.setdefault("id", d.get("id", d.get("fragmentId", "")))
    fragment_data.setdefault(
        "fragmentId",
        d.get("fragmentId", d.get("id", "")),
    )

    # 显式确保常见的基础字段存在。
    fragment_data.setdefault("line", d.get("line", 0))
    fragment_data.setdefault("column", d.get("column", 0))
    fragment_data.setdefault("beginOffset", d.get("beginOffset", 0))
    fragment_data.setdefault("endOffset", d.get("endOffset", 0))
    fragment_data.setdefault(
        "enclosingFunction",
        d.get("enclosingFunction", ""),
    )

    # 注意：
    #
    # outputs / inputs 是 AsmOperand 数组；
    # outputBindings 是 OutputBinding 数组。
    #
    # 它们语义不同，不能将 legacy outputs 映射为 outputBindings。
    fragment_data.setdefault("outputs", d.get("outputs", []))
    fragment_data.setdefault("inputs", d.get("inputs", []))
    fragment_data.setdefault(
        "outputBindings",
        d.get("outputBindings", []),
    )

    # 以下字段在 legacy JSON 中可能直接位于 finding 顶层；
    # 保留它们，使 _frag_from() 可以完整恢复 fragment 语义。
    fragment_data.setdefault("clobbers", d.get("clobbers", []))
    fragment_data.setdefault("gotoLabels", d.get("gotoLabels", []))
    fragment_data.setdefault("gotoEdges", d.get("gotoEdges", []))
    fragment_data.setdefault("symbols", d.get("symbols", []))

    fragment_data.setdefault("kind", d.get("kind", "InlineExtended"))
    fragment_data.setdefault("isVolatile", d.get("isVolatile", False))
    fragment_data.setdefault("hasRetryLoop", d.get("hasRetryLoop", False))
    fragment_data.setdefault("hasAsmGoto", d.get("hasAsmGoto", False))
    fragment_data.setdefault(
        "hasLocalLabels",
        d.get("hasLocalLabels", False),
    )
    fragment_data.setdefault(
        "hasExternalControlFlow",
        d.get("hasExternalControlFlow", False),
    )
    fragment_data.setdefault(
        "hasMultipleExits",
        d.get("hasMultipleExits", False),
    )
    fragment_data.setdefault(
        "hasNonLocalControlDependency",
        d.get("hasNonLocalControlDependency", False),
    )
    fragment_data.setdefault(
        "controlFlowSurface",
        d.get("controlFlowSurface", ""),
    )
    fragment_data.setdefault(
        "microarchSensitive",
        d.get("microarchSensitive", False),
    )
    fragment_data.setdefault(
        "microarchReasons",
        d.get("microarchReasons", []),
    )

    # controlFlow / microArch 若存在则由 _frag_from() 转为对应 dataclass。
    if "controlFlow" in d:
        fragment_data["controlFlow"] = d["controlFlow"]

    if "microArch" in d:
        fragment_data["microArch"] = d["microArch"]

    return fragment_data


def load_report(path: str) -> List[Finding]:
    """
    加载报告，兼容两种输入格式。

    当前标准格式：

    {
      "findings": [
        {
          "category": "...",
          "fragment": {
            "rawAsmText": "...",
            "outputs": [...],
            ...
          },
          "translationRuntimeFacts": {
            "rvToOperandIndex": {
              "a0": 0
            },
            "operandWidthBits": {
              "0": 64
            }
          }
        }
      ]
    }

    legacy 平铺格式：

    {
      "findings": [
        {
          "category": "...",
          "asmText": "...",
          "outputs": [...],
          "inputs": [...],
          ...
        }
      ]
    }

    注意：
    translationRuntimeFacts 在 JSON 中是 camelCase dict，但 pipeline
    内部需要 TranslationRuntimeFacts 对象。因此不能将原始 dict 直接
    setattr 到 Finding.translationRuntimeFacts，必须通过
    translation_runtime_facts_from_dict() 恢复。
    """
    with open(path, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    out: List[Finding] = []

    for finding_index, d in enumerate(data.get("findings", [])):
        if not isinstance(d, dict):
            continue

        f = Finding()

        for k in Finding.__dataclass_fields__:
            if k == "fragment":
                # 当前标准嵌套格式。
                if isinstance(d.get("fragment"), dict):
                    f.fragment = _frag_from(d["fragment"])

                # 兼容旧版 flat finding 格式。
                elif "asmText" in d:
                    legacy_fragment_data = _legacy_asm_text_to_fragment_dict(d)
                    f.fragment = _frag_from(legacy_fragment_data)

            elif k == "translationRuntimeFacts":
                # 不在这里直接 setattr。
                #
                # JSON 中该字段是：
                #
                # {
                #   "rvToOperandIndex": {...},
                #   "operandWidthBits": {...}
                # }
                #
                # 需要在循环结束后通过
                # translation_runtime_facts_from_dict() 恢复为
                # TranslationRuntimeFacts 对象。
                continue

            elif k in d:
                setattr(f, k, d[k])

        # 恢复 JSON / report 中的 translationRuntimeFacts。
        #
        # 缺失该字段的旧报告会得到 None，这是兼容行为；
        # 新进入 Phase 4 -> Phase 6 的 finding 会由 pipeline 在 assemble
        # 和 build_translation_runtime_facts 成功后重新回填该字段。
        try:
            f.translationRuntimeFacts = translation_runtime_facts_from_dict(
                d.get("translationRuntimeFacts")
            )
        except ValueError as exc:
            raise ValueError(
                "invalid translationRuntimeFacts in finding "
                f"#{finding_index} from {path!r}: {exc}"
            ) from exc

        # legacy finding 使用 file；Finding 使用 fileName。
        if not f.fileName:
            f.fileName = d.get("file", "")

        # 若 finding 顶层没有 location，但 fragment 有，则回填。
        if f.fragment is not None:
            if not f.fileName:
                f.fileName = f.fragment.fileName

            if not f.line:
                f.line = f.fragment.line

            if not f.column:
                f.column = f.fragment.column

        out.append(f)

    return out


def save_report(findings: List[Finding], path: str) -> None:
    """
    将 finding 列表保存为当前标准嵌套 JSON 格式。

    必须使用 Finding.to_dict()，不能使用 dataclasses.asdict()。

    原因：
    dataclasses.asdict() 会把 TranslationRuntimeFacts 以内部 snake_case
    字段直接输出：

        {
          "translationRuntimeFacts": {
            "rv_to_operand_index": {...},
            "operand_width_bits": {...}
          }
        }

    而 report / JSON schema 要求使用 camelCase：

        {
          "translationRuntimeFacts": {
            "rvToOperandIndex": {...},
            "operandWidthBits": {...}
          }
        }
    """
    obj = {
        "findings": [
            finding.to_dict()
            for finding in findings
        ]
    }

    with open(path, "w", encoding="utf-8") as fp:
        json.dump(
            obj,
            fp,
            indent=2,
            ensure_ascii=False,
        )