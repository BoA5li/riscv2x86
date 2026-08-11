from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from collections.abc import Mapping


@dataclass(frozen=True)
class TranslationRuntimeFacts:
    """
    Runtime-only facts consumed by translation.

    Authoritative sources:

      * rv_to_operand_index:
          assembler normalization:
          RISC-V register -> GNU inline-asm operand index.

      * operand_width_bits:
          host AST/type analysis:
          GNU inline-asm operand index -> proven host expression width.

    These facts must not be reconstructed from:
      * fragment.outputs / fragment.inputs ordering;
      * p-code register encounter order;
      * expression text;
      * XLEN;
      * serialized fragment JSON bindings.

    They are intentionally runtime-only and must not be written back into
    AsmFragment JSON.
    """

    rv_to_operand_index: Mapping[str, int] = field(
        default_factory=dict
    )
    operand_width_bits: Mapping[int, int] = field(
        default_factory=dict
    )
    provenance: str = ""
    # Phase-4 normalized asm-goto facts.  They are populated only by the
    # restricted beqz/bnez recognizer in assemble.py, never by Phase 6.
    asm_goto_condition_operand_index: int | None = None
    asm_goto_condition_kind: str | None = None


class TranslationFactsError(ValueError):
    """
    assembler normalization / runtime facts 构造失败。

    这类异常仅用于 facts 的生产阶段，例如 assemble.py 完成 GNU inline
    asm placeholder materialization 后，基于实际分配的 RISC-V 寄存器构造
    runtime facts。

    pipeline 消费阶段不应因为该异常直接崩溃；消费阶段应调用
    build_translation_runtime_facts()，获得 TranslationRuntimeFactsResult，
    再由 translator 输出结构化 unsupported / needs_route。
    """


# ---------------------------------------------------------------------------
# RISC-V GPR canonicalization
# ---------------------------------------------------------------------------

# 这里仅定义 RISC-V integer GPR。
#
# 不将 r0/r1/r2 等名称作为 RISC-V alias 接受：
# - r2 在其他 ISA 中未必是 RISC-V sp；
# - 当前事实传递层只负责 RISC-V GNU inline asm / RISC-V p-code；
# - 不能因为名称相似而跨 ISA 猜测寄存器含义。
_RISCV_X_TO_ABI: Dict[str, str] = {
    "x0": "zero",
    "x1": "ra",
    "x2": "sp",
    "x3": "gp",
    "x4": "tp",
    "x5": "t0",
    "x6": "t1",
    "x7": "t2",
    "x8": "s0",
    "x9": "s1",
    "x10": "a0",
    "x11": "a1",
    "x12": "a2",
    "x13": "a3",
    "x14": "a4",
    "x15": "a5",
    "x16": "a6",
    "x17": "a7",
    "x18": "s2",
    "x19": "s3",
    "x20": "s4",
    "x21": "s5",
    "x22": "s6",
    "x23": "s7",
    "x24": "s8",
    "x25": "s9",
    "x26": "s10",
    "x27": "s11",
    "x28": "t3",
    "x29": "t4",
    "x30": "t5",
    "x31": "t6",
}

# 这些 canonical p-code opcode 被视为“普通、局部、确定性的整数数据流”
# operation。
#
# 它们不表达：
#   * return / tail-call / indirect control flow
#   * timing source
#   * cache operation
#   * speculation-control operation
#
# 注意：
#   这里只用于“证明 absence”，所以必须使用保守白名单。
#   不在白名单中的 opcode 一律不应被自动证明为安全。
_PROVEN_PURE_INTEGER_OPCODES: frozenset[str] = frozenset(
    {
        # 基本复制 / 常量传播类。
        "COPY",
        "PIECE",
        "SUBPIECE",

        # 整数算术。
        "INT_ADD",
        "INT_SUB",
        "INT_MULT",
        "INT_DIV",
        "INT_SDIV",
        "INT_REM",
        "INT_SREM",
        "INT_NEGATE",

        # 整数位运算。
        "INT_AND",
        "INT_OR",
        "INT_XOR",
        "INT_NOT",

        # 整数移位。
        "INT_LEFT",
        "INT_RIGHT",
        "INT_SRIGHT",

        # 整数扩展 / 截断。
        "INT_ZEXT",
        "INT_SEXT",

        # 整数比较。
        "INT_EQUAL",
        "INT_NOTEQUAL",
        "INT_LESS",
        "INT_LESSEQUAL",
        "INT_SLESS",
        "INT_SLESSEQUAL",

        # 布尔值运算。
        "BOOL_NEGATE",
        "BOOL_XOR",
        "BOOL_AND",
        "BOOL_OR",
    }
)

# lift / p-code 流中的 instruction marker。
#
# 它们用于标示机器指令边界或调试/归属信息，不表示可执行的
# 数据流、内存访问、控制流或微架构控制语义。
#
# 只能在 canonicalization 已将它们规范化为这些明确 opcode 的情况下
# 忽略。禁止把未知 opcode 当作 marker。
_NON_SEMANTIC_CANONICAL_OPCODES: frozenset[str] = frozenset(
    {
        "IMARK",
    }
)

_RISCV_ABI_REGISTERS = frozenset(_RISCV_X_TO_ABI.values())

# fp 是 s0/x8 的 ABI alias。
_RISCV_REGISTER_ALIASES: Dict[str, str] = {
    "fp": "s0",
}

# 用于从 p-code/SLEIGH/日志风格文本中提取 token，例如：
#
#   x10
#   register:x10
#   register x10
#   ram:x10
#   x10[0:8]
#   a0
_REGISTER_TOKEN_RE = re.compile(r"[a-z][a-z0-9]*")


def canonicalize_riscv_register_name(value: Any) -> str:
    """
    将 RISC-V GPR 的 ABI 名、xN 名及 fp alias 统一为 ABI canonical name。

    示例：

        a0   -> a0
        x10  -> a0

        a1   -> a1
        x11  -> a1

        sp   -> sp
        x2   -> sp

        fp   -> s0
        s0   -> s0
        x8   -> s0

        ra   -> ra
        x1   -> ra

    返回空字符串表示输入中不存在可识别的 RISC-V GPR 名称。

    注意：
    - 该函数仅用于 RISC-V inline asm 与 RISC-V p-code register binding；
    - 不应替代项目中已有的通用 _normalize_register_name()；
    - 不从 r0/r1/r2 形式推断 RISC-V 寄存器；
    - 不处理浮点、向量、CSR 或其他 register class。
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""

    direct = _RISCV_REGISTER_ALIASES.get(text, text)

    if direct in _RISCV_X_TO_ABI:
        return _RISCV_X_TO_ABI[direct]

    if direct in _RISCV_ABI_REGISTERS:
        return direct

    # p-code / SLEIGH 文本可能包含 "register:x10"、
    # "register a0"、"x10[0:8]" 等表示。
    #
    # 从后向前寻找 token，通常最后一个有意义的 token 才是寄存器名。
    tokens = _REGISTER_TOKEN_RE.findall(text)

    for token in reversed(tokens):
        token = _RISCV_REGISTER_ALIASES.get(token, token)

        if token in _RISCV_X_TO_ABI:
            return _RISCV_X_TO_ABI[token]

        if token in _RISCV_ABI_REGISTERS:
            return token

    return ""


# ---------------------------------------------------------------------------
# Phase 3 / Phase 4: assembler normalization facts production
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AsmOperandBinding:
    """
    GNU inline asm operand 与最终 materialized RISC-V register 的绑定。

    operand_index:
        GNU inline asm operand index，例如 %0、%1、%2 的数字部分。

    rv_register:
        实际写入最终规范化 RISC-V 汇编文本的寄存器名称。

        可接受 a0、x10、sp、x2、fp、s0 等 RISC-V ABI/xN 表示；
        build_assembled_translation_runtime_facts() 会将其 canonicalize
        为 ABI 名称。

    当前修订范围只保存最小、明确的 register binding 事实，不实现：

    - complete GNU operand constraint semantics；
    - tied operands；
    - early-clobber；
    - memory operand；
    - immediate operand；
    - floating-point/vector register class；
    - CSR register class；
    - atomics/fence/control-flow semantics。
    """

    operand_index: int
    rv_register: str


def _normalize_assembler_operand_bindings(
    operand_bindings: Sequence[AsmOperandBinding],
) -> Dict[str, int]:
    """
    从 assembler materialization 的实际结果构造：

        canonical RISC-V GPR -> GNU operand index

    不允许一个 canonical GPR 同时绑定到不同 operand index。

    例如以下情况必须拒绝：

        AsmOperandBinding(0, "a0")
        AsmOperandBinding(1, "x10")

    因为 a0 与 x10 canonicalize 后均为 a0，而当前修订不实现 tied
    operand 或完整 constraint 语义，不能静默覆盖或猜测。
    """
    rv_to_operand_index: Dict[str, int] = {}

    for binding in operand_bindings:
        if not isinstance(binding, AsmOperandBinding):
            raise TranslationFactsError(
                "operand_bindings must contain AsmOperandBinding instances; "
                f"got {type(binding).__name__}"
            )

        operand_index = binding.operand_index

        if isinstance(operand_index, bool) or not isinstance(
            operand_index,
            int,
        ):
            raise TranslationFactsError(
                "asm operand index must be an integer: "
                f"{operand_index!r}"
            )

        if operand_index < 0:
            raise TranslationFactsError(
                f"invalid asm operand index: {operand_index}"
            )

        register = canonicalize_riscv_register_name(binding.rv_register)

        if not register:
            raise TranslationFactsError(
                "cannot canonicalize RISC-V register for asm operand: "
                f"operand_index={operand_index}, "
                f"rv_register={binding.rv_register!r}"
            )

        previous = rv_to_operand_index.get(register)

        if previous is not None and previous != operand_index:
            raise TranslationFactsError(
                "one canonical RISC-V register is bound to multiple GNU asm "
                "operands; this revision does not support ambiguous/tied "
                "binding facts: "
                f"register={register!r}, "
                f"existing_operand={previous}, "
                f"new_operand={operand_index}"
            )

        rv_to_operand_index[register] = operand_index

    return rv_to_operand_index


def _normalize_assembler_width_map(
    operand_width_bits: Mapping[int, int] | None,
) -> Dict[int, int]:
    """
    验证 assembler 阶段收到的 host AST/type-analysis width facts。

    这里不从以下来源推断 width：

    - RISC-V XLEN；
    - xN 或 ABI register 名；
    - C expression 文本；
    - 指针大小；
    - p-code varnode size；
    - machine code instruction width。
    """
    normalized_widths: Dict[int, int] = {}

    if operand_width_bits is None:
        return normalized_widths

    if not isinstance(operand_width_bits, Mapping):
        raise TranslationFactsError(
            "operand_width_bits must be a mapping of GNU operand index "
            "to widthBits"
        )

    for raw_index, raw_width in operand_width_bits.items():
        if isinstance(raw_index, bool):
            raise TranslationFactsError(
                "operand_width_bits contains boolean operand index: "
                f"{raw_index!r}"
            )

        try:
            operand_index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise TranslationFactsError(
                "operand_width_bits contains non-integer operand index: "
                f"{raw_index!r}"
            ) from exc

        if operand_index < 0:
            raise TranslationFactsError(
                "operand_width_bits contains negative operand index: "
                f"{operand_index}"
            )

        if isinstance(raw_width, bool) or not isinstance(raw_width, int):
            raise TranslationFactsError(
                f"operand_width_bits[{operand_index}] must be an integer width"
            )

        if raw_width <= 0:
            raise TranslationFactsError(
                f"operand_width_bits[{operand_index}] must be positive, "
                f"got {raw_width}"
            )

        normalized_widths[operand_index] = raw_width

    return normalized_widths


def build_assembled_translation_runtime_facts(
    *,
    operand_bindings: Sequence[AsmOperandBinding],
    operand_width_bits: Mapping[int, int] | None = None,
) -> TranslationRuntimeFacts:
    """
    Phase 3 / Phase 4 使用的 facts 构造入口。

    assemble.py 在 GNU inline asm template materialization 完成后必须调用
    本函数，并将结果保存到：

        AssembleResult.translation_runtime_facts

    数据来源要求：

    1. operand_bindings 必须来自最终 materialized asm 实际使用的寄存器；
    2. operand_width_bits 必须来自 host AST/type analysis；
    3. 不得从 p-code register order、operand array order、XLEN、exprText、
       C 文本或 register number 推断 binding/width。

    返回的 facts 使用 canonical ABI register name，例如：

        {
            "a0": 0,
            "a1": 1,
            "sp": 2,
        }

    即使最终汇编中使用的是 x10、x11、x2，p-code lowerer 也可通过
    canonicalize_riscv_register_name() 正确解析为 a0、a1、sp。
    """
    rv_to_operand_index = _normalize_assembler_operand_bindings(
        operand_bindings
    )
    normalized_widths = _normalize_assembler_width_map(
        operand_width_bits
    )

    return TranslationRuntimeFacts(
        rv_to_operand_index=rv_to_operand_index,
        operand_width_bits=normalized_widths,
    )


def translation_runtime_facts_to_dict(
    facts: TranslationRuntimeFacts,
) -> Dict[str, Any]:
    """
    将 TranslationRuntimeFacts 转换为 finding / JSON 使用的 camelCase 格式。

    输出格式：

        {
            "rvToOperandIndex": {
                "a0": 0,
                "a1": 1,
            },
            "operandWidthBits": {
                0: 64,
                1: 64,
            },
        }

    JSON 序列化后 operandWidthBits 的 key 可能变成字符串；对应的读取和
    规范化由 build_translation_runtime_facts() 完成。
    """
    return {
        "rvToOperandIndex": dict(facts.rv_to_operand_index),
        "operandWidthBits": dict(facts.operand_width_bits),
        "asmGotoConditionKind": facts.asm_goto_condition_kind,
        "asmGotoConditionOperandIndex": facts.asm_goto_condition_operand_index,
    }
    
def translation_runtime_facts_from_dict(
    value: Optional[Mapping[str, Any]],
) -> Optional[TranslationRuntimeFacts]:
    """
    从 finding / JSON camelCase 格式恢复 TranslationRuntimeFacts。

    读取阶段也必须执行与 pipeline 一致的 RISC-V register canonicalization、
    alias conflict 检查和 width map 校验，避免：

        {"a0": 0, "x10": 1}

    这种事实冲突进入后续 lowerer。
    """
    if value is None:
        return None

    if not isinstance(value, Mapping):
        raise ValueError(
            "translationRuntimeFacts must be an object or null, "
            f"got {type(value).__name__}"
        )

    raw_rv_to_operand = value.get(
        "rvToOperandIndex",
        value.get("rv_to_operand_index", {}),
    )
    raw_operand_widths = value.get(
        "operandWidthBits",
        value.get("operand_width_bits", {}),
    )
    asm_goto_condition_kind = value.get(
        "asmGotoConditionKind",
        value.get("asm_goto_condition_kind"),
    )
    asm_goto_condition_operand_index = value.get(
        "asmGotoConditionOperandIndex",
        value.get("asm_goto_condition_operand_index"),
    )

    if raw_rv_to_operand is None:
        raw_rv_to_operand = {}

    if raw_operand_widths is None:
        raw_operand_widths = {}

    rv_to_operand_index, register_errors = _normalize_register_map(
        raw_rv_to_operand
    )
    operand_width_bits, width_errors = _normalize_width_map(
        raw_operand_widths
    )

    errors = [*register_errors, *width_errors]

    if errors:
        raise ValueError(
            "invalid translationRuntimeFacts: " + "; ".join(errors)
        )

    if asm_goto_condition_kind not in {None, "zero", "nonzero"}:
        raise ValueError("translationRuntimeFacts has unsupported asm-goto condition kind")
    if asm_goto_condition_operand_index is not None:
        if (isinstance(asm_goto_condition_operand_index, bool) or
                not isinstance(asm_goto_condition_operand_index, int) or
                asm_goto_condition_operand_index < 0):
            raise ValueError("translationRuntimeFacts has invalid asm-goto condition operand index")
    if ((asm_goto_condition_kind is None) !=
            (asm_goto_condition_operand_index is None)):
        raise ValueError("translationRuntimeFacts requires both asm-goto condition fields")

    # serialized facts 若包含 register binding，则每一个绑定 operand
    # 都必须具有 host-derived width。
    for operand_index in sorted(set(rv_to_operand_index.values())):
        if operand_index not in operand_width_bits:
            raise ValueError(
                "translationRuntimeFacts is missing operandWidthBits for "
                f"bound GNU operand %{operand_index}"
            )

    return TranslationRuntimeFacts(
        rv_to_operand_index=rv_to_operand_index,
        operand_width_bits=operand_width_bits,
        asm_goto_condition_kind=asm_goto_condition_kind,
        asm_goto_condition_operand_index=asm_goto_condition_operand_index,
    )

# ---------------------------------------------------------------------------
# Phase 4 / Phase 5 / Phase 6: pipeline facts extraction and validation
# ---------------------------------------------------------------------------

@dataclass
class TranslationRuntimeFactsResult:
    """
    Phase 4/5/6 之间传递的 runtime facts 构建结果。

    ok:
        True:
            facts 完整通过格式验证，可供 translate() 使用。

        False:
            facts 缺失或格式非法。

    注意：
    即使 ok=False，facts 仍返回一个空 TranslationRuntimeFacts，使 pipeline
    可以继续进入 translate()，由 translator 输出结构化 unsupported /
    needs_route，而不是在 pipeline 内崩溃。

    为避免错误的部分事实被 translator 误用，ok=False 时本类的 facts
    保证为空，而不会保留部分解析成功的数据。
    """

    ok: bool
    facts: TranslationRuntimeFacts
    error: str = ""


def _read_field(obj: Any, *names: str, default=None):
    """
    兼容 dataclass、SimpleNamespace、普通对象和 Mapping。

    names 的顺序即优先级。支持 snake_case 与 camelCase 字段。
    """
    if obj is None:
        return default

    for name in names:
        if isinstance(obj, Mapping):
            if name in obj:
                return obj[name]
        elif hasattr(obj, name):
            return getattr(obj, name)

    return default


def _normalize_register_map(raw: Any) -> tuple[Dict[str, int], List[str]]:
    """
    验证并 canonicalize：

        RISC-V register -> GNU operand index

    本函数不根据 operand 顺序、p-code 顺序、exprText、XLEN 或 C 文本推断
    binding。所有 binding 必须是 assembler normalization 阶段显式产生的事实。

    同时会拒绝如下 alias 冲突：

        {
            "a0": 0,
            "x10": 1,
        }

    因为 x10 canonicalize 后也是 a0。
    """
    result: Dict[str, int] = {}
    errors: List[str] = []

    if raw is None:
        return result, errors

    if not isinstance(raw, Mapping):
        return result, [
            "rv_to_operand_index must be a mapping of RISC-V register "
            "name to GNU operand index"
        ]

    for raw_register, raw_index in raw.items():
        register = canonicalize_riscv_register_name(raw_register)

        if not register:
            errors.append(
                "rv_to_operand_index contains an invalid or unsupported "
                f"RISC-V GPR name: {raw_register!r}"
            )
            continue

        if isinstance(raw_index, bool) or not isinstance(raw_index, int):
            errors.append(
                f"rv_to_operand_index[{register!r}] must be an integer "
                "GNU operand index"
            )
            continue

        if raw_index < 0:
            errors.append(
                f"rv_to_operand_index[{register!r}] has negative operand "
                f"index {raw_index}"
            )
            continue

        previous = result.get(register)

        if previous is not None and previous != raw_index:
            errors.append(
                "rv_to_operand_index contains conflicting aliases for "
                f"canonical register {register!r}: "
                f"existing_operand={previous}, "
                f"new_operand={raw_index}"
            )
            continue

        result[register] = raw_index

    return result, errors


def _normalize_width_map(raw: Any) -> tuple[Dict[int, int], List[str]]:
    """
    验证 host AST/type-analysis 产生的：

        GNU operand index -> widthBits

    不从 C expression 文本、指针大小、RISC-V XLEN、p-code varnode size
    或 register 名推断 width。
    """
    result: Dict[int, int] = {}
    errors: List[str] = []

    if raw is None:
        return result, errors

    if not isinstance(raw, Mapping):
        return result, [
            "operand_width_bits must be a mapping of GNU operand index "
            "to widthBits"
        ]

    for raw_index, raw_width in raw.items():
        if isinstance(raw_index, bool):
            errors.append(
                "operand_width_bits contains boolean operand index "
                f"{raw_index!r}"
            )
            continue

        try:
            operand_index = int(raw_index)
        except (TypeError, ValueError):
            errors.append(
                "operand_width_bits contains non-integer operand index "
                f"{raw_index!r}"
            )
            continue

        if operand_index < 0:
            errors.append(
                "operand_width_bits contains negative operand index "
                f"{operand_index}"
            )
            continue

        if isinstance(raw_width, bool) or not isinstance(raw_width, int):
            errors.append(
                f"operand_width_bits[{operand_index}] must be an integer width"
            )
            continue

        if raw_width <= 0:
            errors.append(
                f"operand_width_bits[{operand_index}] must be positive, "
                f"got {raw_width}"
            )
            continue

        result[operand_index] = raw_width

    return result, errors


def _extract_runtime_fact_container(
    *,
    finding: Any,
    assemble_result: Any,
) -> Any:
    """
    提取 assembler normalization 阶段已经构造的 runtime fact container。

    首选：

        assemble_result.translation_runtime_facts

    兼容以下同义字段：

        translation_runtime_facts
        translationRuntimeFacts
        runtime_facts
        runtimeFacts

    只有 assemble_result 完全不携带 facts 时，才回退读取 finding 中的 facts。

    不从以下来源重建 register -> operand binding：

    - fragment.outputs；
    - fragment.inputs；
    - fragment.materializedOperandBindings；
    - GNU operand 数组顺序；
    - p-code register encounter order；
    - C expression 文本；
    - XLEN。
    """
    candidates = [
        _read_field(
            assemble_result,
            "translation_runtime_facts",
            "translationRuntimeFacts",
            "runtime_facts",
            "runtimeFacts",
            default=None,
        ),
        _read_field(
            finding,
            "translation_runtime_facts",
            "translationRuntimeFacts",
            "runtime_facts",
            "runtimeFacts",
            default=None,
        ),
    ]

    for candidate in candidates:
        if candidate is not None:
            return candidate

    return None


def _empty_facts() -> TranslationRuntimeFacts:
    """
    每次构造新对象，避免潜在共享可变字典问题。
    """
    return TranslationRuntimeFacts(
        rv_to_operand_index={},
        operand_width_bits={},
    )

def build_translation_runtime_facts(
    *,
    finding: Any,
    assemble_result: Any,
) -> TranslationRuntimeFactsResult:
    """
    从 assemble 产物提取、校验并规范化 TranslationRuntimeFacts。

    事实来源约束：

    1. rv_to_operand_index：
       必须来自本次 assemble() 使用的同一次 inline-asm materialization；

    2. operand_width_bits：
       必须来自调用 assemble() 时传入的 host AST/type-analysis facts；

    assemble() 已经将这两类 facts 写入：

        assemble_result.translation_runtime_facts

    因此本函数不能优先读取 finding 中可能过期、反序列化或尚未回填的
    facts，更不能重新根据 operand 顺序、xN、p-code 等信息构造 facts。

    3. 本函数绝不根据以下来源猜测 binding 或 width：

       - operand 数组顺序；
       - p-code 中 register 出现顺序；
       - C expression 文本；
       - XLEN；
       - fragment.materializedOperandBindings；
       - RISC-V xN 编号；
       - p-code varnode size。

    处理策略：

    - assemble facts 缺失：返回 ok=False、空 facts；
    - facts 格式非法：返回 ok=False、空 facts；
    - 任意被绑定 GNU operand 缺失 widthBits：返回 ok=False、空 facts；
    - facts 合法：返回 ok=True、canonicalized facts；
    - register name 可为 x10/a0/fp/s0 等任意已支持 RISC-V GPR 名，
      返回结果统一使用 ABI canonical name。
    """

    # 不使用 _extract_runtime_fact_container()。
    #
    # 原因：该 helper 若从 finding 回退或优先读取 finding，会让
    # Phase 4 已由 assemble() 构造好的 host width facts 被旧数据覆盖。
    #
    # 当前阶段唯一允许的 container 是本次 assemble() 的产物。
    container = _read_field(
        assemble_result,
        "translation_runtime_facts",
        "translationRuntimeFacts",
        default=None,
    )

    if container is None:
        return TranslationRuntimeFactsResult(
            ok=False,
            facts=_empty_facts(),
            error=(
                "missing assembled translation runtime facts: assemble() "
                "must preserve assembler-normalized rv_to_operand_index and "
                "host AST/type-analysis operand_width_bits"
            ),
        )

    raw_register_map = _read_field(
        container,
        "rv_to_operand_index",
        "rvToOperandIndex",
        default=None,
    )
    raw_width_map = _read_field(
        container,
        "operand_width_bits",
        "operandWidthBits",
        default=None,
    )

    rv_to_operand_index, register_errors = _normalize_register_map(
        raw_register_map
    )
    operand_width_bits, width_errors = _normalize_width_map(
        raw_width_map
    )

    errors: List[str] = [
        *register_errors,
        *width_errors,
    ]

    if raw_register_map is None:
        errors.append(
            "missing assembler-normalized field rv_to_operand_index"
        )

    if raw_width_map is None:
        errors.append(
            "missing host AST/type-analysis field operand_width_bits"
        )

    # 重要：width map 非空还不够。
    #
    # 必须确认每一个实际 materialize 到 RISC-V register 的 GNU operand
    # 都具有 host type width。
    #
    # 例如：
    #
    #   rv_to_operand_index = {"a0": 0, "a1": 1, "a2": 2}
    #   operand_width_bits = {0: 64}
    #
    # 这是不完整 facts，不能允许 Phase 6 去猜测 operand %1/%2 的宽度。
    #
    # 注意：不要求 width map 覆盖未绑定的 immediate / label operand；
    # 只要求覆盖真正存在于 register binding map 中的 operand。
    if not errors:
        required_operand_indices = sorted(set(rv_to_operand_index.values()))

        for operand_index in required_operand_indices:
            if operand_index not in operand_width_bits:
                errors.append(
                    "missing host AST/type-analysis widthBits for "
                    f"GNU operand %{operand_index}, which is bound by "
                    "assembler normalization to a RISC-V register"
                )

    if errors:
        return TranslationRuntimeFactsResult(
            ok=False,
            facts=_empty_facts(),
            error="; ".join(errors),
        )

    # 这里创建的是 canonicalized copy：
    #
    #   - register 名已由 _normalize_register_map() 规范化；
    #   - operand index / width 已由 _normalize_width_map() 验证；
    #
    # 但其信息来源仍然是 assemble_result.translation_runtime_facts，
    # 而不是 finding、p-code、寄存器编号或 XLEN。
    return TranslationRuntimeFactsResult(
        ok=True,
        facts=TranslationRuntimeFacts(
            rv_to_operand_index=rv_to_operand_index,
            operand_width_bits=operand_width_bits,
        ),
    )
