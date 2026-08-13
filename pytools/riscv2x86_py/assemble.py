from __future__ import annotations

import os
import re
from dataclasses import replace
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List,  Mapping, Optional, Sequence, Tuple

from .schema import AsmFragment
from .runtime_facts import (
    AsmOperandBinding,
    TranslationRuntimeFacts,
    build_assembled_translation_runtime_facts,
)


@dataclass
class RelocEntry:
    offset: int
    # 保持旧语义：对应 frag.symbols 的下标。
    #
    # 对本地标签、section symbol、".+N"/".-N" 等无法映射到 frag.symbols
    # 的 relocation，使用 -1。其 ELF 层面的实际 symbol 信息由
    # elf_sym_index / symbol_name / symbol_value 保存。
    sym_index: int
    kind: str

    # ELF relocation 的补充信息。保留它们可以正确表达：
    #   symbol + offset
    #   . + offset
    #   section-relative symbol
    #   local label
    symbol_name: Optional[str] = None
    addend: int = 0
    elf_sym_index: Optional[int] = None
    symbol_value: Optional[int] = None

@dataclass(frozen=True)
class MaterializedInlineAsm:
    """
    inline asm 模板物化后的权威结果。

    normalized_asm:
        最终送入后续 asm-unit 渲染/llvm-mc 的 fragment body 文本。
        尚不包含 .text、PIC stub 等外围汇编单元内容。

    operand_bindings:
        GNU inline-asm operand index -> 实际 RISC-V 物理寄存器。

        注意：
          * register 必须是纯寄存器名，例如 "x10"；
          * 不应记录 "(x10)"；
          * tied operand 可以共享同一个 rv_register；
          * 一个 operand 若在模板中多次出现，只记录一次。
    """
    normalized_asm: str
    operand_bindings: List[AsmOperandBinding]
    # synthetic assembler label -> authoritative C asm-goto label.  This is
    # provenance only; the synthetic label is never rendered back to C.
    asm_goto_targets: Dict[str, str] = field(default_factory=dict)


@dataclass
class AssembleResult:
    ok: bool
    machine_code: bytes
    insn_listing: List[Tuple[int, bytes, str]]
    error: str = ""
    rendered_asm: str = ""
    relocations: List[RelocEntry] = field(default_factory=list)

    # ------------------------------------------------------------------
    # 权威运行时事实：
    #
    # 后续 translator / lowerer / analysis 不应再根据 rendered_asm、
    # rv_to_operand_index 或 placeholder 分配规则重新推导 operand-register
    # 关系，而必须消费该字段。
    # ------------------------------------------------------------------
    translation_runtime_facts: TranslationRuntimeFacts = field(
        default_factory=TranslationRuntimeFacts
    )

    # ------------------------------------------------------------------
    # 兼容字段。
    #
    # 这些字段不再是权威来源。若项目中仍有旧调用方依赖它们，可暂时保留。
    # 新代码应使用 translation_runtime_facts。
    # ------------------------------------------------------------------
    rv_to_operand_index: Dict[str, int] = field(default_factory=dict)

    # 如果当前 runtime_facts.py 中实际类型就是 AsmOperandBinding，
    # 请统一使用它，不要保留 MaterializedOperandBinding 这种平行类型。
    materialized_operand_bindings: List[AsmOperandBinding] = field(
        default_factory=list
    )


_PLACEHOLDER_REGS_INT = [
    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
    "x5", "x6", "x7", "x28", "x29", "x30", "x31",
]


_ATOMIC_ASM_RE = re.compile(
    r"(?im)^\s*(?:"
    r"amo[a-z0-9_.]+|"
    r"lr\.(?:w|d)(?:\.[a-z0-9_]+)?|"
    r"sc\.(?:w|d)(?:\.[a-z0-9_]+)?"
    r")\b"
)

_ARCH_PLUS_A_RE = re.compile(
    r"(?im)^\s*\.option\s+arch\s*,\s*\+a\s*$"
)


def _raw_asm_uses_atomic_ext(text: str) -> bool:
    return bool(_ATOMIC_ASM_RE.search(text or ""))


def _rendered_asm_has_plus_a(text: str) -> bool:
    return bool(_ARCH_PLUS_A_RE.search(text or ""))


# ---------------- 操作数占位符渲染 ----------------

def _operand_placeholder(op, idx: int) -> str:
    reg = _PLACEHOLDER_REGS_INT[idx % len(_PLACEHOLDER_REGS_INT)]
    c = (getattr(op, "constraint", "") or "").strip()
    normalized = c.replace("=", "").replace("+", "").replace("&", "").replace("%", "")

    if "A" in normalized or "m" in normalized:
        return f"({reg})"
    return reg


def _line_mnemonic(line: str) -> str:
    s = line.strip()
    if not s:
        return ""
    s = s.split("#", 1)[0].strip()
    if not s:
        return ""

    m = re.match(r"^\d+:\s*(.*)$", s)
    if m:
        s = m.group(1).strip()
        if not s:
            return ""

    parts = s.split(None, 1)
    return parts[0].lower() if parts else ""


def _is_amo_mnemonic(mn: str) -> bool:
    return mn.startswith("amo")


def _is_lr_mnemonic(mn: str) -> bool:
    return mn.startswith("lr.")


def _is_sc_mnemonic(mn: str) -> bool:
    return mn.startswith("sc.")


def _address_operand_position(mnemonic: str, op_pos: int) -> bool:
    if _is_lr_mnemonic(mnemonic):
        return op_pos == 1
    if _is_sc_mnemonic(mnemonic):
        return op_pos == 2
    if _is_amo_mnemonic(mnemonic):
        return op_pos == 2
    return False


def _fallback_placeholder_for_operand_position(mnemonic: str, op_pos: int, reg: str) -> str:
    if _address_operand_position(mnemonic, op_pos):
        return f"({reg})"
    return reg


def _placeholder_is_explicitly_parenthesized(line: str, start: int, end: int) -> bool:
    left = start - 1
    while left >= 0 and line[left].isspace():
        left -= 1

    right = end
    while right < len(line) and line[right].isspace():
        right += 1

    return left >= 0 and right < len(line) and line[left] == "(" and line[right] == ")"


def _fragment_references_symbols(frag: AsmFragment) -> bool:
    """
    判断 fragment 的 rawAsmText 中是否引用了 PIC 相关符号。
    出现 %pcrel_hi / %pcrel_lo / la 伪指令时即视为 PIC。
    """
    text = frag.rawAsmText or ""
    if re.search(r"%\s*pcrel_(hi|lo)\s*\(", text, re.IGNORECASE):
        return True
    if re.search(r"\bla\s+", text):
        return True
    return False


def _constraint_tied_target(
    constraint: str,
    symbolic_name_to_idx: Dict[str, int],
) -> Optional[int]:
    """
    从 GCC inline-asm matching constraint 中提取绑定目标。

    支持：
      "0"
      "1"
      "[dst]"

    对 "0,r" 这类多 alternative constraint，只有所有可识别
    alternative 都指向同一 target 时才接受；否则返回 None，
    避免静默作出错误选择。
    """
    c = (constraint or "").strip()
    if not c:
        return None

    targets = set()

    for alt in c.split(","):
        alt = alt.strip()

        m_num = re.fullmatch(r"\d+", alt)
        if m_num:
            targets.add(int(alt))
            continue

        m_name = re.fullmatch(r"\[([A-Za-z_][A-Za-z0-9_]*)\]", alt)
        if m_name:
            name = m_name.group(1)
            if name not in symbolic_name_to_idx:
                raise ValueError(
                    f"unknown symbolic tied operand name: [{name}]"
                )
            targets.add(symbolic_name_to_idx[name])

    if len(targets) == 1:
        return next(iter(targets))

    # 0 个：不是 matching constraint；
    # >1 个：多 alternative 的绑定关系不确定，不能静默猜测。
    return None


def _build_operand_aliases(operands) -> List[int]:
    """
    返回每个 operand 最终应复用的 operand index。

    例如：
      outputs: [ "=r" ]
      inputs:  [ "0", "r" ]

    返回：
      [0, 0, 2]

    即 %1 与 %0 使用同一个 placeholder register。
    """
    name_to_idx: Dict[str, int] = {}

    for i, op in enumerate(operands):
        name = (getattr(op, "symbolicName", None) or "").strip()
        if name:
            if name in name_to_idx:
                raise ValueError(f"duplicate symbolic operand name: [{name}]")
            name_to_idx[name] = i

    aliases = list(range(len(operands)))

    for i, op in enumerate(operands):
        target = _constraint_tied_target(
            getattr(op, "constraint", "") or "",
            name_to_idx,
        )
        if target is None:
            continue

        if not (0 <= target < len(operands)):
            raise ValueError(
                f"tied operand %{i} references out-of-range operand %{target}"
            )

        aliases[i] = target

    # 解析链式 alias，如 %2 -> %1 -> %0。
    def resolve(i: int) -> int:
        seen = set()
        cur = i

        while aliases[cur] != cur:
            if cur in seen:
                raise ValueError(f"cyclic tied operand constraint involving %{i}")
            seen.add(cur)
            cur = aliases[cur]

        return cur

    return [resolve(i) for i in range(len(operands))]

def _split_asm_statements(line: str) -> List[str]:
    """
    将单行 asm 模板按顶层分号拆分为多条汇编语句。

    规则：
      - 顶层 ';' 是语句分隔符；
      - 单引号/双引号中的 ';' 不拆分；
      - RISC-V '#' 注释后的 ';' 不拆分；
      - 支持反斜杠转义；
      - 每条语句 strip()，保证输出稳定。
    """
    out: List[str] = []
    current: List[str] = []

    quote = ""
    escaped = False

    i = 0
    while i < len(line or ""):
        ch = line[i]

        if escaped:
            current.append(ch)
            escaped = False
            i += 1
            continue

        if ch == "\\":
            current.append(ch)
            escaped = True
            i += 1
            continue

        if quote:
            current.append(ch)

            if ch == quote:
                quote = ""

            i += 1
            continue

        if ch in ('"', "'"):
            current.append(ch)
            quote = ch
            i += 1
            continue

        # RISC-V 汇编中 # 后面属于注释，注释中的分号不是语句分隔符。
        if ch == "#":
            current.extend(line[i:])
            break

        if ch == ";":
            stmt = "".join(current).strip()

            if stmt:
                out.append(stmt)

            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    stmt = "".join(current).strip()

    if stmt:
        out.append(stmt)

    return out

def materialize_template(frag: AsmFragment) -> MaterializedInlineAsm:
    """
    将 C/GCC 风格 inline asm 模板转换为可供 RISC-V llvm-mc 装配的
    规范化汇编文本，并在实际 %N materialization 现场记录：

        GNU asm operand index -> 实际 RISC-V placeholder register

    返回的 operand_bindings 是后续 translation/runtime-facts 阶段的
    权威来源。后续阶段不得通过扫描 normalized_asm/rendered_asm，或重新
    执行 placeholder 分配规则来推导 operand-register 绑定关系。

    处理内容：
      1. %[name] -> %N 的 symbolic operand 展开；
      2. %% -> % 的转义保护；
      3. matching/tied operand，例如 input constraint "0" 或 "[dst]"；
      4. memory / atomic address operand 的括号形式；
      5. 顶层 ';' 拆分为独立汇编语句；
      6. 每个拆分后的语句清理首尾空白；
      7. 数字局部标签独占一行；
      8. 收集实际 materialization 使用的 operand -> rv register binding。
    """
    text = frag.rawAsmText or ""
    operands = list(frag.outputs) + list(frag.inputs)
    operand_aliases = _build_operand_aliases(operands)

    # GNU asm-goto placeholders are not ordinary named operands.  Materialize
    # them into private local labels so llvm-mc/lifting can observe the branch
    # edge, while keeping the source C-label mapping as structured provenance.
    goto_targets: Dict[str, str] = {}
    for edge in list(getattr(frag, "gotoEdges", ()) or ()):
        asm_target = str(getattr(edge, "asmTarget", "")).strip()
        c_label = str(getattr(edge, "cLabel", "")).strip()
        exit_code = getattr(edge, "exitCode", None)
        if not asm_target or not c_label or not isinstance(exit_code, int):
            raise ValueError("incomplete asm-goto source edge")
        synthetic = f".Lriscv2x86_asm_goto_{exit_code}"
        goto_targets[synthetic] = c_label
        text = text.replace(asm_target, synthetic)
        text = text.replace(f"%l[{c_label}]", synthetic)
    if "%l" in text:
        raise ValueError("unbound asm-goto label placeholder")

    # ------------------------------------------------------------------
    # 1) 处理 named operand：%[name] -> %N
    # ------------------------------------------------------------------
    name_to_idx: Dict[str, int] = {}

    for idx, op in enumerate(operands):
        symbolic_name = getattr(op, "symbolicName", None)

        if symbolic_name:
            symbolic_name = str(symbolic_name).strip()

            if symbolic_name in name_to_idx:
                raise ValueError(
                    f"duplicate symbolic asm operand name: [{symbolic_name}]"
                )

            name_to_idx[symbolic_name] = idx

    def replace_named_operand(m) -> str:
        name = m.group(1)

        if name not in name_to_idx:
            # 禁止未知 named operand 静默降级成 %0。
            raise ValueError(f"unknown symbolic asm operand: [{name}]")

        return f"%{name_to_idx[name]}"

    text = re.sub(
        r"%\[([A-Za-z_][A-Za-z0-9_]*)\]",
        replace_named_operand,
        text,
    )

    # ------------------------------------------------------------------
    # 2) 保护 %%。
    #
    # GCC inline asm 中 %% 表示字面量百分号。例如：
    #   "mv %0, %%tp"
    #
    # 在后续 %N 替换前必须先保护，否则会被错误识别为 operand。
    # ------------------------------------------------------------------
    pct_marker = "\x00PCT\x00"
    text = text.replace("%%", pct_marker)

    # ------------------------------------------------------------------
    # 3) 权威 operand -> register binding 收集。
    #
    # 注意 key 必须是模板中实际出现的 operand index n，而不是 canonical_n。
    #
    # 例如：
    #
    #   outputs: [ "=r" ]   # %0
    #   inputs:  [ "0" ]    # %1 tied to %0
    #
    # 则：
    #
    #   %0 -> x10
    #   %1 -> x10
    #
    # 必须记录两条 binding。不能只记录 canonical operand %0。
    #
    # 对于越界的 %N，保留原有 fallback 渲染行为，但不产生 binding。
    # 因为它不对应 fragment.outputs + fragment.inputs 中的合法 C operand。
    # ------------------------------------------------------------------
    register_by_operand_index: Dict[int, str] = {}

    # ------------------------------------------------------------------
    # 4) 逐行、逐语句处理 %N。
    #
    # 注意：不能使用 text.replace(";", "\n")，因为那会：
    #   - 使分号后残留无语义前导空格；
    #   - 错误拆分 ".ascii \"a;b\"" 这类字符串中的分号。
    # ------------------------------------------------------------------
    out_lines: List[str] = []

    for raw_line in text.splitlines():
        for line in _split_asm_statements(raw_line):
            mnemonic = _line_mnemonic(line)
            op_pos = 0

            def repl(m) -> str:
                nonlocal op_pos

                n = int(m.group(1))

                if 0 <= n < len(operands):
                    # tied/matching operand 必须复用其目标 output 的寄存器。
                    #
                    # 例如：
                    #   outputs: [ "=r" ]
                    #   inputs:  [ "0" ]
                    #
                    # 则 operand #1 的 canonical_n 为 #0。
                    canonical_n = operand_aliases[n]

                    reg = _PLACEHOLDER_REGS_INT[
                        canonical_n % len(_PLACEHOLDER_REGS_INT)
                    ]

                    # ------------------------------------------------------
                    # 权威 binding 只能在这里记录。
                    #
                    # reg 必须是纯寄存器名，例如 "x10"；不能记录 "(x10)"。
                    # 即使最终 asm 中该 operand 被 materialize 为 "(x10)"，
                    # runtime facts 中也仍应记录 "x10"。
                    # ------------------------------------------------------
                    register_by_operand_index[n] = reg

                    # 模板本身已经写了 (%N) 时，不重复加括号。
                    if _placeholder_is_explicitly_parenthesized(
                        line,
                        m.start(),
                        m.end(),
                    ):
                        rendered = reg

                    # lr/sc/amo 等汇编指令的位置语义要求地址 operand。
                    #
                    # 例如：
                    #   lr.w %0, %1
                    #
                    # 其中地址位置的 %1 应 materialize 为：
                    #   lr.w x10, (x11)
                    elif _address_operand_position(mnemonic, op_pos):
                        rendered = f"({reg})"

                    # 普通 operand 根据 constraint 决定寄存器或内存占位形式。
                    #
                    # _operand_placeholder() 对 "m"/"A" 等 memory constraint
                    # 返回 "(xN)"，普通 register constraint 返回 "xN"。
                    else:
                        rendered = _operand_placeholder(
                            operands[canonical_n],
                            canonical_n,
                        )

                else:
                    # 对超出 outputs + inputs 范围的 %N，延续既有 fallback 行为。
                    #
                    # 此类 placeholder 不属于合法的 fragment operand，不能作为
                    # TranslationRuntimeFacts 中的 operand binding。
                    reg = _PLACEHOLDER_REGS_INT[
                        n % len(_PLACEHOLDER_REGS_INT)
                    ]

                    rendered = _fallback_placeholder_for_operand_position(
                        mnemonic,
                        op_pos,
                        reg,
                    )

                op_pos += 1
                return rendered

            # 使用 %(\d+) 而不是逐字符替换，确保：
            #
            #   %10
            #
            # 被识别为 operand 10，而不会先错误替换为 %1 + "0"。
            new_line = re.sub(r"%(\d+)", repl, line)
            out_lines.append(new_line)

    normalized_asm = "\n".join(out_lines)
    if goto_targets:
        normalized_asm += "\n" + "\n".join(f"{label}:" for label in goto_targets)

    # ------------------------------------------------------------------
    # 5) 恢复字面百分号。
    # ------------------------------------------------------------------
    normalized_asm = normalized_asm.replace(pct_marker, "%")

    # ------------------------------------------------------------------
    # 6) 让数字局部标签独占一行。
    #
    # 例如：
    #   1: add x10, x10, x11
    #
    # 规范化为：
    #   1:
    #   add x10, x10, x11
    # ------------------------------------------------------------------
    normalized_asm = re.sub(
        r"(?m)^(\s*\d+:)\s+(.+)$",
        r"\1\n\2",
        normalized_asm,
    )

    # 按 operand index 稳定排序，确保结果可复现。
    operand_bindings = [
        AsmOperandBinding(
            operand_index=operand_index,
            rv_register=rv_register,
        )
        for operand_index, rv_register in sorted(
            register_by_operand_index.items()
        )
    ]

    return MaterializedInlineAsm(
        normalized_asm=normalized_asm,
        operand_bindings=operand_bindings,
        asm_goto_targets=goto_targets,
    )


def _asm_goto_condition_fact(frag: AsmFragment) -> tuple[str | None, int | None]:
    """Transport a frontend host-C condition fact; never parse asm here."""
    kind = getattr(frag, "asmGotoConditionKind", "") or None
    index = getattr(frag, "asmGotoConditionOperandIndex", -1)
    if kind not in {"zero", "nonzero"} or not isinstance(index, int) or index < 0:
        return (None, None)
    return (kind, index)
    
def _build_pic_stub(frag: AsmFragment) -> str:
    """
    为 PIC 装配生成外部符号声明。

    只把 frag.symbols 中出现的名字声明为外部全局符号，
    不在当前 .o 内定义实体；这样 %pcrel_hi/%pcrel_lo / la
    会尽量保留为 relocation，供后续 lift / translator 使用。
    """
    if not frag.symbols:
        return (
            "  .option pic\n"
            "  .option rvc\n"
            "  .text\n"
        )

    seen = set()
    parts = [
        "  .option pic",
        # 显式允许汇编模板使用 c.addi、c.j、c.beqz、c.jr 等 C 扩展指令。
        # 真正的 ISA 扩展启用仍由 llvm-mc 的 -mattr=+c 决定。
        "  .option rvc",
    ]

    for sym in frag.symbols:
        name = (getattr(sym, "asmName", "") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        parts.append(f"  .globl {name}")

    parts.append("  .text")
    return "\n".join(parts) + "\n"


def _find_llvm_mc() -> Optional[str]:
    candidates = [
        "llvm-mc-18", "llvm-mc-17", "llvm-mc-16", "llvm-mc-15",
        "llvm-mc-14", "llvm-mc-13", "llvm-mc-12", "llvm-mc-11",
        "llvm-mc-10", "llvm-mc", "llvm-mc-9", "llvm-mc-8",
        "llvm-mc-7", "llvm-mc-6.0",
    ]
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def _find_llvm_objdump() -> Optional[str]:
    candidates = [
        "llvm-objdump-18", "llvm-objdump-17", "llvm-objdump-16", "llvm-objdump-15",
        "llvm-objdump-14", "llvm-objdump-13", "llvm-objdump-12", "llvm-objdump-11",
        "llvm-objdump-10", "llvm-objdump", "llvm-objdump-9", "llvm-objdump-8",
        "llvm-objdump-7", "llvm-objdump-6.0",
    ]
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def _llvm_mc_supports_riscv(llvm_mc: str) -> bool:
    try:
        proc = subprocess.run([llvm_mc, "--version"], capture_output=True, text=True)
    except OSError:
        return False
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    out = out.lower()
    return ("riscv32" in out) or ("riscv64" in out)


def _llvm_mc_features(xlen: int) -> str:
    """
    返回 llvm-mc 装配当前转换链路所需的 RISC-V target features。

    I 是 RISC-V 基础整数 ISA，由 riscv32/riscv64 triple 隐含，不需要
    作为 -mattr 单独传入。

    这里统一启用：
      - M：乘除法扩展；
      - A：LR/SC 以及 AMO 原子指令；
      - C：压缩指令，例如 c.addi、c.j、c.jr、c.beqz。
    """
    if xlen not in (32, 64):
        raise ValueError(f"unsupported RISC-V XLEN: {xlen}")

    return "+m,+a,+c"


# ---------------- ELF 重定位抽取 ----------------

_RELOC_KIND_MAP = {
    # 直接 PC-relative 控制流 relocation。
    "R_RISCV_BRANCH":     "BRANCH",
    "R_RISCV_JAL":        "JAL",
    "R_RISCV_RVC_BRANCH": "RVC_BRANCH",
    "R_RISCV_RVC_JUMP":   "RVC_JUMP",

    # 高/低位地址构造及调用 relocation。
    "R_RISCV_PCREL_HI20":   "PCREL_HI20",
    "R_RISCV_PCREL_LO12_I": "PCREL_LO12_I",
    "R_RISCV_PCREL_LO12_S": "PCREL_LO12_S",
    "R_RISCV_HI20":         "HI20",
    "R_RISCV_LO12_I":       "LO12_I",
    "R_RISCV_LO12_S":       "LO12_S",
    "R_RISCV_CALL":         "CALL",
    "R_RISCV_CALL_PLT":     "CALL_PLT",
}

# RISC-V ELF psABI relocation number。
#
# llvm-mc 生成的 ELF 通常使用 RELA；此映射主要用于 pyelftools /
# LLVM 版本无法把 r_info_type 自动转成字符串名称时的兜底。
_RISCV_RELOC_NUM_TO_NAME = {
    16: "R_RISCV_BRANCH",
    17: "R_RISCV_JAL",
    18: "R_RISCV_CALL",
    19: "R_RISCV_CALL_PLT",
    23: "R_RISCV_PCREL_HI20",
    24: "R_RISCV_PCREL_LO12_I",
    25: "R_RISCV_PCREL_LO12_S",
    26: "R_RISCV_HI20",
    27: "R_RISCV_LO12_I",
    28: "R_RISCV_LO12_S",
    44: "R_RISCV_RVC_BRANCH",
    45: "R_RISCV_RVC_JUMP",
    51: "R_RISCV_RELAX",
}

_TEXT_REL_KINDS_HI = {"PCREL_HI20", "HI20"}
_TEXT_REL_KINDS_LO = {"PCREL_LO12_I", "PCREL_LO12_S", "LO12_I", "LO12_S"}

# 这些 relocation 可以直接表达 PC-relative 控制流目标。
# 它们不能再像旧实现那样因为“不是 frag.symbols 外部符号”而被丢弃。
_TEXT_REL_KINDS_DIRECT_PCREL = {
    "BRANCH",
    "JAL",
    "RVC_BRANCH",
    "RVC_JUMP",
    "CALL",
    "CALL_PLT",
}


def _symbol_st_value(sym) -> Optional[int]:
    try:
        return int(sym["st_value"])
    except Exception:
        pass
    try:
        return int(sym.entry["st_value"])
    except Exception:
        return None


def _symbol_st_shndx(sym) -> Optional[int]:
    try:
        v = sym["st_shndx"]
        if isinstance(v, int):
            return v
    except Exception:
        pass
    try:
        v = sym.entry["st_shndx"]
        if isinstance(v, int):
            return v
    except Exception:
        pass
    return None


def _normalize_reloc_type_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    s = str(name).strip()
    m = re.search(r"(R_[A-Z0-9_]+)", s)
    return m.group(1) if m else None


def _resolve_reloc_type_name(elf, rtype) -> Optional[str]:
    """
    尽量稳健地把 r_info_type 解析成 R_RISCV_* 名字。
    优先级：
      1) 已经是字符串
      2) pyelftools.describe_reloc_type
      3) pyelftools.enums
      4) RISC-V 数字编号兜底
    """
    if isinstance(rtype, str) and rtype.startswith("R_"):
        return rtype

    try:
        rtype_int = int(rtype)
    except Exception:
        rtype_int = None

    # 1) descriptions
    try:
        from elftools.elf.descriptions import describe_reloc_type

        try:
            name = describe_reloc_type(rtype, elf)
            name = _normalize_reloc_type_name(name)
            if name:
                return name
        except Exception:
            pass

        try:
            name = describe_reloc_type(rtype, elf.get_machine_arch())
            name = _normalize_reloc_type_name(name)
            if name:
                return name
        except Exception:
            pass
    except Exception:
        pass

    # 2) enums
    try:
        from elftools.elf import enums as elf_enums

        arch_token = ""
        try:
            arch_token = re.sub(r"[^A-Za-z0-9]+", "", str(elf.get_machine_arch())).upper()
        except Exception:
            pass

        enum_names = [n for n in dir(elf_enums) if n.startswith("ENUM_RELOC_TYPE_")]
        preferred = [n for n in enum_names if arch_token and arch_token in n.upper()]
        others = [n for n in enum_names if n not in preferred]

        for enum_name in preferred + others:
            enum_map = getattr(elf_enums, enum_name, None)
            if not isinstance(enum_map, dict):
                continue

            if rtype_int is not None and rtype_int in enum_map and isinstance(enum_map[rtype_int], str):
                name = _normalize_reloc_type_name(enum_map[rtype_int])
                if name:
                    return name

            for k, v in enum_map.items():
                if rtype_int is not None and v == rtype_int and isinstance(k, str):
                    name = _normalize_reloc_type_name(k)
                    if name:
                        return name
    except Exception:
        pass

    # 3) 数字兜底
    if rtype_int is not None:
        return _RISCV_RELOC_NUM_TO_NAME.get(rtype_int)

    return None


def _normalize_sh_type(sh_type) -> Optional[str]:
    if sh_type is None:
        return None
    if isinstance(sh_type, str):
        return sh_type.strip()

    try:
        v = int(sh_type)
    except Exception:
        return str(sh_type).strip()

    numeric_map = {
        1: "SHT_PROGBITS",
        4: "SHT_RELA",
        9: "SHT_REL",
    }
    return numeric_map.get(v, str(v))


def _is_text_section_name(name: str) -> bool:
    return bool(name) and name.startswith(".text")


def _relsec_name_to_target_sec_name(relsec_name: str) -> Optional[str]:
    relsec_name = (relsec_name or "").strip()
    if relsec_name.startswith(".rela"):
        return "." + relsec_name[len(".rela"):].lstrip(".")
    if relsec_name.startswith(".rel"):
        return "." + relsec_name[len(".rel"):].lstrip(".")
    return None


def _dedup_and_sort_relocs(relocs: List[RelocEntry]) -> List[RelocEntry]:
    out: List[RelocEntry] = []
    seen = set()

    for r in sorted(
        relocs,
        key=lambda x: (
            x.offset,
            x.kind,
            x.sym_index,
            x.elf_sym_index if x.elf_sym_index is not None else -1,
            x.addend,
            x.symbol_name or "",
        ),
    ):
        key = (
            r.offset,
            r.sym_index,
            r.kind,
            r.symbol_name,
            r.addend,
            r.elf_sym_index,
            r.symbol_value,
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(r)

    return out


def _frag_symbol_name_map(frag: AsmFragment) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for i, sym in enumerate(getattr(frag, "symbols", []) or []):
        for name in (
            (getattr(sym, "asmName", "") or "").strip(),
            (getattr(sym, "cName", "") or "").strip(),
        ):
            if name and name not in out:
                out[name] = i
    return out


def _collect_text_layout(elf):
    """
    以 section index 顺序把 .text / .text.* 拼接成一段 machine_code。
    返回：
      machine_code, base_by_sec_idx, base_by_sec_name
    """
    chunks: List[bytes] = []
    base_by_sec_idx: Dict[int, int] = {}
    base_by_sec_name: Dict[str, int] = {}
    cursor = 0

    for sec_idx, sec in enumerate(elf.iter_sections()):
        name = str(getattr(sec, "name", "") or "")
        if not _is_text_section_name(name):
            continue

        sh_type = _normalize_sh_type(getattr(sec, "header", {}).get("sh_type", None))
        if sh_type is None:
            try:
                sh_type = _normalize_sh_type(sec["sh_type"])
            except Exception:
                sh_type = None
        if sh_type != "SHT_PROGBITS":
            continue

        data = sec.data() or b""
        data = bytes(data)

        base_by_sec_idx[sec_idx] = cursor
        base_by_sec_name[name] = cursor
        chunks.append(data)
        cursor += len(data)

    return b"".join(chunks), base_by_sec_idx, base_by_sec_name


@dataclass
class _RawReloc:
    # 已加上目标 .text / .text.* section 在最终 machine_code 中的 base。
    offset: int

    # 项目内部 relocation kind，例如 BRANCH、JAL、PCREL_HI20。
    kind: str

    # ELF 原始 relocation 名称，例如 R_RISCV_BRANCH。
    reloc_name: str

    # ELF symbol 的可读名称；section symbol 常常为空字符串。
    sym_name: str

    # ELF symbol 的 st_value。局部标签或 section-relative symbol 的目标地址
    # 通常需要结合该字段和 addend 才能正确解释。
    sym_value: Optional[int]

    # ELF symbol table 中的原始 symbol index。
    elf_sym_index: Optional[int]

    # RELA 的显式 addend。LLVM 产生的 RISC-V 对象通常使用 RELA。
    # 对 REL 记录当前取 0；如果未来需要支持旧工具链 REL，可进一步从指令位域解码。
    addend: int

    target_sec_idx: int
    sym_sec_idx: Optional[int]
    target_sec_name: str = ""


def _iter_text_reloc_sections(elf):
    """
    不依赖 RelocationSection 的 isinstance，直接按 section type + 名字/目标 section 扫描。
    兼容：
      - .rel.text / .rela.text
      - .rel.text.foo / .rela.text.foo
      - 通过 sh_info 指向 .text / .text.*
    """
    for sec in elf.iter_sections():
        try:
            sh_type = _normalize_sh_type(sec["sh_type"])
        except Exception:
            continue

        if sh_type not in ("SHT_REL", "SHT_RELA"):
            continue

        sec_name = str(getattr(sec, "name", "") or "")
        target_name_by_info = ""

        try:
            target_sec = elf.get_section(sec["sh_info"])
            target_name_by_info = str(getattr(target_sec, "name", "") or "")
        except Exception:
            target_sec = None

        if _is_text_section_name(target_name_by_info):
            yield sec
            continue

        guessed = _relsec_name_to_target_sec_name(sec_name)
        if guessed and _is_text_section_name(guessed):
            yield sec


def _finalize_raw_relocs(
    raw: List[_RawReloc],
    frag: AsmFragment,
    base_by_sec_idx: Dict[int, int],
) -> List[RelocEntry]:
    """
    将 ELF 原始 relocation 转换为项目 RelocEntry。

    重要原则：
      1) 不再只保留能匹配 frag.symbols 的 relocation；
      2) 本地标签、section symbol、.+N / .-N 也必须保留；
      3) 对无法映射到 frag.symbols 的 ELF symbol，RelocEntry.sym_index = -1；
      4) 原始 ELF symbol 信息由 elf_sym_index / symbol_name /
         symbol_value / addend 保留；
      5) 对 PCREL_LO12 保留旧有的“回指 HI20 外部符号”逻辑，以兼容
         auipc + addi / auipc + load-store 等现有 translator 流程。
    """
    name_to_frag_sym_index = _frag_symbol_name_map(frag)
    sole_frag_sym_index = (
        0 if len(getattr(frag, "symbols", []) or []) == 1 else None
    )

    # key: 已拼接 machine_code 中的 HI relocation offset
    # value: frag.symbols 中的下标
    hi_by_addr: Dict[int, int] = {}

    # 同一个目标 text section 中的 HI relocation offsets。
    hi_offsets_by_target: Dict[str, List[int]] = {}

    def target_key(rr: _RawReloc) -> str:
        if rr.target_sec_name:
            return rr.target_sec_name
        return f"#{rr.target_sec_idx}"

    def display_symbol_name(rr: _RawReloc) -> Optional[str]:
        """
        section symbol 往往没有 ELF symbol name。此时使用 relocation
        目标 section 名称作为可读且稳定的 fallback，例如 '.text'。
        """
        if rr.sym_name:
            return rr.sym_name

        if rr.sym_sec_idx is not None:
            for sec_idx, sec_base in base_by_sec_idx.items():
                if sec_idx == rr.sym_sec_idx:
                    # 当前函数没有 elf 对象，无法从 index 反查真实 section name；
                    # target_sec_name 对 .+N / .-N 的常见场景已经足够。
                    break

        return rr.target_sec_name or None

    def frag_symbol_index_for_hi(rr: _RawReloc) -> Optional[int]:
        """
        HI20 优先按外部符号名称匹配 fragment symbol。

        仅当 fragment 只有一个 symbol 且 HI symbol 是空/局部名时，才使用
        唯一符号兜底。该策略不能直接套用于 BRANCH/JAL/LO12，否则会把
        本地跳转或局部标签错误绑定到外部符号。
        """
        sym_index = name_to_frag_sym_index.get(rr.sym_name)
        if sym_index is not None:
            return sym_index

        if sole_frag_sym_index is not None:
            if not rr.sym_name or rr.sym_name.startswith(".L") or rr.sym_name.startswith("1"):
                return sole_frag_sym_index

        return None

    def direct_frag_symbol_index(rr: _RawReloc) -> Optional[int]:
        """
        对 BRANCH/JAL/RVC_* / CALL 等直接 relocation，只按明确的名字映射。
        不对本地 symbol 使用“唯一 fragment symbol”猜测。
        """
        return name_to_frag_sym_index.get(rr.sym_name)

    # 第一阶段：收集可与 PCREL_LO12 配对的 HI relocation。
    for rr in raw:
        if rr.kind not in _TEXT_REL_KINDS_HI:
            continue

        frag_sym_index = frag_symbol_index_for_hi(rr)
        if frag_sym_index is None:
            continue

        hi_by_addr[rr.offset] = frag_sym_index
        hi_offsets_by_target.setdefault(target_key(rr), []).append(rr.offset)

    for offsets in hi_offsets_by_target.values():
        offsets.sort()

    out: List[RelocEntry] = []

    for rr in raw:
        frag_sym_index: Optional[int] = None

        if rr.kind in _TEXT_REL_KINDS_HI:
            frag_sym_index = frag_symbol_index_for_hi(rr)

        elif rr.kind in _TEXT_REL_KINDS_LO:
            # LO relocation 若直接引用了 fragment 外部 symbol，优先使用它。
            frag_sym_index = name_to_frag_sym_index.get(rr.sym_name)

            # LLVM 经常让 PCREL_LO12 指向本地临时标签；该标签对应前面的
            # AUIPC/HI20 位置。此时需反查该 HI20 归属的外部 fragment symbol。
            if frag_sym_index is None and rr.sym_value is not None:
                sec_base = None

                if rr.sym_sec_idx is not None:
                    sec_base = base_by_sec_idx.get(rr.sym_sec_idx)

                if sec_base is None:
                    sec_base = base_by_sec_idx.get(rr.target_sec_idx)

                if sec_base is not None:
                    # 对 section-relative local symbol，目标通常是：
                    #   section_base + st_value + r_addend
                    hi_abs_addr = sec_base + rr.sym_value + rr.addend
                    frag_sym_index = hi_by_addr.get(hi_abs_addr)

            # 常见 auipc + addi/load/store 紧邻配对。
            if frag_sym_index is None:
                frag_sym_index = hi_by_addr.get(rr.offset - 4)

            # 非紧邻时，在同一 text section 中选择最近的前导 HI。
            if frag_sym_index is None:
                prev_hi = None
                for hi_offset in hi_offsets_by_target.get(target_key(rr), []):
                    if hi_offset < rr.offset:
                        prev_hi = hi_offset
                    else:
                        break

                if prev_hi is not None:
                    frag_sym_index = hi_by_addr.get(prev_hi)

        elif rr.kind in _TEXT_REL_KINDS_DIRECT_PCREL:
            # .+N / .-N、局部 label、section-relative expression 都会走到这里。
            # 即使无法映射到 frag.symbols，也必须保留 relocation。
            frag_sym_index = direct_frag_symbol_index(rr)

        else:
            # 未来新增 relocation kind 的保守默认行为：
            # 有明确外部符号名则映射；否则仍保留为内部 relocation。
            frag_sym_index = name_to_frag_sym_index.get(rr.sym_name)

        out.append(RelocEntry(
            offset=rr.offset,
            sym_index=frag_sym_index if frag_sym_index is not None else -1,
            kind=rr.kind,
            symbol_name=display_symbol_name(rr),
            addend=rr.addend,
            elf_sym_index=rr.elf_sym_index,
            symbol_value=rr.sym_value,
        ))

    return _dedup_and_sort_relocs(out)

def _extract_relocations_from_elf(
    elf,
    frag: AsmFragment,
    base_by_sec_idx: Dict[int, int],
) -> List[RelocEntry]:
    raw: List[_RawReloc] = []

    for relsec in _iter_text_reloc_sections(elf):
        try:
            target_sec_idx = int(relsec["sh_info"])
        except Exception:
            target_sec_idx = -1

        target_sec_name = ""
        try:
            target_sec = elf.get_section(relsec["sh_info"])
            target_sec_name = str(getattr(target_sec, "name", "") or "")
        except Exception:
            guessed = _relsec_name_to_target_sec_name(
                str(getattr(relsec, "name", "") or "")
            )
            target_sec_name = guessed or ""

        target_base = base_by_sec_idx.get(target_sec_idx)
        if target_base is None:
            # 当前 machine_code 只拼接 .text / .text.*，因此若 relocation
            # 所属 section 不在 layout 中，就不能生成稳定的 machine_code offset。
            continue

        symtab = None
        try:
            symtab = elf.get_section(relsec["sh_link"])
        except Exception:
            symtab = None

        try:
            rel_iter = relsec.iter_relocations()
        except Exception:
            continue

        for rel in rel_iter:
            try:
                r_offset = int(rel["r_offset"])
            except Exception:
                continue

            reloc_name = _resolve_reloc_type_name(
                elf,
                rel.entry["r_info_type"],
            )
            if not reloc_name:
                continue

            # RELAX 不表示独立的语义 relocation，不能把它作为实际指令
            # relocation 交给下游。
            if reloc_name == "R_RISCV_RELAX":
                continue

            kind = _RELOC_KIND_MAP.get(reloc_name)
            if not kind:
                continue

            sym_name = ""
            sym_value = None
            sym_sec_idx = None
            elf_sym_index = None

            try:
                elf_sym_index = int(rel.entry["r_info_sym"])
            except Exception:
                elf_sym_index = None

            # RISC-V LLVM 对象通常使用 RELA，因此 r_addend 是表达
            # symbol + offset、.+N、section-relative expression 的关键。
            #
            # 对旧式 REL relocation，ELF 中不存在显式 r_addend，这里先取 0。
            # 如果后续需要兼容产生 SHT_REL 的特定工具链，可按 relocation kind
            # 从对应 instruction immediate 位域解码隐式 addend。
            try:
                addend = int(rel.entry["r_addend"])
            except Exception:
                addend = 0

            if symtab is not None and elf_sym_index is not None:
                try:
                    sym = symtab.get_symbol(elf_sym_index)
                    sym_name = str(getattr(sym, "name", "") or "")
                    sym_value = _symbol_st_value(sym)
                    sym_sec_idx = _symbol_st_shndx(sym)
                except Exception:
                    pass

            raw.append(_RawReloc(
                offset=target_base + r_offset,
                kind=kind,
                reloc_name=reloc_name,
                sym_name=sym_name,
                sym_value=sym_value,
                elf_sym_index=elf_sym_index,
                addend=addend,
                target_sec_idx=target_sec_idx,
                sym_sec_idx=sym_sec_idx,
                target_sec_name=target_sec_name,
            ))

    return _finalize_raw_relocs(raw, frag, base_by_sec_idx)

def _parse_objdump_reloc_value(value_field: str) -> Tuple[str, int]:
    """
    解析 llvm-objdump -r 的 VALUE 列。

    常见格式：
      symbol
      symbol+8
      symbol + 8
      symbol-4
      symbol + 0x10
      .text+0x8

    objdump fallback 没有 ELF symbol index，也不能可靠取得 st_value，
    但至少应保留 symbol name 和显式 addend。
    """
    value_field = (value_field or "").strip()
    if not value_field:
        return "", 0

    m = re.match(
        r"^(\S+?)(?:\s*([+-])\s*(0x[0-9A-Fa-f]+|\d+))?$",
        value_field,
    )
    if not m:
        # 保守 fallback：保留第一个 token，不猜测 addend。
        return value_field.split()[0], 0

    sym_name = (m.group(1) or "").strip()
    sign = m.group(2)
    addend_text = m.group(3)

    if not sign or not addend_text:
        return sym_name, 0

    try:
        addend = int(addend_text, 0)
    except ValueError:
        return sym_name, 0

    if sign == "-":
        addend = -addend

    return sym_name, addend

def _extract_relocations_from_objdump(
    obj_path: str,
    frag: AsmFragment,
    *,
    base_by_sec_name: Dict[str, int],
) -> List[RelocEntry]:
    """
    兜底路径：使用 `llvm-objdump -r` 文本解析 relocation。

    典型输出格式：
      RELOCATION RECORDS FOR [.text]:
      OFFSET           TYPE                     VALUE
      0000000000000000 R_RISCV_BRANCH          .text+0x8
      0000000000000004 R_RISCV_JAL             local_label
      0000000000000008 R_RISCV_PCREL_HI20      g_pic_sym
      000000000000000c R_RISCV_PCREL_LO12_I    .Ltmp0
    """
    llvm_objdump = _find_llvm_objdump()
    if not llvm_objdump:
        return []

    try:
        proc = subprocess.run(
            [llvm_objdump, "-r", obj_path],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []

    if proc.returncode != 0:
        return []

    raw: List[_RawReloc] = []
    cur_target_sec_name = ""
    cur_target_base = None

    sec_re = re.compile(r"^\s*RELOCATION RECORDS FOR \[([^\]]+)\]:\s*$")
    row_re = re.compile(r"^\s*([0-9A-Fa-f]+)\s+([A-Za-z0-9_]+)\s+(.+?)\s*$")

    for line in (proc.stdout or "").splitlines():
        msec = sec_re.match(line)
        if msec:
            cur_target_sec_name = (msec.group(1) or "").strip()
            cur_target_base = base_by_sec_name.get(cur_target_sec_name)
            continue

        if cur_target_base is None or not _is_text_section_name(cur_target_sec_name):
            continue

        mrow = row_re.match(line)
        if not mrow:
            continue

        try:
            r_offset = int(mrow.group(1), 16)
        except Exception:
            continue

        reloc_name = _normalize_reloc_type_name(mrow.group(2))
        if not reloc_name or reloc_name == "R_RISCV_RELAX":
            continue

        kind = _RELOC_KIND_MAP.get(reloc_name)
        if not kind:
            continue

        sym_name, addend = _parse_objdump_reloc_value(mrow.group(3))

        raw.append(_RawReloc(
            offset=cur_target_base + r_offset,
            kind=kind,
            reloc_name=reloc_name,
            sym_name=sym_name,
            sym_value=None,
            elf_sym_index=None,
            addend=addend,
            target_sec_idx=-1,
            sym_sec_idx=None,
            target_sec_name=cur_target_sec_name,
        ))

    # objdump 路径没有 ELF symbol st_value / section index 信息；
    # finalize 会跳过 st_value 回查，并退化使用 offset-4 / 最近前导 HI。
    return _finalize_raw_relocs(raw, frag, {})


def _parse_objdump_bytes_field(s: str) -> bytes:
    """
    兼容：
      '97 05 00 00'
      '97050000'
      '01 41'
      '0141'
    """
    s = (s or "").strip()
    if not s:
        return b""

    toks = s.split()
    if toks and all(re.fullmatch(r"[0-9A-Fa-f]+", t or "") for t in toks):
        hexs = "".join(toks)
        if len(hexs) % 2 == 0:
            try:
                return bytes.fromhex(hexs)
            except Exception:
                return b""

    if re.fullmatch(r"[0-9A-Fa-f]+", s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except Exception:
            return b""

    return b""


def _extract_insn_listing(
    obj_path: str,
    *,
    xlen: int,
    base_by_sec_name: Dict[str, int],
) -> List[Tuple[int, bytes, str]]:
    llvm_objdump = _find_llvm_objdump()
    if not llvm_objdump:
        return []

    try:
        proc = subprocess.run(
            [llvm_objdump, "-d", obj_path],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []

    if proc.returncode != 0:
        return []

    out = proc.stdout or ""
    lines = out.splitlines()

    cur_sec = ""
    cur_base = 0
    listing: List[Tuple[int, bytes, str]] = []

    sec_re = re.compile(r"^\s*Disassembly of section\s+([^\s:]+)\s*:\s*$")
    ins_re = re.compile(
        r"^\s*([0-9A-Fa-f]+):\s*([0-9A-Fa-f ]+?)\s{2,}(.*?)\s*$"
    )

    for line in lines:
        msec = sec_re.match(line)
        if msec:
            cur_sec = msec.group(1)
            cur_base = base_by_sec_name.get(cur_sec, 0)
            continue

        mins = ins_re.match(line)
        if not mins:
            continue

        try:
            rel_addr = int(mins.group(1), 16)
        except Exception:
            continue

        raw_bytes = _parse_objdump_bytes_field(mins.group(2))
        asm_text = (mins.group(3) or "").strip()
        if not asm_text:
            continue

        listing.append((cur_base + rel_addr, raw_bytes, asm_text))

    return listing


def _render_asm_unit(
    frag: AsmFragment,
    materialized: MaterializedInlineAsm,
) -> str:
    """
    将已经 materialize 的 fragment body 包装为完整汇编单元。

    注意：这里不能再次调用 materialize_template(frag)，否则会产生两次
    materialization，并可能让 rendered asm 与 runtime facts 不再严格对应。
    """
    body = materialized.normalized_asm.rstrip() + "\n"

    if _fragment_references_symbols(frag):
        prefix = _build_pic_stub(frag)
    else:
        prefix = (
            "  .text\n"
            "  .option rvc\n"
        )

    return prefix + body

# ---------------------------------------------------------------------------
# LLVM RISC-V compatibility: .+N / .-N branch target normalization
# ---------------------------------------------------------------------------

_RISCV_DOT_RELATIVE_BRANCH_OPS = {
    # 标准条件分支。
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",

    # 常见 branch pseudo instructions。
    "bgt",
    "ble",
    "bgtu",
    "bleu",

    # 压缩条件分支。
    "c.beqz",
    "c.bnez",

    # 直接跳转。
    "j",
    "jal",
    "c.j",
    "c.jal",

    # 直接 call/tail pseudo instruction。
    "call",
    "tail",
}

# These aliases are normalized only at the Phase-4 assembler boundary.  They
# are not translation rules and no later semantic phase may inspect this
# spelling.  Keep the table deliberately narrow: an entry is admitted only
# when the assembler alias has the same operand form and architectural effect
# as its canonical spelling.
_RISCV_ASSEMBLER_ALIASES = {
    "mov": "mv",
}

_RISCV_ASM_LINE_RE = re.compile(
    r"""
    ^
    (?P<prefix>
        \s*
        (?:
            (?:
                [A-Za-z_.$][A-Za-z0-9_.$]*  # 普通 label，例如 foo 或 .Ltmp0
                |
                \d+                          # 数字 local label，例如 1:
            )
            :
            \s*
        )?
    )
    (?P<opcode>[A-Za-z][A-Za-z0-9_.]*)
    (?P<space>\s+)
    (?P<operands>.*?)
    $
    """,
    re.VERBOSE,
)

_RISCV_DOT_RELATIVE_TARGET_RE = re.compile(
    r"""
    ^
    \.
    \s*
    (?P<sign>[+-])
    \s*
    (?P<value>
        0[xX][0-9A-Fa-f]+
        |
        \d+
    )
    $
    """,
    re.VERBOSE,
)


def _normalize_riscv_assembler_aliases(asm_text: str) -> str:
    """Normalize a finite set of syntax-only RISC-V assembler aliases.

    Some LLVM RISC-V assembler versions accept only the canonical ``mv``
    spelling, while GCC inline asm commonly uses the ``mov`` alias.  The
    normalization is intentionally conservative: it changes only a two-
    operand alias after template materialization, leaves labels/comments
    untouched, and never infers source semantics from the instruction text.
    Unsupported aliases remain assembler failures rather than being guessed.
    """
    normalized_lines: list[str] = []
    for original_line in asm_text.splitlines(keepends=True):
        line_ending = "\n" if original_line.endswith("\n") else ""
        body = original_line[:-1] if line_ending else original_line
        code, marker, comment = body.partition("#")
        match = _RISCV_ASM_LINE_RE.match(code)
        if match is None:
            normalized_lines.append(original_line)
            continue
        canonical = _RISCV_ASSEMBLER_ALIASES.get(match.group("opcode").lower())
        operands = [item.strip() for item in match.group("operands").split(",")]
        if canonical is None or len(operands) != 2 or not all(operands):
            normalized_lines.append(original_line)
            continue
        normalized_lines.append(
            f"{match.group('prefix')}{canonical}{match.group('space')}"
            f"{', '.join(operands)}{marker}{comment}{line_ending}"
        )
    return "".join(normalized_lines)


def _split_riscv_asm_comment(line: str) -> tuple[str, str]:
    """
    将一行汇编拆分为：

        instruction_part, comment_part

    例如：

        beq a0, a1, .+8  # branch forward

    返回：

        (
            "beq a0, a1, .+8  ",
            "# branch forward",
        )

    本项目这里仅需要处理常见的 '#' 注释形式。
    """
    comment_pos = line.find("#")
    if comment_pos < 0:
        return line, ""

    return line[:comment_pos], line[comment_pos:]


def _normalize_riscv_dot_relative_target(target: str) -> str | None:
    """
    将以下 operand：

        .+8
        . + 8
        .-4
        . - 0x10

    转换为 LLVM RISC-V assembler 可接受的 PC-relative immediate：

        8
        -4
        -0x10

    若 target 不是 .+N / .-N 形式，则返回 None。
    """
    match = _RISCV_DOT_RELATIVE_TARGET_RE.match(target.strip())
    if match is None:
        return None

    sign = match.group("sign")
    value = match.group("value")

    if sign == "-":
        return f"-{value}"

    return value


def _normalize_riscv_dot_relative_targets(asm_text: str) -> str:
    """
    规范化 RISC-V branch/jump operand 中的 .+N / .-N 表达式。

    背景：
      某些 LLVM RISC-V llvm-mc 版本接受：

          beq a0, a1, 8
          jal ra, 16

      但拒绝：

          beq a0, a1, .+8
          jal ra, .+16

      并报错：

          Unsupported relocation type

    RISC-V branch/jump 的数值立即数本身就是相对于当前 PC 的字节偏移，
    因此：

        .+8  ->  8
        .-4  ->  -4

    不改变实际指令语义。

    注意：
      - 只处理 branch/jump/call 的最后一个 operand；
      - 不处理一般算术表达式；
      - 不修改 rawAsmText，只修改送入 llvm-mc 的 rendered assembly；
      - 不需要插入 label，也不依赖后续 instruction 的编码长度。
    """
    if not asm_text:
        return asm_text

    normalized_lines: list[str] = []

    for original_line in asm_text.splitlines(keepends=True):
        if original_line.endswith("\r\n"):
            line_body = original_line[:-2]
            line_ending = "\r\n"
        elif original_line.endswith("\n"):
            line_body = original_line[:-1]
            line_ending = "\n"
        else:
            line_body = original_line
            line_ending = ""

        instruction_part, comment_part = _split_riscv_asm_comment(line_body)

        match = _RISCV_ASM_LINE_RE.match(instruction_part)
        if match is None:
            normalized_lines.append(original_line)
            continue

        opcode = match.group("opcode")
        opcode_lower = opcode.lower()

        if opcode_lower not in _RISCV_DOT_RELATIVE_BRANCH_OPS:
            normalized_lines.append(original_line)
            continue

        operands_text = match.group("operands")
        operands = operands_text.split(",")

        if not operands:
            normalized_lines.append(original_line)
            continue

        normalized_target = _normalize_riscv_dot_relative_target(operands[-1])
        if normalized_target is None:
            normalized_lines.append(original_line)
            continue

        operands[-1] = normalized_target

        normalized_instruction = (
            f"{match.group('prefix')}"
            f"{opcode}"
            f"{match.group('space')}"
            f"{', '.join(part.strip() for part in operands)}"
        )

        normalized_lines.append(
            normalized_instruction + comment_part + line_ending
        )

    return "".join(normalized_lines)

def assemble(
    frag: AsmFragment,
    xlen: int = 64,
    *,
    operand_width_bits: Optional[Mapping[int, int]] = None,
) -> AssembleResult:
    """
    汇编 inline asm fragment，并返回机器码、relocation、listing 以及
    materialization 阶段产生的权威 TranslationRuntimeFacts。

    operand_width_bits 必须来自 AST/type analysis/schema。

    例如：
        {
            0: 32,
            1: 64,
            2: 8,
        }

    不允许根据 xlen、物理寄存器名或 LLVM 汇编输出推断 C operand 宽度。
    """
    llvm_mc = _find_llvm_mc()
    if not llvm_mc:
        return AssembleResult(
            ok=False,
            machine_code=b"",
            insn_listing=[],
            error="llvm-mc not found in PATH",
            rendered_asm="",
            relocations=[],
        )

    if not _llvm_mc_supports_riscv(llvm_mc):
        return AssembleResult(
            ok=False,
            machine_code=b"",
            insn_listing=[],
            error=f"llvm-mc does not advertise RISC-V support: {llvm_mc}",
            rendered_asm="",
            relocations=[],
        )

    materialized: Optional[MaterializedInlineAsm] = None
    runtime_facts = TranslationRuntimeFacts()

    try:
        # 只 materialize 一次。
        #
        # materialized.operand_bindings 是后续 runtime facts 的唯一事实来源。
        materialized = materialize_template(frag)

        # width 由上游提供；缺失时传空映射，而非根据 xlen 推断。
        runtime_facts = build_assembled_translation_runtime_facts(
            operand_bindings=materialized.operand_bindings,
            operand_width_bits=dict(operand_width_bits or {}),
        )
        condition_kind, condition_operand = _asm_goto_condition_fact(frag)
        if condition_kind is not None:
            runtime_facts = replace(
                runtime_facts,
                asm_goto_condition_kind=condition_kind,
                asm_goto_condition_operand_index=condition_operand,
            )

        # 使用与 bindings 完全同一次 materialization 的 asm 文本。
        rendered = _render_asm_unit(frag, materialized)

        # 将 llvm-mc 不能接受的 .+N / .-N branch target 转为等价 immediate。
        #
        # 这只改变最终汇编文本，不改变 operand-register binding。
        rendered = _normalize_riscv_assembler_aliases(rendered)
        rendered = _normalize_riscv_dot_relative_targets(rendered)

    except ValueError as e:
        return AssembleResult(
            ok=False,
            machine_code=b"",
            insn_listing=[],
            error=f"invalid inline-asm operand template: {e}",
            rendered_asm="",
            relocations=[],
            translation_runtime_facts=runtime_facts,
            materialized_operand_bindings=(
                list(materialized.operand_bindings)
                if materialized is not None
                else []
            ),
        )

    try:
        llvm_features = _llvm_mc_features(xlen)
    except ValueError as e:
        return AssembleResult(
            ok=False,
            machine_code=b"",
            insn_listing=[],
            error=str(e),
            rendered_asm=rendered,
            relocations=[],
            translation_runtime_facts=runtime_facts,
            materialized_operand_bindings=list(materialized.operand_bindings),
        )

    triple = f"riscv{xlen}"
    pic_like = _fragment_references_symbols(frag)

    with tempfile.TemporaryDirectory(prefix="r2x_asm_") as td:
        asm_path = os.path.join(td, "frag.s")
        obj_path = os.path.join(td, "frag.o")

        with open(asm_path, "w", encoding="utf-8") as f:
            f.write(rendered)

        cmd = [
            llvm_mc,
            f"-triple={triple}",
            f"-mattr={llvm_features}",
            "-filetype=obj",
            asm_path,
            "-o",
            obj_path,
        ]

        if pic_like:
            cmd.append("--position-independent")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as e:
            return AssembleResult(
                ok=False,
                machine_code=b"",
                insn_listing=[],
                error=f"failed to run llvm-mc: {e}",
                rendered_asm=rendered,
                relocations=[],
                translation_runtime_facts=runtime_facts,
                materialized_operand_bindings=list(materialized.operand_bindings),
            )

        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            return AssembleResult(
                ok=False,
                machine_code=b"",
                insn_listing=[],
                error=err,
                rendered_asm=rendered,
                relocations=[],
                translation_runtime_facts=runtime_facts,
                materialized_operand_bindings=list(materialized.operand_bindings),
            )

        try:
            from elftools.elf.elffile import ELFFile
        except Exception as e:
            return AssembleResult(
                ok=False,
                machine_code=b"",
                insn_listing=[],
                error=f"pyelftools is required for relocation extraction: {e}",
                rendered_asm=rendered,
                relocations=[],
                translation_runtime_facts=runtime_facts,
                materialized_operand_bindings=list(materialized.operand_bindings),
            )

        try:
            with open(obj_path, "rb") as f:
                elf = ELFFile(f)
                (
                    machine_code,
                    base_by_sec_idx,
                    base_by_sec_name,
                ) = _collect_text_layout(elf)

                relocs = _extract_relocations_from_elf(
                    elf,
                    frag,
                    base_by_sec_idx,
                )
        except Exception as e:
            return AssembleResult(
                ok=False,
                machine_code=b"",
                insn_listing=[],
                error=f"failed to parse ELF relocations: {e}",
                rendered_asm=rendered,
                relocations=[],
                translation_runtime_facts=runtime_facts,
                materialized_operand_bindings=list(materialized.operand_bindings),
            )

        if pic_like and not relocs:
            relocs = _extract_relocations_from_objdump(
                obj_path,
                frag,
                base_by_sec_name=base_by_sec_name,
            )

        listing = _extract_insn_listing(
            obj_path,
            xlen=xlen,
            base_by_sec_name=base_by_sec_name,
        )

        return AssembleResult(
            ok=True,
            machine_code=machine_code,
            insn_listing=listing,
            error="",
            rendered_asm=rendered,
            relocations=relocs,

            # 权威数据。
            translation_runtime_facts=runtime_facts,

            # 兼容字段。
            materialized_operand_bindings=list(
                materialized.operand_bindings
            ),

            # 不建议再由 assemble.py 主动构造 register -> operand 的单值映射。
            #
            # 原因：tied operands 合法地允许：
            #
            #   operand 0 -> x10
            #   operand 1 -> x10
            #
            # Dict[str, int] 无法无损表达 x10 同时映射两个 operand。
            #
            # 该字段保持默认空字典，后续消费者必须改读
            # translation_runtime_facts。
            rv_to_operand_index={},
        )
