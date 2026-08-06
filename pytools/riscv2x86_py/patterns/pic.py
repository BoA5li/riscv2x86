"""
Phase 4: 识别 RISC-V PIC 地址装载序列。

最小支持的地址装载形态：

    auipc rd, %pcrel_hi(sym)        ; reloc kind = PCREL_HI20
    addi  rd, rd, %pcrel_lo(...)    ; reloc kind = PCREL_LO12_I / PCREL_LO12_S
=>  rd 持有 &sym 的地址

以及与 translate._simple_pic_pair_fallback() 对齐的最小兼容形态：

    auipc rd, %pcrel_hi(sym)
    mv    rd, rd                    ; 某些 lift / 规范化路径会把 lo 指令表现成 mv
=>  rd 持有 &sym 的地址

输出一份 (寄存器名 -> C 表达式) 的绑定，供 translate / intblock 注入到 LowerCtx 中。

约定：
- PicBinding.reg 始终使用规范化后的 xN 名称（例如 a0 -> x10, zero -> x0）
- c_expr 的位宽策略固定为：
    xlen == 32 -> ((uint32_t)(uintptr_t)&(...))
    xlen == 64 -> ((uint64_t)(uintptr_t)&(...))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import re

from ..schema import AsmFragment


@dataclass
class PicBinding:
    reg: str            # 规范化后的目的寄存器，例如 "x10"
    c_expr: str         # C 表达式，例如 "((uint64_t)(uintptr_t)&(g_foo))"
    sym_index: int
    consumed_insn_addrs: List[int]  # 被 PIC pattern 消费掉的指令地址


# ---------- 寄存器规范化 ----------

_REG_ALIAS_TO_X: Dict[str, str] = {
    # xN
    **{f"x{i}": f"x{i}" for i in range(32)},

    # ABI names
    "zero": "x0",
    "ra": "x1",
    "sp": "x2",
    "gp": "x3",
    "tp": "x4",
    "t0": "x5",
    "t1": "x6",
    "t2": "x7",
    "s0": "x8",
    "fp": "x8",
    "s1": "x9",
    "a0": "x10",
    "a1": "x11",
    "a2": "x12",
    "a3": "x13",
    "a4": "x14",
    "a5": "x15",
    "a6": "x16",
    "a7": "x17",
    "s2": "x18",
    "s3": "x19",
    "s4": "x20",
    "s5": "x21",
    "s6": "x22",
    "s7": "x23",
    "s8": "x24",
    "s9": "x25",
    "s10": "x26",
    "s11": "x27",
    "t3": "x28",
    "t4": "x29",
    "t5": "x30",
    "t6": "x31",
}


def normalize_reg_name(reg: str) -> str:
    """
    把寄存器名字规范化成 xN 形式。
    例如：
        a0   -> x10
        zero -> x0
        x10  -> x10

    未识别的 token 保持小写后原样返回，便于调用方自行决定是否报错。
    """
    if not reg:
        return ""

    tok = reg.strip().lower()
    tok = re.sub(r"^[%$]+", "", tok).strip()

    # 某些反汇编/打印路径会带多余空白
    tok = re.sub(r"\s+", "", tok)

    return _REG_ALIAS_TO_X.get(tok, tok)


# ---------- 基础解析 ----------

def _split_operands(asm_body: str) -> List[str]:
    if not asm_body:
        return []
    return [p.strip() for p in asm_body.split(",") if p.strip()]


def _first_dst_reg(asm_body: str) -> str:
    """从 'rd, ...' 中提取 rd，并规范化为 xN。"""
    ops = _split_operands(asm_body)
    if not ops:
        return ""
    return normalize_reg_name(ops[0])


def _second_reg(asm_body: str) -> str:
    """从 'rd, rs1, ...' 或 'rd, rs' 中提取第二个寄存器，并规范化为 xN。"""
    ops = _split_operands(asm_body)
    if len(ops) < 2:
        return ""
    return normalize_reg_name(ops[1])


def _mnem(ins) -> str:
    return (getattr(ins, "asm_mnem", "") or "").strip().lower()


def _sym_ref(ins) -> Optional[Tuple[int, str]]:
    ref = getattr(ins, "sym_ref", None)
    if not ref or not isinstance(ref, tuple) or len(ref) != 2:
        return None

    sym_index, kind = ref
    if not isinstance(sym_index, int):
        return None
    if not isinstance(kind, str):
        return None

    return sym_index, kind


def _is_supported_lo_mnem(mnem: str) -> bool:
    return mnem in ("addi", "mv")


def _lo_uses_same_base(lo_mnem: str, asm_body: str) -> bool:
    """
    检查 lo 指令是否满足“结果仍在 rd，且来源寄存器也是同一个 rd”。

    支持：
      addi rd, rd, imm
      mv   rd, rd
    """
    ops = _split_operands(asm_body)

    if lo_mnem == "addi":
        if len(ops) < 2:
            return False
        rd = normalize_reg_name(ops[0])
        rs1 = normalize_reg_name(ops[1])
        return bool(rd) and rd == rs1

    if lo_mnem == "mv":
        if len(ops) != 2:
            return False
        rd = normalize_reg_name(ops[0])
        rs = normalize_reg_name(ops[1])
        return bool(rd) and rd == rs

    return False


def _sym_c_expr(frag: AsmFragment, sym_index: int, xlen: int) -> Optional[str]:
    if sym_index < 0 or sym_index >= len(frag.symbols):
        return None

    sym = frag.symbols[sym_index]
    if not getattr(sym, "cName", None):
        return None

    if xlen == 64:
        cast = "uint64_t"
    elif xlen == 32:
        cast = "uint32_t"
    else:
        raise ValueError(f"unsupported xlen for PIC binding: {xlen}")

    return f"(({cast})(uintptr_t)&({sym.cName}))"


# ---------- 主识别 ----------

def detect_pairs(
    insns,
    frag: AsmFragment,
    xlen: int = 64,
) -> List[PicBinding]:
    """
    扫描 lifter 输出，按出现顺序识别所有 PIC 地址装载对。

    当前最小支持：
      - auipc + addi
      - auipc + mv

    其中：
      hi reloc 必须是 PCREL_HI20
      lo reloc 允许是 PCREL_LO12_I / PCREL_LO12_S

    返回的 PicBinding.reg 一律为规范化后的 xN 名称。
    """
    bindings: List[PicBinding] = []
    n = len(insns)

    for i in range(n - 1):
        hi = insns[i]
        lo = insns[i + 1]

        if _mnem(hi) != "auipc":
            continue

        lo_mnem = _mnem(lo)
        if not _is_supported_lo_mnem(lo_mnem):
            continue

        hi_ref = _sym_ref(hi)
        lo_ref = _sym_ref(lo)
        if hi_ref is None or lo_ref is None:
            continue

        hi_sym_index, hi_kind = hi_ref
        lo_sym_index, lo_kind = lo_ref

        if hi_kind != "PCREL_HI20":
            continue
        if lo_kind not in ("PCREL_LO12_I", "PCREL_LO12_S"):
            continue
        if hi_sym_index != lo_sym_index:
            continue

        hi_rd = _first_dst_reg(getattr(hi, "asm_body", "") or "")
        lo_rd = _first_dst_reg(getattr(lo, "asm_body", "") or "")

        if not hi_rd or hi_rd != lo_rd:
            continue

        if not _lo_uses_same_base(lo_mnem, getattr(lo, "asm_body", "") or ""):
            continue

        c_expr = _sym_c_expr(frag, hi_sym_index, xlen)
        if c_expr is None:
            raise ValueError(
                f"PIC symbol index {hi_sym_index} referenced by auipc+{lo_mnem} "
                f"has no cName in fragment.symbols"
            )

        bindings.append(
            PicBinding(
                reg=hi_rd,
                c_expr=c_expr,
                sym_index=hi_sym_index,
                consumed_insn_addrs=[hi.addr, lo.addr],
            )
        )

    return bindings


# 给 translate / 其它调用方一个稳定名字
def detect_pic_pairs(insns, frag: AsmFragment, xlen: int = 64) -> List[PicBinding]:
    return detect_pairs(insns, frag, xlen=xlen)


def has_any_pcrel_reloc(insns) -> bool:
    """是否存在任何 PCREL_* 重定位指令。"""
    for ins in insns:
        ref = _sym_ref(ins)
        if ref is None:
            continue
        _, kind = ref
        if kind.startswith("PCREL_"):
            return True
    return False


def fragment_uses_pic_syntax(frag: AsmFragment) -> bool:
    text = getattr(frag, "rawAsmText", "") or ""
    if re.search(r"%\s*pcrel_(hi|lo)\s*\(", text, re.IGNORECASE):
        return True
    if re.search(r"\bla\s+", text):
        return True
    return False