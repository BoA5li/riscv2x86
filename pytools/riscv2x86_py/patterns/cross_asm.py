"""
跨 __asm__ 块的状态传递：合并相邻的 LR + ALU + SC 模式。

典型场景：
  A: lr.{w,d}  old, (addr)
  (C 语言: new = old OP val)
  B: sc.{w,d}  rc,  new, (addr)

识别条件：
  - A 只有一条 lr 指令
  - B 只有一条 sc 指令
  - A.outputs[0] 流向 B.inputs，且中间经过一次简单 ALU
  - ALU 是 add/sub/and/or/xor 之一（通过 aluExpr 字符串解析）
  - sc 的地址与 lr 相同
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple, List
import re

from ..schema import AsmFragment, OutputBinding
from ..assemble import assemble
from ..lift import lift

_W_LOAD = {"lr.w", "lr.w.aq", "lr.w.aqrl"}
_D_LOAD = {"lr.d", "lr.d.aq", "lr.d.aqrl"}
_W_STORE = {"sc.w", "sc.w.rl", "sc.w.aqrl"}
_D_STORE = {"sc.d", "sc.d.rl", "sc.d.aqrl"}


@dataclass
class CrossAsmFusion:
    """描述一次跨块融合的结果"""
    op_kind: str                    # "add" | "sub" | "and" | "or" | "xor"
    is_w_width: bool                # True = 32-bit, False = 64-bit
    aq: bool
    rl: bool
    addr_expr: str                  # 地址的 C 表达式（来自原 inputs）
    val_expr: str                   # 操作数的 C 表达式（从 aluExpr 提取）
    old_lvalue: Optional[str]       # A 的 output lvalue，用于返回旧值
    rc_lvalue: Optional[str]        # B 的 output lvalue，用于返回 sc 状态码
    retry_loop: bool = False        # 预留：是否有外层 while


def _classify_alu(alu_expr: str, old_name: str) -> Optional[Tuple[str, str]]:
    """
    解析 C 表达式，识别是否为简单二元运算。
    返回 (op_kind, val_expr) 或 None。

    支持形式：
      old + x  → ("add", "x")
      old - x  → ("sub", "x")
      old & x  → ("and", "x")
      old | x  → ("or",  "x")
      old ^ x  → ("xor", "x")
      x + old  → ("add", "x")  (交换律)
      x | old  → ("or",  "x")
      ...
    """
    expr = alu_expr.strip()
    expr = re.sub(r"\s+", "", expr)

    while expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1]

    ops = {
        "+": "add",
        "-": "sub",
        "&": "and",
        "|": "or",
        "^": "xor",
    }

    for sym, kind in ops.items():
        # old OP val
        pattern1 = re.escape(old_name) + re.escape(sym) + r"(.+)"
        m = re.match(pattern1, expr)
        if m:
            val = m.group(1).strip()
            return (kind, val)

        # val OP old (仅交换律运算)
        if kind in ("add", "and", "or", "xor"):
            pattern2 = r"(.+)" + re.escape(sym) + re.escape(old_name)
            m = re.match(pattern2, expr)
            if m:
                val = m.group(1).strip()
                return (kind, val)

    return None


def detect_and_fuse(
    frag_a: AsmFragment,
    frag_b: AsmFragment,
    binding: OutputBinding,
    *,
    xlen: int = 64,
) -> Optional[CrossAsmFusion]:
    """
    尝试将相邻两个 fragment 融合为一个 RMW 原子操作。
    """
    try:
        asm_a = assemble(frag_a, xlen=xlen)
        asm_b = assemble(frag_b, xlen=xlen)
        if not asm_a.ok or not asm_b.ok:
            return None

        lift_a = lift(asm_a.machine_code, xlen=xlen, relocations=asm_a.relocations)
        lift_b = lift(asm_b.machine_code, xlen=xlen, relocations=asm_b.relocations)
        if not lift_a.ok or not lift_b.ok:
            return None
    except Exception:
        return None

    insns_a = lift_a.insns
    insns_b = lift_b.insns

    if len(insns_a) != 1 or len(insns_b) != 1:
        return None

    ins_a = insns_a[0]
    ins_b = insns_b[0]
    mnem_a = ins_a.asm_mnem.lower()
    mnem_b = ins_b.asm_mnem.lower()

    if not mnem_a.startswith("lr."):
        return None
    if not mnem_b.startswith("sc."):
        return None

    is_w = mnem_a in _W_LOAD and mnem_b in _W_STORE
    is_d = mnem_a in _D_LOAD and mnem_b in _D_STORE
    if not (is_w or is_d):
        return None

    if binding.sinkKind != "next_asm_input":
        return None

    if not binding.aluExpr:
        return None

    old_name = frag_a.outputs[binding.outputIndex].exprText if binding.outputIndex < len(frag_a.outputs) else None
    if not old_name:
        return None

    alu_result = _classify_alu(binding.aluExpr, old_name)
    if alu_result is None:
        return None

    op_kind, val_expr = alu_result

    if len(frag_a.inputs) < 1 or len(frag_b.inputs) < 1:
        return None

    addr_a = frag_a.inputs[0].exprText
    addr_b = frag_b.inputs[0].exprText
    if addr_a != addr_b:
        return None

    aq = ".aq" in mnem_a or ".aqrl" in mnem_a
    rl = ".rl" in mnem_b or ".aqrl" in mnem_b

    old_lvalue = frag_a.outputs[0].exprText if frag_a.outputs else None
    rc_lvalue = frag_b.outputs[0].exprText if frag_b.outputs else None

    return CrossAsmFusion(
        op_kind=op_kind,
        is_w_width=is_w,
        aq=aq,
        rl=rl,
        addr_expr=addr_a,
        val_expr=val_expr,
        old_lvalue=old_lvalue,
        rc_lvalue=rc_lvalue,
        retry_loop=False,
    )


def emit_c(fusion: CrossAsmFusion) -> Tuple[str, List[str]]:
    """
    生成融合后的 C 代码。
    """
    cty = "uint32_t" if fusion.is_w_width else "uint64_t"
    sext = "(int64_t)(int32_t)" if fusion.is_w_width else "(int64_t)"

    builtin_map = {
        "add": "__atomic_fetch_add",
        "sub": "__atomic_fetch_sub",
        "and": "__atomic_fetch_and",
        "or":  "__atomic_fetch_or",
        "xor": "__atomic_fetch_xor",
    }
    builtin = builtin_map[fusion.op_kind]

    if fusion.aq and fusion.rl:
        order = "__ATOMIC_ACQ_REL"
    elif fusion.aq:
        order = "__ATOMIC_ACQUIRE"
    elif fusion.rl:
        order = "__ATOMIC_RELEASE"
    else:
        order = "__ATOMIC_RELAXED"

    pointer = f"(volatile {cty}*)({fusion.addr_expr})"
    call = f"{builtin}({pointer}, ({cty})({fusion.val_expr}), {order})"

    stmts = []
    stmts.append(f"{cty} __r2x_old = {call};")
    if fusion.old_lvalue:
        stmts.append(f"({fusion.old_lvalue}) = {sext}__r2x_old;")
    if fusion.rc_lvalue:
        stmts.append(f"({fusion.rc_lvalue}) = 0;")

    body = "do { " + " ".join(stmts) + " } while (0)"

    notes = [
        f"cross-asm fusion: lr.{('w' if fusion.is_w_width else 'd')} + "
        f"{fusion.op_kind} + sc -> {builtin}",
        f"memory_order: {order}",
    ]

    return body, notes