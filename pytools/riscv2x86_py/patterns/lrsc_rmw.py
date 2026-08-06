"""
LR/SC + 算术 (fetch_*) 模式识别。
要求：fragment 反汇编后的指令序列形如
  L:  lr.{w,d}[.aq]   t1, (addr)
      <一条 ALU>     t2, t1, op2     # op2 可以是寄存器或立即数
      sc.{w,d}[.rl]  t3, t2, (addr)
      bnez/bne       t3, L
"""
from __future__ import annotations
from dataclasses import dataclass
import re
from typing import Optional, List, Tuple

from ..lift import LiftedInsn
from ..schema import AsmFragment
from ..assemble import _PLACEHOLDER_REGS_INT as PHR

_W_LOAD = {"lr.w", "lr.w.aq", "lr.w.aqrl"}
_D_LOAD = {"lr.d", "lr.d.aq", "lr.d.aqrl"}
_W_STORE = {"sc.w", "sc.w.rl", "sc.w.aqrl"}
_D_STORE = {"sc.d", "sc.d.rl", "sc.d.aqrl"}

# value = old OP arg
_ALU_REG = {
    "add":  "add",
    "sub":  "sub",
    "and":  "and",
    "or":   "or",
    "xor":  "xor",
    "addw": "add",
    "subw": "sub",
}
_ALU_IMM = {
    "addi":  "add",
    "andi":  "and",
    "ori":   "or",
    "xori":  "xor",
    "addiw": "add",
}

_W_ONLY_ALU = {"addw", "subw", "addiw"}

_RISCV_INT_ABI = {
    "zero": 0,
    "ra": 1,
    "sp": 2,
    "gp": 3,
    "tp": 4,
    "t0": 5,
    "t1": 6,
    "t2": 7,
    "s0": 8,
    "fp": 8,
    "s1": 9,
    "a0": 10,
    "a1": 11,
    "a2": 12,
    "a3": 13,
    "a4": 14,
    "a5": 15,
    "a6": 16,
    "a7": 17,
    "s2": 18,
    "s3": 19,
    "s4": 20,
    "s5": 21,
    "s6": 22,
    "s7": 23,
    "s8": 24,
    "s9": 25,
    "s10": 26,
    "s11": 27,
    "t3": 28,
    "t4": 29,
    "t5": 30,
    "t6": 31,
}


def _build_operand_index_map(frag) -> dict:
    """
    同时支持两类名字：
    1) 内部占位寄存器名 PHR[i]
    2) RISC-V ABI/xN 形式的实寄存器名（重点支持 a0-a7 / x10-x17）
    """
    op_index = {}
    total = len(frag.outputs) + len(frag.inputs)

    for i in range(total):
        if i < len(PHR):
            op_index[PHR[i]] = i

    # 兼容 a0-a7 / x10-x17 这种常见实寄存器名
    # 这里沿用现有 emit_* 的约定：frag.outputs + frag.inputs
    # combined index 0 <-> a0/x10, index 1 <-> a1/x11, ...
    for i in range(min(total, 8)):
        op_index.setdefault(f"a{i}", i)
        op_index.setdefault(f"x{10 + i}", i)

    return op_index


def _resolve_operand_expr(frag, reg_name: str) -> str:
    """
    将寄存器名解析为 frag 对应操作数的 exprText。
    兼容 placeholder reg 和 aN/x(10+N) 命名。
    """
    all_ops = list(frag.outputs) + list(frag.inputs)
    op_index = _build_operand_index_map(frag)

    key = reg_name.strip()
    idx = op_index.get(key)

    if idx is None:
        key_l = key.lower()

        # 再做一层 ABI 别名兜底
        if key_l in _RISCV_INT_ABI:
            regno = _RISCV_INT_ABI[key_l]
            if 10 <= regno <= 17:
                idx = regno - 10

        # xN 兜底
        if idx is None:
            m = re.fullmatch(r"x([0-9]|[12][0-9]|3[01])", key_l)
            if m:
                regno = int(m.group(1))
                if 10 <= regno <= 17:
                    idx = regno - 10

    if idx is None or idx >= len(all_ops):
        raise KeyError(
            f"cannot resolve operand register {reg_name!r} against "
            f"{len(frag.outputs)} outputs + {len(frag.inputs)} inputs"
        )

    return all_ops[idx].exprText


@dataclass
class LrscRmw:
    op_kind: str               # "add"/"sub"/"and"/"or"/"xor"
    is_w_width: bool           # 32-bit (w) vs 64-bit (d)
    addr_reg: str              # 占位寄存器名
    val_kind: str              # "reg" or "imm"
    val_reg: Optional[str]
    val_imm: Optional[int]
    aq: bool
    rl: bool


@dataclass
class CompatLrscRmwMatch:
    """
    向 translate.py 旧接口兼容的 matcher 输出：
      - width_bits
      - addr_input_index
      - arg_input_index / arg_imm
      - old_output_index
      - op
    """
    width_bits: int
    addr_input_index: int
    arg_input_index: Optional[int]
    arg_imm: Optional[int]
    old_output_index: Optional[int]
    op: str
    aq: bool = False
    rl: bool = False


def _split(body: str) -> List[str]:
    return [p.strip() for p in body.split(",") if p.strip()]


_MEM = re.compile(r"^\s*(-?\d+)?\s*\(([^)]+)\)\s*$")


def _parse_mem(tok: str) -> Optional[Tuple[int, str]]:
    m = _MEM.match(tok)
    if not m:
        return None
    off = int(m.group(1), 0) if m.group(1) else 0
    return off, m.group(2).strip()


def _parse_int(tok: str) -> Optional[int]:
    try:
        return int(tok, 0)
    except ValueError:
        return None


def _is_retry_branch_to_lr(br: LiftedInsn, status_reg: str, lr_addr: int) -> bool:
    mnem = br.asm_mnem.strip().lower()
    parts = _split(br.asm_body)

    # 原始形态：bnez rs, target
    if mnem in {"bnez", "c.bnez"}:
        if len(parts) != 2:
            return False
        rs, target = parts
        if rs != status_reg:
            return False
        tgt = _parse_int(target)
        return tgt == lr_addr

    # canonicalize 后常见形态：bne rs, zero, target / bne zero, rs, target
    if mnem in {"bne", "c.bne"}:
        if len(parts) != 3:
            return False
        a, b, target = parts
        zero_names = {"zero", "x0"}
        if not (
            (a == status_reg and b in zero_names) or
            (b == status_reg and a in zero_names)
        ):
            return False
        tgt = _parse_int(target)
        return tgt == lr_addr

    return False


def _is_retry_branch_shape(br: LiftedInsn, status_reg: str) -> bool:
    mnem = br.asm_mnem.strip().lower()
    parts = _split(br.asm_body)

    if mnem in {"bnez", "c.bnez"}:
        if len(parts) != 2:
            return False
        rs, _target = parts
        return rs == status_reg

    if mnem in {"bne", "c.bne"}:
        if len(parts) != 3:
            return False
        a, b, _target = parts
        zero_names = {"zero", "x0"}
        return (
            (a == status_reg and b in zero_names) or
            (b == status_reg and a in zero_names)
        )

    return False


def _node_containing(cfg, insn_addr: int):
    if not cfg or not getattr(cfg, "ok", False):
        return None
    for n in cfg.nodes.values():
        if insn_addr in getattr(n, "instr_addrs", []):
            return n
    return None


def _cfg_has_retry_backedge(cfg, br_addr: int, lr_addr: int) -> bool:
    src = _node_containing(cfg, br_addr)
    dst = _node_containing(cfg, lr_addr)
    if src is None or dst is None:
        return False
    return dst.addr in getattr(src, "successors", [])


def detect(insns: List[LiftedInsn], cfg=None) -> Optional[LrscRmw]:
    if len(insns) < 4:
        return None

    lr, alu, sc, br = insns[0], insns[1], insns[2], insns[3]
    lr_m = lr.asm_mnem.strip().lower()
    alu_m = alu.asm_mnem.strip().lower()
    sc_m = sc.asm_mnem.strip().lower()

    is_w = lr_m in _W_LOAD and sc_m in _W_STORE
    is_d = lr_m in _D_LOAD and sc_m in _D_STORE
    if not (is_w or is_d):
        return None

    # 解析 lr
    lr_parts = _split(lr.asm_body)
    if len(lr_parts) != 2:
        return None
    rd_lr, mem_lr = lr_parts
    pm = _parse_mem(mem_lr)
    if pm is None or pm[0] != 0:
        return None
    addr_reg = pm[1]

    # 解析 sc
    sc_parts = _split(sc.asm_body)
    if len(sc_parts) != 3:
        return None
    rstatus, rsrc, mem_sc = sc_parts
    pm2 = _parse_mem(mem_sc)
    if pm2 is None or pm2[0] != 0 or pm2[1] != addr_reg:
        return None

    # 解析 ALU：要求 ALU 的源里包含 lr 的目的寄存器，目的是 sc 的源
    alu_parts = _split(alu.asm_body)
    if len(alu_parts) != 3:
        return None
    rd_alu, ra, rb = alu_parts
    if rd_alu != rsrc:
        return None
    if rd_lr not in (ra, rb):
        return None

    # 解析 retry branch：
    # 先走严格文本匹配；失败时允许 CFG 辅助确认 backedge
    if not _is_retry_branch_to_lr(br, rstatus, lr.addr):
        if not (_is_retry_branch_shape(br, rstatus) and _cfg_has_retry_backedge(cfg, br.addr, lr.addr)):
            return None

    op_kind = None
    val_kind = None
    val_reg = None
    val_imm = None

    if alu_m in _ALU_REG:
        if is_d and alu_m in _W_ONLY_ALU:
            return None

        op_kind = _ALU_REG[alu_m]

        if op_kind == "sub" and ra != rd_lr:
            return None

        val_kind = "reg"
        val_reg = rb if ra == rd_lr else ra

    elif alu_m in _ALU_IMM:
        if is_d and alu_m in _W_ONLY_ALU:
            return None

        op_kind = _ALU_IMM[alu_m]
        if ra != rd_lr:
            return None
        val_kind = "imm"
        try:
            val_imm = int(rb, 0)
        except ValueError:
            return None
    else:
        return None

    aq = ".aq" in lr_m
    rl = (".rl" in sc_m) or (".aqrl" in sc_m)

    return LrscRmw(
        op_kind=op_kind,
        is_w_width=is_w,
        addr_reg=addr_reg,
        val_kind=val_kind,
        val_reg=val_reg,
        val_imm=val_imm,
        aq=aq,
        rl=rl,
    )


def _build_abs_operand_index(frag: AsmFragment) -> dict[str, int]:
    out = {}
    total = len(getattr(frag, "outputs", []) or []) + len(getattr(frag, "inputs", []) or [])
    for i in range(total):
        out[PHR[i]] = i
    return out


def _abs_to_input_index(frag: AsmFragment, abs_idx: int) -> Optional[int]:
    n_out = len(getattr(frag, "outputs", []) or [])
    if abs_idx < n_out:
        return None
    return abs_idx - n_out


def try_match_lrsc_rmw_raw(frag: AsmFragment, lift, xlen: int = 64) -> Optional[LrscRmw]:
    insns = list(getattr(lift, "insns", []) or [])
    cfg = getattr(lift, "cfg", None)
    m = detect(insns, cfg=cfg)
    if m is None:
        return None

    if xlen == 32 and not m.is_w_width:
        return None

    return m


def try_match_lrsc_rmw(frag: AsmFragment, lift, xlen: int = 64) -> Optional[CompatLrscRmwMatch]:
    """
    对外暴露的稳定入口。
    返回 translate.py 旧 emitter 兼容的 match 对象，便于测试 monkeypatch。
    """
    m = try_match_lrsc_rmw_raw(frag, lift, xlen=xlen)
    if m is None:
        return None

    op_index = _build_abs_operand_index(frag)

    addr_abs = op_index.get(m.addr_reg)
    if addr_abs is None:
        return None
    addr_input_index = _abs_to_input_index(frag, addr_abs)
    if addr_input_index is None:
        return None

    arg_input_index = None
    arg_imm = None
    if m.val_kind == "reg":
        val_abs = op_index.get(m.val_reg or "")
        if val_abs is None:
            return None
        arg_input_index = _abs_to_input_index(frag, val_abs)
        if arg_input_index is None:
            return None
    else:
        arg_imm = m.val_imm

    old_output_index = 0 if getattr(frag, "outputs", None) else None

    return CompatLrscRmwMatch(
        width_bits=32 if m.is_w_width else 64,
        addr_input_index=addr_input_index,
        arg_input_index=arg_input_index,
        arg_imm=arg_imm,
        old_output_index=old_output_index,
        op=m.op_kind,
        aq=m.aq,
        rl=m.rl,
    )


def emit_c(frag: AsmFragment, m: LrscRmw) -> Tuple[str, List[str]]:
    """
    输出形如：
      do {
        uint32_t __r2x_old = __atomic_fetch_add((volatile uint32_t*)addr,
                                                (uint32_t)val,
                                                __ATOMIC_ACQ_REL);
        old_v = (int64_t)(int32_t)__r2x_old;
      } while (0)
    """
    old_lvalue = frag.outputs[0].exprText if frag.outputs else None
    addr_expr = _resolve_operand_expr(frag, m.addr_reg)

    if m.val_kind == "reg":
        val_expr = _resolve_operand_expr(frag, m.val_reg)
    else:
        val_expr = str(m.val_imm)

    cty = "uint32_t" if m.is_w_width else "uint64_t"
    sext = "(int64_t)(int32_t)" if m.is_w_width else "(int64_t)"

    builtin = {
        "add": "__atomic_fetch_add",
        "sub": "__atomic_fetch_sub",
        "and": "__atomic_fetch_and",
        "or":  "__atomic_fetch_or",
        "xor": "__atomic_fetch_xor",
    }[m.op_kind]

    if m.aq and m.rl:
        order = "__ATOMIC_ACQ_REL"
    elif m.aq:
        order = "__ATOMIC_ACQUIRE"
    elif m.rl:
        order = "__ATOMIC_RELEASE"
    else:
        order = "__ATOMIC_RELAXED"

    pointer = f"(volatile {cty} *)({addr_expr})"
    call = f"{builtin}({pointer}, ({cty})({val_expr}), {order})"

    if old_lvalue is not None:
        body = (
            f"do {{ {cty} __r2x_old = {call}; "
            f"({old_lvalue}) = {sext}__r2x_old; }} while (0)"
        )
    else:
        body = f"do {{ (void){call}; }} while (0)"

    notes = [
        f"LR/SC RMW: {m.op_kind}{' w' if m.is_w_width else ' d'} "
        f"aq={m.aq} rl={m.rl}"
    ]
    return body, notes


def emit_x86_inline_asm(frag: AsmFragment, m: LrscRmw) -> Tuple[str, List[str]]:
    """
    输出 x86 cmpxchg retry-loop 模板，保留 LR/SC + ALU 的重试轮廓。
    """
    old_lvalue = frag.outputs[0].exprText if frag.outputs else None
    addr_expr = _resolve_operand_expr(frag, m.addr_reg)

    if m.val_kind == "reg":
        val_expr = _resolve_operand_expr(frag, m.val_reg)
    else:
        val_expr = str(m.val_imm)

    cty = "uint32_t" if m.is_w_width else "uint64_t"
    asm_sfx = "l" if m.is_w_width else "q"
    acc = "%%eax" if m.is_w_width else "%%rax"
    tmp = "%%edx" if m.is_w_width else "%%rdx"

    alu = {
        "add": f"add{asm_sfx}",
        "sub": f"sub{asm_sfx}",
        "and": f"and{asm_sfx}",
        "or":  f"or{asm_sfx}",
        "xor": f"xor{asm_sfx}",
    }[m.op_kind]

    sext = "(int64_t)(int32_t)__r2x_old" if m.is_w_width else "(int64_t)__r2x_old"
    assign_old = f"({old_lvalue}) = {sext};" if old_lvalue is not None else ""

    if m.aq and m.rl:
        order = "__ATOMIC_ACQ_REL"
    elif m.aq:
        order = "__ATOMIC_ACQUIRE"
    elif m.rl:
        order = "__ATOMIC_RELEASE"
    else:
        order = "__ATOMIC_RELAXED"

    body = f"""
do {{
    volatile {cty} *__r2x_p = (volatile {cty} *)({addr_expr});
    {cty} __r2x_arg = ({cty})({val_expr});
    {cty} __r2x_old = 0;
    {cty} __r2x_new = 0;

    __asm__ __volatile__(
        "1:\\n\\t"
        "mov{asm_sfx} %[mem], {acc}\\n\\t"
        "mov{asm_sfx} {acc}, {tmp}\\n\\t"
        "{alu} %[arg], {tmp}\\n\\t"
        "lock cmpxchg{asm_sfx} {tmp}, %[mem]\\n\\t"
        "jne 1b\\n\\t"
        : [mem] "+m"(*__r2x_p),
          "=&a"(__r2x_old),
          "=&d"(__r2x_new)
        : [arg] "r"(__r2x_arg)
        : "cc", "memory"
    );

    {assign_old}
}} while (0)
""".strip()

    notes = [
        f"LR/SC RMW: {m.op_kind}{' w' if m.is_w_width else ' d'} aq={m.aq} rl={m.rl}",
        f"LR/SC RMW x86 microarch template: lock cmpxchg retry loop ({order})",
        "preserve_control_shape=cmpxchg_retry_loop",
        "phase6.x86_inline_asm",
        "memory-order equivalence not fully modeled; x86 lock/cmpxchg chosen conservatively",
    ]
    return body, notes