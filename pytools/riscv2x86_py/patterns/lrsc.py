"""
LR/SC -> __atomic_compare_exchange 模式识别。

输入：lifted 指令序列 + CFG。
输出：MatchedCAS 或 None。
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Dict
import re

from ..lift import LiftedInsn
from ..cfg import CFGResult
from ..schema import AsmFragment
from ..assemble import _PLACEHOLDER_REGS_INT as PHR

def _all_ops(frag: AsmFragment):
    return list(frag.outputs) + list(frag.inputs)


def _expr_at(frag: AsmFragment, idx: int) -> str:
    ops = _all_ops(frag)
    return ops[idx].exprText


def _order_note(success_order: str, failure_order: str) -> list[str]:
    return [
        f"success_order={success_order}",
        f"failure_order={failure_order}",
        "memory-order equivalence not fully modeled; x86 lock/cmpxchg chosen conservatively",
    ]


def emit_x86_inline_asm(frag: AsmFragment, m: MatchedCAS):
    """
    输出 x86 cmpxchg 模板：
      - weak: 单次 lock cmpxchg
      - strong: load/compare/cmpxchg/retry loop
    """
    addr_expr = _expr_at(frag, m.addr_operand_idx)
    expected_expr = _expr_at(frag, m.expected_operand_idx)
    desired_expr = _expr_at(frag, m.desired_operand_idx)

    old_lvalue = frag.outputs[m.old_output_idx].exprText
    status_lvalue = (
        frag.outputs[m.sc_status_output_idx].exprText
        if m.sc_status_output_idx is not None and 0 <= m.sc_status_output_idx < len(frag.outputs)
        else None
    )

    cty = "uint32_t" if m.width == 32 else "uint64_t"
    asm_sfx = "l" if m.width == 32 else "q"
    sext_old = "(int64_t)(int32_t)__r2x_old" if m.width == 32 else "(int64_t)__r2x_old"

    assign_old = f"({old_lvalue}) = {sext_old};"
    assign_status = f"({status_lvalue}) = __r2x_ok ? 0 : 1;" if status_lvalue else ""

    if m.is_weak:
        body = f"""
do {{
    volatile {cty} *__r2x_p = (volatile {cty} *)({addr_expr});
    {cty} __r2x_expected = ({cty})({expected_expr});
    {cty} __r2x_desired  = ({cty})({desired_expr});
    {cty} __r2x_old = __r2x_expected;
    unsigned char __r2x_ok = 0;

    __asm__ __volatile__(
        "lock cmpxchg{asm_sfx} %[desired], %[mem]\\n\\t"
        "sete %[ok]\\n\\t"
        : [mem] "+m"(*__r2x_p),
          "+a"(__r2x_old),
          [ok] "=q"(__r2x_ok)
        : [desired] "r"(__r2x_desired)
        : "cc", "memory"
    );

    {assign_old}
    {assign_status}
}} while (0)
""".strip()

        notes = [
            f"LR/SC CAS width={m.width} weak",
            "LR/SC CAS x86 microarch template: one-shot lock cmpxchg",
            "preserve_control_shape=single_attempt_cmpxchg",
            m.explain,
            *_order_note(m.success_order, m.failure_order),
            "phase6.x86_inline_asm",
        ]
        return body, notes

    body = f"""
do {{
    volatile {cty} *__r2x_p = (volatile {cty} *)({addr_expr});
    {cty} __r2x_expected = ({cty})({expected_expr});
    {cty} __r2x_desired  = ({cty})({desired_expr});
    {cty} __r2x_old = 0;
    unsigned char __r2x_ok = 0;

    __asm__ __volatile__(
        "1:\\n\\t"
        "mov{asm_sfx} %[mem], %%rax\\n\\t"
        "cmp{asm_sfx} %[expected], %%rax\\n\\t"
        "jne 2f\\n\\t"
        "lock cmpxchg{asm_sfx} %[desired], %[mem]\\n\\t"
        "jne 1b\\n\\t"
        "2:\\n\\t"
        "sete %[ok]\\n\\t"
        : [mem] "+m"(*__r2x_p),
          "=&a"(__r2x_old),
          [ok] "=q"(__r2x_ok)
        : [expected] "r"(__r2x_expected),
          [desired] "r"(__r2x_desired)
        : "cc", "memory"
    );

    {assign_old}
    {assign_status}
}} while (0)
""".strip()

    notes = [
        f"LR/SC CAS width={m.width} strong",
        "LR/SC CAS x86 microarch template: cmp/load/cmpxchg retry loop",
        "preserve_control_shape=cmpxchg_retry_loop",
        m.explain,
        *_order_note(m.success_order, m.failure_order),
        "phase6.x86_inline_asm",
    ]
    return body, notes


@dataclass
class MatchedCAS:
    width: int
    is_weak: bool
    success_order: str
    failure_order: str
    addr_operand_idx: int
    expected_operand_idx: int
    desired_operand_idx: int
    old_output_idx: int
    sc_status_output_idx: Optional[int]
    explain: str = ""


_LR_RE = re.compile(r"^lr\.(w|d)(?:\.(aqrl|aq|rl))?$", re.IGNORECASE)
_SC_RE = re.compile(r"^sc\.(w|d)(?:\.(aqrl|aq|rl))?$", re.IGNORECASE)

_BNE_LIKE = ("bne",)
_BNEZ_LIKE = ("bnez",)


def _split_operands(body: str) -> List[str]:
    return [p.strip() for p in (body or "").split(",") if p.strip()]


def _addr_reg(operand: str) -> Optional[str]:
    m = re.match(r"^\(([^)]+)\)$", operand.strip())
    return m.group(1).strip() if m else None


def _normalize_reg(reg: Optional[str]) -> str:
    s = (reg or "").strip().lower()
    abi_to_x = {
        "zero": "x0",  "ra": "x1",   "sp": "x2",   "gp": "x3",   "tp": "x4",
        "t0": "x5",    "t1": "x6",   "t2": "x7",   "s0": "x8",   "fp": "x8",
        "s1": "x9",    "a0": "x10",  "a1": "x11",  "a2": "x12",  "a3": "x13",
        "a4": "x14",   "a5": "x15",  "a6": "x16",  "a7": "x17",  "s2": "x18",
        "s3": "x19",   "s4": "x20",  "s5": "x21",  "s6": "x22",  "s7": "x23",
        "s8": "x24",   "s9": "x25",  "s10": "x26", "s11": "x27", "t3": "x28",
        "t4": "x29",   "t5": "x30",  "t6": "x31",
    }
    return abi_to_x.get(s, s)


def _lookup_operand_index(operand_index_map: Dict[str, int], reg: str) -> int:
    return operand_index_map.get(_normalize_reg(reg), -1)


def _lookup_output_index(output_index_map: Optional[Dict[str, int]], reg: str) -> int:
    if not output_index_map:
        return -1
    return output_index_map.get(_normalize_reg(reg), -1)


def _find_block_containing(cfg: CFGResult, addr: int) -> Optional[int]:
    if not cfg.ok or not cfg.nodes:
        return None
    for baddr, node in cfg.nodes.items():
        if addr in node.instr_addrs:
            return baddr
    return None


def _has_backedge_to(cfg: CFGResult, from_addr: int, to_addr: int) -> bool:
    """
    检查 from_addr 所在块是否有 CFG successor 指向 to_addr 所在块。
    """
    if not cfg.ok or not cfg.nodes:
        return False

    src_block = _find_block_containing(cfg, from_addr)
    dst_block = _find_block_containing(cfg, to_addr)
    if src_block is None or dst_block is None:
        return False

    src = cfg.nodes.get(src_block)
    if src is None:
        return False

    if dst_block in src.successors:
        return True

    # 再保守一点：若 successor 对应块中包含 to_addr，也算
    for s in src.successors:
        node = cfg.nodes.get(s)
        if node and to_addr in node.instr_addrs:
            return True
    return False


def _bits_from_suffix(suffix: Optional[str]) -> tuple[bool, bool]:
    s = (suffix or "").lower()
    has_acquire = s in ("aq", "aqrl")
    has_release = s in ("rl", "aqrl")
    return has_acquire, has_release


def _success_order_from_pair(lr_suffix: Optional[str], sc_suffix: Optional[str]) -> str:
    """
    成功路径：lr/sc 的 acquire/release 位取并集，再映射成 GCC __ATOMIC_*。
    这比“retry loop 一律 SEQ_CST”更接近原始 asm 语义。
    """
    lr_aq, lr_rl = _bits_from_suffix(lr_suffix)
    sc_aq, sc_rl = _bits_from_suffix(sc_suffix)

    has_acquire = lr_aq or sc_aq
    has_release = lr_rl or sc_rl

    if has_acquire and has_release:
        return "__ATOMIC_ACQ_REL"
    if has_acquire:
        return "__ATOMIC_ACQUIRE"
    if has_release:
        return "__ATOMIC_RELEASE"
    return "__ATOMIC_RELAXED"


def _mnem(ins) -> str:
    return (getattr(ins, "asm_mnem", "") or "").strip().lower()


def _failure_order_from_lr(lr_suffix: Optional[str], success_order: str) -> str:
    s = (lr_suffix or "").lower()

    # 失败路径只发生了 load-reserve，不能用 RELEASE / ACQ_REL
    if s in ("aq", "aqrl"):
        return "__ATOMIC_ACQUIRE"

    # rl 对失败路径没有意义，降到 relaxed
    return "__ATOMIC_RELAXED"


def detect_cas(
    insns: List[LiftedInsn],
    cfg: CFGResult,
    operand_index_map: Dict[str, int],
    *,
    output_count: int,
) -> Optional[MatchedCAS]:
    """
    operand_index_map:
        把“占位寄存器名”(a0/a1/... 或 x10/x11/...) 映射回 frag.outputs+inputs 的全局索引。

    output_count:
        frag.outputs 的数量。由于全局索引布局为 outputs 在前、inputs 在后，
        所以若某寄存器映射得到的全局索引 idx 满足 0 <= idx < output_count，
        则其对应的局部 output 索引就是 idx 本身。
    """
    if len(insns) < 3:
        return None

    def lookup_global(reg: str) -> int:
        return _lookup_operand_index(operand_index_map, reg)

    def lookup_output(reg: str) -> int:
        idx = lookup_global(reg)
        return idx if 0 <= idx < output_count else -1

    # 1) 找 lr
    lr_idx = None
    for i, ins in enumerate(insns):
        if _LR_RE.match(ins.asm_mnem.strip()):
            lr_idx = i
            break
    if lr_idx is None:
        return None

    lr = insns[lr_idx]
    m_lr = _LR_RE.match(lr.asm_mnem.strip())
    width = 32 if m_lr.group(1).lower() == "w" else 64
    lr_ord = m_lr.group(2)

    lr_ops = _split_operands(lr.asm_body)
    if len(lr_ops) < 2:
        return None

    rd_old_reg = _normalize_reg(lr_ops[0])
    addr_reg_lr = _addr_reg(lr_ops[1])
    if addr_reg_lr is None:
        return None
    addr_reg_lr = _normalize_reg(addr_reg_lr)

    # 2) lr 后第一条必须是 bne old, expected, fail
    if lr_idx + 1 >= len(insns):
        return None

    bne = insns[lr_idx + 1]
    bne_mnem = _mnem(bne)
    if bne_mnem not in _BNE_LIKE:
        return None

    bne_ops = _split_operands(bne.asm_body)
    if len(bne_ops) < 3:
        return None

    lhs = _normalize_reg(bne_ops[0])
    rhs = _normalize_reg(bne_ops[1])

    if lhs == rd_old_reg:
        expected_reg = rhs
    elif rhs == rd_old_reg:
        expected_reg = lhs
    else:
        return None

    # 3) 下一条必须是 sc
    if lr_idx + 2 >= len(insns):
        return None

    sc = insns[lr_idx + 2]
    m_sc = _SC_RE.match(sc.asm_mnem.strip())
    if not m_sc:
        return None

    sc_width = 32 if m_sc.group(1).lower() == "w" else 64
    if sc_width != width:
        return None

    sc_ord = m_sc.group(2)
    sc_ops = _split_operands(sc.asm_body)
    if len(sc_ops) < 3:
        return None

    rd_sc_reg = _normalize_reg(sc_ops[0])
    desired_reg = _normalize_reg(sc_ops[1])
    addr_reg_sc = _addr_reg(sc_ops[2])
    if addr_reg_sc is None:
        return None
    addr_reg_sc = _normalize_reg(addr_reg_sc)

    if addr_reg_sc != addr_reg_lr:
        return None

    # 4) 可选：紧跟 bnez rd_sc, 1b -> retry loop => strong
    is_weak = True
    if lr_idx + 3 < len(insns):
        nxt = insns[lr_idx + 3]
        nxt_mnem = _mnem(nxt)
        if nxt_mnem in _BNEZ_LIKE:
            ops = _split_operands(nxt.asm_body)
            if ops and _normalize_reg(ops[0]) == rd_sc_reg:
                if _has_backedge_to(cfg, nxt.addr, lr.addr):
                    is_weak = False

    addr_op_idx = lookup_global(addr_reg_lr)
    expected_op_idx = lookup_global(expected_reg)
    desired_op_idx = lookup_global(desired_reg)
    old_out_idx = lookup_output(rd_old_reg)
    sc_out_idx = lookup_output(rd_sc_reg)

    if min(addr_op_idx, expected_op_idx, desired_op_idx, old_out_idx) < 0:
        return None

    success_order = _success_order_from_pair(lr_ord, sc_ord)
    failure_order = _failure_order_from_lr(lr_ord, success_order)

    return MatchedCAS(
        width=width,
        is_weak=is_weak,
        success_order=success_order,
        failure_order=failure_order,
        addr_operand_idx=addr_op_idx,
        expected_operand_idx=expected_op_idx,
        desired_operand_idx=desired_op_idx,
        old_output_idx=old_out_idx,
        sc_status_output_idx=sc_out_idx if sc_out_idx >= 0 else None,
        explain=(
            f"LR/SC {'retry' if not is_weak else 'one-shot'} CAS "
            f"width={width} succ={success_order} fail={failure_order}"
        ),
    )