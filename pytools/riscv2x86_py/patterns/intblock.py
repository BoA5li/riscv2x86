from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
import os
import re

from ..assemble import _PLACEHOLDER_REGS_INT
from .integer import LowerCtx, lower_basic_block
from .structurize import Line, structurize
from .pic import detect_pic_pairs


_DBG = os.environ.get("R2X_INTBLOCK_DEBUG", "").strip() not in ("", "0", "false", "False")


def _dbg(msg: str) -> None:
    if _DBG:
        print(f"[intblock] {msg}")


@dataclass
class IntegerBlockResult:
    body: str
    notes: List[str]


# ----------------------------------------------------------------------
# 操作数/寄存器映射
# ----------------------------------------------------------------------

def _build_operand_index_map(frag) -> Dict[str, int]:
    """
    维持与 assemble 阶段一致的占位寄存器 -> operand index 映射。
    这里只保留“主拼写”，寄存器别名解析在 _resolve_reg_expr/_bind_reg_expr 中处理。
    """
    m: Dict[str, int] = {}
    n = len(frag.outputs) + len(frag.inputs)
    for i in range(n):
        reg = _PLACEHOLDER_REGS_INT[i % len(_PLACEHOLDER_REGS_INT)]
        m[reg] = i
    return m


def _build_index_to_reg(op_index: Dict[str, int]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for reg, idx in op_index.items():
        out[idx] = reg
    return out


def _sanitize_reg(reg: str) -> str:
    reg = (reg or "").strip().lower()
    return re.sub(r"[^0-9A-Za-z_]", "_", reg)

def _reg_value_ctype(xlen: int) -> str:
    """
    intblock 内部“寄存器状态槽”的最小类型选择。
    这里只做 xlen-aware unsigned normalization：
      - RV32 -> uint32_t
      - RV64 -> uint64_t
    """
    return "uint32_t" if int(xlen) <= 32 else "uint64_t"


def _cast_reg_value(expr: str, xlen: int) -> str:
    """
    把任意表达式收口到目标寄存器值宽度。
    这是 intblock 层最重要的一道边界归一化。
    """
    cty = _reg_value_ctype(xlen)
    return f"(({cty})({expr}))"


def _carrier_reg_value(expr: str, xlen: int) -> str:
    """
    对外继续维持现有“uint64_t carrier expression”接口，
    但 carrier 之前先做一次 xlen 归一化。
    这样不会破坏现有 lower_basic_block / ctx.var_of 的使用习惯。
    """
    return f"((uint64_t){_cast_reg_value(expr, xlen)})"


_RISCV_ABI_TO_X = {
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

_RISCV_X_TO_ABI = {
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


def _normalize_reg(reg: str) -> str:
    reg = (reg or "").strip().lower()
    if not reg:
        return ""
    if reg in _RISCV_ABI_TO_X:
        return reg
    if re.fullmatch(r"x([0-9]|[12][0-9]|3[01])", reg):
        return reg
    return reg


def _abi_alias_of(reg: str) -> Optional[str]:
    reg = _normalize_reg(reg)
    if reg in _RISCV_X_TO_ABI:
        return _RISCV_X_TO_ABI[reg]
    return None


def _x_alias_of(reg: str) -> Optional[str]:
    reg = _normalize_reg(reg)
    if reg in _RISCV_ABI_TO_X:
        return _RISCV_ABI_TO_X[reg]
    if re.fullmatch(r"x([0-9]|[12][0-9]|3[01])", reg):
        return reg
    return None


def _reg_aliases(reg: str) -> List[str]:
    reg = _normalize_reg(reg)
    if not reg:
        return []

    out: List[str] = []

    def add(x: Optional[str]) -> None:
        if x and x not in out:
            out.append(x)

    add(reg)

    x = _x_alias_of(reg)
    abi = _abi_alias_of(reg)

    add(x)
    add(abi)

    if x == "x8":
        add("fp")
    if reg == "fp":
        add("s0")
        add("x8")

    return out


def _bind_reg_expr(ctx: "_FlowCtx", reg: str, expr: str) -> None:
    for name in _reg_aliases(reg):
        ctx.var_of[name] = expr


def _bind_state_var(ctx: "_FlowCtx", reg: str, state_name: str) -> None:
    for name in _reg_aliases(reg):
        ctx.state_of[name] = state_name


def _resolve_reg_expr(ctx: "_FlowCtx", reg: str) -> str:
    reg = _normalize_reg(reg)
    xlen = getattr(ctx, "xlen", 64)

    if reg in ("x0", "zero"):
        return _carrier_reg_value("0", xlen)

    aliases = _reg_aliases(reg)

    for name in aliases:
        if name in ctx.state_of:
            return _carrier_reg_value(ctx.state_of[name], xlen)

    for name in aliases:
        if name in ctx.var_of:
            return ctx.var_of[name]

    for name in aliases:
        if name in ctx.op_index:
            return _carrier_reg_value(f"__r2x_in_{name}", xlen)

    return _carrier_reg_value("0", xlen)


# ----------------------------------------------------------------------
# 指令地址/位置辅助
# ----------------------------------------------------------------------

def _insn_size(ins) -> int:
    sz = getattr(ins, "size", None)
    if isinstance(sz, int) and sz > 0:
        return sz

    ln = getattr(ins, "length", None)
    if isinstance(ln, int) and ln > 0:
        return ln

    mnem = (getattr(ins, "asm_mnem", "") or "").lower().strip()
    if mnem.startswith("c."):
        return 2
    return 4


def _insn_end_pos(ins) -> int:
    return int(getattr(ins, "addr")) + _insn_size(ins)


# ----------------------------------------------------------------------
# FlowCtx：把 integer lowering 的“寄存器表达式”桥接到结构化 C 块
# ----------------------------------------------------------------------

class _FlowCtx(LowerCtx):
    """
    关键点：
    - integer.py 内部把 define_reg() 的结果放到 ctx.var_of
    - intblock 这里再把“当前寄存器值”物化到 state 变量，供后续多条语句稳定读取
    - var_for_reg() 永远优先读 state_of / var_of，最后才回退到 __r2x_in_<reg>

    最小 xlen-aware 修订：
    - state/input 槽位不再固定为 uint64_t
    - 改为按 xlen 选择 uint32_t / uint64_t
    - 但对外仍维持 uint64_t carrier expression，尽量不破坏其它 lowering
    """
    def __init__(self, op_index: Dict[str, int], output_count: int, xlen: int):
        super().__init__(
            op_index=op_index,
            output_count=output_count,
            var_of={},
            decls=[],
            next_tmp=0,
            xlen=xlen,
        )
        self.top_decls: List[str] = []
        self.state_of: Dict[str, str] = {}
        self.reg_value_ctype: str = _reg_value_ctype(xlen)

    def var_for_reg(self, reg: str) -> str:
        return _resolve_reg_expr(self, reg)

    def normalize_reg_store(self, expr: str) -> str:
        return _cast_reg_value(expr, self.xlen)

    def reg_read_expr(self, expr: str) -> str:
        return _carrier_reg_value(expr, self.xlen)

    def ensure_state_var(self, reg: str) -> str:
        reg = _normalize_reg(reg)
        existing = self.state_of.get(reg)
        if existing is not None:
            return existing

        name = f"__r2x_state_{_sanitize_reg(reg)}"
        _bind_state_var(self, reg, name)

        init_reg = next((r for r in _reg_aliases(reg) if r in self.op_index), None)
        if init_reg is not None:
            init = self.normalize_reg_store(f"__r2x_in_{init_reg}")
        else:
            init = self.normalize_reg_store("0")

        self.top_decls.append(f"{self.reg_value_ctype} {name} = {init};")
        return name


# ----------------------------------------------------------------------
# PIC 绑定注入
# ----------------------------------------------------------------------

def _pic_consumed_addrs(pic_bindings) -> Set[int]:
    out: Set[int] = set()
    for b in list(pic_bindings or []):
        for a in getattr(b, "consumed_insn_addrs", []) or []:
            try:
                out.add(int(a))
            except Exception:
                pass
    return out


def _inject_pic_bindings(ctx: _FlowCtx, pic_bindings) -> List[str]:
    notes: List[str] = []
    for b in list(pic_bindings or []):
        expr = getattr(b, "c_expr", "") or ""
        reg = getattr(b, "reg", "") or ""
        if not expr or not reg:
            continue

        _bind_reg_expr(ctx, reg, expr)
        notes.append(f"pic-bound {reg} -> {expr}")
    return notes


def _prepare_pic_bindings(frag, insns, *, xlen: int):
    """
    自动识别 auipc/addi 等 PIC 地址装载对，并生成：
      bindings, consumed_addrs, notes
    """
    bindings = detect_pic_pairs(insns, frag, xlen=xlen)
    consumed = _pic_consumed_addrs(bindings)
    notes: List[str] = []

    for b in bindings:
        cname = ""
        if 0 <= getattr(b, "sym_index", -1) < len(frag.symbols):
            cname = getattr(frag.symbols[b.sym_index], "cName", "") or ""

        msg = (
            f"PIC injected into integer block: reg={b.reg} "
            f"sym_index={b.sym_index}"
        )
        if cname:
            msg += f" -> &{cname}"
        notes.append(msg)

    return bindings, consumed, notes


# ----------------------------------------------------------------------
# 输入物化 / 语句映射 / 控制流目标归一
# ----------------------------------------------------------------------

def _materialize_operand_inputs(ctx: _FlowCtx, frag, idx_to_reg: Dict[int, str]) -> None:
    """
    统一生成 __r2x_in_<reg>，并把输入/输出占位寄存器的初值绑定到 ctx。
    - output 初值先置 0
    - input 初值来自 exprText

    最小 xlen-aware 修订：
    - __r2x_in_* 不再固定 uint64_t，而是按 xlen 选择槽位类型
    - 绑定到 ctx 的读取表达式仍保持 uint64_t carrier 形式
    """
    total = len(frag.outputs) + len(frag.inputs)

    for idx in range(total):
        reg = idx_to_reg[idx]
        name = f"__r2x_in_{reg}"

        if idx < len(frag.outputs):
            init = "0"
        else:
            in_op = frag.inputs[idx - len(frag.outputs)]
            init = getattr(in_op, "exprText", None) or str(in_op)

        ctx.top_decls.append(
            f"{ctx.reg_value_ctype} {name} = {ctx.normalize_reg_store(init)};"
        )

        expr = ctx.reg_read_expr(name)
        _bind_reg_expr(ctx, reg, expr)


def _emit_stmt_line(lines: List[Line], ins_pos: List[int], pos: int, text: str) -> None:
    if text.strip():
        lines.append(Line(text=text))
        ins_pos.append(pos)


def _map_target_to_control_pos(target_insn_pos: int, control_pos_sorted: List[int], end_pos: int) -> int:
    """
    把“跳到某条指令地址”映射到“结构化控制位置”：
    - 若目标地址恰好对应某条可执行位置，则直接落到该位置
    - 若目标地址是标签/NOP/已消费 PIC 指令，则前移到最近后继可执行位置
    - 若后续已无语句，则落到 end_pos
    """
    for p in control_pos_sorted:
        if p >= target_insn_pos:
            return p
    return end_pos


def _resolve_target_pos(cur_addr: int,
                        cur_size: int,
                        raw_target: int,
                        valid_insn_pos: Set[int],
                        control_pos_sorted: List[int],
                        end_pos: int) -> Optional[int]:
    """
    lower_basic_block 给出的 target 可能是：
      1) 绝对地址
      2) 相对当前 PC 的偏移
      3) 相对下一条 PC 的偏移
    这里全部试一遍，然后再映射到 structurize 的控制位置坐标系。
    """
    cands = (
        raw_target,
        cur_addr + raw_target,
        cur_addr + cur_size + raw_target,
    )

    for c in cands:
        if c == end_pos:
            return end_pos
        if c in valid_insn_pos:
            return _map_target_to_control_pos(c, control_pos_sorted, end_pos)

    return None


# ----------------------------------------------------------------------
# 主入口
# ----------------------------------------------------------------------

def try_integer_block(frag, lift, pic_bindings=None, xlen: int = 64) -> Optional[IntegerBlockResult]:
    _dbg(f"enter try_integer_block: {__file__}")

    all_insns = list(getattr(lift, "insns", []) or [])
    if not all_insns:
        _dbg("FAIL: no insns")
        return None

    _dbg(f"insn count = {len(all_insns)}")
    for ins in all_insns:
        _dbg(
            f"  ins @0x{getattr(ins, 'addr'):x}: "
            f"{getattr(ins, 'asm_mnem', '')} {getattr(ins, 'asm_body', '')}"
        )

    op_index = _build_operand_index_map(frag)
    idx_to_reg = _build_index_to_reg(op_index)

    _dbg(f"op_index = {op_index}")
    _dbg(f"idx_to_reg = {idx_to_reg}")

    ctx = _FlowCtx(
        op_index=op_index,
        output_count=len(frag.outputs),
        xlen=xlen,
    )
    _materialize_operand_inputs(ctx, frag, idx_to_reg)

    notes: List[str] = []

    # ------------------------------------------------------------
    # 1) 先处理 PIC 绑定
    #    - 外部传入：直接消费
    #    - 未传入：自动识别
    # ------------------------------------------------------------
    external_pic_bindings = list(pic_bindings or [])
    consumed_pic_insns: Set[int] = set()

    if external_pic_bindings:
        notes.extend(_inject_pic_bindings(ctx, external_pic_bindings))
        consumed_pic_insns |= _pic_consumed_addrs(external_pic_bindings)
    else:
        try:
            auto_pic_bindings, auto_consumed, auto_notes = _prepare_pic_bindings(
                frag,
                all_insns,
                xlen=xlen,
            )
        except ValueError as e:
            _dbg(f"FAIL: PIC binding preparation failed: {e}")
            return None

        notes.extend(auto_notes)
        notes.extend(_inject_pic_bindings(ctx, auto_pic_bindings))
        consumed_pic_insns |= auto_consumed

    # ------------------------------------------------------------
    # 2) 把已被 PIC 消费的 auipc/addi 等指令从 intblock lowering 中滤掉
    # ------------------------------------------------------------
    insns = [ins for ins in all_insns if int(getattr(ins, "addr")) not in consumed_pic_insns]

    if not insns:
        _dbg("FAIL: no non-PIC insns remain for integer block")
        return None

    _dbg("top_decls after operand materialization:")
    for d in ctx.top_decls:
        _dbg(f"  {d}")

    # ------------------------------------------------------------
    # 3) 逐指令桥接：
    #    - 让 integer.py 完成单条 lowering
    #    - 把 define_reg() 产生的“新值”同步物化成 state 变量写回
    #    - 再把控制流/普通语句映射成 structurize.Line
    # ------------------------------------------------------------
    lines: List[Line] = []
    ins_pos: List[int] = []
    control_meta: Dict[int, Tuple[int, int]] = {}   # line_idx -> (src_addr, insn_size)

    valid_insn_pos = {int(getattr(ins, "addr")) for ins in insns}
    end_pos = _insn_end_pos(insns[-1])

    saw_control = False

    for ins in insns:
        pos = getattr(ins, "addr", None)
        if pos is None:
            _dbg("FAIL: ins.addr is None")
            return None

        pos = int(pos)
        _dbg(f"lower ins @0x{pos:x}: {getattr(ins, 'asm_mnem', '')} {getattr(ins, 'asm_body', '')}")

        before_decl_len = len(ctx.decls)
        before_var = dict(ctx.var_of)

        lowered = lower_basic_block([ins], ctx)
        if lowered is None:
            _dbg(
                f"FAIL: lower_basic_block returned None at 0x{pos:x}: "
                f"{getattr(ins, 'asm_mnem', '')} {getattr(ins, 'asm_body', '')}"
            )
            return None

        # 3.1 收集这条指令 lowering 新追加的 decls
        new_decls = ctx.decls[before_decl_len:]
        for d in new_decls:
            _dbg(f"  new decl: {d}")
            _emit_stmt_line(lines, ins_pos, pos, d)

        # 3.2 把这条指令修改过的寄存器物化到 state 变量
        changed_regs: List[str] = []
        for reg, expr in ctx.var_of.items():
            if before_var.get(reg) != expr:
                changed_regs.append(reg)

        seen_states: Set[str] = set()
        for reg in changed_regs:
            state = ctx.ensure_state_var(reg)
            new_expr = ctx.var_of[reg]
            normalized_expr = ctx.normalize_reg_store(new_expr)

            if state not in seen_states:
                stmt = f"{state} = {normalized_expr};"
                _dbg(f"  state write: {stmt}")
                _emit_stmt_line(lines, ins_pos, pos, stmt)
                seen_states.add(state)

            _bind_reg_expr(ctx, reg, ctx.reg_read_expr(state))

        # 3.3 把 lowered stmt 映射成结构化输入
        for st in lowered:
            stmt_pos = int(st.src_addr) if st.src_addr is not None else pos

            if st.is_branch:
                if st.branch_target is None or st.branch_cond is None:
                    _dbg(f"FAIL: malformed branch stmt at 0x{stmt_pos:x}: {st}")
                    return None

                saw_control = True
                line_idx = len(lines)
                lines.append(Line(
                    text="",
                    is_branch=True,
                    is_jump=False,
                    cond=st.branch_cond,
                    target_pos=st.branch_target,   # 先放 raw target，后面再解析
                ))
                ins_pos.append(stmt_pos)
                control_meta[line_idx] = (stmt_pos, _insn_size(ins))
                _dbg(f"  raw branch: cond={st.branch_cond} raw_target={st.branch_target}")

            elif st.is_jump:
                if st.branch_target is None:
                    _dbg(f"FAIL: malformed jump stmt at 0x{stmt_pos:x}: {st}")
                    return None

                saw_control = True
                line_idx = len(lines)
                lines.append(Line(
                    text="",
                    is_branch=False,
                    is_jump=True,
                    cond=None,
                    target_pos=st.branch_target,   # 先放 raw target，后面再解析
                ))
                ins_pos.append(stmt_pos)
                control_meta[line_idx] = (stmt_pos, _insn_size(ins))
                _dbg(f"  raw jump: raw_target={st.branch_target}")

            else:
                _dbg(f"  stmt: {st.text}")
                _emit_stmt_line(lines, ins_pos, stmt_pos, st.text)

    # ------------------------------------------------------------
    # 4) 把 branch/jump 目标转成 structurize 所需的“块内控制位置”
    # ------------------------------------------------------------
    control_pos_sorted = sorted(set(ins_pos) | {end_pos})
    _dbg(f"end_pos = 0x{end_pos:x}")
    _dbg(f"control_pos_sorted = {[hex(x) for x in control_pos_sorted]}")

    for idx, (src_addr, src_size) in control_meta.items():
        raw_target = lines[idx].target_pos
        resolved = _resolve_target_pos(
            cur_addr=src_addr,
            cur_size=src_size,
            raw_target=raw_target,
            valid_insn_pos=valid_insn_pos,
            control_pos_sorted=control_pos_sorted,
            end_pos=end_pos,
        )
        _dbg(
            f"resolve target: line#{idx} src=0x{src_addr:x} "
            f"raw={raw_target} -> {None if resolved is None else hex(resolved)}"
        )
        if resolved is None:
            _dbg("FAIL: target resolution failed")
            return None
        lines[idx].target_pos = resolved

    # 若整块没有任何“真实语句”，说明只是控制流壳子，拒绝匹配
    has_real_stmt = any(
        (not getattr(ln, "is_branch", False))
        and (not getattr(ln, "is_jump", False))
        and bool((getattr(ln, "text", "") or "").strip())
        for ln in lines
    )
    if not has_real_stmt:
        _dbg("FAIL: block has no real statements (control-only/empty block)")
        return None

    label_for_pos = {p: f"L_{p:x}" for p in sorted(set(ins_pos))}

    _dbg("final lines before structurize:")
    for i, (ln, p) in enumerate(zip(lines, ins_pos)):
        _dbg(
            f"  [{i}] pos=0x{p:x} text={ln.text!r} "
            f"is_branch={getattr(ln, 'is_branch', False)} "
            f"is_jump={getattr(ln, 'is_jump', False)} "
            f"cond={getattr(ln, 'cond', None)!r} "
            f"target={getattr(ln, 'target_pos', None)!r}"
        )

    structured = structurize(lines, ins_pos, label_for_pos, end_pos)
    if structured is None:
        _dbg("FAIL: structurize returned None")
        return None

    _dbg("structured body:")
    for s in structured:
        _dbg(f"  {s}")

    # ------------------------------------------------------------
    # 5) 输出回写
    # ------------------------------------------------------------
    writeback: List[str] = []
    for i, out_op in enumerate(frag.outputs):
        reg = idx_to_reg.get(i)
        if reg is None:
            _dbg(f"FAIL: no output reg for output index {i}")
            return None

        src = _resolve_reg_expr(ctx, reg)
        wb_src = ctx.normalize_reg_store(src)
        wb = f"{out_op.exprText} = {wb_src};"

        writeback.append(wb)
        _dbg(f"writeback: {wb}")

    # ------------------------------------------------------------
    # 6) 拼装最终 body
    # ------------------------------------------------------------
    body_lines: List[str] = []
    body_lines.extend(ctx.top_decls)
    body_lines.extend(structured)
    body_lines.extend(writeback)

    body = "do {\n" + "\n".join(f"  {x}" for x in body_lines) + "\n} while (0);"

    if saw_control:
        notes.append("matched integer forward-branch block")
    else:
        notes.append("single-block integer lowering")
    notes.append(f"intblock register width normalized at xlen={xlen}")

    return IntegerBlockResult(body=body, notes=notes)