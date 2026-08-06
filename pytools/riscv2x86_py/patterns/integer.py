"""
RV32I / RV64I（含 M）单指令到 C 表达式的显式 lowering。

设计要点：
  - LowerCtx 显式携带 xlen，所有寄存器值按 XLEN 规范化保存。
  - RV32 / RV64 的比较、移位 mask、DIV/REM 语义分别按 ISA 处理。
  - W 系（addw/divw/...）仅允许 RV64；RV32 下直接拒绝。
  - PIC 注入绑定直接通过 LowerCtx.var_of 生效。
  - 内存访问支持两种模式：
      * 默认：直接指针解引用（兼容现有测试/现有链路）
      * 严格：输出 helper 调用，避免宿主未对齐/别名语义问题
        需要外部提供：
            r2x_load_u8/u16/u32/u64(uintptr_t addr)
            r2x_store_u8/u16/u32/u64(uintptr_t addr, T value)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import os
import re

from ..lift import LiftedInsn


_DBG = os.environ.get("R2X_INTLOWER_DEBUG", "").strip() not in ("", "0", "false", "False")
_STRICT_MEM_HELPERS = os.environ.get("R2X_STRICT_MEM_HELPERS", "").strip() not in ("", "0", "false", "False")


def _dbg(msg: str) -> None:
    if _DBG:
        print(f"[integer] {msg}")


@dataclass
class LoweredStmt:
    text: str
    defines_reg: Optional[str] = None
    uses_regs: Tuple[str, ...] = ()
    is_branch: bool = False
    is_jump: bool = False
    branch_target: Optional[int] = None
    branch_cond: Optional[str] = None
    fallthrough: bool = True
    src_addr: Optional[int] = None


# ---------- 寄存器规范化 ----------

_REG_ALIAS: Dict[str, str] = {
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


def _normalize_reg(reg: str) -> str:
    if not reg:
        return ""
    r = reg.strip().lower()
    if r.startswith("%"):
        r = r[1:]
    r = r.strip()
    if r in _REG_ALIAS:
        return _REG_ALIAS[r]
    if re.fullmatch(r"x(?:[0-9]|[12][0-9]|3[01])", r):
        return r
    return r


# ---------- 解析操作数 ----------

def _split(body: str) -> List[str]:
    if not body:
        return []
    return [p.strip() for p in body.split(",") if p.strip()]


_MEM_RE = re.compile(r"^(-?\d+|-?0x[0-9a-fA-F]+)?\s*\(([^)]+)\)$")


def _parse_mem(tok: str) -> Optional[Tuple[int, str]]:
    m = _MEM_RE.match(tok)
    if not m:
        return None
    off = int(m.group(1), 0) if m.group(1) else 0
    return off, _normalize_reg(m.group(2))


# ---------- 指令分类 ----------

_LOAD_SPECS = {
    "lb":  ("int8_t",   "uint8_t",  8,  True),
    "lh":  ("int16_t",  "uint16_t", 16, True),
    "lw":  ("int32_t",  "uint32_t", 32, True),
    "ld":  ("int64_t",  "uint64_t", 64, True),
    "lbu": ("uint8_t",  "uint8_t",  8,  False),
    "lhu": ("uint16_t", "uint16_t", 16, False),
    "lwu": ("uint32_t", "uint32_t", 32, False),
}

_STORE_SPECS = {
    "sb": ("uint8_t",  8),
    "sh": ("uint16_t", 16),
    "sw": ("uint32_t", 32),
    "sd": ("uint64_t", 64),
}

_BRANCH_OPS = {
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "beqz",
    "bnez",
    "blez",
    "bgez",
    "bltz",
    "bgtz",
}

_RV64_ONLY_MNEMS = {
    "ld", "sd", "lwu",
    "addw", "subw", "sllw", "srlw", "sraw", "mulw",
    "addiw", "slliw", "srliw", "sraiw",
    "divw", "divuw", "remw", "remuw",
}

_PSEUDO = {
    "mv":     ("addi",  "{rd}, {rs}, 0"),
    "li":     None,
    "neg":    ("sub",   "{rd}, x0, {rs}"),
    "negw":   ("subw",  "{rd}, x0, {rs}"),
    "not":    ("xori",  "{rd}, {rs}, -1"),
    "sext.w": ("addiw", "{rd}, {rs}, 0"),
    "seqz":   ("sltiu", "{rd}, {rs}, 1"),
    "snez":   ("sltu",  "{rd}, x0, {rs}"),
    "sltz":   ("slt",   "{rd}, {rs}, x0"),
    "sgtz":   ("slt",   "{rd}, x0, {rs}"),
    "j":      None,
    "nop":    None,
    "ret":    None,
}


@dataclass
@dataclass
class LowerCtx:
    op_index: Dict[str, int]
    output_count: int
    var_of: Dict[str, str]
    decls: List[str]
    next_tmp: int
    xlen: int = 64

    def __post_init__(self) -> None:
        if self.xlen not in (32, 64):
            raise ValueError(f"unsupported xlen: {self.xlen}")

        self.op_index = {_normalize_reg(k): v for k, v in self.op_index.items()}
        self.var_of = {_normalize_reg(k): v for k, v in self.var_of.items()}

    def fresh(self, prefix: str = "t") -> str:
        n = self.next_tmp
        self.next_tmp += 1
        return f"__r2x_{prefix}{n}"

    # ---------- 目标 XLEN 基本类型 ----------

    def u_t(self) -> str:
        return "uint32_t" if self.xlen == 32 else "uint64_t"

    def s_t(self) -> str:
        return "int32_t" if self.xlen == 32 else "int64_t"

    def shift_mask(self) -> int:
        return 31 if self.xlen == 32 else 63

    # ---------- 显式宽度转换 ----------

    def u32(self, expr: str) -> str:
        return f"((uint32_t)({expr}))"

    def s32(self, expr: str) -> str:
        return f"((int32_t){self.u32(expr)})"

    def u64(self, expr: str) -> str:
        return f"((uint64_t)({expr}))"

    def s64(self, expr: str) -> str:
        return f"((int64_t){self.u64(expr)})"

    def u(self, expr: str) -> str:
        return self.u32(expr) if self.xlen == 32 else self.u64(expr)

    def s(self, expr: str) -> str:
        return self.s32(expr) if self.xlen == 32 else self.s64(expr)

    # ---------- 寄存器值语义桥接 ----------
    #
    # 设计目标：
    # 1) “寄存器物理存储槽”按 XLEN 发射：RV32 -> uint32_t, RV64 -> uint64_t
    # 2) 对外接口（var_for_reg）仍维持 uint64_t 桥接风格，尽量不破坏现有链路
    # 3) 所有桥接前都先做 XLEN 归一化，避免高位污染

    def reg_storage_t(self) -> str:
        """
        寄存器值落地到 decl 临时量/状态槽时使用的宿主 C 类型。
        """
        return self.u_t()

    def reg_value_expr(self, expr: str) -> str:
        """
        把任意 C 表达式规范化成“目标寄存器值”：
        - RV32: 截断到 32 位
        - RV64: 截断到 64 位
        """
        return self.u(expr)

    def wrap_reg(self, expr: str) -> str:
        """
        对外仍返回 uint64_t 风格表达式，保持与现有调用方兼容；
        但桥接前先按 XLEN 归一化。
        """
        return f"((uint64_t){self.reg_value_expr(expr)})"

    def ptr_from_reg(self, expr: str) -> str:
        """
        把寄存器值桥接到宿主 C 的 uintptr_t。
        先按 XLEN 归一化，避免 RV32 下高位脏数据被直接带入地址计算。
        注意：这只是“先按 XLEN 收口再转 uintptr_t”，并不试图彻底解决
        host pointer width 与 target pointer width 脱钩的问题。
        """
        return f"((uintptr_t){self.reg_value_expr(expr)})"

    # ---------- 寄存器读/写 ----------

    def var_for_reg(self, reg: str) -> str:
        reg = _normalize_reg(reg)
        if reg == "x0":
            return self.wrap_reg("0")
        if reg in self.var_of:
            return self.wrap_reg(self.var_of[reg])
        if reg in self.op_index:
            return self.wrap_reg(f"__r2x_in_{reg}")
        return self.wrap_reg("0")

    def define_reg(self, reg: str, c_expr: str) -> str:
        reg = _normalize_reg(reg)
        if reg == "x0":
            return f"(void)({c_expr})"

        tmp = self.fresh()
        self.decls.append(
            f"{self.reg_storage_t()} {tmp} = {self.reg_value_expr(c_expr)};"
        )
        self.var_of[reg] = tmp
        return ""

    def addr_expr(self, base_reg: str, off: int) -> str:
        base = self.var_for_reg(base_reg)
        return f"({self.ptr_from_reg(base)} + (intptr_t)({off}))"


# ---------- 压缩指令归一化 ----------

def _normalize_compressed(mnem: str, body: str) -> Optional[Tuple[str, str]]:
    """
    把常见 RVC 指令归一成已有 lowering 能处理的普通形式。
    返回 (new_mnem, new_body)，返回 None 表示该压缩指令当前不支持。
    """
    if not mnem.startswith("c."):
        return mnem, body

    base = mnem[2:]
    parts = _split(body)

    if base in {"nop", "li", "lw", "ld", "sw", "sd", "beqz", "bnez", "j"}:
        return base, body

    if base == "lwsp":
        return "lw", body
    if base == "ldsp":
        return "ld", body
    if base == "swsp":
        return "sw", body
    if base == "sdsp":
        return "sd", body

    if base in {"add", "addw", "sub", "subw", "xor", "or", "and"}:
        if len(parts) != 2:
            return None
        rd, rs2 = parts
        return base, f"{rd}, {rd}, {rs2}"

    if base in {"addi", "addiw", "andi", "slli", "srli", "srai"}:
        if len(parts) != 2:
            return None
        rd, imm = parts
        return base, f"{rd}, {rd}, {imm}"

    if base == "mv":
        if len(parts) != 2:
            return None
        rd, rs = parts
        return "mv", f"{rd}, {rs}"

    # c.jr / c.jalr / c.ebreak / c.lui / c.addi16sp / c.addi4spn
    # 这些要么 preservation policy 会拦，要么当前 generic intblock 不安全。
    return None


# ---------- 语义辅助 ----------

def _div_expr(ctx: LowerCtx, a: str, b: str) -> str:
    sa = ctx.s(a)
    sb = ctx.s(b)
    if ctx.xlen == 32:
        return (
            f"(({sb}) == 0 ? ((uint32_t)UINT32_MAX) : "
            f"(({sa}) == INT32_MIN && ({sb}) == -1 ? {ctx.u('INT32_MIN')} : {ctx.u(f'(({sa}) / ({sb}))')}))"
        )
    return (
        f"(({sb}) == 0 ? ((uint64_t)UINT64_MAX) : "
        f"(({sa}) == INT64_MIN && ({sb}) == -1 ? {ctx.u('INT64_MIN')} : {ctx.u(f'(({sa}) / ({sb}))')}))"
    )


def _divu_expr(ctx: LowerCtx, a: str, b: str) -> str:
    ua = ctx.u(a)
    ub = ctx.u(b)
    if ctx.xlen == 32:
        return f"(({ub}) == 0 ? ((uint32_t)UINT32_MAX) : {ctx.u(f'(({ua}) / ({ub}))')})"
    return f"(({ub}) == 0 ? ((uint64_t)UINT64_MAX) : {ctx.u(f'(({ua}) / ({ub}))')})"


def _rem_expr(ctx: LowerCtx, a: str, b: str) -> str:
    sa = ctx.s(a)
    sb = ctx.s(b)
    if ctx.xlen == 32:
        return (
            f"(({sb}) == 0 ? {ctx.u(a)} : "
            f"(({sa}) == INT32_MIN && ({sb}) == -1 ? ((uint32_t)0) : {ctx.u(f'(({sa}) % ({sb}))')}))"
        )
    return (
        f"(({sb}) == 0 ? {ctx.u(a)} : "
        f"(({sa}) == INT64_MIN && ({sb}) == -1 ? ((uint64_t)0) : {ctx.u(f'(({sa}) % ({sb}))')}))"
    )


def _remu_expr(ctx: LowerCtx, a: str, b: str) -> str:
    ua = ctx.u(a)
    ub = ctx.u(b)
    return f"(({ub}) == 0 ? {ctx.u(a)} : {ctx.u(f'(({ua}) % ({ub}))')})"


def _divw_expr(mnem: str, a: str, b: str, ctx: LowerCtx) -> str:
    sa = ctx.s32(a)
    sb = ctx.s32(b)
    ua = ctx.u32(a)
    ub = ctx.u32(b)

    if mnem == "divw":
        return (
            f"(({sb}) == 0 ? ((int64_t)-1) : "
            f"(({sa}) == INT32_MIN && ({sb}) == -1 ? ((int64_t)INT32_MIN) : "
            f"((int64_t)(int32_t)(({sa}) / ({sb})))))"
        )

    if mnem == "divuw":
        return f"(({ub}) == 0 ? ((int64_t)-1) : ((int64_t)(int32_t)(({ua}) / ({ub}))))"

    if mnem == "remw":
        return (
            f"(({sb}) == 0 ? ((int64_t){sa}) : "
            f"(({sa}) == INT32_MIN && ({sb}) == -1 ? ((int64_t)0) : "
            f"((int64_t)(int32_t)(({sa}) % ({sb})))))"
        )

    if mnem == "remuw":
        return f"(({ub}) == 0 ? ((int64_t)(int32_t){ua}) : ((int64_t)(int32_t)(({ua}) % ({ub}))))"

    raise AssertionError(f"unexpected W div/rem mnemonic: {mnem}")


def _lower_bin_expr(mnem: str, a: str, b: str, ctx: LowerCtx) -> Optional[str]:
    ua = ctx.u(a)
    ub = ctx.u(b)
    sa = ctx.s(a)
    sb = ctx.s(b)
    sh = ctx.shift_mask()

    if mnem == "add":
        return f"({ua} + {ub})"
    if mnem == "sub":
        return f"({ua} - {ub})"
    if mnem == "and":
        return f"({ua} & {ub})"
    if mnem == "or":
        return f"({ua} | {ub})"
    if mnem == "xor":
        return f"({ua} ^ {ub})"

    if mnem == "sll":
        return f"({ua} << ({ub} & {sh}))"
    if mnem == "srl":
        return f"({ua} >> ({ub} & {sh}))"
    if mnem == "sra":
        return ctx.u(f"({sa} >> ({ub} & {sh}))")

    if mnem == "slt":
        return f"(({sa} < {sb}) ? 1 : 0)"
    if mnem == "sltu":
        return f"(({ua} < {ub}) ? 1 : 0)"

    # mul 取低 XLEN 位；用 unsigned 乘法避免宿主有符号溢出 UB
    if mnem == "mul":
        return f"({ua} * {ub})"

    if mnem == "div":
        return _div_expr(ctx, a, b)
    if mnem == "divu":
        return _divu_expr(ctx, a, b)
    if mnem == "rem":
        return _rem_expr(ctx, a, b)
    if mnem == "remu":
        return _remu_expr(ctx, a, b)

    if mnem == "addw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} + {ctx.u32(b)}))"
    if mnem == "subw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} - {ctx.u32(b)}))"
    if mnem == "sllw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} << ({ctx.u32(b)} & 31)))"
    if mnem == "srlw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} >> ({ctx.u32(b)} & 31)))"
    if mnem == "sraw":
        return f"((int64_t)({ctx.s32(a)} >> ({ctx.u32(b)} & 31)))"
    if mnem == "mulw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} * {ctx.u32(b)}))"

    if mnem in {"divw", "divuw", "remw", "remuw"}:
        return _divw_expr(mnem, a, b, ctx)

    return None


def _lower_imm_expr(mnem: str, a: str, imm: str, ctx: LowerCtx) -> Optional[str]:
    ua = ctx.u(a)
    sa = ctx.s(a)
    sh = ctx.shift_mask()

    if mnem == "addi":
        return f"({ua} + ({imm}))"
    if mnem == "andi":
        return f"({ua} & ({imm}))"
    if mnem == "ori":
        return f"({ua} | ({imm}))"
    if mnem == "xori":
        return f"({ua} ^ ({imm}))"

    if mnem == "slti":
        return f"(({sa} < ({ctx.s_t()})({imm})) ? 1 : 0)"
    if mnem == "sltiu":
        return f"(({ua} < ({ctx.u_t()})({imm})) ? 1 : 0)"

    if mnem == "slli":
        return f"({ua} << (({imm}) & {sh}))"
    if mnem == "srli":
        return f"({ua} >> (({imm}) & {sh}))"
    if mnem == "srai":
        return ctx.u(f"({sa} >> (({imm}) & {sh}))")

    if mnem == "addiw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} + (uint32_t)({imm})))"
    if mnem == "slliw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} << (({imm}) & 31)))"
    if mnem == "srliw":
        return f"((int64_t)(int32_t)({ctx.u32(a)} >> (({imm}) & 31)))"
    if mnem == "sraiw":
        return f"((int64_t)({ctx.s32(a)} >> (({imm}) & 31)))"

    return None


def _load_expr(mnem: str, base_reg: str, off: int, ctx: LowerCtx) -> Optional[str]:
    spec = _LOAD_SPECS.get(mnem)
    if spec is None:
        return None

    cty, uty, bits, signed = spec
    addr = ctx.addr_expr(base_reg, off)

    if _STRICT_MEM_HELPERS:
        if signed:
            if bits == 8:
                return f"((int64_t)(int8_t)r2x_load_u8({addr}))"
            if bits == 16:
                return f"((int64_t)(int16_t)r2x_load_u16({addr}))"
            if bits == 32:
                return f"((int64_t)(int32_t)r2x_load_u32({addr}))"
            if bits == 64:
                return f"((int64_t)r2x_load_u64({addr}))"
        else:
            return f"((uint64_t)r2x_load_u{bits}({addr}))"

    ptr = f"(({cty}*)(uintptr_t){addr})"
    if signed:
        return f"((int64_t)(*{ptr}))"
    return f"((uint64_t)(*{ptr}))"


def _store_stmt(mnem: str, rs2: str, base_reg: str, off: int, ctx: LowerCtx) -> Optional[str]:
    spec = _STORE_SPECS.get(mnem)
    if spec is None:
        return None

    cty, bits = spec
    addr = ctx.addr_expr(base_reg, off)
    val = ctx.var_for_reg(rs2)

    if _STRICT_MEM_HELPERS:
        return f"r2x_store_u{bits}({addr}, ({cty}){val});"

    return f"*(({cty}*)(uintptr_t){addr}) = ({cty}){val};"


def _branch_cond(mnem: str, parts: List[str], ctx: LowerCtx) -> Optional[str]:
    if mnem in {"beqz", "bnez", "blez", "bgez", "bltz", "bgtz"}:
        if len(parts) != 2:
            return None
        a = ctx.var_for_reg(parts[0])

        if mnem == "beqz":
            return f"({ctx.u(a)} == 0)"
        if mnem == "bnez":
            return f"({ctx.u(a)} != 0)"
        if mnem == "blez":
            return f"({ctx.s(a)} <= 0)"
        if mnem == "bgez":
            return f"({ctx.s(a)} >= 0)"
        if mnem == "bltz":
            return f"({ctx.s(a)} < 0)"
        if mnem == "bgtz":
            return f"({ctx.s(a)} > 0)"
        return None

    if len(parts) != 3:
        return None

    a = ctx.var_for_reg(parts[0])
    b = ctx.var_for_reg(parts[1])

    if mnem == "beq":
        return f"({ctx.u(a)} == {ctx.u(b)})"
    if mnem == "bne":
        return f"({ctx.u(a)} != {ctx.u(b)})"
    if mnem == "blt":
        return f"({ctx.s(a)} < {ctx.s(b)})"
    if mnem == "bge":
        return f"({ctx.s(a)} >= {ctx.s(b)})"
    if mnem == "bltu":
        return f"({ctx.u(a)} < {ctx.u(b)})"
    if mnem == "bgeu":
        return f"({ctx.u(a)} >= {ctx.u(b)})"

    return None


# ---------- 主入口 ----------

def lower_basic_block(insns: List[LiftedInsn], ctx: LowerCtx) -> Optional[List[LoweredStmt]]:
    out: List[LoweredStmt] = []

    for ins in insns:
        raw_mnem = (ins.asm_mnem or "").lower().strip()
        raw_body = (ins.asm_body or "").strip()

        norm = _normalize_compressed(raw_mnem, raw_body)
        if norm is None:
            _dbg(f"FAIL unsupported compressed insn: {raw_mnem} {raw_body}")
            return None

        mnem, body = norm
        _dbg(f"lower ins @0x{ins.addr:x}: raw=({raw_mnem} {raw_body}) -> norm=({mnem} {body})")

        if mnem == "nop":
            continue

        if mnem in _PSEUDO and _PSEUDO[mnem] is not None:
            real, fmt = _PSEUDO[mnem]
            parts = _split(body)
            if mnem in ("mv", "neg", "negw", "not", "sext.w", "seqz", "snez", "sltz", "sgtz"):
                if len(parts) != 2:
                    _dbg(f"FAIL pseudo {mnem}: bad operand count: {parts}")
                    return None
                body = fmt.format(rd=parts[0], rs=parts[1])
            mnem = real

        if mnem in _RV64_ONLY_MNEMS and ctx.xlen != 64:
            _dbg(f"FAIL {mnem}: RV64-only instruction under RV32 lowering")
            return None

        if mnem == "li":
            parts = _split(body)
            if len(parts) != 2:
                _dbg(f"FAIL li: bad operand count: {parts}")
                return None
            rd, imm = _normalize_reg(parts[0]), parts[1]
            ctx.define_reg(rd, imm)
            continue

        if mnem == "j":
            tgt = _branch_target(body)
            if tgt is None:
                _dbg(f"FAIL j: cannot parse target from body={body}")
                return None
            out.append(LoweredStmt(
                text="/*j*/",
                is_jump=True,
                is_branch=False,
                branch_target=tgt,
                branch_cond=None,
                fallthrough=False,
                src_addr=ins.addr,
            ))
            continue

        if mnem in {"ret", "jr", "jalr", "call", "tail"}:
            _dbg(f"FAIL control-sensitive insn reached generic intblock lowering: {mnem}")
            return None

        if mnem in {
            "add", "sub", "and", "or", "xor",
            "sll", "srl", "sra", "slt", "sltu",
            "mul", "div", "divu", "rem", "remu",
            "addw", "subw", "sllw", "srlw", "sraw", "mulw",
            "divw", "divuw", "remw", "remuw",
        }:
            parts = _split(body)
            if len(parts) != 3:
                _dbg(f"FAIL {mnem}: bad operand count: {parts}")
                return None
            rd = _normalize_reg(parts[0])
            rs1 = _normalize_reg(parts[1])
            rs2 = _normalize_reg(parts[2])

            expr = _lower_bin_expr(mnem, ctx.var_for_reg(rs1), ctx.var_for_reg(rs2), ctx)
            if expr is None:
                _dbg(f"FAIL {mnem}: no lowering expr")
                return None
            ctx.define_reg(rd, expr)
            continue

        if mnem in {
            "addi", "andi", "ori", "xori", "slti", "sltiu",
            "slli", "srli", "srai",
            "addiw", "slliw", "srliw", "sraiw",
        }:
            parts = _split(body)
            if len(parts) != 3:
                _dbg(f"FAIL {mnem}: bad operand count: {parts}")
                return None
            rd = _normalize_reg(parts[0])
            rs1 = _normalize_reg(parts[1])
            imm = parts[2]

            expr = _lower_imm_expr(mnem, ctx.var_for_reg(rs1), imm, ctx)
            if expr is None:
                _dbg(f"FAIL {mnem}: no lowering expr")
                return None
            ctx.define_reg(rd, expr)
            continue

        if mnem in _LOAD_SPECS:
            parts = _split(body)
            if len(parts) != 2:
                _dbg(f"FAIL {mnem}: bad operand count: {parts}")
                return None
            rd = _normalize_reg(parts[0])
            pm = _parse_mem(parts[1])
            if pm is None:
                _dbg(f"FAIL {mnem}: bad memory operand: {parts[1]}")
                return None
            off, base = pm

            if mnem in _RV64_ONLY_MNEMS and ctx.xlen != 64:
                _dbg(f"FAIL {mnem}: RV64-only load under RV32 lowering")
                return None

            expr = _load_expr(mnem, base, off, ctx)
            if expr is None:
                _dbg(f"FAIL {mnem}: no load expr")
                return None
            ctx.define_reg(rd, expr)
            continue

        if mnem in _STORE_SPECS:
            parts = _split(body)
            if len(parts) != 2:
                _dbg(f"FAIL {mnem}: bad operand count: {parts}")
                return None
            rs2 = _normalize_reg(parts[0])
            pm = _parse_mem(parts[1])
            if pm is None:
                _dbg(f"FAIL {mnem}: bad memory operand: {parts[1]}")
                return None
            off, base = pm

            if mnem in _RV64_ONLY_MNEMS and ctx.xlen != 64:
                _dbg(f"FAIL {mnem}: RV64-only store under RV32 lowering")
                return None

            stmt = _store_stmt(mnem, rs2, base, off, ctx)
            if stmt is None:
                _dbg(f"FAIL {mnem}: no store stmt")
                return None
            out.append(LoweredStmt(
                text=stmt,
                src_addr=ins.addr,
            ))
            continue

        if mnem in _BRANCH_OPS:
            parts = _split(body)
            if not parts:
                _dbg(f"FAIL {mnem}: empty branch body")
                return None

            tgt = _branch_target(parts[-1])
            if tgt is None:
                _dbg(f"FAIL {mnem}: bad target token: {parts[-1]}")
                return None

            norm_parts = parts[:]
            if mnem in {"beq", "bne", "blt", "bge", "bltu", "bgeu"} and len(norm_parts) >= 2:
                norm_parts[0] = _normalize_reg(norm_parts[0])
                norm_parts[1] = _normalize_reg(norm_parts[1])
            elif mnem in {"beqz", "bnez", "blez", "bgez", "bltz", "bgtz"} and len(norm_parts) >= 1:
                norm_parts[0] = _normalize_reg(norm_parts[0])

            cond = _branch_cond(mnem, norm_parts, ctx)
            if cond is None:
                _dbg(f"FAIL {mnem}: cannot lower branch cond from parts={parts}")
                return None

            out.append(LoweredStmt(
                text="/*branch*/",
                is_branch=True,
                is_jump=False,
                branch_target=tgt,
                branch_cond=cond,
                fallthrough=True,
                src_addr=ins.addr,
            ))
            continue

        _dbg(f"FAIL unsupported mnem: {mnem} body={body}")
        return None

    return out


_TARGET_NUM_RE = re.compile(r"[-+]?(?:0x[0-9a-fA-F]+|\d+)")


def _branch_target(tok: str) -> Optional[int]:
    tok = tok.strip()
    if not tok:
        return None

    try:
        return int(tok, 0)
    except ValueError:
        pass

    tok0 = tok.split("<", 1)[0].strip()
    if tok0:
        try:
            return int(tok0, 0)
        except ValueError:
            pass

    m = re.fullmatch(r"([+-]?(?:0x[0-9a-fA-F]+|\d+))[fb]", tok0)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass

    m = _TARGET_NUM_RE.search(tok)
    if m:
        try:
            return int(m.group(0), 0)
        except ValueError:
            pass

    return None