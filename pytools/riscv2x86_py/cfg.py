"""
Phase 6.5: 为 Phase 6 提供统一 CFG。

设计原则
========

1. P-code / lifted semantic operations 优先：
   若 LiftedInsn 中携带 raw_ops / pcode_ops / pcode / ops，则优先根据
   CBRANCH、BRANCH、BRANCHIND、CALL、CALLIND、RETURN 等语义操作构建 CFG。

2. asm 文本只作为 fallback：
   asm mnemonic、operand 文本和反汇编文本只在没有可用 P-code 控制流
   信息时参与 CFG 构建。

3. CFG 面向 Phase 6 翻译语义：
   - 保留条件分支 taken / fallthrough；
   - 保留直接跳转；
   - 保留 indirect branch / return 的“未知目标”信息；
   - call 的 callee target 与函数内 fallthrough 区分；
   - 不使用 LR/SC retry loop 等猜测式补边。

4. angr 仅作为最后 fallback：
   如果 lifted instruction / P-code CFG 无法建立，才用 angr CFGFast。

注意
====

本模块通过 introspection 兼容不同 LiftedInsn / PcodeOp 实现。通常支持：

LiftedInsn:
    addr
    size / bytes_ / inst_bytes
    asm_mnem
    asm_body
    asm / asm_text / text / disasm
    raw_ops / pcode_ops / pcode / ops

PcodeOp:
    opcode / opcode_name / mnemonic / op / name
    inputs / input0 / input1 / target

Varnode / target:
    offset / value / addr / address
    getOffset()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import io
import logging
import re


# 抑制 angr 相关 INFO 噪音
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)


# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------

@dataclass
class CFGNode:
    """
    一个基本块。

    successors:
        当前 fragment / 当前函数内的普通控制流 successor。

        对 conditional branch：
            - taken edge
            - fallthrough edge

        对 direct jump：
            - jump target

        对 call：
            - 只保留 fallthrough；
            - callee target 单独保存在 call_targets。

    successor_kinds:
        successor 地址对应的边类型，例如：
            {
                0x10020: "branch_taken",
                0x10008: "fallthrough",
            }

    call_targets:
        直接 call 的目标地址。它不进入 successors，避免把 call 错误建模为
        普通无条件跳转。

    has_unknown_target:
        表示该 block 存在无法静态确定目标的控制流，例如：
            - BRANCHIND
            - CALLIND
            - ret
            - jalr x0, reg, imm
    """
    addr: int
    size: int
    instr_addrs: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)

    is_branch: bool = False
    is_call_or_return: bool = False
    is_indirect: bool = False

    successor_kinds: Dict[int, str] = field(default_factory=dict)
    call_targets: List[int] = field(default_factory=list)
    has_unknown_target: bool = False


@dataclass
class CFGResult:
    ok: bool
    nodes: Dict[int, CFGNode] = field(default_factory=dict)
    entry: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# angr fallback CFG
# ---------------------------------------------------------------------------

def _blob_stream(data: bytes):
    return io.BytesIO(data)


def build_cfg(
    machine_code: bytes,
    xlen: int = 64,
    base_addr: int = 0x10000,
) -> CFGResult:
    """
    angr CFGFast fallback。

    正常情况下，Phase 6 应优先使用 build_cfg_any(..., insns=lifted_insns)。
    只有 lifted CFG 无法构建时，才使用此函数。
    """
    if not machine_code:
        return CFGResult(False, error="empty machine code")

    try:
        import angr  # noqa: F401
    except Exception as e:
        return CFGResult(False, error=f"angr import failed: {e}")

    arch_name = "RISCV64" if xlen == 64 else "RISCV32"

    try:
        proj = angr.Project(
            _blob_stream(machine_code),
            main_opts={
                "backend": "blob",
                "arch": arch_name,
                "base_addr": base_addr,
                "entry_point": base_addr,
            },
            auto_load_libs=False,
        )
    except Exception as e:
        return CFGResult(False, error=f"angr load failed: {e}")

    try:
        cfg = proj.analyses.CFGFast(
            regions=[(base_addr, base_addr + len(machine_code))],
            force_complete_scan=True,
            symbols=False,
            function_starts=[base_addr],
            normalize=True,
        )
    except Exception as e:
        return CFGResult(False, error=f"CFGFast failed: {e}")

    res = CFGResult(ok=True, entry=base_addr)

    for n in cfg.model.nodes():
        if n.addr is None:
            continue

        if not (base_addr <= n.addr < base_addr + len(machine_code)):
            continue

        block_insn_addrs: List[int] = []
        block_size = n.size or 0
        last_mnem: Optional[str] = None

        try:
            block = proj.factory.block(n.addr, size=n.size)
            block_size = block.size or block_size

            if block.capstone.insns:
                block_insn_addrs = [ins.address for ins in block.capstone.insns]
                last_mnem = block.capstone.insns[-1].mnemonic.lower()
        except Exception:
            pass

        node = CFGNode(
            addr=n.addr,
            size=block_size,
        )

        if block_insn_addrs:
            node.instr_addrs = block_insn_addrs
        else:
            try:
                node.instr_addrs = list(n.instruction_addrs)
            except Exception:
                node.instr_addrs = []

        seen = set()

        try:
            succ_nodes = cfg.model.get_successors(n)
        except Exception:
            succ_nodes = []

        for succ in succ_nodes:
            succ_addr = getattr(succ, "addr", None)

            if succ_addr is None or succ_addr in seen:
                continue

            seen.add(succ_addr)
            node.successors.append(succ_addr)
            node.successor_kinds[succ_addr] = "angr_successor"

        if last_mnem:
            if last_mnem in ("jalr", "jr", "ret"):
                node.is_indirect = True
                node.has_unknown_target = True

            if last_mnem.startswith((
                "beq",
                "bne",
                "blt",
                "bge",
                "bltu",
                "bgeu",
                "c.beqz",
                "c.bnez",
            )):
                node.is_branch = True

            if last_mnem in ("jal", "jalr", "ret", "call"):
                node.is_call_or_return = True

        res.nodes[n.addr] = node

    if not res.nodes:
        return CFGResult(False, error="angr CFG contains no in-range nodes")

    return res


# ---------------------------------------------------------------------------
# asm fallback classification
# ---------------------------------------------------------------------------

_BRANCH_PREFIXES = (
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
    "c.beqz",
    "c.bnez",
)

_RETURN_MNEMS = (
    "ret",
    "c.jr",
    "jr",
)

_DIRECT_JUMP_MNEMS = (
    "j",
    "c.j",
    "tail",
)

_DIRECT_CALL_MNEMS = (
    "call",
    "c.jal",
)


def _norm_mnem(ins: Any) -> str:
    return (getattr(ins, "asm_mnem", "") or "").strip().lower()


def _insn_size(ins: Any, default: int = 4) -> int:
    """
    获取 lifted instruction 的长度。

    优先级：
        bytes_
        inst_bytes
        size
        默认 4 bytes

    默认 4 是为普通 RISC-V 指令准备的；若支持 compressed instructions，
    LiftedInsn 应尽量提供 bytes_ / inst_bytes / size。
    """
    raw = getattr(ins, "bytes_", None)
    if raw:
        try:
            return len(raw)
        except Exception:
            pass

    raw = getattr(ins, "inst_bytes", None)
    if raw:
        try:
            return len(raw)
        except Exception:
            pass

    size = getattr(ins, "size", None)
    if isinstance(size, int) and size > 0:
        return size

    return default


def _split_operands(ins: Any) -> List[str]:
    body = (getattr(ins, "asm_body", "") or "").strip()

    if not body:
        ops = getattr(ins, "asm_operands", None)
        if ops:
            return [str(x).strip() for x in ops if str(x).strip()]
        return []

    return [p.strip() for p in body.split(",") if p.strip()]


def _is_cond_branch_mnem(mm: str) -> bool:
    return mm.startswith(_BRANCH_PREFIXES)


def _is_call_like_jal(ins: Any) -> bool:
    """
    判断 jal 是否为 call。

    RISC-V:
        jal target             => 通常等价 jal ra, target，视为 call
        jal ra, target         => call
        jal x0, target         => 无条件 jump
    """
    mm = _norm_mnem(ins)

    if mm == "call":
        return True

    if mm not in ("jal", "c.jal"):
        return False

    ops = _split_operands(ins)

    if len(ops) <= 1:
        return True

    rd = ops[0].strip().lower()

    return rd not in ("x0", "zero")


def _is_call_like_jalr(ins: Any) -> bool:
    """
    判断 jalr 是否为 indirect call。

    RISC-V:
        jalr ra, 0(a0)         => indirect call
        jalr x0, 0(a0)         => indirect jump
        ret                    => jalr x0, 0(ra) 的伪指令
    """
    mm = _norm_mnem(ins)

    if mm not in ("jalr", "c.jalr"):
        return False

    ops = _split_operands(ins)

    # 若反汇编文本没有 rd，保守地视为 call-like。
    if not ops:
        return True

    rd = ops[0].strip().lower()
    return rd not in ("x0", "zero")


def _is_direct_jump(ins: Any) -> bool:
    mm = _norm_mnem(ins)

    if mm in _DIRECT_JUMP_MNEMS:
        return True

    if mm in ("jal", "c.jal"):
        return not _is_call_like_jal(ins)

    return False


def _is_indirect_terminal(ins: Any) -> bool:
    mm = _norm_mnem(ins)

    if mm in _RETURN_MNEMS:
        return True

    if mm in ("jalr", "c.jalr"):
        return not _is_call_like_jalr(ins)

    return False


def _is_asm_control_flow(ins: Any) -> bool:
    mm = _norm_mnem(ins)

    return (
        _is_cond_branch_mnem(mm)
        or _is_direct_jump(ins)
        or _is_indirect_terminal(ins)
        or _is_call_like_jal(ins)
        or _is_call_like_jalr(ins)
        or mm == "call"
    )


# ---------------------------------------------------------------------------
# P-code introspection helpers
# ---------------------------------------------------------------------------

def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(value, (str, bytes, bytearray)):
        return []

    if isinstance(value, (list, tuple)):
        return list(value)

    try:
        return list(value)
    except Exception:
        return []


def _pcode_ops(ins: Any) -> List[Any]:
    """
    从 LiftedInsn 中获取 P-code operation 序列。

    兼容常见字段：
        raw_ops
        pcode_ops
        pcode
        ops
    """
    for field_name in ("raw_ops", "pcode_ops", "pcode", "ops"):
        value = getattr(ins, field_name, None)
        ops = _as_list(value)

        if ops:
            return ops

    return []


def _norm_pcode_opcode(op: Any) -> str:
    """
    尽可能获得 P-code operation 名称。

    常见形式：
        op.opcode == "CBRANCH"
        op.opcode_name == "BRANCH"
        op.mnemonic == "RETURN"
        str(op) 包含 "CBRANCH"
    """
    for name in (
        "opcode_name",
        "opcode",
        "mnemonic",
        "op",
        "name",
        "operation",
    ):
        value = getattr(op, name, None)

        if value is None:
            continue

        text = str(value).strip().upper()

        if not text:
            continue

        # 兼容 CPUI_BRANCH / OpCode.CBRANCH 等文本形式
        text = text.replace("CPUI_", "")

        for known in (
            "CBRANCH",
            "BRANCHIND",
            "BRANCH",
            "CALLIND",
            "CALL",
            "RETURN",
        ):
            if text == known or text.endswith("." + known) or text.endswith("_" + known):
                return known

    # 最后尝试读取 str(op)，但仅用于兼容未知 P-code object。
    try:
        text = str(op).upper()
    except Exception:
        return ""

    for known in (
        "CBRANCH",
        "BRANCHIND",
        "BRANCH",
        "CALLIND",
        "CALL",
        "RETURN",
    ):
        if re.search(rf"\b{known}\b", text):
            return known

    return ""


def _pcode_inputs(op: Any) -> List[Any]:
    """
    获取 P-code op 的 input varnode 列表。
    """
    for name in ("inputs", "args", "arguments", "in_vars", "invars"):
        value = getattr(op, name, None)
        values = _as_list(value)

        if values:
            return values

    result: List[Any] = []

    for index in range(8):
        value = getattr(op, f"input{index}", None)

        if value is None:
            break

        result.append(value)

    return result


def _extract_int_values(value: Any) -> List[int]:
    """
    从 P-code target / varnode / address object 中提取可能的整数值。

    注意：
    - 这里仅负责“提取候选数值”；
    - 是否为有效代码地址由 _resolve_target_candidates 决定。
    """
    if value is None:
        return []

    if isinstance(value, bool):
        return []

    if isinstance(value, int):
        return [value]

    candidates: List[int] = []

    for name in (
        "addr",
        "address",
        "offset",
        "value",
        "target",
        "pc",
    ):
        attr = getattr(value, name, None)

        if attr is None:
            continue

        if isinstance(attr, int):
            candidates.append(attr)
            continue

        if attr is not value:
            candidates.extend(_extract_int_values(attr))

    getter = getattr(value, "getOffset", None)

    if callable(getter):
        try:
            offset = getter()
            if isinstance(offset, int):
                candidates.append(offset)
        except Exception:
            pass

    # 兼容字符串形式，例如 "ram:00010020"、"0x10020"。
    try:
        text = str(value)
    except Exception:
        text = ""

    if text:
        for token in re.findall(r"[-+]?0x[0-9a-fA-F]+", text):
            try:
                candidates.append(int(token, 16))
            except Exception:
                pass

    out: List[int] = []
    seen = set()

    for candidate in candidates:
        if candidate in seen:
            continue

        seen.add(candidate)
        out.append(candidate)

    return out


def _pcode_direct_target_values(op: Any) -> List[int]:
    """
    P-code 中 BRANCH / CBRANCH / CALL 的第一个 input 通常是 target。

    Ghidra P-code 约定通常为：
        BRANCH(target)
        CBRANCH(target, condition)
        CALL(target)
    """
    direct = getattr(op, "target", None)

    if direct is not None:
        values = _extract_int_values(direct)
        if values:
            return values

    inputs = _pcode_inputs(op)

    if not inputs:
        return []

    return _extract_int_values(inputs[0])


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def _resolve_target_candidates(
    candidates: Iterable[int],
    *,
    ins_addr: int,
    ins_size: int,
    addr_to_idx: Dict[int, int],
) -> Optional[int]:
    """
    将 P-code / asm 解析得到的候选 target 转换为 lifted instruction 地址。

    优先级：
        1. 候选值本身就是一个 lifted instruction 地址；
        2. ins_addr + candidate；
        3. ins_addr + ins_size + candidate。

    第 2、3 项用于兼容某些 lifter 用 PC-relative offset 表示 target 的情况。

    关键限制：
        只返回 addr_to_idx 中存在的地址；
        不会把任意常量误认为 CFG target。
    """
    for value in candidates:
        if value in addr_to_idx:
            return value

    for value in candidates:
        relative = ins_addr + value

        if relative in addr_to_idx:
            return relative

    for value in candidates:
        relative = ins_addr + ins_size + value

        if relative in addr_to_idx:
            return relative

    return None


def _asm_target_candidates(ins: Any) -> List[int]:
    """
    asm fallback target 解析。

    优先读取显式字段：
        target
        branch_target
        jump_target
        target_addr
        destination

    再从 operand / asm 文本中提取最后一个地址或数值。

    注意：
    这里只产生候选；最终必须经过 _resolve_target_candidates 验证。
    """
    candidates: List[int] = []

    for name in (
        "target",
        "branch_target",
        "jump_target",
        "target_addr",
        "destination",
    ):
        value = getattr(ins, name, None)
        candidates.extend(_extract_int_values(value))

    ops = _split_operands(ins)

    if ops:
        last_operand = ops[-1]

        for token in re.findall(r"[-+]?0x[0-9a-fA-F]+", last_operand):
            try:
                candidates.append(int(token, 16))
            except Exception:
                pass

        # 十进制 target / offset。
        # 只取末尾完整整数，避免把寄存器编号 x10 误解析为 10。
        match = re.search(r"(?<![A-Za-z0-9_])([-+]?\d+)(?![A-Za-z0-9_])\s*$", last_operand)

        if match:
            try:
                candidates.append(int(match.group(1), 10))
            except Exception:
                pass

    if not candidates:
        text = ""

        for name in ("asm", "asm_text", "text", "disasm"):
            value = getattr(ins, name, None)

            if value:
                text = str(value)
                break

        if text:
            hex_hits = re.findall(r"[-+]?0x[0-9a-fA-F]+", text)

            if hex_hits:
                try:
                    candidates.append(int(hex_hits[-1], 16))
                except Exception:
                    pass

    out: List[int] = []
    seen = set()

    for candidate in candidates:
        if candidate in seen:
            continue

        seen.add(candidate)
        out.append(candidate)

    return out


# ---------------------------------------------------------------------------
# Unified per-instruction flow classification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _FlowInfo:
    """
    kind:
        normal
        cond_branch
        jump
        indirect_jump
        call
        indirect_call
        return
    """
    kind: str = "normal"
    target: Optional[int] = None
    source: str = "none"


def _pcode_flow_info(
    ins: Any,
    addr_to_idx: Dict[int, int],
) -> Optional[_FlowInfo]:
    """
    从 P-code 语义操作中获取控制流信息。

    若该 instruction 没有任何 P-code control-flow op，返回 None，
    上层将回退到 asm classification。
    """
    ops = _pcode_ops(ins)

    if not ops:
        return None

    selected_op: Optional[Any] = None
    selected_opcode = ""

    # 一个 instruction 可能有多条 P-code op。
    # 取最后一条控制流 op，因为其最接近该 instruction 的最终 PC 效果。
    for op in ops:
        opcode = _norm_pcode_opcode(op)

        if opcode in (
            "CBRANCH",
            "BRANCH",
            "BRANCHIND",
            "CALL",
            "CALLIND",
            "RETURN",
        ):
            selected_op = op
            selected_opcode = opcode

    if selected_op is None:
        return None

    target: Optional[int] = None

    if selected_opcode in ("CBRANCH", "BRANCH", "CALL"):
        candidates = _pcode_direct_target_values(selected_op)

        target = _resolve_target_candidates(
            candidates,
            ins_addr=ins.addr,
            ins_size=_insn_size(ins),
            addr_to_idx=addr_to_idx,
        )

    if selected_opcode == "CBRANCH":
        return _FlowInfo(
            kind="cond_branch",
            target=target,
            source="pcode",
        )

    if selected_opcode == "BRANCH":
        return _FlowInfo(
            kind="jump",
            target=target,
            source="pcode",
        )

    if selected_opcode == "BRANCHIND":
        return _FlowInfo(
            kind="indirect_jump",
            target=None,
            source="pcode",
        )

    if selected_opcode == "CALL":
        return _FlowInfo(
            kind="call",
            target=target,
            source="pcode",
        )

    if selected_opcode == "CALLIND":
        return _FlowInfo(
            kind="indirect_call",
            target=None,
            source="pcode",
        )

    if selected_opcode == "RETURN":
        return _FlowInfo(
            kind="return",
            target=None,
            source="pcode",
        )

    return None


def _asm_flow_info(
    ins: Any,
    addr_to_idx: Dict[int, int],
) -> _FlowInfo:
    """
    asm fallback classification。
    """
    mm = _norm_mnem(ins)

    target = _resolve_target_candidates(
        _asm_target_candidates(ins),
        ins_addr=ins.addr,
        ins_size=_insn_size(ins),
        addr_to_idx=addr_to_idx,
    )

    if _is_cond_branch_mnem(mm):
        return _FlowInfo(
            kind="cond_branch",
            target=target,
            source="asm",
        )

    if _is_direct_jump(ins):
        return _FlowInfo(
            kind="jump",
            target=target,
            source="asm",
        )

    if _is_indirect_terminal(ins):
        if mm == "ret":
            return _FlowInfo(
                kind="return",
                target=None,
                source="asm",
            )

        return _FlowInfo(
            kind="indirect_jump",
            target=None,
            source="asm",
        )

    if mm == "call" or _is_call_like_jal(ins):
        return _FlowInfo(
            kind="call",
            target=target,
            source="asm",
        )

    if _is_call_like_jalr(ins):
        return _FlowInfo(
            kind="indirect_call",
            target=None,
            source="asm",
        )

    return _FlowInfo(
        kind="normal",
        target=None,
        source="asm",
    )

def _is_control_flow_kind(kind: str) -> bool:
    return kind in (
        "cond_branch",
        "jump",
        "indirect_jump",
        "call",
        "indirect_call",
        "return",
    )


# ---------------------------------------------------------------------------
# CFG construction from lifted instructions
# ---------------------------------------------------------------------------

def _dedup(xs: Sequence[int]) -> List[int]:
    out: List[int] = []
    seen = set()

    for x in xs:
        if x in seen:
            continue

        seen.add(x)
        out.append(x)

    return out


def _next_addr(ins: Any) -> int:
    return ins.addr + _insn_size(ins)

# ---------------------------------------------------------------------------
# CFG construction from authoritative pcode_ir.Block objects
# ---------------------------------------------------------------------------

EXIT_NODE = -1


def _block_field(block: Any, name: str, default: Any = None) -> Any:
    """
    从 Block 或 Block.summary 中读取字段。

    此函数只读取已经由 pcode_ir / from_lifted 产生的结构化元数据，
    不解析 P-code 文本、不解析 asm 文本、不推导控制流。
    """
    if isinstance(block, dict):
        if name in block:
            return block[name]
    else:
        value = getattr(block, name, None)
        if value is not None:
            return value

    summary = block.get("summary") if isinstance(block, dict) else getattr(block, "summary", None)

    if summary is None:
        return default

    if isinstance(summary, dict):
        return summary.get(name, default)

    value = getattr(summary, name, None)
    return default if value is None else value


def _block_bool(block: Any, *names: str, default: bool = False) -> bool:
    """
    从 Block / Block.summary 读取布尔控制流属性。

    支持不同 pcode_ir 实现中的常见字段命名，但不会从 ops、P-code、
    asm 或 successor 数量推导这些属性。
    """
    for name in names:
        value = _block_field(block, name, None)

        if value is not None:
            return bool(value)

    return default


def _block_kind(block: Any) -> str:
    """
    读取结构化 terminator / flow kind。

    允许的典型字段：
        terminator_kind
        flow_kind
        control_flow_kind
        kind

    注意：
        这里只读取上游 IR 已经给出的分类；不重新解析 P-code opcode。
    """
    for name in (
        "terminator_kind",
        "flow_kind",
        "control_flow_kind",
        "kind",
    ):
        value = _block_field(block, name, None)

        if value is None:
            continue

        text = str(value).strip().lower()

        if text:
            return text

    return ""


def _block_successors(block: Any) -> Tuple[Optional[List[int]], Optional[str]]:
    """
    直接读取 Block.successors。

    返回：
        (successors, None)             成功
        (None, "error message")        Block 不满足 authoritative CFG 接口

    关键语义：
        - 不过滤 fragment 外地址；
        - 不补 fallthrough；
        - 不根据 next block 推断后继；
        - [] 是合法结果，不是错误。
    """
    marker = object()

    if isinstance(block, dict):
        raw = block.get("successors", marker)
    else:
        raw = getattr(block, "successors", marker)

    if raw is marker:
        return None, "block has no successors field"

    if raw is None:
        return None, "block.successors is None; expected an iterable of absolute addresses"

    if isinstance(raw, (str, bytes, bytearray)):
        return None, "block.successors must be an iterable of integer addresses"

    try:
        values = list(raw)
    except Exception as e:
        return None, f"cannot iterate block.successors: {e}"

    successors: List[int] = []

    for succ in values:
        # bool 是 int 的子类，但不应成为地址。
        if isinstance(succ, bool) or not isinstance(succ, int):
            return (
                None,
                "block.successors contains a non-integer address: "
                f"{succ!r}",
            )

        # 保留上游给出的地址及其顺序。
        # 不进行 fragment-internal 过滤，不转换成 hex 字符串，
        # 不转换成 block index。
        successors.append(succ)

    return successors, None


def _block_instr_addrs(block: Any) -> List[int]:
    """
    可选地读取 instruction addresses，仅用于展示/debug。

    不依赖它们构建 CFG 边。
    """
    raw = _block_field(block, "instr_addrs", None)

    if raw is not None:
        try:
            return [
                x for x in list(raw)
                if isinstance(x, int) and not isinstance(x, bool)
            ]
        except Exception:
            pass

    # 某些 Block 实现只有 ops。这里最多读取 op.addr 供展示，
    # 绝不检查 op 内容、更不解析 P-code。
    ops = _block_field(block, "ops", None)

    if ops is None:
        return []

    try:
        ops_list = list(ops)
    except Exception:
        return []

    result: List[int] = []

    for op in ops_list:
        addr = getattr(op, "addr", None)

        if isinstance(addr, int) and not isinstance(addr, bool):
            result.append(addr)

    return result


def _block_size(block: Any) -> int:
    """
    读取 Block.size。

    若上游 Block 未提供 size，则返回 0。CFG 正确性不依赖 size；
    不能为了得到 size 而重新按 instruction 或 P-code 推导 block 边界。
    """
    value = _block_field(block, "size", 0)

    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value

    return 0


def _block_successor_kinds(
    block: Any,
    successors: Sequence[int],
) -> Dict[int, str]:
    """
    直接复制 Block.successor_kinds（若存在）。

    若上游未提供边类型，只标记为 block_successor。
    这不是 CFG 推导，也不改变 successor 集合。
    """
    raw = _block_field(block, "successor_kinds", None)
    out: Dict[int, str] = {}

    if isinstance(raw, dict):
        for succ in successors:
            value = raw.get(succ)

            if value is not None:
                out[succ] = str(value)

    for succ in successors:
        out.setdefault(succ, "block_successor")

    return out


def _block_call_targets(block: Any) -> List[int]:
    """
    直接读取上游 IR 已经识别出的 call_targets。

    不从 op / P-code / asm 重新识别 call。
    """
    raw = _block_field(block, "call_targets", None)

    if raw is None:
        return []

    if isinstance(raw, (str, bytes, bytearray)):
        return []

    try:
        values = list(raw)
    except Exception:
        return []

    return [
        x for x in values
        if isinstance(x, int) and not isinstance(x, bool)
    ]


def _metadata_is_branch(block: Any, kind: str) -> bool:
    """
    is_branch 表示该 block 的 terminator 存在 branch/jump 控制转移。

    特别地，外跳到 fragment 外部的单 block：
        successors == []
        is_branch == True

    不能根据 successors 是否为空判断。
    """
    explicit = _block_bool(
        block,
        "is_branch",
        "has_branch",
        "has_conditional_branch",
        default=False,
    )

    if explicit:
        return True

    return kind in {
        "branch",
        "cond_branch",
        "conditional_branch",
        "jump",
        "direct_jump",
        "indirect_jump",
        "branchind",
    }


def _metadata_is_call_or_return(block: Any, kind: str) -> bool:
    explicit = _block_bool(
        block,
        "is_call_or_return",
        "has_call",
        "has_return",
        "is_call",
        "is_return",
        default=False,
    )

    if explicit:
        return True

    return kind in {
        "call",
        "direct_call",
        "indirect_call",
        "return",
        "ret",
    }


def _metadata_is_indirect(block: Any, kind: str) -> bool:
    explicit = _block_bool(
        block,
        "is_indirect",
        "has_indirect_target",
        "is_indirect_branch",
        "is_indirect_call",
        default=False,
    )

    if explicit:
        return True

    return kind in {
        "indirect_jump",
        "indirect_branch",
        "branchind",
        "indirect_call",
        "callind",
        "return",
        "ret",
    }


def _metadata_has_unknown_target(block: Any, kind: str) -> bool:
    """
    unknown target 必须来自上游 IR 元数据或明确的 terminator kind。

    特别注意：
        successors == [] 绝不自动意味着 unknown target。

    例如以下情况可以是 successors == [] 且 unknown == False：
        - 跳到 fragment 外部的 direct jump；
        - fragment 外部 tail-call；
        - 片段末尾无 fallthrough。
    """
    explicit = _block_bool(
        block,
        "has_unknown_target",
        "unknown_target",
        "has_unresolved_target",
        default=False,
    )

    if explicit:
        return True

    return kind in {
        "indirect_jump",
        "indirect_branch",
        "branchind",
        "indirect_call",
        "callind",
        "return",
        "ret",
    }


def build_cfg_from_blocks(
    blocks: Sequence[Any],
    *,
    add_synthetic_exit: bool = False,
) -> CFGResult:
    """
    从 pcode_ir.from_lifted() 的 authoritative Block 序列构建 CFG。

    Block 最低接口要求：

        Block(
            addr=<absolute integer machine-code address>,
            ops=[...],
            successors=[<absolute integer machine-code address>, ...],
        )

    关键约束：

    1. CFG node ID 始终是 Block.addr（int）；
    2. CFG edges 直接复制 Block.successors；
    3. 不重新解析 P-code；
    4. 不重新解析 asm；
    5. 不自行添加 fallthrough；
    6. successors == [] 是合法 CFG 语义；
    7. 不把 block list index、instruction offset、hex(addr) 当作内部 ID。
    """
    if blocks is None:
        return CFGResult(False, error="no authoritative blocks for CFG")

    try:
        block_list = list(blocks)
    except Exception as e:
        return CFGResult(False, error=f"cannot iterate blocks: {e}")

    if not block_list:
        return CFGResult(False, error="empty authoritative block sequence")

    nodes: Dict[int, CFGNode] = {}
    block_addrs: List[int] = []

    for index, block in enumerate(block_list):
        if isinstance(block, dict):
            addr = block.get("addr")
        else:
            addr = getattr(block, "addr", None)

        if isinstance(addr, bool) or not isinstance(addr, int):
            return CFGResult(
                False,
                error=(
                    f"block[{index}] has invalid addr {addr!r}; "
                    "Block.addr must be an absolute integer machine-code address"
                ),
            )

        if addr in nodes:
            return CFGResult(
                False,
                error=f"duplicate Block.addr in authoritative CFG input: 0x{addr:x}",
            )

        successors, succ_error = _block_successors(block)

        if succ_error is not None:
            return CFGResult(
                False,
                error=f"invalid Block at 0x{addr:x}: {succ_error}",
            )

        assert successors is not None

        kind = _block_kind(block)

        node = CFGNode(
            addr=addr,
            size=_block_size(block),
            instr_addrs=_block_instr_addrs(block),

            # 直接复制 authoritative Block.successors。
            successors=list(successors),

            is_branch=_metadata_is_branch(block, kind),
            is_call_or_return=_metadata_is_call_or_return(block, kind),
            is_indirect=_metadata_is_indirect(block, kind),

            successor_kinds=_block_successor_kinds(block, successors),
            call_targets=_block_call_targets(block),

            # 不能用 not successors 推导 unknown target。
            has_unknown_target=_metadata_has_unknown_target(block, kind),
        )

        nodes[addr] = node
        block_addrs.append(addr)

    if add_synthetic_exit:
        # 可选统一出口节点。
        #
        # 默认关闭，因为 successors == [] 本身已经具有准确语义。
        # 开启后仅显式添加 EXIT_NODE 边；绝不会添加“顺序下一块”边。
        if EXIT_NODE in nodes:
            return CFGResult(
                False,
                error=f"synthetic EXIT_NODE collision: Block.addr == {EXIT_NODE}",
            )

        needs_exit = False

        for node in list(nodes.values()):
            if node.successors:
                continue

            node.successors.append(EXIT_NODE)
            node.successor_kinds[EXIT_NODE] = "synthetic_exit"
            needs_exit = True

        if needs_exit:
            nodes[EXIT_NODE] = CFGNode(
                addr=EXIT_NODE,
                size=0,
                instr_addrs=[],
                successors=[],
            )

    return CFGResult(
        ok=True,
        nodes=nodes,
        entry=block_addrs[0],
    )


# ---------------------------------------------------------------------------
# Public unified entry
# ---------------------------------------------------------------------------

def build_cfg_any(
    machine_code: bytes,
    insns: Optional[Sequence[Any]] = None,
    *,
    blocks: Optional[Sequence[Any]] = None,
    xlen: int = 64,
    base_addr: int = 0x10000,
    add_synthetic_exit: bool = False,
) -> CFGResult:
    """
    Phase 6 统一 CFG 入口。

    优先级：

        1. pcode_ir.from_lifted() 输出的 authoritative blocks；
        2. angr CFGFast fallback。

    不再支持：

        LiftedInsn -> 再次解析 P-code / asm -> 重建 CFG

    原因是 block 切分与 CFG 边语义已经由 pcode_ir 统一负责：

        - direct target；
        - conditional taken / fallthrough；
        - branch 后拆 block；
        - call 的 callee / return-fallthrough 区分；
        - return / indirect branch；
        - asm fallback；
        - fragment 内部地址过滤。

    CFG 层只负责把：

        Block.addr
        Block.successors

    映射为 CFGNode.addr 和 CFGNode.successors。

    参数：
        blocks:
            authoritative Block 序列。每个 block 至少应有：
                addr: int
                successors: List[int]

        insns:
            已不再用于从 LiftedInsn 重建 CFG。

            为了兼容某些调用方，如果 insns 实际上是具有 addr 和
            successors 字段的 Block 序列，则会将其当作 blocks 使用。
            否则不会重新解析 P-code 或 asm。
    """
    authoritative_blocks = blocks

    # 兼容旧调用点：
    #
    #   build_cfg_any(..., insns=blocks)
    #
    # 但只在对象确实看起来是 Block（有 addr + successors）时接受。
    # 不会把普通 LiftedInsn 当作 Block，更不会重新解析 P-code。
    if authoritative_blocks is None and insns:
        try:
            candidate_blocks = list(insns)
        except Exception:
            candidate_blocks = []

        if candidate_blocks:
            def looks_like_block(obj: Any) -> bool:
                if isinstance(obj, dict):
                    return "addr" in obj and "successors" in obj

                return (
                    hasattr(obj, "addr")
                    and hasattr(obj, "successors")
                )

            if all(looks_like_block(x) for x in candidate_blocks):
                authoritative_blocks = candidate_blocks

    if authoritative_blocks is not None:
        try:
            result = build_cfg_from_blocks(
                authoritative_blocks,
                add_synthetic_exit=add_synthetic_exit,
            )
        except Exception as e:
            result = CFGResult(
                False,
                error=f"authoritative Block CFG failed: {type(e).__name__}: {e}",
            )

        if result.ok:
            return result

        # authoritative blocks 已提供但构建失败时，不能偷偷退回去重新解析
        # LiftedInsn/P-code/asm，否则会重新引入 IR/CFG 语义不一致。
        #
        # 只有 angr 是独立的最后 fallback。
        if machine_code:
            angr_result = build_cfg(
                machine_code,
                xlen=xlen,
                base_addr=base_addr,
            )

            if angr_result.ok:
                return angr_result

            return CFGResult(
                False,
                error=(
                    f"authoritative Block CFG failed: {result.error}; "
                    f"angr CFG failed: {angr_result.error}"
                ),
            )

        return result

    # 没有 authoritative blocks 时，不允许重新从 LiftedInsn 推导 CFG。
    # 这会避免 P-code IR 与 CFG 层的重复解释。
    if machine_code:
        angr_result = build_cfg(
            machine_code,
            xlen=xlen,
            base_addr=base_addr,
        )

        if angr_result.ok:
            return angr_result

        return CFGResult(
            False,
            error=(
                "no authoritative pcode_ir blocks were provided; "
                f"angr CFG failed: {angr_result.error}"
            ),
        )

    if insns:
        return CFGResult(
            False,
            error=(
                "LiftedInsn input was provided but no authoritative blocks were supplied; "
                "run pcode_ir.from_lifted() first and pass blocks="
            ),
        )

    return CFGResult(
        False,
        error="no authoritative blocks and no machine code for angr fallback",
    )