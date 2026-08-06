
"""
pcode_ir.py regression tests.

运行：
    pytest -q test_pcode_ir.py

说明：
- 本文件不依赖 pypcode；
- 使用 fake raw p-code 对象模拟 lift.LiftedInsn.raw_ops；
- 默认假定 pcode_ir.py 与本测试文件位于同一目录；
- 如果你的项目采用 src/ 布局，则会尝试导入 src.pcode_ir。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence
import importlib


# ---------------------------------------------------------------------------
# Import target module.
# ---------------------------------------------------------------------------
import sys
from pathlib import Path
# 将pytools目录加入模块搜索路径
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "pytools"))

try:
    # 项目标准包路径
    pcode_ir = importlib.import_module("riscv2x86_py.pcode_ir")
except ModuleNotFoundError as e:
    raise RuntimeError("无法导入 riscv2x86_py.pcode_ir，请确认pytools目录结构完整") from e

from_lifted = pcode_ir.from_lifted


# ---------------------------------------------------------------------------
# Fake pypcode-like objects.
#
# pcode_ir.py only requires:
#   - op.opcode.name or str(op.opcode)
#   - op.inputs
#   - op.output
#   - var.space.name
#   - var.offset
#   - var.size
# ---------------------------------------------------------------------------

@dataclass
class FakeSpace:
    name: str


@dataclass
class FakeVarnode:
    space: FakeSpace
    offset: int
    size: int


@dataclass
class FakeOpcode:
    name: str


@dataclass
class FakeRawOp:
    opcode: FakeOpcode
    inputs: list[FakeVarnode] = field(default_factory=list)
    output: Optional[FakeVarnode] = None


@dataclass
class FakeLiftedInsn:
    addr: int
    length: int = 4
    asm_mnem: str = ""
    asm_body: str = ""
    raw_ops: list[FakeRawOp] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def reg(offset: int, size: int = 8) -> FakeVarnode:
    return FakeVarnode(FakeSpace("register"), offset, size)


def const(value: int, size: int = 8) -> FakeVarnode:
    return FakeVarnode(FakeSpace("const"), value, size)


def ram(value: int, size: int = 8) -> FakeVarnode:
    return FakeVarnode(FakeSpace("ram"), value, size)


def unique(value: int, size: int = 8) -> FakeVarnode:
    return FakeVarnode(FakeSpace("unique"), value, size)


def rawop(
    opname: str,
    inputs: Optional[Sequence[FakeVarnode]] = None,
    output: Optional[FakeVarnode] = None,
) -> FakeRawOp:
    return FakeRawOp(
        opcode=FakeOpcode(opname),
        inputs=list(inputs or []),
        output=output,
    )


def insn(
    addr: int,
    *,
    length: int = 4,
    mnem: str = "",
    body: str = "",
    ops: Optional[Sequence[FakeRawOp]] = None,
) -> FakeLiftedInsn:
    return FakeLiftedInsn(
        addr=addr,
        length=length,
        asm_mnem=mnem,
        asm_body=body,
        raw_ops=list(ops or []),
    )


def block_map(blocks):
    return {block.addr: block for block in blocks}


# ---------------------------------------------------------------------------
# Basic / empty behavior.
# ---------------------------------------------------------------------------

def test_empty_input_returns_empty_blocks_and_safe_summary():
    blocks, summary = from_lifted([])

    assert blocks == []
    assert summary.is_single_block is False
    assert summary.has_branch is False
    assert summary.has_call_or_return is False
    assert summary.has_memory_barrier is False
    assert summary.has_atomic is False
    assert summary.reads_regs == set()
    assert summary.writes_regs == set()
    assert summary.reads_mem is False
    assert summary.writes_mem is False
    assert summary.atomic_orderings == set()


def test_linear_instructions_form_one_basic_block():
    lifted = [
        insn(0x1000, mnem="addi", body="a0, a0, 1"),
        insn(0x1004, mnem="addi", body="a1, a1, 2"),
        insn(0x1008, mnem="nop"),
    ]

    blocks, summary = from_lifted(lifted)

    assert len(blocks) == 1
    assert summary.is_single_block is True

    block = blocks[0]
    assert block.addr == 0x1000
    assert block.instr_addrs == [0x1000, 0x1004, 0x1008]
    assert block.successors == []
    assert block.successor_kinds == {}
    assert block.terminator_kind == ""
    assert block.has_branch is False
    assert block.is_call_or_return is False
    assert block.is_indirect is False
    assert block.has_unknown_target is False


def test_block_size_uses_lifted_instruction_length():
    """
    此测试要求 pcode_ir.py 读取 LiftedInsn.length。

    如果当前实现仍然只读取 ins.size，则此测试会失败，
    因为 lift.py 中的 LiftedInsn 没有 size，而是 length。
    """
    lifted = [
        insn(0x1000, length=2, mnem="c.nop"),
        insn(0x1002, length=4, mnem="addi"),
        insn(0x1006, length=2, mnem="c.nop"),
    ]

    blocks, _ = from_lifted(lifted)

    assert len(blocks) == 1
    assert blocks[0].size == 8


# ---------------------------------------------------------------------------
# Conditional branch CFG.
# ---------------------------------------------------------------------------

def test_conditional_branch_splits_blocks_and_creates_taken_and_fallthrough():
    """
    0x1000: beq a0, a1, 0x1008
    0x1004: addi ...
    0x1008: addi ...

    Expected CFG:
        0x1000 --taken-------> 0x1008
        0x1000 --fallthrough-> 0x1004
        0x1004 --linear------> 0x1008
    """
    lifted = [
        insn(
            0x1000,
            mnem="beq",
            body="a0, a1, 0x1008",
            ops=[
                rawop(
                    "CBRANCH",
                    inputs=[const(0x1008), reg(0x20), reg(0x28)],
                )
            ],
        ),
        insn(0x1004, mnem="addi", body="a0, a0, 1"),
        insn(0x1008, mnem="addi", body="a1, a1, 1"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    assert [b.addr for b in blocks] == [0x1000, 0x1004, 0x1008]
    assert summary.is_single_block is False
    assert summary.has_branch is True
    assert summary.has_call_or_return is False

    branch_block = bm[0x1000]
    assert branch_block.terminator_kind == "cbranch"
    assert branch_block.has_branch is True
    assert branch_block.is_call_or_return is False
    assert branch_block.is_indirect is False
    assert branch_block.has_unknown_target is False

    assert branch_block.successors == [0x1008, 0x1004]
    assert branch_block.successor_kinds == {
        0x1008: "taken",
        0x1004: "fallthrough",
    }

    fallthrough_block = bm[0x1004]
    assert fallthrough_block.successors == [0x1008]
    assert fallthrough_block.successor_kinds == {
        0x1008: "linear",
    }

    target_block = bm[0x1008]
    assert target_block.successors == []


def test_conditional_branch_uses_asm_target_when_pcode_target_is_not_directly_decodable():
    """
    raw p-code 的第一个输入使用 unique 空间，不能直接当作地址；
    应退回到 asm_body 最后一个操作数中的 0x2008。
    """
    lifted = [
        insn(
            0x2000,
            mnem="beq",
            body="a0, a1, 0x2008",
            ops=[
                rawop(
                    "CBRANCH",
                    inputs=[unique(0x1234), reg(0x20), reg(0x28)],
                )
            ],
        ),
        insn(0x2004, mnem="addi"),
        insn(0x2008, mnem="addi"),
    ]

    blocks, _ = from_lifted(lifted)
    bm = block_map(blocks)

    assert bm[0x2000].terminator_kind == "cbranch"
    assert bm[0x2000].successors == [0x2008, 0x2004]
    assert bm[0x2000].successor_kinds == {
        0x2008: "taken",
        0x2004: "fallthrough",
    }


# ---------------------------------------------------------------------------
# Direct branch behavior.
# ---------------------------------------------------------------------------

def test_direct_branch_to_internal_target_has_only_taken_successor():
    lifted = [
        insn(
            0x3000,
            mnem="j",
            body="0x3008",
            ops=[rawop("BRANCH", inputs=[const(0x3008)])],
        ),
        insn(0x3004, mnem="addi"),
        insn(0x3008, mnem="addi"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    assert summary.has_branch is True
    assert bm[0x3000].terminator_kind == "branch"
    assert bm[0x3000].successors == [0x3008]
    assert bm[0x3000].successor_kinds == {0x3008: "taken"}
    assert bm[0x3000].has_unknown_target is False

    # branch 后续指令必须拆成独立 basic block，即使语义上不可达。
    assert bm[0x3004].instr_addrs == [0x3004]
    assert bm[0x3004].successors == [0x3008]


def test_direct_branch_to_external_target_is_not_unknown_target():
    """
    片段外 direct branch：
    - successors 为空；
    - has_branch=True；
    - has_unknown_target=False；
    - 不应把“片段外 direct target”误判为 indirect/unknown。
    """
    lifted = [
        insn(
            0x4000,
            mnem="j",
            body="0x9000",
            ops=[rawop("BRANCH", inputs=[const(0x9000)])],
        ),
        insn(0x4004, mnem="addi"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    assert summary.has_branch is True
    assert bm[0x4000].terminator_kind == "branch"
    assert bm[0x4000].successors == []
    assert bm[0x4000].successor_kinds == {}
    assert bm[0x4000].has_unknown_target is False
    assert bm[0x4000].is_indirect is False


def test_jal_x0_is_classified_as_direct_branch_not_call():
    lifted = [
        insn(
            0x4100,
            mnem="jal",
            body="x0, 0x4108",
            ops=[],
        ),
        insn(0x4104, mnem="addi"),
        insn(0x4108, mnem="addi"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    assert summary.has_branch is True
    assert summary.has_call_or_return is False

    assert bm[0x4100].terminator_kind == "branch"
    assert bm[0x4100].successors == [0x4108]
    assert bm[0x4100].successor_kinds == {0x4108: "taken"}
    assert bm[0x4100].call_targets == []


# ---------------------------------------------------------------------------
# Direct / indirect calls.
# ---------------------------------------------------------------------------

def test_direct_call_preserves_external_callee_and_uses_fallthrough_cfg_edge():
    """
    direct call 的 callee 不属于当前 fragment CFG edge，
    但应保存在 call_targets 中。

    CFG:
        0x5000 --call_return--> 0x5004

    Metadata:
        call_targets == [0x9000]
    """
    lifted = [
        insn(
            0x5000,
            mnem="jal",
            body="ra, 0x9000",
            ops=[rawop("CALL", inputs=[const(0x9000)])],
        ),
        insn(0x5004, mnem="addi"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    assert summary.has_call_or_return is True
    assert summary.has_branch is False

    call_block = bm[0x5000]
    assert call_block.terminator_kind == "call"
    assert call_block.call_targets == [0x9000]
    assert call_block.successors == [0x5004]
    assert call_block.successor_kinds == {0x5004: "call_return"}
    assert call_block.is_call_or_return is True
    assert call_block.is_indirect is False
    assert call_block.has_unknown_target is False


def test_indirect_call_has_unknown_callee_but_keeps_call_return_edge():
    lifted = [
        insn(
            0x6000,
            mnem="jalr",
            body="ra, 0(a0)",
            ops=[rawop("CALLIND", inputs=[reg(0x20)])],
        ),
        insn(0x6004, mnem="addi"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    assert summary.has_call_or_return is True

    call_block = bm[0x6000]
    assert call_block.terminator_kind == "callind"
    assert call_block.call_targets == []
    assert call_block.successors == [0x6004]
    assert call_block.successor_kinds == {0x6004: "call_return"}
    assert call_block.is_call_or_return is True
    assert call_block.is_indirect is True
    assert call_block.has_unknown_target is True


# ---------------------------------------------------------------------------
# Return / indirect branch behavior.
# ---------------------------------------------------------------------------

def test_ret_asm_alias_overrides_raw_branchind_and_is_classified_as_return():
    """
    某些 lifting 结果中 ret 可能表现为 BRANCHIND。
    pcode_ir.py 应优先保留 asm ret 的 RETURN 语义。
    """
    lifted = [
        insn(
            0x7000,
            mnem="ret",
            body="",
            ops=[rawop("BRANCHIND", inputs=[reg(0x8)])],
        ),
        insn(0x7004, mnem="addi"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    ret_block = bm[0x7000]

    assert ret_block.terminator_kind == "return"
    assert ret_block.successors == []
    assert ret_block.successor_kinds == {}
    assert ret_block.is_call_or_return is True
    assert ret_block.is_indirect is True
    assert ret_block.has_unknown_target is True

    # ret 后仍必须拆块，避免把 0x7004 归入 return 所在 basic block。
    assert bm[0x7004].instr_addrs == [0x7004]

    assert summary.has_call_or_return is True


def test_indirect_jump_has_unknown_target_and_no_static_successor():
    lifted = [
        insn(
            0x7100,
            mnem="jr",
            body="a0",
            ops=[rawop("BRANCHIND", inputs=[reg(0x20)])],
        ),
        insn(0x7104, mnem="addi"),
    ]

    blocks, summary = from_lifted(lifted)
    bm = block_map(blocks)

    block = bm[0x7100]
    assert summary.has_branch is True
    assert block.terminator_kind == "branchind"
    assert block.successors == []
    assert block.is_indirect is True
    assert block.has_unknown_target is True


# ---------------------------------------------------------------------------
# Fence / atomic / memory / register summary.
# ---------------------------------------------------------------------------

def test_fence_atomic_ordering_memory_and_register_summary():
    """
    验证：
    - fence -> has_memory_barrier=True
    - amoadd.w.aqrl -> has_atomic=True + aqrl ordering
    - LOAD -> reads_mem=True
    - STORE -> writes_mem=True
    - register inputs / outputs 被正确汇总
    """
    lifted = [
        insn(
            0x8000,
            mnem="fence",
            body="rw, rw",
            ops=[],
        ),
        insn(
            0x8004,
            mnem="amoadd.w.aqrl",
            body="a0, a1, (a2)",
            ops=[
                rawop(
                    "LOAD",
                    inputs=[ram(0x100000, 4), reg(0x30)],
                    output=reg(0x20, 4),
                ),
                rawop(
                    "STORE",
                    inputs=[ram(0x100000, 4), reg(0x20, 4), reg(0x28, 4)],
                    output=None,
                ),
            ],
        ),
        insn(
            0x8008,
            mnem="lr.w.aq",
            body="a0, (a1)",
            ops=[],
        ),
        insn(
            0x800C,
            mnem="sc.d.rl",
            body="a0, a1, (a2)",
            ops=[],
        ),
    ]

    blocks, summary = from_lifted(lifted)

    assert len(blocks) == 1
    assert summary.has_memory_barrier is True
    assert summary.has_atomic is True

    # amoadd.w.aqrl + lr.w.aq + sc.d.rl
    assert summary.atomic_orderings == {"aqrl", "aq", "rl"}

    assert summary.reads_mem is True
    assert summary.writes_mem is True

    assert "reg@0x30:8" in summary.reads_regs
    assert "reg@0x20:4" in summary.reads_regs
    assert "reg@0x28:4" in summary.reads_regs

    assert "reg@0x20:4" in summary.writes_regs


def test_relaxed_atomic_has_no_ordering_suffix():
    lifted = [
        insn(
            0x9000,
            mnem="amoadd.w",
            body="a0, a1, (a2)",
            ops=[],
        ),
    ]

    _, summary = from_lifted(lifted)

    assert summary.has_atomic is True
    assert summary.atomic_orderings == set()


# ---------------------------------------------------------------------------
# Raw p-code semantic summary.
# ---------------------------------------------------------------------------

def test_raw_pcode_barrier_and_atomic_fallback_opcodes_are_recognized():
    """
    覆盖 pcode_ir.py 中：
        _BARRIER_OPS = {"FENCE", "MEMORYBARRIER"}
        _ATOMIC_OPS = {"CPOOLREF", "SEGMENTOP"}
    """
    lifted = [
        insn(
            0xA000,
            mnem="unknown",
            ops=[
                rawop("MEMORYBARRIER"),
                rawop("CPOOLREF"),
            ],
        ),
    ]

    _, summary = from_lifted(lifted)

    assert summary.has_memory_barrier is True
    assert summary.has_atomic is True


def test_successor_kind_combines_when_taken_target_equals_fallthrough():
    """
    这是一个较少见但合法的边界情况：
    conditional branch 的 taken target 恰好等于 next block。

    此时 successor 只应出现一次，但类型应保留：
        taken|fallthrough
    或
        fallthrough|taken

    当前实现先添加 taken，再添加 fallthrough，
    因此预期为 taken|fallthrough。
    """
    lifted = [
        insn(
            0xB000,
            mnem="beq",
            body="a0, a1, 0xB004",
            ops=[rawop("CBRANCH", inputs=[const(0xB004), reg(0x20)])],
        ),
        insn(0xB004, mnem="addi"),
    ]

    blocks, _ = from_lifted(lifted)
    bm = block_map(blocks)

    branch_block = bm[0xB000]

    assert branch_block.successors == [0xB004]
    assert branch_block.successor_kinds == {
        0xB004: "taken|fallthrough",
    }