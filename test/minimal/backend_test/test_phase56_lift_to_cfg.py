from __future__ import annotations

import pytest

from riscv2x86_py.pcode_ir import from_lifted


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Real conditional branch CFG.
# ---------------------------------------------------------------------------

def test_real_beq_generates_taken_and_fallthrough_cfg(lift_snippet):
    base = 0x10000

    lifted = lift_snippet(
        """
        beq a0, a1, target
        addi a2, a2, 1
    target:
        addi a3, a3, 1
        """,
        base_addr=base,
    )

    blocks, summary = from_lifted(lifted)

    assert len(blocks) == 3

    branch_block = blocks[0]
    fallthrough_block = blocks[1]
    target_block = blocks[2]

    assert branch_block.terminator_kind == "cbranch"
    assert branch_block.has_branch is True

    assert set(branch_block.successors) == {
        fallthrough_block.addr,
        target_block.addr,
    }

    assert (
        branch_block.successor_kinds[fallthrough_block.addr]
        == "fallthrough"
    )

    assert (
        branch_block.successor_kinds[target_block.addr]
        == "taken"
    )

    assert summary.has_branch is True
    assert summary.is_single_block is False


# ---------------------------------------------------------------------------
# Real direct jump CFG.
# ---------------------------------------------------------------------------

def test_real_direct_jump_splits_following_instruction(lift_snippet):
    lifted = lift_snippet(
        """
        j target
        addi a0, a0, 1
    target:
        addi a1, a1, 1
        """
    )

    blocks, _ = from_lifted(lifted)

    assert len(blocks) == 3

    jump_block = blocks[0]
    dead_fallthrough = blocks[1]
    target_block = blocks[2]

    assert jump_block.terminator_kind == "branch"
    assert jump_block.successors == [target_block.addr]

    assert jump_block.successor_kinds == {
        target_block.addr: "taken",
    }

    assert dead_fallthrough.addr != jump_block.addr
    assert dead_fallthrough.addr not in jump_block.instr_addrs


# ---------------------------------------------------------------------------
# Real direct call CFG.
# ---------------------------------------------------------------------------

def test_real_direct_call_uses_call_return_edge(lift_snippet):
    lifted = lift_snippet(
        """
        jal ra, target
        addi a0, a0, 1
    target:
        ret
        """
    )

    blocks, summary = from_lifted(lifted)

    assert len(blocks) == 3

    call_block = blocks[0]
    return_block = blocks[1]
    callee_block = blocks[2]

    assert call_block.terminator_kind == "call"

    assert call_block.successors == [return_block.addr]
    assert call_block.successor_kinds == {
        return_block.addr: "call_return",
    }

    assert callee_block.addr in call_block.call_targets
    assert callee_block.addr not in call_block.successors

    assert call_block.is_call_or_return is True
    assert call_block.is_indirect is False
    assert call_block.has_unknown_target is False

    assert summary.has_call_or_return is True


# ---------------------------------------------------------------------------
# Real indirect call / return / jump.
# ---------------------------------------------------------------------------

def test_real_indirect_call_has_return_edge(lift_snippet):
    lifted = lift_snippet(
        """
        jalr ra, 0(a0)
        addi a1, a1, 1
        """
    )

    blocks, _ = from_lifted(lifted)

    assert len(blocks) == 2

    call_block = blocks[0]
    return_block = blocks[1]

    assert call_block.terminator_kind == "callind"

    assert call_block.successors == [return_block.addr]
    assert call_block.successor_kinds == {
        return_block.addr: "call_return",
    }

    assert call_block.call_targets == []

    assert call_block.is_call_or_return is True
    assert call_block.is_indirect is True
    assert call_block.has_unknown_target is True


def test_real_ret_is_marked_as_return(lift_one):
    lifted = [lift_one("ret")]

    blocks, summary = from_lifted(lifted)

    assert len(blocks) == 1

    block = blocks[0]

    assert block.terminator_kind == "return"
    assert block.successors == []

    assert block.is_call_or_return is True
    assert block.is_indirect is True
    assert block.has_unknown_target is True

    assert summary.has_call_or_return is True


def test_real_jr_is_marked_as_indirect_branch(lift_one):
    lifted = [lift_one("jr a0")]

    blocks, summary = from_lifted(lifted)

    assert len(blocks) == 1

    block = blocks[0]

    assert block.terminator_kind == "branchind"
    assert block.successors == []

    assert block.has_branch is True
    assert block.is_call_or_return is False

    assert block.is_indirect is True
    assert block.has_unknown_target is True

    assert summary.has_branch is True


# ---------------------------------------------------------------------------
# Real load/store summary.
# ---------------------------------------------------------------------------

def test_real_load_summary(lift_one):
    lifted = [lift_one("lw a0, 0(a1)")]

    _, summary = from_lifted(lifted)

    assert summary.reads_mem is True
    assert summary.writes_mem is False


def test_real_store_summary(lift_one):
    lifted = [lift_one("sw a0, 0(a1)")]

    _, summary = from_lifted(lifted)

    assert summary.reads_mem is False
    assert summary.writes_mem is True


# ---------------------------------------------------------------------------
# Real fence / atomic summary.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "asm",
    [
        "fence",
        "fence rw, rw",
    ],
)
def test_real_fence_sets_memory_barrier(lift_one, asm):
    lifted = [lift_one(asm)]

    _, summary = from_lifted(lifted)

    assert summary.has_memory_barrier is True


@pytest.mark.parametrize(
    ("asm", "ordering"),
    [
        ("lr.w.aq a0, (a1)", "aq"),
        ("sc.w.rl a0, a2, (a1)", "rl"),
        ("amoadd.w.aq a0, a2, (a1)", "aq"),
        ("amoadd.w.rl a0, a2, (a1)", "rl"),
        ("amoadd.w.aqrl a0, a2, (a1)", "aqrl"),
    ],
)
def test_real_atomic_ordering_summary(
    lift_one,
    asm,
    ordering,
):
    lifted = [lift_one(asm)]

    _, summary = from_lifted(lifted)

    assert summary.has_atomic is True
    assert ordering in summary.atomic_orderings


def test_real_relaxed_atomic_has_empty_ordering_set(lift_one):
    lifted = [lift_one("amoadd.w a0, a2, (a1)")]

    _, summary = from_lifted(lifted)

    assert summary.has_atomic is True
    assert summary.atomic_orderings == set()