from __future__ import annotations

from riscv2x86_py.pcode_ir import Block, IRSummary, from_lifted


def _block_by_addr(blocks: list[Block]) -> dict[int, Block]:
    return {block.addr: block for block in blocks}


def test_empty_input_returns_empty_cfg() -> None:
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


def test_real_add_instruction_register_summary(lift_one) -> None:
    lifted = lift_one(
        """
        add a0, a1, a2
        """
    )

    blocks, summary = from_lifted([lifted])

    assert len(blocks) == 1
    assert summary.is_single_block is True

    assert summary.has_branch is False
    assert summary.has_call_or_return is False
    assert summary.reads_mem is False
    assert summary.writes_mem is False

    # a1/a2 会被读取，a0 会被写入。
    #
    # 不硬编码 RISC-V register space 中的 offset，
    # 因为该 offset 属于 pypcode language specification 的实现细节。
    assert len(summary.reads_regs) >= 2
    assert len(summary.writes_regs) >= 1

    assert all(name.startswith("reg@") for name in summary.reads_regs)
    assert all(name.startswith("reg@") for name in summary.writes_regs)

    assert any(op.opcode == "INT_ADD" for op in blocks[0].ops)


def test_real_load_and_store_memory_summary(lift_snippet) -> None:
    lifted = lift_snippet(
        """
        ld a0, 0(a1)
        sd a0, 0(a1)
        """
    )

    blocks, summary = from_lifted(lifted)

    assert len(blocks) == 1
    assert summary.is_single_block is True

    assert summary.reads_mem is True
    assert summary.writes_mem is True

    opcodes = [op.opcode for op in blocks[0].ops]

    assert "LOAD" in opcodes
    assert "STORE" in opcodes


def test_real_conditional_branch_builds_taken_and_fallthrough_edges(
    lift_snippet,
) -> None:
    lifted = lift_snippet(
        """
        beq a0, a1, target
        addi a2, a2, 1
    target:
        addi a3, a3, 1
        """
    )

    assert len(lifted) == 3

    branch_addr = lifted[0].addr
    fallthrough_addr = lifted[1].addr
    target_addr = lifted[2].addr

    blocks, summary = from_lifted(lifted)
    by_addr = _block_by_addr(blocks)

    assert summary.has_branch is True
    assert summary.has_call_or_return is False
    assert summary.is_single_block is False

    branch_block = by_addr[branch_addr]

    assert branch_block.terminator_kind == "cbranch"
    assert branch_block.has_branch is True
    assert branch_block.is_call_or_return is False
    assert branch_block.has_unknown_target is False

    assert set(branch_block.successors) == {
        target_addr,
        fallthrough_addr,
    }

    assert branch_block.successor_kinds[target_addr] == "taken"
    assert branch_block.successor_kinds[fallthrough_addr] == "fallthrough"


def test_real_direct_jump_has_taken_edge_only(lift_snippet) -> None:
    lifted = lift_snippet(
        """
        j target
        addi a0, a0, 1
    target:
        addi a1, a1, 1
        """
    )

    assert len(lifted) == 3

    jump_addr = lifted[0].addr
    target_addr = lifted[2].addr

    blocks, summary = from_lifted(lifted)
    by_addr = _block_by_addr(blocks)

    assert summary.has_branch is True

    jump_block = by_addr[jump_addr]

    assert jump_block.terminator_kind == "branch"
    assert jump_block.has_branch is True
    assert jump_block.is_call_or_return is False
    assert jump_block.has_unknown_target is False

    assert jump_block.successors == [target_addr]
    assert jump_block.successor_kinds[target_addr] == "taken"


def test_real_direct_call_records_callee_and_return_edge(lift_snippet) -> None:
    lifted = lift_snippet(
        """
        jal ra, target
        addi a0, a0, 1
    target:
        addi a1, a1, 1
        """
    )

    assert len(lifted) == 3

    call_addr = lifted[0].addr
    return_addr = lifted[1].addr
    callee_addr = lifted[2].addr

    blocks, summary = from_lifted(lifted)
    by_addr = _block_by_addr(blocks)

    assert summary.has_call_or_return is True

    call_block = by_addr[call_addr]

    assert call_block.terminator_kind == "call"
    assert call_block.is_call_or_return is True
    assert call_block.has_unknown_target is False

    # callee 不是当前 fragment 内的 CFG successor。
    assert call_block.call_targets == [callee_addr]

    # CALL 的 CFG successor 是返回后的下一条指令。
    assert call_block.successors == [return_addr]
    assert call_block.successor_kinds[return_addr] == "call_return"


def test_real_return_creates_return_terminator(lift_snippet) -> None:
    lifted = lift_snippet(
        """
        ret
        addi a0, a0, 1
        """
    )

    assert len(lifted) == 2

    ret_addr = lifted[0].addr
    after_ret_addr = lifted[1].addr

    blocks, summary = from_lifted(lifted)
    by_addr = _block_by_addr(blocks)

    assert summary.has_call_or_return is True
    assert summary.is_single_block is False

    ret_block = by_addr[ret_addr]

    assert ret_block.terminator_kind == "return"
    assert ret_block.is_call_or_return is True
    assert ret_block.is_indirect is True
    assert ret_block.has_unknown_target is True
    assert ret_block.successors == []

    # ret 后的机器指令仍必须独立拆分为一个 block，
    # 即使该路径在正常控制流上不可达。
    assert after_ret_addr in by_addr


def test_real_fence_sets_memory_barrier_summary(lift_one) -> None:
    lifted = lift_one(
        """
        fence rw, rw
        """
    )

    blocks, summary = from_lifted([lifted])

    assert len(blocks) == 1
    assert summary.has_memory_barrier is True
    assert summary.has_atomic is False


def test_real_lr_aq_sets_atomic_and_ordering_summary(lift_one) -> None:
    lifted = lift_one(
        """
        lr.d.aq t0, (a0)
        """
    )

    blocks, summary = from_lifted([lifted])

    assert len(blocks) == 1
    assert summary.has_atomic is True
    assert summary.atomic_orderings == {"aq"}


def test_real_sc_rl_sets_atomic_and_ordering_summary(lift_one) -> None:
    lifted = lift_one(
        """
        sc.d.rl t0, t1, (a0)
        """
    )

    blocks, summary = from_lifted([lifted])

    assert len(blocks) == 1
    assert summary.has_atomic is True
    assert summary.atomic_orderings == {"rl"}


def test_real_amo_aqrl_sets_atomic_and_ordering_summary(lift_one) -> None:
    lifted = lift_one(
        """
        amoadd.d.aqrl t0, t1, (a0)
        """
    )

    blocks, summary = from_lifted([lifted])

    assert len(blocks) == 1
    assert summary.has_atomic is True
    assert summary.atomic_orderings == {"aqrl"}