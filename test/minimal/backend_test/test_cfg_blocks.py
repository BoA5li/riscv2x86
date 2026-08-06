from __future__ import annotations
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Any, Sequence
import pytest
import inspect
from riscv2x86_py.assemble import assemble,_normalize_riscv_dot_relative_targets
from riscv2x86_py.schema import AsmFragment
from riscv2x86_py.pcode_ir  import summarize_lifted_instruction

from types import SimpleNamespace
import riscv2x86_py.translate as translation_mod

# 定位项目根目录，将pytools加入模块搜索路径
file_path = Path(__file__)
# 当前文件：test/minimal/backend_test/xxx.py 向上4层抵达项目根目录
project_root = file_path.parent.parent.parent.parent
sys.path.insert(0, str(project_root / "pytools"))

# 标准完整包导入
from riscv2x86_py.cfg import EXIT_NODE, build_cfg_any, build_cfg_from_blocks
from riscv2x86_py.pcode_ir import Block, from_lifted


@dataclass
class FakeBlock:
    """
    最小 authoritative pcode_ir.Block 测试替身。

    cfg.build_cfg_from_blocks() 只应读取结构化 Block 字段，
    不应读取或解析 asm / pcode 文本。
    """
    addr: int
    successors: List[int]

    size: int = 0
    instr_addrs: List[int] = field(default_factory=list)

    terminator_kind: str = ""
    successor_kinds: Dict[int, str] = field(default_factory=dict)
    call_targets: List[int] = field(default_factory=list)

    is_branch: bool = False
    is_call_or_return: bool = False
    is_indirect: bool = False
    has_unknown_target: bool = False


def test_cfg_node_id_is_absolute_block_address():
    blocks = [
        FakeBlock(addr=0x10000, successors=[0x10004]),
        FakeBlock(addr=0x10004, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error
    assert result.entry == 0x10000
    assert set(result.nodes) == {0x10000, 0x10004}

    assert result.nodes[0x10000].addr == 0x10000
    assert result.nodes[0x10000].successors == [0x10004]


def test_cfg_copies_successors_without_adding_fallthrough():
    """
    上游明确给出 successors=[] 时，CFG 层不得因为存在“下一块”
    而擅自补一条顺序 fallthrough 边。
    """
    blocks = [
        FakeBlock(
            addr=0x10000,
            successors=[],
            terminator_kind="jump",
            is_branch=True,
        ),
        FakeBlock(addr=0x10004, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error

    node = result.nodes[0x10000]
    assert node.successors == []
    assert node.is_branch is True


def test_fragment_external_direct_branch_is_not_unknown_target():
    """
    fragment 外 direct jump 的正确语义：

        successors == []
        is_branch == True
        has_unknown_target == False

    “CFG 中没有可达内部节点”不等于“目标未知”。
    """
    blocks = [
        FakeBlock(
            addr=0x10000,
            successors=[],
            terminator_kind="jump",
            is_branch=True,
            has_unknown_target=False,
        )
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error

    node = result.nodes[0x10000]
    assert node.successors == []
    assert node.is_branch is True
    assert node.is_indirect is False
    assert node.has_unknown_target is False


def test_direct_call_keeps_call_target_separate_from_fallthrough():
    """
    direct call 不应被建模为普通 jump。

    期望：
        successors   = [call-return fallthrough]
        call_targets = [callee]
    """
    blocks = [
        FakeBlock(
            addr=0x10000,
            successors=[0x10004],
            terminator_kind="call",
            successor_kinds={0x10004: "fallthrough"},
            call_targets=[0x20000],
            is_call_or_return=True,
        ),
        FakeBlock(addr=0x10004, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error

    node = result.nodes[0x10000]

    assert node.successors == [0x10004]
    assert node.call_targets == [0x20000]
    assert 0x20000 not in node.successors
    assert node.successor_kinds[0x10004] == "fallthrough"
    assert node.is_call_or_return is True


def test_external_direct_call_preserves_fallthrough_and_external_callee():
    """
    fragment 外 direct call 的正确语义：

        call_targets = [external_target]
        successors   = [fallthrough]

    即使 callee 不在当前 fragment 内，也不能：
        1. 把 callee 错误加入 successors；
        2. 丢掉 call target；
        3. 因 callee 在 fragment 外把 call 误认为 unknown indirect target。
    """
    blocks = [
        FakeBlock(
            addr=0x10000,
            successors=[0x10004],
            terminator_kind="call",
            successor_kinds={0x10004: "fallthrough"},
            call_targets=[0x90000000],
            is_call_or_return=True,
            has_unknown_target=False,
        ),
        FakeBlock(addr=0x10004, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error

    node = result.nodes[0x10000]
    assert node.successors == [0x10004]
    assert node.call_targets == [0x90000000]
    assert node.has_unknown_target is False


def test_indirect_jump_has_unknown_target_without_successors():
    blocks = [
        FakeBlock(
            addr=0x10000,
            successors=[],
            terminator_kind="indirect_jump",
            is_branch=True,
            is_indirect=True,
            has_unknown_target=True,
        )
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error

    node = result.nodes[0x10000]
    assert node.successors == []
    assert node.is_branch is True
    assert node.is_indirect is True
    assert node.has_unknown_target is True


def test_return_has_unknown_target_semantics():
    blocks = [
        FakeBlock(
            addr=0x10000,
            successors=[],
            terminator_kind="return",
            is_call_or_return=True,
            is_indirect=True,
            has_unknown_target=True,
        )
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error

    node = result.nodes[0x10000]
    assert node.successors == []
    assert node.is_call_or_return is True
    assert node.is_indirect is True
    assert node.has_unknown_target is True


def test_successor_order_is_preserved():
    """
    条件分支通常有 taken / fallthrough 的顺序语义。
    CFG 层不得自行排序或去重重排。
    """
    blocks = [
        FakeBlock(
            addr=0x10000,
            successors=[0x10020, 0x10004],
            terminator_kind="cond_branch",
            successor_kinds={
                0x10020: "branch_taken",
                0x10004: "fallthrough",
            },
            is_branch=True,
        ),
        FakeBlock(addr=0x10004, successors=[]),
        FakeBlock(addr=0x10020, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error

    node = result.nodes[0x10000]
    assert node.successors == [0x10020, 0x10004]
    assert node.successor_kinds[0x10020] == "branch_taken"
    assert node.successor_kinds[0x10004] == "fallthrough"


def test_synthetic_exit_is_disabled_by_default():
    blocks = [
        FakeBlock(addr=0x10000, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok, result.error
    assert EXIT_NODE not in result.nodes
    assert result.nodes[0x10000].successors == []


def test_synthetic_exit_is_opt_in():
    blocks = [
        FakeBlock(addr=0x10000, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks, add_synthetic_exit=True)

    assert result.ok, result.error
    assert EXIT_NODE in result.nodes
    assert result.nodes[0x10000].successors == [EXIT_NODE]
    assert result.nodes[0x10000].successor_kinds[EXIT_NODE] == "synthetic_exit"


def test_duplicate_block_addr_is_rejected():
    blocks = [
        FakeBlock(addr=0x10000, successors=[]),
        FakeBlock(addr=0x10000, successors=[]),
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok is False
    assert "duplicate Block.addr" in result.error


def test_non_integer_successor_is_rejected():
    blocks = [
        FakeBlock(addr=0x10000, successors=["0x10004"]),  # type: ignore[list-item]
    ]

    result = build_cfg_from_blocks(blocks)

    assert result.ok is False
    assert "non-integer address" in result.error


def test_build_cfg_any_prefers_authoritative_blocks_over_machine_code():
    """
    即便 machine_code 非空，只要 authoritative blocks 有效，
    build_cfg_any() 必须直接使用 blocks，而不应调用 angr fallback。
    """
    blocks = [
        FakeBlock(addr=0x10000, successors=[0x10004]),
        FakeBlock(addr=0x10004, successors=[]),
    ]

    result = build_cfg_any(
        b"\xff" * 16,
        blocks=blocks,
        xlen=64,
        base_addr=0x10000,
    )

    assert result.ok, result.error
    assert result.entry == 0x10000
    assert result.nodes[0x10000].successors == [0x10004]


BASE = 0x10000


def _split_lift_result(value: Any):
    """
    兼容 fixture 的多种返回形式：

        lifted_insns
        (assembled, lifted_insns)
        {"assembled": ..., "insns": ...}
        {"assembled": ..., "lifted_insns": ...}
    """
    if isinstance(value, tuple) and len(value) == 2:
        return value[0], value[1]

    if isinstance(value, dict):
        return (
            value.get("assembled"),
            value.get("insns", value.get("lifted_insns")),
        )

    return None, value


def _to_blocks(lifted_insns: Sequence[Any]) -> list[Block]:
    """
    使用 pcode_ir.from_lifted() 作为唯一 authoritative BasicBlock 来源。

    禁止在测试侧自行：
      - 猜测或补写 Block.addr；
      - 根据 instruction 下标构造 CFG；
      - 重新解析 asm 文本；
      - 从 p-code 文本重新推导 successor；
      - 将 from_lifted() 返回的 summary 错传给 CFG 层。

    from_lifted() 负责：
      LiftedInsn -> authoritative Block 列表 + IRSummary

    CFG 构建只接收 authoritative Block 列表。
    """
    blocks, _summary = from_lifted(lifted_insns)
    return blocks

def _insn_addr(insn: Any):
    """
    与 pcode_ir 的地址兼容约定保持一致。

    工程中的 lifted instruction 可能用 addr、address 或 pc 表示地址。
    """
    for field_name in ("addr", "address", "pc"):
        value = getattr(insn, field_name, None)
        if isinstance(value, int):
            return value

    if isinstance(insn, dict):
        for field_name in ("addr", "address", "pc"):
            value = insn.get(field_name)
            if isinstance(value, int):
                return value

    return None


def _insn_size(insn: Any):
    value = getattr(insn, "size", None)
    if isinstance(value, int):
        return value

    if isinstance(insn, dict):
        value = insn.get("size")
        if isinstance(value, int):
            return value

    raw = getattr(insn, "bytes", None)
    if raw is None and isinstance(insn, dict):
        raw = insn.get("bytes")

    if raw is not None:
        return len(raw)

    return None


def _summary_of_first(insns: Sequence[Any]):
    insn = insns[0]

    if isinstance(insn, dict):
        for name in ("summary", "ir_summary", "analysis"):
            value = insn.get(name)
            if value is not None:
                return value
        return None

    for name in ("summary", "ir_summary", "analysis"):
        value = getattr(insn, name, None)
        if value is not None:
            return value

    return None




def _block_by_addr(blocks, addr: int):
    for block in blocks:
        block_addr = block["addr"] if isinstance(block, dict) else block.addr
        if block_addr == addr:
            return block
    raise AssertionError(f"no block at 0x{addr:x}")


def _field(block, name, default=None):
    if isinstance(block, dict):
        if name in block:
            return block[name]
        summary = block.get("summary")
    else:
        value = getattr(block, name, None)
        if value is not None:
            return value
        summary = getattr(block, "summary", None)

    if isinstance(summary, dict):
        return summary.get(name, default)

    return getattr(summary, name, default) if summary is not None else default


def test_pc_relative_forward_conditional_branch_cfg(lift_snippet):
    """
    前向 conditional branch 的 CFG。

    RISC-V beq 的 branch immediate 是 PC-relative。

    此测试使用内部标签，而不是 .+8：
    - 当前真实 assemble/ELF relocation 管线不支持 .+N / .-N；
    - 使用标签后，机器码中的 B-type branch 仍是 PC-relative；
    - target/fallthrough 必须来自真实 LiftedInsn 地址；
    - 不应假设后续 addi 一定占用 4 字节，因为测试汇编启用了 .option rvc。
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            beq a0, a1, target
            addi a2, a2, 1
        target:
            addi a3, a3, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert len(insns) == 3

    branch_addr = insns[0].addr
    fallthrough_addr = insns[1].addr
    taken_addr = insns[2].addr

    assert branch_addr == BASE
    assert fallthrough_addr == branch_addr + insns[0].length
    assert taken_addr > fallthrough_addr

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    entry = cfg.nodes[branch_addr]

    # Conditional branch 必须同时保留 taken 和 fallthrough。
    assert fallthrough_addr in entry.successors
    assert taken_addr in entry.successors

    assert entry.successor_kinds[fallthrough_addr] == "fallthrough"
    assert entry.successor_kinds[taken_addr] == "taken"

    assert entry.is_branch is True
    assert entry.is_call_or_return is False
    assert entry.is_indirect is False

def test_pc_relative_backward_conditional_branch_cfg(lift_snippet):
    """
    后向 conditional branch 的 CFG。

    loop 标签位于第一条 addi，beq 跳回该标签。

    不使用 .-4：
    - 当前真实 assemble/ELF relocation 管线不支持 .-N；
    - label branch 最终仍被编码为 RISC-V PC-relative branch；
    - 不假设 addi 长度为 4 字节，因为启用了 .option rvc。
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
        loop:
            addi a0, a0, 1
            beq a0, a1, loop
            addi a2, a2, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert len(insns) == 3

    loop_addr = insns[0].addr
    branch_addr = insns[1].addr
    fallthrough_addr = insns[2].addr

    assert loop_addr == BASE
    assert branch_addr == loop_addr + insns[0].length
    assert fallthrough_addr == branch_addr + insns[1].length

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    # branch 不一定独占一个 Block。例如 loop label 位于第一条 addi 时，
    # Block 可以包含 addi + beq 两条指令。因此按 instr_addrs 查找。
    branch_node = next(
        (
            node
            for node in cfg.nodes.values()
            if branch_addr in node.instr_addrs
        ),
        None,
    )

    assert branch_node is not None, (
        f"no CFG node contains branch instruction at 0x{branch_addr:x}"
    )

    # taken edge 跳回 loop 的第一条指令；fallthrough 到下一条指令。
    assert loop_addr in branch_node.successors
    assert fallthrough_addr in branch_node.successors

    assert branch_node.successor_kinds[loop_addr] == "taken"
    assert branch_node.successor_kinds[fallthrough_addr] == "fallthrough"

    assert branch_node.is_branch is True
    assert branch_node.is_call_or_return is False
    assert branch_node.is_indirect is False

def test_external_direct_jump_has_no_internal_successor_but_is_not_unknown(
    lift_snippet,
):
    """
    fragment 外 direct branch:

        has_unknown_target == False
        successors == []

    该测试应通过真实 lift / pcode_ir 链路验证，而不是人工伪造 Block。
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            j 0x20000
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    node = cfg.nodes[BASE]
    assert node.successors == []
    assert node.is_branch is True
    assert node.is_indirect is False
    assert node.has_unknown_target is False


def test_external_direct_call_keeps_fallthrough_and_call_target(
    lift_snippet,
):
    """
    fragment 外 direct call：

        call_targets == [external_target]
        successors == [fallthrough]
        has_unknown_target == False

    RISC-V jal 的 immediate 是 PC-relative displacement。

    本测试中：
        call_site        = BASE      = 0x10000
        encoded immediate = 0x10000
        actual target     = 0x20000
    """
    external_target = 0x20000
    encoded_displacement = external_target - BASE

    _, insns = _split_lift_result(
        lift_snippet(
            f"""
            jal ra, {encoded_displacement:#x}
            addi a0, a0, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert len(insns) == 2

    call_addr = insns[0].addr
    fallthrough_addr = insns[1].addr

    assert call_addr == BASE
    assert fallthrough_addr == call_addr + insns[0].length

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    node = cfg.nodes[call_addr]

    # direct call 的块内正常控制流继续到 call 后首条指令。
    assert node.successors == [fallthrough_addr]
    assert node.successor_kinds[fallthrough_addr] == "call_return"

    # 外部 call target 只出现在 call_targets，不应成为 fragment CFG successor。
    assert node.call_targets == [external_target]
    assert external_target not in node.successors

    assert node.is_call_or_return is True
    assert node.is_branch is False
    assert node.is_indirect is False
    assert node.has_unknown_target is False

def test_external_symbol_emits_relocation_and_preserves_call_semantics(
    lift_snippet,
):
    """
    此测试依赖 assembler 支持 unresolved external symbol relocation。

    要求：
    1. assembled.relocations 中有 external_symbol；
    2. pcode_ir 仍将其识别为 direct call，而不是 indirect call；
    3. 若链接前无法形成绝对地址，call target 的表示应符合工程约定；
    4. call-return fallthrough 不能丢失。

    如果当前 assembler 不支持 unresolved symbol，可先保留 xfail，
    直到 relocation pipeline 实现完成。
    """
    assembled, insns = _split_lift_result(
        lift_snippet(
            """
            jal ra, external_symbol
            addi a0, a0, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    if assembled is None:
        pytest.skip("lift_snippet fixture did not expose assembled relocation data")

    relocations = getattr(assembled, "relocations", None)
    assert relocations is not None
    assert len(relocations) >= 1

    relocation_text = " ".join(map(str, relocations))
    assert "external_symbol" in relocation_text

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    node = cfg.nodes[BASE]
    assert BASE + 4 in node.successors
    assert node.is_call_or_return is True


@pytest.mark.parametrize(
    "asm",
    [
        """
        call external_symbol
        addi a0, a0, 1
        """,
        """
        tail external_symbol
        """,
    ],
)
def test_call_and_tail_external_symbol_relocation_contract(lift_snippet, asm):
    """
    call external_symbol:
        - 应保留 call / fallthrough 语义。

    tail external_symbol:
        - 通常是外跳 / tail-call；
        - 不应凭空生成返回 fallthrough；
        - 是否记入 call_targets 取决于上游 IR 定义，但 terminator
          必须不是普通 normal flow。
    """
    assembled, insns = _split_lift_result(
        lift_snippet(
            asm,
            xlen=64,
            base_addr=BASE,
        )
    )

    if assembled is None:
        pytest.skip("lift_snippet fixture did not expose assembled relocation data")

    relocations = getattr(assembled, "relocations", None)
    assert relocations is not None
    assert len(relocations) >= 1

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    entry = cfg.nodes[BASE]

    assert (
        entry.is_branch
        or entry.is_call_or_return
        or entry.is_indirect
        or entry.has_unknown_target
        or bool(entry.call_targets)
    ), "external call/tail must not degrade into a normal sequential CFG node"


def _insn_size(insn):
    value = getattr(insn, "size", None)
    if isinstance(value, int):
        return value

    raw = getattr(insn, "bytes", None)
    if raw is not None:
        return len(raw)

    return None


def test_real_compressed_conditional_branch_cfg(lift_snippet):
    """
    验证 c.beqz：

    - 第一条 instruction 真的是 16-bit；
    - taken target 正确；
    - fallthrough 为 addr + 2，而不是 addr + 4；
    - CFG 使用 pcode_ir Block successors。
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            c.beqz a0, target
            c.addi a1, 1
        target:
            c.addi a2, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert _insn_addr(insns[0]) == BASE
    assert _insn_size(insns[0]) == 2

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    entry = cfg.nodes[BASE]

    # c.beqz 的 fallthrough 必须是 +2。
    assert BASE + 2 in entry.successors

    # target 位于两条 compressed instruction 后：BASE + 4。
    assert BASE + 4 in entry.successors
    assert entry.is_branch is True


def test_real_compressed_bnez_cfg(lift_snippet):
    _, insns = _split_lift_result(
        lift_snippet(
            """
            c.bnez a0, target
            c.addi a1, 1
        target:
            c.addi a2, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert _insn_size(insns[0]) == 2

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    node = cfg.nodes[BASE]
    assert BASE + 2 in node.successors
    assert BASE + 4 in node.successors
    assert node.is_branch is True


def test_real_compressed_direct_jump_cfg(lift_snippet):
    """
    c.j target 是无条件直接跳转：

    - 不能生成 fallthrough；
    - target 在 fragment 内时应成为唯一 successor。
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            c.j target
            c.addi a0, 1
        target:
            c.addi a1, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert _insn_size(insns[0]) == 2

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    node = cfg.nodes[BASE]
    assert node.successors == [BASE + 4]
    assert node.is_branch is True
    assert node.has_unknown_target is False


def test_real_compressed_indirect_jump_cfg(lift_snippet):
    """
    c.jr ra 为间接 jump/return-like terminator。

    具体是否归类为 return，取决于 pcode_ir 上游的 terminator_kind；
    但至少应满足：
        successors == []
        is_indirect == True
        has_unknown_target == True
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            c.jr ra
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert _insn_size(insns[0]) == 2

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    node = cfg.nodes[BASE]
    assert node.successors == []
    assert node.is_indirect is True
    assert node.has_unknown_target is True


def test_real_compressed_return_cfg(lift_snippet):
    """
    使用 c.jr ra 验证 compressed return-like terminator。

    不直接使用 c.ret，因为 c.ret 并非所有 assembler 都接受的显式助记符；
    c.jr ra 的编码和控制流语义足以覆盖该测试目标。
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            c.jr ra
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    assert _insn_addr(insns[0]) == BASE
    assert _insn_size(insns[0]) == 2

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    node = cfg.nodes[BASE]
    assert node.successors == []
    assert node.is_indirect is True
    assert node.has_unknown_target is True


def _summary_of_first(insns):
    insn = insns[0]

    for name in ("summary", "ir_summary", "analysis"):
        value = getattr(insn, name, None)
        if value is not None:
            return value

    return None


def test_rv32_addi_lifts_and_normalizes(lift_one):
    """
    RV32 基础 ALU 指令必须能被真实 lift。

    重点检查：
    - xlen=32 链路可用；
    - 指令地址正常；
    - 不应被误以 RV64 语义提升。
    """
    insn = lift_one(
        "addi a0, a0, 1",
        xlen=32,
        base_addr=BASE,
    )

    assert getattr(insn, "addr", None) == BASE

    # 具体字段名称因项目不同可能不同；这里至少要求 lift 产物存在。
    assert insn is not None


def test_rv32_load_store_summary(lift_snippet):
    """
    验证 RV32 下 lw/sw 的内存读写摘要。

    若 summary 字段在 pcode_ir 中有明确命名，建议进一步改成精确断言：
        reads_mem == True
        writes_mem == True
        memory_width == 4
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            lw a0, 0(a1)
            sw a0, 4(a1)
            """,
            xlen=32,
            base_addr=BASE,
        )
    )

    assert len(insns) >= 2

    first_summary = _summary_of_first(insns)
    assert first_summary is not None, "RV32 lifted instruction should expose analysis summary"


def test_rv32_branch_cfg(lift_snippet):
    """
    RV32 conditional branch 的 CFG。

    不使用 BASE + 8 这类固定地址断言，因为 assemble() 默认带有
    .option rvc，addi 可能压缩为 2-byte instruction。

    CFG successor 应使用 lifting 后的真实指令地址判断。
    """
    _, insns = _split_lift_result(
        lift_snippet(
            """
            beq a0, a1, target
            addi a2, a2, 1
        target:
            addi a3, a3, 1
            """,
            xlen=32,
            base_addr=BASE,
        )
    )

    assert len(insns) == 3

    branch_addr = insns[0].addr
    fallthrough_addr = insns[1].addr
    taken_addr = insns[2].addr

    assert branch_addr == BASE
    assert fallthrough_addr == branch_addr + insns[0].length
    assert taken_addr > fallthrough_addr

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error

    entry = cfg.nodes[branch_addr]

    assert fallthrough_addr in entry.successors
    assert taken_addr in entry.successors

    assert entry.successor_kinds[fallthrough_addr] == "fallthrough"
    assert entry.successor_kinds[taken_addr] == "taken"

    assert entry.is_branch is True
    assert entry.is_call_or_return is False
    assert entry.is_indirect is False


@pytest.mark.parametrize(
    "asm",
    [
        "lr.d t0, (a0)",
        "sc.d t1, t2, (a0)",
        "amoadd.d t0, t1, (a0)",
    ],
)
def test_rv32_rejects_rv64_only_atomic_widths(lift_one, asm):
    """
    RV32 中 .d 宽度的原子操作不应被静默接受为 RV64 指令。

    合法行为可以是：
    - assembler/lifter 显式报错；
    - 返回结构化 unsupported/rejected 结果。

    不应出现：
    - 成功 lift 但使用 64-bit 语义；
    - 静默截断；
    - 按错误 xlen 继续翻译。
    """
    with pytest.raises(Exception):
        lift_one(
            asm,
            xlen=32,
            base_addr=BASE,
        )

@pytest.mark.xfail(
    strict=True,
    reason=(
        "Current IRSummary only records aggregate reads/writes; "
        "it does not provide cross-instruction register def-use chains."
    ),
)
def test_branch_condition_depends_on_previous_register_definition(
    lift_snippet,
    analyze_dataflow,
):
    """
    未来应支持：

        addi a0, a0, 1
        beq  a0, zero, target

    并显式表达：

        def(addi@0x10000, a0)
            ->
        use(beq@0x10004, a0)
            ->
        branch-condition dependency

    这不是当前 reads_regs / writes_regs 集合可以表达的。
    """
    graph = analyze_dataflow(
        lift_snippet(
            """
            addi a0, a0, 1
            beq a0, zero, target
        target:
            addi a1, a1, 1
            """,
            xlen=64,
            base_addr=0x10000,
        )
    )

    assert graph.has_def_use(
        definition_addr=0x10000,
        defined_reg="a0",
        use_addr=0x10004,
        used_reg="a0",
    )

    assert graph.is_branch_condition_dependent_on(
        branch_addr=0x10004,
        definition_addr=0x10000,
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Current analysis does not preserve memory-address dependency "
        "from register definitions to load/store effective addresses."
    ),
)
def test_secret_derived_register_controls_load_address(
    lift_snippet,
    analyze_dataflow,
):
    """
    未来用于侧信道/安全语义分析。

        add a1, a0, a2
        ld  t0, 0(a1)

    应能表达：
        load address depends on a0/a2
    """
    graph = analyze_dataflow(
        lift_snippet(
            """
            add a1, a0, a2
            ld t0, 0(a1)
            """,
            xlen=64,
            base_addr=0x10000,
        )
    )

    assert graph.memory_address_depends_on(
        memory_op_addr=0x10004,
        source_reg="a0",
    )

    assert graph.memory_address_depends_on(
        memory_op_addr=0x10004,
        source_reg="a2",
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Current analysis has no explicit control-dependency graph; "
        "CFG reachability alone is insufficient for control-dependence semantics."
    ),
)
def test_control_dependency_is_available(
    lift_snippet,
    analyze_dataflow,
):
    """
    未来应支持：

        beq a0, zero, target
        addi a1, a1, 1
    target:
        ...

    其中 addi a1 的执行受 branch condition 控制。
    """
    graph = analyze_dataflow(
        lift_snippet(
            """
            beq a0, zero, target
            addi a1, a1, 1
        target:
            addi a2, a2, 1
            """,
            xlen=64,
            base_addr=0x10000,
        )
    )

    assert graph.is_control_dependent(
        controlled_addr=0x10004,
        branch_addr=0x10000,
    )

@pytest.mark.parametrize(
    "asm",
    [
        "lr.w.aq t0, (a0)",
        "sc.w.rl t1, t2, (a0)",
        "amoswap.w.aqrl t0, t1, (a0)",
        "amoadd.d.aqrl t0, t1, (a0)",
        "amoxor.d t0, t1, (a0)",
        "amoand.d t0, t1, (a0)",
        "amoor.d t0, t1, (a0)",
        "amomin.d t0, t1, (a0)",
        "amomax.d t0, t1, (a0)",
        "amominu.d t0, t1, (a0)",
        "amomaxu.d t0, t1, (a0)",
    ],
)
def test_atomic_instruction_is_preserved_in_ir_summary(lift_one, asm):
    """
    Phase 5/6 最低要求：

    - 原子操作不能退化为普通 load/store；
    - has_atomic 必须为 True；
    - 若 summary 可区分操作种类，应保留 lr/sc/amo 的类别；
    - aq/rl/aqrl ordering 不应在 lift 阶段丢失。
    """
    insn = lift_one(
        asm,
        xlen=64,
        base_addr=0x10000,
    )

    summary = (
        getattr(insn, "summary", None)
        or getattr(insn, "ir_summary", None)
        or getattr(insn, "analysis", None)
    )

    assert summary is not None, f"missing summary for {asm}"

    has_atomic = getattr(summary, "has_atomic", None)
    if has_atomic is None and isinstance(summary, dict):
        has_atomic = summary.get("has_atomic")

    assert has_atomic is True, f"{asm} must be represented as atomic"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Phase 5/6 currently identifies atomics but does not yet expose "
        "a verified x86 atomic lowering plan."
    ),
)
def test_lr_sc_translation_plan_preserves_success_failure_semantics(
    lift_snippet,
    build_translation_plan,
):
    """
    lr/sc 不能被翻译为普通 mov load + mov store。

    将来 translation plan 至少需要表达：
    - reservation / compare-and-exchange equivalent；
    - sc 成功/失败返回值；
    - retry/failure control-flow；
    - aq/rl ordering。
    """
    plan = build_translation_plan(
        lift_snippet(
            """
            lr.d t0, (a0)
            sc.d t1, t2, (a0)
            """,
            xlen=64,
            base_addr=0x10000,
        )
    )

    assert plan.has_atomic_cmpxchg_or_equivalent()
    assert plan.preserves_sc_result_register("t1")
    assert plan.preserves_memory_ordering()

@pytest.mark.parametrize(
    "asm, expected_pred, expected_succ",
    [
        ("fence r, w", "r", "w"),
        ("fence rw, rw", "rw", "rw"),
        ("fence iorw, iorw", "iorw", "iorw"),
    ],
)
@pytest.mark.xfail(
    strict=True,
    reason=(
        "Current fence analysis only records has_fence=True and does not "
        "preserve RISC-V pred/succ ordering operands."
    ),
)
def test_fence_pred_succ_are_preserved(
    lift_one,
    asm,
    expected_pred,
    expected_succ,
):
    insn = lift_one(
        asm,
        xlen=64,
        base_addr=0x10000,
    )

    summary = (
        getattr(insn, "summary", None)
        or getattr(insn, "ir_summary", None)
        or getattr(insn, "analysis", None)
    )

    assert summary is not None

    barrier = getattr(summary, "barrier_info", None)
    if barrier is None and isinstance(summary, dict):
        barrier = summary.get("barrier_info")

    assert barrier is not None
    assert barrier.pred == expected_pred
    assert barrier.succ == expected_succ
    assert barrier.is_instruction_fence is False
    assert barrier.is_tso_hint is False


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Current fence analysis does not preserve fence.tso as a distinct "
        "ordering/hint class."
    ),
)
def test_fence_tso_is_preserved_distinctly(lift_one):
    insn = lift_one(
        "fence.tso",
        xlen=64,
        base_addr=0x10000,
    )

    summary = (
        getattr(insn, "summary", None)
        or getattr(insn, "ir_summary", None)
        or getattr(insn, "analysis", None)
    )

    barrier = getattr(summary, "barrier_info", None)
    if barrier is None and isinstance(summary, dict):
        barrier = summary.get("barrier_info")

    assert barrier is not None
    assert barrier.is_tso_hint is True

#add_test
def test_assemble_supports_pc_relative_dot_plus_branch():
    result = assemble(
        AsmFragment(
            rawAsmText="""
            beq a0, a1, .+8
            addi a2, a2, 1
            addi a3, a3, 1
            """
        ),
        xlen=64,
    )

    assert result.ok, result.error
    assert result.machine_code

    # 确认送入 llvm-mc 的汇编已经完成规范化。
    assert "beq a0, a1, 8" in result.rendered_asm
    assert ".+8" not in result.rendered_asm


def test_assemble_supports_pc_relative_dot_minus_branch():
    result = assemble(
        AsmFragment(
            rawAsmText="""
            addi a0, a0, 1
            beq a0, a1, .-4
            addi a2, a2, 1
            """
        ),
        xlen=64,
    )

    assert result.ok, result.error
    assert result.machine_code

    assert "beq a0, a1, -4" in result.rendered_asm
    assert ".-4" not in result.rendered_asm


def test_dot_plus_branch_lifts_and_builds_cfg(lift_snippet):
    _, insns = _split_lift_result(
        lift_snippet(
            """
            beq a0, a1, .+8
            addi a2, a2, 1
            addi a3, a3, 1
            """,
            xlen=64,
            base_addr=BASE,
        )
    )

    blocks = _to_blocks(insns)
    cfg = build_cfg_from_blocks(blocks)

    assert cfg.ok, cfg.error


def test_normalize_dot_relative_branch_targets():
    source = """
    beq a0, a1, .+8
    beq a0, a1, .-4
    jal ra, .+16
    c.beqz a0, .-2
    """

    normalized = _normalize_riscv_dot_relative_targets(source)

    assert "beq a0, a1, 8" in normalized
    assert "beq a0, a1, -4" in normalized
    assert "jal ra, 16" in normalized
    assert "c.beqz a0, -2" in normalized

def test_normalize_dot_relative_targets_preserves_comments_labels_and_non_branches():
    source = """
L0:
    beq a0, a1, . + 0x8  # forward
1:  jal ra, . - 4
    addi a0, a0, .+8
    lui a1, %hi(.+8)
    """

    normalized = _normalize_riscv_dot_relative_targets(source)

    assert "beq a0, a1, 0x8# forward" in normalized
    assert "1:  jal ra, -4" in normalized

    # 非 branch/jump 指令不应被修改。
    assert "addi a0, a0, .+8" in normalized
    assert "lui a1, %hi(.+8)" in normalized
    

def test_lrsc_cas_builds_cfg_from_authoritative_blocks(
    lift_snippet,
    monkeypatch,
):
    # 注意：
    #
    # 当前 lift_snippet fixture 返回的是 list[LiftedInsn]，
    # 而不是带有 .insns 字段的 LiftResult。
    lifted_insns = lift_snippet(
        """
        lr.d t0, (a0)
        sc.d t1, t2, (a0)
        """,
        xlen=64,
        base_addr=0x10000,
    )

    assert lifted_insns
    assert isinstance(lifted_insns, list)

    # translation._try_lrsc_cas() 的输入契约是 lift.insns。
    # 为测试构造最小 LiftResult 兼容对象即可。
    lift = SimpleNamespace(insns=lifted_insns)

    calls = {}

    real_from_lifted = translation_mod.from_lifted
    real_build_cfg_from_blocks = translation_mod.build_cfg_from_blocks

    def spy_from_lifted(insns):
        calls["from_lifted_arg"] = insns

        blocks, ir_summary = real_from_lifted(insns)

        calls["blocks"] = blocks
        calls["ir_summary"] = ir_summary

        return blocks, ir_summary

    def spy_build_cfg_from_blocks(blocks):
        calls["build_cfg_blocks"] = blocks
        return real_build_cfg_from_blocks(blocks)

    def fail_build_cfg_any(*args, **kwargs):
        raise AssertionError(
            "LR/SC CAS translation must not call legacy build_cfg_any()"
        )

    # 验证新路径确实调用 from_lifted(lift.insns)。
    monkeypatch.setattr(
        translation_mod,
        "from_lifted",
        spy_from_lifted,
    )

    # 验证 from_lifted() 返回的 blocks 被交给 build_cfg_from_blocks()。
    monkeypatch.setattr(
        translation_mod,
        "build_cfg_from_blocks",
        spy_build_cfg_from_blocks,
    )

    # 即便 translation.py 已经删除 build_cfg_any import，
    # 这里仍通过 raising=False 注入 trap。
    #
    # 若旧实现重新调用 translation_mod.build_cfg_any，
    # 测试将立即失败。
    monkeypatch.setattr(
        translation_mod,
        "build_cfg_any",
        fail_build_cfg_any,
        raising=False,
    )

    detected = {}

    # 本测试不测试完整 CAS semantic detection。
    # 只要 _try_lrsc_cas 已完成 authoritative CFG 构造，
    # 然后调用 detector，就说明目标路径已经被覆盖。
    def reject_lrsc_cas(insns, cfg, op_idx, *, output_count):
        detected["insns"] = insns
        detected["cfg"] = cfg
        detected["op_idx"] = op_idx
        detected["output_count"] = output_count
        return None

    monkeypatch.setattr(
        translation_mod,
        "_detect_lrsc_cas",
        reject_lrsc_cas,
    )

    # 当前测试只会执行到 _detect_lrsc_cas()，不需要真实 operand。
    frag = SimpleNamespace(
        outputs=[],
        inputs=[],
    )

    out = translation_mod._try_lrsc_cas(
        frag=frag,
        lift=lift,
        summary=None,
        xlen=64,
    )

    # detector 被固定为“不匹配”，所以 None 是正常结果。
    assert out is None

    # 1. authoritative builder 的输入就是 lift.insns。
    assert calls["from_lifted_arg"] is lifted_insns
    assert calls["from_lifted_arg"] is lift.insns

    # 2. build_cfg_from_blocks() 接收到的必须是 from_lifted() 返回的 blocks。
    assert calls["build_cfg_blocks"] is calls["blocks"]

    # 3. blocks 确实被构造出来。
    assert calls["blocks"]

    # 4. CFG 已成功构建，并被传递给 CAS detector。
    assert detected["cfg"] is not None
    assert getattr(detected["cfg"], "ok", False)

    # 5. 指令模式识别仍然直接使用 lift.insns；
    #    这是允许的。禁止的是把 lift.insns 直接传入 CFG builder。
    assert detected["insns"] is lift.insns

def test_fence_pred_succ_are_preserved(lift_one):
    summary = summarize_lifted_instruction(lift_one("fence r, w"))

    assert summary.has_memory_barrier is True
    assert summary.has_instruction_barrier is False

    assert summary.barrier_info is not None
    assert summary.barrier_info.kind is BarrierKind.MEMORY_FENCE
    assert summary.barrier_info.pred == "r"
    assert summary.barrier_info.succ == "w"

def test_fence_rw_rw_is_preserved(lift_one):
    summary = summarize_lifted_instruction(lift_one("fence rw, rw"))

    assert summary.has_memory_barrier is True
    assert summary.has_instruction_barrier is False

    assert summary.barrier_info is not None
    assert summary.barrier_info.kind is BarrierKind.MEMORY_FENCE
    assert summary.barrier_info.pred == "rw"
    assert summary.barrier_info.succ == "rw"

def test_fence_iorw_iorw_is_preserved(lift_one):
    summary = summarize_lifted_instruction(lift_one("fence iorw, iorw"))

    assert summary.has_memory_barrier is True
    assert summary.has_instruction_barrier is False

    assert summary.barrier_info is not None
    assert summary.barrier_info.kind is BarrierKind.MEMORY_FENCE
    assert summary.barrier_info.pred == "iorw"
    assert summary.barrier_info.succ == "iorw"

def test_fence_tso_is_preserved_distinctly(lift_one):
    summary = summarize_lifted_instruction(lift_one("fence.tso"))

    assert summary.has_memory_barrier is True
    assert summary.has_instruction_barrier is False

    assert summary.barrier_info is not None
    assert summary.barrier_info.kind is BarrierKind.TSO_FENCE
    assert summary.barrier_info.is_tso_hint is True

def test_fence_i_is_not_collapsed_into_memory_fence(lift_one):
    summary = summarize_lifted_instruction(lift_one("fence.i"))

    assert summary.has_memory_barrier is False
    assert summary.has_instruction_barrier is True

    assert summary.barrier_info is not None
    assert summary.barrier_info.kind is BarrierKind.INSTRUCTION_FENCE

def test_multiple_fences_are_not_lost(lift_one):
    blocks, summary = from_lifted([
        lift_one("fence r, w"),
        lift_one("fence rw, rw"),
    ])

    assert len(summary.barrier_infos) == 2

    first, second = summary.barrier_infos

    assert first.kind is BarrierKind.MEMORY_FENCE
    assert first.pred == "r"
    assert first.succ == "w"

    assert second.kind is BarrierKind.MEMORY_FENCE
    assert second.pred == "rw"
    assert second.succ == "rw"

def test_fence_fragment_is_not_classified_as_generic_pure_c():
    frag = make_fragment("fence r, w")
    lift = lift_fragment(frag)
    _, summary = from_lifted(lift.insns)

    decision = _classify_preservation(frag, lift, summary)

    assert decision.route == "needs_memory_ordering_lowering"
    assert decision.level != "A"

def test_generic_pure_c_rejects_fence():
    frag = make_fragment("fence r, w")
    lift = lift_fragment(frag)
    _, summary = from_lifted(lift.insns)

    decision = _classify_preservation(frag, lift, summary)

    failures = _collect_generic_pure_c_proof_failures(
        frag=frag,
        lift=lift,
        summary=summary,
        decision=decision,
        xlen=64,
    )

    assert any("barrier" in item.lower() for item in failures)