# tests/test_lift.py

from __future__ import annotations

import inspect
import textwrap

import pytest

import riscv2x86_py.pipeline as pipeline
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import LiftResult, lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.schema import (
    AsmControlFlowSurface,
    AsmFragment,
    AsmMicroArchIntent,
    AsmOperand,
    Finding,
    load_report,
    save_report,
)


def assemble_frag(
    asm_text: str,
    *,
    fragment_id: str = "test-fragment",
    file_name: str = "test_input.c",
    line: int = 1,
) -> AsmFragment:
    """
    为 assembler / lifter 测试构造最小但完整的 AsmFragment。

    assemble() 的输入是 AsmFragment，而不是裸字符串；此前测试缺失该
    helper，导致所有 assemble_frag(...) 调用均触发 NameError。
    """
    return AsmFragment(
        kind="InlineExtended",
        rawAsmText=textwrap.dedent(asm_text).strip(),
        fileName=file_name,
        line=line,
        column=1,
        id=fragment_id,
        fragmentId=fragment_id,
    )


def opname(op) -> str:
    return op.opcode.name if hasattr(op.opcode, "name") else str(op.opcode)


def all_opnames(insn) -> list[str]:
    return [opname(op) for op in insn.raw_ops]


def find_ops(insn, opcode: str):
    return [op for op in insn.raw_ops if opname(op) == opcode]


def var_space(v) -> str:
    if v is None:
        return ""
    return getattr(getattr(v, "space", None), "name", "")


def var_offset(v):
    if v is None:
        return None
    return int(v.offset)


def var_size(v):
    if v is None:
        return None
    return int(v.size)


def lift_asm(
    fragment: AsmFragment,
    *,
    xlen: int = 64,
    base_addr: int = 0x10000,
):
    """
    执行 Phase 4 assemble 与 Phase 5 lift。

    这里统一检查 assemble/lift 的错误，以避免后续测试在错误结果上
    继续访问 insns，产生与真正根因无关的 AttributeError/IndexError。
    """
    ar = assemble(fragment, xlen=xlen)
    assert ar.ok, ar.error

    lr = lift(
        ar.machine_code,
        xlen=xlen,
        base_addr=base_addr,
        relocations=ar.relocations,
        strict_disassembly=True,
    )
    assert lr.ok, lr.error
    return ar, lr


def test_fragment_id_and_id_are_kept_in_sync():
    fragment = AsmFragment(rawAsmText="nop", fragmentId="frag-1")

    assert fragment.fragmentId == "frag-1"
    assert fragment.id == "frag-1"

    fragment2 = AsmFragment(rawAsmText="nop", id="frag-2")

    assert fragment2.id == "frag-2"
    assert fragment2.fragmentId == "frag-2"


def test_finding_enters_asm_pipeline_only_with_nonempty_asm():
    empty = Finding(fragment=AsmFragment(rawAsmText=""))
    valid = Finding(fragment=assemble_frag("nop"))
    no_fragment = Finding()

    assert empty.enters_asm_pipeline() is False
    assert no_fragment.enters_asm_pipeline() is False
    assert valid.enters_asm_pipeline() is True
    assert valid.has_asm_fragment() is True


def test_legacy_asm_text_report_preserves_fragment_fields(tmp_path):
    """
    回归测试 schema.py 中 legacy asmText 分支。

    旧版扁平报告加载后必须保留 operand、clobber、控制流与微架构意图，
    而不仅是 rawAsmText。
    """
    report_path = tmp_path / "legacy_report.json"
    report_path.write_text(
        """
        {
          "findings": [
            {
              "category": "NeedsAsmTranslation",
              "file": "legacy.c",
              "line": 12,
              "column": 3,
              "id": "legacy-frag",
              "asmText": "add a0, a1, a2",
              "outputs": [
                {
                  "constraint": "=r",
                  "exprText": "out",
                  "symbolicName": "dst",
                  "isOutput": true
                }
              ],
              "inputs": [
                {
                  "constraint": "r",
                  "exprText": "in"
                }
              ],
              "clobbers": ["memory"],
              "hasAsmGoto": true,
              "gotoEdges": [
                {
                  "asmTarget": "%l0",
                  "cLabel": "slow_path",
                  "exitCode": 1
                }
              ],
              "controlFlow": {
                "style": "AsmGoto",
                "hasAsmGoto": true,
                "hasFallthrough": true,
                "exitTargets": ["slow_path"]
              },
              "microArch": {
                "level": "B",
                "preserveControlFlowShape": true,
                "tags": ["branch-sensitive"]
              }
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    findings = load_report(str(report_path))

    assert len(findings) == 1
    finding = findings[0]
    fragment = finding.fragment

    assert fragment is not None
    assert fragment.rawAsmText == "add a0, a1, a2"
    assert fragment.fileName == "legacy.c"
    assert fragment.line == 12
    assert fragment.id == "legacy-frag"
    assert fragment.fragmentId == "legacy-frag"

    assert len(fragment.outputs) == 1
    assert fragment.outputs[0].constraint == "=r"
    assert fragment.outputs[0].exprText == "out"
    assert fragment.outputs[0].isOutput is True

    assert len(fragment.inputs) == 1
    assert fragment.inputs[0].constraint == "r"
    assert fragment.inputs[0].exprText == "in"

    assert fragment.clobbers == ["memory"]
    assert fragment.hasAsmGoto is True
    assert len(fragment.gotoEdges) == 1
    assert fragment.gotoEdges[0].cLabel == "slow_path"

    assert fragment.controlFlow is not None
    assert fragment.controlFlow.style == "AsmGoto"
    assert fragment.controlFlow.hasAsmGoto is True

    assert fragment.microArch is not None
    assert fragment.microArch.level == "B"
    assert fragment.microArch.preserveControlFlowShape is True


def test_schema_roundtrip_preserves_nested_fragment_metadata(tmp_path):
    report_path = tmp_path / "roundtrip.json"

    fragment = AsmFragment(
        rawAsmText="beq a0, a1, 1f\\n1: nop",
        id="cfg-frag",
        outputs=[
            AsmOperand(
                constraint="=r",
                exprText="result",
                symbolicName="result",
                isOutput=True,
            )
        ],
        clobbers=["memory"],
        hasAsmGoto=True,
        controlFlow=AsmControlFlowSurface(
            style="AsmGoto",
            hasAsmGoto=True,
            hasMultipleExits=True,
            exitTargets=["slow_path"],
        ),
        microArch=AsmMicroArchIntent(
            level="C",
            preserveExperiment=True,
            preserveBranchPredictorShape=True,
            tags=["spectre-test"],
        ),
    )

    save_report([Finding(fragment=fragment)], str(report_path))
    loaded = load_report(str(report_path))

    assert len(loaded) == 1
    loaded_fragment = loaded[0].fragment

    assert loaded_fragment is not None
    assert loaded_fragment.id == "cfg-frag"
    assert loaded_fragment.fragmentId == "cfg-frag"
    assert loaded_fragment.outputs[0].symbolicName == "result"
    assert loaded_fragment.clobbers == ["memory"]

    assert loaded_fragment.controlFlow is not None
    assert loaded_fragment.controlFlow.style == "AsmGoto"
    assert loaded_fragment.controlFlow.hasMultipleExits is True

    assert loaded_fragment.microArch is not None
    assert loaded_fragment.microArch.level == "C"
    assert loaded_fragment.microArch.preserveBranchPredictorShape is True


def test_lift_three_rv64_instructions_have_correct_addresses():
    fragment = assemble_frag(
        """
        nop
        add a0, a1, a2
        addi a0, a1, 1
        """
    )

    ar, lr = lift_asm(fragment, xlen=64, base_addr=0x10000)

    assert len(lr.insns) == 3
    assert [ins.addr for ins in lr.insns] == [0x10000, 0x10004, 0x10008]
    assert [ins.length for ins in lr.insns] == [4, 4, 4]
    assert [ins.asm_mnem.lower() for ins in lr.insns] == ["nop", "add", "addi"]
    assert sum(ins.length for ins in lr.insns) == len(ar.machine_code)


def test_lift_add_contains_int_add():
    _, lr = lift_asm(assemble_frag("add a0, a1, a2"), xlen=64)

    assert len(lr.insns) == 1
    assert lr.insns[0].asm_mnem.lower() == "add"
    assert "INT_ADD" in all_opnames(lr.insns[0])

def test_lift_add_reads_and_writes_registers():
    _, lr = lift_asm(assemble_frag("add a0, a1, a2"), xlen=64)

    _, summary = from_lifted(lr.insns)

    assert summary.reads_regs
    assert summary.writes_regs

    # add a0, a1, a2：
    # 应读取两个源寄存器，并写入一个目标寄存器。
    assert len(summary.reads_regs) >= 2
    assert len(summary.writes_regs) >= 1


def test_lift_add_has_expected_register_dataflow():
    _, lr = lift_asm(assemble_frag("add a0, a1, a2"), xlen=64)

    add_ops = find_ops(lr.insns[0], "INT_ADD")
    assert add_ops, lr.insns[0].pcode_ops

    add_op = add_ops[0]

    # 输出可以是 unique temporary；输入必须承载 RV64 宽度。
    assert len(add_op.inputs) == 2
    assert all(var_size(v) == 8 for v in add_op.inputs)


@pytest.mark.parametrize(
    ("xlen", "expected_size"),
    [
        (32, 4),
        (64, 8),
    ],
)
def test_lift_add_uses_xlen_sized_registers(xlen, expected_size):
    _, lr = lift_asm(assemble_frag("add a0, a1, a2"), xlen=xlen)

    add_ops = find_ops(lr.insns[0], "INT_ADD")
    assert add_ops

    assert any(var_size(v) == expected_size for v in add_ops[0].inputs)


def test_lift_rv64_addw_sign_extends_word_result():
    """
    RV64 addw 的语义为：
        sext32((rs1[31:0] + rs2[31:0]) mod 2^32)

    因此 lift 结果必须显式体现最终 32->64 符号扩展。
    """
    _, lr = lift_asm(assemble_frag("addw a0, a1, a2"), xlen=64)

    ops = set(all_opnames(lr.insns[0]))

    assert "INT_ADD" in ops
    assert "INT_SEXT" in ops


def test_rv32_rejects_ld_before_lifting():
    ar = assemble(assemble_frag("ld a0, 0(a1)"), xlen=32)

    assert ar.ok is False
    assert ar.error


def test_rv64_lifts_ld():
    _, lr = lift_asm(assemble_frag("ld a0, 0(a1)"), xlen=64)

    assert len(lr.insns) == 1
    assert "LOAD" in all_opnames(lr.insns[0])


def test_lift_lw_contains_load_and_summary_reads_memory():
    _, lr = lift_asm(assemble_frag("lw a0, 4(a1)"), xlen=64)

    assert "LOAD" in all_opnames(lr.insns[0])

    _, summary = from_lifted(lr.insns)

    assert summary.reads_mem is True
    assert summary.writes_mem is False


def test_lift_sw_contains_store_and_summary_writes_memory():
    _, lr = lift_asm(assemble_frag("sw a0, 4(a1)"), xlen=64)

    assert "STORE" in all_opnames(lr.insns[0])

    _, summary = from_lifted(lr.insns)

    assert summary.reads_mem is False
    assert summary.writes_mem is True


def test_rv64_lw_and_lwu_have_distinct_extension_semantics():
    """
    lw:  sign-extend 32-bit loaded value to XLEN。
    lwu: zero-extend 32-bit loaded value to XLEN。
    """
    _, lw_lr = lift_asm(assemble_frag("lw a0, 4(a1)"), xlen=64)
    _, lwu_lr = lift_asm(assemble_frag("lwu a0, 4(a1)"), xlen=64)

    lw_ops = set(all_opnames(lw_lr.insns[0]))
    lwu_ops = set(all_opnames(lwu_lr.insns[0]))

    assert "LOAD" in lw_ops
    assert "LOAD" in lwu_ops
    assert "INT_SEXT" in lw_ops
    assert "INT_ZEXT" in lwu_ops


def test_lift_beq_produces_conditional_branch():
    fragment = assemble_frag(
        """
        beq a0, a1, 8
        addi a2, a2, 1
        addi a3, a3, 1
        """
    )

    _, lr = lift_asm(fragment, xlen=64, base_addr=0x10000)

    assert "CBRANCH" in all_opnames(lr.insns[0])

    blocks, summary = from_lifted(lr.insns)

    assert summary.has_branch is True
    assert summary.is_single_block is False
    assert blocks


def test_lift_jal_has_control_flow_and_writes_return_register():
    fragment = assemble_frag(
        """
        jal ra, 1f
        addi a0, a0, 1
        1:
        addi a1, a1, 1
        """
    )

    _, lr = lift_asm(fragment, xlen=64)

    first_ops = set(all_opnames(lr.insns[0]))
    _, summary = from_lifted(lr.insns)

    assert first_ops & {"CALL", "BRANCH"}
    assert summary.has_branch or summary.has_call_or_return

    # jal ra, target 必须写 ra；后续 addi 也可能写 a0/a1。
    assert summary.writes_regs


def test_fence_is_classified_as_memory_barrier():
    _, lr = lift_asm(assemble_frag("fence rw, rw"), xlen=64)

    _, summary = from_lifted(lr.insns)

    assert summary.has_memory_barrier is True


def test_amoadd_is_classified_as_atomic():
    _, lr = lift_asm(assemble_frag("amoadd.w a0, a1, (a2)"), xlen=64)

    _, summary = from_lifted(lr.insns)

    assert summary.has_atomic is True
    assert summary.reads_mem is True or "LOAD" in all_opnames(lr.insns[0])
    assert summary.writes_mem is True or "STORE" in all_opnames(lr.insns[0])


@pytest.mark.parametrize(
    ("asm_text", "expected_ordering"),
    [
        ("amoadd.w.aq a0, a1, (a2)", "aq"),
        ("amoadd.w.rl a0, a1, (a2)", "rl"),
        ("amoadd.w.aqrl a0, a1, (a2)", "aqrl"),
    ],
)
def test_atomic_ordering_suffix_is_not_lost(asm_text, expected_ordering):
    _, lr = lift_asm(assemble_frag(asm_text), xlen=64)

    _, summary = from_lifted(lr.insns)

    assert summary.has_atomic is True
    assert expected_ordering in summary.atomic_orderings


def test_straight_line_code_is_one_block():
    fragment = assemble_frag(
        """
        add a0, a1, a2
        sub a3, a4, a5
        """
    )

    _, lr = lift_asm(fragment, xlen=64)
    blocks, summary = from_lifted(lr.insns)

    assert len(blocks) == 1
    assert summary.is_single_block is True
    assert summary.has_branch is False
    assert blocks[0].successors == []


def test_conditional_branch_creates_target_and_fallthrough_blocks():
    fragment = assemble_frag(
        """
        beq a0, a1, 1f
        addi a2, a2, 1
        1:
        addi a3, a3, 1
        """
    )

    _, lr = lift_asm(fragment, xlen=64, base_addr=0x10000)
    blocks, summary = from_lifted(lr.insns)

    assert summary.has_branch is True
    assert summary.is_single_block is False
    assert len(blocks) == 3

    entry = blocks[0]
    assert entry.addr == 0x10000
    assert set(entry.successors) == {0x10004, 0x10008}


def test_indirect_return_has_no_fake_internal_cfg_successor():
    _, lr = lift_asm(assemble_frag("jalr zero, 0(ra)"), xlen=64)

    blocks, summary = from_lifted(lr.insns)

    assert summary.has_branch or summary.has_call_or_return
    assert len(blocks) == 1
    assert blocks[0].successors == []


def test_lift_rejects_empty_machine_code():
    lr = lift(b"", xlen=64)

    assert lr.ok is False
    assert "empty machine code" in lr.error.lower()


def test_lift_rejects_invalid_xlen():
    lr = lift(b"\x13\x00\x00\x00", xlen=128)

    assert lr.ok is False
    assert "unsupported xlen" in lr.error.lower()


def test_lift_rejects_truncated_instruction():
    lr = lift(b"\x33\x85", xlen=64, strict_disassembly=True)

    assert lr.ok is False
    assert lr.error


def test_pipeline_continues_after_one_lift_failure(monkeypatch):
    """
    验证 pipeline 对单个 lift 失败的隔离能力。

    该测试约定 pipeline 提供如下接口：

        pipeline.run(findings=[...], xlen=64) -> {"failed": int, ...}

    如果当前工程尚未提供 findings 参数，则明确 skip，避免重新引入原始
    测试中 run(...) 占位符导致的语法错误或对未知 API 的错误猜测。
    """
    if not hasattr(pipeline, "run"):
        pytest.skip("pipeline.run is not implemented")

    run_signature = inspect.signature(pipeline.run)
    if "findings" not in run_signature.parameters:
        pytest.skip(
            "pipeline.run does not expose the required findings= API; "
            "add pipeline.run(findings=[...], xlen=...) before enabling this test"
        )

    original_lift = pipeline.lift
    calls = 0

    def fake_lift(*args, **kwargs):
        nonlocal calls
        calls += 1

        if calls == 1:
            return LiftResult(
                ok=False,
                insns=[],
                error="synthetic lift failure",
            )

        return original_lift(*args, **kwargs)

    monkeypatch.setattr(pipeline, "lift", fake_lift)

    findings = [
        Finding(
            category="NeedsAsmTranslation",
            fragment=assemble_frag(
                "addi a0, a0, 1",
                fragment_id="first-failing-fragment",
            ),
        ),
        Finding(
            category="NeedsAsmTranslation",
            fragment=assemble_frag(
                "addi a1, a1, 1",
                fragment_id="second-successful-fragment",
            ),
        ),
    ]

    kwargs = {"findings": findings}
    if "xlen" in run_signature.parameters:
        kwargs["xlen"] = 64

    stats = pipeline.run(**kwargs)

    assert calls >= 2, "第一个 fragment lift 失败后 pipeline 不应停止处理后续 fragment"
    assert isinstance(stats, dict)
    assert stats["failed"] == 1