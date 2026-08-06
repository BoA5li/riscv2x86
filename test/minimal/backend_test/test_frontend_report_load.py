from pathlib import Path

from riscv2x86_py.schema import load_report


# 锁定json存放目录
FIXTURE_DIR = Path("/root/src/poc_trans/path_b/riscv2x86/test/minimal/output")


def load_fixture(name: str):
    json_path = FIXTURE_DIR / name
    return load_report(str(json_path))


def test_load_multi_asm_report():
    # 去掉多余 _report
    findings = load_fixture("rv_multi_asm.json")

    assert len(findings) == 2

    first = findings[0]
    second = findings[1]

    assert first.fragment is not None
    assert second.fragment is not None

    assert first.fragment.rawAsmText == "add %0, %1, %2"
    assert second.fragment.rawAsmText == "addi %0, %0, 1"

    assert first.fragment.beginOffset < first.fragment.endOffset
    assert second.fragment.beginOffset < second.fragment.endOffset
    assert first.fragment.endOffset <= second.fragment.beginOffset


def test_load_tied_operand():
    findings = load_fixture("rv_add_tied_explicit.json")

    assert len(findings) == 1
    fragment = findings[0].fragment
    assert fragment is not None

    assert len(fragment.outputs) == 1
    assert len(fragment.inputs) == 2

    assert fragment.outputs[0].constraint == "=r"

    assert fragment.inputs[0].constraint == "0"
    assert fragment.inputs[0].exprText == "value"
    assert fragment.inputs[0].isTied is True

    assert fragment.inputs[1].constraint == "r"
    assert fragment.inputs[1].exprText == "increment"


def test_load_immediate_operand():
    findings = load_fixture("rv_addi_imm.json")

    assert len(findings) == 1
    fragment = findings[0].fragment
    assert fragment is not None

    assert fragment.inputs[0].constraint == "r"
    assert fragment.inputs[0].exprText == "value"

    assert fragment.inputs[1].constraint == "i"
    assert fragment.inputs[1].exprText == "7"


def test_load_volatile_and_clobber():
    findings = load_fixture("rv_add_with_clobber.json")

    assert len(findings) == 1
    fragment = findings[0].fragment
    assert fragment is not None

    assert fragment.isVolatile is True
    assert fragment.clobbers == ["t0"]


def test_load_memory_clobber():
    findings = load_fixture("rv_memory_clobber_report.json")

    assert len(findings) == 1
    fragment = findings[0].fragment
    assert fragment is not None

    assert "memory" in fragment.clobbers


def test_load_asm_goto():
    findings = load_fixture("rv_asm_goto_report.json")

    assert len(findings) == 1
    fragment = findings[0].fragment
    assert fragment is not None

    assert fragment.kind == "InlineGoto"
    assert fragment.gotoLabels == ["zero"]


def test_load_named_operands():
    findings = load_fixture("rv_add_named.json")

    assert len(findings) == 1
    fragment = findings[0].fragment
    assert fragment is not None

    assert fragment.outputs[0].symbolicName == "out"

    assert fragment.inputs[0].symbolicName == "lhs"
    assert fragment.inputs[1].symbolicName == "rhs"

def test_load_rewrite_range_fields():
    findings = load_fixture("rv_add_tied_explicit.json")

    assert len(findings) == 1

    finding = findings[0]

    assert finding.hasRewriteRange is True
    assert finding.rewriteBeginOffset == 98
    assert finding.rewriteEndOffset == 198

    assert finding.rewriteBeginOffset < finding.rewriteEndOffset

    # 如果前端报告中确实输出 rawSourceText，则启用以下断言。
    assert finding.rawSourceText
    assert "__asm__" in finding.rawSourceText or "asm" in finding.rawSourceText