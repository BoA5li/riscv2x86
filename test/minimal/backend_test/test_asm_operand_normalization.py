from types import SimpleNamespace
import copy
import pytest

from riscv2x86_py.assemble import materialize_template, assemble, _find_llvm_mc
import riscv2x86_py.pipeline as pipeline_module
from riscv2x86_py.pipeline import preflight_inline_asm, phase7_gate_inline_asm
from riscv2x86_py.pipeline import (
    phase7_gate_inline_asm,
    preflight_inline_asm,
)

import sys
from pathlib import Path
from riscv2x86_py.schema import AsmFragment, AsmOperand, Finding
# 把项目根目录加入搜索路径
ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT))

# 从 pytools.tests 包导入 helpers
from pytools.tests.helpers import run_single_pipeline_finding, run_pipeline_report


def op(constraint, symbolic_name=None):
    """
    构造可 JSON 序列化的 AsmOperand。

    不要返回 SimpleNamespace，因为 Finding 会经过：
        save_report() -> json.dump()

    AsmOperand 是 schema 中的 dataclass，能够被 dataclasses.asdict()
    正确递归转换为 JSON object。
    """
    return AsmOperand(
        constraint=constraint,
        symbolicName=symbolic_name,
    )


def frag(raw, outputs=None, inputs=None):
    return SimpleNamespace(
        rawAsmText=raw,
        outputs=outputs or [],
        inputs=inputs or [],
        clobbers=[],
        symbols=[],
    )

def _make_pipeline_finding(
    fragment,
    *,
    source_name="synthetic_inline_asm.c",
):
    """
    构造供 pipeline 集成测试使用的最小合法 Finding。

    返回的 Finding 具有非空 fragment.rawAsmText，因此：
        finding.enters_asm_pipeline() == True

    pipeline 可以在后续阶段安全更新：
        machineCodeHex
        pcodeText
        suggestedReplacement
        translationKind
        verificationStatus
        verificationDetail
        ruleName
        notes
        preservationLevel
        preservationRoute
    """
    raw_asm_text = (fragment.rawAsmText or "").strip()

    if not raw_asm_text:
        raise ValueError(
            "_make_pipeline_finding() requires a fragment "
            "with non-empty rawAsmText"
        )

    # 测试使用 synthetic source。rewrite range 覆盖该完整文本，
    # 使后续 pipeline / rewrite 相关逻辑可以将其视为有效 finding。
    raw_source_text = raw_asm_text

    return Finding(
        # Frontend classification.
        category="NeedsAsmTranslation",
        description="Synthetic inline asm finding for pipeline test",
        subjectKind="InlineAsm",

        # Synthetic source rewrite information.
        hasRewriteRange=True,
        rewriteBeginOffset=0,
        rewriteEndOffset=len(raw_source_text),
        rawSourceText=raw_source_text,

        # Synthetic source location.
        fileName=source_name,
        line=1,
        column=1,

        # The asm payload under test.
        fragment=fragment,

        # Fields populated by later pipeline phases.
        suggestedReplacement="",
        ruleName="",
        machineCodeHex="",
        pcodeText="",
        translationKind="",
        verificationStatus="",
        verificationDetail="",
        notes=[],
        preservationLevel="",
        preservationRoute="",
    )


@pytest.fixture
def valid_asm_finding():
    """
    最小合法 inline asm finding。

    不包含 volatile、asm goto、memory/cc clobber、
    early-clobber 或 tied operand，因此可进入正常 pipeline。
    """
    return _make_pipeline_finding(
        assemble_frag(
            "add %0, %1, %2",
            outputs=[op("=r", "dst")],
            inputs=[
                op("r", "lhs"),
                op("r", "rhs"),
            ],
        ),
        source_name="valid_asm_finding.c",
    )


@pytest.fixture
def another_valid_asm_finding():
    """
    用于验证 pipeline 在前一条 finding 失败后仍继续处理下一条 finding。

    使用不同的 source_name，以便它是独立的 synthetic finding。
    """
    return _make_pipeline_finding(
        assemble_frag(
            "sub %0, %1, %2",
            outputs=[op("=r", "dst")],
            inputs=[
                op("r", "lhs"),
                op("r", "rhs"),
            ],
        ),
        source_name="another_valid_asm_finding.c",
    )


@pytest.fixture
def asm_goto_finding():
    """
    用于验证 Phase 4 preflight 在调用 assemble() 前拒绝 asm goto。
    """
    return _make_pipeline_finding(
        assemble_frag(
            "beq %0, zero, %l[target]",
            inputs=[op("r", "cond")],
            goto_labels=["target"],
        ),
        source_name="asm_goto_finding.c",
    )
    
def assemble_frag(
    raw_asm_text,
    *,
    outputs=None,
    inputs=None,
    clobbers=None,
    symbols=None,
    goto_labels=None,
    is_volatile=False,
):
    """
    构造可 JSON 序列化的 AsmFragment。

    注意：
      - 不能使用 SimpleNamespace；
      - outputs / inputs 必须是 AsmOperand；
      - fragment 必须是 schema.As mFragment；
      - 字段名必须与 schema / JSON 格式一致。
    """
    return AsmFragment(
        rawAsmText=raw_asm_text,
        outputs=list(outputs or []),
        inputs=list(inputs or []),
        clobbers=list(clobbers or []),
        symbols=list(symbols or []),
        gotoLabels=list(goto_labels or []),
        isVolatile=is_volatile,
    )

def _assembled_program_body(rendered_asm: str) -> str:
    """
    从 assemble() 返回的完整汇编单元中提取测试关心的指令 body。

    assemble() 返回的是送往 llvm-mc 的完整汇编文本，可能包含：

        .text
        .data
        .globl ...
        ...

    本测试文件中的 operand normalization 集成测试只关心 inline-asm
    模板经 materialize 后的指令部分，因此过滤 section directive。

    注意：
      - materialize_template() 的精确格式应由其单元测试验证；
      - assemble() 集成测试应验证完整汇编单元可被 assembler 接受，
        而不应依赖 .text 前导空格或末尾换行等封装格式。
    """
    body_lines = []

    for line in (rendered_asm or "").splitlines():
        stripped = line.strip()

        # 当前 assemble() 会在汇编单元前加 .text。
        # 后续若加入 .data/.section 等 directive，也可在此扩展。
        if stripped == ".text":
            continue

        body_lines.append(stripped)

    return "\n".join(body_lines).strip()

def _has_text_section(rendered_asm: str) -> bool:
    return any(
        line.strip() == ".text"
        for line in (rendered_asm or "").splitlines()
    )


def test_plain_register_operands_are_distinct():
    f = frag(
        "add %0, %1, %2",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == "add x10, x11, x12"


def test_named_operands_are_resolved():
    f = frag(
        "add %[dst], %[lhs], %[rhs]",
        outputs=[op("=r", "dst")],
        inputs=[op("r", "lhs"), op("r", "rhs")],
    )

    assert materialize_template(f) == "add x10, x11, x12"


def test_unknown_named_operand_must_not_silently_become_percent_zero():
    f = frag(
        "add %[missing], %0, %1",
        outputs=[op("=r", "dst")],
        inputs=[op("r", "src")],
    )

    with pytest.raises(ValueError, match="unknown symbolic asm operand"):
        materialize_template(f)


def test_tied_numeric_input_reuses_output_register():
    """
    input constraint '0' 表示 input operand #1 绑定 output operand #0。
    """
    f = frag(
        "add %0, %0, %1",
        outputs=[op("=r")],
        inputs=[op("0")],
    )

    assert materialize_template(f) == "add x10, x10, x10"


def test_tied_named_input_reuses_named_output_register():
    f = frag(
        "add %[dst], %[dst], %[src]",
        outputs=[op("=r", "dst")],
        inputs=[
            op("[dst]", "same_as_dst"),
            op("r", "src"),
        ],
    )

    # %[dst] 是 output #0，%[same_as_dst] 在这里没有出现；
    # 若模板改为引用它，则应仍然映射到 x10。
    assert materialize_template(f) == "add x10, x10, x12"


def test_tied_named_input_when_explicitly_referenced():
    f = frag(
        "add %[dst], %[same], %[src]",
        outputs=[op("=r", "dst")],
        inputs=[
            op("[dst]", "same"),
            op("r", "src"),
        ],
    )

    assert materialize_template(f) == "add x10, x10, x12"


def test_memory_constraint_becomes_parenthesized_address():
    f = frag(
        "lw %0, %1",
        outputs=[op("=r")],
        inputs=[op("m")],
    )

    assert materialize_template(f) == "lw x10, (x11)"


def test_explicit_parentheses_are_not_doubled():
    f = frag(
        "lw %0, (%1)",
        outputs=[op("=r")],
        inputs=[op("m")],
    )

    assert materialize_template(f) == "lw x10, (x11)"


def test_lr_address_operand_is_normalized_even_if_constraint_is_r():
    """
    lr.w rd, (rs1)
    第二个汇编操作数必须是地址形式。
    """
    f = frag(
        "lr.w %0, %1",
        outputs=[op("=r")],
        inputs=[op("r")],
    )

    assert materialize_template(f) == "lr.w x10, (x11)"


def test_sc_address_operand_is_normalized_even_if_constraint_is_r():
    """
    sc.w rd, rs2, (rs1)
    第三个汇编操作数必须是地址形式。
    """
    f = frag(
        "sc.w %0, %1, %2",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == "sc.w x10, x11, (x12)"


def test_amo_address_operand_is_normalized_even_if_constraint_is_r():
    """
    amoadd.w rd, rs2, (rs1)
    第三个汇编操作数必须是地址形式。
    """
    f = frag(
        "amoadd.w %0, %1, %2",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == "amoadd.w x10, x11, (x12)"


def test_amo_explicit_parentheses_are_not_doubled():
    f = frag(
        "amoadd.w %0, %1, (%2)",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == "amoadd.w x10, x11, (x12)"


def test_escaped_percent_is_preserved():
    f = frag(
        "1: add %0, %0, %%zero",
        outputs=[op("=r")],
    )

    assert materialize_template(f) == "1:\nadd x10, x10, %zero"


def test_semicolon_is_split_to_assembly_lines():
    f = frag(
        "add %0, %1, %2; sub %0, %0, %1",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == (
        "add x10, x11, x12\n"
        "sub x10, x10, x11"
    )

@pytest.mark.skipif(
    _find_llvm_mc() is None,
    reason="llvm-mc is not installed",
)
def test_tied_operand_rendering_is_accepted_by_llvm_mc():
    f = SimpleNamespace(
        rawAsmText="add %0, %0, %1",
        outputs=[
            SimpleNamespace(constraint="=r", symbolicName=None),
        ],
        inputs=[
            SimpleNamespace(constraint="0", symbolicName=None),
        ],
        clobbers=[],
        symbols=[],
        gotoLabels=[],
        isVolatile=False,
    )

    result = assemble(f, xlen=64)

    assert result.ok, result.error
    assert result.machine_code
    assert "add x10, x10, x10" in result.rendered_asm

@pytest.mark.skipif(
    _find_llvm_mc() is None,
    reason="llvm-mc is not installed",
)
def test_atomic_operand_address_is_accepted_by_llvm_mc():
    f = SimpleNamespace(
        rawAsmText="amoadd.w %0, %1, %2",
        outputs=[
            SimpleNamespace(constraint="=r", symbolicName=None),
        ],
        inputs=[
            SimpleNamespace(constraint="r", symbolicName=None),
            SimpleNamespace(constraint="r", symbolicName=None),
        ],
        clobbers=[],
        symbols=[],
        gotoLabels=[],
        isVolatile=False,
    )

    result = assemble(f, xlen=64)

    assert result.ok, result.error
    assert "amoadd.w x10, x11, (x12)" in result.rendered_asm
    assert len(result.machine_code) == 4

def test_multiple_semicolon_statements_are_trimmed():
    f = frag(
        "  add %0, %1, %2 ;   sub %0, %0, %1 ;  ",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == (
        "add x10, x11, x12\n"
        "sub x10, x10, x11"
    )

def test_semicolon_inside_quoted_asm_string_is_not_split():
    f = frag(
        '.ascii "a;b"; nop',
    )

    assert materialize_template(f) == (
        '.ascii "a;b"\n'
        "nop"
    )

def test_assemble_tied_operand_with_llvm_mc():
    f = frag(
        "add %0, %0, %1",
        outputs=[op("=r")],
        inputs=[op("0")],
    )

    result = assemble(f, xlen=64)

    assert result.ok, result.error
    assert result.machine_code
    assert "add x10, x10, x10" in result.rendered_asm


def test_out_of_range_tied_operand_is_rejected():
    f = frag(
        "add %0, %0, %1",
        outputs=[op("=r")],
        inputs=[op("9")],
    )

    with pytest.raises(ValueError, match="out-of-range operand"):
        materialize_template(f)

def test_unknown_symbolic_tied_operand_is_rejected():
    f = frag(
        "add %0, %0, %1",
        outputs=[op("=r", "dst")],
        inputs=[op("[does_not_exist]", "src")],
    )

    with pytest.raises(ValueError, match="unknown symbolic tied operand name"):
        materialize_template(f)

def test_duplicate_symbolic_operand_name_is_rejected():
    f = frag(
        "add %[same], %[same], %2",
        outputs=[op("=r", "same")],
        inputs=[
            op("r", "same"),
            op("r", "rhs"),
        ],
    )

    with pytest.raises(ValueError, match="duplicate symbolic operand name"):
        materialize_template(f)

def test_assemble_returns_failure_for_invalid_operand_template():
    f = assemble_frag(
        "add %[missing], %0, %1",
        outputs=[op("=r", "dst")],
        inputs=[op("r", "src")],
    )

    result = assemble(f, xlen=64)

    assert not result.ok
    assert result.machine_code == b""
    assert result.rendered_asm == ""
    assert "invalid inline-asm operand template" in result.error
    assert "unknown symbolic asm operand" in result.error

def test_chained_tied_operands_resolve_to_final_output_register():
    """
    operands:
      #0: output =r
      #1: input  0   -> #0
      #2: input  1   -> #1 -> #0

    因此三者都必须使用 x10。
    """
    f = frag(
        "add %0, %1, %2",
        outputs=[op("=r")],
        inputs=[
            op("0"),
            op("1"),
        ],
    )

    assert materialize_template(f) == "add x10, x10, x10"

def test_empty_template_materializes_to_empty_string():
    f = frag("")

    assert materialize_template(f) == ""

def test_only_semicolons_and_whitespace_materialize_to_empty_string():
    f = frag(" ; ; \n  ;  ")

    assert materialize_template(f) == ""

def test_numeric_local_label_is_moved_to_its_own_line():
    f = frag(
        "1: add %0, %1, %2",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == (
        "1:\n"
        "add x10, x11, x12"
    )

def test_numeric_local_label_and_forward_branch_are_preserved():
    f = frag(
        "beq %0, %1, 1f; add %2, %2, %2; 1: nop",
        outputs=[op("=r")],
        inputs=[
            op("r"),
            op("r"),
        ],
    )

    assert materialize_template(f) == (
        "beq x11, x12, 1f\n"
        "add x10, x10, x10\n"
        "1:\n"
        "nop"
    )

def test_numeric_local_label_and_forward_branch_are_preserved():
    f = frag(
        "beq %1, %2, 1f; add %0, %0, %1; 1: nop",
        outputs=[op("=r")],
        inputs=[
            op("r"),
            op("r"),
        ],
    )

    assert materialize_template(f) == (
        "beq x11, x12, 1f\n"
        "add x10, x10, x11\n"
        "1:\n"
        "nop"
    )

def test_semicolon_inside_riscv_comment_is_not_split():
    f = frag(
        "add %0, %1, %2 # comment; not an instruction",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == (
        "add x10, x11, x12 # comment; not an instruction"
    )

def test_statement_separator_before_comment_is_preserved():
    f = frag(
        "add %0, %1, %2; sub %0, %0, %1 # second; comment",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
    )

    assert materialize_template(f) == (
        "add x10, x11, x12\n"
        "sub x10, x10, x11 # second; comment"
    )

@pytest.mark.skipif(
    _find_llvm_mc() is None,
    reason="llvm-mc is not installed",
)
def test_numeric_local_label_template_is_accepted_by_llvm_mc():
    f = assemble_frag(
        "beq %1, %2, 1f; add %0, %0, %1; 1: nop",
        outputs=[op("=r")],
        inputs=[
            op("r"),
            op("r"),
        ],
    )

    result = assemble(f, xlen=64)

    assert result.ok, result.error
    assert result.machine_code

    # assemble() 返回完整 asm unit，而不仅是模板 body。
    assert _has_text_section(result.rendered_asm)

    assert _assembled_program_body(result.rendered_asm) == (
        "beq x11, x12, 1f\n"
        "add x10, x10, x11\n"
        "1:\n"
        "nop"
    )

@pytest.mark.skipif(
    _find_llvm_mc() is None,
    reason="llvm-mc is not installed",
)
@pytest.mark.parametrize("xlen", [32, 64])
def test_basic_register_template_assembles_for_rv32_and_rv64(xlen):
    f = assemble_frag(
        "add %0, %1, %2",
        outputs=[op("=r")],
        inputs=[
            op("r"),
            op("r"),
        ],
    )

    result = assemble(f, xlen=xlen)

    assert result.ok, result.error
    assert result.machine_code

    # 验证 assemble() 返回的确实是可供 llvm-mc 使用的完整汇编单元。
    assert _has_text_section(result.rendered_asm)

    # 验证 inline asm 模板 body 的 operand materialization 正确。
    assert _assembled_program_body(result.rendered_asm) == (
        "add x10, x11, x12"
    )

@pytest.mark.skipif(
    _find_llvm_mc() is None,
    reason="llvm-mc is not installed",
)
def test_ld_is_rejected_for_rv32():
    f = assemble_frag(
        "ld %0, %1",
        outputs=[op("=r")],
        inputs=[op("m")],
    )

    result = assemble(f, xlen=32)

    assert not result.ok

def test_read_write_register_output_uses_register_placeholder():
    f = frag(
        "addi %0, %0, 1",
        outputs=[op("+r")],
    )

    assert materialize_template(f) == "addi x10, x10, 1"

@pytest.mark.skipif(
    _find_llvm_mc() is None,
    reason="llvm-mc is not installed",
)
def test_read_write_register_output_is_accepted_by_llvm_mc():
    f = assemble_frag(
        "addi %0, %0, 1",
        outputs=[op("+r")],
    )

    result = assemble(f, xlen=64)

    assert result.ok, result.error
    assert result.machine_code

    assert _has_text_section(result.rendered_asm)

    assert _assembled_program_body(result.rendered_asm) == (
        "addi x10, x10, 1"
    )

@pytest.mark.xfail(
    reason=(
        "multi-alternative GCC matching constraints require an explicit "
        "synthetic allocation policy"
    ),
    strict=False,
)
def test_ambiguous_multi_alternative_tied_constraint_is_rejected():
    f = frag(
        "add %0, %0, %1",
        outputs=[op("=r")],
        inputs=[op("0,1")],
    )

    with pytest.raises(ValueError, match="ambiguous tied operand"):
        materialize_template(f)


#test_inline_asm_pipeline_guards.py
def _finding_with_fragment(valid_asm_finding, fragment):
    """
    使用已有的可进入 asm pipeline 的 Finding 作为模板，
    替换其 fragment，避免测试依赖旧的 make_test_program /
    make_test_function 等已废弃测试接口。
    """
    finding = copy.deepcopy(valid_asm_finding)
    finding.fragment = fragment
    return finding


def _install_phase7_pipeline_stubs(monkeypatch, *, translation_result):
    """
    为 Phase 7 pipeline 集成测试安装稳定的 assemble/lift/translate stub。

    目标：
      assemble -> lift -> translate -> phase7 gate -> verify

    对于被 Phase 7 阻断的场景，verify 不应被调用。
    """
    calls = {
        "assemble": 0,
        "lift": 0,
        "translate": 0,
        "verify": 0,
    }

    def fake_assemble(*args, **kwargs):
        calls["assemble"] += 1
        return SimpleNamespace(
            ok=True,
            machine_code=b"\x13\x00\x00\x00",
            relocations=[],
            rendered_asm="nop",
            error="",
        )

    def fake_lift(*args, **kwargs):
        calls["lift"] += 1
        return SimpleNamespace(
            ok=True,
            insns=[],
            error="",
        )

    def fake_from_lifted(*args, **kwargs):
        return None, SimpleNamespace()

    def fake_translate(*args, **kwargs):
        calls["translate"] += 1
        return translation_result

    def verify_must_not_run(*args, **kwargs):
        calls["verify"] += 1
        raise AssertionError(
            "Phase 7 blocked finding must not reach verify()"
        )

    monkeypatch.setattr(pipeline_module, "assemble", fake_assemble)
    monkeypatch.setattr(pipeline_module, "lift", fake_lift)
    monkeypatch.setattr(pipeline_module, "from_lifted", fake_from_lifted)

    # 正确的 mock 点是 pipeline.translate，不是 translate_machine_code。
    monkeypatch.setattr(pipeline_module, "translate", fake_translate)
    monkeypatch.setattr(pipeline_module, "verify", verify_must_not_run)

    return calls


def test_assemble_returns_not_ok_for_unknown_named_operand():
    f = assemble_frag(
        "add %[missing], %0, %1",
        outputs=[op("=r", "dst")],
        inputs=[op("r", "src")],
    )

    result = assemble(f, xlen=64)

    assert not result.ok
    assert result.machine_code == b""
    assert result.rendered_asm == ""

    assert "invalid inline-asm operand template" in result.error
    assert "unknown symbolic asm operand" in result.error


def test_assemble_returns_not_ok_for_out_of_range_tied_operand():
    f = assemble_frag(
        "add %0, %0, %1",
        outputs=[op("=r")],
        inputs=[op("9")],
    )

    result = assemble(f, xlen=64)

    assert not result.ok
    assert result.machine_code == b""
    assert result.rendered_asm == ""

    assert "invalid inline-asm operand template" in result.error
    assert "out-of-range operand" in result.error


def test_assemble_returns_not_ok_for_duplicate_symbolic_operand_name():
    f = assemble_frag(
        "add %[same], %[same], %2",
        outputs=[op("=r", "same")],
        inputs=[
            op("r", "same"),
            op("r", "rhs"),
        ],
    )

    result = assemble(f, xlen=64)

    assert not result.ok
    assert result.machine_code == b""
    assert result.rendered_asm == ""
    assert "duplicate symbolic operand name" in result.error


def test_pipeline_marks_finding_failed_when_assemble_fails(
    tmp_path,
    monkeypatch,
    valid_asm_finding,
):
    def fake_assemble(fragment, xlen=64):
        return SimpleNamespace(
            ok=False,
            machine_code=b"",
            relocations=[],
            rendered_asm="",
            error="synthetic assemble failure",
        )

    monkeypatch.setattr(pipeline_module, "assemble", fake_assemble)

    stats, result = run_single_pipeline_finding(
        tmp_path,
        valid_asm_finding,
    )

    assert stats["failed"] == 1
    assert stats["unsupported"] == 0

    # assemble 失败应保持 NeedsAsmTranslation，而不是被转为 Unsupported。
    assert result.category == "NeedsAsmTranslation"
    assert result.verificationStatus == "failed"
    assert result.verificationDetail == "synthetic assemble failure"
    assert "assemble: synthetic assemble failure" in result.notes


def test_pipeline_continues_after_one_finding_assemble_failure(
    tmp_path,
    monkeypatch,
    valid_asm_finding,
    another_valid_asm_finding,
):
    calls = {"assemble": 0}

    def fake_assemble(fragment, xlen=64):
        calls["assemble"] += 1

        if calls["assemble"] == 1:
            return SimpleNamespace(
                ok=False,
                machine_code=b"",
                relocations=[],
                rendered_asm="",
                error="first finding intentionally fails assembly",
            )

        return SimpleNamespace(
            ok=True,
            machine_code=b"\x13\x00\x00\x00",
            relocations=[],
            rendered_asm="nop",
            error="",
        )

    def fake_lift(machine_code, xlen=64, relocations=None):
        return SimpleNamespace(
            ok=False,
            insns=[],
            error="second finding reached lift",
        )

    monkeypatch.setattr(pipeline_module, "assemble", fake_assemble)
    monkeypatch.setattr(pipeline_module, "lift", fake_lift)

    stats, results = run_pipeline_report(
        tmp_path,
        [valid_asm_finding, another_valid_asm_finding],
    )

    assert len(results) == 2
    assert calls["assemble"] == 2

    assert results[0].category == "NeedsAsmTranslation"
    assert results[0].verificationStatus == "failed"
    assert results[0].verificationDetail == (
        "first finding intentionally fails assembly"
    )

    # 第二条 finding 到达 lift，证明第一条 assemble 失败不会终止 pipeline。
    assert results[1].category == "NeedsAsmTranslation"
    assert results[1].verificationStatus == "failed"
    assert results[1].verificationDetail == "second finding reached lift"

    assert stats["failed"] == 2


def test_asm_goto_is_rejected_by_preflight():
    fragment = assemble_frag(
        "beq %0, zero, %l[target]",
        inputs=[op("r")],
        goto_labels=["target"],
    )

    blockers = preflight_inline_asm(fragment)

    assert blockers
    assert any(
        "asm goto" in reason.lower()
        for reason in blockers
    )


def test_asm_goto_is_rejected_before_assemble(
    tmp_path,
    monkeypatch,
    asm_goto_finding,
):
    def assemble_must_not_run(*args, **kwargs):
        raise AssertionError(
            "asm goto must be rejected by phase4 preflight before assemble()"
        )

    monkeypatch.setattr(
        pipeline_module,
        "assemble",
        assemble_must_not_run,
    )

    stats, result = run_single_pipeline_finding(
        tmp_path,
        asm_goto_finding,
    )

    assert stats["unsupported"] == 1
    assert stats["failed"] == 0

    assert result.category == "Unsupported"
    assert result.ruleName == "phase4.preflight_unsupported"
    assert result.verificationStatus == "unsupported"
    assert "asm goto" in result.verificationDetail.lower()

    assert any(
        note.startswith("phase4-preflight:")
        for note in result.notes
    )


@pytest.mark.parametrize(
    ("name", "fragment", "keyword"),
    [
        (
            "volatile asm",
            assemble_frag(
                "nop",
                is_volatile=True,
            ),
            "volatile",
        ),
        (
            "memory clobber",
            assemble_frag(
                "nop",
                clobbers=["memory"],
            ),
            "memory",
        ),
        (
            "condition-code clobber",
            assemble_frag(
                "nop",
                clobbers=["cc"],
            ),
            "cc",
        ),
        (
            "early clobber output",
            assemble_frag(
                "add %0, %1, %2",
                outputs=[op("=&r")],
                inputs=[op("r"), op("r")],
            ),
            "early-clobber",
        ),
    ],
)
def test_phase7_blocks_inline_asm_with_unsupported_semantics(
    name,
    fragment,
    keyword,
):
    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers, f"{name} must be blocked by the Phase 7 gate"
    assert any(keyword in reason.lower() for reason in blockers)


def test_phase7_blocks_volatile_inline_asm():
    fragment = assemble_frag(
        "nop",
        is_volatile=True,
    )

    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any("volatile" in reason.lower() for reason in blockers)


def test_phase7_blocks_memory_clobber():
    fragment = assemble_frag(
        "fence rw, rw",
        clobbers=["memory"],
    )

    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any("memory" in reason.lower() for reason in blockers)


def test_phase7_blocks_cc_clobber():
    fragment = assemble_frag(
        "slt %0, %1, %2",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
        clobbers=["cc"],
    )

    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any("cc" in reason.lower() for reason in blockers)


def test_phase7_blocks_early_clobber_output():
    fragment = assemble_frag(
        "add %0, %1, %2",
        outputs=[op("=&r")],
        inputs=[
            op("r"),
            op("r"),
        ],
    )

    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any("early-clobber" in reason.lower() for reason in blockers)


def test_phase7_blocks_simple_tied_operand():
    fragment = assemble_frag(
        "add %0, %0, %1",
        outputs=[op("=r")],
        inputs=[op("0"), op("r")],
    )

    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any(
        "tied operand" in reason.lower()
        for reason in blockers
    )


def test_phase7_blocks_resolvable_chained_tied_operands():
    fragment = assemble_frag(
        "add %0, %0, %1",
        outputs=[
            op("=r"),
            op("=r"),
        ],
        inputs=[
            op("1"),
            op("0"),
        ],
    )

    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any(
        "tied operand" in reason.lower()
        for reason in blockers
    )


def test_phase7_blocks_ambiguous_multi_alternative_tied_operand():
    fragment = assemble_frag(
        "add %0, %0, %1",
        outputs=[op("=r")],
        inputs=[
            op("0,r"),
        ],
    )

    tr = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any("tied operand" in reason.lower() for reason in blockers)


@pytest.mark.parametrize(
    ("name", "fragment", "keyword"),
    [
        (
            "volatile",
            assemble_frag("nop", is_volatile=True),
            "volatile",
        ),
        (
            "memory_clobber",
            assemble_frag("nop", clobbers=["memory"]),
            "memory",
        ),
        (
            "cc_clobber",
            assemble_frag("nop", clobbers=["cc"]),
            "cc",
        ),
        (
            "early_clobber",
            assemble_frag(
                "add %0, %1, %2",
                outputs=[op("=&r")],
                inputs=[op("r"), op("r")],
            ),
            "early-clobber",
        ),
    ],
)
def test_pipeline_blocks_phase7_unsupported_inline_asm(
    tmp_path,
    monkeypatch,
    valid_asm_finding,
    name,
    fragment,
    keyword,
):
    finding = _finding_with_fragment(valid_asm_finding, fragment)

    translation_result = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src;",
        notes=["synthetic translation"],
    )

    calls = _install_phase7_pipeline_stubs(
        monkeypatch,
        translation_result=translation_result,
    )

    stats, result = run_single_pipeline_finding(
        tmp_path,
        finding,
    )

    assert calls["assemble"] == 1
    assert calls["lift"] == 1

    # Phase 7 位于 translate() 之后。
    assert calls["translate"] == 1

    # 但被 Phase 7 阻断后不得进入 verify()。
    assert calls["verify"] == 0

    assert stats["unsupported"] == 1
    assert stats["shell_semantics_blocked"] == 1

    assert result.category == "Unsupported"
    assert result.ruleName == "phase7.shell_semantics_unsupported"
    assert result.verificationStatus == "unsupported"
    assert keyword in result.verificationDetail.lower()


@pytest.mark.parametrize(
    ("fragment", "keyword"),
    [
        (
            assemble_frag("nop", is_volatile=True),
            "volatile",
        ),
        (
            assemble_frag("nop", clobbers=["memory"]),
            "memory",
        ),
        (
            assemble_frag("nop", clobbers=["cc"]),
            "cc",
        ),
        (
            assemble_frag(
                "add %0, %1, %2",
                outputs=[op("=&r")],
                inputs=[op("r"), op("r")],
            ),
            "early-clobber",
        ),
    ],
)
def test_phase7_blocked_asm_reaches_translation_but_never_reaches_verify(
    tmp_path,
    monkeypatch,
    valid_asm_finding,
    fragment,
    keyword,
):
    """
    修正旧测试的错误预期：

    Phase 7 需要检查 translate() 生成的 replacement 是否保留
    volatile / memory / cc 语义，因此它设计上发生在 translate() 后。

    正确断言是：
      * translate() 必须被调用；
      * verify() 不得被调用；
      * Finding 被标记为 Unsupported。
    """
    finding = _finding_with_fragment(valid_asm_finding, fragment)

    translation_result = SimpleNamespace(
        kind="lower_to_c",
        replacement="dst = src + 1;",
        notes=["synthetic lower_to_c result"],
    )

    calls = _install_phase7_pipeline_stubs(
        monkeypatch,
        translation_result=translation_result,
    )

    stats, result = run_single_pipeline_finding(
        tmp_path,
        finding,
    )

    assert calls["translate"] == 1
    assert calls["verify"] == 0

    assert stats["unsupported"] == 1
    assert stats["shell_semantics_blocked"] == 1

    assert result.category == "Unsupported"
    assert result.ruleName == "phase7.shell_semantics_unsupported"
    assert result.verificationStatus == "unsupported"
    assert keyword in result.verificationDetail.lower()


def test_phase7_blocks_x86_inline_asm_when_volatile_is_not_preserved():
    fragment = assemble_frag(
        "nop",
        is_volatile=True,
    )

    tr = SimpleNamespace(
        kind="lower_to_x86_inline_asm",
        replacement='asm("nop");',
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any(
        "volatile" in reason.lower()
        for reason in blockers
    )


def test_phase7_accepts_x86_inline_asm_when_volatile_is_preserved():
    fragment = assemble_frag(
        "nop",
        is_volatile=True,
    )

    tr = SimpleNamespace(
        kind="lower_to_x86_inline_asm",
        replacement='asm volatile("nop");',
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers == []


def test_phase7_blocks_x86_inline_asm_when_memory_clobber_is_not_preserved():
    fragment = assemble_frag(
        "fence rw, rw",
        clobbers=["memory"],
    )

    tr = SimpleNamespace(
        kind="lower_to_x86_inline_asm",
        replacement='asm volatile("mfence");',
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any(
        "memory" in reason.lower()
        for reason in blockers
    )


def test_phase7_blocks_x86_inline_asm_when_cc_clobber_is_not_preserved():
    fragment = assemble_frag(
        "slt %0, %1, %2",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
        clobbers=["cc"],
    )

    tr = SimpleNamespace(
        kind="lower_to_x86_inline_asm",
        replacement=(
            'asm volatile("cmp %1, %2; setl %0" '
            ': "=r"(dst) : "r"(lhs), "r"(rhs));'
        ),
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers
    assert any(
        "cc" in reason.lower()
        for reason in blockers
    )


def test_phase7_accepts_x86_inline_asm_when_memory_and_cc_are_preserved():
    fragment = assemble_frag(
        "slt %0, %1, %2",
        outputs=[op("=r")],
        inputs=[op("r"), op("r")],
        clobbers=["memory", "cc"],
    )

    tr = SimpleNamespace(
        kind="lower_to_x86_inline_asm",
        replacement=(
            'asm volatile("cmp %1, %2; setl %0" '
            ': "=r"(dst) '
            ': "r"(lhs), "r"(rhs) '
            ': "memory", "cc");'
        ),
        notes=[],
    )

    blockers = phase7_gate_inline_asm(fragment, tr)

    assert blockers == []