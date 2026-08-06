from __future__ import annotations

import ctypes
import json
import random
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from pytools.riscv2x86_py import pipeline
import pytest
from pytools.riscv2x86_py.runtime_facts import TranslationRuntimeFacts, canonicalize_riscv_register_name,build_translation_runtime_facts
from pytools.riscv2x86_py.translate import X86LoweringOperandBindingView,ExplicitRvOperandBinding
from pytools.riscv2x86_py.x86_att_integer_lowering import UnsupportedTranslationError, require_x86_att_64bit_pcode_register_binding
from pytools.riscv2x86_py.assemble import AssembleResult
from pytools.riscv2x86_py.schema import AsmFragment
from pytools.riscv2x86_py.lift import LiftResult, LiftedInsn


def read_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data["findings"]
    return data


@pytest.mark.integration
def test_real_json_to_translate_output(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
):
    """
    真实执行：
        JSON load
        -> assemble
        -> lift
        -> p-code IR
        -> CFG
        -> translate

    正式 verify 被测试桩替代。
    """
    output_json = tmp_path / "output.json"

    monkeypatch.setattr(
        backend_module,
        "verify",
        lambda fragment, lift, summary, translation: SimpleNamespace(
            status="verified",
            detail="Phase 8 bypassed: translate-stage integration test",
        ),
    )

    stats = backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    finding = read_findings(output_json)[0]

    assert stats["total"] == 1
    assert stats["failed"] == 0, (
        f"pipeline failed:\n"
        f"category={finding.get('category')!r}\n"
        f"translationKind={finding.get('translationKind')!r}\n"
        f"verificationStatus={finding.get('verificationStatus')!r}\n"
        f"verificationDetail={finding.get('verificationDetail')!r}\n"
        f"notes={finding.get('translationNotes')!r}\n"
        f"pcode={finding.get('pcodeText')!r}"
    )
    assert finding["category"] == "ReplaceableByRule", (
        "translation did not produce a replaceable rule\n"
        f"category={finding.get('category')!r}\n"
        f"ruleName={finding.get('ruleName')!r}\n"
        f"translationKind={finding.get('translationKind')!r}\n"
        f"translationNotes={finding.get('translationNotes')!r}\n"
        f"translationReason={finding.get('translationReason')!r}\n"
        f"translationMetadata={finding.get('translationMetadata')!r}\n"
        f"notes={finding.get('notes')!r}\n"
        f"verificationStatus={finding.get('verificationStatus')!r}\n"
        f"verificationDetail={finding.get('verificationDetail')!r}\n"
        f"suggestedReplacement={finding.get('suggestedReplacement')!r}\n"
        f"pcode={finding.get('pcodeText')!r}"
    )

    assert finding.get("machineCodeHex")
    assert finding.get("pcodeText")
    assert finding.get("translationKind")

    # 本示例是普通寄存器算术，预期不应落入 unsupported。
    assert finding["category"] == "ReplaceableByRule"
    assert finding["ruleName"] in {
        "phase6.lower_to_c",
        "phase6.lower_to_x86_inline_asm",
    }

    replacement = finding.get("suggestedReplacement", "")
    assert replacement.strip()

    pcode = finding["pcodeText"].lower()
    assert "add" in pcode
    assert "sub" in pcode


def apply_replacement(source: str, finding: dict) -> str:
    begin = finding["rewriteBeginOffset"]
    end = finding["rewriteEndOffset"]
    expected = finding["rawSourceText"]

    assert source[begin:end] == expected, (
        "rewrite offsets do not select rawSourceText; "
        "check whether offsets are byte offsets or character offsets"
    )

    replacement = finding["suggestedReplacement"]
    return source[:begin] + replacement + source[end:]


@pytest.mark.integration
@pytest.mark.semantic
def test_generated_translation_has_same_runtime_semantics(
    monkeypatch,
    backend_module,
    copied_input_json,
    input_c_path,
    tmp_path,
):
    """
    端到端语义测试，但不调用正式 verify/writeback：

      1. 后端真实生成 replacement；
      2. 测试代码临时完成替换；
      3. 使用宿主 x86-64 GCC 编译；
      4. 调用 rv_add_sub；
      5. 比较 RISC-V 源指令的预期语义。

    源指令：
        result = a + b
        result = result - b

    在 XLEN=64 模运算语义下，最终结果应为 a。
    """
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc is required for semantic compile/run test")

    output_json = tmp_path / "output.json"

    monkeypatch.setattr(
        backend_module,
        "verify",
        lambda *args, **kwargs: SimpleNamespace(
            status="verified",
            detail="verify intentionally bypassed",
        ),
    )

    stats = backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    assert stats["failed"] == 0

    finding = read_findings(output_json)[0]
    assert finding["category"] == "ReplaceableByRule", (
    "translation did not produce a replaceable rule\n"
    f"category={finding.get('category')!r}\n"
    f"ruleName={finding.get('ruleName')!r}\n"
    f"translationKind={finding.get('translationKind')!r}\n"
    f"translationNotes={finding.get('translationNotes')!r}\n"
    f"translationReason={finding.get('translationReason')!r}\n"
    f"translationMetadata={finding.get('translationMetadata')!r}\n"
    f"suggestedReplacement={finding.get('suggestedReplacement')!r}\n"
    f"pcode={finding.get('pcodeText')!r}"
)
    assert finding["category"] == "ReplaceableByRule"
    assert finding["suggestedReplacement"].strip()

    original_source = input_c_path.read_text(encoding="utf-8")
    translated_source = apply_replacement(original_source, finding)

    generated_c = tmp_path / "rv_add_sub.translated.c"
    generated_so = tmp_path / "librv_add_sub.so"

    generated_c.write_text(translated_source, encoding="utf-8")

    compile_result = subprocess.run(
        [
            gcc,
            "-shared",
            "-fPIC",
            "-O0",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            str(generated_so),
            str(generated_c),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    assert compile_result.returncode == 0, (
        "generated translation cannot be compiled on x86-64\n"
        f"source:\n{translated_source}\n\n"
        f"stdout:\n{compile_result.stdout}\n"
        f"stderr:\n{compile_result.stderr}"
    )

    library = ctypes.CDLL(str(generated_so))
    function = library.rv_add_sub
    function.argtypes = [ctypes.c_longlong, ctypes.c_longlong]
    function.restype = ctypes.c_longlong

    deterministic_cases = [
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (-1, 1),
        (1, -1),
        (-100, 17),
        (123456789, 987654),
        (2**31 - 1, 17),
        (-(2**31), -19),
    ]

    rng = random.Random(0x52564358)
    random_cases = [
        (
            rng.randint(-(2**40), 2**40),
            rng.randint(-(2**40), 2**40),
        )
        for _ in range(200)
    ]

    for a, b in deterministic_cases + random_cases:
        actual = function(a, b)
        expected = a

        assert actual == expected, (
            f"semantic mismatch: a={a}, b={b}, "
            f"expected={expected}, actual={actual}"
        )
    
def test_x10_is_resolved_using_runtime_operand_index_not_register_number():
    context = SimpleNamespace(
        runtimeFacts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 3},
            operand_width_bits={3: 64},
        ),
        bindings=X86LoweringOperandBindingView(
            rv_to_operand={
                "a0": ExplicitRvOperandBinding(
                    operandIndex=3,
                    role="output",
                    expression="result",
                    widthBits=64,
                ),
            },
            errors=[],
        ),
    )

    binding = require_x86_att_64bit_pcode_register_binding(
        context,
        "x10",
    )

    assert binding.operandIndex == 3
    assert binding.expression == "result"
    assert binding.widthBits == 64

def test_x86_lowering_rejects_missing_width_even_if_xlen_is_64():
    context = SimpleNamespace(
        xlen=64,
        runtimeFacts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0},
            operand_width_bits={},
        ),
        bindings=X86LoweringOperandBindingView(
            rv_to_operand={
                "a0": ExplicitRvOperandBinding(
                    operandIndex=0,
                    role="output",
                    expression="result",
                    widthBits=64,
                ),
            },
            errors=[],
        ),
    )

    with pytest.raises(UnsupportedTranslationError) as exc_info:
        require_x86_att_64bit_pcode_register_binding(context, "a0")

    assert "host operand width fact" in str(exc_info.value)

def test_x86_lowering_rejects_runtime_fact_binding_mismatch():
    context = SimpleNamespace(
        runtimeFacts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 3},
            operand_width_bits={3: 64},
        ),
        bindings=X86LoweringOperandBindingView(
            rv_to_operand={
                "a0": ExplicitRvOperandBinding(
                    operandIndex=0,
                    role="output",
                    expression="result",
                    widthBits=64,
                ),
            },
            errors=[],
        ),
    )

    with pytest.raises(UnsupportedTranslationError) as exc_info:
        require_x86_att_64bit_pcode_register_binding(context, "x10")

    assert "disagree on GNU operand index" in str(exc_info.value)

def test_build_translation_runtime_facts_preserves_assembled_widths():
    assembled_facts = TranslationRuntimeFacts(
        rv_to_operand_index={
            "a0": 0,
            "a1": 1,
            "a2": 2,
        },
        operand_width_bits={
            0: 64,
            1: 64,
            2: 64,
        },
    )

    ar = AssembleResult(
        ok=True,
        machine_code=b"",
        insn_listing=[],
        error="",
        rendered_asm="",
        relocations=[],
        translation_runtime_facts=assembled_facts,
    )

    result = build_translation_runtime_facts(
        finding=object(),
        assemble_result=ar,
    )

    assert result.ok
    assert result.facts.rv_to_operand_index == {
        "a0": 0,
        "a1": 1,
        "a2": 2,
    }
    assert result.facts.operand_width_bits == {
        0: 64,
        1: 64,
        2: 64,
    }

def test_build_translation_runtime_facts_uses_assemble_result_not_stale_finding():
    finding = SimpleNamespace(
        translationRuntimeFacts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0},
            operand_width_bits={},
        )
    )

    ar = AssembleResult(
        ok=True,
        machine_code=b"",
        insn_listing=[],
        error="",
        rendered_asm="",
        relocations=[],
        translation_runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={
                "a0": 0,
                "a1": 1,
            },
            operand_width_bits={
                0: 64,
                1: 64,
            },
        ),
    )

    result = build_translation_runtime_facts(
        finding=finding,
        assemble_result=ar,
    )

    assert result.ok
    assert result.facts.operand_width_bits == {
        0: 64,
        1: 64,
    }

def test_build_translation_runtime_facts_rejects_missing_width_for_bound_operand():
    ar = AssembleResult(
        ok=True,
        machine_code=b"",
        insn_listing=[],
        error="",
        rendered_asm="",
        relocations=[],
        translation_runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={
                "a0": 0,
                "a1": 1,
                "a2": 2,
            },
            operand_width_bits={
                0: 64,
                1: 64,
                # operand 2 缺失
            },
        ),
    )

    result = build_translation_runtime_facts(
        finding=object(),
        assemble_result=ar,
    )

    assert not result.ok
    assert result.facts.rv_to_operand_index == {}
    assert result.facts.operand_width_bits == {}
    assert "GNU operand %2" in result.error
    assert "widthBits" in result.error

def test_x86_lowerer_reads_lift_result_from_translation_context():
    lift_result = LiftResult(
        ok=True,
        insns=[
            LiftedInsn(
                addr=0x10000,
                length=4,
                asm_mnem="add",
                asm_body="a0,a1,a2",
                pcode_ops=[
                    "IMARK ram[10000:4]",
                    "a0 = a1 + a2",
                ],
                raw_ops=[],
                sym_ref=None,
                summary=None,
            ),
            LiftedInsn(
                addr=0x10004,
                length=2,
                asm_mnem="c.sub",
                asm_body="a0,a2",
                pcode_ops=[
                    "IMARK ram[10004:2]",
                    "a0 = a0 - a2",
                ],
                raw_ops=[],
                sym_ref=None,
                summary=None,
            ),
        ],
        error="",
    )

    context = SimpleNamespace(
        lift_result=lift_result,
        # 故意不提供 lift，确保 lowerer 使用正式字段。
    )

    assert "a0 = a1 + a2" in lines
    assert "a0 = a0 - a2" in lines