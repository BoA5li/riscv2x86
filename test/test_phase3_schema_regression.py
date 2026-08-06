import json
import sys
from pathlib import Path

root_path = Path(__file__).parent.parent
sys.path.insert(0, str(root_path))

from pytools.riscv2x86_py.schema import (
    load_report,
    save_report,
    Finding,
    AsmFragment,
    AsmOperand,
    OutputBinding,
    AsmSymbolRef,
)


def test_load_report_accepts_legacy_asmText_and_builds_fragment(tmp_path):
    in_json = tmp_path / "legacy.json"
    data = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "description": "legacy asmText format",
                "file": "legacy.c",
                "line": 12,
                "column": 7,
                "asmText": "addi %0, %1, 1",
                "id": "frag-legacy-1",
                "predecessorFragmentId": "frag-prev",
                "successorFragmentId": "frag-next",
                "hasRetryLoop": True,
                "outputBindings": [
                    {
                        "outputIndex": 0,
                        "sinkKind": "Result",
                        "sinkOpIndex": 1,
                        "aluExpr": "x+1",
                    }
                ],
                "symbols": [
                    {
                        "asmName": "g_foo",
                        "cName": "g_foo",
                        "addrTaken": True,
                    }
                ],
            }
        ]
    }
    in_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    findings = load_report(str(in_json))
    assert len(findings) == 1

    f = findings[0]
    assert f.category == "NeedsAsmTranslation"
    assert f.fragment is not None

    frag = f.fragment
    assert frag.rawAsmText == "addi %0, %1, 1"
    assert frag.fileName == "legacy.c"
    assert frag.line == 12
    assert frag.column == 7

    # 旧格式 id -> fragment.id / fragment.fragmentId 双向归一
    assert frag.id == "frag-legacy-1"
    assert frag.fragmentId == "frag-legacy-1"

    assert frag.predecessorFragmentId == "frag-prev"
    assert frag.successorFragmentId == "frag-next"
    assert frag.hasRetryLoop is True

    assert len(frag.outputBindings) == 1
    assert frag.outputBindings[0].outputIndex == 0
    assert frag.outputBindings[0].sinkKind == "Result"
    assert frag.outputBindings[0].sinkOpIndex == 1
    assert frag.outputBindings[0].aluExpr == "x+1"

    assert len(frag.symbols) == 1
    assert frag.symbols[0].asmName == "g_foo"
    assert frag.symbols[0].cName == "g_foo"
    assert frag.symbols[0].addrTaken is True


def test_fragment_id_and_fragmentId_are_normalized_both_directions(tmp_path):
    in_json = tmp_path / "ids.json"
    data = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "description": "fragment uses id only",
                "fragment": {
                    "id": "frag-id-only",
                    "rawAsmText": "addi %0, %1, 1",
                    "fileName": "a.c",
                    "line": 1,
                    "column": 1,
                },
            },
            {
                "category": "NeedsAsmTranslation",
                "description": "fragment uses fragmentId only",
                "fragment": {
                    "fragmentId": "frag-fragmentId-only",
                    "rawAsmText": "addi %0, %1, 2",
                    "fileName": "b.c",
                    "line": 2,
                    "column": 2,
                },
            },
        ]
    }
    in_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    findings = load_report(str(in_json))
    assert len(findings) == 2

    f0 = findings[0]
    assert f0.fragment is not None
    assert f0.fragment.id == "frag-id-only"
    assert f0.fragment.fragmentId == "frag-id-only"

    f1 = findings[1]
    assert f1.fragment is not None
    assert f1.fragment.id == "frag-fragmentId-only"
    assert f1.fragment.fragmentId == "frag-fragmentId-only"


def test_save_and_load_roundtrip_preserves_phase3_relevant_fields(tmp_path):
    path = tmp_path / "roundtrip.json"

    finding = Finding(
        category="NeedsAsmTranslation",
        description="roundtrip",
        fileName="rt.c",
        line=7,
        column=2,
        verificationStatus="",
        verificationDetail="",
        notes=["seed-note"],
        fragment=AsmFragment(
            kind="InlineExtended",
            rawAsmText="addi %0, %1, 1",
            outputs=[
                AsmOperand(
                    constraint="=r",
                    exprText="out",
                    symbolicName="dst",
                    isOutput=True,
                    isTied=False,
                    isEarlyClobber=False,
                )
            ],
            inputs=[
                AsmOperand(
                    constraint="r",
                    exprText="in",
                    symbolicName="src",
                    isOutput=False,
                    isTied=False,
                    isEarlyClobber=False,
                )
            ],
            clobbers=["memory"],
            gotoLabels=["L_retry"],
            isVolatile=True,
            fileName="rt.c",
            line=7,
            column=2,
            beginOffset=100,
            endOffset=120,
            enclosingFunction="foo",
            fragmentId="frag-rt-1",
            predecessorFragmentId="frag-prev",
            successorFragmentId="frag-next",
            hasRetryLoop=True,
            outputBindings=[
                OutputBinding(
                    outputIndex=0,
                    sinkKind="Result",
                    sinkOpIndex=1,
                    aluExpr="x+1",
                )
            ],
            symbols=[
                AsmSymbolRef(
                    asmName="g_bar",
                    cName="ctx->g_bar",
                    addrTaken=True,
                )
            ],
        ),
    )

    save_report([finding], str(path))
    loaded = load_report(str(path))

    assert len(loaded) == 1
    got = loaded[0]
    assert got.category == "NeedsAsmTranslation"
    assert got.description == "roundtrip"
    assert got.fileName == "rt.c"
    assert got.line == 7
    assert got.column == 2
    assert got.notes == ["seed-note"]

    assert got.fragment is not None
    frag = got.fragment
    assert frag.kind == "InlineExtended"
    assert frag.rawAsmText == "addi %0, %1, 1"
    assert frag.fileName == "rt.c"
    assert frag.line == 7
    assert frag.column == 2
    assert frag.beginOffset == 100
    assert frag.endOffset == 120
    assert frag.enclosingFunction == "foo"
    assert frag.id == "frag-rt-1"
    assert frag.fragmentId == "frag-rt-1"
    assert frag.predecessorFragmentId == "frag-prev"
    assert frag.successorFragmentId == "frag-next"
    assert frag.hasRetryLoop is True
    assert frag.isVolatile is True

    assert len(frag.outputs) == 1
    assert frag.outputs[0].constraint == "=r"
    assert frag.outputs[0].exprText == "out"
    assert frag.outputs[0].symbolicName == "dst"
    assert frag.outputs[0].isOutput is True

    assert len(frag.inputs) == 1
    assert frag.inputs[0].constraint == "r"
    assert frag.inputs[0].exprText == "in"
    assert frag.inputs[0].symbolicName == "src"

    assert frag.clobbers == ["memory"]
    assert frag.gotoLabels == ["L_retry"]

    assert len(frag.outputBindings) == 1
    assert frag.outputBindings[0].outputIndex == 0
    assert frag.outputBindings[0].sinkKind == "Result"
    assert frag.outputBindings[0].sinkOpIndex == 1
    assert frag.outputBindings[0].aluExpr == "x+1"

    assert len(frag.symbols) == 1
    assert frag.symbols[0].asmName == "g_bar"
    assert frag.symbols[0].cName == "ctx->g_bar"
    assert frag.symbols[0].addrTaken is True


def test_enters_asm_pipeline_matches_phase3_contract():
    f_already_rule = Finding(
        category="ReplaceableByRule",
        fragment=AsmFragment(rawAsmText="addi %0, %1, 1"),
    )
    f_non_fragment = Finding(
        category="NeedsAsmTranslation",
        fragment=None,
    )
    f_blank_text = Finding(
        category="NeedsAsmTranslation",
        fragment=AsmFragment(rawAsmText="   "),
    )
    f_real_asm = Finding(
        category="NeedsAsmTranslation",
        fragment=AsmFragment(rawAsmText="addi %0, %1, 1"),
    )
    f_irrelevant = Finding(
        category="OtherCategory",
        fragment=AsmFragment(rawAsmText="addi %0, %1, 1"),
    )

    assert f_already_rule.has_asm_fragment() is True
    assert f_already_rule.enters_asm_pipeline() is False

    assert f_non_fragment.has_asm_fragment() is False
    assert f_non_fragment.enters_asm_pipeline() is False

    assert f_blank_text.has_asm_fragment() is False
    assert f_blank_text.fragment.has_asm_text() is False
    assert f_blank_text.enters_asm_pipeline() is False

    assert f_real_asm.has_asm_fragment() is True
    assert f_real_asm.fragment.has_asm_text() is True
    assert f_real_asm.enters_asm_pipeline() is True

    assert f_irrelevant.has_asm_fragment() is True
    assert f_irrelevant.enters_asm_pipeline() is False