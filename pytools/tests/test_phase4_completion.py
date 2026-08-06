from __future__ import annotations

import importlib
import pytest


def _import_any(paths, name):
    """
    Try importing `name` from a list of module paths.
    Return the attribute once found, otherwise raise ImportError.
    """
    errors = []
    for modname in paths:
        try:
            mod = importlib.import_module(modname)
            if hasattr(mod, name):
                return getattr(mod, name)
            errors.append(f"{modname}: missing {name}")
        except Exception as e:
            errors.append(f"{modname}: {e}")
    raise ImportError(f"cannot import {name}; tried: {errors}")


def _load_api():
    """
    Align imports with the actual project layout instead of assuming pytools.schema.
    """
    AsmFragment = _import_any(
        [
            "pytools.irtypes",
            "pytools.types",
            "pytools.model",
            "pytools.asmtypes",
            "pytools.fragment",
            "pytools.translate",
            "pytools.tests.test_pic",  # last resort for debugging layout
        ],
        "AsmFragment",
    )

    AsmOperand = _import_any(
        [
            "pytools.irtypes",
            "pytools.types",
            "pytools.model",
            "pytools.asmtypes",
            "pytools.fragment",
            "pytools.translate",
            "pytools.tests.test_pic",
        ],
        "AsmOperand",
    )

    AsmSymbolRef = _import_any(
        [
            "pytools.irtypes",
            "pytools.types",
            "pytools.model",
            "pytools.asmtypes",
            "pytools.fragment",
            "pytools.translate",
            "pytools.tests.test_pic",
        ],
        "AsmSymbolRef",
    )

    assemble = _import_any(
        [
            "pytools.assemble",
            "pytools.tests.test_pic",
        ],
        "assemble",
    )

    lift = _import_any(
        [
            "pytools.lift",
            "pytools.tests.test_pic",
        ],
        "lift",
    )

    from_lifted = _import_any(
        [
            "pytools.translate",
            "pytools.lower",
            "pytools.tests.test_pic",
        ],
        "from_lifted",
    )

    translate = _import_any(
        [
            "pytools.translate",
            "pytools.tests.test_pic",
        ],
        "translate",
    )

    return AsmFragment, AsmOperand, AsmSymbolRef, assemble, lift, from_lifted, translate


AsmFragment, AsmOperand, AsmSymbolRef, assemble, lift, from_lifted, translate = _load_api()


def _translate_pipeline(frag, *, xlen=64):
    a = assemble(frag)
    assert a.ok, getattr(a, "error", "")
    assert hasattr(a, "relocations")

    l = lift(a.machine_code, relocations=a.relocations)
    assert l.ok, getattr(l, "error", "")

    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=xlen)
    return a, l, tr


# ------------------------------------------------
# PIC completion tests
# ------------------------------------------------

def test_phase4_pic_pair_roundtrip():
    frag = AsmFragment(
        rawAsmText=(
            "1: auipc %0, %pcrel_hi(g_pic_sym)\n"
            "   addi  %0, %0, %pcrel_lo(1b)\n"
        ),
        outputs=[AsmOperand(constraint="=r", exprText="p", isOutput=True)],
        inputs=[],
        symbols=[AsmSymbolRef(asmName="g_pic_sym", cName="g_pic_sym")],
    )

    a, l, tr = _translate_pipeline(frag)
    rel_kinds = [getattr(r, "kind", "") for r in a.relocations]

    assert "PCREL_HI20" in rel_kinds, a.relocations
    assert any(k.startswith("PCREL_LO12") for k in rel_kinds), a.relocations
    assert tr.kind in ("pure_c", "hybrid_c"), getattr(tr, "notes", None)


def test_phase4_pic_missing_cname_reaches_translate_validation():
    frag = AsmFragment(
        rawAsmText=(
            "1: auipc %0, %pcrel_hi(g_pic_sym)\n"
            "   addi  %0, %0, %pcrel_lo(1b)\n"
        ),
        outputs=[AsmOperand(constraint="=r", exprText="p", isOutput=True)],
        inputs=[],
        symbols=[AsmSymbolRef(asmName="g_pic_sym", cName="")],
    )

    _, _, tr = _translate_pipeline(frag)
    assert tr.kind == "unsupported"
    joined = " ".join(getattr(tr, "notes", []))
    assert "PIC" in joined and "cName" in joined


def test_phase4_pic_multiple_symbols():
    frag = AsmFragment(
        rawAsmText=(
            "1: auipc %0, %pcrel_hi(sym_a)\n"
            "   addi  %0, %0, %pcrel_lo(1b)\n"
            "2: auipc %1, %pcrel_hi(sym_b)\n"
            "   addi  %1, %1, %pcrel_lo(2b)\n"
        ),
        outputs=[
            AsmOperand(constraint="=r", exprText="pa", isOutput=True),
            AsmOperand(constraint="=r", exprText="pb", isOutput=True),
        ],
        inputs=[],
        symbols=[
            AsmSymbolRef(asmName="sym_a", cName="sym_a"),
            AsmSymbolRef(asmName="sym_b", cName="sym_b"),
        ],
    )

    a = assemble(frag)
    assert a.ok, a.error
    assert hasattr(a, "relocations")

    rels = a.relocations
    assert len(rels) >= 4, rels
    assert sum(1 for r in rels if getattr(r, "kind", "") == "PCREL_HI20") >= 2


# ------------------------------------------------
# Integer block completion tests
# ------------------------------------------------

def test_phase4_intblock_simple_add_translates():
    frag = AsmFragment(
        rawAsmText="add %0, %1, %2",
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="a"),
            AsmOperand(constraint="r", exprText="b"),
        ],
        symbols=[],
    )

    _, _, tr = _translate_pipeline(frag)
    assert tr.kind in ("pure_c", "hybrid_c"), getattr(tr, "notes", None)


def test_phase4_intblock_zero_reg_path():
    frag = AsmFragment(
        rawAsmText="add %0, x0, %1",
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="a")],
        symbols=[],
    )

    _, _, tr = _translate_pipeline(frag)
    assert tr.kind in ("pure_c", "hybrid_c", "unsupported")
    joined = " ".join(getattr(tr, "notes", []))
    assert "traceback" not in joined.lower()


def test_phase4_intblock_forward_branch_smoke():
    frag = AsmFragment(
        rawAsmText=(
            "beq %0, x0, 1f\n"
            "add %1, %1, %2\n"
            "1:\n"
        ),
        outputs=[
            AsmOperand(constraint="=r", exprText="condv", isOutput=True),
            AsmOperand(constraint="=r", exprText="out", isOutput=True),
        ],
        inputs=[
            AsmOperand(constraint="r", exprText="in1"),
            AsmOperand(constraint="r", exprText="in2"),
        ],
        symbols=[],
    )

    a = assemble(frag)
    assert a.ok, a.error

    l = lift(a.machine_code, relocations=getattr(a, "relocations", []))
    assert l.ok, getattr(l, "error", "")

    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)

    assert tr.kind in ("pure_c", "hybrid_c", "unsupported")


def test_phase4_intblock_control_only_not_crash():
    frag = AsmFragment(
        rawAsmText=(
            "beq %0, x0, 1f\n"
            "1:\n"
        ),
        outputs=[AsmOperand(constraint="=r", exprText="x", isOutput=True)],
        inputs=[],
        symbols=[],
    )

    a = assemble(frag)
    assert a.ok, a.error

    l = lift(a.machine_code, relocations=getattr(a, "relocations", []))
    assert l.ok, getattr(l, "error", "")

    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)

    assert tr.kind in ("pure_c", "hybrid_c", "unsupported")
    joined = " ".join(getattr(tr, "notes", []))
    assert "traceback" not in joined.lower()


@pytest.mark.parametrize(
    "asm_text,n_inputs",
    [
        ("add %0, %1, %2", 2),
        ("sub %0, %1, %2", 2),
        ("xor %0, %1, %2", 2),
        ("or %0, %1, %2", 2),
        ("and %0, %1, %2", 2),
    ],
)
def test_phase4_integer_smoke_matrix(asm_text, n_inputs):
    inputs = []
    if n_inputs >= 1:
        inputs.append(AsmOperand(constraint="r", exprText="a"))
    if n_inputs >= 2:
        inputs.append(AsmOperand(constraint="r", exprText="b"))

    frag = AsmFragment(
        rawAsmText=asm_text,
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=inputs,
        symbols=[],
    )

    _, _, tr = _translate_pipeline(frag)
    assert tr.kind in ("pure_c", "hybrid_c", "unsupported")