import importlib
import os
import pytest
from types import SimpleNamespace


def import_from_env(env_name: str, default: str):
    mod_name = os.environ.get(env_name, default)
    try:
        return importlib.import_module(mod_name)
    except ModuleNotFoundError as e:
        pytest.skip(f"module not importable: {mod_name} ({e})", allow_module_level=True)


def get_attr_chain(module, dotted: str):
    cur = module
    for part in dotted.split('.'):
        cur = getattr(cur, part)
    return cur

def test_schema_roundtrip_fragment_extra_fields(tmp_path):
    from riscv2x86_py.schema import save_report, load_report, Finding, AsmFragment, AsmControlFlowSurface, AsmMicroArchIntent

    f = Finding(
        fragment=AsmFragment(
            rawAsmText="jal ra, foo",
            controlFlow=AsmControlFlowSurface(style="CallLike", hasCallLike=True),
            microArch=AsmMicroArchIntent(level="C", preserveControlFlowShape=True),
        )
    )

    p = tmp_path / "r.json"
    save_report([f], str(p))
    out = load_report(str(p))

    assert out[0].fragment is not None
    assert out[0].fragment.controlFlow is not None
    assert out[0].fragment.controlFlow.style == "CallLike"
    assert out[0].fragment.microArch is not None
    assert out[0].fragment.microArch.level == "C"

def test_translate_call_like_closes_to_x86():
    from riscv2x86_py.translate import translate
    from riscv2x86_py.schema import AsmFragment, AsmOperand

    frag = AsmFragment(
        rawAsmText="jal ra, foo",
        isVolatile=True,
    )
    lift = SimpleNamespace(
        insns=[SimpleNamespace(addr=0x1000, asm_mnem="jal", asm_body="ra, foo")]
    )
    summary = SimpleNamespace(has_call_or_return=True)

    out = translate(frag, lift, summary, xlen=64)
    assert out.kind == "phase6.lower_to_x86_inline_asm"
    assert "call foo" in out.replacement
    assert any("preservation.level=C" in x for x in out.notes)

def test_translate_lrsc_rmw_emits_cmpxchg_loop(monkeypatch):
    from riscv2x86_py.translate import translate
    from riscv2x86_py.schema import AsmFragment, AsmOperand

    class Match:
        width_bits = 64
        addr_input_index = 0
        arg_input_index = 1
        old_output_index = 0
        op = "add"

    def fake_match(frag, lift, xlen=64):
        return Match()

    import riscv2x86_py.patterns.lrsc_rmw as lrsc_rmw
    monkeypatch.setattr(lrsc_rmw, "try_match_lrsc_rmw", fake_match)

    frag = AsmFragment(
        rawAsmText="lr.d ... sc.d",
        inputs=[
            AsmOperand(exprText="ptr"),
            AsmOperand(exprText="delta"),
        ],
        outputs=[
            AsmOperand(exprText="oldv", isOutput=True),
        ],
        microarchSensitive=True,
    )
    lift = SimpleNamespace(
        insns=[
            SimpleNamespace(addr=0x1000, asm_mnem="lr.d", asm_body="t0, (a0)"),
            SimpleNamespace(addr=0x1004, asm_mnem="add", asm_body="t1, t0, a1"),
            SimpleNamespace(addr=0x1008, asm_mnem="sc.d", asm_body="t2, t1, (a0)"),
        ]
    )
    summary = SimpleNamespace(has_call_or_return=False)

    out = translate(frag, lift, summary, xlen=64)
    assert out.kind == "phase6.lower_to_x86_inline_asm"
    assert "lock cmpxchgq" in out.replacement
    assert "pause" in out.replacement

def test_verify_x86_inline_asm_output():
    from riscv2x86_py.verify import verify_translation
    from riscv2x86_py.translate import TranslationOutput

    tr = TranslationOutput(
        kind="phase6.lower_to_x86_inline_asm",
        replacement='do { __asm__ volatile ("call foo\\n\\t" ::: "rax","rcx","rdx","memory","cc"); } while (0);',
        notes=["preservation.level=C"],
    )

    res = verify_translation(tr, frag=None)
    assert res["status"] in ("verified", "build_only")