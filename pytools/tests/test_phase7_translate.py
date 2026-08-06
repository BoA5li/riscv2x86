from types import SimpleNamespace

from .test_phase7_conftest import import_from_env


translate_mod = import_from_env("R2X_TRANSLATE_MODULE", "riscv2x86_py.translate")


class DummyOut(SimpleNamespace):
    pass


def _mk_frag():
    return SimpleNamespace(outputs=[], inputs=[], symbols=[])


def _mk_lift():
    return SimpleNamespace(insns=[])


def _mk_summary():
    return SimpleNamespace(is_single_block=True, has_atomic=False,
                           has_memory_barrier=False, has_branch=False)


def _mk_decision(level="A"):
    return SimpleNamespace(level=level, reasons=[f"level={level}"])


def test_translate_pic_short_circuits(monkeypatch):
    pic = DummyOut(kind="pure_c", replacement="PIC_OK", notes=["pic"])
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: pic)

    out = translate_mod.translate(_mk_frag(), _mk_lift(), _mk_summary())
    assert out.kind == "pure_c"
    assert out.replacement == "PIC_OK"
    assert "preservation_level=A" in out.notes
    assert "preservation_route=canonical_pic_pure_c" in out.notes


def test_translate_level_d_routes_to_experiment_preserving(monkeypatch):
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_classify_preservation", lambda *a, **k: _mk_decision("D"))

    seen = {}
    def fake_close(**kwargs):
        seen.update(kwargs)
        return DummyOut(kind="needs_route", replacement="", notes=["routed"])

    monkeypatch.setattr(translate_mod, "_close_to_x86_inline_asm_or_route", fake_close)
    out = translate_mod.translate(_mk_frag(), _mk_lift(), _mk_summary())

    assert out.kind == "needs_route"
    assert seen["route"] == "needs_experiment_preserving_lowering"
    assert seen["preserve_experiment"] is True


def test_translate_level_c_routes_to_control_preserving(monkeypatch):
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_classify_preservation", lambda *a, **k: _mk_decision("C"))

    seen = {}
    def fake_needs_route(route, decision, reasons):
        seen["route"] = route
        seen["decision"] = decision
        seen["reasons"] = reasons
        return DummyOut(kind="needs_route", replacement="", notes=["c-route"])

    monkeypatch.setattr(translate_mod, "_needs_route", fake_needs_route)
    out = translate_mod.translate(_mk_frag(), _mk_lift(), _mk_summary())

    assert out.kind == "needs_route"
    assert seen["route"] == "needs_control_preserving_lowering"
    assert any("call/ret-sensitive" in r for r in seen["reasons"])


def test_translate_level_b_routes_to_stack_aware(monkeypatch):
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_classify_preservation", lambda *a, **k: _mk_decision("B"))

    seen = {}
    def fake_needs_route(route, decision, reasons):
        seen["route"] = route
        seen["reasons"] = reasons
        return DummyOut(kind="needs_route", replacement="", notes=["b-route"])

    monkeypatch.setattr(translate_mod, "_needs_route", fake_needs_route)
    out = translate_mod.translate(_mk_frag(), _mk_lift(), _mk_summary())

    assert out.kind == "needs_route"
    assert seen["route"] == "needs_stack_aware_lowering"
    assert any("stack/ra-sensitive" in r for r in seen["reasons"])


def test_translate_proof_gate_failure_falls_back(monkeypatch):
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_classify_preservation", lambda *a, **k: _mk_decision("A"))
    monkeypatch.setattr(translate_mod, "_try_lrsc_cas", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_try_lrsc_rmw", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_iter_canonical_pure_c_strategies", lambda: [])
    monkeypatch.setattr(translate_mod, "_pic_bindings_for_intblock", lambda *a, **k: [])
    monkeypatch.setattr(translate_mod, "_collect_generic_pure_c_proof_failures",
                        lambda **k: ["bad semantics"])

    seen = {}
    def fake_fallback(route, decision, reasons, **kwargs):
        seen["route"] = route
        seen["reasons"] = reasons
        return DummyOut(kind="needs_route", replacement="", notes=["fallback"])

    monkeypatch.setattr(translate_mod, "_fallback_after_pure_c_reject", fake_fallback)
    out = translate_mod.translate(_mk_frag(), _mk_lift(), _mk_summary())

    assert out.kind == "needs_route"
    assert seen["route"] == "needs_semantic_x86_lowering"
    assert any("explicit semantics-preservation proof not satisfied" in r for r in seen["reasons"])


def test_translate_intblock_accepted_when_pic_bindings_exist(monkeypatch):
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_classify_preservation", lambda *a, **k: _mk_decision("A"))
    monkeypatch.setattr(translate_mod, "_try_lrsc_cas", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_try_lrsc_rmw", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_iter_canonical_pure_c_strategies", lambda: [])
    monkeypatch.setattr(translate_mod, "_collect_generic_pure_c_proof_failures", lambda **k: [])

    frag = SimpleNamespace(outputs=[], inputs=[], symbols=[SimpleNamespace(cName="g0")])
    bind = SimpleNamespace(reg="a0", sym_index=0)
    monkeypatch.setattr(translate_mod, "_pic_bindings_for_intblock", lambda *a, **k: [bind])
    monkeypatch.setattr(translate_mod, "_ALLOW_GENERIC_INTBLOCK_PURE_C", False)
    monkeypatch.setattr(translate_mod, "try_integer_block",
                        lambda *a, **k: DummyOut(body="BODY", notes=["ib"]))
    monkeypatch.setattr(translate_mod, "_decision_notes", lambda d: [f"decision={d.level}"])

    out = translate_mod.translate(frag, _mk_lift(), _mk_summary())
    assert out.kind == "pure_c"
    assert out.replacement == "BODY"
    assert any("PIC-backed integer block accepted" in n for n in out.notes)
    assert any("PIC binding injected into intblock" in n for n in out.notes)


def test_translate_intblock_policy_reject_routes_to_x86(monkeypatch):
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_classify_preservation", lambda *a, **k: _mk_decision("A"))
    monkeypatch.setattr(translate_mod, "_try_lrsc_cas", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_try_lrsc_rmw", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_iter_canonical_pure_c_strategies", lambda: [])
    monkeypatch.setattr(translate_mod, "_collect_generic_pure_c_proof_failures", lambda **k: [])
    monkeypatch.setattr(translate_mod, "_pic_bindings_for_intblock", lambda *a, **k: [])
    monkeypatch.setattr(translate_mod, "_ALLOW_GENERIC_INTBLOCK_PURE_C", False)
    monkeypatch.setattr(translate_mod, "try_integer_block",
                        lambda *a, **k: DummyOut(body="BODY", notes=["ib"]))

    seen = {}
    def fake_close(**kwargs):
        seen.update(kwargs)
        return DummyOut(kind="needs_route", replacement="", notes=["x86-route"])

    monkeypatch.setattr(translate_mod, "_close_to_x86_inline_asm_or_route", fake_close)
    out = translate_mod.translate(_mk_frag(), _mk_lift(), _mk_summary())

    assert out.kind == "needs_route"
    assert seen["route"] == "needs_semantic_x86_lowering"
    assert any("integer-block pure_c lowering is disabled by policy" in r for r in seen["reasons"])