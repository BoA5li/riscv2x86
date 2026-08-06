from types import SimpleNamespace

from .test_phase7_conftest import import_from_env


verify_mod = import_from_env("R2X_VERIFY_MODULE", "riscv2x86_py.verify")


def test_verify_amo_verified(monkeypatch):
    monkeypatch.setattr(verify_mod, "_build_check_c", lambda *a, **k: None)
    frag = SimpleNamespace(rawAsmText="amoadd.w a0, a1, (a2)")
    lift = SimpleNamespace(insns=[SimpleNamespace(asm_mnem="amoadd.w")])
    tr = SimpleNamespace(kind="pure_c", replacement="__atomic_fetch_add(..., __ATOMIC_RELAXED)", notes=[])
    out = verify_mod.verify(frag, lift, None, tr)
    assert out.status == "verified"
    assert "functional RMW equivalence" in out.detail


def test_verify_fence_full_verified(monkeypatch):
    monkeypatch.setattr(verify_mod, "_build_check_c", lambda *a, **k: None)
    frag = SimpleNamespace(rawAsmText="fence rw,rw")
    lift = SimpleNamespace(insns=[SimpleNamespace(asm_mnem="fence")])
    tr = SimpleNamespace(kind="pure_c", replacement="__atomic_thread_fence(__ATOMIC_SEQ_CST)", notes=[])
    out = verify_mod.verify(frag, lift, None, tr)
    assert out.status == "verified"


def test_verify_fence_weak_build_only(monkeypatch):
    monkeypatch.setattr(verify_mod, "_build_check_c", lambda *a, **k: None)
    frag = SimpleNamespace(rawAsmText="fence r,r")
    lift = SimpleNamespace(insns=[SimpleNamespace(asm_mnem="fence")])
    tr = SimpleNamespace(kind="pure_c", replacement="__atomic_thread_fence(__ATOMIC_SEQ_CST)", notes=[])
    out = verify_mod.verify(frag, lift, None, tr)
    assert out.status == "build_only"


def test_verify_cas_verified(monkeypatch):
    monkeypatch.setattr(verify_mod, "_build_check_c", lambda *a, **k: None)
    frag = SimpleNamespace(rawAsmText="lr.w/sc.w")
    lift = SimpleNamespace(insns=[SimpleNamespace(asm_mnem="lr.w")])
    tr = SimpleNamespace(kind="pure_c", replacement="__atomic_compare_exchange_n(...)",
                         notes=["LR/SC width=32 weak=true"])
    out = verify_mod.verify(frag, lift, None, tr)
    assert out.status == "verified"
    assert "compare_exchange equivalence" in out.detail


def test_verify_build_failure_is_failed(monkeypatch):
    monkeypatch.setattr(verify_mod, "_build_check_c", lambda *a, **k: "clang error")
    frag = SimpleNamespace(rawAsmText="amoadd.w a0, a1, (a2)")
    lift = SimpleNamespace(insns=[SimpleNamespace(asm_mnem="amoadd.w")])
    tr = SimpleNamespace(kind="pure_c", replacement="BAD", notes=[])
    out = verify_mod.verify(frag, lift, None, tr)
    assert out.status == "failed"
    assert "build check failed" in out.detail