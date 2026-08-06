from types import SimpleNamespace
import pytest

from riscv2x86_py.schema import AsmFragment
from riscv2x86_py.assemble import assemble
import riscv2x86_py.lift as lift_mod
from riscv2x86_py.pcode_ir import from_lifted


def _lift_from_asm(asm: str):
    frag = AsmFragment(rawAsmText=asm, outputs=[], inputs=[])
    a = assemble(frag)
    assert a.ok, a.error
    l = lift_mod.lift(a.machine_code, xlen=64, relocations=getattr(a, "relocations", None))
    assert l.ok, l.error
    return frag, a, l


def test_phase5_smoke_add_still_works():
    _, _, l = _lift_from_asm("add a0, a1, a2")
    blocks, summary = from_lifted(l.insns)

    assert len(blocks) == 1
    assert summary.has_branch is False
    assert summary.reads_regs
    assert summary.writes_regs


def test_phase5_should_split_basic_blocks_when_branch_exists():
    _, _, l = _lift_from_asm(
        "beq a0, a1, 1f\n"
        "addi a2, a2, 1\n"
        "1:\n"
        "addi a3, a3, 2\n"
    )
    blocks, summary = from_lifted(l.insns)

    assert summary.has_branch is True
    assert len(blocks) >= 2


def test_phase5_should_build_successors_for_branch_cfg():
    _, _, l = _lift_from_asm(
        "beq a0, a1, 1f\n"
        "nop\n"
        "1:\n"
        "nop\n"
    )
    blocks, summary = from_lifted(l.insns)

    assert summary.has_branch is True
    assert any(b.successors for b in blocks), "branch 存在时，至少应有一条 CFG 边"


def test_phase5_lift_should_fail_on_empty_pcode(monkeypatch):
    class FakeTx:
        def __init__(self):
            self.ops = []

    class FakeCtx:
        def __init__(self, *args, **kwargs):
            pass

        def translate(self, *args, **kwargs):
            return FakeTx()

        def disassemble(self, *args, **kwargs):
            raise AssertionError("tx.ops 为空时，不应继续 disassemble")

    monkeypatch.setattr(lift_mod.pypcode, "Context", FakeCtx)

    r = lift_mod.lift(b"\x13\x00\x00\x00", xlen=64)
    assert not r.ok
    assert "no p-code ops" in r.error.lower()