"""Regression guards for the stable Phase-6A memory contract."""

from riscv2x86_py.pcode_ir import IRSummary
from riscv2x86_py.source_model import _build_memory_model


def test_memory_model_ignores_legacy_atomic_mnemonics() -> None:
    """Mnemonic display data must not leak into the structured source model."""
    summary = IRSummary(
        is_single_block=True,
        has_branch=False,
        has_call_or_return=False,
        has_memory_barrier=False,
        has_atomic=True,
        reads_regs=set(),
        writes_regs=set(),
        reads_mem=True,
        writes_mem=True,
        atomic_orderings={"seq_cst"},
        atomic_mnemonics={"amoadd.d"},
    )

    memory = _build_memory_model(summary)

    assert memory.has_atomic is True
    assert memory.atomic_orderings == frozenset({"seq_cst"})
    assert not hasattr(memory, "atomic_mnemonics")
