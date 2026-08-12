"""Regression guards for the stable Phase-6A memory contract."""

from dataclasses import replace

from riscv2x86_py.pcode_ir import IRSummary
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.schema import AsmFragment
from riscv2x86_py.source_model import (
    _build_memory_model,
    build_source_semantic_model,
)


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


def test_source_model_collects_evidence_from_completeness_contract() -> None:
    """The Phase-6A builder must not pass non-contract arguments to evidence."""
    summary = IRSummary(
        is_single_block=True,
        has_branch=False,
        has_call_or_return=False,
        has_memory_barrier=False,
        has_atomic=False,
        reads_regs=set(),
        writes_regs=set(),
        reads_mem=False,
        writes_mem=False,
        has_return=False,
        has_tail_call=False,
        has_indirect_control_flow=False,
        has_timing_source=False,
        has_cache_operation=False,
        has_speculation_control=False,
    )

    model = build_source_semantic_model(
        fragment=AsmFragment(),
        blocks=(),
        cfg=CFGResult(ok=True),
        summary=summary,
        xlen=64,
        runtime_facts=None,
    )

    assert model.completeness.runtime_facts_available is False
    facts = model.phase6b_candidate_facts
    assert facts.asm_goto_condition_kind is None
    assert facts.asm_goto_condition_operand_index is None

    try:
        replace(facts, asm_goto_condition_kind="zero")
    except ValueError:
        pass
    else:  # pragma: no cover - explicit fail-closed contract guard
        raise AssertionError("partial asm-goto condition facts must be rejected")
