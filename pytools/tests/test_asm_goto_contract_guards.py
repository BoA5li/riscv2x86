"""Narrow asm-goto family guards: no Phase-4 text inference or CFG collapse."""
from riscv2x86_py.assemble import _asm_goto_condition_fact
from riscv2x86_py.schema import AsmFragment


def test_phase4_transports_frontend_condition_fact_only() -> None:
    fragment = AsmFragment(rawAsmText="beqz %0, %l0")
    # The spelling alone is no longer sufficient at Phase 4.
    assert _asm_goto_condition_fact(fragment) == (None, None)
    fragment.asmGotoConditionKind = "zero"
    fragment.asmGotoConditionOperandIndex = 0
    assert _asm_goto_condition_fact(fragment) == ("zero", 0)


def test_frontend_condition_fact_rejects_unknown_branch_family() -> None:
    fragment = AsmFragment()
    fragment.asmGotoConditionKind = "ltu"
    fragment.asmGotoConditionOperandIndex = 0
    assert _asm_goto_condition_fact(fragment) == (None, None)
