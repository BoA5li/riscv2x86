"""Regression tests for ordinary-fragment routing and attempt diagnostics."""
from dataclasses import replace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import Block, CanonicalInsn
from riscv2x86_py.pipeline import _record_non_candidate_attempt
from riscv2x86_py.privileged_execution_sidecar import (
    default_user_process_execution_facts,
)
from riscv2x86_py.privileged_state_analysis import analyze_privileged_state
from riscv2x86_py.privileged_state_adapter import build_privileged_state_adapter
from riscv2x86_py.schema import (
    AsmFragment, Finding, PublicationOutcome, TranslationOutcome,
    TranslationOutput,
)
from riscv2x86_py.validation_status import ValidationStatus
from tests.test_phase6_rv64_add_contract import _build_rv64_add_model


def test_absent_privileged_observation_does_not_suppress_ordinary_add() -> None:
    model = _build_rv64_add_model()
    ordinary = Block(
        0x1000, instructions=[CanonicalInsn(addr=0x1000, size=4)],
    )
    absence = analyze_privileged_state(
        fragment_id="ordinary:add", blocks=(ordinary,), cfg=CFGResult(ok=True),
        execution_facts=default_user_process_execution_facts("ordinary:add"),
    )
    assert absence.present is False and absence.complete is True

    adapter = build_privileged_state_adapter(
        fragment_id="ordinary:add", phase5_state=absence,
        observability=None, read_only_counter_candidate=None,
        shell=model.shell, memory=model.memory, control_flow=model.control_flow,
        abi_effects=model.abi_effects, whole_function_route=model.whole_function_route,
    )
    assert adapter is not None and adapter.state is absence
    plans = generate_candidate_plans(replace(model, privileged_state=adapter))
    assert any(
        plan.metadata.get("renderer_semantic_contract_id") ==
        "x86.gnu-att.gpr.out-gpr-gpr-binary.v1"
        for plan in plans
    )


def test_non_candidate_attempt_keeps_phase6_route_and_child_reason_codes() -> None:
    finding = Finding(
        fragment=AsmFragment(id="case.c:9:5", rawAsmText="add %0, %1, %2"),
        ruleName="phase6.unsupported",
    )
    result = TranslationOutput(
        kind="unsupported", replacement="", route="phase6e_unsupported",
        preservationRoute="phase6e_unsupported",
        reasonCodes=["phase6e.no_approved_plan"],
        metadata={"attempts": ({
            "planId": "x86.register-only-inline-asm.out-gpr-gpr",
            "stage": "phase6d",
            "reasonCodes": ("phase6d.shell-semantics-unproven",),
        },)},
    )

    _record_non_candidate_attempt(
        finding, result, outcome=TranslationOutcome.UNSUPPORTED,
        validation_outcome=ValidationStatus.UNSUPPORTED.value,
        publication_outcome=PublicationOutcome.NOT_REQUESTED,
    )

    artifact = finding.translationAttemptArtifact
    assert artifact["candidateRoute"] == "phase6e_unsupported"
    assert artifact["reasonCodes"] == [
        "phase6d.shell-semantics-unproven",
        "phase6e.no_approved_plan",
    ]
