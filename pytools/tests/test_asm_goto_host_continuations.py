"""Regression tests for frontend-owned GNU asm-goto continuation facts."""
from riscv2x86_py.schema import AsmFragment, AsmGotoEdge, AsmOperand, _frag_from
from riscv2x86_py.shell_model import SourceShellModel


def _fragment() -> AsmFragment:
    fragment_id = "asm-fragment-17"
    fallthrough = f"asm-goto:{fragment_id}:fallthrough"
    taken = f"asm-goto:{fragment_id}:label:taken"
    return AsmFragment(
        id=fragment_id,
        rawAsmText="beqz %0, %l0",
        inputs=[AsmOperand(constraint="r", exprText="value")],
        gotoLabels=["taken"],
        gotoEdges=[AsmGotoEdge("%l0", "taken", 0, taken)],
        asmGotoFallthroughContinuationId=fallthrough,
        asmGotoSuccessorContinuationIds=[fallthrough, taken],
        asmGotoControlFlowComplete=True,
    )


def test_shell_preserves_host_continuations_without_lifted_addresses() -> None:
    shell = SourceShellModel.from_fragment(_fragment())
    assert shell.asm_goto_control_flow_complete
    assert shell.asm_goto_fallthrough_continuation_id.endswith(":fallthrough")
    assert shell.goto_edges[0][3].endswith(":label:taken")
    assert set(shell.asm_goto_successor_continuation_ids) == {
        shell.asm_goto_fallthrough_continuation_id,
        shell.goto_edges[0][3],
    }


def test_schema_round_trip_keeps_authoritative_continuation_ids() -> None:
    fragment = _fragment()
    restored = _frag_from({
        "id": fragment.id,
        "rawAsmText": fragment.rawAsmText,
        "inputs": [{"constraint": "r", "exprText": "value"}],
        "gotoLabels": ["taken"],
        "gotoEdges": [{
            "asmTarget": "%l0",
            "cLabel": "taken",
            "exitCode": 0,
            "targetContinuationId": fragment.gotoEdges[0].targetContinuationId,
        }],
        "asmGotoFallthroughContinuationId": fragment.asmGotoFallthroughContinuationId,
        "asmGotoSuccessorContinuationIds": fragment.asmGotoSuccessorContinuationIds,
        "asmGotoControlFlowComplete": True,
    })
    assert SourceShellModel.from_fragment(restored) == SourceShellModel.from_fragment(fragment)
