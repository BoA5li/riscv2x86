"""Phase-8 negative validation for D-class whole-function ABI lowering.

These are intentionally fact-level tests: a route can only approve a full
function replacement when its Phase-4/5 facts prove every relevant function
exit and ABI effect.  Each adverse case must leave no replacement artifact.
"""
from dataclasses import replace

from riscv2x86_py.function_abi_machine_join import (
    FunctionMachineAbiFacts, join_function_abi_machine,
)
from riscv2x86_py.function_abi_sidecar import FunctionAbiDeclarationFacts
from riscv2x86_py.whole_function import (
    CalleeSavedRegisterEffect, FunctionAbiFacts, FunctionAstBinding,
    FunctionCfgEdge, FunctionCfgNode, FunctionExitBinding, FunctionExitKind,
    FunctionFramePathSummary, FunctionTranslationUnit,
    SourceFunctionControlFlowModel, SourceFunctionStackModel, SourceTextRange,
    WholeFunctionPhase5Evidence, WholeFunctionRendererContract,
    WholeFunctionTranslationFacts, classify_whole_function_route,
    translate_whole_function,
)
from riscv2x86_py.function_frame_analysis import FunctionFrameAnalysis


def _route(*, tail=False):
    return classify_whole_function_route(
        reads_registers=frozenset({"ra"}), writes_registers=frozenset(),
        has_call=False, has_return=True, has_tail_call=tail,
        stack_kind="whole_function", dynamic_adjustment=False,
        stack_complete=True, has_unwind_or_exception_edge=False,
    )


def _facts(*, exits=None, stack=None, effects=(), abi=None):
    exits = exits or (FunctionExitBinding("return:0", "return", FunctionExitKind.NORMAL_RETURN, True),)
    node_ids = (FunctionCfgNode("entry", "asm_semantic_region", "frag:0", True),
                FunctionCfgNode("return", "return", None, True))
    cfg = SourceFunctionControlFlowModel(
        "entry", node_ids,
        (FunctionCfgEdge("entry", "return", "return", True),), exits, True,
    )
    stack = stack or SourceFunctionStackModel(
        "whole_function", 0, False, False, True, 16, 16,
        tuple(FunctionFramePathSummary(x.exit_id, 0, 16, True)
              for x in exits if x.kind is FunctionExitKind.NORMAL_RETURN), True, True,
    )
    abi = abi or FunctionAbiFacts("rv64-lp64", True, True, True, True, False, False, True)
    unit = FunctionTranslationUnit("f", "ast:f", "rv64-lp64", True)
    ast = FunctionAstBinding("f", "ast:f", SourceTextRange(0, 24), complete=True,
                             provenance="frontend.v1", source_file="input.c")
    recipe = WholeFunctionRendererContract("wf.static", "1", "f", "int f(void) { return 1; }", complete=True)
    evidence = WholeFunctionPhase5Evidence("cfg", "frame", "declaration", "join")
    return WholeFunctionTranslationFacts(unit, ast, cfg, stack, abi, effects, ("frag:0",),
                                         recipe, True, (), evidence)


def _rejects(facts, route=None):
    artifact, proof = translate_whole_function(facts=facts, route=route or _route())
    assert artifact is None
    assert proof is not None
    assert not proof.approved
    return proof.reason_codes


def test_phase8_rejects_multiexit_when_one_exit_lacks_stack_restoration_summary():
    exits = (
        FunctionExitBinding("return:0", "return", FunctionExitKind.NORMAL_RETURN, True),
        FunctionExitBinding("return:1", "return", FunctionExitKind.NORMAL_RETURN, True),
    )
    stack = SourceFunctionStackModel("whole_function", 0, False, False, True, 16, 16,
        (FunctionFramePathSummary("return:0", 0, 16, True),), True, True)
    reasons = _rejects(_facts(exits=exits, stack=stack))
    assert "phase6d.whole_function.normal-exit-stack-restoration-unproven" in reasons


def test_phase8_rejects_callee_saved_register_leak():
    leak = CalleeSavedRegisterEffect("s0", ("save",), (), ("modify",), False, True)
    reasons = _rejects(_facts(effects=(leak,)))
    assert "phase6d.whole_function.callee_saved_unproven" in reasons


def test_phase8_rejects_exceptional_and_nonlocal_setjmp_longjmp_exits():
    for kind in (FunctionExitKind.EXCEPTIONAL, FunctionExitKind.NONLOCAL):
        exits = (FunctionExitBinding("return:0", "return", FunctionExitKind.NORMAL_RETURN, True),
                 FunctionExitBinding("nonlocal", "return", kind, True))
        reasons = _rejects(_facts(exits=exits))
        assert "phase6d.whole_function.unwind_or_nonlocal_transfer" in reasons


def test_phase8_rejects_dynamic_frame_and_unproven_call_alignment():
    dynamic = SourceFunctionStackModel("whole_function", 0, True, False, True, 16, 16,
        (FunctionFramePathSummary("return:0", 0, 16, True),), True, True)
    assert "phase6d.whole_function.frame_unbalanced" in _rejects(_facts(stack=dynamic))
    unaligned = replace(_facts().stack, all_call_sites_aligned=False)
    assert "phase6d.whole_function.call_alignment_unproven" in _rejects(_facts(stack=unaligned))


def test_phase8_rejects_tail_call_route():
    facts = _facts()
    artifact, proof = translate_whole_function(facts=facts, route=_route(tail=True))
    assert artifact is None
    assert proof is not None and not proof.approved
    assert "whole-function.dynamic-frame-or-tail-call" in proof.reason_codes


def test_phase8_abi_join_rejects_pic_and_tls_mismatch():
    declaration = FunctionAbiDeclarationFacts("f", "rv64-lp64", (), (), False,
        "direct", "none", False, "none", True, (), "plugin.v1")
    frame = FunctionFrameAnalysis(_facts().stack, (), False, False, True, True, ())
    machine = FunctionMachineAbiFacts("f", "rv64-lp64", "plt", "local-exec",
        False, False, True, True, 16, True)
    joined = join_function_abi_machine(declaration=declaration, machine=machine,
        cfg=_facts().control_flow, frame=frame)
    assert not joined.complete
    assert "whole-function.pic-plt-mismatch" in joined.missing_fact_codes
    assert "whole-function.tls-mismatch" in joined.missing_fact_codes
