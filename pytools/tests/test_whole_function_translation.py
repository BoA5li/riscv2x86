from riscv2x86_py.whole_function import (
    CalleeSavedRegisterEffect, FunctionAbiFacts, FunctionAstBinding,
    FunctionCfgEdge, FunctionCfgNode, FunctionExitBinding, FunctionExitKind,
    FunctionFramePathSummary, FunctionTranslationUnit, SourceFunctionControlFlowModel,
    SourceFunctionStackModel, SourceTextRange, WholeFunctionRendererContract,
    WholeFunctionTranslationFacts, classify_whole_function_route,
    translate_whole_function,
)
from riscv2x86_py.whole_function_writeback import apply_function_replacements


def _facts(source_text: str = "int f(int x) { return x; }") -> WholeFunctionTranslationFacts:
    unit = FunctionTranslationUnit("f", "ast:f", "rv64-lp64", True)
    ast = FunctionAstBinding("f", "ast:f", SourceTextRange(0, len(source_text)), complete=True, provenance="frontend-sidecar.v1")
    cfg = SourceFunctionControlFlowModel(
        "entry",
        (FunctionCfgNode("entry", "asm_semantic_region", "frag:0", True), FunctionCfgNode("return", "return", None, True)),
        (FunctionCfgEdge("entry", "return", "return", True),),
        (FunctionExitBinding("exit:0", "return", FunctionExitKind.NORMAL_RETURN, True),),
        True,
    )
    stack = SourceFunctionStackModel(
        "whole_function", 0, False, False, True, 16, 16,
        (FunctionFramePathSummary("exit:0", 0, 16, True),), True, True,
    )
    abi = FunctionAbiFacts("rv64-lp64", True, True, True, True, False, False, True)
    recipe = WholeFunctionRendererContract(
        "whole-function.structured-c.static.v1", "1", "f",
        "int f(int x) { return x + 1; }", complete=True,
    )
    return WholeFunctionTranslationFacts(unit, ast, cfg, stack, abi, (), ("frag:0",), recipe, True)


def _route():
    return classify_whole_function_route(
        reads_registers=frozenset({"ra"}), writes_registers=frozenset(),
        has_call=False, has_return=True, has_tail_call=False,
        stack_kind="whole_function", dynamic_adjustment=False,
        stack_complete=True, has_unwind_or_exception_edge=False,
    )


def test_static_whole_function_recipe_is_proved_rendered_and_written_back():
    source = "int f(int x) { return x; }"
    artifact, proof = translate_whole_function(facts=_facts(source), route=_route())
    assert proof is not None and proof.approved
    assert artifact is not None and artifact.proof_identity
    writeback = apply_function_replacements(source_text=source, artifacts=(artifact,))
    assert writeback.approved
    assert writeback.source_text == "int f(int x) { return x + 1; }"


def test_exceptional_exit_and_host_stack_recipe_fail_closed():
    facts = _facts()
    bad_cfg = SourceFunctionControlFlowModel(
        "entry", facts.control_flow.nodes, facts.control_flow.edges,
        facts.control_flow.exits + (FunctionExitBinding("eh", "return", FunctionExitKind.EXCEPTIONAL, True),), True,
    )
    bad = WholeFunctionTranslationFacts(
        facts.unit, facts.ast_binding, bad_cfg, facts.stack, facts.abi,
        facts.callee_saved_effects, facts.fragment_ids, facts.renderer_contract, True,
    )
    artifact, proof = translate_whole_function(facts=bad, route=_route())
    assert artifact is None
    assert proof is None or not proof.approved


def test_writeback_rejects_overlapping_function_ranges():
    source = "abcdef"
    facts = _facts("abcdef")
    artifact, proof = translate_whole_function(facts=facts, route=_route())
    assert artifact is not None and proof is not None and proof.approved
    duplicate = type(artifact)("g", "ast:g", SourceTextRange(2, 5), "X", artifact.proof_identity, artifact.renderer_contract_id, artifact.renderer_contract_version, (), ())
    result = apply_function_replacements(source_text=source, artifacts=(artifact, duplicate))
    assert not result.approved
    assert result.reason_codes == ("whole-function.writeback-overlap-or-range-invalid",)
