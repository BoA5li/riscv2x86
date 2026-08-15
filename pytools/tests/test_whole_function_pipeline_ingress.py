from riscv2x86_py.whole_function_scheduler import schedule_whole_function_replacements
from riscv2x86_py.schema import AsmFragment, Finding
from riscv2x86_py.whole_function import (
    FunctionAstBinding, FunctionCfgEdge, FunctionCfgNode, FunctionExitBinding,
    FunctionExitKind, FunctionFramePathSummary, FunctionTranslationUnit,
    SourceFunctionControlFlowModel, SourceFunctionStackModel, SourceTextRange,
    FunctionAbiFacts, WholeFunctionRendererContract, WholeFunctionTranslationFacts,
)
from riscv2x86_py.whole_function_sidecar import WholeFunctionSidecar


def _facts():
    unit = FunctionTranslationUnit("f", "ast:f", "rv64-lp64", True)
    ast = FunctionAstBinding("f", "ast:f", SourceTextRange(0, 24), complete=True,
                             provenance="frontend.v1", source_file="input.c")
    cfg = SourceFunctionControlFlowModel("entry", (
        FunctionCfgNode("entry", "asm_semantic_region", "frag:0", True),
        FunctionCfgNode("return", "return", None, True),
    ), (FunctionCfgEdge("entry", "return", "return", True),),
    (FunctionExitBinding("exit", "return", FunctionExitKind.NORMAL_RETURN, True),), True)
    stack = SourceFunctionStackModel("whole_function", 0, False, False, True, 16, 16,
        (FunctionFramePathSummary("exit", 0, 16, True),), True, True)
    abi = FunctionAbiFacts("rv64-lp64", True, True, True, True, False, False, True)
    recipe = WholeFunctionRendererContract("wf.static", "1", "f", "int f(void) { return 1; }", complete=True)
    return WholeFunctionTranslationFacts(unit, ast, cfg, stack, abi, (), ("frag:0",), recipe, True)


def test_pipeline_scheduler_emits_function_rewrite_only_after_proof():
    finding = Finding(fragment=AsmFragment(id="frag:0", rawAsmText="ret"), category="NeedsAsmTranslation")
    sidecar = WholeFunctionSidecar("riscv2x86.whole-function-sidecar.v1", (_facts(),), "frontend.v1")
    emitted = schedule_whole_function_replacements([finding], sidecar)
    assert len(emitted) == 1
    assert emitted[0].subjectKind == "Function"
    assert emitted[0].rewriteBeginOffset == 0
    assert emitted[0].approvalArtifact["proofStatus"] == "approved"
    assert finding.category == "AlreadyRule"


def test_scheduler_does_not_suppress_fragments_when_membership_is_incomplete():
    finding = Finding(fragment=AsmFragment(id="frag:0", rawAsmText="ret"), category="NeedsAsmTranslation")
    facts = _facts()
    bad = WholeFunctionTranslationFacts(facts.unit, facts.ast_binding, facts.control_flow,
        facts.stack, facts.abi, facts.callee_saved_effects, ("missing",), facts.renderer_contract, True)
    sidecar = WholeFunctionSidecar("riscv2x86.whole-function-sidecar.v1", (bad,), "frontend.v1")
    assert schedule_whole_function_replacements([finding], sidecar) == ()
    assert finding.category == "NeedsAsmTranslation"
