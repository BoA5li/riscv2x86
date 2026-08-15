from riscv2x86_py.whole_function_facts_adapter import *
def test_adapter_fails_closed_when_phase5_inputs_are_missing():
 f=FrontendFunctionFacts("f",FunctionAstBinding("f","ast",SourceTextRange(0,1),complete=True,source_file="x.c"),("a",),True)
 facts=build_whole_function_translation_facts(frontend=f,mixed_cfg=None,frame=None,declaration=None,abi_join=None,renderer_contract=None)
 assert not facts.complete and "whole-function.mixed-cfg-incomplete" in facts.missing_fact_codes
