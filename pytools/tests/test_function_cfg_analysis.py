from riscv2x86_py.function_cfg_analysis import *
from riscv2x86_py.whole_function import *

def test_joins_complete_c_and_asm_cfg_with_normal_exit():
    front=FrontendCfgFacts("c.entry",(FunctionCfgNode("c.entry","c",None,True),FunctionCfgNode("c.ret","return",None,True)),(FunctionCfgEdge("c.entry","c.ret","fallthrough",True),),(FunctionExitBinding("exit","c.ret",FunctionExitKind.NORMAL_RETURN,True),),True)
    asm=AsmRegionCfgFacts("f0","a.entry",("a.exit",),(FunctionCfgNode("a.entry","asm","f0",True),FunctionCfgNode("a.exit","asm_exit","f0",True)),(FunctionCfgEdge("a.entry","a.exit","fallthrough",True),),("c.ret",),True)
    model=build_mixed_function_cfg(frontend=front,asm_regions=(asm,),expected_fragment_ids=("f0",))
    assert model.complete and len(model.nodes)==4

def test_missing_asm_cfg_is_never_assumed_to_fallthrough():
    front=FrontendCfgFacts("e",(FunctionCfgNode("e","c",None,True),),( ),(FunctionExitBinding("x","e",FunctionExitKind.NORMAL_RETURN,True),),True)
    model=build_mixed_function_cfg(frontend=front,asm_regions=(),expected_fragment_ids=("f0",))
    assert not model.complete and "whole-function.asm-region-membership-mismatch" in model.missing_fact_codes
