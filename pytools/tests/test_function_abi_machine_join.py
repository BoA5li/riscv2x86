from riscv2x86_py.function_abi_machine_join import *
from riscv2x86_py.function_abi_sidecar import FunctionAbiDeclarationFacts
from riscv2x86_py.whole_function import *
from riscv2x86_py.function_frame_analysis import FunctionFrameAnalysis
def _cfg():return SourceFunctionControlFlowModel("e",(FunctionCfgNode("e","c",None,True),),( ),(FunctionExitBinding("x","e",FunctionExitKind.NORMAL_RETURN,True),),True)
def _decl():return FunctionAbiDeclarationFacts("f","rv64-lp64",(),(),False,"direct","none",False,"none",True,(),"plugin")
def _frame():return FunctionFrameAnalysis(SourceFunctionStackModel("whole_function",0,False,False,True,None,16,(),True,True),(),False,False,True,True,())
def test_exact_join_constructs_complete_abi_facts():
 m=FunctionMachineAbiFacts("f","rv64-lp64","direct","none",False,False,True,True,16,True); assert join_function_abi_machine(declaration=_decl(),machine=m,cfg=_cfg(),frame=_frame()).complete
def test_profile_mismatch_fails_closed():
 m=FunctionMachineAbiFacts("f","rv64-lp64d","direct","none",False,False,True,True,16,True); assert "whole-function.abi-profile-mismatch" in join_function_abi_machine(declaration=_decl(),machine=m,cfg=_cfg(),frame=_frame()).missing_fact_codes
