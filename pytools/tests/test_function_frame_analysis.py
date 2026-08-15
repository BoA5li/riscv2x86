from riscv2x86_py.function_frame_analysis import *
from riscv2x86_py.whole_function import *
def _cfg(): return SourceFunctionControlFlowModel("e",(FunctionCfgNode("e","c",None,True),FunctionCfgNode("x","return",None,True)),(FunctionCfgEdge("e","x","fallthrough",True),),(FunctionExitBinding("x","x",FunctionExitKind.NORMAL_RETURN,True),),True)
def test_balanced_frame_and_restored_saved_register_are_proved():
 a=analyze_function_frame(cfg=_cfg(),transfers=(FunctionBlockTransfer("e",-16,callee_saved_updates=(("s0",SavedState.SAVED),)),FunctionBlockTransfer("x",16,callee_saved_updates=(("s0",SavedState.RESTORED),),reads_ra=True,writes_ra=True)),required_call_alignment=16); assert a.complete and a.stack.all_normal_exits_restore_entry_sp
def test_unrestored_callee_saved_fails_closed():
 a=analyze_function_frame(cfg=_cfg(),transfers=(FunctionBlockTransfer("e",0,callee_saved_updates=(("s0",SavedState.MODIFIED),)),FunctionBlockTransfer("x",0)),required_call_alignment=16); assert not a.complete and "whole-function.callee-saved-restore-unproven" in a.missing_fact_codes
