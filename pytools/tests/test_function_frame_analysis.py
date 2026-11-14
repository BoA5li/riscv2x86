"""Frame facts are explicit fixtures, not claimed machine-byte production."""
from dataclasses import replace
import os
import subprocess
import sys
import pytest
from riscv2x86_py.function_frame_analysis import *
from riscv2x86_py.whole_function import *


def cfg(edges=(('e','x'),),exits=('x',)):
    ids=sorted({n for edge in edges for n in edge}|set(exits)|{'e'})
    return SourceFunctionControlFlowModel('e',tuple(FunctionCfgNode(n,'c',None,True) for n in ids),
        tuple(FunctionCfgEdge(a,b,'flow',True) for a,b in edges),
        tuple(FunctionExitBinding(n,n,FunctionExitKind.NORMAL_RETURN,True) for n in exits),True)


def test_balanced_frame_and_restored_saved_register_are_proved():
    result=analyze_function_frame(cfg=cfg(),transfers=(
        FunctionBlockTransfer('e',-16,callee_saved_updates=(('s0',SavedState.SAVED),),reads_ra=True,ra_updates=(SavedState.SAVED,)),
        FunctionBlockTransfer('x',16,callee_saved_updates=(('s0',SavedState.RESTORED),),
                              writes_ra=True,ra_updates=(SavedState.RESTORED,))),required_call_alignment=16)
    assert result.complete and result.stack.all_normal_exits_restore_entry_sp
    assert result.stack.exit_summaries[0].final_sp_offset_bytes==0


def test_unrestored_callee_saved_fails_closed():
    result=analyze_function_frame(cfg=cfg(),transfers=(FunctionBlockTransfer('e',0,
        callee_saved_updates=(('s0',SavedState.MODIFIED),)),FunctionBlockTransfer('x',0)),required_call_alignment=16)
    assert not result.complete and 'whole-function.callee-saved-restore-unproven' in result.missing_fact_codes


@pytest.mark.parametrize('right_restore',[0,16])
def test_branch_join_uses_predecessor_exit_values(right_restore):
    graph=cfg((('e','a'),('e','b'),('a','x'),('b','x')))
    result=analyze_function_frame(cfg=graph,transfers=(FunctionBlockTransfer('e',-16),
        FunctionBlockTransfer('a',16),FunctionBlockTransfer('b',right_restore),FunctionBlockTransfer('x',0)),required_call_alignment=16)
    assert result.complete is (right_restore==16)


def test_nonzero_stack_loop_widens_and_terminates():
    program='''from riscv2x86_py.function_frame_analysis import *
from riscv2x86_py.whole_function import *
nodes=tuple(FunctionCfgNode(n,'c',None,True) for n in ('e','loop','x'))
edges=tuple(FunctionCfgEdge(a,b,'flow',True) for a,b in [('e','loop'),('loop','loop'),('loop','x')])
graph=SourceFunctionControlFlowModel('e',nodes,edges,(FunctionExitBinding('x','x',FunctionExitKind.NORMAL_RETURN,True),),True)
r=analyze_function_frame(cfg=graph,transfers=(FunctionBlockTransfer('e',0),FunctionBlockTransfer('loop',-16),FunctionBlockTransfer('x',0)),required_call_alignment=16)
assert not r.complete and 'whole-function.stack-affine-nonconvergent' in r.missing_fact_codes
'''
    subprocess.run([sys.executable,'-c',program],check=True,timeout=5,capture_output=True,env=os.environ.copy())


@pytest.mark.parametrize('updates',[
    (SavedState.RESTORED,),
    (SavedState.MODIFIED,SavedState.SAVED,SavedState.RESTORED),
    (SavedState.SAVED,SavedState.UNKNOWN,SavedState.RESTORED)])
def test_restore_without_original_saved_value_never_proves_preservation(updates):
    result=analyze_function_frame(cfg=cfg(),transfers=(FunctionBlockTransfer('e',0,
        callee_saved_updates=tuple(('s0',op) for op in updates)),FunctionBlockTransfer('x',0)),required_call_alignment=16)
    assert not result.complete


def test_save_on_only_one_branch_cannot_justify_shared_restore():
    graph=cfg((('e','a'),('e','b'),('a','x'),('b','x')))
    result=analyze_function_frame(cfg=graph,transfers=(FunctionBlockTransfer('e',0),
        FunctionBlockTransfer('a',0,callee_saved_updates=(('s0',SavedState.SAVED),)),
        FunctionBlockTransfer('b',0,callee_saved_updates=(('s0',SavedState.MODIFIED),)),
        FunctionBlockTransfer('x',0,callee_saved_updates=(('s0',SavedState.RESTORED),))),required_call_alignment=16)
    assert not result.complete


def test_reading_and_writing_ra_does_not_prove_restoration():
    result=analyze_function_frame(cfg=cfg(),transfers=(FunctionBlockTransfer('e',0,reads_ra=True,writes_ra=True),
        FunctionBlockTransfer('x',0)),required_call_alignment=16)
    assert not result.complete and not result.ra_continuation_complete


@pytest.mark.parametrize('offsets,expected',[((),False),((0,),False),((8,),True)])
def test_call_alignment_uses_actual_incoming_sp_and_call_offset(offsets,expected):
    result=analyze_function_frame(cfg=cfg((('e','call'),('call','x'))),transfers=(FunctionBlockTransfer('e',-8),
        FunctionBlockTransfer('call',0,contains_call=True,call_alignment_bytes=16,call_sp_offsets=offsets),
        FunctionBlockTransfer('x',8)),required_call_alignment=16)
    assert result.complete is expected


def test_amd64_entry_residue_is_not_assumed_zero():
    result=analyze_function_frame(cfg=cfg(),transfers=(FunctionBlockTransfer('e',-8),
        FunctionBlockTransfer('x',8,contains_call=True,call_alignment_bytes=16,call_sp_offsets=(0,))),
        required_call_alignment=16,entry_sp_residue_bytes=8)
    assert result.complete


def test_unknown_fp_and_unreachable_exit_do_not_pass():
    result=analyze_function_frame(cfg=cfg(exits=('x','unreachable')),transfers=(FunctionBlockTransfer('e',0,fp_delta_bytes=None),
        FunctionBlockTransfer('x',0),FunctionBlockTransfer('unreachable',0)),required_call_alignment=16)
    assert not result.complete


def test_duplicate_transfer_cannot_silently_replace_an_effect():
    with pytest.raises(ValueError,match='uniquely'):
        analyze_function_frame(cfg=cfg(),transfers=(FunctionBlockTransfer('e',0),FunctionBlockTransfer('e',-16)),required_call_alignment=16)


def test_incomplete_exit_and_unrecorded_terminal_are_not_trusted():
    graph=replace(cfg(),exits=(replace(cfg().exits[0],complete=False),))
    assert not analyze_function_frame(cfg=graph,transfers=(FunctionBlockTransfer('e',0),FunctionBlockTransfer('x',0)),required_call_alignment=16).complete
    graph=cfg((('e','x'),('e','missing-return')))
    assert not analyze_function_frame(cfg=graph,transfers=tuple(FunctionBlockTransfer(n.node_id,0) for n in graph.nodes),required_call_alignment=16).complete
