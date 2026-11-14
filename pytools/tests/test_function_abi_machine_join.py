"""Conditional joins reject inconsistent facts, not a machine producer fixture."""
from dataclasses import replace
import pytest
from riscv2x86_py.function_abi_machine_join import *
from riscv2x86_py.function_abi_sidecar import FunctionAbiDeclarationFacts,FunctionAbiValue
from riscv2x86_py.whole_function import *
from riscv2x86_py.function_frame_analysis import analyze_function_frame,FunctionBlockTransfer


def _cfg():return SourceFunctionControlFlowModel('e',(FunctionCfgNode('e','c',None,True),),(),
    (FunctionExitBinding('x','e',FunctionExitKind.NORMAL_RETURN,True),),True)
def _decl():return FunctionAbiDeclarationFacts('f','rv64-lp64',(),(),False,'direct','none',False,'none',True,(),'plugin')
def _frame():return analyze_function_frame(cfg=_cfg(),transfers=(FunctionBlockTransfer('e',0),),required_call_alignment=16)
def _machine():return FunctionMachineAbiFacts('f','rv64-lp64','direct','none',False,False,True,True,16,True,(),(),0)
def join(declaration=None,machine=None,cfg=None,frame=None):
    return join_function_abi_machine(declaration=declaration or _decl(),machine=machine or _machine(),cfg=cfg or _cfg(),frame=frame or _frame())


def test_exact_join_constructs_complete_abi_facts():assert join().complete

def test_profile_mismatch_fails_closed():
    assert 'whole-function.abi-profile-mismatch' in join(machine=replace(_machine(),source_abi_profile='rv64-lp64d')).missing_fact_codes


@pytest.mark.parametrize('change', ['no-summary','bad-summary','unaligned','unrestored','ra','missing-facts'])
def test_complete_flags_cannot_hide_inconsistent_frame(change):
    frame=_frame();stack=frame.stack
    if change=='no-summary':stack=replace(stack,exit_summaries=())
    elif change=='bad-summary':stack=replace(stack,exit_summaries=(replace(stack.exit_summaries[0],final_sp_offset_bytes=8),))
    elif change=='unaligned':stack=replace(stack,all_call_sites_aligned=False)
    elif change=='unrestored':stack=replace(stack,all_normal_exits_restore_entry_sp=False)
    elif change=='ra':frame=replace(frame,ra_continuation_complete=False)
    else:frame=replace(frame,missing_fact_codes=('fixture missing proof',))
    assert not join(frame=replace(frame,stack=stack)).complete


@pytest.mark.parametrize('field,value', [('may_trap',None),('may_unwind',None),('direct_calls_complete',False),
    ('callee_saved_preserved',False),('stack_alignment_bytes',8),('pic_plt_mode',None)])
def test_machine_completeness_does_not_replace_required_facts(field,value):
    assert not join(machine=replace(_machine(),**{field:value})).complete


def test_argument_carrier_and_declared_type_must_match_profile():
    argument=FunctionAbiValue('u64',64,'unsigned','gpr','a0',None,True)
    declaration=replace(_decl(),entry_arguments=(argument,))
    machine=replace(_machine(),entry_arguments=(argument,))
    assert join(declaration=declaration,machine=machine).complete
    assert not join(declaration=declaration).complete
    for broken in [replace(argument,register='a1'),replace(argument,width_bits=32),replace(argument,signedness='signed'),replace(argument,complete=False)]:
        assert not join(declaration=replace(declaration,entry_arguments=(broken,)),machine=machine).complete


def test_amd64_scalar_slots_and_stack_argument_are_distinct_from_riscv():
    parameters=tuple(FunctionAbiValue('u64',64,'unsigned','gpr',reg,None,True) for reg in ('rdi','rsi','rdx','rcx','r8','r9'))
    parameters+=(FunctionAbiValue('ptr',64,'none','stack',None,8,True),)
    declaration=replace(_decl(),source_abi_profile='sysv-amd64',entry_arguments=parameters)
    machine=replace(_machine(),source_abi_profile='sysv-amd64',entry_arguments=parameters,entry_sp_residue_bytes=8)
    frame=analyze_function_frame(cfg=_cfg(),transfers=(FunctionBlockTransfer('e',0),),required_call_alignment=16,entry_sp_residue_bytes=8)
    assert join(declaration=declaration,machine=machine,frame=frame).complete
    assert not join(declaration=declaration,machine=machine,frame=_frame()).complete
    assert not join(declaration=replace(declaration,entry_arguments=parameters[:-1]+(replace(parameters[-1],stack_offset_bytes=0),)),machine=machine,frame=frame).complete


def test_enabled_unwinding_does_not_mean_this_function_actually_unwinds():
    assert join(declaration=replace(_decl(),unwind_enabled=True)).complete
    assert not join(machine=replace(_machine(),may_unwind=True)).complete


def test_unreachable_exit_or_missing_terminal_inventory_is_rejected():
    graph=replace(_cfg(),nodes=_cfg().nodes+(FunctionCfgNode('unreachable','c',None,True),),
        exits=_cfg().exits+(FunctionExitBinding('bad','unreachable',FunctionExitKind.NORMAL_RETURN,True),))
    assert not join(cfg=graph).complete
    graph=replace(_cfg(),nodes=_cfg().nodes+(FunctionCfgNode('other','c',None,True),),edges=(FunctionCfgEdge('e','other','flow',True),))
    assert not join(cfg=graph).complete


def test_actual_unwinding_requires_separate_exceptional_route():
    result=join(declaration=replace(_decl(),unwind_enabled=True),machine=replace(_machine(),may_unwind=True))
    assert not result.complete and 'whole-function.exceptional-abi-route-required' in result.missing_fact_codes


def test_machine_complete_flag_without_value_locations_is_not_evidence():
    assert not join(machine=replace(_machine(),entry_arguments=None)).complete
    assert not join(machine=replace(_machine(),return_values=None)).complete
    assert not join(machine=replace(_machine(),entry_sp_residue_bytes=None)).complete


def test_narrow_argument_requires_extension_and_read_view_evidence():
    value=FunctionAbiValue('u32',32,'unsigned','gpr','a0',None,True)
    assert not join(declaration=replace(_decl(),entry_arguments=(value,)),machine=replace(_machine(),entry_arguments=(value,))).complete
