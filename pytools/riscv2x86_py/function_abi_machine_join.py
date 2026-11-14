"""Conditional ABI join over compiler declarations and checked machine facts.

No boolean completeness marker replaces consistency checks. Machine/CFG/frame
provenance must still be bound and replayed by the evidence producer.
"""
from __future__ import annotations
from dataclasses import dataclass,replace
from .function_abi_sidecar import FunctionAbiDeclarationFacts,FunctionAbiValue
from .function_frame_analysis import FunctionFrameAnalysis
from .whole_function import SourceFunctionControlFlowModel,FunctionAbiFacts,FunctionExitKind

@dataclass(frozen=True)
class FunctionMachineAbiFacts:
    function_id:str; source_abi_profile:str|None; pic_plt_mode:str|None; tls_model:str|None
    may_unwind:bool|None; may_trap:bool|None; direct_calls_complete:bool
    callee_saved_preserved:bool; stack_alignment_bytes:int|None; complete:bool
    entry_arguments:tuple[FunctionAbiValue,...]|None=None
    return_values:tuple[FunctionAbiValue,...]|None=None
    entry_sp_residue_bytes:int|None=None

@dataclass(frozen=True)
class FunctionAbiMachineJoin:
    abi:FunctionAbiFacts; complete:bool; missing_fact_codes:tuple[str,...]


def _slots(declaration):
    profile=declaration.source_abi_profile
    if profile=='sysv-amd64':registers=('rdi','rsi','rdx','rcx','r8','r9');base=8;result='rax'
    elif profile in ('rv64-lp64','rv64-lp64d'):registers=tuple('a'+str(i) for i in range(8));base=0;result='a0'
    else:return False
    if declaration.variadic_or_aggregate_abi is not False or len(declaration.return_values)>1:return False
    for returning,values in ((False,declaration.entry_arguments),(True,declaration.return_values)):
        for i,value in enumerate(values):
            if not isinstance(value.type_id,str):return False
            expected_width=64 if value.type_id=='ptr' else int(value.type_id[1:]) if value.type_id in (
                'i8','u8','i16','u16','i32','u32','i64','u64') else None
            signed='none' if value.type_id=='ptr' else 'signed' if value.type_id.startswith('i') else 'unsigned'
            if (value.complete is not True or type(value.width_bits) is not int or value.width_bits!=expected_width
                    or value.signedness!=signed):return False
            # Narrow carriers require an additional extension/read-view proof.
            # Do not infer it from a declaration or from the ABI profile name.
            if expected_width!=64:return False
            if returning or i<len(registers):
                if value.location_kind!='gpr' or value.register!=(result if returning else registers[i]) or value.stack_offset_bytes is not None:return False
            elif (value.location_kind!='stack' or value.register is not None or type(value.stack_offset_bytes) is not int
                    or value.stack_offset_bytes!=base+8*(i-len(registers))):return False
    return True


def join_function_abi_machine(*,declaration:FunctionAbiDeclarationFacts|None,machine:FunctionMachineAbiFacts|None,
                             cfg:SourceFunctionControlFlowModel|None,frame:FunctionFrameAnalysis|None)->FunctionAbiMachineJoin:
    reasons=set()
    if declaration is None:reasons.add('whole-function.abi-declaration-missing')
    if machine is None:reasons.add('whole-function.machine-abi-facts-missing')
    if cfg is None or cfg.complete is not True or cfg.missing_fact_codes:reasons.add('whole-function.cfg-incomplete')
    if frame is None or frame.complete is not True:reasons.add('whole-function.frame-analysis-incomplete')
    if cfg is not None:
        nodes={n.node_id:n for n in cfg.nodes};successors={n:[] for n in nodes}
        if (cfg.entry_node_id not in nodes or any(n.complete is not True for n in nodes.values())
                or any(e.complete is not True or e.source_node_id not in nodes or e.target_node_id not in nodes for e in cfg.edges)):
            reasons.add('whole-function.cfg-incomplete')
        for e in cfg.edges:
            if e.source_node_id in nodes:successors[e.source_node_id].append(e.target_node_id)
        reached=set();pending=[cfg.entry_node_id]
        while pending:
            n=pending.pop()
            if n in reached or n not in nodes:continue
            reached.add(n);pending.extend(successors[n])
        if (not cfg.exits or len({e.exit_id for e in cfg.exits})!=len(cfg.exits)
                or any(e.complete is not True or e.node_id not in reached or e.kind is FunctionExitKind.UNKNOWN for e in cfg.exits)
                or any(successors.get(e.node_id) for e in cfg.exits)
                or any(not successors[n] and n not in {e.node_id for e in cfg.exits} for n in reached)):
            reasons.add('whole-function.cfg-exit-inventory-unproven')
    if frame is not None:
        stack=frame.stack
        if (stack.complete is not True or stack.all_normal_exits_restore_entry_sp is not True
                or stack.all_call_sites_aligned is not True or type(stack.net_stack_delta_bytes) is not int
                or stack.net_stack_delta_bytes!=0 or stack.dynamic_adjustment_present is not False
                or frame.missing_fact_codes or frame.ra_continuation_complete is not True
                or any(e.complete is not True or e.restored_on_all_normal_exits is not True for e in frame.callee_saved_effects)):
            reasons.add('whole-function.frame-analysis-inconsistent')
        if cfg is not None:
            summaries={e.exit_id:e for e in stack.exit_summaries};expected={e.exit_id for e in cfg.normal_exits}
            if (not expected or len(summaries)!=len(stack.exit_summaries) or set(summaries)!=expected
                    or any(s.complete is not True or type(s.final_sp_offset_bytes) is not int or s.final_sp_offset_bytes!=0
                           or s.stack_alignment_bytes!=stack.required_alignment_bytes for s in summaries.values())):
                reasons.add('whole-function.frame-exit-summary-mismatch')
    if declaration is not None:
        if declaration.complete is not True or declaration.missing_fact_codes:reasons.add('whole-function.abi-declaration-incomplete')
        if not isinstance(declaration.provenance,str) or not declaration.provenance:reasons.add('whole-function.abi-declaration-provenance-missing')
        if not _slots(declaration):reasons.add('whole-function.abi-value-location-unproven')
        if frame is not None and (type(frame.entry_sp_residue_bytes) is not int or
                frame.entry_sp_residue_bytes!=(8 if declaration.source_abi_profile=='sysv-amd64' else 0)):
            reasons.add('whole-function.entry-stack-residue-unproven')
        if type(declaration.unwind_enabled) is not bool:reasons.add('whole-function.unwind-mismatch-or-unproven')
    if declaration is not None and machine is not None:
        if machine.complete is not True:reasons.add('whole-function.machine-abi-facts-incomplete')
        if not machine.function_id or declaration.function_id!=machine.function_id:reasons.add('whole-function.abi-function-identity-mismatch')
        if declaration.source_abi_profile!=machine.source_abi_profile:reasons.add('whole-function.abi-profile-mismatch')
        if (type(machine.entry_arguments) is not tuple or type(machine.return_values) is not tuple
                or machine.entry_arguments!=declaration.entry_arguments or machine.return_values!=declaration.return_values
                or not _slots(replace(declaration,entry_arguments=machine.entry_arguments,return_values=machine.return_values))):
            reasons.add('whole-function.machine-value-location-evidence-required')
        if (type(machine.entry_sp_residue_bytes) is not int or
                machine.entry_sp_residue_bytes!=(8 if declaration.source_abi_profile=='sysv-amd64' else 0)):
            reasons.add('whole-function.machine-entry-stack-residue-unproven')
        for label,a,b in (('pic-plt',declaration.pic_plt_mode,machine.pic_plt_mode),('tls',declaration.tls_model,machine.tls_model)):
            if not isinstance(a,str) or not a or not isinstance(b,str) or a!=b:reasons.add('whole-function.'+label+'-mismatch')
        # Enabled unwinding is a capability, not a claim that unwinding occurs.
        if type(machine.may_unwind) is not bool or declaration.unwind_enabled is False and machine.may_unwind:
            reasons.add('whole-function.unwind-mismatch-or-unproven')
        if machine.may_unwind is True or cfg is not None and cfg.has_exceptional_exit:
            reasons.add('whole-function.exceptional-abi-route-required')
        if type(machine.may_trap) is not bool:reasons.add('whole-function.trap-behavior-unproven')
        if machine.direct_calls_complete is not True:reasons.add('whole-function.direct-call-identity-unproven')
        if machine.callee_saved_preserved is not True:reasons.add('whole-function.callee-saved-unproven')
        if (type(machine.stack_alignment_bytes) is not int or machine.stack_alignment_bytes!=16
                or frame is not None and frame.stack.required_alignment_bytes!=16):
            reasons.add('whole-function.call-alignment-unproven')
    if declaration is not None and cfg is not None and declaration.unwind_enabled is False and cfg.has_exceptional_exit:
        reasons.add('whole-function.unwind-cfg-mismatch')
    complete=not reasons
    abi=FunctionAbiFacts('unknown' if declaration is None else declaration.source_abi_profile,complete,complete,
        machine is not None and machine.direct_calls_complete is True,complete,
        None if machine is None else machine.may_unwind,None if machine is None else machine.may_trap,complete)
    return FunctionAbiMachineJoin(abi,complete,tuple(sorted(reasons)))
