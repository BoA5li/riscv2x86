"""Finite path-sensitive frame checks over authoritative machine transfers.

This module consumes transfers; it does not derive them from machine bytes.
SAVED/RESTORED must refer to the same producer-proven saved entry value. A
successful abstract analysis is conditional on that fact provenance.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from enum import Enum
from .whole_function import (SourceFunctionControlFlowModel,CalleeSavedRegisterEffect,
    FunctionFramePathSummary,SourceFunctionStackModel,FunctionExitKind)

class SavedState(str,Enum):
    UNCHANGED='unchanged'; SAVED='saved'; MODIFIED='modified'; RESTORED='restored'; UNKNOWN='unknown'

@dataclass(frozen=True)
class FunctionBlockTransfer:
    node_id:str; sp_delta_bytes:int|None=None; fp_delta_bytes:int|None=0
    callee_saved_updates:tuple[tuple[str,SavedState],...]=(); reads_ra:bool=False; writes_ra:bool=False
    call_alignment_bytes:int|None=None; complete:bool=True
    ra_updates:tuple[SavedState,...]=()
    contains_call:bool=False
    call_sp_offsets:tuple[int,...]=()

@dataclass(frozen=True)
class FunctionFrameAnalysis:
    stack:SourceFunctionStackModel; callee_saved_effects:tuple[CalleeSavedRegisterEffect,...]
    reads_ra:bool; writes_ra:bool; ra_continuation_complete:bool; complete:bool; missing_fact_codes:tuple[str,...]
    entry_sp_residue_bytes:int|None=None


def _value_transfer(values,operation):
    result=set()
    for value,saved in values:
        if operation is SavedState.UNCHANGED:result.add((value,saved))
        elif operation is SavedState.SAVED:result.add((value,value=='entry'))
        elif operation is SavedState.MODIFIED:result.add(('modified',saved))
        elif operation is SavedState.RESTORED:result.add(('entry' if saved else 'unknown',saved))
        elif operation is SavedState.UNKNOWN:result.add(('unknown',False))
        else:raise ValueError('function frame transfer has unknown saved-state operation')
    return frozenset(result)


def _join(left,right):
    if left is None:return right
    return (left[0] if left[0]==right[0] else None,
            left[1] if left[1]==right[1] else None,
            left[2]|right[2],tuple(a|b for a,b in zip(left[3],right[3])))


def analyze_function_frame(*,cfg:SourceFunctionControlFlowModel,transfers:tuple[FunctionBlockTransfer,...],
                           required_call_alignment:int|None,entry_sp_residue_bytes:int=0)->FunctionFrameAnalysis:
    nodes={n.node_id:n for n in cfg.nodes};by={t.node_id:t for t in transfers}
    if len(by)!=len(transfers) or any(t.node_id not in nodes for t in transfers):
        raise ValueError('function frame transfers must uniquely designate CFG nodes')
    if cfg.entry_node_id not in nodes or any(e.source_node_id not in nodes or e.target_node_id not in nodes for e in cfg.edges):
        raise ValueError('function frame CFG endpoints are invalid')
    if not cfg.exits or any(e.node_id not in nodes for e in cfg.exits):
        raise ValueError('function frame CFG exit inventory is invalid')
    if type(entry_sp_residue_bytes) is not int:raise ValueError('function entry SP residue must be an integer')
    for t in transfers:
        for delta in (t.sp_delta_bytes,t.fp_delta_bytes):
            if delta is not None and type(delta) is not int:raise ValueError('function frame offset must be an integer or unknown')
        if any(not isinstance(r,str) or not r or not isinstance(op,SavedState) for r,op in t.callee_saved_updates):
            raise ValueError('function frame register update is malformed')
        if any(not isinstance(op,SavedState) for op in t.ra_updates):raise ValueError('function RA update is malformed')
        if any(type(offset) is not int for offset in t.call_sp_offsets):raise ValueError('function call SP offsets must be integers')
        if any(type(v) is not bool for v in (t.complete,t.reads_ra,t.writes_ra,t.contains_call)):
            raise ValueError('function frame transfer boolean is malformed')
    reasons=set(cfg.missing_fact_codes)
    if cfg.complete is not True or any(n.complete is not True for n in nodes.values()) or any(e.complete is not True for e in cfg.edges):
        reasons.add('whole-function.cfg-incomplete')
    if (len({e.exit_id for e in cfg.exits})!=len(cfg.exits)
            or any(not e.exit_id or e.complete is not True or not isinstance(e.kind,FunctionExitKind)
                   or e.kind is FunctionExitKind.UNKNOWN for e in cfg.exits)):
        reasons.add('whole-function.cfg-exit-inventory-incomplete')
    alignment=required_call_alignment
    if type(alignment) is not int or alignment<=0 or alignment&(alignment-1):
        reasons.add('whole-function.call-alignment-unproven');alignment=None
    elif not 0<=entry_sp_residue_bytes<alignment:raise ValueError('function entry SP residue outside alignment')
    regs=sorted({r for t in transfers for r,_ in t.callee_saved_updates})
    positions={r:i for i,r in enumerate(regs)}
    original=frozenset({('entry',False)})
    entry=(0,0,original,tuple(original for _ in regs))
    incoming={cfg.entry_node_id:entry};outgoing={};successors={n:[] for n in nodes}
    for edge in cfg.edges:successors[edge.source_node_id].append(edge.target_node_id)
    queue=deque([cfg.entry_node_id]);queued={cfg.entry_node_id}
    # Offset lattice: unreachable -> one exact integer -> unknown. Register
    # lattices are finite sets. Backedges widen by join, never overwrite entry
    # with an exit value or iterate an unbounded sequence of integer offsets.
    while queue:
        node=queue.popleft();queued.remove(node);state=incoming[node];t=by.get(node)
        if t is None or not t.complete:
            reasons.add('whole-function.frame-transfer-missing')
            result=(None,None,frozenset({('unknown',False)}),tuple(frozenset({('unknown',False)}) for _ in regs))
        else:
            sp=None if state[0] is None or t.sp_delta_bytes is None else state[0]+t.sp_delta_bytes
            fp=None if state[1] is None or t.fp_delta_bytes is None else state[1]+t.fp_delta_bytes
            ra=state[2];values=list(state[3])
            for reg,operation in t.callee_saved_updates:values[positions[reg]]=_value_transfer(values[positions[reg]],operation)
            if t.writes_ra and not t.ra_updates:
                reasons.add('whole-function.ra-transfer-required');ra=frozenset({('unknown',False)})
            for operation in t.ra_updates:
                if (operation is SavedState.SAVED and not t.reads_ra or
                        operation in (SavedState.MODIFIED,SavedState.RESTORED) and not t.writes_ra):
                    reasons.add('whole-function.ra-transfer-flags-inconsistent')
                ra=_value_transfer(ra,operation)
            result=(sp,fp,ra,tuple(values))
        if outgoing.get(node)==result:continue
        outgoing[node]=result
        for target in successors[node]:
            merged=_join(incoming.get(target),result)
            if incoming.get(target)!=merged:
                incoming[target]=merged
                if target not in queued:queue.append(target);queued.add(target)
    reached=set(incoming)
    if any(not successors[node] and node not in {e.node_id for e in cfg.exits} for node in reached):
        reasons.add('whole-function.cfg-terminal-exit-missing')
    for node in reached:
        t=by.get(node)
        if t is None or not t.complete:continue
        has_call=t.contains_call or bool(t.call_sp_offsets) or t.call_alignment_bytes is not None or nodes[node].kind=='call'
        if has_call:
            guarantee=t.call_alignment_bytes
            if (not t.call_sp_offsets or alignment is None or type(guarantee) is not int
                    or guarantee<alignment or guarantee%alignment or incoming[node][0] is None
                    or any((entry_sp_residue_bytes+incoming[node][0]+offset)%alignment for offset in t.call_sp_offsets)):
                reasons.add('whole-function.call-alignment-unproven')
    exits=[];normal=cfg.normal_exits
    if not normal:reasons.add('whole-function.normal-exit-missing')
    for exit in normal:
        state=outgoing.get(exit.node_id)
        value=None if state is None else state[0]
        restored=state is not None and value==0 and state[1]==0
        exits.append(FunctionFramePathSummary(exit.exit_id,value,alignment,restored))
        if not restored:reasons.add('whole-function.normal-exit-stack-unrestored')
        if successors[exit.node_id]:reasons.add('whole-function.normal-exit-has-successor')
    if any(e.node_id not in reached for e in cfg.exits):reasons.add('whole-function.exit-unreachable-or-unproved')
    if any(outgoing[n][0] is None or outgoing[n][1] is None for n in reached):
        reasons.add('whole-function.stack-affine-nonconvergent')
    effects=[]
    for reg,index in positions.items():
        updates=[(t.node_id,op) for t in transfers if t.node_id in reached for r,op in t.callee_saved_updates if r==reg]
        restored=bool(normal) and all(e.node_id in outgoing and all(value=='entry' for value,_ in outgoing[e.node_id][3][index]) for e in normal)
        if not restored:reasons.add('whole-function.callee-saved-restore-unproven')
        effects.append(CalleeSavedRegisterEffect(reg,tuple(n for n,s in updates if s is SavedState.SAVED),
            tuple(n for n,s in updates if s is SavedState.RESTORED),tuple(n for n,s in updates if s is SavedState.MODIFIED),
            restored,restored and not any(s is SavedState.UNKNOWN for _,s in updates)))
    ra_ok=bool(normal) and all(e.node_id in outgoing and all(v=='entry' for v,_ in outgoing[e.node_id][2]) for e in normal)
    if not ra_ok:reasons.add('whole-function.ra-continuation-unproven')
    complete=not reasons
    balanced=bool(normal) and all(e.complete for e in exits)
    net=0 if balanced else None
    stack=SourceFunctionStackModel('whole_function',net,any(t.sp_delta_bytes is None or t.fp_delta_bytes is None for t in transfers),
        False,complete,None,alignment,tuple(exits),balanced,'whole-function.call-alignment-unproven' not in reasons)
    return FunctionFrameAnalysis(stack,tuple(effects),any(by[n].reads_ra for n in reached if n in by),
        any(by[n].writes_ra for n in reached if n in by),ra_ok,complete,tuple(sorted(reasons)),entry_sp_residue_bytes)
