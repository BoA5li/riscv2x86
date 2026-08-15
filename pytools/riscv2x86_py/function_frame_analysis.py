"""Phase-5 conservative function SP/FP, RA and callee-saved dataflow."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from .whole_function import SourceFunctionControlFlowModel, CalleeSavedRegisterEffect, FunctionFramePathSummary, SourceFunctionStackModel

class SavedState(str,Enum): UNCHANGED="unchanged"; SAVED="saved"; MODIFIED="modified"; RESTORED="restored"; UNKNOWN="unknown"
@dataclass(frozen=True)
class FunctionBlockTransfer:
    node_id:str; sp_delta_bytes:int|None=None; fp_delta_bytes:int|None=0
    callee_saved_updates:tuple[tuple[str,SavedState],...]=(); reads_ra:bool=False; writes_ra:bool=False
    call_alignment_bytes:int|None=None; complete:bool=True
@dataclass(frozen=True)
class FunctionFrameAnalysis:
    stack:SourceFunctionStackModel; callee_saved_effects:tuple[CalleeSavedRegisterEffect,...]
    reads_ra:bool; writes_ra:bool; ra_continuation_complete:bool; complete:bool; missing_fact_codes:tuple[str,...]

def _merge(a,b): return a if a==b else None
def analyze_function_frame(*,cfg:SourceFunctionControlFlowModel,transfers:tuple[FunctionBlockTransfer,...],required_call_alignment:int|None)->FunctionFrameAnalysis:
    by={x.node_id:x for x in transfers}; pred={n.node_id:[] for n in cfg.nodes}
    for e in cfg.edges: pred.setdefault(e.target_node_id,[]).append(e.source_node_id)
    sp={cfg.entry_node_id:0}; states={cfg.entry_node_id:{}}; reasons=set(cfg.missing_fact_codes); changed=True; reads=writes=False; call_ok=True
    while changed:
        changed=False
        for node in sorted(n.node_id for n in cfg.nodes):
            if node!=cfg.entry_node_id and pred.get(node):
                vals=[sp[p] for p in pred[node] if p in sp]
                if len(vals)==len(pred[node]) and vals:
                    merged=vals[0] if all(v==vals[0] for v in vals) else None
                    if merged is None: reasons.add("whole-function.stack-affine-nonconvergent")
                    if sp.get(node,"unset")!=merged: sp[node]=merged; changed=True
            if node not in sp: continue
            t=by.get(node)
            if t is None or not t.complete: reasons.add("whole-function.frame-transfer-missing"); continue
            reads|=t.reads_ra; writes|=t.writes_ra
            if t.call_alignment_bytes is not None and required_call_alignment is not None and t.call_alignment_bytes<required_call_alignment: call_ok=False
            if t.sp_delta_bytes is None: reasons.add("whole-function.stack-affine-nonconvergent"); continue
            out=sp[node]+t.sp_delta_bytes
            for e in cfg.edges:
                if e.source_node_id==node and (e.target_node_id not in sp or sp[e.target_node_id]!=out): sp[e.target_node_id]=out; changed=True
    exits=[]
    for x in cfg.normal_exits:
        value=sp.get(x.node_id); exits.append(FunctionFramePathSummary(x.exit_id,value,required_call_alignment,value==0))
        if value!=0: reasons.add("whole-function.normal-exit-stack-unrestored")
    if not call_ok: reasons.add("whole-function.call-alignment-unproven")
    effects=[]
    regs={r for t in transfers for r,_ in t.callee_saved_updates}
    for r in sorted(regs):
        updates=[(t.node_id,s) for t in transfers for rr,s in t.callee_saved_updates if rr==r]
        modified=any(s is SavedState.MODIFIED for _,s in updates); restored=bool(modified and all(any(n==e.node_id and s is SavedState.RESTORED for n,s in updates) for e in cfg.normal_exits))
        if modified and not restored: reasons.add("whole-function.callee-saved-restore-unproven")
        effects.append(CalleeSavedRegisterEffect(r,tuple(n for n,s in updates if s is SavedState.SAVED),tuple(n for n,s in updates if s is SavedState.RESTORED),tuple(n for n,s in updates if s is SavedState.MODIFIED),restored or not modified,not any(s is SavedState.UNKNOWN for _,s in updates)))
    ra_ok=not writes or reads
    if not ra_ok: reasons.add("whole-function.ra-continuation-unproven")
    complete=cfg.complete and not reasons
    stack=SourceFunctionStackModel("whole_function",0 if all(x.final_sp_offset_bytes==0 for x in exits) else None,False,False,complete,None,required_call_alignment,tuple(exits),all(x.restored_on_all_normal_exits for x in exits),call_ok)
    return FunctionFrameAnalysis(stack,tuple(effects),reads,writes,ra_ok,complete,tuple(sorted(reasons)))
