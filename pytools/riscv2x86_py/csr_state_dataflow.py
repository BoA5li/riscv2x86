"""Conservative cross-CFG CSR abstract interpretation."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
UNKNOWN="<unknown>"; ENTRY="<entry>"
@dataclass(frozen=True)
class CsrAbstractState:
 field_values:tuple[tuple[str,str],...]=(); access_gate_state:str=UNKNOWN; privilege_mode:str=UNKNOWN; pending_trap:str=UNKNOWN; delegation_state:str=UNKNOWN; interrupt_state:str=UNKNOWN; address_space_identity:str=UNKNOWN; external_state_escape:bool=False
 def value_map(self):return dict(self.field_values)
@dataclass(frozen=True)
class CsrStateDataflowResult:
 entry_state:CsrAbstractState; block_in_states:tuple[tuple[int,CsrAbstractState],...]; block_out_states:tuple[tuple[int,CsrAbstractState],...]; exit_states:tuple[tuple[int,CsrAbstractState],...]; complete:bool; requires_whole_function:bool; reason_codes:tuple[str,...]
def _field(op:Any,f:Any)->str:
 return getattr(f,"canonical_field_id",None) or f"{getattr(op,'csr_id','')}.{getattr(f,'field_id','')}"
def _merge(a,b):
 av,bv=a.value_map(),b.value_map(); keys=set(av)|set(bv); same=lambda x,y:x if x==y else UNKNOWN
 return CsrAbstractState(tuple(sorted((k,same(av.get(k,UNKNOWN),bv.get(k,UNKNOWN))) for k in keys)),same(a.access_gate_state,b.access_gate_state),same(a.privilege_mode,b.privilege_mode),same(a.pending_trap,b.pending_trap),same(a.delegation_state,b.delegation_state),same(a.interrupt_state,b.interrupt_state),same(a.address_space_identity,b.address_space_identity),a.external_state_escape or b.external_state_escape)
def _apply(s,op,reasons):
 v=s.value_map(); kind=getattr(getattr(op,"csr_operation",None),"value",""); imm=getattr(op,"immediate_mask",None); token=f"const:{imm}" if isinstance(imm,int) else getattr(op,"write_value_node_id",None) or UNKNOWN
 fs=tuple(getattr(op,"affected_csr_fields",()) or ())
 if not getattr(op,"state_complete",False) or not fs: reasons.add("csr-dataflow.effect-or-field-incomplete")
 for f in fs:
  k=_field(op,f); old=v.get(k,ENTRY)
  if kind=="set_bits":v[k]=f"masked-set({old},{token})"
  elif kind=="clear_bits":v[k]=f"masked-clear({old},{token})"
  elif kind in {"write","read_write"}:v[k]=token
 csr=getattr(op,"csr_id","") or ""; klass=getattr(op,"csr_semantic_class","") or ""
 gate=(token if csr.endswith(("mcounteren","scounteren")) and kind in {"write","read_write"} else s.access_gate_state)
 interrupt=(token if csr.endswith(("mstatus","sstatus","mie","sie","mip","sip")) and kind in {"write","read_write","set_bits","clear_bits"} else s.interrupt_state)
 delegation=(token if csr.endswith(("medeleg","mideleg")) and kind in {"write","read_write"} else s.delegation_state)
 asid=(token if csr.endswith("satp") and kind in {"write","read_write"} else s.address_space_identity)
 external= s.external_state_escape or klass in {"address_translation","trap_vector","delegation","interrupt_state"}
 if getattr(op,"may_trap",None) is True: reasons.add("csr-dataflow.trap-edge-requires-route")
 if external: reasons.add("csr-dataflow.external-privileged-state-requires-route")
 return CsrAbstractState(tuple(sorted(v.items())),gate,s.privilege_mode,"pending" if getattr(op,"may_trap",None) is True else s.pending_trap,delegation,interrupt,asid,external)
def analyze_csr_state_dataflow(*,blocks,cfg,initial_privilege_mode=None,max_iterations=256):
 by={getattr(b,"addr"):b for b in blocks}; entry=getattr(cfg,"entry",None); initial=CsrAbstractState(privilege_mode=initial_privilege_mode or UNKNOWN,pending_trap="none")
 if entry not in by:return CsrStateDataflowResult(initial,(),(),(),False,True,("csr-dataflow.cfg-entry-missing",))
 incoming={entry:initial}; outgoing={}; work=[entry]; reasons=set(); n=0
 while work:
  n+=1
  if n>max_iterations:reasons.add("csr-dataflow.fixed-point-not-reached");break
  a=work.pop(0); state=incoming[a]; block=by[a]
  for ins in tuple(getattr(block,"instructions",()) or ()):
   if getattr(ins,"has_unknown_call",False) or getattr(ins,"has_unknown_return",False):reasons.add("csr-dataflow.unknown-call-or-return")
   for op in tuple(getattr(ins,"privileged_operations",()) or ()):
    if getattr(getattr(op,"kind",None),"value",None)=="csr_access":state=_apply(state,op,reasons)
  if outgoing.get(a)==state:continue
  outgoing[a]=state
  for suc in tuple(getattr(block,"successors",()) or ()):
   if suc not in by:reasons.add("csr-dataflow.external-successor");continue
   m=state if suc not in incoming else _merge(incoming[suc],state)
   if incoming.get(suc)!=m:incoming[suc]=m;work.append(suc)
 exits=tuple(sorted((a,s) for a,s in outgoing.items() if not tuple(getattr(by[a],"successors",()) or ())))
 whole=any("requires-route" in x or "unknown-call" in x or "external-successor" in x for x in reasons)
 return CsrStateDataflowResult(initial,tuple(sorted(incoming.items())),tuple(sorted(outgoing.items())),exits,not reasons and not whole,whole,tuple(sorted(reasons)))
