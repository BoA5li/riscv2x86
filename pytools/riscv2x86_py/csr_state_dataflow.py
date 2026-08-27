"""Phase-5 fail-closed CFG abstract interpretation for typed CSR effects."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

UNKNOWN = "<unknown>"

@dataclass(frozen=True)
class CsrAbstractState:
    field_values: tuple[tuple[str,str], ...] = ()
    access_gate_state: str = UNKNOWN
    privilege_mode: str = UNKNOWN
    pending_trap: str = UNKNOWN
    address_space_identity: str = UNKNOWN
    def value_map(self): return dict(self.field_values)

@dataclass(frozen=True)
class CsrStateDataflowResult:
    entry_state: CsrAbstractState
    block_in_states: tuple[tuple[int,CsrAbstractState], ...]
    block_out_states: tuple[tuple[int,CsrAbstractState], ...]
    exit_states: tuple[tuple[int,CsrAbstractState], ...]
    complete: bool
    reason_codes: tuple[str,...]

def _field_id(csr: str, field: str) -> str:
    # Architectural aliases/views must update one abstract location.
    aliases={"riscv.csr.fcsr.fflags":"riscv.csr.fflags.fflags","riscv.csr.fcsr.frm":"riscv.csr.frm.frm"}
    return aliases.get(f"{csr}.{field}",f"{csr}.{field}")

def _merge(a:CsrAbstractState,b:CsrAbstractState)->CsrAbstractState:
    av,bv=a.value_map(),b.value_map(); keys=set(av)|set(bv)
    fields=tuple(sorted((k,av.get(k,UNKNOWN) if av.get(k,UNKNOWN)==bv.get(k,UNKNOWN) else UNKNOWN) for k in keys))
    def same(x,y): return x if x==y else UNKNOWN
    return CsrAbstractState(fields,same(a.access_gate_state,b.access_gate_state),same(a.privilege_mode,b.privilege_mode),same(a.pending_trap,b.pending_trap),same(a.address_space_identity,b.address_space_identity))

def _apply(state:CsrAbstractState,op:Any,reasons:set[str])->CsrAbstractState:
    if not getattr(op,"state_complete",False): reasons.add("csr-dataflow.effect-incomplete")
    csr=getattr(op,"csr_id",None) or ""
    kind=getattr(getattr(op,"csr_operation",None),"value","")
    values=state.value_map(); immediate=getattr(op,"immediate_mask",None)
    token=(f"imm:{immediate}" if isinstance(immediate,int) else getattr(op,"write_value_node_id",None) or UNKNOWN)
    fields=tuple(getattr(op,"affected_csr_fields",()) or ())
    if not fields: reasons.add("csr-dataflow.field-coverage-incomplete")
    for field in fields:
        key=_field_id(csr,getattr(field,"field_id","").rsplit(".",1)[-1])
        old=values.get(key,UNKNOWN)
        if kind=="set_bits" and isinstance(immediate,int): values[key]=f"set({old},{immediate:#x})"
        elif kind=="clear_bits" and isinstance(immediate,int): values[key]=f"clear({old},{immediate:#x})"
        elif kind in {"write","read_write","set_bits","clear_bits"}: values[key]=token
    if csr=="riscv.csr.satp" and kind in {"write","read_write"}: state_asid=token
    else: state_asid=state.address_space_identity
    trap="pending" if getattr(op,"may_trap",None) is True else state.pending_trap
    return CsrAbstractState(tuple(sorted(values.items())),state.access_gate_state,state.privilege_mode,trap,state_asid)

def analyze_csr_state_dataflow(*,blocks:tuple[Any,...]|list[Any],cfg:Any,initial_privilege_mode:str|None=None,max_iterations:int=256)->CsrStateDataflowResult:
    by_addr={getattr(b,"addr"):b for b in blocks}; entry=getattr(cfg,"entry",None)
    reasons=set(); initial=CsrAbstractState(privilege_mode=initial_privilege_mode or UNKNOWN,pending_trap="none")
    if entry not in by_addr: return CsrStateDataflowResult(initial,(),(),(),False,("csr-dataflow.cfg-entry-missing",))
    incoming={entry:initial}; outgoing={}; work=[entry]; steps=0
    while work:
        steps+=1
        if steps>max_iterations: reasons.add("csr-dataflow.fixed-point-not-reached"); break
        addr=work.pop(0); block=by_addr[addr]; state=incoming[addr]
        for insn in tuple(getattr(block,"instructions",()) or ()):
            for op in tuple(getattr(insn,"privileged_operations",()) or ()):
                if getattr(getattr(op,"kind",None),"value",None)=="csr_access": state=_apply(state,op,reasons)
        if outgoing.get(addr)==state: continue
        outgoing[addr]=state
        for succ in tuple(getattr(block,"successors",()) or ()):
            if succ not in by_addr: reasons.add("csr-dataflow.external-successor"); continue
            merged=state if succ not in incoming else _merge(incoming[succ],state)
            if incoming.get(succ)!=merged: incoming[succ]=merged; work.append(succ)
    exits=tuple(sorted((addr,state) for addr,state in outgoing.items() if not tuple(getattr(by_addr[addr],"successors",()) or ())))
    if any(state.pending_trap=="pending" for state in outgoing.values()): reasons.add("csr-dataflow.trap-edge-unmodelled")
    complete=not reasons
    return CsrStateDataflowResult(initial,tuple(sorted(incoming.items())),tuple(sorted(outgoing.items())),exits,complete,tuple(sorted(reasons)))
