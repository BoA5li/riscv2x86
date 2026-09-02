"""Phase-5 CSR/GNU operand join using only frontend authority facts."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

@dataclass(frozen=True)
class SourceCsrOperandBinding:
    source_effect_id:str; read_result_operand_index:int|None; write_value_operand_index:int|None
    immediate_value:int|None; source_value_width_bits:int|None; source_signedness:str|None
    complete:bool; reason_codes:tuple[str,...]=()

@dataclass(frozen=True)
class CsrOperandAuthorityFacts:
    fragment_id:str
    value_node_to_operand_index:Mapping[str,int]
    operand_width_bits:Mapping[int,int]
    operand_signedness:Mapping[int,str]
    operand_access:Mapping[int,str]
    tied_operand_pairs:tuple[tuple[int,int],...]
    early_clobber_outputs:tuple[int,...]
    fixed_register_constraints:Mapping[int,str|None]
    output_escape_facts:Mapping[int,bool]
    shell_facts:Mapping[str,bool]
    complete:bool

# Compatibility alias for callers migrated incrementally; no adapter from
# runtime facts exists because deriving authority from registers is forbidden.
CsrOperandAuthority=CsrOperandAuthorityFacts

def _effect_id(addr:int, ordinal:int, op:Any)->str:
    return f"csr-effect:{addr:#x}:{ordinal}:{getattr(op,'csr_id',None) or 'unknown'}"
def _index(m:Mapping[str,int], node:object)->int|None:
    v=m.get(node) if isinstance(node,str) else None
    return v if isinstance(v,int) and not isinstance(v,bool) and v>=0 else None
def _suppressed(op:Any, name:str)->bool:
    return getattr(op,name,None) is True

def join_csr_operand_bindings(*, lifted_insns:tuple[Any,...]|list[Any], authority:CsrOperandAuthorityFacts,
                              fragment_shell:Any=None)->tuple[SourceCsrOperandBinding,...]:
    """Join typed decoder nodes to frontend sidecar facts without inference."""
    out=[]; ordinal=0
    for insn in lifted_insns:
      for op in tuple(getattr(insn,"privileged_operations",()) or ()):
        if getattr(getattr(op,"kind",None),"value",None)!="csr_access": continue
        ordinal+=1; reasons=[]; eid=_effect_id(getattr(insn,"addr",0),ordinal,op)
        read_node=getattr(op,"read_value_node_id",None); write_node=getattr(op,"write_value_node_id",None)
        immediate=getattr(op,"immediate_mask",None)
        read_required=read_node is not None and not _suppressed(op,"read_result_suppressed")
        write_required=write_node is not None and immediate is None and not _suppressed(op,"write_value_suppressed")
        read=_index(authority.value_node_to_operand_index,read_node); write=_index(authority.value_node_to_operand_index,write_node)
        if not authority.complete: reasons.append("csr-join.frontend-authority-incomplete")
        if read_required and read is None: reasons.append("csr-join.read-result-binding-missing")
        if write_required and write is None: reasons.append("csr-join.write-value-binding-missing")
        if immediate is not None and (not isinstance(immediate,int) or isinstance(immediate,bool) or not 0<=immediate<=31): reasons.append("csr-join.zimm-invalid")
        used=tuple(x for x in (read if read_required else None,write if write_required else None) if x is not None)
        widths={authority.operand_width_bits.get(x) for x in used}; signed={authority.operand_signedness.get(x) for x in used}
        if used and (None in widths or any(not isinstance(x,int) or x<=0 for x in widths)): reasons.append("csr-join.c-type-width-missing")
        if used and (None in signed or any(x not in {"signed","unsigned"} for x in signed)): reasons.append("csr-join.c-type-signedness-missing")
        if len(widths)!=1 and len(used)>1: reasons.append("csr-join.operand-width-mismatch")
        if len(signed)!=1 and len(used)>1: reasons.append("csr-join.operand-signedness-mismatch")
        if read_required:
          if authority.operand_access.get(read) not in {"output","read_write"}: reasons.append("csr-join.read-output-access-missing")
          if authority.output_escape_facts.get(read) is not False: reasons.append("csr-join.output-escape-unproven")
        if write_required and authority.operand_access.get(write) not in {"input","read_write"}: reasons.append("csr-join.write-input-access-missing")
        if read_required and write_required and read==write and (read,write) not in authority.tied_operand_pairs: reasons.append("csr-join.tied-operand-unproven")
        for x in used:
          if x not in authority.fixed_register_constraints: reasons.append("csr-join.fixed-register-fact-missing")
          elif authority.fixed_register_constraints[x] is None: reasons.append("csr-join.fixed-register-constraint-incomplete")
        if read_required and read in authority.early_clobber_outputs: reasons.append("csr-join.early-clobber-requires-contract")
        if any(k not in authority.shell_facts or not isinstance(authority.shell_facts[k],bool) for k in ("volatile","memory","cc")): reasons.append("csr-join.shell-facts-incomplete")
        out.append(SourceCsrOperandBinding(eid,read if read_required else None,write if write_required else None,immediate,
          next(iter(widths)) if len(widths)==1 else None,next(iter(signed)) if len(signed)==1 else None,not reasons,tuple(sorted(set(reasons)))))
    return tuple(out)
