"""Phase-6C CSR effect constraints: registry-only, one mapping per effect."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class TargetCsrEffectConstraint:
    source_effect_id:str; operation:str; source_csr_id:str; target_state_object_id:str
    target_operation_id:str; read_result_mapping:str|None; write_value_mapping:str|None
    field_mappings:tuple[str,...]; old_new_state_relation_id:str|None
    access_policy_mapping_id:str|None; denied_access_trap_mapping_id:str|None
    side_effect_mapping_ids:tuple[str,...]; ordering_relation_id:str|None; complete:bool
    reason_codes:tuple[str,...]=()

@dataclass(frozen=True)
class CsrTargetMapping:
    source_effect_id:str; source_csr_id:str; target_state_object_id:str; target_operation_id:str
    runtime_version:str; execution_profile:str; state_lifetime_id:str|None
    read_result_mapping:str|None=None; write_value_mapping:str|None=None; field_mappings:tuple[str,...]=()
    old_new_state_relation_id:str|None=None; access_policy_mapping_id:str|None=None
    denied_access_trap_mapping_id:str|None=None; side_effect_mapping_ids:tuple[str,...]=(); ordering_relation_id:str|None=None

def derive_csr_effect_constraints(*,source_model:Any,mappings:tuple[CsrTargetMapping,...],runtime_version:str,execution_profile:str,shell_transportable:bool)->tuple[TargetCsrEffectConstraint,...]:
    if source_model is None: return ()
    bindings={getattr(x,"source_effect_id",""):x for x in getattr(source_model,"operand_bindings",())}
    out=[]
    for effect in tuple(getattr(source_model,"effects",()) or ()):
        eid=next((getattr(x,"source_effect_id","") for x in bindings.values() if getattr(x,"source_effect_id","").endswith(getattr(effect,"csr_id","") or "")),"")
        matches=tuple(x for x in mappings if x.source_effect_id==eid and x.source_csr_id==getattr(effect,"csr_id",None)); reasons=[]
        if not matches: reasons.append("csr-6c.mapping-missing")
        if len(matches)>1: reasons.append("csr-6c.mapping-ambiguous")
        m=matches[0] if len(matches)==1 else None; b=bindings.get(eid)
        writes=getattr(getattr(effect,"operation",None),"value","") in {"write","read_write","set_bits","clear_bits"}
        reads=getattr(getattr(effect,"operation",None),"value","") in {"read","read_write","set_bits","clear_bits"}
        if b is None or not getattr(b,"complete",False): reasons.append("csr-6c.operand-binding-incomplete")
        if m is not None:
            if reads and not m.read_result_mapping: reasons.append("csr-6c.read-mapping-missing")
            if writes and not m.write_value_mapping and getattr(b,"immediate_value",None) is None: reasons.append("csr-6c.write-mapping-missing")
            if not m.field_mappings: reasons.append("csr-6c.field-mapping-missing")
            if not m.old_new_state_relation_id: reasons.append("csr-6c.state-relation-missing")
            if not m.access_policy_mapping_id: reasons.append("csr-6c.access-policy-missing")
            if getattr(effect,"may_trap",None) is not False and not m.denied_access_trap_mapping_id: reasons.append("csr-6c.denied-trap-mapping-missing")
            if not m.state_lifetime_id: reasons.append("csr-6c.target-state-lifetime-unknown")
            if m.runtime_version!=runtime_version or m.execution_profile!=execution_profile: reasons.append("csr-6c.runtime-profile-mismatch")
        if not shell_transportable: reasons.append("csr-6c.shell-not-transportable")
        out.append(TargetCsrEffectConstraint(eid,getattr(getattr(effect,"operation",None),"value",""),getattr(effect,"csr_id","") or "",*( (m.target_state_object_id,m.target_operation_id,m.read_result_mapping,m.write_value_mapping,m.field_mappings,m.old_new_state_relation_id,m.access_policy_mapping_id,m.denied_access_trap_mapping_id,m.side_effect_mapping_ids,m.ordering_relation_id) if m else ("","",None,None,(),None,None,None,(),None)),not reasons,tuple(sorted(set(reasons)))))
    return tuple(out)
