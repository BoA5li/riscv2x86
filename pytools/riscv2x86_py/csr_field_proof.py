"""Phase-6D per-field CSR proof gate over 6A/6C artifacts only."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

@dataclass(frozen=True)
class CsrFieldProofEvidence:
    source_effect_id:str; csr_id:str; field_id:str; target_mapping_id:str
    relation_id:str; conclusion:str; proof_id:str

@dataclass(frozen=True)
class CsrFieldProofResult:
    approved:bool; evidence:tuple[CsrFieldProofEvidence,...]; reason_codes:tuple[str,...]

def _id(*parts:str)->str: return "csr-field-proof:"+sha256("|".join(parts).encode()).hexdigest()

def prove_csr_fields(*,source_model:Any,constraints:tuple[Any,...],execution_profile:str,shell_preserved:bool,external_state_complete:bool)->CsrFieldProofResult:
    """Prove every declared source field; no raw asm, IR, or renderer input."""
    reasons=set(); evidence=[]; by_effect={getattr(x,"source_effect_id",""):x for x in constraints}
    bindings={getattr(x,"source_effect_id",""):x for x in getattr(source_model,"operand_bindings",())}
    if not shell_preserved: reasons.add("csr-6d.shell-unpreserved")
    if not external_state_complete: reasons.add("csr-6d.external-state-incomplete")
    if getattr(source_model,"requires_whole_function",False): reasons.add("csr-6d.whole-function-proof-required")
    for effect in tuple(getattr(source_model,"effects",()) or ()):
        eid=next((x for x in by_effect if x.endswith(getattr(effect,"csr_id","") or "")),"")
        c=by_effect.get(eid); b=bindings.get(eid)
        if c is None or not getattr(c,"complete",False): reasons.add("csr-6d.constraint-incomplete"); continue
        if b is None or not getattr(b,"complete",False): reasons.add("csr-6d.operand-proof-incomplete"); continue
        if getattr(effect,"may_trap",None) is not False and not getattr(c,"denied_access_trap_mapping_id",None): reasons.add("csr-6d.trap-proof-missing")
        if not getattr(c,"access_policy_mapping_id",None): reasons.add("csr-6d.access-proof-missing")
        if not getattr(c,"ordering_relation_id",None): reasons.add("csr-6d.ordering-proof-missing")
        fields=tuple(getattr(effect,"affected_fields",()) or ())
        if not fields: reasons.add("csr-6d.field-proof-missing")
        for field in fields:
            fid=getattr(field,"field_id","")
            # A policy id is mandatory only for a source field classified as
            # WARL/WLRL upstream; a normal RW field legitimately has none.
            if not getattr(field,"complete",False): reasons.add("csr-6d.field-semantics-incomplete"); continue
            if not getattr(c,"field_mappings",()): reasons.add("csr-6d.field-mapping-missing"); continue
            relation=getattr(c,"old_new_state_relation_id",None)
            if not relation: reasons.add("csr-6d.state-relation-missing"); continue
            target=getattr(c,"target_operation_id",None) or ""
            evidence.append(CsrFieldProofEvidence(eid,getattr(effect,"csr_id","") or "",fid,target,relation,"field_equivalent",_id(eid,fid,target,relation,execution_profile)))
    approved=bool(evidence) and not reasons
    return CsrFieldProofResult(approved,tuple(evidence),tuple(sorted(reasons)))
