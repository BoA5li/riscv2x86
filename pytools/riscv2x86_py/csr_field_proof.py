"""Phase-6D per-field CSR proof gate over 6A/6C artifacts only."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from .semantic_content import semantic_payload, semantic_identity

@dataclass(frozen=True)
class CsrFieldProofEvidence:
    source_effect_id:str; csr_id:str; field_id:str; target_mapping_id:str
    relation_id:str; conclusion:str; proof_id:str

@dataclass(frozen=True)
class CsrFieldProofResult:
    approved:bool; evidence:tuple[CsrFieldProofEvidence,...]; reason_codes:tuple[str,...]; proof_identity:str=""; proof_payload:dict|None=None

def _id(*parts:str)->str: return "csr-field-proof:"+sha256("|".join(parts).encode()).hexdigest()

def prove_csr_fields(*,source_model:Any,constraints:tuple[Any,...],execution_profile:str,shell_preserved:bool,external_state_complete:bool,registry_identity:str="",target_environment_id:str="",shell_facts:tuple[str,...]=(),allow_functional_relations:bool=False)->CsrFieldProofResult:
    """Prove every declared source field; no raw asm, IR, or renderer input."""
    reasons=set(); evidence=[]; by_effect={getattr(x,"source_effect_id",""):x for x in constraints}
    ordered_bindings=tuple(getattr(source_model,"operand_bindings",()) or ())
    bindings={getattr(x,"source_effect_id",""):x for x in ordered_bindings}
    if getattr(source_model,"complete",None) is False: reasons.add("csr-6d.source-model-incomplete")
    if getattr(source_model,"trap_contract_required",False): reasons.add("csr-6d.trap-contract-required")
    effect_count=len(tuple(getattr(source_model,"effects",()) or ()))
    if (len(by_effect)!=len(constraints) or len(bindings)!=len(ordered_bindings)
            or len(constraints)!=effect_count or len(ordered_bindings)!=effect_count
            or set(by_effect)!=set(bindings)):
        reasons.add("csr-6d.effect-coverage-mismatch")
    if not shell_preserved: reasons.add("csr-6d.shell-unpreserved")
    if not external_state_complete: reasons.add("csr-6d.external-state-incomplete")
    if getattr(source_model,"requires_whole_function",False): reasons.add("csr-6d.whole-function-proof-required")
    for effect_index,effect in enumerate(tuple(getattr(source_model,"effects",()) or ())):
        eid=(getattr(ordered_bindings[effect_index],"source_effect_id","")
             if effect_index < len(ordered_bindings) else "")
        c=by_effect.get(eid); b=bindings.get(eid)
        if c is None or not getattr(c,"complete",False): reasons.add("csr-6d.constraint-incomplete"); continue
        if b is None or not getattr(b,"complete",False): reasons.add("csr-6d.operand-proof-incomplete"); continue
        if getattr(effect,"may_trap",None) is not False and not getattr(c,"denied_access_trap_mapping_id",None): reasons.add("csr-6d.trap-proof-missing")
        if not getattr(c,"access_policy_mapping_id",None): reasons.add("csr-6d.access-proof-missing")
        if not getattr(c,"ordering_relation_id",None): reasons.add("csr-6d.ordering-proof-missing")
        relation_kind=getattr(c,"counter_relation_kind",None)
        if (relation_kind=="functional-monotonic-observation" and
                not allow_functional_relations): reasons.add("csr-6d.functional-counter-relation-not-approved")
        counter = semantic_payload(getattr(c, 'counter_contract_payload', None) or {})
        if counter.get('trace_relation') is not None:
            try:
                from .time_trace_contract import validate_counter_payload
                validate_counter_payload(counter)
            except ValueError as exc:
                reasons.add(str(exc))
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
            conclusion=("functional_relation" if relation_kind=="functional-monotonic-observation" else "field_equivalent")
            evidence.append(CsrFieldProofEvidence(eid,getattr(effect,"csr_id","") or "",fid,target,relation,conclusion,_id(eid,fid,target,relation,execution_profile)))
    approved=bool(evidence) and not reasons
    payload=semantic_payload({"schemaVersion":"riscv2x86.csr-field-proof.v2",
        "sourceModel":source_model,"constraints":constraints,
        "registryIdentity":registry_identity,"targetEnvironmentId":target_environment_id,
        "shellFacts":tuple(sorted(shell_facts)),"executionProfile":execution_profile,
        "shellPreserved":shell_preserved,"externalStateComplete":external_state_complete,
        "functionalRelationsEnabled":allow_functional_relations,
        "approved":approved,"evidence":tuple(evidence),"reasonCodes":tuple(sorted(reasons))})
    return CsrFieldProofResult(approved,tuple(evidence),tuple(sorted(reasons)),semantic_identity(payload),payload)
