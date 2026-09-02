"""Phase-6B CSR plan-family derivation from the 6A source model only."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any
from .plan_types import TargetLoweringPlan,TargetLoweringKind,TargetLoweringFamily,PlanPriorityTier,PlanRequirement

class CsrPlanFamily(str,Enum):
    CSR_COUNTER_OBSERVATION_ADAPTER="csr_counter_observation_adapter"
    CSR_FPU_STATE_ADAPTER="csr_fpu_state_adapter"
    CSR_VECTOR_STATE_ADAPTER="csr_vector_state_adapter"
    CSR_IDENTITY_PROFILE_ADAPTER="csr_identity_profile_adapter"
    CSR_PRIVILEGED_STATE_RUNTIME="csr_privileged_state_runtime"
    CSR_INTERRUPT_STATE_RUNTIME="csr_interrupt_state_runtime"
    CSR_MMU_STATE_RUNTIME="csr_mmu_state_runtime"
    CSR_FUNCTIONAL_FALLBACK="csr_functional_fallback"
    CSR_STATE_MACHINE="csr_state_machine"

@dataclass(frozen=True)
class CsrPlanCandidate:
    family:CsrPlanFamily
    source_effect_ids:tuple[str,...]
    requires_whole_function:bool
    strict:bool
    complete:bool
    reason_codes:tuple[str,...]=()

def derive_csr_plan_candidates(model:Any,*,allow_functional_fallbacks:bool=False)->tuple[CsrPlanCandidate,...]:
    """Classify, never lower.  Incomplete 6A facts produce no candidate."""
    if model is None or not getattr(model,"complete",False): return ()
    effects=tuple(getattr(model,"effects",()) or ()); classes=set(getattr(model,"semantic_classes",()) or ())
    ids=tuple(getattr(x,"csr_id","") or "" for x in effects)
    whole=bool(getattr(model,"requires_whole_function",False))
    if not effects: return ()
    if len(effects)>1 and (whole or len(classes)>1): family=CsrPlanFamily.CSR_STATE_MACHINE
    elif classes <= {"user_counter_observation"}: family=CsrPlanFamily.CSR_COUNTER_OBSERVATION_ADAPTER
    elif "fpu_state" in classes: family=CsrPlanFamily.CSR_FPU_STATE_ADAPTER
    elif "vector_state" in classes: family=CsrPlanFamily.CSR_VECTOR_STATE_ADAPTER
    elif classes <= {"identity_profile"}: family=CsrPlanFamily.CSR_IDENTITY_PROFILE_ADAPTER
    elif "address_translation" in classes or any(x.endswith((".satp",".hgatp",".vsatp")) for x in ids): family=CsrPlanFamily.CSR_MMU_STATE_RUNTIME
    elif "interrupt_state" in classes: family=CsrPlanFamily.CSR_INTERRUPT_STATE_RUNTIME
    else: family=CsrPlanFamily.CSR_PRIVILEGED_STATE_RUNTIME
    strict=bool(getattr(model,"strict_eligible",False)) and not whole
    candidates=[CsrPlanCandidate(family,ids,whole,strict,True)]
    if allow_functional_fallbacks and getattr(model,"fallback_eligible",False) and family in {CsrPlanFamily.CSR_COUNTER_OBSERVATION_ADAPTER,CsrPlanFamily.CSR_IDENTITY_PROFILE_ADAPTER}:
        candidates.append(CsrPlanCandidate(CsrPlanFamily.CSR_FUNCTIONAL_FALLBACK,ids,False,False,True))
    return tuple(candidates)

def derive_csr_target_lowering_plans(model:Any,*,allow_functional_fallbacks:bool=False)->tuple[TargetLoweringPlan,...]:
    """Materialize CSR families as Phase-6B plans consumable by 6C/6D/6E."""
    out=[]
    kinds={CsrPlanFamily.CSR_COUNTER_OBSERVATION_ADAPTER:(TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER,TargetLoweringFamily.COUNTER_OBSERVATION,PlanPriorityTier.COUNTER_OBSERVATION),CsrPlanFamily.CSR_INTERRUPT_STATE_RUNTIME:(TargetLoweringKind.PRIVILEGED_EVENT_ADAPTER,TargetLoweringFamily.PRIVILEGED_EVENT,PlanPriorityTier.PRIVILEGED_EVENT),CsrPlanFamily.CSR_MMU_STATE_RUNTIME:(TargetLoweringKind.MMU_RUNTIME_ADAPTER,TargetLoweringFamily.PRIVILEGED_MMU,PlanPriorityTier.PRIVILEGED_MMU),CsrPlanFamily.CSR_STATE_MACHINE:(TargetLoweringKind.PRIVILEGED_STATE_MACHINE,TargetLoweringFamily.PRIVILEGED_STATE_MACHINE,PlanPriorityTier.PRIVILEGED_STATE_MACHINE),CsrPlanFamily.CSR_FUNCTIONAL_FALLBACK:(TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK,TargetLoweringFamily.PRIVILEGED_FUNCTIONAL,PlanPriorityTier.PRIVILEGED_FUNCTIONAL)}
    for c in derive_csr_plan_candidates(model,allow_functional_fallbacks=allow_functional_fallbacks):
        if c.requires_whole_function and c.family is not CsrPlanFamily.CSR_STATE_MACHINE: continue
        kind,family,tier=kinds.get(c.family,(TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER,TargetLoweringFamily.PRIVILEGED_RUNTIME,PlanPriorityTier.PRIVILEGED_RUNTIME))
        req=frozenset({PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS})
        out.append(TargetLoweringPlan("csr:"+c.family.value+":"+"|".join(c.source_effect_ids),kind,family,tier,0,requirements=req,metadata={"csrPlanFamily":c.family.value,"sourceCsrModelIdentity":getattr(model,"model_identity","")},reason_codes=c.reason_codes))
    return tuple(out)
