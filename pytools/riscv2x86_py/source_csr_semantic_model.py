"""Phase-6A read-only CSR semantic-model adapter (no lifting or rendering)."""
from __future__ import annotations
from dataclasses import dataclass
from .semantic_content import semantic_identity
from typing import Any
@dataclass(frozen=True)
class SourceCsrSemanticModel:
 effects:tuple[Any,...]; operand_bindings:tuple[Any,...]; entry_state_relation:Any; exit_state_relation:tuple[Any,...]; access_policy:tuple[tuple[str,Any],...]; trap_relations:tuple[tuple[str,Any],...]; state_escapes:tuple[str,...]; semantic_classes:tuple[str,...]; strict_eligible:bool; fallback_eligible:bool; requires_whole_function:bool; complete:bool; reason_codes:tuple[str,...]; model_identity:str; trap_contract_required:bool=False; identity_schema:str="riscv2x86.csr-source-model-identity.v2"
def adapt_source_csr_semantic_model(privileged_state:Any,*,observability:Any=None)->SourceCsrSemanticModel:
 """Adapt Phase-5 products only; no asm, p-code, lifter, or renderer input."""
 effects=tuple(getattr(privileged_state,"csr_effects",()) or ()); bindings=tuple(getattr(privileged_state,"csr_operand_bindings",()) or ()); flow=getattr(privileged_state,"csr_state_dataflow",None); reasons=set()
 if not effects:reasons.add("csr-6a.effects-missing")
 if len(bindings)!=len(effects):reasons.add("csr-6a.effect-binding-cardinality-mismatch")
 if any(not getattr(x,"complete",False) for x in effects):reasons.add("csr-6a.effect-incomplete")
 if any(not getattr(x,"complete",False) for x in bindings):reasons.add("csr-6a.operand-binding-incomplete")
 if flow is None or not getattr(flow,"complete",False):reasons.add("csr-6a.state-dataflow-incomplete")
 access=tuple((getattr(x,"csr_id","") or "",getattr(x,"access_allowed",None)) for x in effects); traps=tuple((getattr(x,"csr_id","") or "",getattr(x,"may_trap",None)) for x in effects)
 if any(v is None for _,v in access):reasons.add("csr-6a.access-policy-incomplete")
 if any(v is None for _,v in traps):reasons.add("csr-6a.trap-relation-incomplete")
 classes=tuple(sorted({getattr(getattr(x,"csr_class",None),"value",getattr(x,"csr_semantic_class",None) or "unknown") for x in effects}))
 escapes=tuple(sorted({getattr(x,"source_effect_id","") for x in bindings if any("escape" in r for r in getattr(x,"reason_codes",()))}))
 whole=bool(getattr(flow,"requires_whole_function",False)) or bool(escapes) or any(c in {"address_translation","interrupt_state","privileged_status","pmp_state","virtualization_state","delegation","trap_vector","trap_state"} for c in classes)
 trap_required=any(v is not False for _,v in traps)
 if trap_required:reasons.add("csr-6a.trap-contract-required")
 if whole:reasons.add("csr-6a.whole-function-required")
 complete=not {r for r in reasons if r not in {"csr-6a.whole-function-required"}}
 strict=complete and not whole and not trap_required
 ignored_complete=bool(getattr(observability,"complete",False)) and not bool(getattr(observability,"unignored_privileged_state_ids",())) and all(getattr(x,"complete",False) for x in getattr(observability,"ignored_states",()))
 fallback=complete and not whole and ignored_complete and bool(getattr(observability,"fallback_eligible",False))
 identity="csr-6a:"+semantic_identity({
  "schemaVersion":"riscv2x86.csr-source-model-identity.v2",
  "effects":effects,"operandBindings":bindings,"stateDataflow":flow,
  "accessPolicy":access,"trapRelations":traps,"stateEscapes":escapes,
  "semanticClasses":classes,"strictEligible":strict,"fallbackEligible":fallback,
  "requiresWholeFunction":whole,"trapContractRequired":trap_required,
  "complete":complete,"reasonCodes":tuple(sorted(reasons))}).split(":",1)[1]
 return SourceCsrSemanticModel(effects,bindings,None if flow is None else getattr(flow,"entry_state",None),() if flow is None else tuple(getattr(flow,"exit_states",()) or ()),access,traps,escapes,classes,strict,fallback,whole,complete,tuple(sorted(reasons)),identity,trap_required)
