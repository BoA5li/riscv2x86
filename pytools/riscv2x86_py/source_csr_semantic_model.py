"""Phase-6A read-only CSR semantic-model adapter (no lifting or rendering)."""
from __future__ import annotations
from dataclasses import dataclass
from .semantic_content import semantic_identity
from typing import Any
from .csr_state_escape import CsrStateEscapeFact, whole_function_requirements
@dataclass(frozen=True)
class SourceCsrSemanticModel:
 effects:tuple[Any,...]; operand_bindings:tuple[Any,...]; entry_state_relation:Any; exit_state_relation:tuple[Any,...]; access_policy:tuple[tuple[str,Any],...]; trap_relations:tuple[tuple[str,Any],...]; state_escapes:tuple[str,...]; semantic_classes:tuple[str,...]; strict_eligible:bool; fallback_eligible:bool; requires_whole_function:bool; complete:bool; reason_codes:tuple[str,...]; model_identity:str; trap_contract_required:bool=False; identity_schema:str="riscv2x86.csr-source-model-identity.v3"; whole_function_requirements:tuple[Any,...]=()
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
 # A scalar result use (including return/store) is not hidden CSR state
 # escape. Never promote missing escape evidence based on reason text.
 state_facts=tuple(getattr(privileged_state,"csr_state_escape_facts",()) or ())
 valid_state_facts=[]
 for fact in state_facts:
  if not isinstance(fact,CsrStateEscapeFact):
   reasons.add("csr-6a.state-escape-fact-invalid");continue
  try:fact.validate()
  except ValueError:reasons.add("csr-6a.state-escape-fact-invalid");continue
  if not fact.complete:reasons.add("csr-6a.state-escape-fact-incomplete")
  else:valid_state_facts.append(fact)
 escapes=tuple(sorted({x.state_identity for x in valid_state_facts if x.escapes}))
 requirements=whole_function_requirements(flow,effects,tuple(valid_state_facts))
 whole=bool(requirements)
 trap_required=any(v is not False for _,v in traps)
 if trap_required:reasons.add("csr-6a.trap-contract-required")
 if whole:reasons.add("csr-6a.whole-function-required")
 complete=not {r for r in reasons if r not in {"csr-6a.whole-function-required"}}
 strict=complete and not whole and not trap_required
 ignored_complete=bool(getattr(observability,"complete",False)) and not bool(getattr(observability,"unignored_privileged_state_ids",())) and all(getattr(x,"complete",False) for x in getattr(observability,"ignored_states",()))
 fallback=complete and not whole and ignored_complete and bool(getattr(observability,"fallback_eligible",False))
 identity="csr-6a:"+semantic_identity({
  "schemaVersion":"riscv2x86.csr-source-model-identity.v3",
  "effects":effects,"operandBindings":bindings,"stateDataflow":flow,
  "accessPolicy":access,"trapRelations":traps,"stateEscapes":escapes,
  "semanticClasses":classes,"strictEligible":strict,"fallbackEligible":fallback,
  "requiresWholeFunction":whole,"wholeFunctionRequirements":requirements,
  "stateEscapeFacts":tuple(x if isinstance(x,CsrStateEscapeFact) else
      {"invalidFactType":type(x).__name__} for x in state_facts),"trapContractRequired":trap_required,
  "complete":complete,"reasonCodes":tuple(sorted(reasons))}).split(":",1)[1]
 return SourceCsrSemanticModel(effects,bindings,None if flow is None else getattr(flow,"entry_state",None),() if flow is None else tuple(getattr(flow,"exit_states",()) or ()),access,traps,escapes,classes,strict,fallback,whole,complete,tuple(sorted(reasons)),identity,trap_required,"riscv2x86.csr-source-model-identity.v3",requirements)
