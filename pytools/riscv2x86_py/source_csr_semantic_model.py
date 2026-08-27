"""Phase-6A read-only adapter for Phase-5 CSR facts."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class SourceCsrSemanticModel:
    effects: tuple[Any,...]
    operand_bindings: tuple[Any,...]
    entry_state_relation: Any
    exit_state_relation: tuple[Any,...]
    access_policy: tuple[tuple[str,Any],...]
    trap_relations: tuple[tuple[str,Any],...]
    state_escapes: tuple[str,...]
    semantic_classes: tuple[str,...]
    strict_eligible: bool
    fallback_eligible: bool
    requires_whole_function: bool
    complete: bool
    reason_codes: tuple[str,...]

def adapt_source_csr_semantic_model(privileged_state: Any) -> SourceCsrSemanticModel:
    """Cross-check existing Phase-5 facts; never inspect source/lift/IR."""
    effects=tuple(getattr(privileged_state,"csr_effects",()) or ())
    bindings=tuple(getattr(privileged_state,"csr_operand_bindings",()) or ())
    flow=getattr(privileged_state,"csr_state_dataflow",None); reasons=set()
    if not effects: reasons.add("csr-6a.effects-missing")
    if len(bindings)!=len(effects): reasons.add("csr-6a.effect-binding-cardinality-mismatch")
    if any(not getattr(x,"complete",False) for x in effects): reasons.add("csr-6a.effect-incomplete")
    if any(not getattr(x,"complete",False) for x in bindings): reasons.add("csr-6a.operand-binding-incomplete")
    if flow is None or not getattr(flow,"complete",False): reasons.add("csr-6a.state-dataflow-incomplete")
    access=tuple((getattr(x,"csr_id","") or "",getattr(x,"access_allowed",None)) for x in effects)
    if any(value is None for _,value in access): reasons.add("csr-6a.access-policy-incomplete")
    traps=tuple((getattr(x,"csr_id","") or "",getattr(x,"may_trap",None)) for x in effects)
    if any(value is True for _,value in traps): reasons.add("csr-6a.trap-relation-unresolved")
    escapes=tuple(sorted({getattr(x,"source_effect_id","") for x in bindings if any("escape" in r for r in getattr(x,"reason_codes",()))}))
    if escapes: reasons.add("csr-6a.state-escape")
    classes=tuple(sorted({getattr(x,"csr_class",None).value if hasattr(getattr(x,"csr_class",None),"value") else str(getattr(x,"csr_class","") or "unknown") for x in effects}))
    whole=any(c in {"address_translation","interrupt_state","privileged_status","pmp_state","virtualization_state"} for c in classes)
    if whole: reasons.add("csr-6a.whole-function-or-runtime-route-required")
    complete=not reasons
    strict=complete and not whole
    fallback=complete and set(classes) <= {"user_counter_observation"} and not whole
    return SourceCsrSemanticModel(effects,bindings,None if flow is None else flow.entry_state,() if flow is None else flow.exit_states,access,traps,escapes,classes,strict,fallback,whole,complete,tuple(sorted(reasons)))
