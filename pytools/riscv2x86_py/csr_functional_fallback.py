"""Controlled Phase-6 fallback eligibility for CSR effects."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class CsrFunctionalFallbackDecision:
    approved:bool; preservation_mode:str; ignored_state_ids:tuple[str,...]; reason_codes:tuple[str,...]

_FORBIDDEN={"privileged_status","address_translation","pmp_state","interrupt_state","trap_vector","debug_state","virtualization_state"}
_ALLOWED={"user_counter_observation","identity_profile","custom_logical_query"}

def evaluate_csr_functional_fallback(*,enabled:bool,semantic_classes:tuple[str,...],is_write:bool,
    observability_complete:bool,read_result_complete:bool,c_output_complete:bool,memory_complete:bool,
    error_complete:bool,termination_complete:bool,trap_to_result_complete:bool,ignored_state_ids:tuple[str,...],
    ignored_state_non_escaping:bool,address_value_non_escaping:bool,runtime_no_extra_effects:bool,shell_preserved:bool)->CsrFunctionalFallbackDecision:
    reasons=[]; classes=set(semantic_classes)
    if not enabled: reasons.append("csr-fallback.disabled")
    if not classes <= _ALLOWED or classes & _FORBIDDEN: reasons.append("csr-fallback.semantic-class-forbidden")
    if is_write: reasons.append("csr-fallback.csr-write-forbidden")
    for ok,code in ((observability_complete,"observability"),(read_result_complete,"read-result"),(c_output_complete,"c-output"),(memory_complete,"memory"),(error_complete,"error"),(termination_complete,"termination"),(trap_to_result_complete,"trap-to-result"),(ignored_state_non_escaping,"ignored-state-escape"),(address_value_non_escaping,"address-value-escape"),(runtime_no_extra_effects,"runtime-side-effects"),(shell_preserved,"shell")):
        if not ok: reasons.append("csr-fallback."+code+"-incomplete")
    if not ignored_state_ids: reasons.append("csr-fallback.ignored-state-not-declared")
    return CsrFunctionalFallbackDecision(not reasons,"functional_equivalence_only",tuple(sorted(set(ignored_state_ids))),tuple(sorted(set(reasons))))
