"""6E-facing CSR functional fallback gate."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
@dataclass(frozen=True)
class CsrFunctionalFallbackRequest:
 source_model:Any; functional_observability:Any; ignored_state_declarations:tuple[str,...]; runtime_contract:Any; shell_proof:bool; state_escape_proof:bool
@dataclass(frozen=True)
class CsrFunctionalFallbackGateResult:
 approved:bool; reason_codes:tuple[str,...]; manifest:dict
_ALLOWED={"user_counter_observation","identity_profile","custom_logical_query"};_FORBIDDEN={"privileged_status","address_translation","interrupt_state","pmp_state","trap_vector","debug_state","virtualization_state","delegation"}
def evaluate_csr_functional_fallback_6e(request:CsrFunctionalFallbackRequest)->CsrFunctionalFallbackGateResult:
 m=request.source_model; classes=set(getattr(m,"semantic_classes",()) or ()); reasons=[]
 if not getattr(m,"fallback_eligible",False):reasons.append("csr-fallback.source-not-eligible")
 if not getattr(request.functional_observability,"complete",False):reasons.append("csr-fallback.observability-incomplete")
 if not request.shell_proof:reasons.append("csr-fallback.shell-unproven")
 if not request.state_escape_proof:reasons.append("csr-fallback.state-escape-unproven")
 if not request.ignored_state_declarations:reasons.append("csr-fallback.ignored-state-missing")
 if not classes <= _ALLOWED or classes&_FORBIDDEN:reasons.append("csr-fallback.semantic-class-forbidden")
 if any(getattr(getattr(e,"operation",None),"value","") in {"write","read_write","set_bits","clear_bits"} for e in getattr(m,"effects",())):reasons.append("csr-fallback.write-forbidden")
 if not getattr(request.runtime_contract,"complete",False):reasons.append("csr-fallback.runtime-contract-incomplete")
 manifest={"preservationMode":"functional_equivalence_only","architectureSemanticsPreserved":False,"microarchitectureSemanticsPreserved":False,"ignoredSourceState":list(request.ignored_state_declarations)}
 return CsrFunctionalFallbackGateResult(not reasons,tuple(sorted(reasons)),manifest)
