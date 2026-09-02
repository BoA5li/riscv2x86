"""6F CSR writeback: only an approved recipe may produce C text."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
@dataclass(frozen=True)
class ApprovedCsrRecipe:
 callable:str; csr_token:str; context_operand:str; input_operand:str|None; output_operand:str|None; headers:tuple[str,...]; libraries:tuple[str,...]; runtime_version:str; trap_result_policy:str; recipe_id:str; contract_id:str; proof_id:str; preservation_mode:str; ignored_state:tuple[str,...]=()
@dataclass(frozen=True)
class CsrWritebackResult:
 text:str|None; manifest:dict; reason_codes:tuple[str,...]=()
_DENY=("%cr","rdmsr","wrmsr","rdtsc","%rsp","%rbp","__builtin_frame_address")
def render_approved_csr_writeback(recipe:ApprovedCsrRecipe)->CsrWritebackResult:
 if not all((recipe.callable,recipe.csr_token,recipe.context_operand,recipe.recipe_id,recipe.contract_id,recipe.proof_id,recipe.runtime_version,recipe.trap_result_policy)):return CsrWritebackResult(None,{},("csr-6f.recipe-provenance-incomplete",))
 if recipe.trap_result_policy not in {"runtime-trap-contract","no-trap-observation"}:return CsrWritebackResult(None,{},("csr-6f.trap-policy-invalid",))
 args=[recipe.context_operand,recipe.csr_token]+([] if recipe.input_operand is None else [recipe.input_operand]); call=recipe.callable+"("+", ".join(args)+")";text=(recipe.output_operand+" = "+call+";" if recipe.output_operand else "(void)"+call+";")
 if any(x in text.lower() for x in _DENY):return CsrWritebackResult(None,{},("csr-6f.emitted-text-denied",))
 manifest={"replacementDigest":sha256(text.encode()).hexdigest(),"recipeId":recipe.recipe_id,"runtimeContract":recipe.contract_id,"proofIdentity":recipe.proof_id,"runtimeVersion":recipe.runtime_version,"preservationMode":recipe.preservation_mode,"ignoredState":recipe.ignored_state,"headers":recipe.headers,"libraries":recipe.libraries}
 return CsrWritebackResult(text,manifest)
