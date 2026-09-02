"""Phase-6F CSR renderer; emits only an approved, explicit recipe."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping

@dataclass(frozen=True)
class CsrRuntimeRecipe:
    recipe_id:str; callable_identifier:str; csr_token:str; context_expression:str
    input_expression:str|None; output_expression:str|None; required_header:str
    required_library:str; runtime_version:str; trap_result_policy:str; approved:bool

@dataclass(frozen=True)
class CsrRenderResult:
    emitted_text:str|None; required_headers:tuple[str,...]; required_libraries:tuple[str,...]
    reason_codes:tuple[str,...]=()

def render_csr_recipe(recipe:CsrRuntimeRecipe,*,approved_recipe_ids:Mapping[str,str],expected_runtime_version:str)->CsrRenderResult:
    """Render fixed callable/token from recipe; never infer from CSR names."""
    reasons=[]
    if not recipe.approved or approved_recipe_ids.get(recipe.recipe_id)!=recipe.runtime_version: reasons.append("csr-6f.recipe-not-approved")
    if recipe.runtime_version!=expected_runtime_version: reasons.append("csr-6f.runtime-version-mismatch")
    if not all((recipe.callable_identifier,recipe.csr_token,recipe.context_expression,recipe.required_header,recipe.required_library,recipe.trap_result_policy)): reasons.append("csr-6f.recipe-incomplete")
    if recipe.callable_identifier not in {"rv2x86_csr_read","rv2x86_csr_write","rv2x86_csr_set_bits","rv2x86_csr_clear_bits","rv2x86_read_counter"}: reasons.append("csr-6f.callable-not-registered")
    if recipe.trap_result_policy not in {"runtime-trap-contract","no-trap-observation"}: reasons.append("csr-6f.trap-policy-invalid")
    if reasons:return CsrRenderResult(None,(),(),tuple(sorted(reasons)))
    args=[recipe.context_expression,recipe.csr_token]
    if recipe.callable_identifier!="rv2x86_csr_read":
        if recipe.input_expression is None: return CsrRenderResult(None,(),(),("csr-6f.input-missing",))
        args.append(recipe.input_expression)
    call=f"{recipe.callable_identifier}({', '.join(args)})"
    text=f"{recipe.output_expression} = {call};" if recipe.output_expression else f"(void){call};"
    return CsrRenderResult(text,(recipe.required_header,),(recipe.required_library,))

def render_approved_csr_recipe(recipe:CsrRuntimeRecipe,*,approved_recipe_ids:Mapping[str,str],expected_runtime_version:str,proof_approved:bool,proof_identity:str)->CsrRenderResult:
    """6F hard gate: a recipe is unusable without a concrete 6D approval."""
    if not proof_approved or not proof_identity:
        return CsrRenderResult(None,(),(),("csr-6f.approved-proof-required",))
    return render_csr_recipe(recipe,approved_recipe_ids=approved_recipe_ids,expected_runtime_version=expected_runtime_version)
