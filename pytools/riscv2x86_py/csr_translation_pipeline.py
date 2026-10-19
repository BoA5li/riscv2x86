"""Single production CSR translation pipeline.

This module is the only permitted bridge from the Phase-6A CSR model to emitted
C text.  It consumes structured Phase-6 artifacts only: it never rescans asm,
p-code, decoded instructions, or register names.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping
from .semantic_content import semantic_identity

from .csr_effect_constraints import (
    CsrTargetMapping,
    TargetCsrEffectConstraint,
    derive_csr_effect_constraints,
)
from .csr_field_proof import CsrFieldProofResult, prove_csr_fields
from .csr_plan_families import CsrPlanCandidate, derive_csr_plan_candidates
from .csr_structured_renderer import (
    CsrRenderResult,
    CsrRuntimeRecipe,
    render_approved_csr_recipe,
)


@dataclass(frozen=True)
class CsrRuntimeRegistry:
    """Versioned target mappings usable by the CSR production pipeline."""

    registry_version: str
    runtime_version: str
    execution_profile: str
    mappings: tuple[CsrTargetMapping, ...]
    shell_transportable: bool
    external_state_complete: bool
    source_digest: str = ""
    fragment_id: str = ""


@dataclass(frozen=True)
class CsrRendererRegistry:
    """Versioned, explicit 6F recipes keyed by approved target operation."""

    registry_version: str
    recipes_by_target_operation: Mapping[str, CsrRuntimeRecipe]
    approved_recipe_ids: Mapping[str, str]


@dataclass(frozen=True)
class CsrTranslationFallbackPolicy:
    allow_functional_fallbacks: bool = False
    shell_preserved: bool = False


@dataclass(frozen=True)
class CsrTranslationPipelineResult:
    status: str
    route: str
    suggested_replacement: str | None
    reason_codes: tuple[str, ...]
    plan_candidates: tuple[CsrPlanCandidate, ...]
    constraints: tuple[TargetCsrEffectConstraint, ...]
    proof: CsrFieldProofResult | None
    render: CsrRenderResult | None
    proof_invoked: bool
    implementation_identity: str = ""
    shell_payload: dict | None = None
    recipe_payload: dict | None = None


def _facts_profile(
    privileged_execution_facts: Any,
    runtime_registry: CsrRuntimeRegistry | None,
) -> str:
    value = getattr(privileged_execution_facts, "execution_profile", None)
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, str) and value:
        return value
    return "" if runtime_registry is None else runtime_registry.execution_profile


def _reasons(*groups: object) -> tuple[str, ...]:
    values: set[str] = set()
    for group in groups:
        for value in group or ():
            if value:
                values.add(str(value))
    return tuple(sorted(values))


def run_csr_translation_pipeline(
    source_csr_model: Any,
    target_environment: Any,
    privileged_execution_facts: Any,
    runtime_registry: CsrRuntimeRegistry | None,
    renderer_registry: CsrRendererRegistry | None,
    fallback_policy: CsrTranslationFallbackPolicy,
    operand_expressions: Mapping[int, str] | None = None,
    fragment_id: str = "",
    source_fragment: Any = None,
    target_build_contract: str | None = None,
) -> CsrTranslationPipelineResult:
    """Run the mandatory 6A -> 6B -> 6C -> 6D -> 6E -> 6F CSR chain.

    An emitted replacement is possible only after 6D was invoked and approved,
    then rendered by an explicitly registered 6F recipe.  Missing facts are
    normal route requests, not permission to synthesize a local replacement.
    """
    if source_csr_model is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_source_model", None,
            ("csr-pipeline.source-model-missing",), (), (), None, None, False,
        )

    candidates = derive_csr_plan_candidates(
        source_csr_model,
        allow_functional_fallbacks=fallback_policy.allow_functional_fallbacks,
    )
    if not candidates:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_source_model", None,
            _reasons(
                getattr(source_csr_model, "reason_codes", ()),
                ("csr-pipeline.no-approved-plan-candidate",),
            ),
            (), (), None, None, False,
        )

    if runtime_registry is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_runtime_registry", None,
            ("csr-pipeline.runtime-registry-missing",), candidates, (), None,
            None, False,
        )

    if fragment_id and runtime_registry.fragment_id != fragment_id:
        return CsrTranslationPipelineResult("needs_route", "csr_runtime_binding", None,
            ("CSR_RUNTIME_CONTRACT_FRAGMENT_MISMATCH",), candidates, (), None, None, False)
    profile = _facts_profile(privileged_execution_facts, runtime_registry)
    constraints = derive_csr_effect_constraints(
        source_model=source_csr_model,
        mappings=runtime_registry.mappings,
        runtime_version=runtime_registry.runtime_version,
        execution_profile=profile,
        shell_transportable=runtime_registry.shell_transportable,
        allow_functional_relations=fallback_policy.allow_functional_fallbacks,
    )

    # 6D is deliberately unconditional once 6C has been built.  It must run
    # even for rejected constraints, making a skipped proof mechanically
    # distinguishable from a negative proof result.
    implementation_payload = None
    implementation_reason = "CSR_RUNTIME_IMPLEMENTATION_NOT_APPLICABLE"
    if operand_expressions is not None and renderer_registry is not None and len(constraints) == 1:
        from .csr_runtime_implementation import validate_implementation
        proposed_recipe = renderer_registry.recipes_by_target_operation.get(constraints[0].target_operation_id)
        if proposed_recipe is not None:
            try:
                implementation_payload, _ = validate_implementation(proposed_recipe, source_csr_model.effects, constraints)
            except ValueError as exc:
                implementation_reason = str(exc)
    shell_payload = None
    shell_preserved = fallback_policy.shell_preserved
    if source_fragment is not None:
        if implementation_payload is None:
            return CsrTranslationPipelineResult("needs_route", "csr_runtime_implementation", None,
                (implementation_reason,), candidates, constraints, None, None, False)
        from .csr_runtime_shell import prove_runtime_shell
        try:
            shell_payload = prove_runtime_shell(source_fragment,
                semantic_identity(implementation_payload), target_build_contract)
        except ValueError as exc:
            return CsrTranslationPipelineResult("needs_route", "csr_runtime_shell", None,
                (str(exc),), candidates, constraints, None, None, False)
        shell_preserved = True
    proof = prove_csr_fields(
        source_model=source_csr_model,
        constraints=constraints,
        execution_profile=profile,
        shell_preserved=shell_preserved,
        shell_facts=(() if shell_payload is None else (semantic_identity(shell_payload),)),
        external_state_complete=runtime_registry.external_state_complete,
        allow_functional_relations=fallback_policy.allow_functional_fallbacks,
        registry_identity=semantic_identity({"runtime": runtime_registry,
            "renderer": renderer_registry, "implementation": implementation_payload}),
        target_environment_id=semantic_identity(target_environment),
    )
    if not proof.approved:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_per_field_proof", None,
            _reasons(proof.reason_codes, ("csr-pipeline.proof-not-approved",)),
            candidates, constraints, proof, None, True,
        )

    # 6E: deterministic selection.  Exact plans win; a fallback plan is never
    # selected merely because it happens to be present.
    functional_relation = any(
        item.counter_relation_kind == "functional-monotonic-observation"
        for item in constraints
    )
    selected = next((candidate for candidate in candidates
                     if candidate.complete and (
                         (not candidate.strict) if functional_relation
                         else candidate.strict)), None)
    if selected is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_plan_selection", None,
            (("csr-pipeline.no-approved-functional-plan",)
             if functional_relation else ("csr-pipeline.no-approved-strict-plan",)),
            candidates, constraints, proof, None, True,
        )

    if renderer_registry is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_renderer_registry", None,
            ("csr-pipeline.renderer-registry-missing",),
            candidates, constraints, proof, None, True,
        )
    if len(constraints) != 1 or not constraints[0].complete:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_renderer_recipe", None,
            ("csr-pipeline.composite-recipe-required",),
            candidates, constraints, proof, None, True,
        )
    recipe = renderer_registry.recipes_by_target_operation.get(
        constraints[0].target_operation_id
    )
    if recipe is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_renderer_recipe", None,
            ("csr-pipeline.recipe-missing",),
            candidates, constraints, proof, None, True,
        )
    implementation_identity = ""
    if operand_expressions is not None:
        from .csr_runtime_implementation import validate_implementation
        try:
            _implementation_payload, implementation_identity = validate_implementation(
                recipe, source_csr_model.effects, constraints)
        except ValueError as exc:
            return CsrTranslationPipelineResult("needs_route", "csr_runtime_implementation", None,
                (str(exc),), candidates, constraints, proof, None, True)
        binding = source_csr_model.operand_bindings[0]
        read_index = getattr(binding, "read_result_operand_index", None)
        write_index = getattr(binding, "write_value_operand_index", None)
        immediate = getattr(binding, "immediate_value", None)
        if any(type(i) is not int or i < 0 or i not in operand_expressions or not isinstance(operand_expressions[i], str)
               or not operand_expressions[i] for i in (read_index, write_index) if i is not None):
            return CsrTranslationPipelineResult("needs_route", "csr_renderer_binding", None,
                ("csr-6f.compiler-operand-expression-missing",),candidates,constraints,proof,None,True)
        # Select expressions by proved operand index. Their spelling is used
        # only to render C, never as a semantic join key or identity.
        recipe = replace(recipe,
            output_expression=None if read_index is None else operand_expressions[read_index],
            input_expression=(operand_expressions[write_index] if write_index is not None
                              else str(immediate) if immediate is not None else None))
    rendered = render_approved_csr_recipe(
        recipe,
        approved_recipe_ids=renderer_registry.approved_recipe_ids,
        expected_runtime_version=runtime_registry.runtime_version,
        proof_approved=proof.approved,
        proof_identity=proof.proof_identity,
    )
    if rendered.emitted_text is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_renderer_recipe", None,
            _reasons(rendered.reason_codes, ("csr-pipeline.render-not-approved",)),
            candidates, constraints, proof, rendered, True,
        )
    if shell_payload is not None:
        from .csr_runtime_shell import render_runtime_shell
        rendered = replace(rendered, emitted_text=render_runtime_shell(rendered.emitted_text, shell_payload))
    return CsrTranslationPipelineResult(
        "approved", selected.family.value, rendered.emitted_text, (),
        candidates, constraints, proof, rendered, True, implementation_identity, shell_payload, asdict(recipe),
    )
