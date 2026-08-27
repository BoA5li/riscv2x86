"""Single production CSR translation pipeline.

This module is the only permitted bridge from the Phase-6A CSR model to emitted
C text.  It consumes structured Phase-6 artifacts only: it never rescans asm,
p-code, decoded instructions, or register names.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

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
    render_csr_recipe,
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

    profile = _facts_profile(privileged_execution_facts, runtime_registry)
    constraints = derive_csr_effect_constraints(
        source_model=source_csr_model,
        mappings=runtime_registry.mappings,
        runtime_version=runtime_registry.runtime_version,
        execution_profile=profile,
        shell_transportable=runtime_registry.shell_transportable,
    )

    # 6D is deliberately unconditional once 6C has been built.  It must run
    # even for rejected constraints, making a skipped proof mechanically
    # distinguishable from a negative proof result.
    proof = prove_csr_fields(
        source_model=source_csr_model,
        constraints=constraints,
        execution_profile=profile,
        shell_preserved=fallback_policy.shell_preserved,
        external_state_complete=runtime_registry.external_state_complete,
    )
    if not proof.approved:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_per_field_proof", None,
            _reasons(proof.reason_codes, ("csr-pipeline.proof-not-approved",)),
            candidates, constraints, proof, None, True,
        )

    # 6E: deterministic selection.  Exact plans win; a fallback plan is never
    # selected merely because it happens to be present.
    selected = next(
        (candidate for candidate in candidates
         if candidate.strict and candidate.complete),
        None,
    )
    if selected is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_plan_selection", None,
            ("csr-pipeline.no-approved-strict-plan",),
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
    rendered = render_csr_recipe(
        recipe,
        approved_recipe_ids=renderer_registry.approved_recipe_ids,
        expected_runtime_version=runtime_registry.runtime_version,
    )
    if rendered.emitted_text is None:
        return CsrTranslationPipelineResult(
            "needs_route", "csr_renderer_recipe", None,
            _reasons(rendered.reason_codes, ("csr-pipeline.render-not-approved",)),
            candidates, constraints, proof, rendered, True,
        )
    return CsrTranslationPipelineResult(
        "approved", selected.family.value, rendered.emitted_text, (),
        candidates, constraints, proof, rendered, True,
    )
