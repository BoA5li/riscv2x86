"""Strict, versioned construction of registered L0-L3 validation runners."""
from __future__ import annotations

import json
from hashlib import sha256
import re
from pathlib import Path
from typing import Callable, Mapping

from .translation_validation import (
    LayerValidator, ValidationLayerResult, ValidationLevel, ValidationRuntimeRegistry,
)
from .l2_dimensions import (
    L2ClaimScope, L2DimensionStatus, parse_l2_dimension,
)
from .l2_results import L2DimensionResult, L2FragmentResult
from .l2_program_results import canonical_identity, sample_set_identity
from .l2_validator_resolution import (
    ExplicitL2Bindings, L2BindingKind, L2BindingStatus, L2RuntimeCapabilities,
    L2ValidatorResolver, fragment_requirement_from_dict, provider_from_dict,
    write_resolved_execution_plan,
    L2_REQUIREMENT_DRIVEN_REGISTRY_SCHEMA,
)
from .validation_status import PreservationMode, ValidationStatus


LEGACY_VALIDATION_RUNTIME_REGISTRY_SCHEMA = "riscv2x86.validation-runtime-registry.v1"
VALIDATION_RUNTIME_REGISTRY_SCHEMA = "riscv2x86.validation-runtime-registry.v2"
ValidatorFactory = Callable[[Mapping[str, object]], LayerValidator]
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _dimension_status(status: ValidationStatus) -> L2DimensionStatus:
    if status is ValidationStatus.VERIFIED:
        return L2DimensionStatus.VERIFIED
    if status is ValidationStatus.FAILED:
        return L2DimensionStatus.FAILED
    return L2DimensionStatus.INCONCLUSIVE


def _dimension_claim_scope(artifact: object) -> L2ClaimScope:
    raw = getattr(artifact, "preservation_mode", None)
    try:
        mode = raw if isinstance(raw, PreservationMode) else PreservationMode(str(raw))
    except ValueError:
        return L2ClaimScope.NONE
    if mode is PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY:
        return L2ClaimScope.APPROVED_FUNCTIONAL_RELATION
    return L2ClaimScope.ARCHITECTURAL


def _result_claim_scope(result: ValidationLayerResult, artifact: object) -> L2ClaimScope:
    """Use a validator's typed lower claim without permitting scope escalation."""
    artifact_scope = _dimension_claim_scope(artifact)
    try:
        detail = json.loads(result.detail)
    except (TypeError, json.JSONDecodeError):
        return artifact_scope
    raw = detail.get("claimScope") if isinstance(detail, Mapping) else None
    if not isinstance(raw, str):
        return artifact_scope
    try:
        scope = L2ClaimScope(raw)
    except ValueError:
        return L2ClaimScope.NONE
    if scope is L2ClaimScope.ARCHITECTURAL and artifact_scope is not L2ClaimScope.ARCHITECTURAL:
        return L2ClaimScope.NONE
    if scope is L2ClaimScope.APPROVED_FUNCTIONAL_RELATION and artifact_scope is L2ClaimScope.NONE:
        return L2ClaimScope.NONE
    return scope


def _result_reason_codes(result: ValidationLayerResult) -> tuple[str, ...]:
    if result.status is ValidationStatus.VERIFIED:
        return ()
    try:
        detail = json.loads(result.detail)
    except (TypeError, json.JSONDecodeError):
        detail = None
    if isinstance(detail, Mapping):
        raw = detail.get("reasonCodes")
        if isinstance(raw, list) and all(isinstance(item, str) and item for item in raw):
            return tuple(sorted(set(raw)))
        raw = detail.get("reasonCode")
        if isinstance(raw, str) and raw:
            return (raw,)
    if isinstance(detail, list) and all(isinstance(item, str) and item for item in detail):
        return tuple(sorted(set(detail)))
    return ("l2.validator-result:" + result.status.value,)


def _provider_observation_identities(result: ValidationLayerResult) -> tuple[str, str]:
    """Read identities explicitly emitted by an automatic observation producer."""
    try:
        detail = json.loads(result.detail)
    except (TypeError, json.JSONDecodeError):
        return "", ""
    if not isinstance(detail, Mapping):
        return "", ""
    source = detail.get("sourceObservationIdentity")
    target = detail.get("targetObservationIdentity")
    return (
        source if isinstance(source, str) and _SHA256.fullmatch(source) else "",
        target if isinstance(target, str) and _SHA256.fullmatch(target) else "",
    )


def _l0_build_matrix_factory(config: Mapping[str, object]) -> LayerValidator:
    # Delayed import avoids a translation_validation -> registry -> L0 cycle.
    from .l0_build_matrix import build_l0_validator, load_l0_build_matrix
    return build_l0_validator(load_l0_build_matrix(config))


def _l1_differential_factory(config: Mapping[str, object]) -> LayerValidator:
    from .l1_differential import build_l1_validator, load_l1_runner_config
    return build_l1_validator(load_l1_runner_config(config))


def _automatic_l0_factory(config: Mapping[str, object]) -> LayerValidator:
    from .automatic_validation import build_auto_l0_validator
    return build_auto_l0_validator(config)


def _automatic_l1_factory(config: Mapping[str, object]) -> LayerValidator:
    from .automatic_validation import build_auto_l1_validator
    return build_auto_l1_validator(config)


def _automatic_l2_operand_factory(config: Mapping[str, object]) -> LayerValidator:
    from .automatic_l2_operand import build_auto_l2_operand_validator
    return build_auto_l2_operand_validator(config)


def _automatic_l2_effect_factory(config: Mapping[str, object]) -> LayerValidator:
    from .automatic_l2_effect import build_auto_l2_effect_validator
    return build_auto_l2_effect_validator(config)


def _l2_operand_differential_factory(config: Mapping[str, object]) -> LayerValidator:
    from .l2_operand_differential import build_l2_operand_validator, load_l2_operand_runner_config
    return build_l2_operand_validator(load_l2_operand_runner_config(config))


def _l2_effect_trace_differential_factory(config: Mapping[str, object]) -> LayerValidator:
    from .l2_effect_trace_differential import build_l2_effect_validator, load_l2_effect_runner_config
    return build_l2_effect_validator(load_l2_effect_runner_config(config))


def _l2_privileged_real_runner_factory(config: Mapping[str, object]) -> LayerValidator:
    from .l2_privileged_runner import build_l2_privileged_validator, load_l2_privileged_runner_config
    return build_l2_privileged_validator(load_l2_privileged_runner_config(config))


def _explicit_l2_harness_factory(config: Mapping[str, object]) -> LayerValidator:
    from .l2_explicit_harness import (
        build_explicit_l2_harness_validator, load_explicit_l2_harness_runner_config,
    )
    return build_explicit_l2_harness_validator(
        load_explicit_l2_harness_runner_config(config)
    )


def _l2_concurrency_memory_model_factory(config: Mapping[str, object]) -> LayerValidator:
    from .l2_concurrency_runner import build_l2_concurrency_validator, load_l2_concurrency_runner_config
    return build_l2_concurrency_validator(load_l2_concurrency_runner_config(config))


def _l3_experiment_contract_factory(config: Mapping[str, object]) -> LayerValidator:
    from .l3_experiment_runner import build_l3_experiment_validator, load_l3_experiment_runner_config
    return build_l3_experiment_validator(load_l3_experiment_runner_config(config))


_BUILTIN_FACTORIES: Mapping[str, ValidatorFactory] = {
    "automatic-l0-build-matrix": _automatic_l0_factory,
    "automatic-l1-functional-differential": _automatic_l1_factory,
    "automatic-l2-operand-differential": _automatic_l2_operand_factory,
    "automatic-l2-effect-differential": _automatic_l2_effect_factory,
    "l0-build-matrix": _l0_build_matrix_factory,
    "l1-functional-differential": _l1_differential_factory,
    "l2-logical-operand-differential": _l2_operand_differential_factory,
    "l2-effect-trace-differential": _l2_effect_trace_differential_factory,
    "l2-privileged-real-runner": _l2_privileged_real_runner_factory,
    "l2-explicit-harness": _explicit_l2_harness_factory,
    "l2-concurrency-memory-model": _l2_concurrency_memory_model_factory,
    "l3-experiment-contract": _l3_experiment_contract_factory,
}


def _composite_validator(items: tuple[tuple[str, LayerValidator], ...]) -> LayerValidator:
    def validate(**kwargs: object) -> ValidationLayerResult:
        results = []
        for dimension, validator in items:
            result = validator(**kwargs)
            if not isinstance(result, ValidationLayerResult) or result.level is not kwargs.get("level"):
                result = ValidationLayerResult(
                    kwargs["level"], ValidationStatus.FAILED,
                    detail="invalid composite child result",
                )
            elif (result.status is ValidationStatus.VERIFIED
                  and _SHA256.fullmatch(result.evidence_identity) is None):
                result = ValidationLayerResult(
                    kwargs["level"], ValidationStatus.INCONCLUSIVE,
                    detail="verified composite child has no stable evidence identity",
                )
            results.append((dimension, result))
        statuses = [item.status for _dimension, item in results]
        status = (ValidationStatus.FAILED if ValidationStatus.FAILED in statuses else
                  ValidationStatus.INCONCLUSIVE if ValidationStatus.INCONCLUSIVE in statuses
                  else ValidationStatus.VERIFIED)
        payload = {
            "schemaVersion": "riscv2x86.validation-dimensions.v1",
            "dimensions": {dimension: {"status": result.status.value,
                                        "evidenceIdentity": result.evidence_identity,
                                        "detail": result.detail}
                           for dimension, result in results},
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        evidence = "sha256:" + sha256(encoded).hexdigest()
        return ValidationLayerResult(kwargs["level"], status, evidence,
                                     json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return validate


def _requirement_driven_l2_validator(
    config: Mapping[str, object], factories: Mapping[str, ValidatorFactory],
) -> LayerValidator:
    """Build an L2 runner whose exact children are selected per fragment."""
    expected = {"schemaVersion", "requirementManifestPath", "semanticProfilePath",
                "fragmentId", "semanticProfileSource", "providerSelectionUnit",
                "environmentCapabilities", "environmentExecutionProfiles",
                "executionProfile", "resolvedPlanPath", "providers"}
    if set(config) != expected or config.get("schemaVersion") != L2_REQUIREMENT_DRIVEN_REGISTRY_SCHEMA:
        raise ValueError("requirement-driven L2 registry config is malformed")
    manifest_path = config.get("requirementManifestPath")
    semantic_profile_path = config.get("semanticProfilePath")
    configured_fragment_id = config.get("fragmentId")
    semantic_profile_source = config.get("semanticProfileSource")
    provider_selection_unit = config.get("providerSelectionUnit")
    execution_profile = config.get("executionProfile")
    resolved_plan_path = config.get("resolvedPlanPath")
    raw_providers = config.get("providers")
    environment_capabilities = config.get("environmentCapabilities")
    environment_profiles = config.get("environmentExecutionProfiles")
    if (not isinstance(manifest_path, str) or not manifest_path
            or not isinstance(semantic_profile_path, str) or not semantic_profile_path
            or not isinstance(configured_fragment_id, str) or not configured_fragment_id
            or semantic_profile_source != "translated-report"
            or provider_selection_unit != "fragment"
            or not isinstance(execution_profile, str) or not execution_profile
            or not isinstance(resolved_plan_path, str) or not resolved_plan_path
            or not isinstance(raw_providers, list)
            or not isinstance(environment_capabilities, list)
            or environment_capabilities != sorted(set(environment_capabilities))
            or not all(isinstance(item, str) and item for item in environment_capabilities)
            or not isinstance(environment_profiles, list)
            or environment_profiles != sorted(set(environment_profiles))
            or not all(isinstance(item, str) and item for item in environment_profiles)):
        raise ValueError("requirement-driven L2 registry paths/profile/providers are invalid")
    from .l2_eligibility import load_l2_requirement_manifest
    from .l2_semantic_profile import profile_from_finding
    manifest = load_l2_requirement_manifest(manifest_path)
    raw_report = json.loads(Path(semantic_profile_path).read_text(encoding="utf-8"))
    raw_findings = raw_report.get("findings") if isinstance(raw_report, Mapping) else None
    profile_matches = [] if not isinstance(raw_findings, list) else [
        profile_from_finding(item) for item in raw_findings
        if isinstance(item, Mapping)
        and isinstance(item.get("fragment"), Mapping)
        and (item["fragment"].get("id") or item["fragment"].get("fragmentId"))
        == configured_fragment_id
    ]
    if len(profile_matches) != 1:
        raise ValueError("requirement-driven L2 semantic profile join is not total")
    semantic_profile = profile_matches[0]
    providers = tuple(provider_from_dict(item) for item in raw_providers
                      if isinstance(item, Mapping))
    if len(providers) != len(raw_providers):
        raise ValueError("requirement-driven L2 provider is malformed")
    for provider in providers:
        if provider.validator_type not in factories:
            raise ValueError("requirement-driven L2 provider type is unregistered")
    requirements = manifest.get("requirements")
    assert isinstance(requirements, list)
    by_fragment = {}
    for raw in requirements:
        assert isinstance(raw, Mapping)
        requirement = fragment_requirement_from_dict(raw)
        if requirement.fragment_id in by_fragment:
            raise ValueError("L2 requirement manifest contains duplicate fragment IDs")
        by_fragment[requirement.fragment_id] = requirement
    explicit = ExplicitL2Bindings(tuple(
        item for item in providers if item.binding_kind is L2BindingKind.EXPLICIT))
    capabilities = L2RuntimeCapabilities(
        tuple(item for item in providers if item.binding_kind is not L2BindingKind.EXPLICIT),
        tuple(environment_capabilities), tuple(environment_profiles),
    )
    resolver = L2ValidatorResolver()
    requirement = by_fragment.get(configured_fragment_id)
    plan = (None if requirement is None else
            resolver.resolve(requirement, capabilities, explicit,
                             execution_profile=execution_profile,
                             profile=semantic_profile))
    if plan is not None:
        write_resolved_execution_plan(resolved_plan_path, plan)
    selected_provider_ids = {
        binding.provider_id for binding in (plan.bindings if plan is not None else ())
        if binding.binding_status is L2BindingStatus.RESOLVED
    }
    validators = {
        item.provider_id: factories[item.validator_type](item.config)
        for item in providers if item.provider_id in selected_provider_ids
    }

    def validate(**kwargs: object) -> ValidationLayerResult:
        artifact = kwargs.get("translation_artifact")
        fragment_id = str(getattr(artifact, "fragment_id", ""))
        if fragment_id != configured_fragment_id or requirement is None or plan is None:
            detail = {"schemaVersion": "riscv2x86.validation-dimensions.v1",
                      "reasonCode": "l2.requirement.fragment-missing",
                      "fragmentId": fragment_id, "dimensions": {}}
            return ValidationLayerResult(
                kwargs["level"], ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(detail, sort_keys=True, separators=(",", ":")),
            )
        if requirement.semantic_profile_identity and (
                getattr(artifact, "l2_semantic_profile_identity", "")
                != requirement.semantic_profile_identity
                or getattr(artifact, "l2_pattern_kind", "")
                != requirement.pattern_kind
                or plan.semantic_profile_identity != requirement.semantic_profile_identity
                or plan.pattern_kind != requirement.pattern_kind
                or plan.required_capabilities != requirement.required_capabilities):
            detail = {
                "schemaVersion": "riscv2x86.validation-dimensions.v1",
                "reasonCode": "l2.semantic-profile.binding-mismatch",
                "fragmentId": fragment_id, "dimensions": {},
            }
            return ValidationLayerResult(
                kwargs["level"], ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(detail, sort_keys=True, separators=(",", ":")),
            )
        if requirement.eligibility_status.value != "eligible":
            detail = {"schemaVersion": "riscv2x86.validation-dimensions.v1",
                      "reasonCode": "l2.requirement.not-eligible",
                      "fragmentId": fragment_id,
                      "eligibilityStatus": requirement.eligibility_status.value,
                      "dimensions": {}}
            return ValidationLayerResult(
                kwargs["level"], ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(detail, sort_keys=True, separators=(",", ":")),
            )
        provider_results: dict[str, ValidationLayerResult] = {}
        dimension_results: list[L2DimensionResult] = []
        for binding in plan.bindings:
            if binding.binding_status is not L2BindingStatus.RESOLVED:
                dimension_results.append(L2DimensionResult.create(
                    dimension=binding.dimension,
                    status=(L2DimensionStatus.NOT_RUN
                            if binding.binding_status is L2BindingStatus.NOT_RUN
                            else L2DimensionStatus.INCONCLUSIVE),
                    reason_codes=binding.reason_codes,
                    materialize_evidence=False,
                ))
                continue
            if binding.provider_id not in provider_results:
                result = validators[binding.provider_id](**kwargs)
                if not isinstance(result, ValidationLayerResult) or result.level is not kwargs.get("level"):
                    result = ValidationLayerResult(kwargs["level"], ValidationStatus.FAILED,
                                                   detail="invalid requirement-driven child result")
                elif (result.status is ValidationStatus.VERIFIED
                      and _SHA256.fullmatch(result.evidence_identity) is None):
                    result = ValidationLayerResult(
                        kwargs["level"], ValidationStatus.INCONCLUSIVE,
                        detail="verified requirement-driven child has no stable evidence identity",
                    )
                provider_results[binding.provider_id] = result
            result = provider_results[binding.provider_id]
            dimension_status = _dimension_status(result.status)
            claim_scope = (_result_claim_scope(result, artifact)
                           if dimension_status is L2DimensionStatus.VERIFIED
                           else L2ClaimScope.NONE)
            authority_identity = str(getattr(artifact, "l2_authority_identity", ""))
            effect_relation_identity = str(
                getattr(artifact, "effect_relation_set_identity", "")
            )
            source_identity = str(getattr(kwargs.get("source_observation"), "identity", ""))
            target_identity = str(getattr(kwargs.get("target_observation"), "identity", ""))
            provider_source, provider_target = _provider_observation_identities(result)
            if not source_identity:
                source_identity = provider_source
            if not target_identity:
                target_identity = provider_target
            execution_identity = (
                canonical_identity({
                    "schemaVersion": "riscv2x86.l2-program-execution.v1",
                    "sourceObservationIdentity": source_identity,
                    "targetObservationIdentity": target_identity,
                    "sampleSetIdentity": sample_set_identity(
                        source_identity, target_identity,
                    ),
                })
                if (_SHA256.fullmatch(source_identity)
                    and _SHA256.fullmatch(target_identity)) else ""
            )
            identities = {
                "authority": authority_identity, "source-observation": source_identity,
                "target-observation": target_identity,
                "effect-relation": effect_relation_identity,
                "execution": execution_identity,
            }
            missing = tuple(
                "l2.dimension-identity-missing:" + name
                for name, value in identities.items() if _SHA256.fullmatch(value) is None
            )
            reasons = _result_reason_codes(result)
            scope_missing = claim_scope is L2ClaimScope.NONE
            authority_incomplete = not bool(
                getattr(artifact, "l2_authority_complete", False)
            )
            if authority_incomplete:
                missing = tuple(sorted(set(missing + (
                    "l2.authority.incomplete",
                ))))
                # A mismatch without complete producer authority is not a
                # translation-semantic failure; the comparison is unauthorised.
                dimension_status = L2DimensionStatus.INCONCLUSIVE
                claim_scope = L2ClaimScope.NONE
                reasons = tuple(sorted(set(reasons + missing)))
            elif dimension_status is L2DimensionStatus.VERIFIED and (
                    scope_missing or missing):
                dimension_status = L2DimensionStatus.INCONCLUSIVE
                claim_scope = L2ClaimScope.NONE
                reasons = tuple(sorted(set(reasons + missing + (
                    (() if not scope_missing else
                     ("l2.dimension-claim-scope-missing",))
                ))))
            dimension_results.append(L2DimensionResult.create(
                dimension=binding.dimension, status=dimension_status,
                claim_scope=claim_scope, authority_identity=(authority_identity
                    if _SHA256.fullmatch(authority_identity) else ""),
                source_observation_identity=(source_identity
                    if _SHA256.fullmatch(source_identity) else ""),
                target_observation_identity=(target_identity
                    if _SHA256.fullmatch(target_identity) else ""),
                effect_relation_identity=(effect_relation_identity
                    if _SHA256.fullmatch(effect_relation_identity) else ""),
                execution_identity=(execution_identity
                    if _SHA256.fullmatch(execution_identity) else ""),
                reason_codes=reasons,
                relation_kind=(
                    "runtime_mediated" if claim_scope is L2ClaimScope.APPROVED_FUNCTIONAL_RELATION
                    else "diagnostic" if claim_scope is L2ClaimScope.DIAGNOSTIC_ONLY
                    else "exact" if claim_scope is L2ClaimScope.ARCHITECTURAL else ""
                ),
                verified_properties=(
                    tuple(getattr(artifact, "l2_verified_properties", ())) or
                    (("declared-return-relation",) if claim_scope is
                     L2ClaimScope.APPROVED_FUNCTIONAL_RELATION else ())
                ),
                not_claimed_properties=(
                    tuple(getattr(artifact, "l2_not_claimed_properties", ())) or
                    (("architectural-state-equivalence",) if claim_scope is
                     L2ClaimScope.APPROVED_FUNCTIONAL_RELATION else ())
                ),
            ))
        fragment_result = L2FragmentResult.close(
            fragment_id=fragment_id,
            requirement_identity=requirement.requirement_identity,
            required_dimensions=requirement.required_dimensions,
            dimension_results=dimension_results,
        )
        status = (
            ValidationStatus.VERIFIED
            if fragment_result.status is L2DimensionStatus.VERIFIED
            else ValidationStatus.FAILED
            if fragment_result.status is L2DimensionStatus.FAILED
            else ValidationStatus.INCONCLUSIVE
        )
        payload = fragment_result.to_dict()
        return ValidationLayerResult(
            kwargs["level"], status, fragment_result.evidence_identity,
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )
    return validate


def validation_runtime_registry_from_dict(
    data: Mapping[str, object], *,
    validator_factories: Mapping[str, ValidatorFactory] | None = None,
) -> ValidationRuntimeRegistry:
    expected = {"schemaVersion", "version", "validators"}
    if set(data) != expected:
        raise ValueError("validation runtime registry fields are incomplete or unknown")
    schema_version = data.get("schemaVersion")
    if schema_version not in {LEGACY_VALIDATION_RUNTIME_REGISTRY_SCHEMA,
                              VALIDATION_RUNTIME_REGISTRY_SCHEMA}:
        raise ValueError("validation runtime registry schema version is unsupported")
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("validation runtime registry version is missing")
    descriptors = data.get("validators")
    if not isinstance(descriptors, Mapping):
        raise ValueError("validation runtime registry validators must be an object")

    factories = dict(_BUILTIN_FACTORIES)
    if validator_factories:
        factories.update(validator_factories)
    validators: dict[ValidationLevel, LayerValidator] = {}
    for raw_level, raw_descriptor in descriptors.items():
        try:
            level = ValidationLevel(str(raw_level))
        except ValueError as exc:
            raise ValueError("validation runtime registry level is unsupported") from exc
        if not isinstance(raw_descriptor, Mapping):
            raise ValueError("validation runner descriptor is malformed")
        runner_type = raw_descriptor.get("type")
        if runner_type == "requirement-driven":
            if level is not ValidationLevel.L2 or schema_version != VALIDATION_RUNTIME_REGISTRY_SCHEMA:
                raise ValueError("requirement-driven validation is only supported for L2 in registry v2")
            if set(raw_descriptor) != {"type", "config"} or not isinstance(raw_descriptor.get("config"), Mapping):
                raise ValueError("requirement-driven validation runner descriptor is malformed")
            validators[level] = _requirement_driven_l2_validator(raw_descriptor["config"], factories)
            continue
        if runner_type == "composite":
            if schema_version != VALIDATION_RUNTIME_REGISTRY_SCHEMA:
                raise ValueError("composite validation requires registry schema v2")
            if set(raw_descriptor) != {"type", "validators"}:
                raise ValueError("composite validation runner descriptor is malformed")
            raw_items = raw_descriptor.get("validators")
            if not isinstance(raw_items, list) or not raw_items:
                raise ValueError("composite validation runner requires validators")
            children = []
            for item in raw_items:
                if not isinstance(item, Mapping) or set(item) != {"dimension", "type", "config"}:
                    raise ValueError("composite child descriptor is malformed")
                dimension, child_type, child_config = item.get("dimension"), item.get("type"), item.get("config")
                if (not isinstance(dimension, str) or not dimension or not isinstance(child_type, str)
                        or child_type not in factories or not isinstance(child_config, Mapping)):
                    raise ValueError("composite child validator is invalid")
                if level is ValidationLevel.L2:
                    dimension = parse_l2_dimension(dimension).value
                children.append((dimension, factories[child_type](child_config)))
            dimensions = tuple(item[0] for item in children)
            if dimensions != tuple(sorted(set(dimensions))):
                raise ValueError("composite validation dimensions must be unique and sorted")
            if level is ValidationLevel.L2:
                raise ValueError("L2 composite validation must use the requirement-driven registry")
            validators[level] = _composite_validator(tuple(children))
            continue
        if set(raw_descriptor) != {"type", "config"}:
            raise ValueError("validation runner descriptor is malformed")
        config = raw_descriptor.get("config")
        if not isinstance(runner_type, str) or runner_type not in factories:
            raise ValueError("validation runner type is unregistered")
        if not isinstance(config, Mapping):
            raise ValueError("validation runner config must be an object")
        validators[level] = factories[runner_type](config)
    return ValidationRuntimeRegistry(version, validators)


def load_validation_runtime_registry(
    path: str | Path, *,
    validator_factories: Mapping[str, ValidatorFactory] | None = None,
) -> ValidationRuntimeRegistry:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("validation runtime registry must be an object")
    return validation_runtime_registry_from_dict(
        data, validator_factories=validator_factories,
    )
