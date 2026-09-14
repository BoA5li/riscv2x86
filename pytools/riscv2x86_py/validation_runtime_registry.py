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
from .l2_dimensions import parse_l2_dimension
from .l2_validator_resolution import (
    ExplicitL2Bindings, L2BindingStatus, L2RuntimeCapabilities,
    L2ValidatorResolver, fragment_requirement_from_dict, provider_from_dict,
    write_resolved_execution_plan,
    L2_REQUIREMENT_DRIVEN_REGISTRY_SCHEMA,
)
from .validation_status import ValidationStatus


LEGACY_VALIDATION_RUNTIME_REGISTRY_SCHEMA = "riscv2x86.validation-runtime-registry.v1"
VALIDATION_RUNTIME_REGISTRY_SCHEMA = "riscv2x86.validation-runtime-registry.v2"
ValidatorFactory = Callable[[Mapping[str, object]], LayerValidator]
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


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
    expected = {"schemaVersion", "requirementManifestPath", "fragmentId",
                "executionProfile", "resolvedPlanPath", "providers"}
    if set(config) != expected or config.get("schemaVersion") != L2_REQUIREMENT_DRIVEN_REGISTRY_SCHEMA:
        raise ValueError("requirement-driven L2 registry config is malformed")
    manifest_path = config.get("requirementManifestPath")
    configured_fragment_id = config.get("fragmentId")
    execution_profile = config.get("executionProfile")
    resolved_plan_path = config.get("resolvedPlanPath")
    raw_providers = config.get("providers")
    if (not isinstance(manifest_path, str) or not manifest_path
            or not isinstance(configured_fragment_id, str) or not configured_fragment_id
            or not isinstance(execution_profile, str) or not execution_profile
            or not isinstance(resolved_plan_path, str) or not resolved_plan_path
            or not isinstance(raw_providers, list)):
        raise ValueError("requirement-driven L2 registry paths/profile/providers are invalid")
    from .l2_eligibility import load_l2_requirement_manifest
    manifest = load_l2_requirement_manifest(manifest_path)
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
    explicit = ExplicitL2Bindings(tuple(item for item in providers if item.binding_kind == "explicit"))
    capabilities = L2RuntimeCapabilities(tuple(item for item in providers if item.binding_kind != "explicit"))
    resolver = L2ValidatorResolver()
    requirement = by_fragment.get(configured_fragment_id)
    plan = (None if requirement is None else
            resolver.resolve(requirement, capabilities, explicit,
                             execution_profile=execution_profile))
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
        dimension_results: dict[str, dict[str, object]] = {}
        for binding in plan.bindings:
            if binding.binding_status is not L2BindingStatus.RESOLVED:
                dimension_results[binding.dimension.value] = {
                    "status": ("not_run" if binding.binding_status is L2BindingStatus.NOT_RUN
                               else "inconclusive"),
                    "evidenceIdentity": "", "providerId": "",
                    "bindingStatus": binding.binding_status.value,
                    "detail": ";".join(binding.reason_codes),
                }
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
            dimension_results[binding.dimension.value] = {
                "status": result.status.value, "evidenceIdentity": result.evidence_identity,
                "providerId": binding.provider_id, "bindingStatus": "resolved",
                "detail": result.detail,
            }
        raw_statuses = [str(item["status"]) for item in dimension_results.values()]
        status = (ValidationStatus.FAILED if "failed" in raw_statuses else
                  ValidationStatus.INCONCLUSIVE if any(item != "verified" for item in raw_statuses)
                  else ValidationStatus.VERIFIED)
        payload = {
            "schemaVersion": "riscv2x86.validation-dimensions.v1",
            "fragmentId": fragment_id,
            "requirementIdentity": requirement.requirement_identity,
            "resolvedPlanIdentity": plan.to_dict()["planIdentity"],
            "resolvedPlanPath": resolved_plan_path,
            "dimensions": dimension_results,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        evidence = "sha256:" + sha256(encoded).hexdigest()
        return ValidationLayerResult(
            kwargs["level"], status, evidence,
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
