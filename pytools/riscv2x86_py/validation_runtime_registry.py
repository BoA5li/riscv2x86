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
