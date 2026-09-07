"""Strict, versioned construction of registered L0-L3 validation runners."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Mapping

from .translation_validation import (
    LayerValidator, ValidationLevel, ValidationRuntimeRegistry,
)


VALIDATION_RUNTIME_REGISTRY_SCHEMA = (
    "riscv2x86.validation-runtime-registry.v1"
)
ValidatorFactory = Callable[[Mapping[str, object]], LayerValidator]


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


_BUILTIN_FACTORIES: Mapping[str, ValidatorFactory] = {
    "l0-build-matrix": _l0_build_matrix_factory,
    "l1-functional-differential": _l1_differential_factory,
    "l2-logical-operand-differential": _l2_operand_differential_factory,
}


def validation_runtime_registry_from_dict(
    data: Mapping[str, object], *,
    validator_factories: Mapping[str, ValidatorFactory] | None = None,
) -> ValidationRuntimeRegistry:
    expected = {"schemaVersion", "version", "validators"}
    if set(data) != expected:
        raise ValueError("validation runtime registry fields are incomplete or unknown")
    if data.get("schemaVersion") != VALIDATION_RUNTIME_REGISTRY_SCHEMA:
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
        if not isinstance(raw_descriptor, Mapping) or set(raw_descriptor) != {"type", "config"}:
            raise ValueError("validation runner descriptor is malformed")
        runner_type = raw_descriptor.get("type")
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
