from copy import deepcopy

import pytest

from riscv2x86_py.translation_validation import (
    TARGET_ENVIRONMENT_SCHEMA,
    VALIDATION_PLAN_SCHEMA,
    ValidationLayerResult,
    ValidationLevel,
    ValidationProfile,
    target_environment_from_dict,
    validation_plan_from_dict,
)
from riscv2x86_py.validation_runtime_registry import (
    VALIDATION_RUNTIME_REGISTRY_SCHEMA,
    validation_runtime_registry_from_dict,
)
from riscv2x86_py.validation_status import ValidationStatus


def _plan():
    return {
        "schemaVersion": VALIDATION_PLAN_SCHEMA,
        "planId": "plan-1",
        "profile": "architectural",
        "sourceRunner": "qemu",
        "targetRunner": "native",
        "seed": 7,
        "timeoutSeconds": 30,
        "runtimeRegistryVersion": "registry-1",
        "experimentContractId": "",
    }


def _environment():
    return {
        "schemaVersion": TARGET_ENVIRONMENT_SCHEMA,
        "environmentId": "environment-1",
        "sourceIsa": "rv64gc",
        "sourceAbi": "lp64d",
        "targetIsa": "x86_64",
        "targetAbi": "sysv_amd64",
        "sourceRunnerCapabilities": ["qemu", "spike"],
        "targetRunnerCapabilities": ["native"],
        "sanitizerCapabilities": ["asan", "none", "ubsan"],
        "runtimeIdentity": "runtime-1",
        "loaderIdentity": "loader-1",
    }


def test_validation_plan_schema_is_strict_and_typed():
    plan = validation_plan_from_dict(_plan())
    assert plan.profile is ValidationProfile.ARCHITECTURAL
    for name, value in (
        ("unknown", True), ("planId", 7), ("seed", "7"),
        ("timeoutSeconds", False),
    ):
        malformed = deepcopy(_plan())
        malformed[name] = value
        with pytest.raises(ValueError):
            validation_plan_from_dict(malformed)


def test_target_environment_requires_rv64_x86_64_abi_and_capabilities():
    environment = target_environment_from_dict(_environment())
    assert environment.target_isa == "x86_64"
    for name, value in (
        ("sourceIsa", "rv32gc"),
        ("sourceAbi", "ilp32"),
        ("targetIsa", "aarch64"),
        ("targetAbi", "win64"),
        ("runtimeIdentity", 1),
        ("sourceRunnerCapabilities", ["unknown"]),
        ("sanitizerCapabilities", ["asan"]),
    ):
        malformed = deepcopy(_environment())
        malformed[name] = value
        with pytest.raises(ValueError):
            target_environment_from_dict(malformed)


def test_runtime_registry_uses_only_registered_versioned_layer_factories():
    calls = []

    def factory(config):
        calls.append(dict(config))
        return lambda **kwargs: ValidationLayerResult(
            kwargs["level"], ValidationStatus.INCONCLUSIVE,
        )

    registry = validation_runtime_registry_from_dict({
        "schemaVersion": VALIDATION_RUNTIME_REGISTRY_SCHEMA,
        "version": "registry-1",
        "validators": {
            "L1": {"type": "test-l1", "config": {"policy": "result-v1"}},
        },
    }, validator_factories={"test-l1": factory})
    assert registry.validator_for(ValidationLevel.L1) is not None
    assert calls == [{"policy": "result-v1"}]

    with pytest.raises(ValueError):
        validation_runtime_registry_from_dict({
            "schemaVersion": VALIDATION_RUNTIME_REGISTRY_SCHEMA,
            "version": "registry-1",
            "validators": {
                "L1": {"type": "unregistered-runner", "config": {}},
            },
        })
