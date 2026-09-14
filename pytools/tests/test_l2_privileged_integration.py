import json

import pytest

from riscv2x86_py import automatic_batch_cli as auto
from riscv2x86_py.automatic_batch_cli import (
    PRIVILEGED_BINDING_SCHEMA, _identity, _privileged_binding,
)
from riscv2x86_py.batch_evaluation_cli import _privileged_claim_counts
from riscv2x86_py.l2_privileged_runner import (
    LEGACY_PRIVILEGED_RUNNER_SCHEMA, PRIVILEGED_RUNNER_SCHEMA,
    L2PrivilegedRunnerConfig, PrivilegedRunnerSpec, validate_runner_environment,
)
from riscv2x86_py.l2_effect_trace_differential import L2EffectRunnerConfig


def _source_runner():
    return PrivilegedRunnerSpec(
        ("/bin/true",), "qemu-system", "rv64-system", "runtime-v1",
        "rv64gc-system-v1", "emulator-only",
    )


def _target_runner(kind="x86-logical-runtime", mode="logical-csr-runtime"):
    return PrivilegedRunnerSpec(
        ("/bin/true",), kind, "x86-privileged", "runtime-v1",
        "x86-privileged-v1", mode,
    )


def _config(target=None, *, schema=PRIVILEGED_RUNNER_SCHEMA):
    return L2PrivilegedRunnerConfig(
        L2EffectRunnerConfig("operands.json", "effects.json"),
        _source_runner(), target or _target_runner(),
        "initial.json", "manifest.json", "routes.json", 10,
        required_environment_id=("environment-v1" if schema == PRIVILEGED_RUNNER_SCHEMA else ""),
        schema_version=schema,
    )


def test_logical_runtime_requires_typed_environment_capability():
    config = _config()
    ordinary = {
        "environmentId": "environment-v1",
        "sourceRunnerCapabilities": ["qemu-system"],
        "targetRunnerCapabilities": ["native"],
    }
    assert validate_runner_environment(config, ordinary) == (
        "privileged-environment:target-capability-missing:logical-csr-runtime",
    )
    approved = dict(ordinary)
    approved["targetRunnerCapabilities"] = ["logical-csr-runtime", "native"]
    assert validate_runner_environment(config, approved) == ()


def test_system_or_vmm_route_requires_non_user_environment_capability():
    config = _config(_target_runner("x86-vmm-adapter", "vmm-adapter"))
    ordinary = {
        "environmentId": "environment-v1",
        "sourceRunnerCapabilities": ["qemu-system"],
        "targetRunnerCapabilities": ["native"],
    }
    reasons = validate_runner_environment(config, ordinary)
    assert "privileged-environment:target-capability-missing:vmm-adapter" in reasons
    assert "privileged-environment:ordinary-user-process-cannot-claim-isolated-route" in reasons
    with pytest.raises(ValueError, match="legacy privileged runner"):
        _config(_target_runner("x86-vmm-adapter", "vmm-adapter"),
                schema=LEGACY_PRIVILEGED_RUNNER_SCHEMA)


def test_content_addressed_binding_resolves_inputs_and_binds_capabilities(tmp_path, monkeypatch):
    source_root = tmp_path / "corpus"; source_root.mkdir()
    source = source_root / "csr.c"; source.write_text("int csr(void){return 0;}\n")
    binding_root = tmp_path / "bindings"; binding_root.mkdir()
    for name in ("initial.json", "manifest.json", "routes.json", "operands.json", "effects.json"):
        (binding_root / name).write_text("{}\n")
    runner_config = {
        "schemaVersion": PRIVILEGED_RUNNER_SCHEMA,
        "comparisonPolicy": "riscv2x86.comparison-policy.architectural.v1",
        "baseEffectRunner": {
            "schemaVersion": "riscv2x86.l2-effect-trace-differential-runner.v1",
            "operandAuthoritySidecarPath": "operands.json",
            "effectAuthoritySidecarPath": "effects.json",
            "comparisonPolicy": "riscv2x86.comparison-policy.architectural.v1",
        },
        "sourceRunner": {
            "command": ["qemu-system-riscv64"], "runnerKind": "qemu-system",
            "runnerId": "source-system", "runtimeVersion": "runtime-v1",
            "executionProfile": "rv64gc-system-v1", "targetExecutionMode": "emulator-only",
        },
        "targetRunner": {
            "command": ["logical-csr-runner"], "runnerKind": "x86-logical-runtime",
            "runnerId": "target-logical", "runtimeVersion": "runtime-v1",
            "executionProfile": "x86-logical-csr-v1", "targetExecutionMode": "logical-csr-runtime",
        },
        "initialStatePath": "initial.json", "privilegedManifestPath": "manifest.json",
        "csrRouteContractPath": "routes.json", "timeoutSeconds": 30,
        "requiredEnvironmentId": "auto-rv64gc-privileged-x86-v2",
    }
    payload = {
        "schemaVersion": PRIVILEGED_BINDING_SCHEMA,
        "sourceRelativePath": "csr.c",
        "sourceCapability": "qemu-system",
        "targetCapability": "logical-csr-runtime",
        "runnerConfig": runner_config,
    }
    (binding_root / "csr.c.privileged.json").write_text(json.dumps({
        **payload, "bindingIdentity": _identity(payload),
    }))

    binding = _privileged_binding(
        source, source_root, binding_root, "auto-rv64gc-privileged-x86-v2",
    )

    assert binding is not None
    assert binding["identity"] == _identity(payload)
    assert binding["config"]["requiredEnvironmentId"] == "auto-rv64gc-privileged-x86-v2"
    assert binding["config"]["initialStatePath"] == str(binding_root / "initial.json")

    frontend = tmp_path / "riscv2x86"
    frontend.write_text("#!/bin/sh\n"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda _source: (
        False, ({"name": "csr", "arity": 0, "returnType": "uint64_t",
                 "parameterTypes": [], "pointerParameters": [],
                 "l2OperandBoundary": {"complete": False}},),
    ))
    auto.prepare_automatic_inventory(
        source_root, tmp_path / "inventory", frontend=frontend,
        privileged_config_directory=binding_root,
    )
    descriptor = json.loads(next(
        (tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json")
    ).read_text())
    request = descriptor["request"]
    l2 = request["runtimeRegistryTemplate"]["validators"]["L2"]
    assert l2["type"] == "requirement-driven"
    explicit = [item for item in l2["config"]["providers"]
                if item["bindingKind"] == "explicit"]
    assert len(explicit) == 1
    assert explicit[0]["validatorType"] == "l2-privileged-real-runner"
    assert explicit[0]["dimensions"] == ["privileged_state", "trap_semantics"]
    environment = json.loads((tmp_path / "inventory/config/target-environment.json").read_text())
    assert "qemu-system" in environment["sourceRunnerCapabilities"]
    assert "logical-csr-runtime" in environment["targetRunnerCapabilities"]


def test_batch_counts_privileged_claim_boundary_without_counting_program_run_twice():
    privileged = json.dumps({
        "schemaVersion": "riscv2x86.l2-privileged-result.v2",
        "claimBoundary": "functional-privileged-observable-projection",
    })
    attempts = [{"validation": {"layers": [{
        "level": "L2", "detail": json.dumps({
            "schemaVersion": "riscv2x86.validation-dimensions.v1",
            "dimensions": {"privileged_state": {"detail": privileged}},
        }),
    }]}}]
    assert _privileged_claim_counts(attempts) == {
        "functional-privileged-observable-projection": 1,
    }
