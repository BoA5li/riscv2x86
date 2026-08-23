from __future__ import annotations

import json
import sys

import pytest

from riscv2x86_py import cli
from riscv2x86_py.privileged_pipeline_inputs import (
    PRIVILEGED_IGNORED_STATE_SIDECAR_SCHEMA,
    PRIVILEGED_OBSERVABILITY_SIDECAR_SCHEMA,
    load_privileged_pipeline_inputs,
    privileged_functional_registry_from_dict,
    privileged_ignored_state_sidecar_from_dict,
    privileged_observability_sidecar_from_dict,
    privileged_runtime_registry_from_dict,
)
from riscv2x86_py.privileged_execution_sidecar import (
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA,
)
from riscv2x86_py.privileged_functional_contracts import (
    PRIVILEGED_FUNCTIONAL_REGISTRY_SCHEMA,
)
from riscv2x86_py.privileged_runtime_contracts import (
    PRIVILEGED_RUNTIME_REGISTRY_SCHEMA,
)


def test_registry_loaders_require_versioned_schema_and_reject_duplicates():
    runtime = {
        "schemaVersion": PRIVILEGED_RUNTIME_REGISTRY_SCHEMA,
        "version": "runtime.test.v1",
        "contracts": [{
            "contractId": "counter.strict",
            "semanticVersion": "1",
            "sourcePrivilegedIdentity": "sha256:source",
            "targetEnvironmentId": "x86_64:sysv_amd64:gnu_att",
            "runtimeSymbol": "rv2x86_counter",
            "requiredTargetCapability": "runtime:counter",
        }],
    }
    loaded = privileged_runtime_registry_from_dict(runtime)
    assert loaded.version == "runtime.test.v1"
    runtime["contracts"].append(dict(runtime["contracts"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        privileged_runtime_registry_from_dict(runtime)


def test_functional_registry_flag_does_not_create_contract():
    inputs = load_privileged_pipeline_inputs(
        execution_sidecar_path=None,
        runtime_registry_path=None,
        functional_registry_path=None,
        observability_sidecar_path=None,
        ignored_state_declarations_path=None,
        allow_functional_fallbacks=True,
    )
    assert inputs.preservation_policy.enabled
    assert inputs.functional_registry is None

    loaded = privileged_functional_registry_from_dict({
        "schemaVersion": PRIVILEGED_FUNCTIONAL_REGISTRY_SCHEMA,
        "version": "functional.test.v1",
        "contracts": [],
    })
    assert loaded.version == "functional.test.v1"


def test_observability_and_ignored_state_sidecars_are_exact_and_typed():
    observability = privileged_observability_sidecar_from_dict({
        "schemaVersion": PRIVILEGED_OBSERVABILITY_SIDECAR_SCHEMA,
        "provenance": "clang-plugin:test",
        "fragments": [{
            "fragmentId": "frag-1",
            "sourceExecutionProfile": "riscv_user_process",
            "observableContractId": "counter-observation.v1",
            "declaredIgnoredStateIds": ["csr:riscv.csr.cycle@0x1000:0:state"],
            "complete": True,
        }],
    })
    assert observability.declaration_for("frag-1") is not None
    assert observability.declaration_for("frag-other") is None

    ignored = privileged_ignored_state_sidecar_from_dict({
        "schemaVersion": PRIVILEGED_IGNORED_STATE_SIDECAR_SCHEMA,
        "provenance": "corpus:test",
        "fragments": [{
            "fragmentId": "frag-1",
            "complete": True,
            "declarations": [{
                "stateId": "csr:riscv.csr.cycle@0x1000:0:state",
                "kind": "csr",
                "justification": "counter state is observation-only",
                "complete": True,
            }],
        }],
    })
    assert ignored.declarations_for("frag-1")[0].kind.value == "csr"


def test_membership_validation_reports_stable_reason(tmp_path):
    path = tmp_path / "execution.json"
    path.write_text(json.dumps({
        "schemaVersion": PRIVILEGED_EXECUTION_SIDECAR_SCHEMA,
        "provenance": "clang-plugin:test",
        "fragments": [],
    }), encoding="utf-8")
    inputs = load_privileged_pipeline_inputs(
        execution_sidecar_path=path,
        runtime_registry_path=None,
        functional_registry_path=None,
        observability_sidecar_path=None,
        ignored_state_declarations_path=None,
        allow_functional_fallbacks=False,
    )
    assert inputs.validate_fragment_membership(("frag-1",)) == ()


def test_cli_constructs_privileged_pipeline_inputs(monkeypatch, tmp_path):
    execution = tmp_path / "execution.json"
    execution.write_text(json.dumps({
        "schemaVersion": PRIVILEGED_EXECUTION_SIDECAR_SCHEMA,
        "provenance": "clang-plugin:test",
        "fragments": [],
    }), encoding="utf-8")
    captured = {}

    monkeypatch.setattr(
        cli, "load_riscv_register_resolver_via_pythonrun", lambda **_: object()
    )
    monkeypatch.setattr(
        cli,
        "run",
        lambda *args, **kwargs: captured.update(kwargs) or {"failed": 0},
    )
    monkeypatch.setattr(sys, "argv", [
        "riscv2x86-py",
        "--in", str(tmp_path / "in.json"),
        "--out", str(tmp_path / "out.json"),
        "--privileged-execution-sidecar", str(execution),
        "--allow-functional-fallbacks",
    ])
    assert cli.main() == 0
    inputs = captured["privileged_pipeline_inputs"]
    assert inputs.execution_sidecar is not None
    assert inputs.preservation_policy.enabled
    assert inputs.functional_registry is None
