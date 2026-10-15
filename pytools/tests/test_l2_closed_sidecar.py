from dataclasses import replace
from copy import deepcopy

import pytest

from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_authority import (
    L2_CLOSED_AUTHORITY_SIDECAR_SCHEMA, l2_authority_sidecar_from_dict,
)
from tests.test_l2_fragment_execution_authority import _findings, _function


def _materialized(tmp_path):
    findings = _findings()
    frontend = tmp_path / "frontend"
    frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": findings}, [_function()], frontend) == 2
    return findings


def test_production_sidecar_and_observation_use_identical_value_nodes(tmp_path):
    for finding in _materialized(tmp_path):
        approval = finding["approvalArtifact"]
        sidecar = l2_authority_sidecar_from_dict(approval["l2AuthoritySidecar"])
        assert sidecar.schema_version == L2_CLOSED_AUTHORITY_SIDECAR_SCHEMA
        observation = sidecar.operand_observation_authority
        assert observation.to_dict() == approval["l2OperandObservationAuthority"]
        bindings = {item.operand_index: item for item in observation.bindings}
        for fact in sidecar.operands:
            assert fact.value_node_identity
            assert fact.value_node_identity == bindings[fact.operand_index].value_node_identity
        assert l2_authority_sidecar_from_dict(sidecar.to_dict()) == sidecar


def test_sink_or_dependency_changes_sidecar_identity(tmp_path):
    approval = _materialized(tmp_path)[0]["approvalArtifact"]
    original = l2_authority_sidecar_from_dict(approval["l2AuthoritySidecar"])
    observation = original.operand_observation_authority
    output, *rest = observation.bindings
    assert output.closure_kind == "consumer"
    for field in ("observation_sink_identity", "consumer_value_node_identity",
                  "value_flow_edge_identity"):
        changed = replace(output, **{field: "sha256:" + "a" * 64})
        new_observation = replace(observation, bindings=(changed, *rest))
        new_sidecar = replace(original, operand_observation_authority=new_observation,
                              authority_identity="")
        assert new_sidecar.authority_identity != original.authority_identity


def test_observation_mismatch_and_stale_identity_are_rejected(tmp_path):
    raw = _materialized(tmp_path)[0]["approvalArtifact"]["l2AuthoritySidecar"]
    original = l2_authority_sidecar_from_dict(raw)
    observation = original.operand_observation_authority
    first, *rest = observation.bindings
    changed = replace(first, value_node_identity="sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="operand binding mismatch"):
        replace(original, authority_identity="", operand_observation_authority=
                replace(observation, bindings=(changed, *rest)))
    tampered = deepcopy(raw)
    tampered["schemaVersion"] = "riscv2x86.l2-authority-sidecar.v3"
    with pytest.raises(ValueError, match="fields"):
        l2_authority_sidecar_from_dict(tampered)
