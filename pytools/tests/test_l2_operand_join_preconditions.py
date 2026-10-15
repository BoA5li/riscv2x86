from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

import riscv2x86_py.automatic_l2_operand as provider
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.validation_status import PreservationMode
from tests.test_l2_fragment_execution_authority import _findings, _function


@pytest.mark.parametrize("field,value,reason", [
    ("operandId", "foreign", "IDENTITY_MISMATCH"),
    ("operandIndex", 99, "INDEX_MISMATCH"),
    ("declarationId", "foreign", "DECLARATION_IDENTITY_MISMATCH"),
    ("valueNodeIdentity", "", "VALUE_NODE_IDENTITY_MISSING"),
    ("valueNodeIdentity", "sha256:" + "a" * 64, "VALUE_NODE_IDENTITY_MISMATCH"),
    ("accessMode", "input", "ACCESS_MODE_MISMATCH"),
    ("widthBits", 32, "WIDTH_MISMATCH"),
    ("signedness", "signed", "SIGNEDNESS_MISMATCH"),
    ("parameterIndex", 7, "PARAMETER_INDEX_MISMATCH"),
    ("tiedToOperandId", "foreign", "TIED_OPERAND_MISMATCH"),
])
def test_field_mismatch_prevents_all_provider_work(tmp_path, monkeypatch, field, value, reason):
    findings, function = _findings(), _function()
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": findings}, [function], frontend) == 2
    finding = findings[0]
    approval = finding["approvalArtifact"]
    sidecar = l2_authority_sidecar_from_dict(approval["l2AuthoritySidecar"])
    artifact = SimpleNamespace(
        fragment_id=finding["fragment"]["id"],
        preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
        shell_facts_identity=sidecar.shell_fact_identity,
        proof_identity=approval["proofIdentity"],
        l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity,
    )
    approval["l2AuthoritySidecar"]["operands"][0][field] = value
    source = tmp_path / "source.c"; source.write_text("int f(void){return 0;}")
    target = tmp_path / "target.c"; target.write_bytes(source.read_bytes())
    report = tmp_path / "report.json"; report.write_text(json.dumps({"findings": findings}))
    def forbidden(*args, **kwargs):
        pytest.fail("provider work occurred after authority rejection")
    for name in ("_wrapper", "_run", "_traces", "_sample_observations",
                 "provider_evidence_fields"):
        monkeypatch.setattr(provider, name, forbidden)
    validator = provider.build_auto_l2_operand_validator({
        "schemaVersion": provider.AUTO_L2_OPERAND_SCHEMA,
        "sourcePath": str(source), "sourceDigest": provider._digest_bytes(source.read_bytes()),
        "targetPath": str(target), "targetDigest": provider._digest_bytes(target.read_bytes()),
        "translatedReport": str(report), "functions": [function],
        "workDirectory": str(tmp_path / "work"),
        "replayDirectory": str(tmp_path / "replay"),
        "timeoutSeconds": 1, "seed": 0, "qemuBinary": "/missing/qemu",
    })
    result = validator(level=ValidationLevel.L2, translation_artifact=artifact,
                       comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    detail = json.loads(result.detail)
    assert detail["reasonCode"] == "L2_OPERAND_" + reason
    assert detail["executionDisposition"] == "precondition_rejected"
    assert detail["evidenceProductionDisposition"] == "not_produced"
    assert detail["failureStage"] == "authority_join"
    assert not (tmp_path / "work").exists()


@pytest.mark.parametrize("field,reason", [
    ("observationSinkIdentity", "L2_OPERAND_OBSERVATION_SINK_IDENTITY_MISMATCH"),
    ("consumerValueNodeIdentity", "L2_OPERAND_DEPENDENCY_IDENTITY_MISMATCH"),
    ("valueFlowEdgeIdentity", "L2_OPERAND_DEPENDENCY_IDENTITY_MISMATCH"),
])
def test_observation_route_has_precise_preexecution_reason(tmp_path, field, reason):
    findings = _findings()
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    materialize_automatic_l2_authority({"findings": findings}, [_function()], frontend)
    finding = findings[0]; approval = finding["approvalArtifact"]
    sidecar = l2_authority_sidecar_from_dict(approval["l2AuthoritySidecar"])
    approval["l2OperandObservationAuthority"]["bindings"][0][field] = "sha256:" + "e" * 64
    authority, actual = provider._authority(finding, [_function()], SimpleNamespace(
        fragment_id=finding["fragment"]["id"], proof_identity=approval["proofIdentity"],
        shell_facts_identity=sidecar.shell_fact_identity,
        l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity))
    assert authority is None
    assert actual == reason


@pytest.mark.parametrize("mutation,expected", [
    ("proof", "L2_OPERAND_PROOF_IDENTITY_MISMATCH"),
    ("graph", "L2_OPERAND_DEPENDENCY_IDENTITY_MISMATCH"),
])
def test_proof_and_graph_mutations_have_distinct_roots(tmp_path, mutation, expected):
    findings = _findings()
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    materialize_automatic_l2_authority({"findings": findings}, [_function()], frontend)
    finding = findings[0]; approval = finding["approvalArtifact"]
    sidecar = l2_authority_sidecar_from_dict(approval["l2AuthoritySidecar"])
    artifact = SimpleNamespace(fragment_id=finding["fragment"]["id"],
        proof_identity=approval["proofIdentity"], shell_facts_identity=sidecar.shell_fact_identity,
        l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity)
    if mutation == "proof":
        approval["l2CanonicalOperandBindings"]["proofIdentity"] = "sha256:" + "f" * 64
    else:
        approval["l2FragmentDependencyGraph"]["edges"][0]["consumerValueNodeIdentity"] = "sha256:" + "f" * 64
    value, reason = provider._authority(finding, [_function()], artifact)
    assert value is None
    assert reason == expected
