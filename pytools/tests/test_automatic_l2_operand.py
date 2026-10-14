from __future__ import annotations

from riscv2x86_py.automatic_l2_operand import (
    AUTO_L2_FAILURE_SCHEMA,
    L2OperandFailureStage,
    _authority,
    build_auto_l2_operand_validator,
    _digest_bytes,
    _failure_result,
    _load_shared_execution,
    _save_shared_execution,
    _traces,
    _wrapper,
)
from riscv2x86_py.l2_evidence_closure import L2ProviderExecutionDisposition
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.translation_validation import TranslationArtifact
from riscv2x86_py.validation_status import PreservationMode
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from types import SimpleNamespace
import tempfile
import json
import subprocess
from pathlib import Path
from tests.l2_profile_fixtures import profile_dict
from tests.l2_effect_proof_fixtures import attach_effect_proof


def _artifact():
    return TranslationArtifact(
        "fragment", "model", "plan", "constraint", "proof",
        PreservationMode.ARCHITECTURE_EQUIVALENT, "sha256:" + "1" * 64,
        "riscv2x86.runtime.none", "v1", "recipe", (), "integer", "x86",
    )


def _function():
    return {
        "name": "add", "arity": 2, "returnType": "uint64_t",
        "parameterTypes": ["uint64_t", "uint64_t"],
        "l2OperandBoundary": {
            "schemaVersion": "riscv2x86.compiler-operand-boundary.v1", "complete": True,
            "parameterDeclarationIds": ["lhs-id", "rhs-id"],
            "asmOperandDeclarationIds": ["out-id", "lhs-id", "rhs-id"],
            "returnDeclarationId": "out-id",
            "declarationReferenceCounts": {"out-id": 2, "lhs-id": 1, "rhs-id": 1},
            "declarations": {
                "out-id": {"name": "out", "type": "uint64_t"},
                "lhs-id": {"name": "lhs", "type": "uint64_t"},
                "rhs-id": {"name": "rhs", "type": "uint64_t"},
            },
        },
    }


def test_authority_joins_compiler_boundary_and_frontend_shell():
    finding = {
        "fragment": {"id": "fragment", "enclosingFunction": "add",
                     "outputs": [{"constraint": "=&r", "symbolicName": "dst",
                                  "isEarlyClobber": True}],
                     "inputs": [{"constraint": "r", "symbolicName": "lhs"},
                                {"constraint": "r", "symbolicName": "rhs"}]},
        "approvalArtifact": {"proofStatus": "approved"},
        "l2SemanticProfile": profile_dict("fragment"),
    }
    artifact = _artifact()
    finding["approvalArtifact"].update({
        "architectureSemanticsPreserved": True,
        "shellSemanticsPreserved": True,
        "sourceModelId": "model",
        "constraintsId": "constraint",
        "preservationDecisionId": "decision",
        "planId": "plan",
        "targetEnvironmentId": "environment",
        "targetCatalogVersion": "catalog",
    })
    attach_effect_proof(finding["approvalArtifact"], "fragment")
    report = {"findings": [finding]}
    with tempfile.NamedTemporaryFile() as producer:
        assert materialize_automatic_l2_authority(
            report, [_function()], Path(producer.name),
        ) == 1
    sidecar = finding["approvalArtifact"]["l2AuthoritySidecar"]
    artifact_fields = dict(artifact.__dict__)
    artifact_fields.update(
        shell_facts_identity=sidecar["shellFactIdentity"],
        proof_identity=finding["approvalArtifact"]["proofIdentity"],
        l2_authority_identity=sidecar["authorityIdentity"],
        effect_relation_set_identity=__import__(
            "riscv2x86_py.l2_authority", fromlist=["l2_authority_sidecar_from_dict"]
        ).l2_authority_sidecar_from_dict(sidecar).effect_relation_set_identity,
        l2_authority_complete=True,
    )
    artifact = SimpleNamespace(**artifact_fields)
    authority, reason = _authority(finding, [_function()], artifact)
    assert reason == "" and authority is not None
    assert authority["operands"][0]["earlyClobber"] is True
    assert authority["operands"][0]["targetContractCarriedByProof"] is True
    assert authority["operands"][1]["declarationId"] == "lhs-id"
    assert authority["authorityIdentity"].startswith("sha256:")


def test_internal_temporary_is_inconclusive_not_silently_omitted():
    function = _function()
    function["l2OperandBoundary"]["asmOperandDeclarationIds"] = [
        "tmp-id", "out-id", "lhs-id", "rhs-id",
    ]
    function["l2OperandBoundary"]["declarations"]["tmp-id"] = {
        "name": "tmp", "type": "uint64_t",
    }
    finding = {
        "fragment": {"id": "fragment", "enclosingFunction": "add",
                     "outputs": [{"constraint": "=&r"}, {"constraint": "=r"}],
                     "inputs": [{"constraint": "r"}, {"constraint": "r"}]},
        "approvalArtifact": {"proofStatus": "approved"},
    }
    authority, reason = _authority(finding, [function], _artifact())
    assert authority is None
    assert reason == "L2_OPERAND_INTERNAL_VALUE_REQUIRES_INSTRUMENTATION"


def test_trace_parser_requires_complete_cartesian_domain():
    wrapper = _wrapper(_function())
    assert "operand_trace=add" in wrapper
    line = "operand_trace=add;0000000000000000;0000000000000001;0000000000000001\n"
    assert _traces(line, "add", 2) is None
    complete = line * 64
    assert len(_traces(complete, "add", 2)) == 64


def test_wrapper_accepts_a_zero_argument_scalar_function():
    wrapper = _wrapper({
        "name": "read_counter", "arity": 0, "returnType": "uint64_t",
        "parameterTypes": [],
    })
    assert "uint64_t read_counter(void);" in wrapper
    assert "read_counter()" in wrapper


def test_wrapper_rejects_non_scalar_signature_instead_of_casting_pointer_values():
    function = _function()
    function["parameterTypes"] = ["uint64_t *", "uint64_t"]
    try:
        _wrapper(function)
    except ValueError as exc:
        assert str(exc) == "automatic L2 scalar function type is unsupported"
    else:
        raise AssertionError("pointer signature was accepted by scalar provider")


def test_shared_execution_record_is_content_addressed_and_schema_strict(tmp_path):
    path = tmp_path / "shared.json"
    binding = {"providerId": "operand", "authorizedExecutionIdentity": "sha256:" + "1" * 64}
    run = subprocess.CompletedProcess((), 0, "trace\n", "")
    _save_shared_execution(path, binding, source=run, target=run)
    assert _load_shared_execution(path, binding)["binding"] == binding
    value = json.loads(path.read_text(encoding="utf-8"))
    value["schemaVersion"] = "unknown"
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        _load_shared_execution(path, binding)
    except ValueError as exc:
        assert "schema" in str(exc)
    else:
        raise AssertionError("foreign provider execution record was reused")


def test_infrastructure_failure_preserves_stage_exception_and_artifact_path(tmp_path):
    artifact = tmp_path / "operand-observation.json"
    result = _failure_result(
        L2OperandFailureStage.TRACE_PARSE, ValueError("bad trace"),
        artifact_path=artifact,
        disposition=L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE,
    )
    detail = json.loads(result.detail)
    assert detail == {
        "schemaVersion": AUTO_L2_FAILURE_SCHEMA,
        "executionDisposition": "executed_inconclusive",
        "evidenceProductionDisposition": "not_produced",
        "reasonCode": "L2_OPERAND_TRACE_PARSE_FAILED",
        "failureStage": "trace_parse",
        "exceptionType": "ValueError",
        "detail": "bad trace",
        "artifactPath": str(artifact),
    }


def test_validator_reports_the_exact_artifact_and_stage_for_invalid_report(tmp_path):
    source, target = tmp_path / "source.c", tmp_path / "target.c"
    report = tmp_path / "translated-report.json"
    source.write_text("int f(void){return 0;}\n", encoding="utf-8")
    target.write_text("int f(void){return 0;}\n", encoding="utf-8")
    report.write_text("{invalid", encoding="utf-8")
    validator = build_auto_l2_operand_validator({
        "schemaVersion": "riscv2x86.auto-l2-operand-runner.v1",
        "sourcePath": str(source), "sourceDigest": _digest_bytes(source.read_bytes()),
        "targetPath": str(target), "targetDigest": _digest_bytes(target.read_bytes()),
        "translatedReport": str(report), "functions": [],
        "workDirectory": str(tmp_path / "work"),
        "replayDirectory": str(tmp_path / "replay"),
        "timeoutSeconds": 1, "seed": 0, "qemuBinary": "/missing/qemu",
    })
    result = validator(
        level=ValidationLevel.L2,
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        translation_artifact=SimpleNamespace(
            preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT),
    )
    detail = json.loads(result.detail)
    assert detail["reasonCode"] == "L2_OPERAND_REPORT_INVALID"
    assert detail["executionDisposition"] == "not_executed"
    assert detail["failureStage"] == "report_load"
    assert detail["exceptionType"] == "JSONDecodeError"
    assert detail["artifactPath"] == str(report)
