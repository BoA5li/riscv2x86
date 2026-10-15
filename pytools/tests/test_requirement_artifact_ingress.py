import json
from pathlib import Path

import pytest

from riscv2x86_py import evaluation
from riscv2x86_py.requirement_staging import (
    atomic_json, content_identity, read_staged_requirements,
    write_requirement_staging, RequirementArtifactError,
)
from riscv2x86_py.l2_eligibility import classify_l2_requirements
from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
from riscv2x86_py.schema import TranslationOutcome, save_report
from riscv2x86_py.translation_attempt import save_translation_attempt_archive, terminal_attempt_from_finding
from tests.test_translation_attempt import _finding
from tests.test_evaluation_runner import _setup


def _staged(tmp_path):
    report = tmp_path / "report.json"
    finding = _finding(TranslationOutcome.EMITTED)
    finding.validationOutcome = "not_verified"
    finding.translationAttemptArtifact["reasonCodes"] = ["validation.external-evaluation-pending"]
    save_report([finding], str(report))
    save_translation_attempt_archive((terminal_attempt_from_finding(finding, 0),),
                                     str(report) + ".attempts.json")
    value = json.loads(report.read_text())
    atomic_json(str(report) + ".l2-requirements.json", classify_l2_requirements(value))
    atomic_json(str(report) + ".l3-requirements.json", classify_l3_requirements(value).to_dict())
    write_requirement_staging(report, returncode=1)
    return report


def test_available_pending_requirements_pass_all_checks(tmp_path):
    report = _staged(tmp_path)
    artifacts = read_staged_requirements(report)
    assert artifacts["l2"]["schemaVersion"] == "riscv2x86.l2-requirement-manifest.v3"
    assert artifacts["l3"]["schemaVersion"] == "riscv2x86.l3-requirement-manifest.v1"


@pytest.mark.parametrize("fault", ["missing_marker", "missing_l2", "bad_json", "wrong_path", "wrong_schema", "wrong_identity", "wrong_report", "wrong_disposition"])
def test_artifact_ingress_preserves_original_failure(tmp_path, fault):
    report = _staged(tmp_path)
    marker = Path(str(report) + ".requirement-staging.json")
    l2 = Path(str(report) + ".l2-requirements.json")
    value = json.loads(marker.read_text())
    if fault == "missing_marker": marker.unlink()
    elif fault == "missing_l2": l2.unlink()
    elif fault == "bad_json": l2.write_text("{")
    elif fault == "wrong_path": value["l2RequirementArtifact"] = "/foreign"
    elif fault == "wrong_disposition": value["l2RequirementDisposition"] = "unsupported"
    elif fault == "wrong_identity": l2.write_text("{}")
    elif fault == "wrong_report": report.write_text("{}")
    elif fault == "wrong_schema":
        payload = json.loads(l2.read_text()); payload["schemaVersion"] = "foreign"
        atomic_json(l2, payload); value["l2RequirementIdentity"] = content_identity(payload)
    if fault not in {"missing_marker"}:
        value.pop("stagingIdentity"); value["stagingIdentity"] = content_identity(value)
        atomic_json(marker, value)
    with pytest.raises(RequirementArtifactError) as caught:
        read_staged_requirements(report)
    detail = caught.value.detail
    assert detail["failureStage"] == "requirement_staging"
    assert detail["artifactPath"]
    assert detail["exceptionType"]
    assert {"schemaVersion", "expectedSchema", "actualSchema",
            "expectedIdentity", "actualIdentity", "detail"}.issubset(detail)


def test_missing_requirements_return_inconclusive_before_build(tmp_path, monkeypatch):
    request, _, _ = _setup(tmp_path)
    def checked(*args, **kwargs):
        read_staged_requirements(Path(request.translated_report))
    monkeypatch.setattr(evaluation, "_materialize_l2_resolution_plans", checked)
    result = evaluation.run_evaluation(request, work_directory=tmp_path / "work")
    assert result["status"] == "inconclusive"
    assert result["reasonCodes"] == ["evaluation.l2-requirement-artifact-production-failed"]
    assert result["requirementStagingFailure"]["exceptionType"] == "FileNotFoundError"
    assert result["commands"] == []


@pytest.mark.parametrize("outcome", [TranslationOutcome.NEEDS_ROUTE, TranslationOutcome.UNSUPPORTED, TranslationOutcome.FAILED])
def test_nonemitted_terminals_never_read_requirements(tmp_path, monkeypatch, outcome):
    request, _, _ = _setup(tmp_path, translation_outcome=outcome)
    monkeypatch.setattr(evaluation, "_materialize_l2_resolution_plans",
                        lambda *a, **k: pytest.fail("terminal entered L2"))
    result = evaluation.run_evaluation(request, work_directory=tmp_path / "work")
    assert result["status"] == outcome.value
    assert not result["commands"]
