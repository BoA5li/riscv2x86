import json
import subprocess
import sys

import pytest

from riscv2x86_py import automatic_translation_command as command
from riscv2x86_py.requirement_staging import verify_requirement_staging
from riscv2x86_py.schema import (
    TranslationOutcome, ValidationOutcome, save_report,
)
from riscv2x86_py.translation_attempt import (
    save_translation_attempt_archive, terminal_attempt_from_finding,
)
from tests.test_translation_attempt import _finding


@pytest.mark.parametrize("outcome,disposition", [
    (TranslationOutcome.EMITTED, "available"),
    (TranslationOutcome.NEEDS_ROUTE, "route_required"),
    (TranslationOutcome.UNSUPPORTED, "unsupported"),
    (TranslationOutcome.FAILED, "not_applicable"),
])
def test_nonzero_backend_stages_terminal_requirements(tmp_path, monkeypatch, outcome, disposition):
    report = tmp_path / "translated.json"
    plan = tmp_path / "validation-plan.json"
    plan.write_text(json.dumps({"schemaVersion": "test-plan"}))
    finding = _finding(outcome)
    if outcome is TranslationOutcome.EMITTED:
        finding.validationOutcome = ValidationOutcome.NOT_VERIFIED.value
        finding.translationAttemptArtifact["reasonCodes"] = ["validation.external-evaluation-pending"]
    def run(argv, **kwargs):
        if "-print-sysroot" in argv:
            return subprocess.CompletedProcess(argv, 0, "/test/sysroot", "")
        if "--analysis-only" in argv:
            (tmp_path / "raw_report.json").write_text("{}")
            return subprocess.CompletedProcess(argv, 0, "", "")
        save_report([finding], str(report))
        save_translation_attempt_archive(
            (terminal_attempt_from_finding(finding, 0),), str(report) + ".attempts.json")
        return subprocess.CompletedProcess(argv, 1, "", "terminal nonzero")
    monkeypatch.setattr(command.subprocess, "run", run)
    monkeypatch.setattr(command, "inspect_entry_points", lambda _: (False, ()))
    monkeypatch.setattr(command, "_inject_compiler_fragment_authority", lambda *args: None)
    monkeypatch.setattr(command, "materialize_automatic_l2_authority", lambda *args: 0)
    monkeypatch.setattr(sys, "argv", ["translation", "--frontend", "/frontend",
        "--source", str(tmp_path / "source.c"), "--source-root", str(tmp_path),
        "--report", str(report), "--validation-plan", str(plan)])
    assert command.main() == 1
    staged = verify_requirement_staging(report)
    assert staged["commandDisposition"] == "completed"
    assert staged["translationOutcome"] == outcome.value
    assert staged["l2RequirementDisposition"] == disposition
    assert staged["l3RequirementDisposition"] == disposition
    assert staged["validationPlanArtifact"] == str(plan)
    if outcome is TranslationOutcome.EMITTED:
        assert staged["publicationDisposition"] == "withheld_pending_validation"
    requirements = tmp_path / "translated.json.l2-requirements.json"
    requirements.write_text("{}")
    with pytest.raises(ValueError, match="requirement identity"):
        verify_requirement_staging(report)


def test_stale_report_is_rejected_before_launch(tmp_path, monkeypatch):
    report = tmp_path / "report.json"; report.write_text("{}")
    monkeypatch.setattr(sys, "argv", ["translation", "--frontend", "/frontend",
        "--source", "source.c", "--source-root", str(tmp_path), "--report", str(report)])
    monkeypatch.setattr(command.subprocess, "run", lambda *a, **k: pytest.fail("stale output executed"))
    assert command.main() == 2
