import subprocess
import sys
from pathlib import Path

import pytest

from riscv2x86_py import automatic_translation_command as command
from riscv2x86_py.requirement_staging import verify_requirement_staging
from riscv2x86_py.schema import TranslationOutcome, save_report
from riscv2x86_py.translation_attempt import save_translation_attempt_archive, terminal_attempt_from_finding
from tests.test_translation_attempt import _finding


@pytest.mark.parametrize("fault", ["published", "crash", "malformed_report", "classification_failure"])
def test_backend_lifecycle_never_publishes_partial_requirement_bundle(tmp_path, monkeypatch, fault):
    report = tmp_path / "report.json"
    finding = _finding(TranslationOutcome.EMITTED)
    finding.validationOutcome = "verified"
    finding.publicationOutcome = "admitted"
    finding.translationAttemptArtifact["reasonCodes"] = []
    def run(argv, **kwargs):
        if "-print-sysroot" in argv:
            return subprocess.CompletedProcess(argv, 0, "/test/sysroot", "")
        if "--analysis-only" in argv:
            (tmp_path / "raw_report.json").write_text("{}")
            return subprocess.CompletedProcess(argv, 0, "", "")
        save_report([finding], str(report))
        save_translation_attempt_archive((terminal_attempt_from_finding(finding, 0),),
                                         str(report) + ".attempts.json")
        if fault == "malformed_report": report.write_text("{")
        return subprocess.CompletedProcess(argv, -11 if fault == "crash" else 0, "", "")
    monkeypatch.setattr(command.subprocess, "run", run)
    monkeypatch.setattr(command, "inspect_entry_points", lambda _: (False, ()))
    monkeypatch.setattr(command, "_inject_compiler_fragment_authority", lambda *a: None)
    monkeypatch.setattr(command, "materialize_automatic_l2_authority", lambda *a: 0)
    if fault == "classification_failure":
        def fail(*a): raise ValueError("classifier rejected semantic authority")
        monkeypatch.setattr(command, "classify_l2_requirements", fail)
    monkeypatch.setattr(sys, "argv", ["translation", "--frontend", "/frontend",
        "--source", "source.c", "--source-root", str(tmp_path), "--report", str(report)])
    status = command.main()
    if fault == "published":
        assert status == 0
        assert verify_requirement_staging(report)["publicationDisposition"] == "published"
    else:
        assert status != 0
        assert not Path(str(report) + ".requirement-staging.json").exists()
