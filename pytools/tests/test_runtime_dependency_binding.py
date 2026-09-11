"""Runtime dependency injection contract tests."""
from __future__ import annotations

import json

import pytest

from riscv2x86_py.runtime_dependency_binding import dependencies_from_translated_report


def _runtime_tree(tmp_path):
    (tmp_path / "runtime/include").mkdir(parents=True)
    (tmp_path / "runtime/include/riscv2x86_runtime_helpers.h").write_text("void h(void);\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build/libriscv2x86_runtime.a").write_bytes(b"archive")


def _report(headers=None, libraries=None):
    return {"findings": [{"translationOutcome": "functional_fallback",
        "approvalArtifact": {
            "runtimeContractId": "riscv2x86_rt_instruction_stream_sync_local@v1",
            "requiredHeaders": (["riscv2x86_runtime_helpers.h"] if headers is None else headers),
            "requiredLibraries": (["libriscv2x86_runtime"] if libraries is None else libraries),
        }}]}


def test_report_runtime_dependencies_resolve_to_shipped_artifacts(tmp_path):
    _runtime_tree(tmp_path)
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report()))
    value = dependencies_from_translated_report(report, root=tmp_path)
    assert value.headers == ("riscv2x86_runtime_helpers.h",)
    assert value.libraries == ("riscv2x86_runtime",)
    assert value.library_paths == (str(tmp_path / "build/libriscv2x86_runtime.a"),)


def test_report_runtime_declaration_mismatch_fails_closed(tmp_path):
    _runtime_tree(tmp_path)
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(headers=[])))
    with pytest.raises(ValueError, match="dependency mismatch"):
        dependencies_from_translated_report(report, root=tmp_path)


def test_unregistered_runtime_contract_fails_closed(tmp_path):
    _runtime_tree(tmp_path)
    value = _report()
    value["findings"][0]["approvalArtifact"]["runtimeContractId"] = "unknown@v1"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="unregistered runtime contract"):
        dependencies_from_translated_report(report, root=tmp_path)


def test_legacy_helper_dependency_schema_is_normalized(tmp_path):
    _runtime_tree(tmp_path)
    value = _report()
    approval = value["findings"][0]["approvalArtifact"]
    approval.pop("requiredHeaders")
    approval.pop("requiredLibraries")
    approval["helperRequiredHeader"] = "riscv2x86_runtime_helpers.h"
    approval["helperRuntimeLibrary"] = "libriscv2x86_runtime"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(value))
    resolved = dependencies_from_translated_report(report, root=tmp_path)
    assert resolved.headers == ("riscv2x86_runtime_helpers.h",)
    assert resolved.libraries == ("riscv2x86_runtime",)


def test_conflicting_canonical_and_legacy_dependencies_fail_closed(tmp_path):
    _runtime_tree(tmp_path)
    value = _report()
    approval = value["findings"][0]["approvalArtifact"]
    approval["helperRequiredHeader"] = "wrong.h"
    approval["helperRuntimeLibrary"] = "libriscv2x86_runtime"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="declarations conflict"):
        dependencies_from_translated_report(report, root=tmp_path)
