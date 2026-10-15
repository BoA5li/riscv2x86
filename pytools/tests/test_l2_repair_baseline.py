from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "experiment" / "baselines" / "phase43-l2-before-authority-v3.json"
SCRIPT = ROOT / "pytools" / "archive_l2_repair_baseline.py"


def _module():
    spec = importlib.util.spec_from_file_location("archive_l2_repair_baseline", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_phase43_l2_baseline_is_machine_readable_and_self_consistent():
    value = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert value["schemaVersion"] == "riscv2x86.l2-repair-baseline.v1"
    assert value["source"]["caseCount"] == 32
    expected = value["expected"]
    scalar_cases = expected["scalarMismatchCases"]
    assert expected["l2RequiredCaseCount"] == (
        expected["l2VerifiedCaseCount"] + expected["l2InconclusiveCaseCount"]
    )
    assert expected["scalarMismatchCount"] == len(scalar_cases) == 19
    assert scalar_cases == sorted(set(scalar_cases))
    assert expected["fenceCase"] not in scalar_cases
    assert len(value["independentFailureClasses"]) == 2


def test_baseline_contract_is_not_imported_by_production_package():
    production = ROOT / "pytools" / "riscv2x86_py"
    needle = BASELINE.name
    assert all(
        needle not in path.read_text(encoding="utf-8")
        for path in production.glob("*.py")
    )


def test_dimension_archive_deduplicates_without_losing_evidence_fields():
    module = _module()
    row = {
        "fragmentId": "fragment:0",
        "dimension": "logical_operands",
        "required": True,
        "status": "inconclusive",
        "authorityIdentity": "sha256:" + "1" * 64,
        "effectRelationIdentity": "",
        "executionIdentity": "",
        "sourceObservationIdentity": "",
        "targetObservationIdentity": "",
        "reasonCodes": ["L2_OPERAND_OBSERVATION_BINDING_MISMATCH"],
    }
    batch = {"first": row, "duplicate": dict(row)}
    assert module.dimension_rows(batch) == [row]


def test_archive_contract_contains_required_scalar_and_fence_evidence():
    value = json.loads(BASELINE.read_text(encoding="utf-8"))
    artifacts = set(value["archiveContract"]["requiredArtifacts"])
    assert {
        "batch-evaluation.json",
        "scalar-dimension-results.json",
        "representative-operand-authority.json",
        "case_006/evaluation-result.json",
        "case_006/translated_report.json",
        "case_006/translated_report.json.attempts.json",
        "case_006/frontend.stderr",
        "case_006/backend.stderr",
        "provenance.json",
        "baseline-verification.json",
    } <= artifacts
