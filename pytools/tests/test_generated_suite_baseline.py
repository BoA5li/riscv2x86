import json
from pathlib import Path

import pytest

from riscv2x86_py.generated_suite_baseline import (
    compare_results, load_baseline, load_batch_cases,
)


BASELINE = (Path(__file__).parents[2] / "experiment" / "baselines" /
            "generated-suite-phase16.json")


def _actual(baseline):
    return {
        item["caseId"]: {"reportedCaseId": item["caseId"],
                         "status": item["baselineStatus"],
                         "reasonCodes": item.get("observedReasonCodes", [])}
        for item in baseline["cases"]
    }


def test_frozen_baseline_accounts_for_all_cases_and_denominators():
    baseline = load_baseline(BASELINE)
    statuses = {}
    for item in baseline["cases"]:
        statuses[item["baselineStatus"]] = statuses.get(item["baselineStatus"], 0) + 1
    assert statuses == {"verified": 21, "inconclusive": 3, "unsupported": 4,
                        "failed": 2, "needs_route": 2}
    rejected = [item for item in baseline["cases"]
                if item["coverageDisposition"] == "frontend_rejection"]
    assert [item["caseId"] for item in rejected] == ["case_023", "case_026"]
    assert all(item["primaryCapabilityGap"] == "invalid_source_input" for item in rejected)
    non_verified = [item for item in baseline["cases"] if item["baselineStatus"] != "verified"]
    assert len(non_verified) == 11
    assert all(item["primaryCapabilityGap"] for item in non_verified)


def test_exact_comparison_accepts_non_verified_frozen_states():
    baseline = load_baseline(BASELINE)
    result = compare_results(baseline, _actual(baseline), mode="exact")
    assert result["integrityStatus"] == "verified"
    assert result["observedStatusCounts"] == {
        "failed": 2, "inconclusive": 3, "needs_route": 2,
        "unsupported": 4, "verified": 21,
    }


def test_comparison_reports_missing_and_unexpected_cases_individually():
    baseline = load_baseline(BASELINE)
    actual = _actual(baseline)
    del actual["case_004"]
    actual["case_999"] = {"reportedCaseId": "case_999", "status": "verified",
                          "reasonCodes": []}
    result = compare_results(baseline, actual)
    assert result["integrityStatus"] == "failed"
    assert result["failures"] == [
        {"caseId": "case_004", "transition": "missing_case"},
        {"caseId": "case_999", "transition": "unexpected_case"},
    ]


def test_progress_aware_mode_accepts_declared_progress_but_not_invalid_source_acceptance():
    baseline = load_baseline(BASELINE)
    actual = _actual(baseline)
    actual["case_004"]["status"] = "verified"
    actual["case_004"]["reasonCodes"] = []
    assert compare_results(baseline, actual, mode="exact")["integrityStatus"] == "failed"
    progressed = compare_results(baseline, actual, mode="progress-aware")
    assert progressed["integrityStatus"] == "verified"
    actual["case_023"]["status"] = "verified"
    assert compare_results(baseline, actual, mode="progress-aware")["integrityStatus"] == "failed"


def test_unchanged_non_verified_case_requires_frozen_observed_reason():
    baseline = load_baseline(BASELINE)
    actual = _actual(baseline)
    actual["case_030"]["reasonCodes"] = []
    result = compare_results(baseline, actual)
    assert result["failures"] == [
        {"caseId": "case_030", "transition": "baseline_reason_missing"}
    ]


def test_batch_case_loader_uses_stable_prefix_and_rejects_duplicates(tmp_path):
    path = tmp_path / "batch-evaluation.json"
    path.write_text(json.dumps({"cases": [
        {"caseId": "case_000_6deaa092ec", "status": "verified", "reasonCodes": []},
        {"caseId": "case_004_db41060b70", "status": "inconclusive",
         "reasonCodes": ["L2_MEMORY_OPERAND_BOUNDARY_INCOMPLETE"]},
    ]}))
    assert set(load_batch_cases(path)) == {"case_000", "case_004"}
    path.write_text(json.dumps({"cases": [
        {"caseId": "case_000_a", "status": "verified", "reasonCodes": []},
        {"caseId": "case_000_b", "status": "verified", "reasonCodes": []},
    ]}))
    with pytest.raises(ValueError, match="duplicate stable case"):
        load_batch_cases(path)


def test_baseline_rejects_count_or_noncanonical_case_identity(tmp_path):
    value = json.loads(BASELINE.read_text())
    value["cases"] = value["cases"][:-1]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="exactly 32"):
        load_baseline(path)
