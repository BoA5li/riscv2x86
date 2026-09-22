"""Validate and compare the frozen generated-suite baseline case by case."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping


BASELINE_SCHEMA = "riscv2x86.generated-suite-baseline.v1"
COMPARISON_SCHEMA = "riscv2x86.generated-suite-comparison.v1"
_CASE_ID = re.compile(r"case_[0-9]{3}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_STATUSES = {"verified", "failed", "inconclusive", "unsupported", "needs_route"}
_DISPOSITIONS = {"translation_coverage", "frontend_rejection"}


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _strings(value: object, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an array of non-empty strings")
    result = tuple(value)
    if result != tuple(sorted(set(result))) or (not allow_empty and not result):
        raise ValueError(label + " must be unique and canonically sorted")
    return result


def load_baseline(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    fields = {"schemaVersion", "baselineCommit", "corpusId", "description",
              "comparisonPolicy", "cases"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("generated-suite baseline fields are incomplete or unknown")
    if value.get("schemaVersion") != BASELINE_SCHEMA:
        raise ValueError("generated-suite baseline schema is unsupported")
    commit = value.get("baselineCommit")
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise ValueError("generated-suite baseline commit must be a full SHA-1")
    policy = value.get("comparisonPolicy")
    if policy != {"caseIdentity": "stable-case-prefix",
                  "invalidSourcesRemainInFrontendRejectionCoverage": True,
                  "resultSource": "batch-evaluation.json/cases",
                  "unit": "program-case"}:
        raise ValueError("generated-suite comparison policy is not the frozen policy")
    raw_cases = value.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) != 32:
        raise ValueError("generated-suite baseline must contain exactly 32 cases")
    cases = []
    for raw in raw_cases:
        required = {"caseId", "capability", "coverageDisposition", "baselineStatus",
                    "allowedFutureStatuses", "primaryCapabilityGap"}
        optional = {"observedReasonCodes", "sourceExpectation"}
        if not isinstance(raw, Mapping) or not required <= set(raw) <= required | optional:
            raise ValueError("generated-suite case fields are incomplete or unknown")
        case_id = raw.get("caseId")
        status = raw.get("baselineStatus")
        disposition = raw.get("coverageDisposition")
        if not isinstance(case_id, str) or _CASE_ID.fullmatch(case_id) is None:
            raise ValueError("generated-suite case identity is invalid")
        if status not in _STATUSES or disposition not in _DISPOSITIONS:
            raise ValueError("generated-suite case status/disposition is invalid")
        if not isinstance(raw.get("capability"), str) or not raw["capability"]:
            raise ValueError("generated-suite case capability is missing")
        gap = raw.get("primaryCapabilityGap")
        if not isinstance(gap, str) or (status != "verified" and not gap):
            raise ValueError("every non-verified case requires one primary capability gap")
        allowed = _strings(raw.get("allowedFutureStatuses"), "allowedFutureStatuses",
                           allow_empty=False)
        if status not in allowed or any(item not in _STATUSES for item in allowed):
            raise ValueError("baseline status must be an allowed future status")
        reasons = _strings(raw.get("observedReasonCodes", []), "observedReasonCodes")
        if disposition == "frontend_rejection":
            if status != "failed" or raw.get("primaryCapabilityGap") != "invalid_source_input":
                raise ValueError("frontend rejection cases must remain failed invalid inputs")
            if not isinstance(raw.get("sourceExpectation"), str) or not raw["sourceExpectation"]:
                raise ValueError("frontend rejection case needs a source expectation")
        item = dict(raw)
        item["allowedFutureStatuses"] = list(allowed)
        item["observedReasonCodes"] = list(reasons)
        cases.append(item)
    ids = tuple(item["caseId"] for item in cases)
    expected = tuple(f"case_{index:03d}" for index in range(32))
    if ids != expected:
        raise ValueError("generated-suite cases must be case_000..case_031 in order")
    result = dict(value)
    result["cases"] = cases
    return result


def _stable_case_id(value: object) -> str:
    if not isinstance(value, str):
        return ""
    match = re.match(r"^(case_[0-9]{3})(?:_|$)", value)
    return match.group(1) if match else ""


def load_batch_cases(path: str | Path) -> dict[str, dict[str, object]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    raw_cases = value.get("cases") if isinstance(value, Mapping) else None
    if not isinstance(raw_cases, list):
        raise ValueError("batch evaluation has no structured cases array")
    result: dict[str, dict[str, object]] = {}
    for raw in raw_cases:
        if not isinstance(raw, Mapping):
            raise ValueError("batch evaluation case must be an object")
        case_id = _stable_case_id(raw.get("caseId"))
        status = raw.get("status")
        reasons = raw.get("reasonCodes", [])
        if not case_id or status not in _STATUSES:
            raise ValueError("batch evaluation case identity/status is invalid")
        if case_id in result:
            raise ValueError("batch evaluation contains duplicate stable case identity")
        if not isinstance(reasons, list) or not all(isinstance(item, str) and item for item in reasons):
            raise ValueError("batch evaluation reason codes are invalid")
        result[case_id] = {"reportedCaseId": raw["caseId"], "status": status,
                           "reasonCodes": sorted(set(reasons))}
    return result


def compare_results(baseline: Mapping[str, object], actual: Mapping[str, Mapping[str, object]],
                    *, mode: str = "exact") -> dict[str, object]:
    if mode not in {"exact", "progress-aware"}:
        raise ValueError("comparison mode must be exact or progress-aware")
    expected = {str(item["caseId"]): item for item in baseline["cases"]}  # type: ignore[index]
    comparisons = []
    failures = []
    for case_id in sorted(set(expected) | set(actual)):
        wanted = expected.get(case_id)
        observed = actual.get(case_id)
        if wanted is None:
            transition = "unexpected_case"
        elif observed is None:
            transition = "missing_case"
        else:
            old, new = wanted["baselineStatus"], observed["status"]
            if old == new:
                required_reasons = set(wanted.get("observedReasonCodes", []))
                present_reasons = set(observed.get("reasonCodes", []))
                transition = ("unchanged" if required_reasons <= present_reasons
                              else "baseline_reason_missing")
            elif mode == "progress-aware" and new in wanted["allowedFutureStatuses"]:
                transition = "progressed"
            else:
                transition = "unexpected_change"
        comparison = {
            "caseId": case_id,
            "baselineStatus": None if wanted is None else wanted["baselineStatus"],
            "observedStatus": None if observed is None else observed["status"],
            "capability": None if wanted is None else wanted["capability"],
            "coverageDisposition": None if wanted is None else wanted["coverageDisposition"],
            "primaryCapabilityGap": None if wanted is None else wanted["primaryCapabilityGap"],
            "transition": transition,
        }
        comparisons.append(comparison)
        if transition not in ({"unchanged"} if mode == "exact" else {"unchanged", "progressed"}):
            failures.append({"caseId": case_id, "transition": transition})
    counts = Counter(item["observedStatus"] for item in comparisons
                     if isinstance(item["observedStatus"], str))
    payload = {
        "schemaVersion": COMPARISON_SCHEMA,
        "baselineCommit": baseline["baselineCommit"],
        "corpusId": baseline["corpusId"],
        "mode": mode,
        "integrityStatus": "verified" if not failures else "failed",
        "caseCount": len(comparisons),
        "observedStatusCounts": dict(sorted(counts.items())),
        "failures": failures,
        "cases": comparisons,
        "comparisonIdentity": "",
    }
    identity_value = dict(payload)
    identity_value.pop("comparisonIdentity")
    payload["comparisonIdentity"] = _identity(identity_value)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-generated-suite-baseline")
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--batch-result", required=True)
    parser.add_argument("--output")
    parser.add_argument("--mode", choices=("exact", "progress-aware"), default="exact")
    args = parser.parse_args()
    try:
        baseline = load_baseline(args.baseline)
        result = compare_results(baseline, load_batch_cases(args.batch_result), mode=args.mode)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        print(json.dumps({"comparisonIdentity": result["comparisonIdentity"],
                          "integrityStatus": result["integrityStatus"],
                          "caseCount": result["caseCount"],
                          "observedStatusCounts": result["observedStatusCounts"]}, sort_keys=True))
        return 0 if result["integrityStatus"] == "verified" else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"integrityStatus": "failed",
                          "reasonCode": "generated-suite.baseline-invalid",
                          "detail": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
