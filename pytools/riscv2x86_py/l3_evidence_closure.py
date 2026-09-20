"""Fail-closed L3 property evidence and program-level experimental scope."""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

DIMENSION_SCHEMA = "riscv2x86.l3-dimension-result.v1"
FRAGMENT_SCHEMA = "riscv2x86.l3-fragment-result.v1"
PROGRAM_SCHEMA = "riscv2x86.l3-program-result.v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCOPES = {"architectural_intent", "target_experiment_diagnostic"}
_STATUSES = {"verified", "failed", "inconclusive", "not_run"}


def identity(value: object) -> str:
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode("utf-8")).hexdigest()


def _sha(value: object, label: str) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ValueError(label + " identity missing or invalid")


def _checked(value: object, schema: str, fields: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields | {"resultIdentity"} or value.get("schemaVersion") != schema:
        raise ValueError(label + " schema/fields invalid")
    result = dict(value)
    _sha(result.pop("resultIdentity"), label)
    if identity(result) != value["resultIdentity"]:
        raise ValueError(label + " content identity mismatch")
    return value


_DIM_FIELDS = {"schemaVersion", "fragmentId", "programId", "propertyId", "dimension", "unit",
               "status", "claimScope", "requirementIdentity", "profileIdentity", "contractIdentity",
               "translationArtifactIdentity", "sourceArtifactIdentity", "targetArtifactIdentity",
               "sourceReportIdentity", "targetReportIdentity", "sourceEnvironmentIdentity",
               "targetEnvironmentIdentity", "executionIdentity", "comparisonEvidenceIdentity",
               "l0EvidenceIdentity", "l1EvidenceIdentity", "l2EvidenceIdentity", "l2ClaimScope",
               "declaredLimitations", "uncoveredEffects", "reasonCodes"}


def parse_dimension(value: object, *, source_report: Mapping | None = None,
                    target_report: Mapping | None = None) -> Mapping[str, object]:
    value = _checked(value, DIMENSION_SCHEMA, _DIM_FIELDS, "L3 dimension")
    for name in ("requirementIdentity", "profileIdentity", "contractIdentity", "translationArtifactIdentity",
                 "sourceArtifactIdentity", "targetArtifactIdentity", "sourceReportIdentity", "targetReportIdentity",
                 "sourceEnvironmentIdentity", "targetEnvironmentIdentity", "executionIdentity",
                 "comparisonEvidenceIdentity", "l0EvidenceIdentity", "l1EvidenceIdentity", "l2EvidenceIdentity"):
        _sha(value[name], name)
    if (value["status"] not in _STATUSES or value["claimScope"] not in _SCOPES or
            value["l2ClaimScope"] not in {"architectural", "approved_functional_relation"} or
            value["claimScope"] == "architectural_intent" and value["l2ClaimScope"] != "architectural" or
            value["claimScope"] == "target_experiment_diagnostic" and value["status"] == "verified" and
            value["l2ClaimScope"] != "approved_functional_relation"):
        raise ValueError("L3 claim scope or prerequisite invalid")
    for name in ("fragmentId", "programId", "propertyId", "dimension"):
        if not isinstance(value[name], str) or not value[name]:
            raise ValueError("L3 dimension property identity missing")
    if value["unit"] not in {"fragment", "program", "campaign"}:
        raise ValueError("L3 evidence unit unknown")
    for name in ("declaredLimitations", "uncoveredEffects", "reasonCodes"):
        data = value[name]
        if not isinstance(data, list) or any(not isinstance(x, str) or not x for x in data) or data != sorted(set(data)):
            raise ValueError("L3 limitations/effects/reasons invalid")
    if value["status"] == "verified" and (value["uncoveredEffects"] or value["reasonCodes"]):
        raise ValueError("L3 verified dimension has uncovered effects or reasons")
    if source_report is not None and identity(source_report) != value["sourceReportIdentity"]:
        raise ValueError("L3 source report content identity mismatch")
    if target_report is not None and identity(target_report) != value["targetReportIdentity"]:
        raise ValueError("L3 target report content identity mismatch")
    return value


def close_fragment(requirement: Mapping, dimensions: Sequence[Mapping], *, claim_scope: str,
                   uncovered_effects: Sequence[str] = ()) -> dict[str, object]:
    if claim_scope not in _SCOPES or requirement.get("eligibilityStatus") != "eligible":
        raise ValueError("L3 requirement is ineligible or scope invalid")
    expected = {x["propertyId"]: (x["dimension"], x["unit"]) for x in requirement["requiredProperties"]}
    if len(expected) != len(requirement["requiredProperties"]) or not expected:
        raise ValueError("L3 required properties are incomplete")
    parsed = [parse_dimension(x) for x in dimensions]
    actual = {x["propertyId"]: x for x in parsed}
    if len(actual) != len(parsed) or set(actual) - set(expected):
        raise ValueError("L3 duplicate/unrequested property evidence")
    for key, item in actual.items():
        if ((item["dimension"], item["unit"]) != expected[key] or
                item["claimScope"] != claim_scope or
                item["requirementIdentity"] != requirement["requirementIdentity"] or
                item["profileIdentity"] != requirement["profileIdentity"] or
                item["fragmentId"] != requirement["fragmentId"] or
                item["programId"] != requirement["programId"]):
            raise ValueError("L3 dimension/requirement/scope identity mismatch")
    for field in ("contractIdentity", "translationArtifactIdentity", "sourceArtifactIdentity",
                  "targetArtifactIdentity", "sourceReportIdentity", "targetReportIdentity",
                  "sourceEnvironmentIdentity", "targetEnvironmentIdentity", "executionIdentity",
                  "l0EvidenceIdentity", "l1EvidenceIdentity", "l2EvidenceIdentity", "l2ClaimScope",
                  "declaredLimitations"):
        if len({json.dumps(item[field], sort_keys=True) for item in actual.values()}) > 1:
            raise ValueError("L3 fragment mixes incompatible property evidence: " + field)
    statuses = [actual[key]["status"] for key in expected if key in actual]
    uncovered = sorted(set(uncovered_effects))
    if any(not isinstance(x, str) or not x for x in uncovered):
        raise ValueError("L3 uncovered effect invalid")
    status = ("inconclusive" if set(expected) - set(actual) or uncovered else
              "failed" if "failed" in statuses else
              "inconclusive" if "inconclusive" in statuses else
              "not_run" if "not_run" in statuses else "verified")
    payload = {"schemaVersion": FRAGMENT_SCHEMA, "fragmentId": requirement["fragmentId"],
               "programId": requirement["programId"], "requirementIdentity": requirement["requirementIdentity"],
               "profileIdentity": requirement["profileIdentity"], "claimScope": claim_scope,
               "requiredProperties": sorted(expected),
               "dimensionResults": {key: actual[key] for key in sorted(actual)},
               "uncoveredEffects": uncovered, "status": status}
    return dict(payload, resultIdentity=identity(payload))


def parse_fragment(value: object) -> Mapping[str, object]:
    value = _checked(value, FRAGMENT_SCHEMA, {"schemaVersion", "fragmentId", "programId",
        "requirementIdentity", "profileIdentity", "claimScope", "requiredProperties",
        "dimensionResults", "uncoveredEffects", "status"}, "L3 fragment")
    if (not isinstance(value["requiredProperties"], list) or
            not value["requiredProperties"] or value["requiredProperties"] != sorted(set(value["requiredProperties"])) or
            not isinstance(value["dimensionResults"], Mapping) or
            set(value["dimensionResults"]) - set(value["requiredProperties"])):
        raise ValueError("L3 fragment required property set invalid")
    for key, dimension in value["dimensionResults"].items():
        if key != parse_dimension(dimension)["propertyId"]:
            raise ValueError("L3 fragment property key mismatch")
    requirement = {"fragmentId": value["fragmentId"], "programId": value["programId"],
                   "requirementIdentity": value["requirementIdentity"], "profileIdentity": value["profileIdentity"],
                   "eligibilityStatus": "eligible", "requiredProperties": [
                       {"propertyId": pid, "dimension": value["dimensionResults"][pid]["dimension"],
                        "unit": value["dimensionResults"][pid]["unit"]}
                       for pid in value["requiredProperties"] if pid in value["dimensionResults"]]}
    if set(value["requiredProperties"]) - set(value["dimensionResults"]):
        # The missing properties must stay missing; a verified claim cannot be reconstructed.
        if value["status"] != "inconclusive":
            raise ValueError("L3 fragment missing required property")
        for dimension in value["dimensionResults"].values():
            if (dimension["fragmentId"] != value["fragmentId"] or dimension["programId"] != value["programId"] or
                    dimension["requirementIdentity"] != value["requirementIdentity"] or
                    dimension["profileIdentity"] != value["profileIdentity"] or
                    dimension["claimScope"] != value["claimScope"]):
                raise ValueError("L3 fragment partial property identity mismatch")
        return value
    expected = close_fragment(requirement, list(value["dimensionResults"].values()),
                              claim_scope=value["claimScope"], uncovered_effects=value["uncoveredEffects"])
    if expected != value:
        raise ValueError("L3 fragment closure mismatch")
    return value


def close_program(program_id: str, required_fragment_ids: Sequence[str], members: Sequence[Mapping],
                  *, claim_scope: str) -> dict[str, object]:
    if claim_scope not in _SCOPES or not required_fragment_ids or list(required_fragment_ids) != sorted(set(required_fragment_ids)):
        raise ValueError("L3 required program members invalid")
    parsed = [parse_fragment(x) for x in members]
    included = [x for x in parsed if x["fragmentId"] in required_fragment_ids]
    by_id = {x["fragmentId"]: x for x in included}
    if len(by_id) != len(included) or any(x["programId"] != program_id or x["claimScope"] != claim_scope for x in included):
        raise ValueError("L3 program member identity/scope conflict")
    statuses = [x["status"] for x in included]
    status = ("inconclusive" if set(required_fragment_ids) - set(by_id) else
              "failed" if "failed" in statuses else
              "inconclusive" if "inconclusive" in statuses else
              "not_run" if "not_run" in statuses else "verified")
    executions = sorted({x["executionIdentity"] for member in included
                         for x in member["dimensionResults"].values()})
    payload = {"schemaVersion": PROGRAM_SCHEMA, "programId": program_id,
               "requiredFragmentIds": list(required_fragment_ids),
               "members": {key: by_id[key]["resultIdentity"] for key in sorted(by_id)},
               "executionIdentities": executions, "executionSampleCount": len(executions),
               "claimScope": claim_scope, "status": status}
    return dict(payload, resultIdentity=identity(payload))


def parse_program(value: object, members: Sequence[Mapping]) -> Mapping[str, object]:
    value = _checked(value, PROGRAM_SCHEMA, {"schemaVersion", "programId", "requiredFragmentIds",
        "members", "executionIdentities", "executionSampleCount", "claimScope", "status"}, "L3 program")
    expected = close_program(value["programId"], value["requiredFragmentIds"], members,
                             claim_scope=value["claimScope"])
    if expected != value:
        raise ValueError("L3 program required member/unique execution closure mismatch")
    return value
