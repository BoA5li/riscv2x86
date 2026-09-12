"""Fail-closed L2 requirement classification and validator planning.

This stage deliberately does not execute L2.  It records which architectural
dimensions a translated fragment must validate and which registered validator
families must eventually produce evidence.  Classification consumes only
structured frontend/translation facts; it never parses mnemonic text.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping, Sequence


L2_REQUIREMENT_MANIFEST_SCHEMA = "riscv2x86.l2-requirement-manifest.v1"
L2_FRAGMENT_REQUIREMENT_SCHEMA = "riscv2x86.l2-fragment-requirement.v1"
L2_VALIDATOR_PLAN_SCHEMA = "riscv2x86.l2-validator-plan.v1"

_CANDIDATES = {"emitted", "strengthened", "functional_fallback"}
_NO_CANDIDATE = {"keep", "needs_route", "unsupported", "failed", "not_attempted"}
_DIMENSION_VALIDATOR = {
    "atomic": "l2-concurrency-memory-model",
    "control_flow": "l2-effect-trace-differential",
    "logical_operands": "l2-logical-operand-differential",
    "memory": "l2-effect-trace-differential",
    "privileged_state": "l2-privileged-real-runner",
    "shell": "l2-effect-trace-differential",
    "trap": "l2-privileged-real-runner",
}


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str) and item)


def _fragment_id(finding: Mapping[str, object]) -> str:
    fragment = finding.get("fragment")
    if not isinstance(fragment, Mapping):
        return ""
    return str(fragment.get("id") or fragment.get("fragmentId") or "")


def _reason_matches(reasons: Sequence[str], *needles: str) -> bool:
    upper = tuple(item.upper() for item in reasons)
    return any(any(needle in item for needle in needles) for item in upper)


def _structured_dimensions(finding: Mapping[str, object]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return required dimensions and conservative classification diagnostics."""
    fragment = finding.get("fragment")
    if not isinstance(fragment, Mapping):
        return (), ("l2.classification.fragment-facts-missing",)
    dimensions = {"shell"}
    reasons = _strings(finding.get("translationReasonCodes"))
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if ((isinstance(outputs, list) and outputs) or
            (isinstance(inputs, list) and inputs)):
        dimensions.add("logical_operands")
    clobbers = _strings(fragment.get("clobbers"))
    if ("memory" in clobbers or
            _reason_matches(reasons, "MEMORY", "LOAD", "STORE", "BARRIER", "FENCE")):
        dimensions.add("memory")
    control = fragment.get("controlFlow")
    control_surface = str(fragment.get("controlFlowSurface") or "")
    if (isinstance(control, Mapping) or control_surface not in {"", "StraightLine"} or
            any(bool(fragment.get(name)) for name in (
                "hasAsmGoto", "hasLocalLabels", "hasExternalControlFlow",
                "hasMultipleExits", "hasNonLocalControlDependency")) or
            _reason_matches(reasons, "BRANCH", "CONTROL_FLOW", "CONTROL-FLOW")):
        dimensions.add("control_flow")
    privileged_manifest = finding.get("privilegedOutputManifest")
    if ((isinstance(privileged_manifest, Mapping) and bool(privileged_manifest)) or
            _reason_matches(reasons, "CSR", "PRIVILEGED", "MMU", "PMP")):
        dimensions.add("privileged_state")
    if _reason_matches(reasons, "TRAP", "EXCEPTION", "INTERRUPT"):
        dimensions.add("trap")
    if (_reason_matches(reasons, "ATOMIC", "LRSC", "LR_SC", "MEMORY_ORDER") or
            str(finding.get("buildFamily") or "").lower() in {"atomic", "lrsc"}):
        dimensions.add("atomic")
        dimensions.add("memory")
    return tuple(sorted(dimensions)), ()


class L2EligibilityClassifier:
    """Classify translated findings without claiming that L2 was executed."""

    def classify(self, finding: Mapping[str, object], index: int) -> dict[str, object]:
        fragment_id = _fragment_id(finding)
        finding_id = f"finding:{index}:{fragment_id}"
        outcome = str(finding.get("translationOutcome") or "not_attempted")
        dimensions, diagnostics = _structured_dimensions(finding)
        if outcome in _NO_CANDIDATE:
            disposition = "not_applicable"
            reason_codes = ("l2.no-target-candidate",)
            dimensions = ()
        elif outcome not in _CANDIDATES:
            disposition = "inconclusive"
            reason_codes = ("l2.translation-outcome-unknown",)
        elif diagnostics or not fragment_id or not dimensions:
            disposition = "inconclusive"
            reason_codes = diagnostics or ("l2.classification-facts-incomplete",)
        else:
            disposition = "not_run"
            reason_codes = ("l2.execution-not-yet-configured",)
        validators = tuple(sorted({_DIMENSION_VALIDATOR[item] for item in dimensions}))
        plan = {
            "schemaVersion": L2_VALIDATOR_PLAN_SCHEMA,
            "level": "L2",
            "composite": len(validators) > 1,
            "validators": [
                {"dimension": dimension, "type": _DIMENSION_VALIDATOR[dimension]}
                for dimension in dimensions
            ],
            "validatorTypes": list(validators),
        }
        payload = {
            "schemaVersion": L2_FRAGMENT_REQUIREMENT_SCHEMA,
            "findingId": finding_id,
            "fragmentId": fragment_id,
            "translationOutcome": outcome,
            "requiredDimensions": list(dimensions),
            "disposition": disposition,
            "reasonCodes": list(reason_codes),
            "validatorPlan": plan,
        }
        payload["requirementIdentity"] = _identity(payload)
        return payload

    def classify_report(self, report: Mapping[str, object]) -> dict[str, object]:
        findings = report.get("findings")
        if not isinstance(findings, list):
            raise ValueError("translated report findings must be an array")
        requirements = [
            self.classify(item, index)
            for index, item in enumerate(findings) if isinstance(item, Mapping)
        ]
        if len(requirements) != len(findings):
            raise ValueError("translated report contains a malformed finding")
        counts: dict[str, int] = {}
        dimension_counts: dict[str, int] = {}
        for item in requirements:
            disposition = str(item["disposition"])
            counts[disposition] = counts.get(disposition, 0) + 1
            for dimension in item["requiredDimensions"]:
                dimension_counts[str(dimension)] = dimension_counts.get(str(dimension), 0) + 1
        payload = {
            "schemaVersion": L2_REQUIREMENT_MANIFEST_SCHEMA,
            "classificationPolicy": "structured-authority-facts-fail-closed-v1",
            "requirements": requirements,
            "dispositionCounts": dict(sorted(counts.items())),
            "requiredDimensionCounts": dict(sorted(dimension_counts.items())),
        }
        payload["manifestIdentity"] = _identity(payload)
        return payload


def classify_l2_requirements(report: Mapping[str, object]) -> dict[str, object]:
    return L2EligibilityClassifier().classify_report(report)


def validate_l2_requirement_manifest(value: Mapping[str, object]) -> None:
    expected = {"schemaVersion", "classificationPolicy", "requirements",
                "dispositionCounts", "requiredDimensionCounts", "manifestIdentity"}
    if set(value) != expected or value.get("schemaVersion") != L2_REQUIREMENT_MANIFEST_SCHEMA:
        raise ValueError("L2 requirement manifest schema or fields are invalid")
    identity = value.get("manifestIdentity")
    payload = dict(value); payload.pop("manifestIdentity")
    if not isinstance(identity, str) or identity != _identity(payload):
        raise ValueError("L2 requirement manifest identity does not match content")
    requirements = value.get("requirements")
    if not isinstance(requirements, list):
        raise ValueError("L2 requirement manifest requirements must be an array")
    requirement_fields = {"schemaVersion", "findingId", "fragmentId", "translationOutcome",
                          "requiredDimensions", "disposition", "reasonCodes", "validatorPlan",
                          "requirementIdentity"}
    seen = set()
    disposition_counts: dict[str, int] = {}
    dimension_counts: dict[str, int] = {}
    for item in requirements:
        if not isinstance(item, Mapping) or set(item) != requirement_fields:
            raise ValueError("L2 fragment requirement fields are invalid")
        item_identity = item.get("requirementIdentity")
        item_payload = dict(item); item_payload.pop("requirementIdentity")
        if not isinstance(item_identity, str) or item_identity != _identity(item_payload):
            raise ValueError("L2 fragment requirement identity does not match content")
        finding_id = item.get("findingId")
        if not isinstance(finding_id, str) or not finding_id or finding_id in seen:
            raise ValueError("L2 fragment finding identity is missing or duplicated")
        seen.add(finding_id)
        dimensions = item.get("requiredDimensions")
        if (not isinstance(dimensions, list) or dimensions != sorted(set(dimensions)) or
                not all(item in _DIMENSION_VALIDATOR for item in dimensions)):
            raise ValueError("L2 required dimensions are invalid or non-canonical")
        if item.get("disposition") not in {"not_run", "not_applicable", "inconclusive"}:
            raise ValueError("L2 planning disposition is invalid")
        reasons = item.get("reasonCodes")
        if (not isinstance(reasons, list) or not reasons or
                not all(isinstance(reason, str) and reason for reason in reasons)):
            raise ValueError("L2 planning reason codes are invalid")
        plan = item.get("validatorPlan")
        if (not isinstance(plan, Mapping) or set(plan) != {
                "schemaVersion", "level", "composite", "validators", "validatorTypes"} or
                plan.get("schemaVersion") != L2_VALIDATOR_PLAN_SCHEMA or plan.get("level") != "L2"):
            raise ValueError("L2 validator plan is malformed")
        expected_entries = [
            {"dimension": dimension, "type": _DIMENSION_VALIDATOR[dimension]}
            for dimension in dimensions
        ]
        expected_types = sorted({_DIMENSION_VALIDATOR[dimension] for dimension in dimensions})
        if (plan.get("validators") != expected_entries or plan.get("validatorTypes") != expected_types
                or plan.get("composite") is not (len(expected_types) > 1)):
            raise ValueError("L2 validator selection does not match required dimensions")
        disposition = str(item["disposition"])
        disposition_counts[disposition] = disposition_counts.get(disposition, 0) + 1
        for dimension in dimensions:
            dimension_counts[dimension] = dimension_counts.get(dimension, 0) + 1
    if value.get("dispositionCounts") != dict(sorted(disposition_counts.items())):
        raise ValueError("L2 disposition counts do not match requirements")
    if value.get("requiredDimensionCounts") != dict(sorted(dimension_counts.items())):
        raise ValueError("L2 dimension counts do not match requirements")


def load_l2_requirement_manifest(path: str | Path) -> Mapping[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("L2 requirement manifest root must be an object")
    validate_l2_requirement_manifest(value)
    return value
