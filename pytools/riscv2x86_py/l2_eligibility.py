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
import re
from typing import Mapping, Sequence

from .l2_dimensions import (
    L2Dimension, L2DimensionStatus, L2EligibilityStatus,
    parse_l2_dimensions,
)
from .l2_semantic_profile import L2PatternKind, profile_from_finding
from .l2_memory_object import assess_memory_authority_materializability
from .l2_scalar_authority import (
    assess_scalar_authority_materializability,
    scalar_authority_decision_matches_assessment,
    scalar_authority_decision_from_dict,
)

LEGACY_L2_REQUIREMENT_MANIFEST_SCHEMA = "riscv2x86.l2-requirement-manifest.v1"
LEGACY_L2_FRAGMENT_REQUIREMENT_SCHEMA = "riscv2x86.l2-fragment-requirement.v1"
LEGACY_L2_VALIDATOR_PLAN_SCHEMA = "riscv2x86.l2-validator-plan.v1"
L2_REQUIREMENT_MANIFEST_SCHEMA = "riscv2x86.l2-requirement-manifest.v3"
L2_FRAGMENT_REQUIREMENT_SCHEMA = "riscv2x86.l2-fragment-requirement.v3"
L2_VALIDATOR_PLAN_SCHEMA = "riscv2x86.l2-validator-plan.v3"
L2_DIMENSION_MIGRATION_VERSION = "l2-semantic-profile-migration-v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

_CANDIDATES = {"emitted", "strengthened", "functional_fallback"}
_NO_CANDIDATE = {"keep", "needs_route", "unsupported", "failed", "not_attempted"}
_DIMENSION_VALIDATOR = {
    L2Dimension.ATOMIC_MEMORY_ORDER: "l2-concurrency-memory-model",
    L2Dimension.CONTROL_FLOW: "l2-effect-trace-differential",
    L2Dimension.LOGICAL_OPERANDS: "l2-logical-operand-differential",
    L2Dimension.MEMORY_EFFECTS: "l2-effect-trace-differential",
    L2Dimension.PRIVILEGED_STATE: "l2-privileged-real-runner",
    L2Dimension.SHELL_SEMANTICS: "l2-effect-trace-differential",
    L2Dimension.TRAP_SEMANTICS: "l2-privileged-real-runner",
}
_LEGACY_DIMENSION_MAP = {
    "atomic": L2Dimension.ATOMIC_MEMORY_ORDER,
    "control_flow": L2Dimension.CONTROL_FLOW,
    "logical_operands": L2Dimension.LOGICAL_OPERANDS,
    "memory": L2Dimension.MEMORY_EFFECTS,
    "privileged_state": L2Dimension.PRIVILEGED_STATE,
    "shell": L2Dimension.SHELL_SEMANTICS,
    "trap": L2Dimension.TRAP_SEMANTICS,
}
_PROFILE_DIMENSIONS = {
    L2PatternKind.SCALAR: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.BRANCH: (L2Dimension.CONTROL_FLOW, L2Dimension.LOGICAL_OPERANDS,
                           L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.JUMP: (L2Dimension.CONTROL_FLOW, L2Dimension.LOGICAL_OPERANDS,
                         L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.MEMORY_LOAD: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.MEMORY_EFFECTS,
                                L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.MEMORY_STORE: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.MEMORY_EFFECTS,
                                 L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.FENCE: (L2Dimension.MEMORY_EFFECTS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.INSTRUCTION_VISIBILITY_FENCE: (
        L2Dimension.MEMORY_EFFECTS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.PRIVILEGED_READ: (L2Dimension.PRIVILEGED_STATE,
                                    L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.PRIVILEGED_WRITE: (L2Dimension.PRIVILEGED_STATE,
                                     L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.ATOMIC: (L2Dimension.ATOMIC_MEMORY_ORDER, L2Dimension.LOGICAL_OPERANDS,
                           L2Dimension.MEMORY_EFFECTS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.COMPOSITE: (L2Dimension.LOGICAL_OPERANDS,
                              L2Dimension.SHELL_SEMANTICS),
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


def _structured_dimensions(finding: Mapping[str, object]) -> tuple[tuple[L2Dimension, ...], tuple[str, ...]]:
    """Return required dimensions and conservative classification diagnostics."""
    fragment = finding.get("fragment")
    if not isinstance(fragment, Mapping):
        return (), ("l2.classification.fragment-facts-missing",)
    dimensions = {L2Dimension.SHELL_SEMANTICS}
    reasons = _strings(finding.get("translationReasonCodes"))
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if ((isinstance(outputs, list) and outputs) or
            (isinstance(inputs, list) and inputs)):
        dimensions.add(L2Dimension.LOGICAL_OPERANDS)
    clobbers = _strings(fragment.get("clobbers"))
    if ("memory" in clobbers or
            _reason_matches(reasons, "MEMORY", "LOAD", "STORE", "BARRIER", "FENCE")):
        dimensions.add(L2Dimension.MEMORY_EFFECTS)
    control = fragment.get("controlFlow")
    control_surface = str(fragment.get("controlFlowSurface") or "")
    if (isinstance(control, Mapping) or control_surface not in {"", "StraightLine"} or
            any(bool(fragment.get(name)) for name in (
                "hasAsmGoto", "hasLocalLabels", "hasExternalControlFlow",
                "hasMultipleExits", "hasNonLocalControlDependency")) or
            _reason_matches(reasons, "BRANCH", "CONTROL_FLOW", "CONTROL-FLOW")):
        dimensions.add(L2Dimension.CONTROL_FLOW)
    privileged_manifest = finding.get("privilegedOutputManifest")
    if ((isinstance(privileged_manifest, Mapping) and bool(privileged_manifest)) or
            _reason_matches(reasons, "CSR", "PRIVILEGED", "MMU", "PMP")):
        dimensions.add(L2Dimension.PRIVILEGED_STATE)
    if _reason_matches(reasons, "TRAP", "EXCEPTION", "INTERRUPT"):
        dimensions.add(L2Dimension.TRAP_SEMANTICS)
    if (_reason_matches(reasons, "ATOMIC", "LRSC", "LR_SC", "MEMORY_ORDER") or
            str(finding.get("buildFamily") or "").lower() in {"atomic", "lrsc"}):
        dimensions.add(L2Dimension.ATOMIC_MEMORY_ORDER)
        dimensions.add(L2Dimension.MEMORY_EFFECTS)
    return tuple(sorted(dimensions, key=lambda item: item.value)), ()


def _memory_authority_eligibility_reason(
    finding: Mapping[str, object], fragment_id: str,
) -> str:
    """Require the exact authority result produced by the materializer."""
    approval = finding.get("approvalArtifact")
    if not isinstance(approval, Mapping):
        return "l2.memory-authority.approval-missing"
    fragment = finding.get("fragment")
    raw_decision = approval.get("l2MemoryAuthorityDecision")
    if not isinstance(fragment, Mapping) or not isinstance(raw_decision, Mapping):
        return "l2.memory-authority.decision-missing"
    decision = assess_memory_authority_materializability(
        approval, raw_decision, None, fragment)
    if not decision.materializable:
        return (decision.reason_codes[0] if decision.reason_codes else
                "l2.memory-authority.decision-invalid")
    record = approval.get("l2AuthorityMaterialization")
    fields = {
        "schemaVersion", "fragmentId", "authorityKind", "status",
        "reasonCode", "authorityIdentity", "materializationIdentity",
    }
    if not isinstance(record, Mapping) or set(record) != fields:
        return "l2.memory-authority.materialization-record-missing"
    payload = dict(record)
    identity = payload.pop("materializationIdentity", None)
    if (record.get("schemaVersion") != "riscv2x86.l2-authority-materialization.v1"
            or record.get("fragmentId") != fragment_id
            or record.get("authorityKind") != "object_relative_memory"
            or identity != _identity(payload)):
        return "l2.memory-authority.materialization-record-invalid"
    if record.get("status") != "materialized":
        reason = record.get("reasonCode")
        return (str(reason) if isinstance(reason, str) and reason
                else "l2.memory-authority.materialization-rejected")
    authority_identity = record.get("authorityIdentity")
    sidecar = approval.get("l2AuthoritySidecar")
    if (_SHA256.fullmatch(str(authority_identity)) is None
            or not isinstance(sidecar, Mapping)):
        return "l2.memory-authority.sidecar-missing"
    try:
        from .l2_authority import l2_authority_sidecar_from_dict
        parsed = l2_authority_sidecar_from_dict(
            sidecar, expected_fragment_id=fragment_id)
    except ValueError:
        return "l2.memory-authority.sidecar-invalid"
    if (not parsed.complete or parsed.authority_identity != authority_identity
            or not parsed.memory_objects or not parsed.source_effects
            or not parsed.approved_effect_relations):
        return "l2.memory-authority.sidecar-incomplete"
    return ""


class L2EligibilityClassifier:
    """Classify translated findings without claiming that L2 was executed."""

    def classify(self, finding: Mapping[str, object], index: int) -> dict[str, object]:
        fragment_id = _fragment_id(finding)
        finding_id = f"finding:{index}:{fragment_id}"
        outcome = str(finding.get("translationOutcome") or "not_attempted")
        legacy_dimensions, diagnostics = _structured_dimensions(finding)
        dimensions = legacy_dimensions
        try:
            semantic_profile = profile_from_finding(finding)
            profile_diagnostics = (() if semantic_profile.complete else
                                   ("l2.semantic-profile.incomplete",))
            # A v3 typed semantic profile is the authority for required
            # dimensions. Legacy structured hints remain useful diagnostics,
            # but may not silently enlarge the verification gate: those hints
            # conflate helper calls, CSR effects and instruction visibility
            # with ordinary memory/control-flow observations.
            dimensions = tuple(sorted(
                _PROFILE_DIMENSIONS.get(semantic_profile.pattern_kind, ()),
                key=lambda item: item.value,
            ))
            if semantic_profile.pattern_kind is L2PatternKind.COMPOSITE:
                expanded = set(dimensions)
                if semantic_profile.memory_shape.reads or semantic_profile.memory_shape.writes:
                    expanded.add(L2Dimension.MEMORY_EFFECTS)
                if (semantic_profile.control_flow_shape.internal_branch
                        or semantic_profile.control_flow_shape.direct_jump
                        or semantic_profile.control_flow_shape.external):
                    expanded.add(L2Dimension.CONTROL_FLOW)
                if semantic_profile.privileged_shape.present:
                    expanded.add(L2Dimension.PRIVILEGED_STATE)
                dimensions = tuple(sorted(expanded, key=lambda item: item.value))
        except ValueError:
            semantic_profile = None
            profile_diagnostics = ("l2.semantic-profile.missing-or-invalid",)
        memory_authority_reason = ""
        scalar_authority_reason = ""
        scalar_authority_decision = None
        if (semantic_profile is not None
                and semantic_profile.pattern_kind in {
                    L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE,
                }):
            memory_authority_reason = _memory_authority_eligibility_reason(
                finding, fragment_id)
        if (semantic_profile is not None
                and semantic_profile.pattern_kind in {
                    L2PatternKind.SCALAR, L2PatternKind.BRANCH,
                    L2PatternKind.JUMP, L2PatternKind.COMPOSITE,
                }):
            approval = finding.get("approvalArtifact")
            raw_decision = (approval.get("l2ScalarAuthorityDecision")
                            if isinstance(approval, Mapping) else None)
            if isinstance(raw_decision, Mapping):
                try:
                    parsed_decision = scalar_authority_decision_from_dict(
                        raw_decision, expected_fragment_id=fragment_id)
                    raw_boundary = approval.get("l2FragmentOperandBoundary")
                    if isinstance(raw_boundary, Mapping):
                        assessed = assess_scalar_authority_materializability(
                            finding, None, raw_boundary)
                        if not scalar_authority_decision_matches_assessment(
                                parsed_decision, assessed):
                            raise ValueError("stale scalar authority decision")
                    scalar_authority_decision = parsed_decision.to_dict()
                    if not parsed_decision.materializable:
                        scalar_authority_reason = parsed_decision.reason_codes[0]
                except ValueError:
                    scalar_authority_reason = "L2_SCALAR_AUTHORITY_DECISION_INVALID"
        if outcome in _NO_CANDIDATE:
            eligibility = L2EligibilityStatus.NOT_APPLICABLE
            disposition = L2DimensionStatus.NOT_APPLICABLE
            reason_codes = ("l2.no-target-candidate",)
            dimensions = ()
        elif outcome not in _CANDIDATES:
            eligibility = L2EligibilityStatus.INCONCLUSIVE
            disposition = L2DimensionStatus.INCONCLUSIVE
            reason_codes = ("l2.translation-outcome-unknown",)
        elif memory_authority_reason:
            eligibility = L2EligibilityStatus.INCONCLUSIVE
            disposition = L2DimensionStatus.INCONCLUSIVE
            reason_codes = (memory_authority_reason,)
        elif scalar_authority_reason:
            eligibility = L2EligibilityStatus.INCONCLUSIVE
            disposition = L2DimensionStatus.INCONCLUSIVE
            reason_codes = (scalar_authority_reason,)
        elif diagnostics or profile_diagnostics or not fragment_id or not dimensions:
            eligibility = L2EligibilityStatus.INCONCLUSIVE
            disposition = L2DimensionStatus.INCONCLUSIVE
            reason_codes = diagnostics or profile_diagnostics or (
                "l2.classification-facts-incomplete",)
        else:
            eligibility = L2EligibilityStatus.ELIGIBLE
            disposition = L2DimensionStatus.NOT_RUN
            reason_codes = ("l2.execution-not-yet-configured",)
        validators = tuple(sorted({_DIMENSION_VALIDATOR[item] for item in dimensions}))
        plan = {
            "schemaVersion": L2_VALIDATOR_PLAN_SCHEMA,
            "level": "L2",
            "composite": len(validators) > 1,
            "validators": [
                {"dimension": dimension.value, "type": _DIMENSION_VALIDATOR[dimension]}
                for dimension in dimensions
            ],
            "validatorTypes": list(validators),
        }
        payload = {
            "schemaVersion": L2_FRAGMENT_REQUIREMENT_SCHEMA,
            "findingId": finding_id,
            "fragmentId": fragment_id,
            "translationOutcome": outcome,
            "semanticProfileIdentity": (
                "" if semantic_profile is None else semantic_profile.profile_identity
            ),
            "patternKind": (
                L2PatternKind.UNKNOWN.value if semantic_profile is None
                else semantic_profile.pattern_kind.value
            ),
            "requiredCapabilities": (
                [] if semantic_profile is None
                else list(semantic_profile.required_capabilities)
            ),
            "requiredDimensions": [item.value for item in dimensions],
            "eligibilityStatus": eligibility.value,
            "disposition": disposition.value,
            "reasonCodes": list(reason_codes),
            "validatorPlan": plan,
        }
        if (semantic_profile is not None
                and semantic_profile.pattern_kind in {
                    L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE}):
            approval = finding.get("approvalArtifact")
            payload["memoryAuthorityDecision"] = (
                approval.get("l2MemoryAuthorityDecision")
                if isinstance(approval, Mapping) else None)
        if scalar_authority_decision is not None:
            payload["scalarAuthorityDecision"] = scalar_authority_decision
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
    migration_fields = {"sourceSchemaVersion", "canonicalizationVersion"}
    if (frozenset(value) not in {frozenset(expected), frozenset(expected | migration_fields)}
            or value.get("schemaVersion") != L2_REQUIREMENT_MANIFEST_SCHEMA):
        raise ValueError("L2 requirement manifest schema or fields are invalid")
    if migration_fields.issubset(value):
        if (value.get("sourceSchemaVersion") != LEGACY_L2_REQUIREMENT_MANIFEST_SCHEMA
                or value.get("canonicalizationVersion") != L2_DIMENSION_MIGRATION_VERSION):
            raise ValueError("L2 requirement manifest migration provenance is invalid")
    identity = value.get("manifestIdentity")
    payload = dict(value); payload.pop("manifestIdentity")
    if not isinstance(identity, str) or identity != _identity(payload):
        raise ValueError("L2 requirement manifest identity does not match content")
    requirements = value.get("requirements")
    if not isinstance(requirements, list):
        raise ValueError("L2 requirement manifest requirements must be an array")
    requirement_fields = {"schemaVersion", "findingId", "fragmentId", "translationOutcome",
                          "semanticProfileIdentity", "patternKind", "requiredCapabilities",
                          "requiredDimensions", "eligibilityStatus", "disposition",
                          "reasonCodes", "validatorPlan", "requirementIdentity"}
    seen = set()
    disposition_counts: dict[str, int] = {}
    dimension_counts: dict[str, int] = {}
    for item in requirements:
        if (not isinstance(item, Mapping)
                or set(item) not in {frozenset(requirement_fields),
                                     frozenset(requirement_fields |
                                               {"memoryAuthorityDecision"}),
                                     frozenset(requirement_fields |
                                               {"scalarAuthorityDecision"})}):
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
        if not isinstance(dimensions, list):
            raise ValueError("L2 required dimensions are invalid or non-canonical")
        try:
            parsed_dimensions = parse_l2_dimensions(dimensions)
            eligibility = L2EligibilityStatus(str(item.get("eligibilityStatus")))
            disposition = L2DimensionStatus(str(item.get("disposition")))
        except ValueError as exc:
            raise ValueError("L2 required dimensions or statuses are invalid") from exc
        profile_identity = item.get("semanticProfileIdentity")
        pattern_kind = item.get("patternKind")
        capabilities = item.get("requiredCapabilities")
        try:
            parsed_kind = L2PatternKind(str(pattern_kind))
        except ValueError as exc:
            raise ValueError("L2 semantic profile pattern kind is invalid") from exc
        if (not isinstance(profile_identity, str)
                or (profile_identity and _SHA256.fullmatch(profile_identity) is None)
                or not isinstance(capabilities, list)
                or capabilities != sorted(set(capabilities))
                or not all(isinstance(capability, str) and capability
                           for capability in capabilities)):
            raise ValueError("L2 semantic profile binding is invalid")
        if eligibility is L2EligibilityStatus.ELIGIBLE and (
                not profile_identity or parsed_kind is L2PatternKind.UNKNOWN
                or not capabilities):
            raise ValueError("eligible L2 requirement lacks a complete semantic profile")
        valid_pair = {
            L2EligibilityStatus.ELIGIBLE: L2DimensionStatus.NOT_RUN,
            L2EligibilityStatus.NOT_APPLICABLE: L2DimensionStatus.NOT_APPLICABLE,
            L2EligibilityStatus.INCONCLUSIVE: L2DimensionStatus.INCONCLUSIVE,
        }
        if valid_pair[eligibility] is not disposition:
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
            {"dimension": dimension.value, "type": _DIMENSION_VALIDATOR[dimension]}
            for dimension in parsed_dimensions
        ]
        expected_types = sorted({_DIMENSION_VALIDATOR[dimension] for dimension in parsed_dimensions})
        if (plan.get("validators") != expected_entries or plan.get("validatorTypes") != expected_types
                or plan.get("composite") is not (len(expected_types) > 1)):
            raise ValueError("L2 validator selection does not match required dimensions")
        disposition_value = disposition.value
        disposition_counts[disposition_value] = disposition_counts.get(disposition_value, 0) + 1
        for dimension in parsed_dimensions:
            dimension_counts[dimension.value] = dimension_counts.get(dimension.value, 0) + 1
    if value.get("dispositionCounts") != dict(sorted(disposition_counts.items())):
        raise ValueError("L2 disposition counts do not match requirements")
    if value.get("requiredDimensionCounts") != dict(sorted(dimension_counts.items())):
        raise ValueError("L2 dimension counts do not match requirements")


def migrate_l2_requirement_v1_to_v3(value: Mapping[str, object]) -> dict[str, object]:
    """Explicitly migrate a strict v1 manifest; normal v2 parsing never aliases."""
    if value.get("schemaVersion") != LEGACY_L2_REQUIREMENT_MANIFEST_SCHEMA:
        raise ValueError("L2 requirement migration requires a v1 manifest")
    expected = {"schemaVersion", "classificationPolicy", "requirements",
                "dispositionCounts", "requiredDimensionCounts", "manifestIdentity"}
    if set(value) != expected:
        raise ValueError("legacy L2 requirement manifest fields are invalid")
    legacy_payload = dict(value); legacy_identity = legacy_payload.pop("manifestIdentity", None)
    if legacy_identity != _identity(legacy_payload):
        raise ValueError("legacy L2 requirement manifest identity does not match content")
    raw_requirements = value.get("requirements")
    if not isinstance(raw_requirements, list):
        raise ValueError("legacy L2 requirements must be an array")
    migrated = []
    for raw in raw_requirements:
        legacy_fields = {"schemaVersion", "findingId", "fragmentId", "translationOutcome",
                         "requiredDimensions", "disposition", "reasonCodes", "validatorPlan",
                         "requirementIdentity"}
        if (not isinstance(raw, Mapping) or set(raw) != legacy_fields
                or raw.get("schemaVersion") != LEGACY_L2_FRAGMENT_REQUIREMENT_SCHEMA):
            raise ValueError("legacy L2 fragment requirement is invalid")
        legacy_item = dict(raw); legacy_item_identity = legacy_item.pop("requirementIdentity", None)
        if legacy_item_identity != _identity(legacy_item):
            raise ValueError("legacy L2 fragment requirement identity does not match content")
        raw_dimensions = raw.get("requiredDimensions")
        if (not isinstance(raw_dimensions, list)
                or raw_dimensions != sorted(set(raw_dimensions))):
            raise ValueError("legacy L2 dimensions are not canonical")
        try:
            dimensions = tuple(_LEGACY_DIMENSION_MAP[item] for item in raw_dimensions)
        except (KeyError, TypeError) as exc:
            raise ValueError("legacy L2 dimension is unsupported") from exc
        dimensions = tuple(sorted(dimensions, key=lambda item: item.value))
        legacy_plan = raw.get("validatorPlan")
        legacy_validator_map = {
            name: _DIMENSION_VALIDATOR[dimension]
            for name, dimension in _LEGACY_DIMENSION_MAP.items()
        }
        legacy_validators = tuple(sorted({legacy_validator_map[item] for item in raw_dimensions}))
        expected_legacy_plan = {
            "schemaVersion": LEGACY_L2_VALIDATOR_PLAN_SCHEMA,
            "level": "L2", "composite": len(legacy_validators) > 1,
            "validators": [
                {"dimension": item, "type": legacy_validator_map[item]}
                for item in raw_dimensions
            ],
            "validatorTypes": list(legacy_validators),
        }
        if legacy_plan != expected_legacy_plan:
            raise ValueError("legacy L2 validator plan is inconsistent")
        disposition = L2DimensionStatus(str(raw.get("disposition")))
        eligibility = {
            L2DimensionStatus.NOT_RUN: L2EligibilityStatus.ELIGIBLE,
            L2DimensionStatus.NOT_APPLICABLE: L2EligibilityStatus.NOT_APPLICABLE,
            L2DimensionStatus.INCONCLUSIVE: L2EligibilityStatus.INCONCLUSIVE,
        }.get(disposition)
        if eligibility is None:
            raise ValueError("legacy L2 planning disposition is invalid")
        # A v1 manifest predates authoritative semantic profiles.  Migration
        # records that absence explicitly and never upgrades an old eligible
        # entry into a profile-backed executable requirement.
        migrated_disposition = disposition
        migrated_reasons = list(raw.get("reasonCodes") or ())
        if eligibility is L2EligibilityStatus.ELIGIBLE:
            eligibility = L2EligibilityStatus.INCONCLUSIVE
            migrated_disposition = L2DimensionStatus.INCONCLUSIVE
            migrated_reasons = sorted(set(migrated_reasons + [
                "l2.semantic-profile.unavailable-after-v1-migration",
            ]))
        validators = tuple(sorted({_DIMENSION_VALIDATOR[item] for item in dimensions}))
        item = {
            "schemaVersion": L2_FRAGMENT_REQUIREMENT_SCHEMA,
            "findingId": raw.get("findingId"),
            "fragmentId": raw.get("fragmentId"),
            "translationOutcome": raw.get("translationOutcome"),
            "semanticProfileIdentity": "",
            "patternKind": L2PatternKind.UNKNOWN.value,
            "requiredCapabilities": [],
            "requiredDimensions": [dimension.value for dimension in dimensions],
            "eligibilityStatus": eligibility.value,
            "disposition": migrated_disposition.value,
            "reasonCodes": migrated_reasons,
            "validatorPlan": {
                "schemaVersion": L2_VALIDATOR_PLAN_SCHEMA,
                "level": "L2",
                "composite": len(validators) > 1,
                "validators": [
                    {"dimension": dimension.value, "type": _DIMENSION_VALIDATOR[dimension]}
                    for dimension in dimensions
                ],
                "validatorTypes": list(validators),
            },
        }
        item["requirementIdentity"] = _identity(item)
        migrated.append(item)
    disposition_counts: dict[str, int] = {}
    dimension_counts: dict[str, int] = {}
    for item in migrated:
        disposition = str(item["disposition"])
        disposition_counts[disposition] = disposition_counts.get(disposition, 0) + 1
        for dimension in item["requiredDimensions"]:
            dimension_counts[str(dimension)] = dimension_counts.get(str(dimension), 0) + 1
    expected_legacy_dispositions: dict[str, int] = {}
    expected_legacy_dimensions: dict[str, int] = {}
    for raw in raw_requirements:
        disposition = str(raw["disposition"])
        expected_legacy_dispositions[disposition] = expected_legacy_dispositions.get(disposition, 0) + 1
        for dimension in raw["requiredDimensions"]:
            expected_legacy_dimensions[str(dimension)] = expected_legacy_dimensions.get(str(dimension), 0) + 1
    if value.get("dispositionCounts") != dict(sorted(expected_legacy_dispositions.items())):
        raise ValueError("legacy L2 disposition counts are inconsistent")
    if value.get("requiredDimensionCounts") != dict(sorted(expected_legacy_dimensions.items())):
        raise ValueError("legacy L2 dimension counts are inconsistent")
    result = {
        "schemaVersion": L2_REQUIREMENT_MANIFEST_SCHEMA,
        "classificationPolicy": value.get("classificationPolicy"),
        "requirements": migrated,
        "dispositionCounts": dict(sorted(disposition_counts.items())),
        "requiredDimensionCounts": dict(sorted(dimension_counts.items())),
        "sourceSchemaVersion": LEGACY_L2_REQUIREMENT_MANIFEST_SCHEMA,
        "canonicalizationVersion": L2_DIMENSION_MIGRATION_VERSION,
    }
    result["manifestIdentity"] = _identity(result)
    validate_l2_requirement_manifest(result)
    return result


def migrate_l2_requirement_v1_to_v2(value: Mapping[str, object]) -> dict[str, object]:
    """Compatibility entry point for the historical public migration API.

    The current output is v3.  In particular, this function never fabricates
    an authoritative semantic profile for a pre-profile manifest; formerly
    eligible entries are migrated to an explicit inconclusive state.
    """
    return migrate_l2_requirement_v1_to_v3(value)


def load_l2_requirement_manifest(path: str | Path) -> Mapping[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("L2 requirement manifest root must be an object")
    validate_l2_requirement_manifest(value)
    return value
