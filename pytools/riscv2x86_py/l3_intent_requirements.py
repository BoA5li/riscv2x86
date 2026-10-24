"""Versioned L3 experimental intent and fail-closed per-fragment requirements.

Only an explicit translator/proof-side intent is authoritative. L2 instruction
patterns, file names and asm strings are deliberately not classification inputs.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Mapping

INTENT_SCHEMA = "riscv2x86.l3-intent-profile.v1"
INTENT_SCHEMA_V2 = "riscv2x86.l3-intent-profile.v2"
REQUIREMENT_SCHEMA_V2 = "riscv2x86.l3-fragment-requirement.v2"
MANIFEST_SCHEMA_V2 = "riscv2x86.l3-requirement-manifest.v2"
REQUIREMENT_SCHEMA = "riscv2x86.l3-fragment-requirement.v1"
MANIFEST_SCHEMA = "riscv2x86.l3-requirement-manifest.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class L3IntentKind(str, Enum):
    CACHE_MODEL = "cache_model"
    MEMORY_ACCESS = "memory_access"
    CONTROL_FLOW = "control_flow"
    SYNCHRONIZATION = "synchronization"
    PERFORMANCE_TREND = "performance_trend"
    SIDE_CHANNEL_SPECULATION = "side_channel_speculation"
    COMPOSITE = "composite"
    NONE = "none"
    UNKNOWN = "unknown"


class L3EvidenceUnit(str, Enum):
    FRAGMENT = "fragment"
    PROGRAM = "program"
    CAMPAIGN = "campaign"


_DIMENSIONS = frozenset({"cache_model", "access_pattern", "control_flow", "synchronization",
                          "performance_trend", "side_channel_speculation"})
_CLASSES = frozenset(item.value for item in L3IntentKind if item not in
                     (L3IntentKind.COMPOSITE, L3IntentKind.NONE, L3IntentKind.UNKNOWN))
_OUTCOMES = frozenset({"emitted", "strengthened", "functional_fallback"})


def _hash(value: object) -> str:
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False).encode("utf-8")).hexdigest()


def _keys(value: Mapping[str, object], names: set[str], label: str) -> None:
    if set(value) != names:
        raise ValueError(label + " fields are incomplete or unknown")


def _text(value: object, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError(label + " must be a string" + ("" if empty else " with content"))
    return value


def _sha(value: object, label: str, *, empty: bool = False) -> str:
    result = _text(value, label, empty=empty)
    if result or not empty:
        if _SHA.fullmatch(result) is None:
            raise ValueError(label + " must be a sha256 identity")
    return result


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise ValueError(label + " must be an array of nonempty strings")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ValueError(label + " must be sorted and unique")
    return result


@dataclass(frozen=True)
class L3RequiredProperty:
    property_id: str
    dimension: str
    unit: L3EvidenceUnit

    def to_dict(self) -> dict[str, str]:
        return {"propertyId": self.property_id, "dimension": self.dimension,
                "unit": self.unit.value}


@dataclass(frozen=True)
class L3IntentProfile:
    fragment_id: str
    program_id: str
    intent_kind: L3IntentKind
    experiment_classes: tuple[str, ...]
    source_intent: str
    approved_target_relation_identity: str
    required_properties: tuple[L3RequiredProperty, ...]
    source_capabilities: tuple[str, ...]
    target_capabilities: tuple[str, ...]
    observation_boundary_kind: str
    observation_boundary_identity: str
    not_claimed_properties: tuple[str, ...]
    producer_kind: str
    producer_identity: str
    proof_identity: str
    complete: bool
    profile_identity: str
    schema_version: str = INTENT_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
                "programId": self.program_id, "intentKind": self.intent_kind.value,
                "experimentClasses": list(self.experiment_classes),
                "sourceIntent": self.source_intent,
                "approvedTargetRelationIdentity": self.approved_target_relation_identity,
                "requiredProperties": [item.to_dict() for item in self.required_properties],
                "sourceCapabilities": list(self.source_capabilities),
                "targetCapabilities": list(self.target_capabilities),
                "observationBoundary": {"kind": self.observation_boundary_kind,
                                        "identity": self.observation_boundary_identity},
                "notClaimedProperties": list(self.not_claimed_properties),
                "producer": {"kind": self.producer_kind,
                             "producerIdentity": self.producer_identity,
                             "proofIdentity": self.proof_identity},
                "complete": self.complete, "profileIdentity": self.profile_identity}


def parse_l3_intent_profile(value: Mapping[str, object], *, fragment_id: str = "") -> L3IntentProfile:
    if not isinstance(value, Mapping):
        raise ValueError("L3 intent profile must be an object")
    names = {"schemaVersion", "fragmentId", "programId", "intentKind", "experimentClasses",
             "sourceIntent", "approvedTargetRelationIdentity", "requiredProperties",
             "sourceCapabilities", "targetCapabilities", "observationBoundary",
             "notClaimedProperties", "producer", "complete", "profileIdentity"}
    _keys(value, names, "L3 intent profile")
    if value["schemaVersion"] not in {INTENT_SCHEMA, INTENT_SCHEMA_V2}:
        raise ValueError("L3 intent schema unsupported")
    fid = _text(value["fragmentId"], "fragmentId")
    if fragment_id and fid != fragment_id:
        raise ValueError("L3 intent fragment identity mismatch")
    kind = L3IntentKind(value["intentKind"])
    classes = _strings(value["experimentClasses"], "experimentClasses")
    if set(classes) - _CLASSES:
        raise ValueError("unknown L3 experiment class")
    properties = value["requiredProperties"]
    if not isinstance(properties, list):
        raise ValueError("requiredProperties must be an array")
    parsed = []
    for item in properties:
        if not isinstance(item, Mapping):
            raise ValueError("L3 required property must be an object")
        _keys(item, {"propertyId", "dimension", "unit"}, "L3 required property")
        dimension = _text(item["dimension"], "dimension")
        if dimension not in _DIMENSIONS:
            raise ValueError("L3 dimension unknown")
        parsed.append(L3RequiredProperty(_text(item["propertyId"], "propertyId"),
                                         dimension, L3EvidenceUnit(item["unit"])))
    ids = tuple(item.property_id for item in parsed)
    if ids != tuple(sorted(set(ids))):
        raise ValueError("L3 properties must be sorted and unique")
    boundary, producer = value["observationBoundary"], value["producer"]
    if not isinstance(boundary, Mapping) or not isinstance(producer, Mapping):
        raise ValueError("L3 boundary/producer must be objects")
    _keys(boundary, {"kind", "identity"}, "observationBoundary")
    _keys(producer, {"kind", "producerIdentity", "proofIdentity"}, "producer")
    complete = value["complete"]
    if not isinstance(complete, bool):
        raise ValueError("L3 completeness must be boolean")
    source_intent = _text(value["sourceIntent"], "sourceIntent", empty=True)
    relation = _sha(value["approvedTargetRelationIdentity"], "approved relation", empty=True)
    bkind = _text(boundary["kind"], "boundary kind", empty=True)
    bidentity = _sha(boundary["identity"], "boundary identity", empty=True)
    pkind = _text(producer["kind"], "producer kind", empty=True)
    pid = _sha(producer["producerIdentity"], "producer identity", empty=True)
    proof = _sha(producer["proofIdentity"], "proof identity", empty=True)
    if complete:
        if (kind is L3IntentKind.UNKNOWN or not all((source_intent, bkind, bidentity,
                                                     pkind, pid, proof))):
            raise ValueError("complete L3 profile requires authoritative intent and provenance")
        if pkind not in {"frontend-compiler", "translation-proof"}:
            raise ValueError("L3 intent producer is not authoritative")
        if kind is L3IntentKind.NONE:
            if classes or parsed or relation:
                raise ValueError("L3 not-applicable profile has experiment requirements")
        elif (not relation or not classes or not parsed or not value["sourceCapabilities"]
              or not value["targetCapabilities"] or
              (kind is not L3IntentKind.COMPOSITE and kind.value not in classes)):
            raise ValueError("complete L3 experiment intent lacks approved requirements")
        if not _text(value["programId"], "programId"):
            raise ValueError("L3 program identity missing")
    if value["schemaVersion"] == INTENT_SCHEMA and ("cache_model" in classes or any(p.dimension == "cache_model" for p in parsed)):
        raise ValueError("cache model intent requires v2 schema")
    payload = dict(value)
    identity = _sha(payload.pop("profileIdentity"), "profileIdentity")
    if identity != _hash(payload):
        raise ValueError("L3 intent profile identity mismatch")
    return L3IntentProfile(fid, _text(value["programId"], "programId", empty=True),
                           kind, classes, source_intent, relation, tuple(parsed),
                           _strings(value["sourceCapabilities"], "sourceCapabilities"),
                           _strings(value["targetCapabilities"], "targetCapabilities"),
                           bkind, bidentity,
                           _strings(value["notClaimedProperties"], "notClaimedProperties"),
                           pkind, pid, proof, complete, identity, value["schemaVersion"])


def _unknown_profile(fragment_id: str) -> L3IntentProfile:
    payload = {"schemaVersion": INTENT_SCHEMA, "fragmentId": fragment_id,
               "programId": "", "intentKind": "unknown", "experimentClasses": [],
               "sourceIntent": "", "approvedTargetRelationIdentity": "",
               "requiredProperties": [], "sourceCapabilities": [], "targetCapabilities": [],
               "observationBoundary": {"kind": "", "identity": ""},
               "notClaimedProperties": [],
               "producer": {"kind": "", "producerIdentity": "", "proofIdentity": ""},
               "complete": False}
    return parse_l3_intent_profile(dict(payload, profileIdentity=_hash(payload)))


@dataclass(frozen=True)
class L3RequirementManifest:
    requirements: tuple[Mapping[str, object], ...]
    manifest_identity: str
    schema_version: str = MANIFEST_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion": self.schema_version, "requirements": list(self.requirements),
                "manifestIdentity": self.manifest_identity}


def classify_l3_requirements(report: Mapping[str, object]) -> L3RequirementManifest:
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("translated report findings must be an array")
    requirements = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise ValueError("translated finding must be an object")
        fragment = finding.get("fragment")
        fid = fragment.get("id") if isinstance(fragment, Mapping) else None
        # Other frontend findings can lack an asm fragment. Keep an explicitly
        # unresolved entry rather than preventing the translation from running.
        has_fragment_identity = isinstance(fid, str) and bool(fid)
        fid = fid if has_fragment_identity else f"unidentified:{index}"
        raw = finding.get("l3IntentProfile")
        profile = (_unknown_profile(fid) if raw is None
                   else parse_l3_intent_profile(raw, fragment_id=fid))
        if not has_fragment_identity or not profile.complete or profile.intent_kind is L3IntentKind.UNKNOWN:
            status, disposition, reasons = "inconclusive", "inconclusive", ["l3.intent.incomplete"]
        elif profile.intent_kind is L3IntentKind.NONE:
            status, disposition, reasons = "not_applicable", "not_applicable", []
        elif finding.get("translationOutcome") not in _OUTCOMES:
            status, disposition, reasons = "needs_route", "not_run", ["l3.translation.no-candidate"]
        else:
            status, disposition, reasons = "eligible", "not_run", ["l3.execution.not-yet-configured"]
        payload = {"schemaVersion": REQUIREMENT_SCHEMA_V2 if profile.schema_version == INTENT_SCHEMA_V2 else REQUIREMENT_SCHEMA,
                   "findingId": f"finding:{index}:{fid}", "fragmentId": fid,
                   "programId": profile.program_id, "translationOutcome":
                   _text(finding.get("translationOutcome", "not_attempted"), "translationOutcome"),
                   "profileIdentity": profile.profile_identity,
                   "proofIdentity": profile.proof_identity,
                   "approvedTargetRelationIdentity": profile.approved_target_relation_identity,
                   "intentKind": profile.intent_kind.value,
                   "experimentClasses": list(profile.experiment_classes),
                   "requiredProperties": [item.to_dict() for item in profile.required_properties],
                   "eligibilityStatus": status, "disposition": disposition,
                   "reasonCodes": reasons}
        payload["requirementIdentity"] = _hash(payload)
        requirements.append(payload)
    schema = MANIFEST_SCHEMA_V2 if any(r["schemaVersion"] == REQUIREMENT_SCHEMA_V2 for r in requirements) else MANIFEST_SCHEMA
    payload = {"schemaVersion": schema, "requirements": requirements}
    return L3RequirementManifest(tuple(requirements), _hash(payload), schema)


def parse_l3_requirement_manifest(value: Mapping[str, object]) -> L3RequirementManifest:
    if not isinstance(value, Mapping):
        raise ValueError("L3 manifest must be an object")
    _keys(value, {"schemaVersion", "requirements", "manifestIdentity"}, "L3 manifest")
    if value["schemaVersion"] not in {MANIFEST_SCHEMA, MANIFEST_SCHEMA_V2} or not isinstance(value["requirements"], list):
        raise ValueError("L3 manifest schema/requirements invalid")
    identity = _sha(value["manifestIdentity"], "manifestIdentity")
    if identity != _hash({"schemaVersion": value["schemaVersion"], "requirements": value["requirements"]}):
        raise ValueError("L3 manifest identity mismatch")
    for index, item in enumerate(value["requirements"]):
        if not isinstance(item, Mapping):
            raise ValueError("L3 requirement must be an object")
        names = {"schemaVersion", "findingId", "fragmentId", "programId", "translationOutcome",
                 "profileIdentity", "proofIdentity", "approvedTargetRelationIdentity",
                 "intentKind", "experimentClasses", "requiredProperties",
                 "eligibilityStatus", "disposition", "reasonCodes", "requirementIdentity"}
        _keys(item, names, "L3 requirement")
        if item["schemaVersion"] not in {REQUIREMENT_SCHEMA, REQUIREMENT_SCHEMA_V2} or (value["schemaVersion"] == MANIFEST_SCHEMA and item["schemaVersion"] != REQUIREMENT_SCHEMA):
            raise ValueError("L3 requirement schema unsupported")
        payload = dict(item)
        if _sha(payload.pop("requirementIdentity"), "requirementIdentity") != _hash(payload):
            raise ValueError("L3 requirement identity mismatch")
        if item["findingId"] != f"finding:{index}:{item['fragmentId']}":
            raise ValueError("L3 finding identity mismatch")
        _sha(item["profileIdentity"], "profileIdentity")
        _sha(item["proofIdentity"], "proofIdentity", empty=True)
        _sha(item["approvedTargetRelationIdentity"], "approvedTargetRelationIdentity", empty=True)
        kind = L3IntentKind(item["intentKind"])
        for name in ("fragmentId", "findingId"):
            _text(item[name], name)
        _text(item["programId"], "programId", empty=True)
        _text(item["translationOutcome"], "translationOutcome")
        classes = _strings(item["experimentClasses"], "experimentClasses")
        if set(classes) - _CLASSES:
            raise ValueError("L3 requirement experiment class unknown")
        _strings(item["reasonCodes"], "reasonCodes")
        props = item["requiredProperties"]
        if not isinstance(props, list):
            raise ValueError("L3 requirement properties invalid")
        ids = []
        for prop in props:
            if not isinstance(prop, Mapping):
                raise ValueError("L3 requirement property invalid")
            _keys(prop, {"propertyId", "dimension", "unit"}, "L3 required property")
            ids.append(_text(prop["propertyId"], "propertyId"))
            if prop["dimension"] not in _DIMENSIONS:
                raise ValueError("L3 requirement dimension unknown")
            L3EvidenceUnit(prop["unit"])
        if ids != sorted(set(ids)):
            raise ValueError("L3 requirement properties must be sorted and unique")
        if item["schemaVersion"] == REQUIREMENT_SCHEMA and ("cache_model" in classes or any(p["dimension"] == "cache_model" for p in props)):
            raise ValueError("cache model requirement requires v2 schema")
        status = item["eligibilityStatus"]
        if status == "eligible":
            if (kind in {L3IntentKind.NONE, L3IntentKind.UNKNOWN} or not props or not classes
                    or not item["programId"] or not item["proofIdentity"]
                    or not item["approvedTargetRelationIdentity"]
                    or item["translationOutcome"] not in _OUTCOMES
                    or item["disposition"] != "not_run"):
                raise ValueError("L3 eligible requirement inconsistent")
        elif status == "not_applicable":
            if kind is not L3IntentKind.NONE or props or classes or item["disposition"] != status:
                raise ValueError("L3 not-applicable requirement inconsistent")
        elif status == "inconclusive" and item["disposition"] != "inconclusive":
            raise ValueError("L3 incomplete requirement disposition invalid")
        elif status == "needs_route" and (item["disposition"] != "not_run" or
                item["translationOutcome"] in _OUTCOMES or kind in {L3IntentKind.NONE, L3IntentKind.UNKNOWN}):
            raise ValueError("L3 route requirement inconsistent")
        if item["eligibilityStatus"] not in {"eligible", "inconclusive", "not_applicable", "needs_route"}:
            raise ValueError("L3 eligibility status unknown")
    ids = [x["fragmentId"] for x in value["requirements"]]
    if len(ids) != len(set(ids)):
        raise ValueError("L3 requirement fragment identities ambiguous")
    return L3RequirementManifest(tuple(value["requirements"]), identity, value["schemaVersion"])
