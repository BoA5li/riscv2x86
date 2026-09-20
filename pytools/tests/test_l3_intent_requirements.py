"""L3 requirements use only explicit proof-side experimental intent."""
from __future__ import annotations

import copy

import pytest

from riscv2x86_py.l3_intent_requirements import (
    INTENT_SCHEMA, L3IntentKind, classify_l3_requirements,
    parse_l3_intent_profile, parse_l3_requirement_manifest, _hash,
)

PROOF = "sha256:" + "a" * 64
RELATION = "sha256:" + "b" * 64
PRODUCER = "sha256:" + "c" * 64
BOUNDARY = "sha256:" + "d" * 64


def profile(fragment, kind, *, dimension, unit="fragment", program="program:one"):
    value = {"schemaVersion": INTENT_SCHEMA, "fragmentId": fragment,
             "programId": program, "intentKind": kind,
             "experimentClasses": [kind], "sourceIntent": "preserve declared experimental behavior",
             "approvedTargetRelationIdentity": RELATION,
             "requiredProperties": [{"propertyId": "property:0", "dimension": dimension,
                                     "unit": unit}],
             "sourceCapabilities": ["source-controlled-observation"],
             "targetCapabilities": ["target-controlled-observation"],
             "observationBoundary": {"kind": "proof-region", "identity": BOUNDARY},
             "notClaimedProperties": ["raw-hardware-counter-equality"],
             "producer": {"kind": "translation-proof", "producerIdentity": PRODUCER,
                          "proofIdentity": PROOF}, "complete": True}
    return dict(value, profileIdentity=_hash(value))


def finding(fragment, intent=None, outcome="emitted"):
    value = {"fragment": {"id": fragment}, "translationOutcome": outcome}
    if intent is not None:
        value["l3IntentProfile"] = intent
    return value


def test_distinct_fragment_and_program_properties_share_one_program():
    rows = [
        finding("fragment:arithmetic"),
        finding("fragment:load", profile("fragment:load", "memory_access",
                                         dimension="access_pattern")),
        finding("fragment:fence", profile("fragment:fence", "synchronization",
                                          dimension="synchronization", unit="campaign")),
    ]
    manifest = classify_l3_requirements({"findings": rows})
    parsed = parse_l3_requirement_manifest(manifest.to_dict())
    arithmetic, load, fence = parsed.requirements
    assert arithmetic["eligibilityStatus"] == "inconclusive"
    assert arithmetic["requiredProperties"] == []
    assert load["eligibilityStatus"] == fence["eligibilityStatus"] == "eligible"
    assert load["programId"] == fence["programId"] == "program:one"
    assert load["requiredProperties"][0]["unit"] == "fragment"
    assert fence["requiredProperties"][0]["unit"] == "campaign"
    assert load["requirementIdentity"] != fence["requirementIdentity"]


def test_file_name_or_l2_pattern_cannot_infer_l3_intent():
    rows = [{"fragment": {"id": "/round2/cache_fence.c:4:3", "asmText": "fence"},
             "l2SemanticProfile": {"patternKind": "fence"},
             "translationOutcome": "emitted"}]
    assert classify_l3_requirements({"findings": rows}).requirements[0]["eligibilityStatus"] == "inconclusive"


def test_only_authoritative_complete_none_can_be_not_applicable():
    raw = profile("fragment:plain", "memory_access", dimension="access_pattern")
    raw.update(intentKind="none", experimentClasses=[], requiredProperties=[],
               approvedTargetRelationIdentity="")
    raw["profileIdentity"] = _hash({k: v for k, v in raw.items() if k != "profileIdentity"})
    result = classify_l3_requirements({"findings": [finding("fragment:plain", raw)]})
    assert result.requirements[0]["eligibilityStatus"] == "not_applicable"


def test_no_candidate_preserves_intent_but_cannot_run():
    raw = profile("fragment:load", "memory_access", dimension="access_pattern")
    item = classify_l3_requirements({"findings": [finding("fragment:load", raw, "needs_route")]})
    assert item.requirements[0]["eligibilityStatus"] == "needs_route"
    assert item.requirements[0]["requiredProperties"][0]["dimension"] == "access_pattern"


def test_mutated_profile_and_manifest_identity_are_rejected():
    raw = profile("fragment:load", "memory_access", dimension="access_pattern")
    raw["sourceIntent"] = "different intent"
    with pytest.raises(ValueError, match="identity mismatch"):
        parse_l3_intent_profile(raw)
    raw = profile("fragment:load", "memory_access", dimension="access_pattern")
    manifest = classify_l3_requirements({"findings": [finding("fragment:load", raw)]}).to_dict()
    modified = copy.deepcopy(manifest)
    modified["requirements"][0]["requiredProperties"][0]["unit"] = "campaign"
    with pytest.raises(ValueError, match="identity mismatch"):
        parse_l3_requirement_manifest(modified)


@pytest.mark.parametrize("change,expected", [
    ({"intentKind": "not_a_kind"}, "not_a_kind"),
    ({"fragmentId": "fragment:other"}, "fragment identity mismatch"),
])
def test_intent_schema_does_not_guess_unknown_or_stale_facts(change, expected):
    raw = profile("fragment:load", "memory_access", dimension="access_pattern")
    raw.update(change)
    raw["profileIdentity"] = _hash({k: v for k, v in raw.items() if k != "profileIdentity"})
    with pytest.raises(ValueError, match=expected):
        parse_l3_intent_profile(raw, fragment_id="fragment:load")


def test_identity_tracks_approved_relation_and_proof():
    raw = profile("fragment:load", "memory_access", dimension="access_pattern")
    changed = dict(raw, approvedTargetRelationIdentity="sha256:" + "e" * 64)
    changed["profileIdentity"] = _hash({k: v for k, v in changed.items() if k != "profileIdentity"})
    a = classify_l3_requirements({"findings": [finding("fragment:load", raw)]})
    b = classify_l3_requirements({"findings": [finding("fragment:load", changed)]})
    assert a.requirements[0]["requirementIdentity"] != b.requirements[0]["requirementIdentity"]
    assert L3IntentKind.SYNCHRONIZATION.value == "synchronization"
