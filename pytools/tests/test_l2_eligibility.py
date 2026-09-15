from __future__ import annotations

import json
from hashlib import sha256

import pytest

from riscv2x86_py.l2_eligibility import (
    L2EligibilityClassifier, load_l2_requirement_manifest,
    migrate_l2_requirement_v1_to_v3,
)
from riscv2x86_py.l2_dimensions import L2Dimension, parse_l2_dimension
from riscv2x86_py.l2_semantic_profile import L2PatternKind
from tests.l2_profile_fixtures import profile_dict


def _identity(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + sha256(raw.encode()).hexdigest()


def _finding(*, outcome="emitted", reasons=(), fragment=None, privileged=None):
    result = {
        "translationOutcome": outcome,
        "translationReasonCodes": list(reasons),
        "fragment": fragment if fragment is not None else {
            "id": "fragment:1", "outputs": [{"constraint": "=r"}],
            "inputs": [{"constraint": "r"}], "clobbers": [],
            "controlFlowSurface": "StraightLine",
        },
        "privilegedOutputManifest": privileged or {},
        "buildFamily": "",
    }
    candidate_fragment = result.get("fragment")
    if isinstance(candidate_fragment, dict):
        kind = (L2PatternKind.COMPOSITE if reasons or privileged
                or candidate_fragment.get("controlFlowSurface") != "StraightLine"
                else L2PatternKind.SCALAR)
        result["l2SemanticProfile"] = profile_dict(
            candidate_fragment.get("id", "fragment:1"), kind,
        )
    return result


def test_register_only_fragment_plans_operand_and_shell_composite():
    item = L2EligibilityClassifier().classify(_finding(), 0)
    assert item["schemaVersion"] == "riscv2x86.l2-fragment-requirement.v3"
    assert item["eligibilityStatus"] == "eligible"
    assert item["disposition"] == "not_run"
    assert item["requiredDimensions"] == ["logical_operands", "shell_semantics"]
    assert item["validatorPlan"]["composite"] is True
    assert item["validatorPlan"]["validatorTypes"] == [
        "l2-effect-trace-differential", "l2-logical-operand-differential",
    ]


def test_memory_atomic_control_and_privileged_dimensions_route_to_all_families():
    fragment = {
        "id": "fragment:2", "outputs": [], "inputs": [], "clobbers": ["memory"],
        "controlFlowSurface": "LocalCFG", "hasLocalLabels": True,
    }
    item = L2EligibilityClassifier().classify(_finding(
        fragment=fragment, privileged={"schemaVersion": "test"},
        reasons=("SM_ATOMIC_OPERATION", "SM_TRAP")), 1)
    assert item["requiredDimensions"] == [
        "atomic_memory_order", "control_flow", "memory_effects", "privileged_state",
        "shell_semantics", "trap_semantics",
    ]
    assert item["validatorPlan"]["validatorTypes"] == [
        "l2-concurrency-memory-model", "l2-effect-trace-differential",
        "l2-privileged-real-runner",
    ]


@pytest.mark.parametrize("outcome", ["keep", "needs_route", "unsupported"])
def test_no_candidate_is_explicitly_not_applicable(outcome):
    item = L2EligibilityClassifier().classify(_finding(outcome=outcome), 0)
    assert item["eligibilityStatus"] == "not_applicable"
    assert item["disposition"] == "not_applicable"
    assert item["requiredDimensions"] == []
    assert item["reasonCodes"] == ["l2.no-target-candidate"]


def test_candidate_without_fragment_authority_is_inconclusive():
    item = L2EligibilityClassifier().classify(_finding(fragment="bad"), 0)
    assert item["eligibilityStatus"] == "inconclusive"
    assert item["disposition"] == "inconclusive"
    assert item["reasonCodes"] == ["l2.classification.fragment-facts-missing"]


def test_manifest_is_content_addressed_and_tampering_fails(tmp_path):
    manifest = L2EligibilityClassifier().classify_report({"findings": [_finding()]})
    path = tmp_path / "l2.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert load_l2_requirement_manifest(path)["manifestIdentity"].startswith("sha256:")
    manifest["requirements"][0]["disposition"] = "not_applicable"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="identity"):
        load_l2_requirement_manifest(path)


@pytest.mark.parametrize("value", ["effects", "operands", "operand", "shell", "memory", "unknown", " logical_operands"])
def test_dimension_parser_rejects_legacy_aliases_and_unknown_values(value):
    with pytest.raises(ValueError, match="unsupported L2 dimension"):
        parse_l2_dimension(value)
    assert parse_l2_dimension(L2Dimension.LOGICAL_OPERANDS.value) is L2Dimension.LOGICAL_OPERANDS


def test_v2_manifest_rejects_duplicate_and_noncanonical_dimensions(tmp_path):
    manifest = L2EligibilityClassifier().classify_report({"findings": [_finding()]})
    item = manifest["requirements"][0]
    item["requiredDimensions"] = ["shell_semantics", "logical_operands", "logical_operands"]
    item["requirementIdentity"] = _identity({k: v for k, v in item.items() if k != "requirementIdentity"})
    manifest["requiredDimensionCounts"] = {"logical_operands": 2, "shell_semantics": 1}
    manifest["manifestIdentity"] = _identity({k: v for k, v in manifest.items() if k != "manifestIdentity"})
    path = tmp_path / "bad-v2.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="dimensions"):
        load_l2_requirement_manifest(path)


def test_v1_manifest_requires_explicit_migration_and_records_provenance(tmp_path):
    plan = {
        "schemaVersion": "riscv2x86.l2-validator-plan.v1", "level": "L2",
        "composite": True,
        "validators": [
            {"dimension": "logical_operands", "type": "l2-logical-operand-differential"},
            {"dimension": "shell", "type": "l2-effect-trace-differential"},
        ],
        "validatorTypes": ["l2-effect-trace-differential", "l2-logical-operand-differential"],
    }
    item = {
        "schemaVersion": "riscv2x86.l2-fragment-requirement.v1",
        "findingId": "finding:0:fragment:1", "fragmentId": "fragment:1",
        "translationOutcome": "emitted",
        "requiredDimensions": ["logical_operands", "shell"],
        "disposition": "not_run", "reasonCodes": ["l2.execution-not-yet-configured"],
        "validatorPlan": plan,
    }
    item["requirementIdentity"] = _identity(item)
    legacy = {
        "schemaVersion": "riscv2x86.l2-requirement-manifest.v1",
        "classificationPolicy": "structured-authority-facts-fail-closed-v1",
        "requirements": [item], "dispositionCounts": {"not_run": 1},
        "requiredDimensionCounts": {"logical_operands": 1, "shell": 1},
    }
    legacy["manifestIdentity"] = _identity(legacy)
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        load_l2_requirement_manifest(path)
    migrated = migrate_l2_requirement_v1_to_v3(legacy)
    assert migrated["sourceSchemaVersion"] == "riscv2x86.l2-requirement-manifest.v1"
    assert migrated["canonicalizationVersion"] == "l2-semantic-profile-migration-v1"
    assert migrated["requirements"][0]["requiredDimensions"] == [
        "logical_operands", "shell_semantics",
    ]
