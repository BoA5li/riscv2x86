from __future__ import annotations

import json

import pytest

from riscv2x86_py.l2_eligibility import (
    L2EligibilityClassifier, load_l2_requirement_manifest,
)


def _finding(*, outcome="emitted", reasons=(), fragment=None, privileged=None):
    return {
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


def test_register_only_fragment_plans_operand_and_shell_composite():
    item = L2EligibilityClassifier().classify(_finding(), 0)
    assert item["disposition"] == "not_run"
    assert item["requiredDimensions"] == ["logical_operands", "shell"]
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
        "atomic", "control_flow", "memory", "privileged_state", "shell", "trap",
    ]
    assert item["validatorPlan"]["validatorTypes"] == [
        "l2-concurrency-memory-model", "l2-effect-trace-differential",
        "l2-privileged-real-runner",
    ]


@pytest.mark.parametrize("outcome", ["keep", "needs_route", "unsupported"])
def test_no_candidate_is_explicitly_not_applicable(outcome):
    item = L2EligibilityClassifier().classify(_finding(outcome=outcome), 0)
    assert item["disposition"] == "not_applicable"
    assert item["requiredDimensions"] == []
    assert item["reasonCodes"] == ["l2.no-target-candidate"]


def test_candidate_without_fragment_authority_is_inconclusive():
    item = L2EligibilityClassifier().classify(_finding(fragment="bad"), 0)
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
