import json
from types import SimpleNamespace

from riscv2x86_py.evaluation import _translation_evaluation_linkage
from riscv2x86_py.l2_eligibility import L2EligibilityClassifier


def _finding(fragment_id: str) -> dict[str, object]:
    return {
        "fragment": {
            "id": fragment_id,
            "outputs": [{"name": "out"}],
            "inputs": [{"name": "in"}],
            "clobbers": [],
            "controlFlowSurface": "StraightLine",
        },
        "translationOutcome": "emitted",
        "translationKind": "x86_inline_asm",
        "verificationStatus": "inconclusive",
        "verificationDetail": "evaluation pending",
        "suggestedReplacement": "",
    }


def _attempt(index: int, fragment_id: str, *, include_l2: bool) -> dict[str, object]:
    attempt_id = "sha256:" + str(index + 1) * 64
    layers: list[dict[str, object]] = [{
        "level": "L1",
        "status": "verified",
        "evidenceIdentity": "sha256:" + "a" * 64,
        "detail": "shared program execution",
    }]
    completed = ["L0", "L1"]
    if include_l2:
        layers.append({
            "level": "L2",
            "status": "verified",
            "evidenceIdentity": "sha256:" + "b" * 64,
            "detail": "fragment observation",
        })
        completed.append("L2")
    return {
        "findingId": f"finding:{index}:{fragment_id}",
        "fragmentId": fragment_id,
        "attemptArtifactId": attempt_id,
        "translationOutcome": "emitted",
        "status": "verified" if include_l2 else "inconclusive",
        "reasonCodes": [],
        "validation": {
            "profile": "architectural",
            "completedLevels": completed,
            "layers": layers,
            "validationIdentity": "sha256:" + "c" * 64,
        },
    }


def test_multifragment_l2_group_requires_every_member_and_deduplicates_execution(tmp_path):
    findings = [_finding("fragment:0"), _finding("fragment:1")]
    report = {"findings": findings}
    report_path = tmp_path / "translated-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    manifest = L2EligibilityClassifier().classify_report(report)
    report_path.with_name(report_path.name + ".l2-requirements.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    request = SimpleNamespace(
        translated_report=report_path.name,
        attempt_archive="attempts.json",
        source_relative_path="case.c",
    )
    attempts = [
        _attempt(0, "fragment:0", include_l2=True),
        _attempt(1, "fragment:1", include_l2=False),
    ]

    linkage = _translation_evaluation_linkage(request, tmp_path, attempts)
    group = next(item for item in linkage["validationGroups"] if item["level"] == "L2")

    assert group["status"] == "not_run"
    assert group["requiredMemberAttemptIds"] == [item["attemptArtifactId"] for item in attempts]
    assert group["executionSampleCount"] == 1
    assert group["programExecutionEvidenceIdentities"] == ["sha256:" + "a" * 64]
    assert [item["status"] for item in group["memberResults"]] == ["verified", "not_run"]
    assert all(item["required"] is True for item in group["memberResults"])
    assert linkage["findings"][0]["l2Result"]["evidenceIdentity"] == "sha256:" + "b" * 64
    assert linkage["findings"][1]["l2Result"]["evidenceIdentity"] == ""


def test_multifragment_l2_group_is_verified_only_when_all_required_members_pass(tmp_path):
    findings = [_finding("fragment:0"), _finding("fragment:1")]
    report = {"findings": findings}
    report_path = tmp_path / "translated-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    manifest = L2EligibilityClassifier().classify_report(report)
    report_path.with_name(report_path.name + ".l2-requirements.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    request = SimpleNamespace(
        translated_report=report_path.name,
        attempt_archive="attempts.json",
        source_relative_path="case.c",
    )

    linkage = _translation_evaluation_linkage(
        request,
        tmp_path,
        [_attempt(0, "fragment:0", include_l2=True),
         _attempt(1, "fragment:1", include_l2=True)],
    )
    group = next(item for item in linkage["validationGroups"] if item["level"] == "L2")

    assert group["status"] == "verified"
    assert len(group["memberResults"]) == 2
    assert group["executionSampleCount"] == 1


def test_stale_requirement_manifest_cannot_omit_candidate_from_l2_gate(tmp_path):
    findings = [_finding("fragment:0"), _finding("fragment:1")]
    report = {"findings": findings}
    report_path = tmp_path / "translated-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    # The manifest is structurally valid, but belongs to a different one-finding
    # report.  The joined program gate must fail closed for both real candidates.
    stale = L2EligibilityClassifier().classify_report({"findings": [_finding("other")]})
    report_path.with_name(report_path.name + ".l2-requirements.json").write_text(
        json.dumps(stale), encoding="utf-8",
    )
    request = SimpleNamespace(
        translated_report=report_path.name,
        attempt_archive="attempts.json",
        source_relative_path="case.c",
    )

    linkage = _translation_evaluation_linkage(
        request,
        tmp_path,
        [_attempt(0, "fragment:0", include_l2=True),
         _attempt(1, "fragment:1", include_l2=True)],
    )
    group = next(item for item in linkage["validationGroups"] if item["level"] == "L2")

    assert group["status"] == "inconclusive"
    assert len(group["requiredMemberAttemptIds"]) == 2
    assert [item["status"] for item in group["memberResults"]] == [
        "inconclusive", "inconclusive",
    ]
