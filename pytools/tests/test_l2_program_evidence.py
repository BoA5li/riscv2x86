import json
from types import SimpleNamespace

from riscv2x86_py.evaluation import _translation_evaluation_linkage
from riscv2x86_py.l2_dimensions import L2ClaimScope, L2Dimension, L2DimensionStatus
from riscv2x86_py.l2_eligibility import L2EligibilityClassifier
from riscv2x86_py.l2_program_results import (
    ProgramExecutionEvidence, ProgramL2GroupResult, ProgramL2MemberResult,
    sample_set_identity,
)
from riscv2x86_py.l2_results import L2DimensionResult, L2FragmentResult


def _id(character):
    return "sha256:" + character * 64


EXECUTION, SOURCE, TARGET = _id("e"), _id("b"), _id("c")


def _finding(fragment_id):
    return {"fragment": {"id": fragment_id, "outputs": [{"name": "out"}],
                         "inputs": [{"name": "in"}], "clobbers": [],
                         "controlFlowSurface": "StraightLine"},
            "translationOutcome": "emitted", "translationKind": "x86_inline_asm",
            "verificationStatus": "inconclusive", "verificationDetail": "pending",
            "suggestedReplacement": ""}


def _fragment_result(fragment_id, requirement, *, omit_dimension=False):
    dimensions = tuple(L2Dimension(item) for item in requirement["requiredDimensions"])
    results = tuple(L2DimensionResult.create(
        dimension=dimension, status=L2DimensionStatus.VERIFIED,
        claim_scope=L2ClaimScope.ARCHITECTURAL, authority_identity=_id("a"),
        source_observation_identity=SOURCE, target_observation_identity=TARGET,
        effect_relation_identity=_id("d"), execution_identity=EXECUTION,
    ) for dimension in (dimensions[1:] if omit_dimension else dimensions))
    return L2FragmentResult.close(
        fragment_id=fragment_id, requirement_identity=requirement["requirementIdentity"],
        required_dimensions=dimensions, dimension_results=results,
    )


def _attempt(index, fragment_id, result):
    layers = [{"level": "L1", "status": "verified", "evidenceIdentity": _id("1"),
               "detail": "shared program execution"}]
    completed = ["L0", "L1"]
    if result is not None:
        layers.append({"level": "L2",
                       "status": "verified" if result.status is L2DimensionStatus.VERIFIED else "inconclusive",
                       "evidenceIdentity": result.evidence_identity,
                       "detail": json.dumps(result.to_dict(), sort_keys=True)})
        if result.status is L2DimensionStatus.VERIFIED:
            completed.append("L2")
    return {"findingId": f"finding:{index}:{fragment_id}", "fragmentId": fragment_id,
            "attemptArtifactId": _id(str(index + 1)), "translationOutcome": "emitted",
            "status": "verified" if "L2" in completed else "inconclusive", "reasonCodes": [],
            "validation": {"profile": "architectural", "completedLevels": completed,
                           "layers": layers, "validationIdentity": _id("v")}}


def _setup(tmp_path, count=3):
    report = {"findings": [_finding(f"fragment:{index}") for index in range(count)]}
    path = tmp_path / "translated-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    manifest = L2EligibilityClassifier().classify_report(report)
    path.with_name(path.name + ".l2-requirements.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    request = SimpleNamespace(translated_report=path.name, attempt_archive="attempts.json",
                              source_relative_path="case.c")
    return request, manifest["requirements"]


def test_three_fragments_share_one_program_execution_sample(tmp_path):
    request, requirements = _setup(tmp_path)
    attempts = [_attempt(i, f"fragment:{i}", _fragment_result(
        f"fragment:{i}", requirements[i])) for i in range(3)]
    linkage = _translation_evaluation_linkage(request, tmp_path, attempts)
    group = next(item for item in linkage["validationGroups"] if item["level"] == "L2")
    assert group["status"] == "verified"
    assert group["executionSampleCount"] == 1
    assert group["programExecutionEvidenceIdentities"] == [EXECUTION]
    assert len(linkage["programExecutionEvidence"]) == 1
    assert linkage["programExecutionEvidence"][0]["memberFragmentIds"] == [
        "fragment:0", "fragment:1", "fragment:2"]
    assert all(item["programExecutionEvidenceIdentities"] == [EXECUTION]
               for item in group["memberResults"])


def test_missing_required_dimension_prevents_program_verification(tmp_path):
    request, requirements = _setup(tmp_path)
    attempts = [_attempt(i, f"fragment:{i}", _fragment_result(
        f"fragment:{i}", requirements[i], omit_dimension=(i == 1))) for i in range(3)]
    group = next(item for item in _translation_evaluation_linkage(
        request, tmp_path, attempts)["validationGroups"] if item["level"] == "L2")
    assert group["status"] == "inconclusive"


def test_nonrequired_member_does_not_gate_and_duplicate_sample_does_not_count():
    requirement = {"requiredDimensions": [L2Dimension.LOGICAL_OPERANDS.value],
                   "requirementIdentity": _id("f")}
    first = _fragment_result("fragment:0", requirement)
    second = _fragment_result("fragment:1", requirement)
    evidence = ProgramExecutionEvidence(
        EXECUTION, "case.c", SOURCE, TARGET, sample_set_identity(SOURCE, TARGET),
        ("fragment:0", "fragment:1"))
    group = ProgramL2GroupResult.close(
        program_id="case.c", required_member_fragment_ids=("fragment:0",),
        member_results=(ProgramL2MemberResult("fragment:0", True, first),
                        ProgramL2MemberResult("fragment:1", False, second,
                                              ("diagnostic:uncovered",))),
        execution_evidence=(evidence, evidence))
    assert group.status is L2DimensionStatus.VERIFIED
    assert group.execution_sample_count == 1
    assert ProgramL2GroupResult.from_dict(group.to_dict()) == group

    forged = group.to_dict()
    forged["executionSampleCount"] = 2
    try:
        ProgramL2GroupResult.from_dict(forged)
    except ValueError:
        pass
    else:
        raise AssertionError("forged execution sample count was accepted")


def test_functional_member_cannot_close_architectural_program_group():
    dimension = L2Dimension.LOGICAL_OPERANDS
    result = L2DimensionResult.create(
        dimension=dimension, status=L2DimensionStatus.VERIFIED,
        claim_scope=L2ClaimScope.APPROVED_FUNCTIONAL_RELATION,
        authority_identity=_id("a"), source_observation_identity=SOURCE,
        target_observation_identity=TARGET, effect_relation_identity=_id("d"),
        execution_identity=EXECUTION,
    )
    fragment = L2FragmentResult.close(
        fragment_id="fragment:0", requirement_identity=_id("f"),
        required_dimensions=(dimension,), dimension_results=(result,),
    )
    evidence = ProgramExecutionEvidence(
        EXECUTION, "case.c", SOURCE, TARGET, sample_set_identity(SOURCE, TARGET),
        ("fragment:0",),
    )
    group = ProgramL2GroupResult.close(
        program_id="case.c", required_member_fragment_ids=("fragment:0",),
        member_results=(ProgramL2MemberResult("fragment:0", True, fragment),),
        execution_evidence=(evidence,),
    )
    assert group.status is L2DimensionStatus.INCONCLUSIVE


def test_stale_requirement_manifest_cannot_omit_candidate_from_l2_gate(tmp_path):
    request, requirements = _setup(tmp_path, 2)
    path = tmp_path / request.translated_report
    stale = L2EligibilityClassifier().classify_report({"findings": [_finding("other")]})
    path.with_name(path.name + ".l2-requirements.json").write_text(
        json.dumps(stale), encoding="utf-8")
    attempts = [_attempt(i, f"fragment:{i}", _fragment_result(
        f"fragment:{i}", requirements[i])) for i in range(2)]
    group = next(item for item in _translation_evaluation_linkage(
        request, tmp_path, attempts)["validationGroups"] if item["level"] == "L2")
    assert group["status"] == "inconclusive"
    assert len(group["requiredMemberAttemptIds"]) == 2
