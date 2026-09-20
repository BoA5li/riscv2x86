"""Program-level L3 concurrency campaigns: valid observation versus finite-sample claim."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py import l3_concurrency_campaign as subject
from riscv2x86_py import l3_experiment_runner as runner
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
from riscv2x86_py.validation_status import ValidationStatus
from pytools.tests.test_l3_experiment_runner import _contract, _report

H = "sha256:" + "e" * 64
P = "sha256:" + "c" * 64


def campaign(criterion="safety", **changes):
    platform = {"environmentIdentity": H, "capabilities": ["bounded-observation"], "complete": True}
    compilation = {"artifactDigest": H, "compilerDigest": H, "optimizationLevel": "O2", "abi": "lp64", "complete": True}
    value = {"schemaVersion": subject.CAMPAIGN_SCHEMA, "campaignId": "campaign:mp-variant",
        "programId": "program:renamed", "memberFragmentIds": ["fragment:a", "fragment:b", "fragment:c"],
        "kind": "MP", "semanticFactsIdentity": H, "l2ConcurrencyContractIdentity": H,
        "approvedRelationIdentity": H, "threadTopology": {"threads": 2, "roles": ["reader", "writer"], "complete": True},
        "initialState": {"stateIdentity": H, "complete": True}, "sourceAllowedOutcomes": ["0", "1"],
        "targetAllowedOutcomes": ["1"], "forbiddenOutcomes": ["forbidden"],
        "protocolInvariants": ["message-visible"], "criterion": criterion,
        "requiredOutcomeSupport": [] if criterion == "safety" else ["1"],
        "minimumIterations": 10, "minimumIndependentRuns": 10, "schedulePolicy": "fixed-seed-v1",
        "sourcePlatform": deepcopy(platform), "targetPlatform": deepcopy(platform),
        "sourceCompilation": deepcopy(compilation), "targetCompilation": deepcopy(compilation),
        "confidenceLevel": 0.95, "minimumDetectableProbability": 0.05,
        "maximumProbabilityDifference": 0.2 if criterion == "probability" else 0.0,
        "complete": True}
    value.update(changes)
    return value


def observation(c, side, outcomes=None, violations=0):
    outcomes = outcomes if outcomes is not None else ["1"] * 50
    counts = {name: outcomes.count(name) for name in sorted(set(outcomes))}
    return {"schemaVersion": subject.OBSERVATION_SCHEMA, "campaignIdentity": subject.identity(c),
        "side": side, "runnerId": side + ":runner", "programId": c["programId"],
        "environmentIdentity": H, "artifactDigest": H, "compilerDigest": H,
        "schedulePolicy": c["schedulePolicy"], "initialStateIdentity": H, "threadCount": 2,
        "iterationsCompleted": len(outcomes), "independentRunsCompleted": len(outcomes),
        "outcomeCounts": counts, "runSamples": [{"runId": f"sample:{i}", "seed": i,
            "outcome": item, "iterations": 1} for i, item in enumerate(outcomes)],
        "protocolViolations": {"message-visible": violations}, "complete": True}


def pair(c, source=None, target=None):
    return (subject.parse_observation(source or observation(c, "source"), c, "source", "source:runner"),
            subject.parse_observation(target or observation(c, "target"), c, "target", "target:runner"))


def test_safety_does_not_require_every_allowed_result_observed():
    c = subject.parse_campaign(campaign())
    source, target = pair(c)
    result = subject.evaluate_campaign(c, source, target)
    assert result["status"] == "verified"
    assert result["claimBoundary"].endswith("not-memory-model-equivalence")
    assert subject.aggregate_campaign_results([result, result])["campaignSampleCount"] == 1


@pytest.mark.parametrize("bad,reason", [("outcome", "forbidden-or-outside-approved-outcome"),
                                       ("protocol", "protocol-invariant-violated")])
def test_valid_safety_violation_fails_even_if_sample_count_low(bad, reason):
    c = subject.parse_campaign(campaign())
    source = observation(c, "source")
    target = observation(c, "target", ["forbidden"] if bad == "outcome" else ["1"],
                         int(bad == "protocol"))
    src, dst = pair(c, source, target)
    result = subject.evaluate_campaign(c, src, dst)
    assert result["status"] == "failed"
    assert reason in result["reasonCodes"][0]


def test_absence_is_inconclusive_even_after_many_independent_runs():
    c = subject.parse_campaign(campaign("observed_support"))
    src, dst = pair(c, target=observation(c, "target", ["0"] * 100000))
    # The declared target relation excludes 0, so this is a safety failure,
    # not a missing-result inference. Use a relation that permits both.
    assert subject.evaluate_campaign(c, src, dst)["status"] == "failed"
    c = subject.parse_campaign(campaign("observed_support", targetAllowedOutcomes=["0", "1"]))
    src, dst = pair(c, target=observation(c, "target", ["0"] * 100000))
    result = subject.evaluate_campaign(c, src, dst)
    assert result["status"] == "inconclusive"
    assert "reachability-undetermined" in result["reasonCodes"][0]
    assert result["detectionPower"]["target"] < 0.05


def test_probability_requires_independent_samples_and_reports_bounds():
    c = subject.parse_campaign(campaign("probability", targetAllowedOutcomes=["0", "1"],
                                         maximumProbabilityDifference=0.4))
    src, dst = pair(c, source=observation(c, "source", ["1"] * 2000),
                    target=observation(c, "target", ["1"] * 2000))
    result = subject.evaluate_campaign(c, src, dst)
    assert result["status"] == "verified"
    assert result["confidenceBounds"]["source"]["1"]
    target = observation(c, "target", ["1"] * 1000 + ["0"] * 1000)
    dst = subject.parse_observation(target, c, "target", "target:runner")
    assert subject.evaluate_campaign(c, src, dst)["status"] == "failed"
    c = subject.parse_campaign(campaign("probability", targetAllowedOutcomes=["0", "1"],
                                         maximumProbabilityDifference=0.01))
    src, dst = pair(c)
    assert subject.evaluate_campaign(c, src, dst)["status"] == "inconclusive"


def test_campaign_malformed_observation_and_strengthening_are_rejected():
    c = campaign()
    with pytest.raises(ValueError, match="approved outcome relation"):
        subject.parse_campaign(dict(c, targetAllowedOutcomes=["other"]))
    c = subject.parse_campaign(c)
    o = observation(c, "target")
    o["outcomeCounts"]["1"] = 49
    with pytest.raises(ValueError, match="outcome counts"):
        subject.parse_observation(o, c, "target", "target:runner")
    o = observation(c, "target")
    o["runSamples"][1]["runId"] = o["runSamples"][0]["runId"]
    with pytest.raises(ValueError, match="duplicate independent run"):
        subject.parse_observation(o, c, "target", "target:runner")


def test_conflicting_duplicate_campaign_evidence_rejected():
    c = subject.parse_campaign(campaign())
    src, dst = pair(c)
    result = subject.evaluate_campaign(c, src, dst)
    conflict = dict(result, reasonCodes=["different run"])
    conflict["resultIdentity"] = subject.identity({k: v for k, v in conflict.items() if k != "resultIdentity"})
    with pytest.raises(ValueError, match="conflicting"):
        subject.aggregate_campaign_results([result, conflict])


def test_v4_integrates_l2_evidence_and_program_binary_binding(tmp_path, monkeypatch):
    c = subject.parse_campaign(campaign())
    base = _contract(schemaVersion=runner.EXPERIMENT_CONTRACT_CAMPAIGN_SCHEMA,
        experimentClasses=["synchronization"], requiredAccessPattern=[], requiredControlFlow=[],
        requiredSyncSemantics=["message-visible"], metrics=[], intentProfileIdentity=H,
        requirementIdentity=H, approvedTargetRelationIdentity=H, programId=c["programId"],
        campaignContract=c)
    path = tmp_path / "campaign-contract.json"
    path.write_text(json.dumps(base))
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    config = runner.ExperimentRunnerConfig("concurrency", object(), None, str(path), digest,
        "source:runner", "target:runner", ("/bin/true",), ("/bin/true",), 10)
    monkeypatch.setattr(runner, "run_l2_concurrency_differential", lambda *_a, **_k:
        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED, H,
                              json.dumps({"contractIdentity": H})))
    import riscv2x86_py.l3_intent_requirements as intents
    monkeypatch.setattr(intents, "parse_l3_requirement_manifest", lambda *_:
        SimpleNamespace(requirements=[{"fragmentId": "fragment:a", "eligibilityStatus": "eligible",
            "profileIdentity": H, "requirementIdentity": H, "proofIdentity": base["proofIdentity"],
            "programId": c["programId"], "approvedTargetRelationIdentity": H}]))
    bad = False
    def execute(_command, stdin, _timeout):
        request = json.loads(stdin)
        reply = _report(request)
        reply["schemaVersion"] = runner.EXPERIMENT_REPORT_CAMPAIGN_SCHEMA
        reply["logicalAccesses"] = []
        reply["controlFlow"] = []
        reply["metricSamples"] = {}
        reply["syncObservations"] = ["message-visible"]
        obs = observation(c, request["side"])
        obs["runnerId"] = request["runnerId"]
        if bad and request["side"] == "target":
            obs["protocolViolations"]["message-visible"] = 1
        reply["campaignObservation"] = obs
        return runner.CommandResult(0, json.dumps(reply))
    kwargs = {"validation_plan": SimpleNamespace(profile=ValidationProfile.MICROARCH,
              experiment_contract_id=base["experimentId"]),
        "translation_artifact": SimpleNamespace(translation_plan_id=base["translationPlanId"],
              proof_identity=base["proofIdentity"], fragment_id="fragment:a"),
        "source_program_artifact": SimpleNamespace(artifact_digest=H),
        "target_program_artifact": SimpleNamespace(artifact_digest=H),
        "l3_source_environment_identity": H, "l3_target_environment_identity": H,
        "l3_campaign_semantic_facts_identity": H,
        "l3_requirement_manifest": {}, "comparison_policy": ARCHITECTURAL_COMPARISON_POLICY,
        "l3_command_runner": execute}
    from pytools.tests.l3_closure_test_support import prerequisites
    prerequisites(kwargs, monkeypatch, base, dimension="synchronization", property_id="property:sync",
                  unit="campaign")
    kwargs["prior_layer_results"] = (*kwargs["prior_layer_results"][:2],
        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED, H,
                              json.dumps({"claimScope": "architectural", "contractIdentity": H})))
    assert runner.run_l3_experiment_validation(config, **kwargs).status is ValidationStatus.VERIFIED
    bad = True
    assert runner.run_l3_experiment_validation(config, **kwargs).status is ValidationStatus.FAILED
    kwargs["target_program_artifact"].artifact_digest = "stale"
    assert runner.run_l3_experiment_validation(config, **kwargs).status is ValidationStatus.INCONCLUSIVE


def test_batch_counts_shared_campaign_once(tmp_path, monkeypatch):
    import riscv2x86_py.batch_evaluation_cli as batch
    c = subject.parse_campaign(campaign())
    src, dst = pair(c)
    result = subject.evaluate_campaign(c, src, dst)
    monkeypatch.setattr(batch, "discover_batch_cases", lambda *_args, **_kwargs:
        [{"caseId": f"case-{i}"} for i in range(3)])
    def run_case(case, _output):
        return {"caseId": case["caseId"], "category": "concurrency", "status": "verified",
                "reasonCodes": [], "attempts": [], "evaluationIdentity": H, "evaluationDisposition": "candidate_evaluated",
                "programValidationLevels": {"L3": "verified"},
                "l3ConcurrencyCampaignResults": [result], "l2CoverageDiagnostics": {}}
    monkeypatch.setattr(batch, "_run_case", run_case)
    payload = batch.run_batch_evaluation(tmp_path / "input", tmp_path / "output", jobs=1)
    assert payload["l3ConcurrencyCampaignSampleCount"] == 1
    assert payload["programValidationCounts"]["L3"]["verified"] == 3
