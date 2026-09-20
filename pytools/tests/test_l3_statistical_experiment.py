"""Preregistered paired-round conclusions and integrated L3 verdicts."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from types import SimpleNamespace

import pytest

from riscv2x86_py import l3_statistical_experiment as subject
from riscv2x86_py import l3_experiment_runner as runner
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
from riscv2x86_py.validation_status import ValidationStatus
from pytools.tests.test_l3_experiment_runner import _contract, _report

H = "sha256:" + "b" * 64
PROOF = "sha256:" + "c" * 64


def experiment(**changes):
    value = {"schemaVersion": subject.CONTRACT_SCHEMA, "experimentId": "stride-versus-random",
             "programId": "program:generic", "proofIdentity": PROOF,
             "baselineLabel": "sequential", "treatmentLabel": "random", "independentUnit": "experiment_round",
             "roundClusterUnit": "program/round", "randomSeed": 177, "randomizeOrder": True,
             "roundCount": 20, "minimumRounds": 12, "pairsPerRound": 4, "warmupsPerRound": 3,
             "bootstrapDraws": 600, "confidenceLevel": 0.95,
             "multipleTestingCorrection": "bonferroni",
             "exclusionRule": "exclude-entire-round-if-noise-exceeds-threshold", "noiseThreshold": 5,
             "sourceEnvironmentIdentity": H, "targetEnvironmentIdentity": H,
             "sourceArtifactDigest": H, "targetArtifactDigest": H,
             "sourceCompilerDigest": H, "targetCompilerDigest": H,
             "metrics": [{"metricId": "latency-trend", "sourceMetric": "rv-latency",
                          "targetMetric": "x86-latency", "sourceUnit": "rv-cycle",
                          "targetUnit": "x86-cycle", "normalization": "difference",
                          "valueRange": [1, 1000], "conclusion": "random accesses are slower",
                          "direction": "increase", "minimumMeaningfulEffect": 3,
                          "equivalenceMargin": 0, "nonInferiorityMargin": 0}], "complete": True}
    value.update(changes)
    return value


def observation(c, side, effects=None, noisy=(), count=20):
    effects = effects or [20] * count
    rng = Random(c["randomSeed"])
    rounds = []
    for i, delta in enumerate(effects):
        noisy_round = i in noisy
        rounds.append({"roundId": f"round:{i}", "programId": c["programId"],
                       "order": "treatment_first" if rng.randrange(2) else "baseline_first",
                       "noiseScore": 10 if noisy_round else 1, "excluded": noisy_round,
                       "exclusionReason": "noise-threshold" if noisy_round else "",
                       "pairs": {c["metrics"][0][side + "Metric"]:
                                 [[100 + i % 3, 100 + i % 3 + delta] for _ in range(c["pairsPerRound"])]}})
    return {"schemaVersion": subject.OBSERVATION_SCHEMA, "experimentIdentity": subject.identity(c),
            "side": side, "runnerId": side + ":runner", "programId": c["programId"],
            "environmentIdentity": H, "artifactDigest": H, "compilerDigest": H,
            "warmupsPerRound": c["warmupsPerRound"], "randomSeed": c["randomSeed"],
            "rounds": rounds, "complete": True}


def evaluate(c, source=None, target=None):
    c = subject.parse_experiment(c)
    source = subject.parse_observation(source or observation(c, "source"), c, "source", "source:runner")
    target = subject.parse_observation(target or observation(c, "target"), c, "target", "target:runner")
    return subject.evaluate_experiment(c, source, target)


def test_paired_rounds_support_declared_within_platform_conclusion():
    c = experiment()
    result = evaluate(c)
    assert result["status"] == "verified"
    assert len(result["statisticalSummaries"]) == 2
    assert result["statisticalSummaries"][0]["effect"] == 20
    assert result["statisticalSummaries"][0]["roundClusterUnit"] == "program/round"
    assert result["statisticalSummaries"][0]["unit"] != result["statisticalSummaries"][1]["unit"]
    assert result == evaluate(c)  # reproducible seed, round resampling and digest


def test_source_conclusion_not_reproduced_is_inconclusive_even_if_target_passes():
    c = experiment()
    result = evaluate(c, source=observation(c, "source", [0] * 20))
    assert result["status"] == "inconclusive"
    assert "source:original-conclusion-not-reproduced" in result["reasonCodes"]


def test_reverse_target_trend_fails_only_after_source_reproduced():
    c = experiment()
    result = evaluate(c, target=observation(c, "target", [-20] * 20))
    assert result["status"] == "failed"
    assert "target:declared-conclusion-contradicted" in result["reasonCodes"]
    assert result["statisticalSummaries"][1]["confidenceInterval"][1] < -3


def test_noise_and_ambiguous_interval_cannot_be_false_failures():
    c = experiment()
    assert evaluate(c, target=observation(c, "target", [20] * 20, noisy=range(12)))["status"] == "inconclusive"
    variable = [-12, 12] * 10
    result = evaluate(c, target=observation(c, "target", variable))
    assert result["status"] == "inconclusive"
    assert result["statisticalSummaries"][1]["confidenceInterval"][0] < 0
    assert result["statisticalSummaries"][1]["confidenceInterval"][1] > 0


@pytest.mark.parametrize("corrupt", [
    lambda r: r["rounds"][0]["pairs"].clear(),
    lambda r: r["rounds"][0]["pairs"]["rv-latency"].pop(),
    lambda r: r["rounds"][1].update(roundId="round:0"),
    lambda r: r["rounds"][0].update(noiseScore=10),
    lambda r: r["rounds"][0].update(order="different"),
    lambda r: r["rounds"][0]["pairs"]["rv-latency"][0].__setitem__(0, 1001),
])
def test_missing_samples_noise_rule_wrong_schedule_or_out_of_range_rejected(corrupt):
    c = subject.parse_experiment(experiment())
    report = observation(c, "source")
    corrupt(report)
    with pytest.raises(ValueError):
        subject.parse_observation(report, c, "source", "source:runner")


def test_zero_effect_does_not_prove_equivalence_with_tiny_margin():
    c = experiment(metrics=[dict(experiment()["metrics"][0], direction="equivalent",
                                 equivalenceMargin=0.01, minimumMeaningfulEffect=0)])
    result = evaluate(c, source=observation(c, "source", [0] * 20),
                      target=observation(c, "target", [-4, 4] * 10))
    assert result["status"] == "inconclusive"
    assert result["statisticalSummaries"][1]["outcome"] == "undetermined"


def test_v5_l3_runner_consumes_raw_preregistered_rounds(tmp_path, monkeypatch):
    c = subject.parse_experiment(experiment())
    value = _contract(schemaVersion=runner.EXPERIMENT_CONTRACT_STATISTICAL_SCHEMA,
        experimentClasses=["statistical"], requiredAccessPattern=[], requiredControlFlow=[],
        requiredSyncSemantics=[], metrics=[], statisticalExperiment=c, intentProfileIdentity=H,
        requirementIdentity=H, approvedTargetRelationIdentity=H, programId=c["programId"],
        knownNonEquivalences=["cross-ISA-absolute-cycle-equality-not-claimed"],
        sampleCount=20, randomSeed=177, warmupCount=3,
        noisePolicy=c["exclusionRule"], calibrationProtocol="paired-round-cluster-bootstrap-v1")
    path = tmp_path / "experiment.json"
    path.write_text(json.dumps(value))
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    config = runner.ExperimentRunnerConfig("effect", None, object(), str(path), digest,
        "source:runner", "target:runner", ("/bin/true",), ("/bin/true",), 10)
    monkeypatch.setattr(runner, "run_l2_effect_trace_differential", lambda *_a, **_k:
        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED, H, "L2"))
    import riscv2x86_py.l3_intent_requirements as intents
    monkeypatch.setattr(intents, "parse_l3_requirement_manifest", lambda *_:
        SimpleNamespace(requirements=[{"fragmentId": "fragment:0", "eligibilityStatus": "eligible",
            "profileIdentity": H, "requirementIdentity": H, "proofIdentity": PROOF,
            "programId": c["programId"], "approvedTargetRelationIdentity": H}]))
    bad = None
    def execute(_command, stdin, _timeout):
        request = json.loads(stdin)
        base = _report(request)
        base.update(schemaVersion=runner.EXPERIMENT_REPORT_STATISTICAL_SCHEMA, logicalAccesses=[],
                    controlFlow=[], syncObservations=[], metricSamples={},
                    randomSeed=177, warmupsCompleted=3, noisePolicy=c["exclusionRule"],
                    calibrationProtocol="paired-round-cluster-bootstrap-v1")
        base["statisticalObservation"] = observation(c, request["side"],
            [-20] * 20 if bad == "reverse" and request["side"] == "target" else
            [0] * 20 if bad == "source" and request["side"] == "source" else None)
        base["statisticalObservation"]["runnerId"] = request["runnerId"]
        return runner.CommandResult(0, json.dumps(base))
    kw = {"validation_plan": SimpleNamespace(profile=ValidationProfile.MICROARCH,
          experiment_contract_id=value["experimentId"]),
          "translation_artifact": SimpleNamespace(translation_plan_id=value["translationPlanId"],
          proof_identity=PROOF, fragment_id="fragment:0"),
          "source_program_artifact": SimpleNamespace(artifact_digest=H),
          "target_program_artifact": SimpleNamespace(artifact_digest=H),
          "l3_source_environment_identity": H, "l3_target_environment_identity": H,
          "l3_source_compiler_digest": H, "l3_target_compiler_digest": H,
          "l3_requirement_manifest": {}, "comparison_policy": ARCHITECTURAL_COMPARISON_POLICY,
          "l3_command_runner": execute}
    from pytools.tests.l3_closure_test_support import prerequisites
    prerequisites(kw, monkeypatch, value, dimension="performance_trend", property_id="property:trend",
                  unit="program")
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.VERIFIED
    bad = "source"
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.INCONCLUSIVE
    bad = "reverse"
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.FAILED
    kw["l3_target_compiler_digest"] = "stale"
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.INCONCLUSIVE


def test_multiple_metrics_use_preregistered_familywise_confidence():
    first = experiment()["metrics"][0]
    second = dict(first, metricId="second-trend", sourceMetric="rv-other",
                  targetMetric="x86-other", conclusion="second predefined trend")
    c = subject.parse_experiment(experiment(metrics=[first, second]))
    observations = {}
    for side in ("source", "target"):
        report = observation(c, side)
        for rnd in report["rounds"]:
            rnd["pairs"][second[side + "Metric"]] = deepcopy(rnd["pairs"][first[side + "Metric"]])
        observations[side] = subject.parse_observation(report, c, side, side + ":runner")
    result = subject.evaluate_experiment(c, observations["source"], observations["target"])
    assert result["status"] == "verified"
    assert len(result["statisticalSummaries"]) == 4
    assert all(item["adjustedConfidenceLevel"] == 0.975 for item in result["statisticalSummaries"])


def test_outer_and_inner_randomization_contract_cannot_disagree(tmp_path):
    c = subject.parse_experiment(experiment())
    value = _contract(schemaVersion=runner.EXPERIMENT_CONTRACT_STATISTICAL_SCHEMA,
        experimentClasses=["statistical"], requiredAccessPattern=[], requiredControlFlow=[],
        requiredSyncSemantics=[], metrics=[], statisticalExperiment=c, intentProfileIdentity=H,
        requirementIdentity=H, approvedTargetRelationIdentity=H, programId=c["programId"],
        knownNonEquivalences=["cross-ISA-absolute-cycle-equality-not-claimed"],
        sampleCount=20, randomSeed=1, warmupCount=3,
        noisePolicy=c["exclusionRule"], calibrationProtocol="paired-round-cluster-bootstrap-v1")
    path = tmp_path / "conflicting.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="binding mismatch"):
        runner.load_experiment_contract(path)


def test_statistical_program_unit_not_fragment_count():
    c = experiment()
    r = evaluate(c)
    group = subject.aggregate_statistical_results([r, r, r])
    assert group["experimentSampleCount"] == 1
    altered = dict(r, reasonCodes=["different evaluation"])
    altered["resultIdentity"] = subject.identity({k: v for k, v in altered.items() if k != "resultIdentity"})
    with pytest.raises(ValueError, match="conflicting"):
        subject.aggregate_statistical_results([r, altered])


def test_batch_statistical_sample_is_deduplicated_across_fragments(tmp_path, monkeypatch):
    import riscv2x86_py.batch_evaluation_cli as batch
    result = evaluate(experiment())
    monkeypatch.setattr(batch, "discover_batch_cases", lambda *_a, **_k:
        [{"caseId": f"case-{i}"} for i in range(3)])
    monkeypatch.setattr(batch, "_run_case", lambda case, _output: {
        "caseId": case["caseId"], "category": "performance", "status": "verified",
        "reasonCodes": [], "attempts": [], "evaluationIdentity": H,
        "evaluationDisposition": "candidate_evaluated", "programValidationLevels": {"L3": "verified"},
        "l3StatisticalExperimentResults": [result], "l2CoverageDiagnostics": {}})
    batch_result = batch.run_batch_evaluation(tmp_path / "input", tmp_path / "output")
    assert batch_result["l3StatisticalExperimentSampleCount"] == 1
    assert batch_result["programValidationCounts"]["L3"]["verified"] == 3


def test_v5_capability_provider_resolves_preregistered_performance(tmp_path):
    from riscv2x86_py.l3_intent_requirements import _hash, classify_l3_requirements
    from riscv2x86_py.l3_provider_resolution import provider_from_dict, resolve_l3_execution_plan, PROVIDER_SCHEMA
    raw = {"schemaVersion": "riscv2x86.l3-intent-profile.v1", "fragmentId": "fragment:0",
        "programId": "program:generic", "intentKind": "performance_trend",
        "experimentClasses": ["performance_trend"], "sourceIntent": "random versus sequential access",
        "approvedTargetRelationIdentity": H,
        "requiredProperties": [{"propertyId": "property:trend", "dimension": "performance_trend", "unit": "program"}],
        "sourceCapabilities": ["paired-rounds"], "targetCapabilities": ["paired-rounds"],
        "observationBoundary": {"kind": "proof-region", "identity": PROOF},
        "notClaimedProperties": ["raw-cycle-equality"],
        "producer": {"kind": "translation-proof", "producerIdentity": PROOF,
                     "proofIdentity": PROOF}, "complete": True}
    profile = dict(raw, profileIdentity=_hash(raw))
    req = classify_l3_requirements({"findings": [{"fragment": {"id": "fragment:0"},
          "translationOutcome": "emitted", "l3IntentProfile": profile}]}).to_dict()["requirements"][0]
    c = experiment()
    outer = _contract(schemaVersion=runner.EXPERIMENT_CONTRACT_STATISTICAL_SCHEMA,
        experimentClasses=["statistical"], requiredAccessPattern=[], requiredControlFlow=[],
        requiredSyncSemantics=[], metrics=[], statisticalExperiment=c, intentProfileIdentity=profile["profileIdentity"],
        requirementIdentity=req["requirementIdentity"], approvedTargetRelationIdentity=H, programId=c["programId"],
        knownNonEquivalences=["cross-ISA-absolute-cycle-equality-not-claimed"],
        sampleCount=20, randomSeed=177, warmupCount=3,
        noisePolicy=c["exclusionRule"], calibrationProtocol="paired-round-cluster-bootstrap-v1")
    path = tmp_path / "statistical-contract.json"
    path.write_text(json.dumps(outer))
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    provider = provider_from_dict({"schemaVersion": PROVIDER_SCHEMA, "providerId": "paired-rounds-v1",
        "bindingKind": "automatic", "validatorType": "l3-experiment-contract",
        "config": {"contractPath": str(path), "contractDigest": digest,
                   "sourceCommand": ["/bin/true"], "targetCommand": ["/bin/true"]},
        "experimentClasses": ["performance_trend"], "propertyDimensions": ["performance_trend"],
        "sourceCapabilities": ["paired-rounds"], "targetCapabilities": ["paired-rounds"],
        "executionProfiles": ["rv64-to-x86"], "contractSchemas": [runner.EXPERIMENT_CONTRACT_STATISTICAL_SCHEMA],
        "fragmentIds": [], "profileIdentities": []})
    plan = resolve_l3_execution_plan(req, profile, (provider,), execution_profile="rv64-to-x86",
        source_capabilities=("paired-rounds",), target_capabilities=("paired-rounds",),
        environment_identity=H, source_artifact_digest=H, target_artifact_digest=H,
        validator_types={"l3-experiment-contract"}, translation_plan_id="plan-3",
        experiment_contract_id="cache-direction-v1")
    assert plan["bindingStatus"] == "resolved", plan
