"""Explicit platform experiment route and bounded observations only."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py import l3_specialized_experiment as spec
from riscv2x86_py import l3_experiment_runner as runner
from riscv2x86_py.l3_intent_requirements import _hash, classify_l3_requirements
from riscv2x86_py.l3_provider_resolution import PROVIDER_SCHEMA, provider_from_dict, resolve_l3_execution_plan
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY, L1_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
from riscv2x86_py.validation_status import ValidationStatus, PreservationMode
from pytools.tests.test_l3_experiment_runner import _contract, _report

H = "sha256:" + "a" * 64
PROOF = "sha256:" + "c" * 64
TARGET_ENV = {"environmentId": "controlled-target", "runtime": "explicit"}
TARGET_ENV_ID = runner._digest(TARGET_ENV)


def contract(model="cache_timing", **changes):
    mechanism = {"mechanismId": "public-probe", "publicInterface": "registered-target-adapter-v1",
        "registrationIdentity": H, "approvalIdentity": H,
        "requiredCapabilities": ["controlled-experiment"], "complete": True}
    value = {"schemaVersion": spec.CONTRACT_SCHEMA, "experimentId": "experiment:other",
        "programId": "program:other", "fragmentId": "fragment:other", "profileIdentity": H,
        "proofIdentity": PROOF, "model": model, "sourceMechanism": dict(mechanism,
            registrationIdentity="sha256:"+"d"*64),
        "targetMechanism": dict(mechanism), "targetRelationIdentity": H,
        "dataVisibility": {"scopeId": "declared-aggregate-only", "boundaryIdentity": H,
            "allowedOutputs": ["aggregate-rate"], "rawSensitiveDataExport": False, "complete": True},
        "timingConfig": {"clockDomain": "platform-local", "measurementWindowIdentity": H,
            "samplingPolicy": "independent-fixed-inputs", "resolution": 1, "complete": True},
        "cacheConfig": {"configurationIdentity": H, "cacheLineBytes": 64,
            "statePolicy": "declared-flush-protocol", "complete": True},
        "sourceEnvironmentIdentity": H, "targetEnvironmentIdentity": TARGET_ENV_ID,
        "sourceArtifactDigest": H, "targetArtifactDigest": H, "samplingPlanIdentity": H,
        "sampleCount": 1000, "warmupCount": 10,
        "metrics": [{"metricId": "measured-success", "metricKind": "success_rate",
                     "declaredConclusion": "named platform experiment clears its preregistered threshold",
                     "sourceMinimumRate": 0.8, "targetMinimumRate": 0.8, "confidenceLevel": 0.95}],
        "notClaimedProperties": ["cross-ISA-hardware-equivalence", "identical-cache-or-timing-parameters"],
        "complete": True}
    value.update(changes)
    return value


def registry(c):
    m = c["targetMechanism"]
    return {c[side+"Mechanism"]["registrationIdentity"]: {
        "mechanismId": c[side+"Mechanism"]["mechanismId"],
        "publicInterface": c[side+"Mechanism"]["publicInterface"],
        "approvalIdentity": c[side+"Mechanism"]["approvalIdentity"],
        "environmentIdentity": c[side+"EnvironmentIdentity"]}
        for side in ("source", "target")}


def observation(c, side, hits=950):
    m = c[side + "Mechanism"]
    return {"schemaVersion": spec.OBSERVATION_SCHEMA, "experimentIdentity": spec.identity(c),
        "side": side, "runnerId": side + ":runner", "programId": c["programId"],
        "mechanismId": m["mechanismId"], "registrationIdentity": m["registrationIdentity"],
        "environmentIdentity": c[side + "EnvironmentIdentity"], "artifactDigest": H,
        "dataBoundaryIdentity": H, "measurementWindowIdentity": H,
        "cacheConfigurationIdentity": H, "sampleCount": 1000, "independentRuns": 1000,
        "samplingPlanIdentity": H, "warmupsCompleted": 10,
        "metricCounts": {"measured-success": {"hits": hits, "trials": 1000}}, "complete": True}


def test_registered_platform_conclusion_does_not_claim_isa_hardware_equality():
    c = spec.parse_contract(contract())
    assert spec.mechanism_route_status(c, registry(c),
        {"source": ["controlled-experiment"], "target": ["controlled-experiment"]}) == []
    result = spec.evaluate_experiment(c, spec.parse_observation(observation(c,"source"), c,"source","source:runner"),
                                     spec.parse_observation(observation(c,"target"), c,"target","target:runner"))
    assert result["status"] == "verified"
    assert result["claimScope"] == "registered-platform-experiment-only"
    assert "cross-ISA-hardware-equivalence" in result["notClaimedProperties"]


@pytest.mark.parametrize("target_hits,expected", [(500,"failed"), (800,"inconclusive"), (950,"verified")])
def test_target_specific_success_threshold_requires_controlled_observation(target_hits, expected):
    c = spec.parse_contract(contract())
    result = spec.evaluate_experiment(c, observation(c,"source"), observation(c,"target",target_hits))
    assert result["status"] == expected
    assert result["observedProperties"][1]["trials"] == 1000


def test_source_effect_missing_is_inconclusive_even_if_target_passes():
    c = spec.parse_contract(contract())
    assert spec.evaluate_experiment(c, observation(c,"source",500), observation(c,"target",950))["status"] == "inconclusive"


def test_missing_mechanism_or_environment_never_starts_generic_experiment():
    c = spec.parse_contract(contract())
    assert "target-mechanism-unapproved" in str(spec.mechanism_route_status(c, {},
        {"source": ["controlled-experiment"], "target": ["controlled-experiment"]}))
    assert "target-capability-missing" in str(spec.mechanism_route_status(c, registry(c),
        {"source": ["controlled-experiment"], "target": []}))
    with pytest.raises(ValueError, match="raw sensitive"):
        spec.parse_contract(contract(dataVisibility=dict(c["dataVisibility"], rawSensitiveDataExport=True)))
    with pytest.raises(ValueError, match="claim boundary"):
        spec.parse_contract(contract(notClaimedProperties=["identical-cache-or-timing-parameters"]))


@pytest.mark.parametrize("mutator", [
    lambda x: x["metricCounts"].clear(),
    lambda x: x["metricCounts"]["measured-success"].update(hits=1001),
    lambda x: x.update(cacheConfigurationIdentity="stale"),
    lambda x: x.update(independentRuns=1),
    lambda x: x.update(dataBoundaryIdentity="stale"),
])
def test_broken_report_is_inconclusive_in_runner_not_semantic_failure(mutator):
    c = spec.parse_contract(contract())
    report = observation(c,"target")
    mutator(report)
    with pytest.raises(ValueError):
        spec.parse_observation(report,c,"target","target:runner")


def _intent():
    raw = {"schemaVersion": "riscv2x86.l3-intent-profile.v1", "fragmentId": "fragment:other",
        "programId": "program:other", "intentKind": "side_channel_speculation",
        "experimentClasses": ["side_channel_speculation"], "sourceIntent": "registered bounded platform study",
        "approvedTargetRelationIdentity": H,
        "requiredProperties": [{"propertyId": "property:specialized", "dimension": "side_channel_speculation", "unit": "program"}],
        "sourceCapabilities": ["controlled-experiment"], "targetCapabilities": ["controlled-experiment"],
        "observationBoundary": {"kind": "proof-region", "identity": H},
        "notClaimedProperties": ["cross-ISA-hardware-equivalence", "identical-cache-or-timing-parameters"],
        "producer": {"kind": "translation-proof", "producerIdentity": PROOF, "proofIdentity": PROOF},
        "complete": True}
    profile = dict(raw, profileIdentity=_hash(raw))
    req = classify_l3_requirements({"findings": [{"fragment": {"id": "fragment:other"},
        "translationOutcome": "functional_fallback", "l3IntentProfile": profile}]}).to_dict()["requirements"][0]
    return profile, req


def _outer(c, profile, req):
    return _contract(schemaVersion=runner.EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA,
        experimentClasses=["side_channel_speculation"], requiredAccessPattern=[], requiredControlFlow=[],
        requiredSyncSemantics=[], metrics=[], specializedExperiment=c,
        intentProfileIdentity=profile["profileIdentity"], requirementIdentity=req["requirementIdentity"],
        approvedTargetRelationIdentity=H, programId=c["programId"],
        knownNonEquivalences=["cross-ISA-hardware-equivalence", "identical-cache-or-timing-parameters"],
        sampleCount=c["sampleCount"], warmupCount=c["warmupCount"])


def test_no_explicit_provider_means_needs_route_not_generic_sidechannel_pass():
    profile, req = _intent()
    plan = resolve_l3_execution_plan(req, profile, (), execution_profile="rv64-to-x86",
        source_capabilities=("controlled-experiment",), target_capabilities=("controlled-experiment",),
        environment_identity=H, source_artifact_digest=H, target_artifact_digest=H,
        validator_types={"l3-experiment-contract"})
    assert plan["bindingStatus"] == "needs_route"
    with pytest.raises(ValueError, match="explicit"):
        provider_from_dict({"schemaVersion": PROVIDER_SCHEMA, "providerId": "generic", "bindingKind": "automatic",
            "validatorType": "l3-experiment-contract", "config": {}, "experimentClasses": ["side_channel_speculation"],
            "propertyDimensions": ["side_channel_speculation"], "sourceCapabilities": [], "targetCapabilities": [],
            "executionProfiles": ["rv64-to-x86"], "contractSchemas": [runner.EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA],
            "fragmentIds": [], "profileIdentities": []})


def test_v6_runner_requires_explicit_mechanism_environment_and_report(tmp_path,monkeypatch):
    profile, req = _intent()
    c = contract(profileIdentity=profile["profileIdentity"])
    outer = _outer(c,profile,req)
    path=tmp_path/"specialized.json";path.write_text(json.dumps(outer))
    digest="sha256:"+sha256(path.read_bytes()).hexdigest()
    registered = registry(c)
    config=runner.ExperimentRunnerConfig("effect",None,object(),str(path),digest,
        "source:runner","target:runner",("/bin/true",),("/bin/true",),10,
        comparison_policy=L1_COMPARISON_POLICY,
        schema_version=runner.EXPERIMENT_RUNNER_SPECIALIZED_SCHEMA,
        specialized_mechanism_registry=registered,
        specialized_capabilities={"source":["controlled-experiment"],"target":["controlled-experiment"]})
    monkeypatch.setattr(runner,"run_l2_effect_trace_differential",lambda *_a,**_k:
        ValidationLayerResult(ValidationLevel.L2,ValidationStatus.VERIFIED,H,"L2"))
    import riscv2x86_py.l3_intent_requirements as intents
    monkeypatch.setattr(intents,"parse_l3_requirement_manifest",lambda *_:
        SimpleNamespace(requirements=[req]))
    bad=None
    def command(_cmd,stdin,_timeout):
        request=json.loads(stdin)
        output=_report(request)
        output.update(schemaVersion=runner.EXPERIMENT_REPORT_SPECIALIZED_SCHEMA,
            logicalAccesses=[],controlFlow=[],syncObservations=[],metricSamples={},
            warmupsCompleted=10)
        output["specializedObservation"]=observation(c,request["side"],
            500 if bad=="target" and request["side"]=="target" else 950)
        output["specializedObservation"]["runnerId"]=request["runnerId"]
        if bad=="report" and request["side"]=="target":
            output["specializedObservation"]["dataBoundaryIdentity"]="stale"
        if bad=="warmup" and request["side"]=="target":
            output["warmupsCompleted"]=0
        return runner.CommandResult(0,json.dumps(output))
    kwargs={"validation_plan":SimpleNamespace(profile=ValidationProfile.MICROARCH_DIAGNOSTIC,
                experiment_contract_id=outer["experimentId"]),
        "translation_artifact":SimpleNamespace(translation_plan_id=outer["translationPlanId"],
                                                proof_identity=PROOF,fragment_id=c["fragmentId"],
                                                identity=H,preservation_mode=PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY),
        "source_program_artifact":SimpleNamespace(artifact_digest=H),
        "target_program_artifact":SimpleNamespace(artifact_digest=H),
        "target_environment":TARGET_ENV,"l3_requirement_manifest":{},"l3_intent_profile":profile,
        "prior_layer_results":tuple(ValidationLayerResult(level,ValidationStatus.VERIFIED,H,
            json.dumps({"claimScope":"approved_functional_relation"}) if level is ValidationLevel.L2 else "")
            for level in (ValidationLevel.L0,ValidationLevel.L1,ValidationLevel.L2)),
        "comparison_policy":L1_COMPARISON_POLICY,"l3_command_runner":command}
    assert runner.run_l3_experiment_validation(config,**kwargs).status is ValidationStatus.VERIFIED
    prerequisites = kwargs["prior_layer_results"]
    kwargs["prior_layer_results"] = (*prerequisites[:2], ValidationLayerResult(
        ValidationLevel.L2, ValidationStatus.VERIFIED, H, json.dumps({"claimScope": "architectural"})))
    assert runner.run_l3_experiment_validation(config,**kwargs).status is ValidationStatus.INCONCLUSIVE
    kwargs["prior_layer_results"] = prerequisites
    bad="target"
    assert runner.run_l3_experiment_validation(config,**kwargs).status is ValidationStatus.FAILED
    bad="report"
    assert runner.run_l3_experiment_validation(config,**kwargs).status is ValidationStatus.INCONCLUSIVE
    bad="warmup"
    assert runner.run_l3_experiment_validation(config,**kwargs).status is ValidationStatus.INCONCLUSIVE
    config.specialized_mechanism_registry.clear()
    assert runner.run_l3_experiment_validation(config,**kwargs).status is ValidationStatus.NEEDS_ROUTE


def test_exact_explicit_specialized_provider_resolves_only_matching_profile(tmp_path):
    profile, req = _intent()
    c = contract(profileIdentity=profile["profileIdentity"])
    path = tmp_path / "specialized.json"
    path.write_text(json.dumps(_outer(c, profile, req)))
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    provider = provider_from_dict({"schemaVersion": PROVIDER_SCHEMA, "providerId": "exact-platform-plugin",
        "bindingKind": "explicit", "validatorType": "l3-experiment-contract",
        "config": {"schemaVersion": runner.EXPERIMENT_RUNNER_SPECIALIZED_SCHEMA,
                   "contractPath": str(path), "contractDigest": digest,
                   "sourceCommand": ["/bin/true"], "targetCommand": ["/bin/true"],
                   "specializedMechanismRegistry": registry(c),
                   "specializedCapabilities": {"source": ["controlled-experiment"],
                                               "target": ["controlled-experiment"]}},
        "experimentClasses": ["side_channel_speculation"],
        "propertyDimensions": ["side_channel_speculation"],
        "sourceCapabilities": ["controlled-experiment"], "targetCapabilities": ["controlled-experiment"],
        "executionProfiles": ["rv64-to-x86"],
        "contractSchemas": [runner.EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA],
        "fragmentIds": ["fragment:other"], "profileIdentities": []})
    def resolve(target_caps):
        return resolve_l3_execution_plan(req, profile, (provider,), execution_profile="rv64-to-x86",
            source_capabilities=("controlled-experiment",), target_capabilities=target_caps,
            environment_identity=TARGET_ENV_ID, source_artifact_digest=H, target_artifact_digest=H,
            validator_types={"l3-experiment-contract"}, translation_plan_id="plan-3",
            experiment_contract_id="cache-direction-v1")
    assert resolve(("controlled-experiment",))["bindingStatus"] == "resolved"
    missing = resolve(())
    assert missing["bindingStatus"] == "inconclusive"
    assert "l3.capability.target-missing:controlled-experiment" in missing["reasonCodes"]
    path.write_text(path.read_text() + "\n")
    assert resolve(("controlled-experiment",))["bindingStatus"] == "inconclusive"


def test_platform_experiment_count_is_program_unit(tmp_path, monkeypatch):
    import riscv2x86_py.batch_evaluation_cli as batch
    c = spec.parse_contract(contract())
    result = spec.evaluate_experiment(c, observation(c,"source"), observation(c,"target"))
    assert spec.aggregate_specialized_results([result,result])["experimentSampleCount"] == 1
    monkeypatch.setattr(batch,"discover_batch_cases",lambda *_a,**_k:[{"caseId":f"part-{i}"} for i in range(2)])
    monkeypatch.setattr(batch,"_run_case",lambda case,_output: {
        "caseId":case["caseId"],"category":"specialized","status":"verified",
        "reasonCodes":[],"attempts":[],"evaluationIdentity":H,
        "evaluationDisposition":"candidate_evaluated","programValidationLevels":{"L3":"verified"},
        "l3SpecializedExperimentResults":[result],"l2CoverageDiagnostics":{}})
    grouped=batch.run_batch_evaluation(tmp_path/"input",tmp_path/"output")
    assert grouped["l3SpecializedExperimentSampleCount"] == 1
    assert grouped["programValidationCounts"]["L3"]["verified"] == 2
