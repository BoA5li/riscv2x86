from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import riscv2x86_py.l3_experiment_runner as subject
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
from riscv2x86_py.validation_status import ValidationStatus
from riscv2x86_py.l3_intent_requirements import _hash as l3_hash, classify_l3_requirements


PROOF = "sha256:" + "c" * 64
ACCESS = {"eventId": "access-1", "objectId": "arg:buffer", "offset": 64, "size": 8,
          "access": "read", "alignment": 8, "atomicity": "none", "requiredOrdering": "acquire",
          "orderingPredecessors": []}
CONTROL = {"eventId": "branch-1", "kind": "branch", "subject": "loop-condition",
           "outcome": "taken-sequence:1,1,0", "orderingPredecessors": []}
ENV = {"cpuModel": "contract-cpu", "microcode": "1", "kernel": "6.8", "emulator": "none",
       "emulatorArguments": "none", "governor": "performance", "turbo": False,
       "cpuAffinity": "2", "numaNode": 0, "pageSize": 4096, "aslr": "disabled"}


def _contract(**changes):
    value = {
        "schemaVersion": subject.EXPERIMENT_CONTRACT_SCHEMA,
        "experimentId": "cache-direction-v1", "translationPlanId": "plan-3", "proofIdentity": PROOF,
        "sourceIntent": "measure cache-hit timing direction", "targetStrategy": "registered target cache probe",
        "strategyRegistrationId": "strategy:x86-cache-probe.v1",
        "preservationLevel": "microarchitecture_intent_preserved",
        "experimentClasses": ["control_flow", "memory_access", "statistical"],
        "requiredAccessPattern": [ACCESS], "approvedExtraAccesses": [],
        "requiredControlFlow": [CONTROL], "requiredSyncSemantics": ["acquire-before-observation"],
        "metrics": [{"metricId": "latency-direction", "sourceMetric": "rv-cycle-domain",
                     "targetMetric": "x86-tsc-domain", "observationDomain": "within-platform calibrated latency",
                     "statisticalTest": "bootstrap_median_effect_v1",
                     "acceptanceCriteria": {"direction": "increase",
                                            "minimumAbsoluteEffectSize": 0.5, "confidenceLevel": 0.95}}],
        "calibrationProtocol": "paired-baseline-v1", "sampleCount": 20, "warmupCount": 5,
        "randomSeed": 20260907, "affinityPolicy": "pin-one-cpu", "noisePolicy": "iqr-record-no-delete-v1",
        "sourceEnvironmentRequirements": {"cpuAffinity": "2", "governor": "performance"},
        "targetEnvironmentRequirements": {"cpuAffinity": "2", "governor": "performance"},
        "knownNonEquivalences": ["cache geometry and raw cycle domains differ across ISAs"], "complete": True,
    }
    value.update(changes)
    return value


def _write(tmp_path: Path, **changes):
    path = tmp_path / "experiment.json"
    path.write_text(json.dumps(_contract(**changes), sort_keys=True), encoding="utf-8")
    return path, "sha256:" + sha256(path.read_bytes()).hexdigest(), subject.load_experiment_contract(path)


def _config(path, digest, command=("/bin/true",)):
    return subject.ExperimentRunnerConfig(
        "effect", None, object(), str(path), digest, "rv64-controlled-v1", "x86-controlled-v1",
        command, command, 10,
    )


def _report(request, *, bad=None):
    side = request["side"]
    source = side == "source"
    baseline = [10 + (i % 3) for i in range(20)] if source else [100 + (i % 5) for i in range(20)]
    treatment = [20 + (i % 3) for i in range(20)] if source else [140 + (i % 5) for i in range(20)]
    if bad == "statistics" and not source:
        treatment = [80 + (i % 5) for i in range(20)]
    if bad == "ambiguous-statistics" and not source:
        treatment = list(baseline)
    accesses = [ACCESS]
    if bad == "extra-access" and not source:
        accesses = [ACCESS, dict(ACCESS, eventId="access-2", offset=128)]
    control = [CONTROL] if not (bad == "control" and not source) else []
    environment = dict(ENV)
    if bad == "environment" and not source:
        environment["governor"] = "powersave"
    metric_name = "rv-cycle-domain" if source else "x86-tsc-domain"
    return {"schemaVersion": subject.EXPERIMENT_REPORT_SCHEMA, "side": side,
            "runnerId": request["runnerId"], "contractIdentity": request["contractIdentity"],
            "calibrationProtocol": "paired-baseline-v1", "warmupsCompleted": 5,
            "randomSeed": request.get("randomSeed", 20260907),
            "affinityPolicy": request.get("affinityPolicy", "pin-one-cpu"),
            "noisePolicy": request.get("noisePolicy", "iqr-record-no-delete-v1"),
            "environment": environment, "logicalAccesses": accesses, "controlFlow": control,
            "syncObservations": ["acquire-before-observation"],
            "metricSamples": {metric_name: {"baseline": baseline, "treatment": treatment}}}


def _run(tmp_path, monkeypatch, *, bad=None, **contract_changes):
    path, digest, _ = _write(tmp_path, **contract_changes)
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "d" * 64, "L2 passed"))
    def command_runner(_command, stdin, _timeout):
        return subject.CommandResult(0, json.dumps(_report(json.loads(stdin), bad=bad)), "")
    return subject.run_l3_experiment_validation(
        _config(path, digest), validation_plan=SimpleNamespace(
            profile=ValidationProfile.MICROARCH, experiment_contract_id="cache-direction-v1"),
        translation_artifact=SimpleNamespace(translation_plan_id="plan-3", proof_identity=PROOF),
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY, l3_command_runner=command_runner,
    )


def test_accepts_same_conclusion_across_different_metric_domains(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch)
    assert result.status is ValidationStatus.VERIFIED
    assert result.evidence_identity.startswith("sha256:")
    assert "baselineVariance" in result.detail
    assert "knownNonEquivalences" in result.detail


@pytest.mark.parametrize("bad,expected", [
    ("extra-access", "unapproved-explicit-access"),
    ("control", "logical-control-flow-mismatch"),
    ("statistics", "rawSampleSummary"),
])
def test_semantic_or_statistical_contract_violation_fails(tmp_path, monkeypatch, bad, expected):
    result = _run(tmp_path, monkeypatch, bad=bad)
    assert result.status is ValidationStatus.FAILED
    assert expected in result.detail


def test_environment_mismatch_is_inconclusive_not_success(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch, bad="environment")
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert "controlled environment" in result.detail


def test_unresolved_statistical_effect_is_inconclusive_not_failure(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch, bad="ambiguous-statistics")
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert result.evidence_identity == ""
    assert '"accepted": false' in result.detail


def test_raw_cross_isa_values_are_not_compared(tmp_path, monkeypatch):
    # Source effects are about 10 units; target effects are about 40. Both retain
    # the predeclared positive conclusion, so raw cycles are deliberately incomparable.
    assert _run(tmp_path, monkeypatch).status is ValidationStatus.VERIFIED


def test_incomplete_contract_fails_closed(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(_contract(complete=False)), encoding="utf-8")
    with pytest.raises(ValueError, match="sample/warmup/complete"):
        subject.load_experiment_contract(path)


def test_report_requires_full_environment_provenance(tmp_path):
    _, _, contract = _write(tmp_path)
    request = {"side": "source", "runnerId": "rv64-controlled-v1", "contractIdentity": contract.identity}
    report = _report(request)
    del report["environment"]["microcode"]
    with pytest.raises(ValueError, match="environment fields"):
        subject.parse_platform_report(report, side="source", runner_id="rv64-controlled-v1", contract=contract)


def test_measurement_capability_unavailable_is_inconclusive(tmp_path, monkeypatch):
    path, digest, _ = _write(tmp_path)
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "d" * 64, "L2 passed"))
    result = subject.run_l3_experiment_validation(
        _config(path, digest),
        validation_plan=SimpleNamespace(profile=ValidationProfile.MICROARCH,
                                        experiment_contract_id="cache-direction-v1"),
        translation_artifact=SimpleNamespace(translation_plan_id="plan-3", proof_identity=PROOF),
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        l3_command_runner=lambda *_a: subject.CommandResult(75, "", "PMC unavailable"),
    )
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert "capability unavailable" in result.detail


@pytest.mark.parametrize("failure,expected", [
    ("timeout", "timed out"),
    ("runner-error", "runner failed"),
    ("invalid-json", "report invalid"),
    ("invalid-schema", "report invalid"),
])
def test_infrastructure_failure_never_counts_as_semantic_failure(tmp_path, monkeypatch, failure, expected):
    path, digest, _ = _write(tmp_path)
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "d" * 64, "L2 passed"))

    def command_runner(_command, stdin, _timeout):
        if failure == "timeout":
            return subject.CommandResult(-1, "", "timeout", True)
        if failure == "runner-error":
            return subject.CommandResult(2, "", "runner crashed")
        if failure == "invalid-json":
            return subject.CommandResult(0, "{", "")
        report = _report(json.loads(stdin))
        report.pop("metricSamples")
        return subject.CommandResult(0, json.dumps(report), "")

    result = subject.run_l3_experiment_validation(
        _config(path, digest),
        validation_plan=SimpleNamespace(profile=ValidationProfile.MICROARCH,
                                        experiment_contract_id="cache-direction-v1"),
        translation_artifact=SimpleNamespace(translation_plan_id="plan-3", proof_identity=PROOF),
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY, l3_command_runner=command_runner,
    )
    assert result.level is ValidationLevel.L3
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert result.evidence_identity == ""
    assert expected in result.detail


def test_stale_or_invalid_contract_is_inconclusive(tmp_path, monkeypatch):
    path, digest, _ = _write(tmp_path)
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED))
    path.write_text("{", encoding="utf-8")
    kwargs = dict(validation_plan=SimpleNamespace(profile=ValidationProfile.MICROARCH,
                                                  experiment_contract_id="cache-direction-v1"),
                  translation_artifact=SimpleNamespace(translation_plan_id="plan-3", proof_identity=PROOF),
                  comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    stale = subject.run_l3_experiment_validation(_config(path, digest), **kwargs)
    assert stale.status is ValidationStatus.INCONCLUSIVE
    assert "digest mismatch" in stale.detail
    new_digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    invalid = subject.run_l3_experiment_validation(_config(path, new_digest), **kwargs)
    assert invalid.status is ValidationStatus.INCONCLUSIVE
    assert "contract invalid" in invalid.detail


def test_missing_l2_prerequisite_is_l3_inconclusive(tmp_path, monkeypatch):
    path, digest, _ = _write(tmp_path)
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED))
    result = subject.run_l3_experiment_validation(_config(path, digest))
    assert result.level is ValidationLevel.L3
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert "prerequisite L2" in result.detail


def test_v2_contract_requires_matching_intent_and_requirement_evidence(tmp_path, monkeypatch):
    fragment_id = "fragment:cache-experiment"
    relation = "sha256:" + "a" * 64
    profile = {"schemaVersion": "riscv2x86.l3-intent-profile.v1",
               "fragmentId": fragment_id, "programId": "program:cache",
               "intentKind": "performance_trend", "experimentClasses": ["performance_trend"],
               "sourceIntent": "same per-platform timing direction",
               "approvedTargetRelationIdentity": relation,
               "requiredProperties": [{"propertyId": "property:direction", "dimension": "performance_trend",
                                       "unit": "program"}],
               "sourceCapabilities": ["controlled-timing"], "targetCapabilities": ["controlled-timing"],
               "observationBoundary": {"kind": "proof-region", "identity": "sha256:" + "b" * 64},
               "notClaimedProperties": ["raw-cycle-equivalence"],
               "producer": {"kind": "translation-proof", "producerIdentity": "sha256:" + "e" * 64,
                            "proofIdentity": PROOF}, "complete": True}
    profile["profileIdentity"] = l3_hash(profile)
    manifest = classify_l3_requirements({"findings": [
        {"fragment": {"id": fragment_id}, "translationOutcome": "emitted", "l3IntentProfile": profile}
    ]}).to_dict()
    requirement = manifest["requirements"][0]
    bound_contract = _contract(schemaVersion=subject.EXPERIMENT_CONTRACT_BOUND_SCHEMA,
                               intentProfileIdentity=profile["profileIdentity"],
                               requirementIdentity=requirement["requirementIdentity"],
                               approvedTargetRelationIdentity=relation,
                               programId="program:cache")
    path = tmp_path / "experiment.json"
    path.write_text(json.dumps(bound_contract), encoding="utf-8")
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "d" * 64))
    kwargs = dict(validation_plan=SimpleNamespace(profile=ValidationProfile.MICROARCH,
                                                  experiment_contract_id="cache-direction-v1"),
                  translation_artifact=SimpleNamespace(fragment_id=fragment_id,
                                                       translation_plan_id="plan-3", proof_identity=PROOF),
                  comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
                  l3_command_runner=lambda _c, s, _t: subject.CommandResult(0,
                                        json.dumps(_report(json.loads(s)))))
    missing = subject.run_l3_experiment_validation(_config(path, digest), **kwargs)
    assert missing.status is ValidationStatus.INCONCLUSIVE
    assert "requirement unavailable" in missing.detail
    verified = subject.run_l3_experiment_validation(_config(path, digest),
                                                    l3_requirement_manifest=manifest, **kwargs)
    assert verified.status is ValidationStatus.VERIFIED
    assert verified.evidence_identity
    stale = json.loads(json.dumps(manifest))
    stale["requirements"][0]["proofIdentity"] = "sha256:" + "0" * 64
    stale["requirements"][0]["requirementIdentity"] = l3_hash({
        k: v for k, v in stale["requirements"][0].items() if k != "requirementIdentity"})
    stale["manifestIdentity"] = l3_hash({"schemaVersion": stale["schemaVersion"],
                                         "requirements": stale["requirements"]})
    rejected = subject.run_l3_experiment_validation(_config(path, digest),
                                                    l3_requirement_manifest=stale, **kwargs)
    assert rejected.status is ValidationStatus.INCONCLUSIVE


def test_partial_order_cycle_is_rejected(tmp_path):
    access_a = dict(ACCESS, eventId="access-1", orderingPredecessors=["access-2"])
    access_b = dict(ACCESS, eventId="access-2", orderingPredecessors=["access-1"])
    path = tmp_path / "cycle.json"
    path.write_text(json.dumps(_contract(requiredAccessPattern=[access_a, access_b])), encoding="utf-8")
    with pytest.raises(ValueError, match="contains a cycle"):
        subject.load_experiment_contract(path)


def test_real_subprocess_report_protocol(tmp_path, monkeypatch):
    script = tmp_path / "experiment-runner.py"
    template = repr({"access": ACCESS, "control": CONTROL, "environment": ENV})
    script.write_text(
        "#!/usr/bin/env python3\nimport json,sys\n"
        f"x={template}; r=json.load(sys.stdin); s=r['side']=='source'; n='rv-cycle-domain' if s else 'x86-tsc-domain'\n"
        "b=list(range(20)); t=[v+10 for v in b]\n"
        "json.dump({'schemaVersion':'riscv2x86.l3-experiment-report.v1','side':r['side'],'runnerId':r['runnerId'],'contractIdentity':r['contractIdentity'],'calibrationProtocol':r['calibrationProtocol'],'randomSeed':r['randomSeed'],'affinityPolicy':r['affinityPolicy'],'noisePolicy':r['noisePolicy'],'warmupsCompleted':r['warmupCount'],'environment':x['environment'],'logicalAccesses':[x['access']],'controlFlow':[x['control']],'syncObservations':['acquire-before-observation'],'metricSamples':{n:{'baseline':b,'treatment':t}}},sys.stdout)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    path, digest, _ = _write(tmp_path)
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "d" * 64, "L2 passed"))
    result = subject.run_l3_experiment_validation(
        _config(path, digest, (str(script),)),
        validation_plan=SimpleNamespace(profile=ValidationProfile.MICROARCH,
                                        experiment_contract_id="cache-direction-v1"),
        translation_artifact=SimpleNamespace(translation_plan_id="plan-3", proof_identity=PROOF),
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
    )
    assert result.status is ValidationStatus.VERIFIED
