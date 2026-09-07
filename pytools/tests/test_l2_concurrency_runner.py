from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import riscv2x86_py.l2_concurrency_runner as subject
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_status import ValidationStatus


PROOF = "sha256:" + "a" * 64


def _contract(*, target_order="acq_rel", strengthen=True, retry_shape="not_observable_at_l2"):
    return {
        "schemaVersion": subject.CONCURRENCY_CONTRACT_SCHEMA,
        "contractId": "atomic-rmw-1",
        "translationPlanId": "plan-1",
        "proofIdentity": PROOF,
        "sourceOperation": "atomic_rmw",
        "requiredOrdering": "acquire",
        "targetOrdering": target_order,
        "requiredFailureOrdering": "not_applicable",
        "targetFailureOrdering": "not_applicable",
        "requiredAtomicWidthBits": 64,
        "requiredAlignmentBytes": 8,
        "allowedTargetStrengthening": strengthen,
        "retryFailureBehavior": "spurious_failure_allowed",
        "retryShapePolicy": retry_shape,
        "scenarios": [
            {"testId": "litmus", "kind": "litmus", "minimumIterations": 100,
             "allowedFinalStates": ["0,1", "1,0", "1,1"], "forbiddenOutcomes": ["0,0"],
             "requiredOrderingObservations": ["acquire-load"]},
            {"testId": "single", "kind": "single_thread", "minimumIterations": 1,
             "allowedFinalStates": ["counter=1"], "forbiddenOutcomes": [],
             "requiredOrderingObservations": ["atomic-rmw"]},
            {"testId": "stress", "kind": "stress", "minimumIterations": 1000,
             "allowedFinalStates": ["counter=2000"], "forbiddenOutcomes": ["lost-update"],
             "requiredOrderingObservations": ["atomic-rmw"]},
        ],
    }


def _write_contract(tmp_path: Path, **changes):
    value = _contract(**changes)
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    return path, digest, subject.load_concurrency_contract(path)


def _config(path: Path, digest: str):
    runners = tuple(
        subject.ScenarioRunner(test_id, "rv64-qemu-v1", "x86-native-v1", ("/bin/true",), ("/bin/true",))
        for test_id in ("litmus", "single", "stress")
    )
    return subject.L2ConcurrencyRunnerConfig(
        "effect", object(), None, str(path), digest, runners, 5,
    )


def _observation(request, side, *, bad=None):
    test_id = request["testId"]
    values = {
        "litmus": (100, {"0,1": 45, "1,0": 55}, ["acquire-load"]),
        "single": (1, {"counter=1": 1}, ["atomic-rmw"]),
        "stress": (1000, {"counter=2000": 1000}, ["atomic-rmw"]),
    }
    iterations, counts, ordering = values[test_id]
    # Different distributions are valid; schedules are intentionally not compared.
    if side == "target" and test_id == "litmus": counts = {"0,1": 5, "1,1": 95}
    if bad == "forbidden" and side == "target" and test_id == "litmus": counts = {"0,0": 1, "1,1": 99}
    if bad == "ordering" and side == "target" and test_id == "litmus": ordering = []
    if bad == "width" and side == "target" and test_id == "single": return_value_width = [32]
    else: return_value_width = [64]
    return {
        "schemaVersion": subject.CONCURRENCY_OBSERVATION_SCHEMA,
        "testId": test_id, "runnerId": request["runnerId"],
        "contractIdentity": request["contractIdentity"],
        "iterationsCompleted": iterations, "outcomeCounts": counts,
        "orderingObservations": ordering, "atomicWidthsObserved": return_value_width,
        "alignmentsObserved": [8], "successCount": iterations, "failureCount": 0,
        "retryCount": 3 if side == "source" else 0, "completed": True,
    }


def _run(tmp_path, monkeypatch, *, bad=None, **contract_changes):
    path, digest, _ = _write_contract(tmp_path, **contract_changes)
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "b" * 64, "base passed"))
    def command_runner(_command, stdin, _timeout):
        request = json.loads(stdin)
        value = _observation(request, request["side"], bad=bad)
        return subject.CommandResult(0, json.dumps(value), "")
    return subject.run_l2_concurrency_differential(
        _config(path, digest), translation_artifact=SimpleNamespace(
            translation_plan_id="plan-1", proof_identity=PROOF),
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        concurrency_command_runner=command_runner,
    )


def test_accepts_different_source_target_schedules_within_contract(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch)
    assert result.status is ValidationStatus.VERIFIED
    assert result.evidence_identity.startswith("sha256:")


@pytest.mark.parametrize("bad,marker", [
    ("forbidden", "forbidden-outcome-observed"),
    ("ordering", "required-ordering-observation-missing"),
    ("width", "atomic-width-mismatch"),
])
def test_fails_closed_for_contract_violations(tmp_path, monkeypatch, bad, marker):
    result = _run(tmp_path, monkeypatch, bad=bad)
    assert result.status is ValidationStatus.FAILED
    assert marker in result.detail


def test_rejects_unapproved_target_strengthening(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch, target_order="seq_cst", strengthen=False)
    assert result.status is ValidationStatus.FAILED
    assert "strengthening" in result.detail


def test_routes_retry_shape_observation_to_l3(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch, retry_shape="requires_l3")
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert "requires L3" in result.detail


def test_runner_identity_is_not_self_asserted(tmp_path, monkeypatch):
    path, digest, contract = _write_contract(tmp_path)
    value = _observation({"testId": "single", "runnerId": "wrong",
                          "contractIdentity": contract.identity}, "source")
    with pytest.raises(ValueError, match="runner/contract binding"):
        subject.parse_concurrency_observation(
            value, test_id="single", runner_id="rv64-qemu-v1",
            contract_identity=contract.identity,
        )


def test_contract_requires_all_three_test_classes(tmp_path):
    value = _contract()
    value["scenarios"] = value["scenarios"][:-1]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="single-thread, stress and litmus"):
        subject.load_concurrency_contract(path)


def test_real_subprocess_protocol(tmp_path, monkeypatch):
    script = tmp_path / "runner.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "r=json.load(sys.stdin); t=r['testId']; n={'single':1,'stress':1000,'litmus':100}[t]\n"
        "states={'single':{'counter=1':1},'stress':{'counter=2000':1000},'litmus':{'0,1':n}}[t]\n"
        "order=['acquire-load'] if t=='litmus' else ['atomic-rmw']\n"
        "json.dump({'schemaVersion':'riscv2x86.concurrency-observation.v1','testId':t,'runnerId':r['runnerId'],'contractIdentity':r['contractIdentity'],'iterationsCompleted':n,'outcomeCounts':states,'orderingObservations':order,'atomicWidthsObserved':[64],'alignmentsObserved':[8],'successCount':n,'failureCount':0,'retryCount':0,'completed':True},sys.stdout)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    path, digest, _ = _write_contract(tmp_path)
    config = _config(path, digest)
    config = subject.L2ConcurrencyRunnerConfig(
        config.base_kind, config.base_effect_config, None, config.contract_path,
        config.contract_digest,
        tuple(subject.ScenarioRunner(r.test_id, r.source_runner_id, r.target_runner_id,
                                     (str(script),), (str(script),)) for r in config.runners), 5,
    )
    monkeypatch.setattr(subject, "run_l2_effect_trace_differential", lambda *_a, **_k:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "b" * 64, "base passed"))
    result = subject.run_l2_concurrency_differential(
        config, translation_artifact=SimpleNamespace(translation_plan_id="plan-1", proof_identity=PROOF),
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
    )
    assert result.status is ValidationStatus.VERIFIED
