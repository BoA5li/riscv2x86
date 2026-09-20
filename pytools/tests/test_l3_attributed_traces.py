"""L3-3 protocol and failure-closed attribution checks; synthetic observers only."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py import l3_attributed_traces as trace
from riscv2x86_py import l3_experiment_runner as runner
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
from riscv2x86_py.validation_status import ValidationStatus
from pytools.tests.test_l3_experiment_runner import _contract, _report

H = "sha256:" + "a" * 64
BIN = "sha256:" + sha256(Path("/bin/true").read_bytes()).hexdigest()


def contract():
    region = {"regionIdentity": H, "binaryDigest": BIN, "entryIdentity": "entry:main",
              "compilerId": "clang", "compilerVersion": "17", "optimizationLevel": "O2",
              "abi": "lp64", "captureProofIdentity": H, "observerBinaryDigest": BIN,
              "approvedExclusions": [], "complete": True}
    return {"schemaVersion": trace.TRACE_CONTRACT_SCHEMA, "authorityIdentity": H,
            "fragmentId": "fragment:other-directory", "sourceEffectIds": ["branch:0", "effect:load", "effect:store"], "memoryObjects": [
                {"objectId": "arg:buffer", "sizeBytes": 512, "minimumAlignment": 8, "complete": True}],
            "sourceRegion": deepcopy(region), "targetRegion": deepcopy(region), "complete": True}


def memory(eid, effect, order, offset=64, kind="ReadMemory", preds=None):
    return {"eventId": eid, "sourceEffectId": effect, "executionOrder": order,
            "eventKind": kind, "payload": {"objectId": "arg:buffer", "offset": offset,
            "size": 8, "alignment": 8, "atomicity": "none", "memoryOrder": "relaxed"},
            "orderingPredecessors": preds or []}


def control(eid, order, outcome, preds=None):
    return {"eventId": eid, "sourceEffectId": "branch:0", "executionOrder": order,
            "eventKind": "Branch", "payload": {"subjectId": "condition:0", "outcome": outcome},
            "orderingPredecessors": preds or []}


def report(events, machine_events=None):
    if machine_events is None:
        machine_events = [machine(e, i) for i, e in enumerate(events) if e["eventKind"] in {"ReadMemory", "WriteMemory", "Branch", "ControlTransfer"}]
    region = contract()["sourceRegion"]
    return {"logicalTrace": {"schemaVersion": trace.LOGICAL_TRACE_SCHEMA, "authorityIdentity": H,
                             "fragmentId": "fragment:other-directory", "complete": True, "events": events},
            "machineTrace": {"schemaVersion": trace.MACHINE_TRACE_SCHEMA,
                             **{k: region[k] for k in ("regionIdentity", "binaryDigest", "entryIdentity",
                                 "compilerId", "compilerVersion", "optimizationLevel", "abi",
                                 "captureProofIdentity", "observerBinaryDigest")},
                             "complete": True, "events": machine_events}}


def machine(logical, order):
    payload = logical["payload"]
    return {"eventId": "instruction:" + str(order), "executionOrder": order,
            "regionOffset": 4 * order, "eventKind": logical["eventKind"],
            "logicalEventId": logical["eventId"], "objectId": payload.get("objectId", ""),
            "offset": payload.get("offset", 0), "size": payload.get("size", 0),
            "attributionKind": "logical", "attributionProofIdentity": H}


def base_events():
    return [memory("visit:0", "effect:load", 0), memory("visit:1", "effect:load", 1, preds=["visit:0"]),
            control("visit:2", 2, "taken", ["visit:1"])]


@pytest.mark.parametrize("mutation", [
    lambda e: e[1]["payload"].update(offset=72),
    lambda e: e.pop(1),
    lambda e: e.insert(1, memory("extra:write", "effect:store", 1, kind="WriteMemory")),
    lambda e: e[2]["payload"].update(outcome="not-taken"),
])
def test_complete_logical_mismatches_are_detected(mutation):
    source = report(base_events())
    target_events = base_events()
    mutation(target_events)
    for i, event in enumerate(target_events):
        event["executionOrder"] = i
        event["orderingPredecessors"] = [target_events[i-1]["eventId"]] if i else []
    target = report(target_events)
    reasons, _ = trace.compare_traces(source, target, contract())
    assert "logical-access-or-control-path-mismatch" in reasons


def test_proven_spill_excluded_only_in_bound_region():
    source = report(base_events())
    target = report(base_events())
    compiler_access = {"eventId": "spill:0", "executionOrder": 3, "regionOffset": 12,
                       "eventKind": "WriteMemory", "logicalEventId": "", "objectId": "",
                       "offset": 0, "size": 8, "attributionKind": "compiler_artifact",
                       "attributionProofIdentity": H}
    target["machineTrace"]["events"].append(compiler_access)
    with pytest.raises(ValueError, match="exclusion"):
        trace.compare_traces(source, target, contract())
    bound = contract()
    bound["targetRegion"]["approvedExclusions"] = [{"eventId": "spill:0", "eventKind": "WriteMemory",
                                                       "attributionKind": "compiler_artifact", "proofIdentity": H}]
    reasons, _ = trace.compare_traces(source, target, bound)
    assert reasons == []
    target["machineTrace"]["binaryDigest"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="binding mismatch"):
        trace.compare_traces(source, target, bound)


def test_unattributed_extra_machine_write_is_inconclusive():
    target = report(base_events())
    target["machineTrace"]["events"].append({"eventId": "surprise", "executionOrder": 3,
        "regionOffset": 12, "eventKind": "WriteMemory", "logicalEventId": "", "objectId": "",
        "offset": 0, "size": 8, "attributionKind": "compiler_artifact", "attributionProofIdentity": H})
    with pytest.raises(ValueError, match="exclusion"):
        trace.compare_traces(report(base_events()), target, contract())


@pytest.mark.parametrize("mutate", [
    lambda e: e[1].update(eventId=e[0]["eventId"]),
    lambda e: e[1]["orderingPredecessors"].append("unknown"),
    lambda e: e[0]["payload"].update(objectId="0xdeadbeef"),
    lambda e: e[1]["payload"].update(offset=512),
    lambda e: e[1].update(executionOrder=9),
])
def test_invalid_trace_is_rejected_not_repaired(mutate):
    events = base_events()
    mutate(events)
    with pytest.raises(ValueError):
        trace.parse_logical_trace(report(events)["logicalTrace"], contract())


def test_v3_runner_checks_attribution_and_retains_old_contracts(tmp_path, monkeypatch):
    old_path = tmp_path / "old.json"
    old_path.write_text(json.dumps(_contract()))
    assert runner.load_experiment_contract(old_path).identity
    bound = contract()
    value = _contract(schemaVersion=runner.EXPERIMENT_CONTRACT_TRACE_SCHEMA, traceContract=bound,
                      intentProfileIdentity=H, requirementIdentity=H,
                      approvedTargetRelationIdentity=H, programId="program:1")
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(value))
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    config = runner.ExperimentRunnerConfig("effect", None, object(), str(path), digest,
        "rv64-controlled-v1", "x86-controlled-v1", ("/bin/true",), ("/bin/true",), 10)
    monkeypatch.setattr(runner, "run_l2_effect_trace_differential", lambda *_a, **_k:
        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED, H, "L2"))
    import riscv2x86_py.l3_intent_requirements as intents
    monkeypatch.setattr(intents, "parse_l3_requirement_manifest", lambda *_:
        SimpleNamespace(requirements=[{"fragmentId": bound["fragmentId"], "eligibilityStatus": "eligible",
            "profileIdentity": H, "requirementIdentity": H, "proofIdentity": value["proofIdentity"],
            "programId": "program:1", "approvedTargetRelationIdentity": H}]))
    broken = False
    def observe(_command, stdin, _timeout):
        request = json.loads(stdin)
        base = _report(request)
        base.update(report(base_events()))
        base["schemaVersion"] = runner.EXPERIMENT_REPORT_TRACE_SCHEMA
        if broken and request["side"] == "target":
            base["logicalTrace"]["events"][1]["payload"]["offset"] = 72
            base["machineTrace"]["events"][1]["offset"] = 72
        return runner.CommandResult(0, json.dumps(base))
    kw = {"validation_plan": SimpleNamespace(profile=ValidationProfile.MICROARCH,
                  experiment_contract_id=value["experimentId"]),
          "translation_artifact": SimpleNamespace(translation_plan_id=value["translationPlanId"],
                  proof_identity=value["proofIdentity"], fragment_id=bound["fragmentId"],
                  l2_authority_identity=H), "comparison_policy": ARCHITECTURAL_COMPARISON_POLICY,
          "l3_command_runner": observe, "l3_source_binary_path": "/bin/true",
          "l3_target_binary_path": "/bin/true", "l3_attribution_proof_verifier": lambda *_: True,
          "l3_attribution_proof_verifier_binary_path": "/bin/true",
          "l3_attribution_proof_verifier_binary_digest": BIN}
    from pytools.tests.l3_closure_test_support import prerequisites
    prerequisites(kw, monkeypatch, value, dimension="access_pattern", property_id="property:access")
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.VERIFIED
    broken = True
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.FAILED
    kw["translation_artifact"].l2_authority_identity = "stale"
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.INCONCLUSIVE
    kw["translation_artifact"].l2_authority_identity = H
    kw["l3_attribution_proof_verifier"] = lambda *_: False
    assert runner.run_l3_experiment_validation(config, **kw).status is ValidationStatus.INCONCLUSIVE
