"""L3 batch denominators and fail-closed provider enrollment."""
from __future__ import annotations

import json

import pytest

from riscv2x86_py import automatic_batch_cli as auto
from riscv2x86_py.l3_coverage import merge_l3_coverage, summarize_l3_case
from riscv2x86_py.l3_intent_requirements import INTENT_SCHEMA, _hash, classify_l3_requirements

H = "sha256:" + "a" * 64


def _intent(fid, kind="memory_access"):
    data = {"schemaVersion": INTENT_SCHEMA, "fragmentId": fid, "programId": "program:one",
            "intentKind": kind, "experimentClasses": [kind] if kind != "none" else [],
            "sourceIntent": "registered experimental purpose", "approvedTargetRelationIdentity": H if kind != "none" else "",
            "requiredProperties": [{"propertyId": "p:0", "dimension": "access_pattern", "unit": "fragment"}]
            if kind != "none" else [], "sourceCapabilities": ["trace"],
            "targetCapabilities": ["trace"],
            "observationBoundary": {"kind": "region", "identity": H},
            "notClaimedProperties": [], "producer": {"kind": "translation-proof", "producerIdentity": H,
                                             "proofIdentity": H}, "complete": True}
    return dict(data, profileIdentity=_hash(data))


def _evaluation():
    findings = [{"fragment": {"id": f"fragment:{i}"}, "translationOutcome": "emitted",
                 "l3IntentProfile": _intent(f"fragment:{i}")} for i in range(10)]
    findings += [{"fragment": {"id": "fragment:none"}, "translationOutcome": "emitted",
                  "l3IntentProfile": _intent("fragment:none", "none")},
                 {"fragment": {"id": "fragment:route"}, "translationOutcome": "needs_route",
                  "l3IntentProfile": _intent("fragment:route")}]
    manifest = classify_l3_requirements({"findings": findings}).to_dict()
    return {"translationEvaluationLink": {"findings": [
        {"fragmentId": finding["fragment"]["id"]} for finding in findings],
        "l3Requirements": manifest}, "attempts": []}, manifest


def test_eligible_not_run_stays_in_denominator_and_program_cluster_is_one():
    evaluation, manifest = _evaluation()
    result = summarize_l3_case(evaluation, ())
    assert result["recognizedFragmentCount"] == 12
    assert result["counts"]["intentClassification"] == 12
    assert result["eligibilityCounts"] == {"eligible": 10, "needs_route": 1, "not_applicable": 1}
    assert result["counts"]["notRun"] == 10
    assert result["counts"]["completeExecution"] == 0
    assert result["counts"]["architecturalIntentVerified"] == 0
    assert manifest["requirements"][0]["programId"] == "program:one"
    merged = merge_l3_coverage([{"l3Coverage": result}])
    assert merged["counts"]["notRun"] == 10
    assert merged["metricDefinitions"]["attempted"]["denominator"] == "L3 eligible fragments"


def test_invocation_not_equivalent_to_evidence_or_verification():
    evaluation, _ = _evaluation()
    evaluation["attempts"] = [{"fragmentId": "fragment:0", "validation": {"layers": [
        {"level": "L3", "status": "inconclusive", "detail": json.dumps({
            "providerInvoked": True, "providerKind": "explicit", "executionIdentity": H,
            "reasonCodes": ["l3.capability.source-missing:perf"]})}]}}]
    result = summarize_l3_case(evaluation, ())
    assert result["counts"]["attempted"] == 1
    assert result["counts"]["inconclusive"] == 1
    assert result["counts"]["notRun"] == 9
    assert result["providerInvocationCounts"] == {"explicit": 1}
    assert result["missingCapabilityCounts"] == {"l3.capability.source-missing:perf": 1}


def test_diagnostic_evidence_never_enters_architectural_numerator():
    evaluation, manifest = _evaluation()
    req = manifest["requirements"][0]
    result = {"fragmentId": req["fragmentId"], "requirementIdentity": req["requirementIdentity"],
              "claimScope": "target_experiment_diagnostic", "status": "verified",
              "uncoveredEffects": [], "dimensionResults": {"p:0": {"status": "verified",
                                                               "evidenceIdentity": H}}}
    counts = summarize_l3_case(evaluation, [result])["counts"]
    assert counts["architecturalIntentVerified"] == 0
    assert counts["diagnosticVerified"] == 1


def test_binding_requires_content_and_source_identity(tmp_path, monkeypatch):
    source = tmp_path / "case.c"; source.write_text("int f(void) {return 1;}\n")
    frontend = tmp_path / "frontend"; frontend.write_text("x"); frontend.chmod(0o755)
    directory = tmp_path / "bindings"; directory.mkdir()
    monkeypatch.setattr(auto, "inspect_entry_points", lambda _: (False, ({
        "name": "f", "arity": 0, "returnType": "int", "parameterTypes": [],
        "l2OperandBoundary": {"complete": True}},)))
    provider = {"schemaVersion": "riscv2x86.l3-validator-provider.v1",
                "providerId": "bounded-experiment", "bindingKind": "explicit",
                "validatorType": "l3-experiment-contract", "config": {"contractPath": "missing"},
                "experimentClasses": ["memory_access"], "propertyDimensions": ["access_pattern"],
                "sourceCapabilities": [], "targetCapabilities": [],
                "executionProfiles": ["rv64gc-user-to-x86_64-user"],
                "contractSchemas": ["riscv2x86.l3-experiment-contract.v1"],
                "fragmentIds": [], "profileIdentities": [H]}
    raw = {"schemaVersion": "riscv2x86.l3-batch-provider-binding.v1",
           "sourceRelativePath": "case.c", "sourceDigest": auto._digest(source),
           "executionProfile": "rv64gc-user-to-x86_64-user",
           "environmentId": "auto-rv64gc-qemu-x86-native-v1",
           "sourceCapabilities": [], "targetCapabilities": [], "providers": [provider]}
    raw["manifestIdentity"] = auto._identity(raw)
    path = directory / "case.c.l3-providers.json"; path.write_text(json.dumps(raw))
    auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend,
                                     l3_provider_directory=directory)
    descriptor = json.loads(next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json")).read_text())
    plan = json.loads((tmp_path / "inventory/cases/case/validation-plan.json").read_text())
    assert plan["profile"] == "microarch"
    assert plan["experimentContractId"] == "resolved-per-fragment"
    assert "L3" in descriptor["request"]["runtimeRegistryTemplate"]["validators"]
    source.write_text("int f(void) {return 2;}\n")
    with pytest.raises(ValueError, match="stale"):
        auto.prepare_automatic_inventory(source, tmp_path / "inventory2", frontend=frontend,
                                         l3_provider_directory=directory)
