from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py.l3_intent_requirements import _hash, classify_l3_requirements
from riscv2x86_py.l3_experiment_runner import EXPERIMENT_CONTRACT_BOUND_SCHEMA
from riscv2x86_py.l3_provider_resolution import (
    PROVIDER_SCHEMA, REGISTRY_SCHEMA, build_l3_capability_registry_validator,
    provider_from_dict, resolve_l3_execution_plan,
)
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_status import ValidationStatus
from riscv2x86_py.validation_runtime_registry import (
    VALIDATION_RUNTIME_REGISTRY_SCHEMA, validation_runtime_registry_from_dict,
)


PROOF = "sha256:" + "a" * 64
RELATION = "sha256:" + "b" * 64
SOURCE = "sha256:" + "c" * 64
TARGET = "sha256:" + "d" * 64


def _facts():
    raw = {"schemaVersion": "riscv2x86.l3-intent-profile.v1", "fragmentId": "fragment:0",
           "programId": "program:0", "intentKind": "memory_access",
           "experimentClasses": ["memory_access"], "sourceIntent": "same logical access pattern",
           "approvedTargetRelationIdentity": RELATION,
           "requiredProperties": [{"propertyId": "property:access", "dimension": "access_pattern",
                                   "unit": "fragment"}],
           "sourceCapabilities": ["source-trace"], "targetCapabilities": ["target-trace"],
           "observationBoundary": {"kind": "proof-region", "identity": PROOF},
           "notClaimedProperties": ["cache-miss-count-equality"],
           "producer": {"kind": "translation-proof", "producerIdentity": PROOF,
                        "proofIdentity": PROOF}, "complete": True}
    profile = dict(raw, profileIdentity=_hash(raw))
    manifest = classify_l3_requirements({"findings": [
        {"fragment": {"id": "fragment:0"}, "translationOutcome": "emitted",
         "l3IntentProfile": profile}
    ]}).to_dict()
    return profile, manifest


def _contract(path: Path, profile: dict, requirement: dict):
    contract = {
        "schemaVersion": EXPERIMENT_CONTRACT_BOUND_SCHEMA,
        "experimentId": "experiment:0", "translationPlanId": "plan:0",
        "proofIdentity": PROOF, "intentProfileIdentity": profile["profileIdentity"],
        "requirementIdentity": requirement["requirementIdentity"],
        "approvedTargetRelationIdentity": RELATION, "programId": "program:0",
        "sourceIntent": "same logical access pattern", "targetStrategy": "registered access tracer",
        "strategyRegistrationId": "strategy:access-v1",
        "preservationLevel": "microarchitecture_intent_preserved",
        "experimentClasses": ["memory_access"],
        "requiredAccessPattern": [{"eventId": "access:0", "objectId": "arg:buffer", "offset": 0,
                                   "size": 8, "access": "read", "alignment": 8,
                                   "atomicity": "none", "requiredOrdering": "none",
                                   "orderingPredecessors": []}],
        "approvedExtraAccesses": [], "requiredControlFlow": [], "requiredSyncSemantics": [],
        "metrics": [], "calibrationProtocol": "paired-v1", "sampleCount": 4,
        "warmupCount": 1, "randomSeed": 7, "affinityPolicy": "pin-core",
        "noisePolicy": "record-all", "sourceEnvironmentRequirements": {},
        "targetEnvironmentRequirements": {},
        "knownNonEquivalences": ["cache geometry differs"], "complete": True,
    }
    path.write_text(json.dumps(contract), encoding="utf-8")
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _provider(path: Path, digest: str, *, provider_id="auto", kind="automatic",
              fragments=None, profiles=None, validator="l3-experiment-contract"):
    return {"schemaVersion": PROVIDER_SCHEMA, "providerId": provider_id,
            "bindingKind": kind, "validatorType": validator,
            "config": {"contractPath": str(path), "contractDigest": digest,
                       "sourceCommand": ["/bin/true"], "targetCommand": ["/bin/true"]},
            "experimentClasses": ["memory_access"], "propertyDimensions": ["access_pattern"],
            "sourceCapabilities": ["source-trace"], "targetCapabilities": ["target-trace"],
            "executionProfiles": ["rv64-to-x86"],
            "contractSchemas": [EXPERIMENT_CONTRACT_BOUND_SCHEMA],
            "fragmentIds": fragments or [], "profileIdentities": profiles or []}


def _resolve(profile, manifest, providers, *, source=None, target=None, execution="rv64-to-x86"):
    return resolve_l3_execution_plan(
        manifest["requirements"][0], profile, tuple(provider_from_dict(x) for x in providers),
        execution_profile=execution, source_capabilities=tuple(source or ("source-trace",)),
        target_capabilities=tuple(target or ("target-trace",)),
        environment_identity=PROOF, source_artifact_digest=SOURCE,
        target_artifact_digest=TARGET, validator_types={"l3-experiment-contract", "other-registered"},
        translation_plan_id="plan:0", experiment_contract_id="experiment:0",
    )


def test_exact_binding_overrides_automatic_and_ambiguity_fails_closed(tmp_path):
    profile, manifest = _facts()
    path = tmp_path / "experiment.json"
    digest = _contract(path, profile, manifest["requirements"][0])
    auto = _provider(path, digest)
    exact = _provider(path, digest, provider_id="explicit", kind="explicit",
                      fragments=["fragment:0"])
    selected = _resolve(profile, manifest, [auto, exact])
    assert selected["bindingStatus"] == "resolved"
    assert selected["providerId"] == "explicit"
    competing = _provider(path, digest, provider_id="other", kind="explicit",
                          fragments=["fragment:0"])
    ambiguous = _resolve(profile, manifest, [auto, exact, competing])
    assert ambiguous["bindingStatus"] == "inconclusive"
    assert ambiguous["reasonCodes"] == ["l3.provider.ambiguous"]


def test_missing_capability_and_contract_version_and_stale_digest(tmp_path):
    profile, manifest = _facts()
    path = tmp_path / "experiment.json"
    digest = _contract(path, profile, manifest["requirements"][0])
    provider = _provider(path, digest)
    assert _resolve(profile, manifest, [provider], target=["different"])["reasonCodes"] == [
        "l3.capability.target-missing:target-trace"]
    bad_version = dict(provider, contractSchemas=["riscv2x86.microarchitecture-experiment-contract.v1"])
    assert _resolve(profile, manifest, [bad_version])["reasonCodes"] == ["l3.contract.version-mismatch"]
    path.write_text(path.read_text() + "\n", encoding="utf-8")
    assert _resolve(profile, manifest, [provider])["reasonCodes"] == ["l3.contract.stale"]
    explicit = _provider(path, digest, provider_id="manual", kind="explicit",
                         fragments=["fragment:0"])
    assert _resolve(profile, manifest, [provider, explicit])["reasonCodes"] == ["l3.contract.stale"]


def test_environment_and_artifact_and_runner_files_change_execution_identity(tmp_path):
    profile, manifest = _facts()
    path = tmp_path / "experiment.json"
    digest = _contract(path, profile, manifest["requirements"][0])
    provider = _provider(path, digest)
    first = _resolve(profile, manifest, [provider])
    changed_source = resolve_l3_execution_plan(
        manifest["requirements"][0], profile, (provider_from_dict(provider),),
        execution_profile="rv64-to-x86", source_capabilities=("source-trace",),
        target_capabilities=("target-trace",), environment_identity=PROOF,
        source_artifact_digest="sha256:" + "e" * 64, target_artifact_digest=TARGET,
        validator_types={"l3-experiment-contract"})
    assert first["executionIdentity"] != changed_source["executionIdentity"]
    assert first["sourceRunnerBinaries"][0]["digest"].startswith("sha256:")
    assert first["contractIdentity"].startswith("sha256:")
    changed_environment = resolve_l3_execution_plan(
        manifest["requirements"][0], profile, (provider_from_dict(provider),),
        execution_profile="rv64-to-x86", source_capabilities=("source-trace",),
        target_capabilities=("target-trace",), environment_identity="sha256:" + "e" * 64,
        source_artifact_digest=SOURCE, target_artifact_digest=TARGET,
        validator_types={"l3-experiment-contract"})
    assert first["executionIdentity"] != changed_environment["executionIdentity"]
    runner = tmp_path / "runner"
    runner.write_text("#!/bin/sh\nexit 0\n")
    runner.chmod(0o755)
    local = _provider(path, digest)
    local["config"] = dict(local["config"], sourceCommand=[str(runner)])
    before = _resolve(profile, manifest, [local])
    runner.write_text("#!/bin/sh\nexit 1\n")
    after = _resolve(profile, manifest, [local])
    assert before["executionIdentity"] != after["executionIdentity"]


def test_declared_provider_cannot_cover_missing_contract_properties(tmp_path):
    profile, manifest = _facts()
    path = tmp_path / "experiment.json"
    digest = _contract(path, profile, manifest["requirements"][0])
    contract = json.loads(path.read_text())
    contract["experimentClasses"] = ["statistical"]
    contract["requiredAccessPattern"] = []
    contract["metrics"] = [{"metricId": "effect", "sourceMetric": "source",
                            "targetMetric": "target", "observationDomain": "within-platform",
                            "statisticalTest": "bootstrap_median_effect_v1",
                            "acceptanceCriteria": {"direction": "increase",
                                                   "minimumAbsoluteEffectSize": 0.1,
                                                   "confidenceLevel": 0.95}}]
    path.write_text(json.dumps(contract), encoding="utf-8")
    digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    assert _resolve(profile, manifest, [_provider(path, digest)])["reasonCodes"] == [
        "l3.contract.properties-uncovered"]


def test_registered_new_validator_type_needs_no_resolver_edits(tmp_path):
    profile, manifest = _facts()
    path = tmp_path / "experiment.json"
    digest = _contract(path, profile, manifest["requirements"][0])
    provider = _provider(path, digest, validator="other-registered")
    assert _resolve(profile, manifest, [provider])["bindingStatus"] == "resolved"

    def fake_factory(_config):
        return lambda **kwargs: ValidationLayerResult(ValidationLevel.L3, ValidationStatus.VERIFIED,
                                                      "sha256:" + "f" * 64)

    validator = build_l3_capability_registry_validator(
        {"schemaVersion": REGISTRY_SCHEMA, "providers": [provider],
         "executionProfile": "rv64-to-x86", "sourceCapabilities": ["source-trace"],
         "targetCapabilities": ["target-trace"], "environmentId": "environment:0"},
        {"other-registered": fake_factory},
    )
    kwargs = {"translation_artifact": SimpleNamespace(fragment_id="fragment:0", proof_identity=PROOF,
                                                        translation_plan_id="plan:0"),
              "validation_plan": SimpleNamespace(experiment_contract_id="experiment:0"),
              "target_environment": {"environmentId": "environment:0"},
              "source_program_artifact": SimpleNamespace(artifact_digest=SOURCE),
              "target_program_artifact": SimpleNamespace(artifact_digest=TARGET),
              "l3_intent_profile": profile, "l3_requirement_manifest": manifest,
              "l3_plan_directory": str(tmp_path / "plans")}
    result = validator(**kwargs)
    assert result.status is ValidationStatus.VERIFIED
    assert list((tmp_path / "plans").glob("*.json"))
    assert "executionIdentity" in result.detail
    no_manifest = validator(**dict(kwargs, l3_requirement_manifest=None))
    assert no_manifest.status is ValidationStatus.INCONCLUSIVE

    registry = validation_runtime_registry_from_dict({
        "schemaVersion": VALIDATION_RUNTIME_REGISTRY_SCHEMA, "version": "test-registry",
        "validators": {"L3": {"type": "l3-capability-provider-registry",
                             "config": {"schemaVersion": REGISTRY_SCHEMA, "providers": [provider],
                                        "executionProfile": "rv64-to-x86",
                                        "sourceCapabilities": ["source-trace"],
                                        "targetCapabilities": ["target-trace"],
                                        "environmentId": "environment:0"}}},
    }, validator_factories={"other-registered": fake_factory})
    assert registry.validator_for(ValidationLevel.L3)(**kwargs).status is ValidationStatus.VERIFIED


def test_no_intent_does_not_bind_and_invalid_provider_is_rejected(tmp_path):
    profile, manifest = _facts()
    path = tmp_path / "experiment.json"
    digest = _contract(path, profile, manifest["requirements"][0])
    bad = _provider(path, digest, kind="explicit")
    with pytest.raises(ValueError, match="explicit L3 provider"):
        provider_from_dict(bad)
    manifest["requirements"][0]["eligibilityStatus"] = "inconclusive"
    # Resolver receives a validated manifest in normal operation; this direct
    # call checks the gate without claiming a complete experimental result.
    assert _resolve(profile, manifest, [_provider(path, digest)])["bindingStatus"] == "not_run"
