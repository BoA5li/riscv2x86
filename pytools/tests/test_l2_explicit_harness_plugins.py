from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_dimensions import L2Dimension, L2EligibilityStatus
from riscv2x86_py.l2_explicit_harness import (
    EXPLICIT_L2_HARNESS_MANIFEST_SCHEMA, EXPLICIT_L2_HARNESS_RUNNER_SCHEMA,
    EXPLICIT_L2_OBSERVATION_SCHEMA, load_explicit_l2_harness_manifest,
    load_explicit_l2_harness_runner_config, run_explicit_l2_harness,
    validate_explicit_l2_harness_provider,
)
from riscv2x86_py.l2_semantic_profile import (
    L2PatternKind, l2_fragment_semantic_profile_from_dict,
)
from riscv2x86_py.l2_validator_resolution import (
    ExplicitL2Bindings, L2BindingKind, L2BindingStatus, L2FragmentRequirement,
    L2RuntimeCapabilities, L2ValidatorProvider, L2ValidatorResolver,
)
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.validation_status import ValidationStatus
from tests.l2_profile_fixtures import profile_dict
from tests.l2_materialization_fixtures import complete_materialization_decision


def _identity(value):
    return "sha256:" + sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()


def _digest(path: Path):
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _profile():
    return l2_fragment_semantic_profile_from_dict(
        profile_dict("fragment:0", L2PatternKind.BRANCH)
    )


def _provider(provider_id, kind, profiles=()):
    return L2ValidatorProvider(
        provider_id, (L2Dimension.CONTROL_FLOW,), (L2PatternKind.BRANCH,),
        ("control_flow_observation",), ("rv64gc-user-to-x86_64-user",),
        kind, "l2-explicit-harness" if kind is L2BindingKind.EXPLICIT else "automatic",
        "config.v1", {"schemaVersion": "config.v1"}, (), tuple(profiles),
    )


def test_explicit_provider_wins_but_stale_profile_falls_back_to_automatic():
    profile = _profile()
    requirement = L2FragmentRequirement(
        "fragment:0", "sha256:" + "2" * 64, (L2Dimension.CONTROL_FLOW,),
        L2EligibilityStatus.ELIGIBLE, profile.profile_identity, "branch",
        profile.required_capabilities, None,
        complete_materialization_decision("fragment:0", (L2Dimension.CONTROL_FLOW,)),
    )
    explicit = _provider("explicit", L2BindingKind.EXPLICIT,
                         (profile.profile_identity,))
    automatic = _provider("automatic", L2BindingKind.AUTOMATIC)
    runtime = L2RuntimeCapabilities((automatic,), ("control_flow_observation",),
                                    (profile.execution_profile,))
    plan = L2ValidatorResolver().resolve(
        requirement, runtime, ExplicitL2Bindings((explicit,)),
        execution_profile=profile.execution_profile, profile=profile,
    )
    assert plan.bindings[0].provider_id == "explicit"

    stale = replace(explicit, semantic_profile_ids=("sha256:" + "3" * 64,))
    fallback = L2ValidatorResolver().resolve(
        requirement, runtime, ExplicitL2Bindings((stale,)),
        execution_profile=profile.execution_profile, profile=profile,
    )
    assert fallback.bindings[0].provider_id == "automatic"


def test_insufficient_provided_dimensions_do_not_close_fragment():
    profile = _profile()
    requirement = L2FragmentRequirement(
        "fragment:0", "sha256:" + "2" * 64,
        (L2Dimension.CONTROL_FLOW, L2Dimension.MEMORY_EFFECTS),
        L2EligibilityStatus.ELIGIBLE, profile.profile_identity, "branch",
        profile.required_capabilities, None,
        complete_materialization_decision("fragment:0", (
            L2Dimension.CONTROL_FLOW, L2Dimension.MEMORY_EFFECTS)),
    )
    explicit = _provider("explicit", L2BindingKind.EXPLICIT,
                         (profile.profile_identity,))
    plan = L2ValidatorResolver().resolve(
        requirement,
        L2RuntimeCapabilities((), ("control_flow_observation",),
                              (profile.execution_profile,)),
        ExplicitL2Bindings((explicit,)), execution_profile=profile.execution_profile,
        profile=profile,
    )
    assert [item.binding_status for item in plan.bindings] == [
        L2BindingStatus.RESOLVED, L2BindingStatus.NOT_RUN]
    assert not plan.complete


def _write_plugin(tmp_path, *, source_text="source-v1", target_text="target-v1"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "source-harness.py"
    target = tmp_path / "target-harness.py"
    script = ("import json,sys\nr=json.load(sys.stdin)\njson.dump({"
              "'schemaVersion':'riscv2x86.explicit-l2-observation.v1',"
              "'fragmentId':r['fragmentId'],"
              "'semanticProfileIdentity':r['semanticProfileIdentity'],"
              "'dimensionObservations':{'control_flow':{'taken':True,'continuation':'taken'}},"
              "'termination':'normal'},sys.stdout,sort_keys=True)\n")
    source.write_text("# " + source_text + "\n" + script)
    target.write_text("# " + target_text + "\n" + script)
    profile_id = _profile().profile_identity
    relation = "sha256:" + "4" * 64
    payload = {
        "schemaVersion": EXPLICIT_L2_HARNESS_MANIFEST_SCHEMA,
        "harnessId": "branch-harness", "harnessVersion": "v1",
        "producerDigest": "sha256:" + "5" * 64,
        "supportedFragmentIdentities": ["fragment:0"],
        "supportedSemanticProfiles": [profile_id], "contractId": "branch-contract.v1",
        "providedDimensions": ["control_flow"],
        "executionProfile": "rv64gc-user-to-x86_64-user",
        "sourceHarnessDigest": _digest(source), "targetHarnessDigest": _digest(target),
        "observationSchemaVersion": EXPLICIT_L2_OBSERVATION_SCHEMA,
        "relationSetIdentity": relation,
        "nonInterferenceProofIdentity": "sha256:" + "6" * 64,
        "complete": True,
    }
    payload["manifestIdentity"] = _identity(payload)
    manifest = tmp_path / "harness.json"; manifest.write_text(json.dumps(payload))
    config = load_explicit_l2_harness_runner_config({
        "schemaVersion": EXPLICIT_L2_HARNESS_RUNNER_SCHEMA,
        "manifestPath": str(manifest), "sourceHarnessPath": str(source),
        "targetHarnessPath": str(target),
        "sourceCommand": ["python", str(source)], "targetCommand": ["python", str(target)],
        "contractId": "branch-contract.v1", "timeoutSeconds": 10,
    })
    artifact = SimpleNamespace(fragment_id="fragment:0",
        l2_semantic_profile_identity=profile_id, effect_relation_set_identity=relation)
    return manifest, config, artifact


def test_harness_executes_and_digest_changes_observation_identity(tmp_path):
    manifest, config, artifact = _write_plugin(tmp_path)
    result = run_explicit_l2_harness(config, level=ValidationLevel.L2,
                                     translation_artifact=artifact)
    assert result.status is ValidationStatus.VERIFIED
    first = json.loads(result.detail)["sourceObservationIdentity"]

    manifest2, config2, artifact2 = _write_plugin(
        tmp_path / "changed", source_text="source-v2")
    result2 = run_explicit_l2_harness(config2, level=ValidationLevel.L2,
                                      translation_artifact=artifact2)
    assert result2.status is ValidationStatus.VERIFIED
    assert json.loads(result2.detail)["sourceObservationIdentity"] != first


def test_stale_manifest_and_execution_failure_are_inconclusive(tmp_path):
    manifest, config, artifact = _write_plugin(tmp_path)
    value = json.loads(manifest.read_text()); value["harnessVersion"] = "v2"
    manifest.write_text(json.dumps(value))
    stale = run_explicit_l2_harness(config, level=ValidationLevel.L2,
                                    translation_artifact=artifact)
    assert stale.status is ValidationStatus.INCONCLUSIVE
    assert "binding-invalid" in stale.detail

    manifest, config, artifact = _write_plugin(tmp_path / "failure")
    failed_config = replace(config, source_command=("/missing/harness",))
    failed = run_explicit_l2_harness(failed_config, level=ValidationLevel.L2,
                                     translation_artifact=artifact)
    assert failed.status is ValidationStatus.INCONCLUSIVE
    assert "runner-unavailable" in failed.detail


def test_provider_envelope_must_exactly_match_manifest_applicability(tmp_path):
    manifest_path, config, _artifact = _write_plugin(tmp_path)
    manifest = load_explicit_l2_harness_manifest(manifest_path)
    provider = L2ValidatorProvider(
        "explicit-branch", (L2Dimension.CONTROL_FLOW,), (L2PatternKind.BRANCH,),
        ("control_flow_observation",), (manifest.execution_profile,),
        L2BindingKind.EXPLICIT, "l2-explicit-harness",
        EXPLICIT_L2_HARNESS_RUNNER_SCHEMA,
        {"schemaVersion": EXPLICIT_L2_HARNESS_RUNNER_SCHEMA,
         "manifestPath": config.manifest_path,
         "sourceHarnessPath": config.source_harness_path,
         "targetHarnessPath": config.target_harness_path,
         "sourceCommand": list(config.source_command),
         "targetCommand": list(config.target_command),
         "contractId": config.contract_id, "timeoutSeconds": config.timeout_seconds},
        manifest.supported_fragment_identities, manifest.supported_semantic_profiles,
    )
    validate_explicit_l2_harness_provider(provider)
    with pytest.raises(ValueError, match="applicability"):
        validate_explicit_l2_harness_provider(
            replace(provider, semantic_profile_ids=("sha256:" + "9" * 64,))
        )
