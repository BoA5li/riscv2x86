import json
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_dimensions import L2Dimension, L2EligibilityStatus
from riscv2x86_py.l2_eligibility import classify_l2_requirements
from riscv2x86_py.l2_validator_resolution import (
    ExplicitL2Bindings, L2FragmentRequirement, L2RuntimeCapabilities,
    L2ValidatorProvider, L2ValidatorResolver, validate_resolved_execution_plan,
)
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_runtime_registry import validation_runtime_registry_from_dict
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


def _requirement():
    return L2FragmentRequirement(
        "fragment:1", "sha256:" + "1" * 64,
        (L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
        L2EligibilityStatus.ELIGIBLE,
    )


def _provider(provider_id, kind, dimensions):
    return L2ValidatorProvider(
        provider_id, tuple(dimensions), kind, "test-provider", {}, ()
    )


def test_resolver_prefers_explicit_provider_without_dropping_dimensions():
    automatic = _provider("auto", "automatic", (L2Dimension.LOGICAL_OPERANDS,))
    explicit = _provider("explicit", "explicit", (L2Dimension.LOGICAL_OPERANDS,))
    shell = _provider("shell", "automatic", (L2Dimension.SHELL_SEMANTICS,))
    plan = L2ValidatorResolver().resolve(
        _requirement(), L2RuntimeCapabilities((automatic, shell)),
        ExplicitL2Bindings((explicit,)), execution_profile="rv64gc-user-to-x86_64-user",
    )
    assert [item.dimension for item in plan.bindings] == list(_requirement().required_dimensions)
    assert plan.bindings[0].provider_id == "explicit"
    assert plan.complete
    validate_resolved_execution_plan(plan.to_dict())


def test_resolver_marks_missing_and_ambiguous_bindings_fail_closed():
    duplicate = (
        _provider("a", "automatic", (L2Dimension.LOGICAL_OPERANDS,)),
        _provider("b", "automatic", (L2Dimension.LOGICAL_OPERANDS,)),
    )
    plan = L2ValidatorResolver().resolve(
        _requirement(), L2RuntimeCapabilities(duplicate),
        execution_profile="rv64gc-user-to-x86_64-user",
    )
    assert not plan.complete
    assert [item.binding_status.value for item in plan.bindings] == ["inconclusive", "not_run"]


def _manifest(path):
    report = {"findings": [{
        "translationOutcome": "emitted",
        "fragment": {"id": "fragment:1", "inputs": [{"name": "lhs"}],
                     "outputs": [{"name": "out"}], "clobbers": []},
        "translationReasonCodes": [],
    }]}
    value = classify_l2_requirements(report)
    path.write_text(json.dumps(value), encoding="utf-8")
    return value


def _factory(_config):
    return lambda **kwargs: ValidationLayerResult(
        kwargs["level"], ValidationStatus.VERIFIED, "sha256:" + "a" * 64, "ok"
    )


def _registry(tmp_path, providers):
    manifest = tmp_path / "requirements.json"
    _manifest(manifest)
    plan = tmp_path / "resolved-plan.json"
    payload = {
        "schemaVersion": "riscv2x86.validation-runtime-registry.v2",
        "version": "test-v1",
        "validators": {"L2": {"type": "requirement-driven", "config": {
            "schemaVersion": "riscv2x86.l2-requirement-driven-registry.v1",
            "requirementManifestPath": str(manifest), "fragmentId": "fragment:1",
            "executionProfile": "rv64gc-user-to-x86_64-user",
            "resolvedPlanPath": str(plan), "providers": providers,
        }}},
    }
    registry = validation_runtime_registry_from_dict(
        payload, validator_factories={"test-provider": _factory},
    )
    return registry, plan


def _artifact():
    identity = "sha256:" + "b" * 64
    return SimpleNamespace(
        fragment_id="fragment:1", preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
        shell_facts_identity=identity, proof_identity=identity,
        l2_authority_identity=identity, effect_relation_set_identity=identity,
        l2_authority_complete=True,
    )


def _observation():
    return SimpleNamespace(identity="sha256:" + "c" * 64)


def test_registry_consumes_manifest_and_persists_plan(tmp_path):
    providers = [{
        "providerId": "both", "dimensions": ["logical_operands", "shell_semantics"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "config": {}, "fragmentIds": [],
    }]
    registry, plan_path = _registry(tmp_path, providers)
    assert plan_path.is_file()
    validator = registry.validator_for(ValidationLevel.L2)
    result = validator(
        level=ValidationLevel.L2, translation_artifact=_artifact(),
        source_observation=_observation(), target_observation=_observation(),
    )
    assert result.status is ValidationStatus.VERIFIED
    detail = json.loads(result.detail)
    assert detail["schemaVersion"] == "riscv2x86.l2-fragment-result.v2"
    assert set(detail["dimensionResults"]) == {"logical_operands", "shell_semantics"}
    assert detail["requiredDimensions"] == ["logical_operands", "shell_semantics"]
    assert detail["claimScope"] == "architectural"
    assert all(item["schemaVersion"] == "riscv2x86.l2-dimension-result.v2"
               for item in detail["dimensionResults"].values())
    assert len({item["executionIdentity"]
                for item in detail["dimensionResults"].values()}) == 1


def test_registry_missing_required_provider_cannot_verify(tmp_path):
    providers = [{
        "providerId": "operand", "dimensions": ["logical_operands"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "config": {}, "fragmentIds": [],
    }]
    registry, _plan_path = _registry(tmp_path, providers)
    result = registry.validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2,
        translation_artifact=_artifact(),
        source_observation=_observation(), target_observation=_observation(),
    )
    assert result.status is ValidationStatus.INCONCLUSIVE
    detail = json.loads(result.detail)
    assert detail["status"] == "not_run"
    assert detail["dimensionResults"]["shell_semantics"]["status"] == "not_run"


def test_provider_dimensions_reject_legacy_alias(tmp_path):
    providers = [{
        "providerId": "legacy", "dimensions": ["operands"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "config": {}, "fragmentIds": [],
    }]
    with pytest.raises(ValueError, match="unsupported L2 dimension"):
        _registry(tmp_path, providers)
