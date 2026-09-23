import json
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_dimensions import L2Dimension, L2EligibilityStatus
from riscv2x86_py.l2_eligibility import classify_l2_requirements
from riscv2x86_py.l2_validator_resolution import (
    ExplicitL2Bindings, L2BindingKind, L2FragmentRequirement, L2RuntimeCapabilities,
    L2ValidatorProvider, L2ValidatorResolver, validate_resolved_execution_plan,
)
from riscv2x86_py.l2_semantic_profile import (
    L2PatternKind, l2_fragment_semantic_profile_from_dict,
)
from riscv2x86_py.l2_memory_object import (
    AuthorityMaterializationDecision, MemoryAccessAuthority,
)
from riscv2x86_py.l2_evidence_closure import provider_evidence_fields
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_runtime_registry import validation_runtime_registry_from_dict
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus
from tests.l2_profile_fixtures import profile_dict


def _requirement(kind=L2PatternKind.SCALAR, dimensions=None):
    profile = profile_dict(kind=kind)
    decision = None
    if kind in {L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE}:
        access = "load" if kind is L2PatternKind.MEMORY_LOAD else "store"
        authority = MemoryAccessAuthority(
            "fragment:1", access, "parameter-object:base", "base", "base",
            0, 8, 8, 8, 32, "0<=0 && 8<=32", "alias:base", "c.default",
            "value", False, True)
        decision = AuthorityMaterializationDecision(
            "fragment:1", True, (), authority).to_dict()
    return L2FragmentRequirement(
        "fragment:1", "sha256:" + "1" * 64,
        dimensions or (L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
        L2EligibilityStatus.ELIGIBLE,
        profile["profileIdentity"], profile["patternKind"],
        tuple(profile["requiredCapabilities"]), decision,
    )


def _provider(provider_id, kind, dimensions, *, patterns=(L2PatternKind.SCALAR,),
              capabilities=("logical_operand_observation", "shell_observation")):
    return L2ValidatorProvider(
        provider_id, tuple(dimensions),
        tuple(sorted(patterns, key=lambda item: item.value)),
        tuple(sorted(capabilities)),
        ("rv64gc-user-to-x86_64-user",), L2BindingKind(kind),
        "test-provider", "test-provider.v1",
        {"schemaVersion": "test-provider.v1"}, (),
    )


def _runtime(providers, capabilities=("logical_operand_observation", "shell_observation")):
    return L2RuntimeCapabilities(
        tuple(providers), tuple(sorted(capabilities)),
        ("rv64gc-user-to-x86_64-user",),
    )


def test_resolver_prefers_explicit_provider_without_dropping_dimensions():
    automatic = _provider("auto", "automatic", (L2Dimension.LOGICAL_OPERANDS,))
    explicit = _provider("explicit", "explicit", (L2Dimension.LOGICAL_OPERANDS,))
    shell = _provider("shell", "automatic", (L2Dimension.SHELL_SEMANTICS,))
    plan = L2ValidatorResolver().resolve(
        _requirement(), _runtime((automatic, shell)),
        ExplicitL2Bindings((explicit,)), execution_profile="rv64gc-user-to-x86_64-user",
        profile=l2_fragment_semantic_profile_from_dict(profile_dict()),
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
        _requirement(), _runtime(duplicate),
        execution_profile="rv64gc-user-to-x86_64-user",
        profile=l2_fragment_semantic_profile_from_dict(profile_dict()),
    )
    assert not plan.complete
    assert [item.binding_status.value for item in plan.bindings] == ["inconclusive", "not_run"]


@pytest.mark.parametrize("pattern", [
    L2PatternKind.BRANCH, L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE,
])
def test_operand_family_is_matched_per_declared_non_scalar_pattern(pattern):
    requirement = _requirement(pattern, (L2Dimension.LOGICAL_OPERANDS,))
    profile = l2_fragment_semantic_profile_from_dict(profile_dict(kind=pattern))
    operand = _provider(
        "operand-family", "automatic", (L2Dimension.LOGICAL_OPERANDS,),
        patterns=(L2PatternKind.BRANCH, L2PatternKind.MEMORY_LOAD,
                  L2PatternKind.MEMORY_STORE, L2PatternKind.SCALAR),
        capabilities=("logical_operand_observation",),
    )
    plan = L2ValidatorResolver().resolve(
        requirement, _runtime((operand,), ("logical_operand_observation",)),
        execution_profile="rv64gc-user-to-x86_64-user", profile=profile,
    )
    assert plan.complete
    assert plan.bindings[0].provider_id == "operand-family"
    assert plan.bindings[0].matched_capabilities == ("logical_operand_observation",)


def test_missing_environment_capability_is_reported_on_binding():
    requirement = _requirement(dimensions=(L2Dimension.LOGICAL_OPERANDS,))
    profile = l2_fragment_semantic_profile_from_dict(profile_dict())
    operand = _provider(
        "operand", "automatic", (L2Dimension.LOGICAL_OPERANDS,),
        capabilities=("logical_operand_observation",),
    )
    plan = L2ValidatorResolver().resolve(
        requirement, _runtime((operand,), ()),
        execution_profile="rv64gc-user-to-x86_64-user", profile=profile,
    )
    binding = plan.bindings[0]
    assert binding.binding_status.value == "not_run"
    assert binding.missing_capabilities == ("logical_operand_observation",)
    assert "l2.environment.capability-missing" in binding.reason_codes


def test_memory_provider_refuses_requirement_without_materialization_decision():
    profile = l2_fragment_semantic_profile_from_dict(
        profile_dict(kind=L2PatternKind.MEMORY_STORE))
    requirement = L2FragmentRequirement(
        "fragment:1", "sha256:" + "1" * 64,
        (L2Dimension.MEMORY_EFFECTS,), L2EligibilityStatus.ELIGIBLE,
        profile.profile_identity, profile.pattern_kind.value,
        profile.required_capabilities, None)
    provider = _provider(
        "memory", "automatic", (L2Dimension.MEMORY_EFFECTS,),
        patterns=(L2PatternKind.MEMORY_STORE,),
        capabilities=("object_relative_memory_observation",))
    plan = L2ValidatorResolver().resolve(
        requirement, _runtime((provider,), ("object_relative_memory_observation",)),
        execution_profile="rv64gc-user-to-x86_64-user", profile=profile)
    assert not plan.complete
    assert "L2_MEMORY_ADDRESS_BINDING_MISSING" in plan.bindings[0].reason_codes


def _manifest(path):
    report = {"findings": [{
        "translationOutcome": "emitted",
        "fragment": {"id": "fragment:1", "inputs": [{"name": "lhs"}],
                     "outputs": [{"name": "out"}], "clobbers": []},
        "translationReasonCodes": [],
        "l2SemanticProfile": profile_dict(),
    }]}
    value = classify_l2_requirements(report)
    path.write_text(json.dumps(value), encoding="utf-8")
    report_path = path.with_name("translated-report.json")
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return value, report_path


def _factory(_config):
    def validate(**kwargs):
        identity = "sha256:" + "c" * 64
        detail = provider_evidence_fields(
            kwargs["translation_artifact"],
            provider_id=kwargs["l2_provider_id"],
            harness_identity="sha256:" + "d" * 64,
            source_observation_identity=identity,
            target_observation_identity=identity,
            execution_nonce={"test": "registered-provider"},
        )
        return ValidationLayerResult(
            kwargs["level"], ValidationStatus.VERIFIED,
            "sha256:" + "a" * 64, json.dumps(detail, sort_keys=True))
    return validate


def _registry(tmp_path, providers, factory=_factory):
    manifest = tmp_path / "requirements.json"
    _value, report_path = _manifest(manifest)
    plan = tmp_path / "resolved-plan.json"
    payload = {
        "schemaVersion": "riscv2x86.validation-runtime-registry.v2",
        "version": "test-v1",
        "validators": {"L2": {"type": "requirement-driven", "config": {
            "schemaVersion": "riscv2x86.l2-requirement-driven-registry.v3",
            "requirementManifestPath": str(manifest), "fragmentId": "fragment:1",
            "semanticProfilePath": str(report_path),
            "semanticProfileSource": "translated-report",
            "providerSelectionUnit": "fragment",
            "environmentCapabilities": ["logical_operand_observation", "shell_observation"],
            "environmentExecutionProfiles": ["rv64gc-user-to-x86_64-user"],
            "executionProfile": "rv64gc-user-to-x86_64-user",
            "resolvedPlanPath": str(plan), "providers": providers,
        }}},
    }
    registry = validation_runtime_registry_from_dict(
        payload, validator_factories={"test-provider": factory},
    )
    return registry, plan


def _legacy_verified_factory(_config):
    return lambda **kwargs: ValidationLayerResult(
        kwargs["level"], ValidationStatus.VERIFIED,
        "sha256:" + "a" * 64, '{"claimScope":"architectural"}')


def _artifact():
    identity = "sha256:" + "b" * 64
    profile = profile_dict()
    return SimpleNamespace(
        fragment_id="fragment:1", preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
        shell_facts_identity=identity, proof_identity=identity,
        l2_authority_identity=identity, effect_relation_set_identity=identity,
        l2_authority_complete=True,
        l2_semantic_profile_identity=profile["profileIdentity"],
        l2_pattern_kind=profile["patternKind"],
    )


def _observation():
    return SimpleNamespace(identity="sha256:" + "c" * 64)


def test_registry_consumes_manifest_and_persists_plan(tmp_path):
    providers = [{
        "providerId": "both", "supportedDimensions": ["logical_operands", "shell_semantics"],
        "supportedPatterns": ["scalar"],
        "requiredCapabilities": ["logical_operand_observation", "shell_observation"],
        "executionProfiles": ["rv64gc-user-to-x86_64-user"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "configSchemaVersion": "test-provider.v1",
        "config": {"schemaVersion": "test-provider.v1"}, "fragmentIds": [],
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


def test_provider_verified_without_total_evidence_chain_is_inconclusive(tmp_path):
    providers = [{
        "providerId": "both", "supportedDimensions": ["logical_operands", "shell_semantics"],
        "supportedPatterns": ["scalar"],
        "requiredCapabilities": ["logical_operand_observation", "shell_observation"],
        "executionProfiles": ["rv64gc-user-to-x86_64-user"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "configSchemaVersion": "test-provider.v1",
        "config": {"schemaVersion": "test-provider.v1"}, "fragmentIds": [],
    }]
    registry, _ = _registry(tmp_path, providers, _legacy_verified_factory)
    result = registry.validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2, translation_artifact=_artifact())
    assert result.status is ValidationStatus.INCONCLUSIVE
    dimensions = json.loads(result.detail)["dimensionResults"]
    assert all("l2.provider-evidence.schema-missing-or-unsupported"
               in item["reasonCodes"] for item in dimensions.values())


def test_registry_missing_required_provider_cannot_verify(tmp_path):
    providers = [{
        "providerId": "operand", "supportedDimensions": ["logical_operands"],
        "supportedPatterns": ["scalar"],
        "requiredCapabilities": ["logical_operand_observation"],
        "executionProfiles": ["rv64gc-user-to-x86_64-user"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "configSchemaVersion": "test-provider.v1",
        "config": {"schemaVersion": "test-provider.v1"}, "fragmentIds": [],
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
        "providerId": "legacy", "supportedDimensions": ["operands"],
        "supportedPatterns": ["scalar"],
        "requiredCapabilities": ["logical_operand_observation"],
        "executionProfiles": ["rv64gc-user-to-x86_64-user"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "configSchemaVersion": "test-provider.v1",
        "config": {"schemaVersion": "test-provider.v1"}, "fragmentIds": [],
    }]
    with pytest.raises(ValueError, match="unsupported L2 dimension"):
        _registry(tmp_path, providers)


def test_provider_parser_rejects_noncanonical_pattern_order(tmp_path):
    providers = [{
        "providerId": "bad-order", "supportedDimensions": ["logical_operands"],
        "supportedPatterns": ["scalar", "branch"],
        "requiredCapabilities": ["logical_operand_observation"],
        "executionProfiles": ["rv64gc-user-to-x86_64-user"],
        "bindingKind": "automatic", "validatorType": "test-provider",
        "configSchemaVersion": "test-provider.v1",
        "config": {"schemaVersion": "test-provider.v1"}, "fragmentIds": [],
    }]
    with pytest.raises(ValueError, match="patterns are non-canonical"):
        _registry(tmp_path, providers)
