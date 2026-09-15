import json
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_authority import (
    L2AuthorityProducer, L2AuthoritySidecar, L2OperandAuthority,
    L2SourceEffectAuthority, authority_identity_set,
    l2_authority_sidecar_from_dict,
)
from riscv2x86_py.l2_dimensions import L2Dimension, L2EligibilityStatus
from riscv2x86_py.l2_validator_resolution import L2FragmentRequirement
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_runtime_registry import validation_runtime_registry_from_dict
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus
from riscv2x86_py.effect_relation import ApprovedEffectRelation


def _digest(text):
    return "sha256:" + sha256(text.encode()).hexdigest()


def _sidecar(*, fragment="fragment:1", shell=None, width=64, relation="exact", complete=True):
    approved = ApprovedEffectRelation(
        "relation:effect:0", "effect:0", ("target-effect:0",), relation,
        ("kind", "subject", "value"), (), "", complete,
    )
    return L2AuthoritySidecar(
        fragment, L2AuthorityProducer(
            "frontend-compiler-sidecar", "clang-plugin", "1", _digest("producer"),
        ), shell or _digest("shell"),
        (L2OperandAuthority("operand:out", 0, "out", "output", "integer",
                            width, "unsigned", "", False, "", "function_return"),),
        (), (L2SourceEffectAuthority("effect:0", "WriteOperand", "operand:out", True),),
        (approved,),
        (), (), complete,
    )


def test_sidecar_identity_covers_operand_width_and_artifact_identity():
    left = _sidecar(width=32)
    right = _sidecar(width=64)
    assert left.authority_identity != right.authority_identity
    base = dict(
        fragment_id="fragment:1", source_model_identity="source", translation_plan_id="plan",
        constraint_id="constraints", proof_identity=_digest("proof"),
        preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
        shell_facts_identity=_digest("shell"), runtime_contract_id="none",
        runtime_contract_version="v1", recipe_id="recipe", ignored_source_state=(),
        semantic_class="integer", target_route="pure-c", l2_authority_complete=True,
    )
    from riscv2x86_py.translation_validation import TranslationArtifact
    a = TranslationArtifact(**base, l2_authority_identity=left.authority_identity,
                            effect_relation_set_identity=left.effect_relation_set_identity)
    b = TranslationArtifact(**base, l2_authority_identity=right.authority_identity,
                            effect_relation_set_identity=right.effect_relation_set_identity)
    assert a.identity != b.identity


def test_sidecar_rejects_stale_fragment_and_shell_bindings():
    raw = _sidecar().to_dict()
    stale = deepcopy(raw); stale["operands"][0]["widthBits"] = 32
    with pytest.raises(ValueError, match="stale sidecar"):
        l2_authority_sidecar_from_dict(stale)
    with pytest.raises(ValueError, match="fragment identity mismatch"):
        l2_authority_sidecar_from_dict(raw, expected_fragment_id="fragment:other")
    with pytest.raises(ValueError, match="shell fact identity mismatch"):
        l2_authority_sidecar_from_dict(raw, expected_shell_fact_identity=_digest("other"))


def test_effect_relation_change_changes_candidate_manifest_identity():
    from riscv2x86_py.candidate_materialization import CandidateArtifactManifest
    exact = _sidecar(relation="exact")
    strengthened = _sidecar(relation="strengthened")
    common = dict(
        source_root_identity=_digest("source-root"),
        staging_root_identity=_digest("target-root"),
        source_tree_digest=_digest("source-tree"), target_tree_digest=_digest("target-tree"),
        attempt_archive_id=_digest("archive"), translated_report_digest=_digest("report"),
        l2_authority_identity=authority_identity_set(
            [exact.authority_identity], role="authority",
        ), edits=(),
    )
    left = CandidateArtifactManifest(
        **common, effect_relation_set_identity=authority_identity_set(
            [exact.effect_relation_set_identity], role="effect-relations",
        ),
    )
    right = CandidateArtifactManifest(
        **common, effect_relation_set_identity=authority_identity_set(
            [strengthened.effect_relation_set_identity], role="effect-relations",
        ),
    )
    assert left.manifest_id != right.manifest_id


def test_incomplete_authority_is_inconclusive_not_semantic_failure(tmp_path):
    from tests.l2_profile_fixtures import profile_dict
    profile = profile_dict()
    requirement_path = tmp_path / "requirements.json"
    from riscv2x86_py.l2_eligibility import classify_l2_requirements
    translated_report = {"findings": [{
        "translationOutcome": "emitted", "translationReasonCodes": [],
        "fragment": {"id": "fragment:1", "inputs": [{"name": "lhs"}],
                     "outputs": [{"name": "out"}], "clobbers": []},
        "l2SemanticProfile": profile,
    }]}
    requirement_path.write_text(json.dumps(classify_l2_requirements(translated_report)))
    report_path = tmp_path / "translated-report.json"
    report_path.write_text(json.dumps(translated_report))
    payload = {
        "schemaVersion": "riscv2x86.validation-runtime-registry.v2", "version": "test-v1",
        "validators": {"L2": {"type": "requirement-driven", "config": {
            "schemaVersion": "riscv2x86.l2-requirement-driven-registry.v3",
            "requirementManifestPath": str(requirement_path), "fragmentId": "fragment:1",
            "semanticProfilePath": str(report_path),
            "semanticProfileSource": "translated-report",
            "providerSelectionUnit": "fragment",
            "environmentCapabilities": ["logical_operand_observation"],
            "environmentExecutionProfiles": ["rv64gc-user-to-x86_64-user"],
            "executionProfile": "rv64gc-user-to-x86_64-user",
            "resolvedPlanPath": str(tmp_path / "plan.json"), "providers": [{
                "providerId": "operand", "supportedDimensions": ["logical_operands"],
                "supportedPatterns": ["scalar"],
                "requiredCapabilities": ["logical_operand_observation"],
                "executionProfiles": ["rv64gc-user-to-x86_64-user"],
                "bindingKind": "automatic", "validatorType": "test-provider",
                "configSchemaVersion": "test-provider.v1",
                "config": {"schemaVersion": "test-provider.v1"}, "fragmentIds": [],
            }],
        }}},
    }
    factory = lambda _config: (lambda **kwargs: ValidationLayerResult(
        kwargs["level"], ValidationStatus.FAILED, _digest("execution"), "mismatch",
    ))
    registry = validation_runtime_registry_from_dict(
        payload, validator_factories={"test-provider": factory},
    )
    identity = _digest("identity")
    artifact = SimpleNamespace(
        fragment_id="fragment:1", preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
        l2_authority_identity=identity, effect_relation_set_identity=identity,
        l2_authority_complete=False,
        l2_semantic_profile_identity=profile["profileIdentity"],
        l2_pattern_kind=profile["patternKind"],
    )
    observation = SimpleNamespace(identity=_digest("observation"))
    result = registry.validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2, translation_artifact=artifact,
        source_observation=observation, target_observation=observation,
    )
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert "l2.authority.incomplete" in result.detail
