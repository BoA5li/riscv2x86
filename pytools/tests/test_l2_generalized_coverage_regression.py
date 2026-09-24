"""Capability-level regression matrix independent of round corpus names."""
from hashlib import sha256

import pytest

from riscv2x86_py.l2_dimensions import L2Dimension, L2EligibilityStatus
from riscv2x86_py.l2_semantic_profile import (
    L2PatternKind, l2_fragment_semantic_profile_from_dict,
)
from riscv2x86_py.l2_validator_resolution import (
    L2BindingKind, L2BindingStatus, L2FragmentRequirement,
    L2RuntimeCapabilities, L2ValidatorProvider, L2ValidatorResolver,
)
from riscv2x86_py.l2_memory_object import (
    AuthorityMaterializationDecision, MemoryAccessAuthority,
)
from tests.l2_profile_fixtures import profile_dict
from tests.l2_materialization_fixtures import complete_materialization_decision


def _id(text: str) -> str:
    return "sha256:" + sha256(text.encode()).hexdigest()


_DIMENSIONS = {
    L2PatternKind.SCALAR: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.BRANCH: (L2Dimension.CONTROL_FLOW, L2Dimension.LOGICAL_OPERANDS,
                           L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.JUMP: (L2Dimension.CONTROL_FLOW, L2Dimension.LOGICAL_OPERANDS,
                         L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.MEMORY_LOAD: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.MEMORY_EFFECTS,
                                L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.MEMORY_STORE: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.MEMORY_EFFECTS,
                                 L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.FENCE: (L2Dimension.MEMORY_EFFECTS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.COMPOSITE: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.PRIVILEGED_READ: (L2Dimension.PRIVILEGED_STATE,
                                    L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.INSTRUCTION_VISIBILITY_FENCE: (L2Dimension.MEMORY_EFFECTS,
                                                 L2Dimension.SHELL_SEMANTICS),
}


def _profile(fragment_id: str, kind: L2PatternKind):
    return l2_fragment_semantic_profile_from_dict(profile_dict(fragment_id, kind))


def _requirement(profile):
    decision = None
    if profile.pattern_kind in {L2PatternKind.MEMORY_LOAD,
                                L2PatternKind.MEMORY_STORE}:
        access = ("load" if profile.pattern_kind is L2PatternKind.MEMORY_LOAD
                  else "store")
        authority = MemoryAccessAuthority(
            profile.fragment_id, access, "parameter-object:base", "base", "base",
            0, 8, 8, 8, 32, "0<=0 && 8<=32", "alias:base", "c.default",
            "value", False, True)
        decision = AuthorityMaterializationDecision(
            profile.fragment_id, True, (), authority).to_dict()
    dimensions = tuple(sorted(_DIMENSIONS[profile.pattern_kind], key=lambda item: item.value))
    return L2FragmentRequirement(
        profile.fragment_id, _id("requirement:" + profile.fragment_id),
        dimensions,
        L2EligibilityStatus.ELIGIBLE, profile.profile_identity,
        profile.pattern_kind.value, profile.required_capabilities, decision,
        complete_materialization_decision(profile.fragment_id, dimensions),
    )


def _provider(kind: L2PatternKind):
    profile = _profile("capability-template:" + kind.value, kind)
    capabilities = set(profile.required_capabilities)
    if kind is L2PatternKind.COMPOSITE:
        capabilities.add("logical_operand_observation")
    return L2ValidatorProvider(
        "general-" + kind.value,
        tuple(sorted(_DIMENSIONS[kind], key=lambda item: item.value)), (kind,),
        tuple(sorted(capabilities)), (profile.execution_profile,),
        L2BindingKind.AUTOMATIC, "test-general-provider", "test.general.v1",
        {"schemaVersion": "test.general.v1"},
    )


@pytest.mark.parametrize("kind", [
    L2PatternKind.BRANCH, L2PatternKind.JUMP,
    L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE,
    L2PatternKind.FENCE, L2PatternKind.COMPOSITE,
])
def test_generalized_round2_capabilities_ignore_names_directories_and_signatures(kind):
    fragments = [
        _profile("renamed-tree/a:17:3", kind),
        _profile("different/location/member:204:9", kind),
    ]
    provider = _provider(kind)
    for profile in fragments:
        runtime = L2RuntimeCapabilities(
            (provider,), provider.required_capabilities, (profile.execution_profile,))
        plan = L2ValidatorResolver().resolve(
            _requirement(profile), runtime, execution_profile=profile.execution_profile,
            profile=profile,
        )
        assert plan.complete
        assert {item.provider_id for item in plan.bindings} == {provider.provider_id}


def test_round1_ten_scalar_fragments_keep_automatic_provider_coverage():
    provider = _provider(L2PatternKind.SCALAR)
    plans = []
    for index in range(10):
        profile = _profile(f"arbitrary/scalar-member:{index}:1", L2PatternKind.SCALAR)
        runtime = L2RuntimeCapabilities(
            (provider,), provider.required_capabilities, (profile.execution_profile,))
        plans.append(L2ValidatorResolver().resolve(
            _requirement(profile), runtime, execution_profile=profile.execution_profile,
            profile=profile))
    assert len(plans) == 10
    assert all(item.complete for item in plans)
    assert all({binding.binding_kind for binding in item.bindings} == {"automatic"}
               for item in plans)


@pytest.mark.parametrize("kind,missing", [
    (L2PatternKind.PRIVILEGED_READ, "privileged_state_observation"),
    (L2PatternKind.INSTRUCTION_VISIBILITY_FENCE, "instruction_visibility"),
])
def test_unsupported_environment_stays_not_run_with_missing_capability(kind, missing):
    profile = _profile("unsupported/environment:0", kind)
    provider = _provider(kind)
    available = tuple(item for item in profile.required_capabilities if item != missing)
    runtime = L2RuntimeCapabilities((provider,), available, (profile.execution_profile,))
    plan = L2ValidatorResolver().resolve(
        _requirement(profile), runtime, execution_profile=profile.execution_profile,
        profile=profile)
    assert not plan.complete
    assert all(item.binding_status is L2BindingStatus.NOT_RUN for item in plan.bindings)
    assert any(missing in item.missing_capabilities for item in plan.bindings)
