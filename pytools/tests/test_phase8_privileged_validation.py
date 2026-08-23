"""Phase-8 privileged translation validation matrix.

These tests intentionally exercise the public Phase 5/6/7 surfaces.  They
verify that strict privileged translation, explicitly enabled functional
fallback, and fail-closed rejection remain distinct end-to-end policies.
"""
from dataclasses import replace

import pytest

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import (
    TargetConstraintReasonCode,
    derive_target_constraints,
)
from riscv2x86_py.plan_types import TargetLoweringKind
from riscv2x86_py.privileged_emitted_audit import (
    audit_privileged_emitted_text,
)
from riscv2x86_py.privileged_functional_contracts import (
    PrivilegedFunctionalFallbackPolicy,
    PrivilegedFunctionalFallbackRegistry,
)
from riscv2x86_py.privileged_runtime_contracts import (
    PrivilegedRuntimeRegistry,
)
from tests.test_phase6_privileged_functional_fallback import (
    _environment as functional_environment,
    _fallback_plan,
    _policy,
    _registry as functional_registry,
)
from tests.test_phase6_privileged_runtime_contract import (
    _environment as strict_environment,
    _registry as strict_registry,
    _mapping_registries,
    _source_model,
)


def test_default_policy_never_silently_uses_functional_fallback():
    source = _source_model()

    plans = generate_candidate_plans(source)

    assert tuple(plan.kind for plan in plans) == (
        TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER,
    )


def test_explicit_fallback_policy_keeps_routes_typed_and_excludes_helper():
    source = _source_model(True)

    plans = generate_candidate_plans(
        source,
        privileged_functional_policy=PrivilegedFunctionalFallbackPolicy(
            enabled=True
        ),
    )
    kinds = tuple(plan.kind for plan in plans)

    assert TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER in kinds
    assert TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK in kinds
    assert TargetLoweringKind.HELPER_CALL not in kinds


@pytest.mark.parametrize(
    "field",
    (
        "complete",
        "functional_fallback_eligible",
    ),
)
def test_incomplete_or_unapproved_privileged_state_fails_closed(field):
    source = _source_model()
    changes = {
        "complete": False,
        "strict_translation_eligible": False,
        "functional_fallback_eligible": False,
        "reason_codes": ("phase8.validation-incomplete",),
    }
    changes[field] = False
    incomplete = replace(
        source,
        privileged_state=replace(source.privileged_state, **changes),
    )

    assert generate_candidate_plans(
        incomplete,
        privileged_functional_policy=_policy(),
    ) == ()


def test_strict_constraint_requires_exact_versioned_registry():
    source = _source_model()
    environment = strict_environment()
    plan = generate_candidate_plans(source)[0]
    contract, _ = strict_registry(source, environment)
    stale = replace(
        contract,
        source_privileged_identity="sha256:" + "0" * 64,
    )

    result = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=environment,
        privileged_runtime_registry=PrivilegedRuntimeRegistry(
            version="phase8.stale-strict.v0",
            contracts=(stale,),
            mapping_registries=_mapping_registries(stale),
        ),
    )

    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_RUNTIME_CONTRACT_MISSING,
    )


def test_functional_constraint_requires_exact_observability_identity():
    source = _source_model(True)
    environment = functional_environment()
    policy = _policy()
    contract, _ = functional_registry(source, environment)
    stale = replace(
        contract,
        source_observability_identity="sha256:" + "0" * 64,
    )

    result = derive_target_constraints(
        source_model=source,
        candidate_plan=_fallback_plan(source, policy),
        target_environment=environment,
        privileged_functional_policy=policy,
        privileged_functional_registry=PrivilegedFunctionalFallbackRegistry(
            version="phase8.stale-functional.v0",
            contracts=(stale,),
        ),
    )

    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_CONTRACT_MISSING,
    )


@pytest.mark.parametrize(
    ("emitted", "expected_reason"),
    (
        (
            '__asm__ volatile ("rdmsr");',
            "privileged-renderer.x86-privileged-instruction-forbidden",
        ),
        (
            '__asm__ volatile ("wrmsr");',
            "privileged-renderer.x86-privileged-instruction-forbidden",
        ),
        (
            '__asm__ volatile ("mov %rsp, %rax");',
            "privileged-renderer.inline-asm-forbidden",
        ),
    ),
)
def test_emitted_text_audit_rejects_privileged_or_host_stack_escape(
    emitted,
    expected_reason,
):
    reasons = audit_privileged_emitted_text(
        emitted,
        expected_callable_identifier="rv2x86_registered_adapter",
    )

    assert expected_reason in reasons


def test_functional_fallback_cannot_be_derived_when_policy_is_disabled():
    source = _source_model(True)
    environment = functional_environment()
    enabled_policy = _policy()
    plan = _fallback_plan(source, enabled_policy)
    _contract, registry = functional_registry(source, environment)

    result = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=environment,
        privileged_functional_policy=_policy(False),
        privileged_functional_registry=registry,
    )

    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_POLICY_DISABLED,
    )
