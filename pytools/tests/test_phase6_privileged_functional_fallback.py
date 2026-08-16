from dataclasses import replace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import (
    TargetConstraintReasonCode,
    TargetEnvironment,
    derive_target_constraints,
)
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel,
    PreservationConclusion,
    TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from riscv2x86_py.phase6e_selection import (
    FinalSelectionKind,
    Phase6ESelectionPolicy,
    Phase6ESelectionRequest,
    ProvenCandidate,
    select_final_target_lowering_plan,
)
from riscv2x86_py.plan_types import TargetLoweringKind
from riscv2x86_py.privileged_functional_contracts import (
    PrivilegedFunctionalFallbackContract,
    PrivilegedFunctionalFallbackPolicy,
    PrivilegedFunctionalFallbackRegistry,
    functional_observability_identity,
)
from riscv2x86_py.privileged_runtime_contracts import (
    privileged_source_identity,
    target_environment_identity,
)
from tests.test_phase6_privileged_runtime_contract import _source_model


def _environment():
    return TargetEnvironment.fixed_sysv_amd64_gnu_att(
        helper_contract_capabilities={"privileged-functional:counter:v1"}
    )


def _policy(enabled=True):
    return PrivilegedFunctionalFallbackPolicy(enabled=enabled)


def _registry(source, environment):
    privileged = source.privileged_state
    observability = privileged.observability
    contract = PrivilegedFunctionalFallbackContract(
        contract_id="counter-value",
        semantic_version="1",
        source_privileged_identity=privileged_source_identity(privileged),
        source_observability_identity=functional_observability_identity(
            observability
        ),
        target_environment_id=target_environment_identity(environment),
        implementation_id="rv2x86_functional_counter_v1",
        required_target_capability="privileged-functional:counter:v1",
        ignored_state_ids=tuple(
            item.state_id for item in observability.ignored_states
        ),
        required_value_source_ids=(
            observability.required_privileged_value_sources
        ),
    )
    return contract, PrivilegedFunctionalFallbackRegistry(
        version="privileged-functional-test.v1", contracts=(contract,)
    )


def _fallback_plan(source, policy):
    plans = generate_candidate_plans(
        source, privileged_functional_policy=policy
    )
    return next(
        plan for plan in plans
        if plan.kind is TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK
    )


def test_policy_disabled_does_not_generate_functional_candidate():
    source = _source_model()
    plans = generate_candidate_plans(
        source, privileged_functional_policy=_policy(False)
    )
    assert tuple(plan.kind for plan in plans) == (
        TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER,
    )


def test_enabled_policy_still_requires_exact_registry_contract():
    source = _source_model()
    environment = _environment()
    policy = _policy()
    plan = _fallback_plan(source, policy)
    missing = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=environment,
        privileged_functional_policy=policy,
    )
    assert not missing.success
    assert missing.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_REGISTRY_MISSING,
    )


def test_exact_functional_contract_completes_6c_6d_and_6e():
    source = _source_model()
    environment = _environment()
    policy = _policy()
    contract, registry = _registry(source, environment)
    plan = _fallback_plan(source, policy)
    derived = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=environment,
        privileged_functional_registry=registry,
        privileged_functional_policy=policy,
    )
    assert derived.success and derived.constraints is not None
    catalog = TargetSemanticCatalog(
        supported_plan_kinds=frozenset({plan.kind}),
        semantic_contract_ids=frozenset({contract.semantic_contract_id}),
        version="functional-target-catalog.v1",
    )
    capabilities = CompilerCapabilityModel(True, False)
    proof = run_semantic_proof_gate(
        source_model=source,
        candidate_plan=plan,
        constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=catalog,
        compiler_capabilities=capabilities,
        privileged_functional_registry=registry,
        privileged_functional_policy=policy,
    )
    assert proof.approved
    assert PreservationConclusion.FUNCTIONAL_EQUIVALENT in proof.conclusions
    assert PreservationConclusion.ARCHITECTURE_EQUIVALENT not in proof.conclusions
    catalog_id = catalog.version + ":" + ",".join(
        sorted(catalog.semantic_contract_ids)
    )
    request = Phase6ESelectionRequest(
        source_model=source,
        preservation_decision=source.preservation,
        target_environment=environment,
        candidates=(ProvenCandidate(plan, derived, proof),),
        generated_plan_ids=frozenset({plan.plan_id}),
        target_catalog_version=catalog_id,
        compiler_capability_id="asm=True;goto=False",
        privileged_functional_registry_version=registry.version,
        privileged_functional_policy_identity=policy.identity,
        selection_policy=Phase6ESelectionPolicy(
            allow_functional_fallbacks=True
        ),
    )
    result = select_final_target_lowering_plan(request)
    assert result.kind is FinalSelectionKind.SELECTED
    assert result.selected_plan.plan.kind is (
        TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK
    )
    denied = select_final_target_lowering_plan(replace(
        request,
        selection_policy=Phase6ESelectionPolicy(
            allow_functional_fallbacks=False
        ),
    ))
    assert denied.kind is FinalSelectionKind.UNSUPPORTED


def test_unknown_privileged_state_never_generates_functional_candidate():
    source = _source_model()
    incomplete = replace(
        source,
        privileged_state=replace(
            source.privileged_state,
            complete=False,
            functional_fallback_possible=False,
            reason_codes=("phase6a.unknown-privileged-state",),
        ),
    )
    plans = generate_candidate_plans(
        incomplete, privileged_functional_policy=_policy()
    )
    assert plans == ()


def test_contract_observability_identity_mismatch_fails_closed():
    source = _source_model()
    environment = _environment()
    policy = _policy()
    contract, _ = _registry(source, environment)
    mismatched = replace(
        contract, source_observability_identity="sha256:" + "0" * 64
    )
    registry = PrivilegedFunctionalFallbackRegistry(
        version="mismatched.v1", contracts=(mismatched,)
    )
    result = derive_target_constraints(
        source_model=source,
        candidate_plan=_fallback_plan(source, policy),
        target_environment=environment,
        privileged_functional_registry=registry,
        privileged_functional_policy=policy,
    )
    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_CONTRACT_MISSING,
    )
