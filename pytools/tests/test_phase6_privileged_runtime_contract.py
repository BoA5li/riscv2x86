from dataclasses import replace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import (
    TargetConstraintReasonCode,
    TargetEnvironment,
    derive_target_constraints,
)
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel,
    TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from riscv2x86_py.phase6e_selection import (
    FinalSelectionKind,
    Phase6ESelectionRequest,
    ProvenCandidate,
    select_final_target_lowering_plan,
)
from riscv2x86_py.plan_types import TargetLoweringKind
from riscv2x86_py.privileged_policy import PrivilegedPreservationPolicy
from riscv2x86_py.privileged_runtime_contracts import (
    PrivilegedRuntimeContract,
    PrivilegedRuntimeRegistry,
    privileged_source_identity,
    target_environment_identity,
)
from riscv2x86_py.source_model import build_source_semantic_model
from tests.test_phase6a_privileged_state_adapter import _counter_inputs


def _source_model(allow_functional_fallbacks=False):
    fragment, block, cfg, summary, state, observability, facts = (
        _counter_inputs()
    )
    return build_source_semantic_model(
        fragment=fragment,
        blocks=(block,),
        cfg=cfg,
        summary=summary,
        runtime_facts=facts,
        xlen=64,
        privileged_state=state,
        functional_observability=observability,
        privileged_preservation_policy=(
            PrivilegedPreservationPolicy.from_allow_functional_fallbacks(
                allow_functional_fallbacks
            )
        ),
    )


def _environment():
    return TargetEnvironment.fixed_sysv_amd64_gnu_att(
        helper_contract_capabilities={"privileged-runtime:counter-time:v1"}
    )


def _registry(source, environment, *, version="privileged-test-registry.v1"):
    contract = PrivilegedRuntimeContract(
        contract_id="counter-time",
        semantic_version="1",
        source_privileged_identity=privileged_source_identity(
            source.privileged_state
        ),
        target_environment_id=target_environment_identity(environment),
        runtime_symbol="rv2x86_privileged_counter_time_v1",
        required_target_capability="privileged-runtime:counter-time:v1",
        required_headers=("riscv2x86_privileged_runtime.h",),
        required_library="riscv2x86_privileged_runtime",
    )
    return contract, PrivilegedRuntimeRegistry(
        version=version, contracts=(contract,)
    )



def test_strict_plan_does_not_require_functional_observability():
    fragment, block, cfg, summary, state, _observability, facts = (
        _counter_inputs()
    )
    source = build_source_semantic_model(
        fragment=fragment,
        blocks=(block,),
        cfg=cfg,
        summary=summary,
        runtime_facts=facts,
        xlen=64,
        privileged_state=state,
        functional_observability=None,
    )

    assert source.privileged_state.strict_translation_eligible
    assert not source.privileged_state.functional_fallback_eligible
    assert tuple(plan.kind for plan in generate_candidate_plans(source)) == (
        TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER,
    )


def test_privileged_plan_is_exclusive_and_never_generic_helper():
    source = _source_model()
    plans = generate_candidate_plans(source)

    assert len(plans) == 1
    assert plans[0].kind is TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER
    assert all(plan.kind is not TargetLoweringKind.HELPER_CALL for plan in plans)


def test_missing_or_mismatched_registry_fails_in_phase6c():
    source = _source_model()
    environment = _environment()
    plan = generate_candidate_plans(source)[0]
    missing = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=environment,
    )
    assert not missing.success
    assert missing.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_RUNTIME_REGISTRY_MISSING,
    )

    contract, _registry_ok = _registry(source, environment)
    wrong = replace(contract, source_privileged_identity="sha256:" + "0" * 64)
    mismatched = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=environment,
        privileged_runtime_registry=PrivilegedRuntimeRegistry(
            version="wrong-registry.v1", contracts=(wrong,)
        ),
    )
    assert not mismatched.success
    assert mismatched.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_RUNTIME_CONTRACT_MISSING,
    )


def test_registry_rejects_ambiguous_source_target_contracts():
    source = _source_model()
    environment = _environment()
    contract, _ = _registry(source, environment)
    duplicate_route = replace(
        contract, contract_id="counter-time-alternate"
    )
    try:
        PrivilegedRuntimeRegistry(
            version="ambiguous-registry.v1",
            contracts=(contract, duplicate_route),
        )
    except ValueError as exc:
        assert "ambiguous" in str(exc)
    else:
        raise AssertionError("ambiguous privileged contracts were accepted")


def test_strict_privileged_runtime_completes_6b_through_6e():
    source = _source_model()
    environment = _environment()
    contract, registry = _registry(source, environment)
    plan = generate_candidate_plans(source)[0]
    derived = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=environment,
        privileged_runtime_registry=registry,
    )
    assert derived.success and derived.constraints is not None
    assert derived.constraints.helper_abi_contract is None
    assert derived.constraints.privileged_runtime_constraint is not None
    catalog = TargetSemanticCatalog(
        supported_plan_kinds=frozenset({plan.kind}),
        semantic_contract_ids=frozenset({contract.semantic_contract_id}),
        version="privileged-target-catalog.v1",
    )
    capabilities = CompilerCapabilityModel(True, False)
    proof = run_semantic_proof_gate(
        source_model=source,
        candidate_plan=plan,
        constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=catalog,
        compiler_capabilities=capabilities,
        privileged_runtime_registry=registry,
    )
    assert proof.approved and proof.evidence is not None
    assert proof.evidence.privileged_registry_version == registry.version
    catalog_id = catalog.version + ":" + ",".join(
        sorted(catalog.semantic_contract_ids)
    )
    result = select_final_target_lowering_plan(Phase6ESelectionRequest(
        source_model=source,
        preservation_decision=source.preservation,
        target_environment=environment,
        candidates=(ProvenCandidate(plan, derived, proof),),
        generated_plan_ids=frozenset({plan.plan_id}),
        target_catalog_version=catalog_id,
        compiler_capability_id="asm=True;goto=False",
        privileged_registry_version=registry.version,
    ))
    assert result.kind is FinalSelectionKind.SELECTED
    assert result.selected_plan is not None
    assert result.selected_plan.plan.kind is (
        TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER
    )

    stale = select_final_target_lowering_plan(replace(
        Phase6ESelectionRequest(
            source_model=source,
            preservation_decision=source.preservation,
            target_environment=environment,
            candidates=(ProvenCandidate(plan, derived, proof),),
            generated_plan_ids=frozenset({plan.plan_id}),
            target_catalog_version=catalog_id,
            compiler_capability_id="asm=True;goto=False",
            privileged_registry_version=registry.version,
        ),
        privileged_registry_version="stale-registry.v0",
    ))
    assert stale.kind is FinalSelectionKind.INVARIANT_VIOLATION


def test_incomplete_privileged_adapter_has_no_lowering_candidate():
    source = _source_model()
    incomplete = replace(
        source,
        privileged_state=replace(
            source.privileged_state,
            complete=False,
            strict_translation_eligible=False,
            functional_fallback_eligible=False,
            reason_codes=("phase6a.test-incomplete",),
        ),
    )
    assert generate_candidate_plans(incomplete) == ()
