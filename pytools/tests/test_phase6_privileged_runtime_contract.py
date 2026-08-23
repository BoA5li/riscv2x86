from dataclasses import replace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import (
    TargetConstraintReasonCode,
    TargetEnvironment,
    derive_target_constraints,
)
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel,
    SemanticProofReasonCode,
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
    TargetCsrStateMapping,
    source_effect_id,
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
    effect = source.privileged_state.state.csr_effects[0]
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
        runtime_contract_set_id="x86-user-counter-v1",
        csr_mappings=(TargetCsrStateMapping(
            source_effect_id("csr", effect.block_address, effect.operation_index),
            effect.csr_id,
            tuple(field.field_id for field in effect.affected_fields),
            "runtime.counter.time", "read", "counter-observation.v1",
            effect.trap_binding_id,
        ),),
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
    effect_constraint = derived.constraints.privileged_runtime_constraint
    assert effect_constraint.complete
    assert len(effect_constraint.csr_mappings) == 1
    assert effect_constraint.source_execution_profile == "riscv_user_process"
    assert effect_constraint.target_execution_mode == "x86_user_process"
    assert effect_constraint.runtime_symbol_or_intrinsic == contract.runtime_symbol
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
    assert len(proof.evidence.privileged_effect_evidence) == 1
    assert proof.evidence.privileged_effect_proof_identity.startswith("sha256:")
    assert proof.evidence.privileged_effect_evidence[0].conclusion == "architecture_equivalent"
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


def test_6c_rejects_runtime_contract_without_effect_coverage():
    source = _source_model(); environment = _environment()
    contract, _ = _registry(source, environment)
    registry = PrivilegedRuntimeRegistry(
        version="missing-mapping.v1",
        contracts=(replace(contract, csr_mappings=()),),
    )
    result = derive_target_constraints(
        source_model=source,
        candidate_plan=generate_candidate_plans(source)[0],
        target_environment=environment,
        privileged_runtime_registry=registry,
    )
    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_EFFECT_MAPPING_MISSING,
    )


def test_6c_rejects_runtime_profile_mismatch():
    source = _source_model(); environment = _environment()
    contract, _ = _registry(source, environment)
    registry = PrivilegedRuntimeRegistry(
        version="profile-mismatch.v1",
        contracts=(replace(contract, source_execution_profile="riscv_supervisor_kernel"),),
    )
    result = derive_target_constraints(
        source_model=source,
        candidate_plan=generate_candidate_plans(source)[0],
        target_environment=environment,
        privileged_runtime_registry=registry,
    )
    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_RUNTIME_PROFILE_MISMATCH,
    )


def test_6d_rejects_unproven_csr_old_new_relation():
    source = _source_model(); environment = _environment()
    contract, _ = _registry(source, environment)
    broken_mapping = replace(
        contract.csr_mappings[0], old_new_state_relation_id=""
    )
    broken_contract = replace(contract, csr_mappings=(broken_mapping,))
    registry = PrivilegedRuntimeRegistry(
        version="unproven-csr-relation.v1", contracts=(broken_contract,)
    )
    plan = generate_candidate_plans(source)[0]
    derived = derive_target_constraints(
        source_model=source, candidate_plan=plan,
        target_environment=environment, privileged_runtime_registry=registry,
    )
    assert derived.success
    proof = run_semantic_proof_gate(
        source_model=source, candidate_plan=plan,
        constraints=derived.constraints, target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(
            frozenset({plan.kind}),
            frozenset({broken_contract.semantic_contract_id}), "test.v1"
        ),
        compiler_capabilities=CompilerCapabilityModel(True, False),
        privileged_runtime_registry=registry,
    )
    assert not proof.approved
    assert proof.reason_codes == (
        SemanticProofReasonCode.PRIVILEGED_CSR_MAPPING_UNPROVEN,
    )


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
