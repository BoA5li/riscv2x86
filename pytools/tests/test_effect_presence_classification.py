"""Production Phase-5 absence must survive the adapter and Phase-6D join."""
from dataclasses import replace
import pytest
from tests.test_phase6_rv64_add_contract import _build_rv64_add_model, _CONTRACT_ID
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import (
    run_semantic_proof_gate, TargetSemanticCatalog, CompilerCapabilityModel,
)
from riscv2x86_py.l2_effect_proof import effect_proof_facts_from_dict


def prove(model):
    plan = next(p for p in generate_candidate_plans(model)
                if p.metadata.get('renderer_semantic_contract_id') == _CONTRACT_ID)
    env = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    constraints = derive_target_constraints(source_model=model, candidate_plan=plan,
                                          target_environment=env).constraints
    return run_semantic_proof_gate(
        source_model=model, candidate_plan=plan, constraints=constraints,
        target_environment=env, fragment_id='typed-scalar',
        target_semantic_catalog=TargetSemanticCatalog(
            supported_plan_kinds=frozenset({plan.kind}),
            semantic_contract_ids=frozenset({_CONTRACT_ID}), version='presence-test'),
        compiler_capabilities=CompilerCapabilityModel(
            supports_gnu_inline_asm=True, supports_asm_goto=False))


@pytest.mark.parametrize('cc', [False, True])
def test_phase5_adapter_absence_produces_scalar_effects(cc):
    model = _build_rv64_add_model(source_cc_clobber=cc, include_phase5=True)
    assert model.privileged_state is not None
    assert model.privileged_state.state.present is False
    assert model.privileged_state.semantic_presence is False
    proof = prove(model)
    assert proof.approved, proof
    facts = proof.l2_effect_proof_facts
    assert {x.effect_kind for x in facts.source_effects} == {'ScalarResult'}
    assert {x.effect_kind for x in facts.target_effects} == {'ScalarResult'}
    assert all(r.relation_kind == 'exact' for r in facts.relations)
    assert effect_proof_facts_from_dict(facts.to_dict()) == facts


def test_adapter_unknown_is_not_absence():
    adapter = _build_rv64_add_model(include_phase5=True).privileged_state
    assert replace(adapter, state=None).semantic_presence is None
    assert replace(adapter, state=replace(adapter.state, classification_complete=False)).semantic_presence is None
    assert replace(adapter, state=replace(adapter.state, present=True, execution_environment_complete=True)).semantic_presence is True


def test_unproven_presence_cannot_publish_complete_effect_facts():
    model = _build_rv64_add_model(include_phase5=True)
    model = replace(model, privileged_state=replace(model.privileged_state, state=None))
    proof = prove(model)
    assert not proof.approved
    assert proof.l2_effect_proof_facts is None
    assert proof.details['failureStage'] == 'effect_classification'


def test_real_counter_remains_privileged_and_inconsistent_absence_rejects():
    from tests.test_phase6a_privileged_state_adapter import _counter_inputs
    from riscv2x86_py.source_model import build_source_semantic_model
    fragment, block, cfg, summary, state, observability, runtime = _counter_inputs()
    model = build_source_semantic_model(
        fragment=fragment, blocks=(block,), cfg=cfg, summary=summary,
        runtime_facts=runtime, xlen=64, privileged_state=state,
        functional_observability=observability)
    adapter = model.privileged_state
    assert adapter.semantic_presence is True
    assert replace(adapter, state=replace(state, present=False)).semantic_presence is None
