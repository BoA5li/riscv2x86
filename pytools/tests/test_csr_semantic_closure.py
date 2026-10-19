from dataclasses import replace
from copy import deepcopy
from types import SimpleNamespace as NS
import pytest
from riscv2x86_py.csr_state_dataflow import analyze_csr_state_dataflow,CsrControlDisposition
from riscv2x86_py.source_csr_semantic_model import adapt_source_csr_semantic_model
from riscv2x86_py.csr_field_proof import prove_csr_fields
from riscv2x86_py.csr_effect_constraints import CsrTargetMapping,derive_csr_effect_constraints
from riscv2x86_py.csr_metadata_ingress import canonical_csr_operations_from_decoded,decode_csr_instruction,CsrDecoderProfile
from riscv2x86_py.pcode_ir import CanonicalInsn,Block,Op


def read_inputs():
    decoded=decode_csr_instruction(bytes.fromhex('732510c0'))
    op=canonical_csr_operations_from_decoded(addr=0x1000,decoded=decoded,
        xlen_bits=64,profile=CsrDecoderProfile('1.12',64,('zicsr',)))[0]
    block=Block(addr=0x1000,ops=[Op(0x1000,'COPY',None,[])],
        instructions=[CanonicalInsn(addr=0x1000,size=4,privileged_operations=(op,))])
    return block,NS(entry=0x1000),op


def test_potential_trap_is_not_automatically_whole_function():
    block,cfg,_=read_inputs()
    r=analyze_csr_state_dataflow(blocks=[block],cfg=cfg)
    assert not r.complete and not r.requires_whole_function
    assert r.control_disposition is CsrControlDisposition.TRAP_CONTRACT_REQUIRED
    effect=NS(csr_id='riscv.csr.time',csr_class=NS(value='user_counter_observation'),
        complete=True,access_allowed=None,may_trap=True)
    binding=NS(source_effect_id='e',complete=True,reason_codes=())
    model=adapt_source_csr_semantic_model(NS(csr_effects=(effect,),csr_operand_bindings=(binding,),csr_state_dataflow=r))
    assert not model.strict_eligible and not model.complete and not model.requires_whole_function
    assert model.trap_contract_required


def test_function_state_escape_still_requires_whole_function():
    block,cfg,op=read_inputs()
    block.instructions[0].privileged_operations=(replace(op,csr_semantic_class='address_translation'),)
    r=analyze_csr_state_dataflow(blocks=[block],cfg=cfg)
    assert r.requires_whole_function
    assert r.control_disposition is CsrControlDisposition.WHOLE_FUNCTION_REQUIRED


def test_only_complete_explicit_counter_access_policy_resolves_potential_trap():
    from tests.test_privileged_state_analysis import _facts
    from riscv2x86_py.privileged_state_analysis import _typed_csr_effect
    block,cfg,op=read_inputs()
    facts=_facts(readable=('riscv.csr.time',),writable=())
    effect=_typed_csr_effect(block.addr,0,op,facts,isolated_counter_access=True)
    assert _typed_csr_effect(block.addr,0,op,facts).may_trap is True
    assert effect.complete and effect.access_allowed and effect.may_trap is False
    flow=analyze_csr_state_dataflow(blocks=[block],cfg=cfg,access_effects=(effect,))
    assert flow.complete and flow.control_disposition is CsrControlDisposition.LOCAL
    incomplete=_typed_csr_effect(block.addr,0,op,replace(facts,complete=False))
    assert incomplete.may_trap is True and not incomplete.complete
    unresolved=analyze_csr_state_dataflow(blocks=[block],cfg=cfg,access_effects=(incomplete,))
    assert not unresolved.complete
    # The decoder fact itself stays conservative and immutable.
    assert op.may_trap is True


@pytest.mark.parametrize('mutation',['width','permission','operand','field','flow'])
def test_source_identity_covers_all_semantic_payload(mutation):
    def build():
        effect=NS(csr_id='riscv.csr.time',csr_class=NS(value='user_counter_observation'),
            complete=True,access_allowed=True,may_trap=False,xlen_bits=64,
            affected_fields=(NS(field_id='time.value',complete=True),))
        binding=NS(source_effect_id='e',complete=True,reason_codes=(),read_result_operand_index=0)
        flow=NS(complete=True,entry_state='in',exit_states=((1,'out'),),requires_whole_function=False)
        return NS(csr_effects=(effect,),csr_operand_bindings=(binding,),csr_state_dataflow=flow)
    a=build();b=build()
    if mutation=='width':b.csr_effects[0].xlen_bits=32
    if mutation=='permission':b.csr_effects[0].access_allowed=False
    if mutation=='operand':b.csr_operand_bindings[0].read_result_operand_index=1
    if mutation=='field':b.csr_effects[0].affected_fields[0].field_id='other'
    if mutation=='flow':b.csr_state_dataflow.exit_states=((1,'different'),)
    assert adapt_source_csr_semantic_model(a).model_identity!=adapt_source_csr_semantic_model(b).model_identity


def test_counter_payload_must_match_declared_relation_and_id():
    from tests.test_csr_translation_pipeline import _complete_counter_model,_counter_contract
    model=_complete_counter_model();contract=_counter_contract()
    mapping=CsrTargetMapping('e:riscv.csr.cycle','riscv.csr.cycle','state','op','v1','user','life',
        read_result_mapping='result',field_mappings=('f',),old_new_state_relation_id='r',
        access_policy_mapping_id='a',ordering_relation_id='o',counter_contract_identity='different',
        counter_relation_kind='architectural-equivalence',counter_contract=contract)
    constraints=derive_csr_effect_constraints(source_model=model,mappings=(mapping,),
        runtime_version='v1',execution_profile='user',shell_transportable=True)
    assert not constraints[0].complete
    assert 'csr-6c.counter-contract-binding-mismatch' in constraints[0].reason_codes


def test_proof_identity_binds_counter_payload_even_with_unchanged_label():
    from tests.test_csr_translation_pipeline import _complete_counter_model,_counter_contract
    model=_complete_counter_model();contract=_counter_contract()
    def prove(c):
        mapping=CsrTargetMapping('e:riscv.csr.cycle','riscv.csr.cycle','state','op','v1','user','life',
            read_result_mapping='result',field_mappings=('f',),old_new_state_relation_id='r',
            access_policy_mapping_id='a',ordering_relation_id='o',counter_contract_identity=c.contract_id,
            counter_relation_kind=c.relation_kind,counter_contract=c)
        constraints=derive_csr_effect_constraints(source_model=model,mappings=(mapping,),runtime_version='v1',execution_profile='user',shell_transportable=True)
        return prove_csr_fields(source_model=model,constraints=constraints,execution_profile='user',shell_preserved=True,external_state_complete=True)
    a=prove(contract);b=prove(replace(contract,frequency_hz=20_000_000))
    assert a.approved and b.approved and a.proof_identity!=b.proof_identity
    assert a.proof_payload['schemaVersion']=='riscv2x86.csr-field-proof.v2'


def test_counter_renderer_has_two_arguments_and_preserves_output():
    from riscv2x86_py.csr_structured_renderer import CsrRuntimeRecipe, render_csr_recipe
    recipe = CsrRuntimeRecipe("r", "rv2x86_read_counter", "id", "ctx", None,
        "output", "riscv2x86_csr_runtime.h", "runtime", "v1", "no-trap-observation", True)
    result = render_csr_recipe(recipe, approved_recipe_ids={"r": "v1"}, expected_runtime_version="v1")
    assert result.emitted_text == "output = rv2x86_read_counter(ctx, id);"


def test_duplicate_effect_bindings_cannot_receive_proof():
    from tests.test_csr_translation_pipeline import _complete_counter_model
    model = _complete_counter_model()
    model.operand_bindings = model.operand_bindings * 2
    result = prove_csr_fields(source_model=model, constraints=(), execution_profile="user",
        shell_preserved=True, external_state_complete=True)
    assert not result.approved
    assert "csr-6d.effect-coverage-mismatch" in result.reason_codes


def test_instruction_sync_proof_identity_binds_range_and_scope_payload():
    from tests.test_instruction_stream_sync_contracts import _contract
    from riscv2x86_py.instruction_stream_sync_contracts import prove_instruction_stream_sync
    from riscv2x86_py.semantic_content import semantic_identity
    contract = _contract()
    first = prove_instruction_stream_sync(contract)
    second = prove_instruction_stream_sync(replace(contract,
        modified_code_range=replace(contract.modified_code_range, offset_bytes=32)))
    assert first.approved and second.approved
    assert first.proof_identity != second.proof_identity
    assert first.proof_identity == semantic_identity(first.proof_payload)


def test_production_access_refinement_requires_an_isolated_instruction():
    from tests.test_privileged_state_analysis import _facts, _cfg
    from riscv2x86_py.privileged_state_analysis import analyze_privileged_state
    block, _, _ = read_inputs()
    facts = _facts(readable=("riscv.csr.time",), writable=())
    first = analyze_privileged_state(fragment_id="frag", blocks=(block,),
        cfg=_cfg(block), execution_facts=facts)
    assert first.csr_effects[0].may_trap is False
    block.instructions.append(CanonicalInsn(addr=0x1004, size=4))
    second = analyze_privileged_state(fragment_id="frag", blocks=(block,),
        cfg=_cfg(block), execution_facts=facts)
    assert second.csr_effects[0].may_trap is True


@pytest.mark.parametrize("expressions,expected", [({0: "compiler_output"}, "compiler_output = rv2x86_csr_read(ctx, id);"), ({}, None)])
def test_pipeline_consumes_proved_operand_index_for_rendering(expressions, expected, monkeypatch):
    monkeypatch.setattr("riscv2x86_py.csr_runtime_implementation.validate_implementation",
        lambda *args: ({"unitTestImplementation": True}, "sha256:" + "1" * 64))
    from tests.test_csr_translation_pipeline import _complete_counter_model, _counter_contract
    from riscv2x86_py.csr_translation_pipeline import (CsrRuntimeRegistry,
        CsrRendererRegistry, CsrTranslationFallbackPolicy, run_csr_translation_pipeline)
    from riscv2x86_py.csr_structured_renderer import CsrRuntimeRecipe
    model = _complete_counter_model()
    model.operand_bindings[0].read_result_operand_index = 0
    mapping = CsrTargetMapping("e:riscv.csr.cycle", "riscv.csr.cycle", "state", "op", "v1", "user", "life",
        read_result_mapping="result", field_mappings=("f",), old_new_state_relation_id="r",
        access_policy_mapping_id="a", ordering_relation_id="o", counter_contract_identity="counter-contract-v1",
        counter_relation_kind="architectural-equivalence", counter_contract=_counter_contract())
    runtime = CsrRuntimeRegistry("registry", "v1", "user", (mapping,), True, True)
    recipe = CsrRuntimeRecipe("r", "rv2x86_csr_read", "id", "ctx", None,
        "wrong_sidecar_output", "header", "library", "v1", "no-trap-observation", True)
    renderer = CsrRendererRegistry("renderer", {"op": recipe}, {"r": "v1"})
    result = run_csr_translation_pipeline(model, None, NS(execution_profile="user"), runtime,
        renderer, CsrTranslationFallbackPolicy(shell_preserved=True), operand_expressions=expressions)
    assert result.suggested_replacement == expected
    if expected is None:
        assert result.reason_codes == ("csr-6f.compiler-operand-expression-missing",)
