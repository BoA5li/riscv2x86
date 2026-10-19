from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace as NS
import pytest
from riscv2x86_py.csr_result_flow import result_flows_from_compiler
from riscv2x86_py.csr_value_flow import join_csr_operand_bindings
from riscv2x86_py.source_csr_semantic_model import adapt_source_csr_semantic_model
from riscv2x86_py.csr_state_escape import CsrStateEscapeFact
from riscv2x86_py.route_authority import content_identity
from tests.test_csr_sync_production_contracts import compiler_fragment, one_insn, profile


def authority_for_use(kind, relation, *, complete=True):
    fragment=compiler_fragment()
    authority=fragment.compilerFragmentAuthority
    candidate=authority['candidate'];node=candidate['operandBindings'][0]['valueNodeIdentity']
    candidate['downstreamUses']=[{
        'valueNodeIdentity':node,'useNodeIdentity':'sha256:'+'a'*64,
        'useKind':kind,'consumerFragmentIdentity':'consumer' if kind=='subsequent_asm_input' else '',
        'observationSinkIdentity':'' if kind in {'dead','discarded'} else 'sha256:'+'b'*64,
        'relationKind':relation,'complete':complete}]
    candidate['closureIdentity']=content_identity({k:v for k,v in candidate.items() if k!='closureIdentity'})
    authority['authorityIdentity']=content_identity({k:v for k,v in authority.items() if k!='authorityIdentity'})
    return fragment


def production_join(fragment):
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.csr_architecture_profile import parse_profile
    facts,witness=bind_csr_compiler_operands(fragment,TranslationRuntimeFacts(
        rv_to_operand_index={'a0':0},operand_width_bits={0:64}),[one_insn()],
        source_digest=fragment.compilerFragmentAuthority['sourceDigest'],architecture_profile=parse_profile(profile()))
    return facts,join_csr_operand_bindings(lifted_insns=[one_insn()],authority=facts)[0],witness


@pytest.mark.parametrize('kind,relation',[
    ('function_return','function_return'),('c_expression','pure_integer_expression'),
    ('branch_condition','control_predicate'),('subsequent_asm_input','fragment_operand'),
    ('dead','discarded'),('discarded','discarded')])
def test_production_csr_join_preserves_typed_uses_without_no_escape_fabrication(kind,relation):
    fragment=authority_for_use(kind,relation)
    facts,binding,witness=production_join(fragment)
    assert facts.output_escape_facts=={}
    assert binding.complete and binding.result_value_flow.uses[0].use_kind==kind
    assert witness['resultValueFlows']['0']==binding.result_value_flow.flow_identity
    state=NS(csr_effects=(NS(csr_id='riscv.csr.time',csr_class=NS(value='user_counter_observation'),
        complete=True,access_allowed=True,may_trap=False),),csr_operand_bindings=(binding,),
        csr_state_dataflow=NS(complete=True,requires_whole_function=False))
    model=adapt_source_csr_semantic_model(state)
    assert model.complete and not model.requires_whole_function and model.state_escapes==()


def test_unknown_scalar_use_blocks_completeness_without_claiming_state_escape():
    fragment=authority_for_use('escape_unknown','identity',complete=False)
    _,binding,_=production_join(fragment)
    assert not binding.complete
    assert 'csr-join.result-value-flow-incomplete' in binding.reason_codes
    model=adapt_source_csr_semantic_model(NS(csr_effects=(),csr_operand_bindings=(binding,),
        csr_state_dataflow=NS(complete=True)))
    assert not model.complete and not model.requires_whole_function


@pytest.mark.parametrize('mutation,reason',[
    ('relation','RELATION_MISMATCH'),('consumer','CONSUMER_MISSING'),
    ('duplicate','USE_BINDING_INVALID'),('discard','DISCARD_CONFLICT'),('node','inconsistent')])
def test_result_flow_mutations_rejected_even_with_fresh_outer_hashes(mutation,reason):
    f=authority_for_use('subsequent_asm_input','fragment_operand');a=f.compilerFragmentAuthority
    use=a['candidate']['downstreamUses'][0]
    if mutation=='relation':use['relationKind']='memory_store'
    if mutation=='consumer':use['consumerFragmentIdentity']=''
    if mutation=='duplicate':a['candidate']['downstreamUses'].append(deepcopy(use))
    if mutation=='discard':
        a['candidate']['downstreamUses'].append({**use,'useKind':'discarded','relationKind':'discarded',
            'useNodeIdentity':'sha256:'+'c'*64,'observationSinkIdentity':'','consumerFragmentIdentity':''})
    if mutation=='node':use['valueNodeIdentity']='not-sha'
    a['candidate']['closureIdentity']=content_identity({k:v for k,v in a['candidate'].items() if k!='closureIdentity'})
    a['authorityIdentity']=content_identity({k:v for k,v in a.items() if k!='authorityIdentity'})
    with pytest.raises(ValueError,match=reason):result_flows_from_compiler(f.id,a)


def test_flow_identity_covers_sink_and_compiler_closure():
    f=authority_for_use('function_return','function_return');a=f.compilerFragmentAuthority
    first=result_flows_from_compiler(f.id,a)[0].flow_identity
    a['candidate']['downstreamUses'][0]['observationSinkIdentity']='sha256:'+'c'*64
    assert result_flows_from_compiler(f.id,a)[0].flow_identity!=first


def test_reason_text_cannot_establish_hidden_state_escape():
    model=adapt_source_csr_semantic_model(NS(csr_effects=(),csr_operand_bindings=(
        NS(complete=False,reason_codes=('csr-join.output-escape-unproven',)),),
        csr_state_dataflow=NS(complete=False)))
    assert not model.requires_whole_function and not model.state_escapes


def test_typed_state_escape_is_distinct_and_has_granularity_provenance():
    fact=CsrStateEscapeFact('riscv.csr.satp','external',True,'compiler-state-flow.v1','sha256:'+'a'*64,True)
    state=NS(csr_effects=(),csr_operand_bindings=(),csr_state_dataflow=NS(complete=True),csr_state_escape_facts=(fact,))
    model=adapt_source_csr_semantic_model(state)
    assert model.requires_whole_function and model.state_escapes==('riscv.csr.satp',)
    assert model.whole_function_requirements[0].origin=='typed_state_escape'
    state.csr_state_escape_facts=(replace(fact,complete=False),)
    model=adapt_source_csr_semantic_model(state)
    assert not model.requires_whole_function and 'csr-6a.state-escape-fact-incomplete' in model.reason_codes


def test_invalid_escape_fact_is_a_diagnostic_not_an_adapter_exception():
    model=adapt_source_csr_semantic_model(NS(csr_effects=(),csr_operand_bindings=(),
        csr_state_dataflow=NS(complete=True),csr_state_escape_facts=(object(),)))
    assert not model.complete and 'csr-6a.state-escape-fact-invalid' in model.reason_codes


def approved_production_binding_fixture():
    """Real decoder/join/6A/6D/renderer replay; no frontend/QEMU claim."""
    from tests.test_privileged_state_analysis import _facts
    from tests.test_csr_translation_pipeline import _counter_contract
    from tests.test_runtime_contract_consumption import recipe
    from riscv2x86_py.privileged_state_analysis import _typed_csr_effect
    from riscv2x86_py.csr_translation_pipeline import (CsrRuntimeRegistry,CsrRendererRegistry,
        CsrTranslationFallbackPolicy,run_csr_translation_pipeline)
    from riscv2x86_py.csr_effect_constraints import CsrTargetMapping
    from riscv2x86_py.csr_runtime_shell import AUTOMATIC_RUNTIME_BUILD_CONTRACT
    from riscv2x86_py.csr_runtime_approval import build_csr_runtime_approval
    f=authority_for_use('function_return','function_return');f.outputs[0].exprText='emitted_result'
    _,binding,_=production_join(f)
    op=one_insn().privileged_operations[0]
    effect=_typed_csr_effect(0x10000,0,op,_facts(readable=('riscv.csr.time',),writable=()),isolated_counter_access=True)
    assert effect.complete and not effect.may_trap
    observability=NS(complete=True,unignored_privileged_state_ids=(),fallback_eligible=True,
        ignored_states=(NS(state_id='riscv.csr.time.architectural_counter_value',complete=True),))
    model=adapt_source_csr_semantic_model(NS(csr_effects=(effect,),csr_operand_bindings=(binding,),
        csr_state_dataflow=NS(complete=True,requires_whole_function=False)),observability=observability)
    contract=replace(_counter_contract('functional-monotonic-observation'),
        target_observation_mechanism='clock_gettime:CLOCK_MONOTONIC:ns',
        availability_policy='runtime-checked-fail-closed',trap_policy='execution-failure-not-a-counter-value')
    mapping=CsrTargetMapping(binding.source_effect_id,'riscv.csr.time','context','read-counter','v1','unit-profile','execution',
        read_result_mapping='return',field_mappings=tuple(x.field_id for x in effect.affected_fields),
        old_new_state_relation_id='clock-observation',access_policy_mapping_id='explicit-policy',ordering_relation_id='call-order',
        counter_contract_identity=contract.contract_id,counter_relation_kind=contract.relation_kind,counter_contract=contract)
    result=run_csr_translation_pipeline(model,None,NS(execution_profile='unit-profile'),
        CsrRuntimeRegistry('registry','v1','unit-profile',(mapping,),True,True,fragment_id=f.id),
        CsrRendererRegistry('renderer',{'read-counter':recipe()},{'recipe':'v1'}),
        CsrTranslationFallbackPolicy(allow_functional_fallbacks=True),
        operand_expressions={0:'emitted_result'},fragment_id=f.id,source_fragment=f,
        target_build_contract=AUTOMATIC_RUNTIME_BUILD_CONTRACT)
    assert result.status=='approved',result.reason_codes
    approval=build_csr_runtime_approval(f,result,machine_code=bytes.fromhex('732510c0'),
        decoder_profile={'privilege_spec_version':'1.12','xlen_bits':64,'extensions':['zicsr']},
        target_environment_id='unit-environment',functional_observability=observability)
    return f,result,approval


def test_approved_runtime_replays_compiler_result_use_authority():
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    f,result,approval=approved_production_binding_fixture()
    assert validate_csr_runtime_approval(approval,f,result.suggested_replacement)==approval['l2EffectProofFacts']
    assert 'emitted_result' in result.suggested_replacement


def test_rehashed_field_proof_cannot_remove_compiler_result_use():
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    from riscv2x86_py.csr_field_proof import prove_csr_fields
    from riscv2x86_py.csr_runtime_approval import _namespace
    from riscv2x86_py.semantic_content import semantic_identity
    f,result,approval=approved_production_binding_fixture();p=approval['proofPayload'];field=p['fieldProof']
    field['sourceModel']['operand_bindings'][0]['result_value_flow']=None
    proof=prove_csr_fields(source_model=_namespace(field['sourceModel']),
        constraints=tuple(_namespace(x) for x in field['constraints']),execution_profile=field['executionProfile'],
        shell_preserved=field['shellPreserved'],external_state_complete=field['externalStateComplete'],
        registry_identity=field['registryIdentity'],target_environment_id=field['targetEnvironmentId'],
        shell_facts=tuple(field['shellFacts']),allow_functional_relations=field['functionalRelationsEnabled'])
    p['fieldProofIdentity']=proof.proof_identity;p['fieldProof']=proof.proof_payload
    approval['proofIdentity']=semantic_identity(p)
    with pytest.raises(ValueError,match='RESULT_VALUE_FLOW_MISMATCH'):
        validate_csr_runtime_approval(approval,f,result.suggested_replacement)


def test_unused_recipe_input_cannot_be_added_by_rehashing():
    from tests.test_runtime_contract_consumption import approved_csr_runtime_fixture
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    from riscv2x86_py.semantic_content import semantic_identity
    f,result,approval=approved_csr_runtime_fixture()
    approval['proofPayload']['recipe']['input_expression']='7'
    approval['proofIdentity']=semantic_identity(approval['proofPayload'])
    with pytest.raises(ValueError,match='IMMEDIATE_OR_INPUT_BINDING_MISMATCH'):
        validate_csr_runtime_approval(approval,f,result.suggested_replacement)


def test_discarded_csrrs_result_still_has_an_effect_without_requiring_a_value_node():
    from tests.test_privileged_state_analysis import _facts
    from riscv2x86_py.csr_metadata_ingress import decode_csr_instruction, canonical_csr_operations_from_decoded, CsrDecoderProfile
    from riscv2x86_py.privileged_state_analysis import _typed_csr_effect
    # CSRRS x0,time,x0 still reads the CSR, but its GPR result is discarded.
    instruction=((0xc01<<20)|(2<<12)|0x73).to_bytes(4,'little')
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=decode_csr_instruction(instruction),
        xlen_bits=64,profile=CsrDecoderProfile('1.12',64,('zicsr',)))[0]
    assert op.read_result_suppressed and op.read_value_node_id is None
    effect=_typed_csr_effect(0x10000,0,op,_facts(readable=('riscv.csr.time',),writable=()))
    assert effect.csr_id=='riscv.csr.time'
    assert 'privileged-state.csr-value-flow-incomplete' not in effect.missing_fact_codes
    # Discarding the result never grants access or resolves a potential trap.
    assert effect.may_trap is True


@pytest.mark.parametrize('mutation',['read','write','immediate'])
def test_rehashed_field_proof_cannot_change_decoder_operand_roles(mutation):
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval, _namespace
    from riscv2x86_py.csr_field_proof import prove_csr_fields
    from riscv2x86_py.semantic_content import semantic_identity
    f,result,approval=approved_production_binding_fixture();p=approval['proofPayload'];field=p['fieldProof']
    binding=field['sourceModel']['operand_bindings'][0]
    if mutation=='read':binding['read_result_operand_index']=None
    if mutation=='write':binding['write_value_operand_index']=0
    if mutation=='immediate':binding['immediate_value']=7
    proof=prove_csr_fields(source_model=_namespace(field['sourceModel']),
        constraints=tuple(_namespace(x) for x in field['constraints']),execution_profile=field['executionProfile'],
        shell_preserved=field['shellPreserved'],external_state_complete=field['externalStateComplete'],
        registry_identity=field['registryIdentity'],target_environment_id=field['targetEnvironmentId'],
        shell_facts=tuple(field['shellFacts']),allow_functional_relations=field['functionalRelationsEnabled'])
    p['fieldProof']=proof.proof_payload;p['fieldProofIdentity']=proof.proof_identity
    approval['proofIdentity']=semantic_identity(p)
    with pytest.raises(ValueError,match='DECODER_OPERAND_ROLE_MISMATCH'):
        validate_csr_runtime_approval(approval,f,result.suggested_replacement)
