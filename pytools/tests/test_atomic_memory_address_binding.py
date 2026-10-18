from copy import deepcopy
from dataclasses import replace
import pytest
from riscv2x86_py.atomic_memory_binding import identity,validate_binding,model_binding_reason,AtomicMemoryBindingError
from riscv2x86_py.l2_semantic_profile import profile_from_source_model
from riscv2x86_py.l2_atomic_authority import materialize_atomic_authority
from tests.test_l2_atomic_production import atomic_finding


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('shape',['pointer_only','separate_pointer','memory_only'])
def test_all_operand_roles_reach_profile_and_materializer(width,shape):
    finding,functions,model,_=atomic_finding(memory_width=width,
        expression=shape=='separate_pointer',memory_only=shape=='memory_only')
    operands=model.operands.operands
    assert len(operands)==len(finding['fragment']['outputs'])+len(finding['fragment']['inputs'])
    assert [x.source_operand_index for x in operands]==list(range(len(operands)))
    if shape=='separate_pointer':
        assert operands[1].access.value=='read_write'
        assert operands[2].access.value=='address'
        b=operands[1].address.memory_access_binding
        assert (b['memoryOperandIndex'],b['addressOperandIndex'])==(1,2)
        validate_binding(b)
    profile=profile_from_source_model(finding['fragment']['id'],model)
    assert profile.complete and profile.memory_shape.object_relative
    assert materialize_atomic_authority(finding,functions,'sha256:'+'f'*64) is not None


@pytest.mark.parametrize('field,value,reason',[
    ('memory_object_identity','other','L2_ATOMIC_MEMORY_OBJECT_MISMATCH'),
    ('byte_offset',8,'L2_ATOMIC_MEMORY_ACCESS_RANGE_MISMATCH'),
    ('atomic_read_effect_identity','other','L2_ATOMIC_MEMORY_EFFECT_BINDING_MISMATCH'),
    ('atomic_authority_identity','sha256:'+'0'*64,'L2_ATOMIC_MEMORY_AUTHORITY_MISMATCH'),
    ('memory_access_binding',None,'L2_ATOMIC_MEMORY_BINDING_SCHEMA_INVALID'),
])
def test_each_access_is_required_even_if_a_valid_pointer_exists(field,value,reason):
    finding,_,model,_=atomic_finding(expression=True)
    memory=model.operands.operands[1]
    bad=replace(memory,address=replace(memory.address,**{field:value}))
    operands=(model.operands.operands[0],bad,model.operands.operands[2])
    assert model_binding_reason(bad,operands,model.atomic,finding['fragment']['id'])==reason
    changed=replace(model,operands=replace(model.operands,operands=operands))
    assert not profile_from_source_model(finding['fragment']['id'],changed).complete


@pytest.mark.parametrize('field,value',[
    ('addressOperandIndex',99),('memoryOperandIndex',2),('offsetBytes',4),
    ('widthBits',32),('memoryExpressionIdentity','sha256:'+'a'*64),
    ('addressValueNodeIdentity','sha256:'+'b'*64),('readEffectIdentity','wrong'),
])
def test_rehashing_a_mutated_relation_cannot_preserve_the_join(field,value):
    _,_,model,_=atomic_finding(expression=True)
    b=deepcopy(model.operands.operands[1].address.memory_access_binding)
    b[field]=value
    b['bindingIdentity']=identity({k:v for k,v in b.items() if k!='bindingIdentity'})
    with pytest.raises(AtomicMemoryBindingError):validate_binding(b)


def test_versioned_runtime_snapshot_roundtrip_and_legacy_rejection():
    from tests.test_atomic_expression_consumer import authority_for_expression,consume
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts,translation_runtime_facts_to_dict,translation_runtime_facts_from_dict
    objects=consume(authority_for_expression())
    facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':2},operand_width_bits={0:64,1:64,2:64},atomic_memory_objects=objects)
    raw=translation_runtime_facts_to_dict(facts)
    assert raw['atomicMemoryObjects']['1']['schemaVersion']=='riscv2x86.atomic-memory-object-runtime.v2'
    assert translation_runtime_facts_from_dict(raw).atomic_memory_objects==objects
    raw['atomicMemoryObjects']['1'].pop('schemaVersion')
    with pytest.raises(ValueError):translation_runtime_facts_from_dict(raw)


@pytest.mark.parametrize('width',[32,64])
def test_runtime_semantics_carries_all_memory_and_pointer_roles(width):
    from tests.test_atomic_expression_consumer import authority_for_expression
    from tests.test_production_route_authority import _atomic
    from riscv2x86_py.atomic_authority import atomic_runtime_object_from_compiler_authority
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.source_model import _runtime_operand_bindings,_runtime_operand_semantics
    from riscv2x86_py.shell_model import SourceShellModel
    from riscv2x86_py.schema import AsmFragment,AsmOperand
    authority=authority_for_expression(memory_width=width)
    decoded=_atomic();decoded.width_bits=width;decoded.register_width_bits=64
    decoded.result_extension='sign_extend' if width==32 else 'identity'
    facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':2},operand_width_bits={0:64,1:width,2:64})
    objects=atomic_runtime_object_from_compiler_authority(authority,fragment_id=authority['fragmentId'],
        source_digest=authority['sourceDigest'],begin_offset=100,end_offset=140,runtime_facts=facts,atomic_operation=decoded)
    facts=replace(facts,atomic_memory_objects=objects)
    shell=SourceShellModel.from_fragment(AsmFragment(id=authority['fragmentId'],
        outputs=[AsmOperand(constraint='+r',isOutput=True),AsmOperand(constraint='+m',isOutput=True)],
        inputs=[AsmOperand(constraint='r')]))
    semantic=_runtime_operand_semantics(facts,shell=shell,authoritative_bindings=_runtime_operand_bindings(facts),
        memory_address_operand_offsets={2:0})
    assert sorted(semantic)==[0,1,2]
    assert semantic[1].address.memory_access_binding==objects[1].memory_access_binding
    assert facts.operand_width_bits[1]==width and facts.operand_width_bits[2]==64
    assert semantic[1].address.memory_access_binding['widthBits']==width
    assert semantic[1].access.value=='read_write' and semantic[2].access.value=='address'


def test_legacy_memory_only_projection_does_not_authorize_a_separate_carrier():
    f,_,m,_=atomic_finding(memory_only=True)
    memory=m.operands.operands[1]
    memory=replace(memory,address=replace(memory.address,memory_access_binding=None))
    operands=(m.operands.operands[0],memory)
    assert model_binding_reason(memory,operands,m.atomic,f['fragment']['id'])==''
    f,_,m,_=atomic_finding(expression=True)
    memory=m.operands.operands[1]
    memory=replace(memory,address=replace(memory.address,memory_access_binding=None))
    assert model_binding_reason(memory,(m.operands.operands[0],memory,m.operands.operands[2]),m.atomic,f['fragment']['id'])=='L2_ATOMIC_MEMORY_BINDING_SCHEMA_INVALID'


def test_an_additional_unbound_access_cannot_be_hidden_by_valid_accesses():
    f,_,m,_=atomic_finding(expression=True)
    operands=m.operands.operands+(replace(m.operands.operands[1],source_operand_index=3),)
    changed=replace(m,operands=replace(m.operands,operands=operands))
    assert not profile_from_source_model(f['fragment']['id'],changed).complete


def test_classification_retains_the_specific_binding_reason():
    from riscv2x86_py.atomic_memory_binding import model_binding_diagnostics
    from riscv2x86_py.l2_eligibility import L2EligibilityClassifier
    f,_,m,_=atomic_finding(expression=True)
    memory=m.operands.operands[1]
    bad=replace(memory,address=replace(memory.address,memory_object_identity='other'))
    m=replace(m,operands=replace(m.operands,operands=(m.operands.operands[0],bad,m.operands.operands[2])))
    profile=profile_from_source_model(f['fragment']['id'],m)
    f['l2SemanticProfile']=profile.to_dict();f['translationOutcome']='emitted'
    issues=model_binding_diagnostics(f['fragment']['id'],m)
    d={'schemaVersion':'riscv2x86.atomic-memory-profile-decision.v1','profileIdentity':profile.profile_identity,
       'fragmentId':f['fragment']['id'],'complete':False,'issues':issues}
    d['decisionIdentity']=identity(d)
    f['approvalArtifact']['l2AtomicMemoryBindingDecision']=d
    classified=L2EligibilityClassifier().classify(f,0)
    import json
    text=json.dumps(classified)
    assert 'L2_ATOMIC_MEMORY_OBJECT_MISMATCH' in text
    assert 'l2.semantic-profile.incomplete' not in text
