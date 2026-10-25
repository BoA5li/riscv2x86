"""Bounded route refusal, store observations and literal closure regressions."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from riscv2x86_py.l3_memory_intent import produce, memory_spec
from riscv2x86_py.l3_intent_requirements import _hash, classify_l3_requirements, parse_l3_requirement_manifest
from riscv2x86_py.l3_qemu_memory_route import parse_objects, normalize
from riscv2x86_py.l3_trace_deployment import harness
from tests.test_l3_memory_trace import finding, SHA
from tests.test_compiler_expression_evaluation import memory_candidate
from tests.test_compiler_expression_contracts import expr, node, ctype, S, F


def request(f):
    value={'schemaVersion':'riscv2x86.l3-intent-producer-request.v1','producerIdentity':SHA,
        'candidates':[{'finding':f,'translationArtifact':{'proof_identity':SHA,'effect_relation_set_identity':SHA}}]}
    return dict(value,requestIdentity=_hash(value))


def store_finding():
    f=finding();a=f['approvalArtifact'];facts=a['l2MemoryProofFacts'];auth=a['l2AuthoritySidecar']
    facts.update(accessKind='store',valueOperandIndex=2)
    auth['sourceEffects'][0]['effectKind']='WriteMemory'
    auth['memoryObjects'][0]['writableRanges']=[[24,32]]
    auth['operands'].append({'operandIndex':2,'typeKind':'integer','parameterIndex':1,'accessMode':'input'})
    return f


def test_non_memory_refusal_is_explicit_unknown_not_none_or_approval():
    f=finding();f['approvalArtifact'].pop('l2MemoryProofFacts')
    response=produce(request(f))
    assert response['schemaVersion'].endswith('v2')
    profile=response['profiles'][0];decision=response['dispositions'][0]
    assert profile['intentKind']=='unknown' and profile['complete'] is False
    assert decision['status']=='unsupported'
    f.update(l3IntentProfile=profile,l3IntentDisposition=decision)
    manifest=classify_l3_requirements({'findings':[f]}).to_dict()
    assert parse_l3_requirement_manifest(manifest)
    assert manifest['requirements'][0]['eligibilityStatus']=='inconclusive'
    assert 'l3.intent.unsupported' in manifest['requirements'][0]['reasonCodes']
    assert manifest['requirements'][0]['disposition']!='not_applicable'


def test_refusal_cannot_be_attached_to_a_complete_profile():
    f=finding();response=produce(request(f));profile=response['profiles'][0]
    decision={'schemaVersion':'riscv2x86.l3-intent-disposition.v1','fragmentId':f['fragment']['id'],
        'profileIdentity':profile['profileIdentity'],'status':'unsupported','reasonCodes':['scope']}
    decision['dispositionIdentity']=_hash(decision)
    f.update(l3IntentProfile=profile,l3IntentDisposition=decision)
    with pytest.raises(ValueError,match='disposition-binding'):
        classify_l3_requirements({'findings':[f]})


def test_store_requires_writable_domain_and_independent_value_binding():
    f=store_finding();spec=memory_spec(f);assert spec['access']=='write'
    f['approvalArtifact']['l2AuthoritySidecar']['operands'][-1]['parameterIndex']=0
    with pytest.raises(ValueError):memory_spec(f)


def test_store_object_result_is_checked_against_input_not_only_other_side():
    spec=memory_spec(store_finding());token='a'*64
    expected=bytearray((0x31+17*i)&255 for i in range(32))
    value=0x1020304050607080;expected[24:32]=value.to_bytes(8,'little')
    row={'token':token,'sample':0,'objectBase':'2000','objectSize':32,
         'value':f'{value:016x}','objectHex':expected.hex()}
    objects=parse_objects(json.dumps(row),token,spec,1)
    events=[{'sample':0,'address':0x2018,'size':8,'access':'write'}]
    assert normalize(events,objects,spec)[1]==[]
    row['objectHex']='00'*32
    with pytest.raises(ValueError,match='STORE_VALUE_OR_OBJECT'):parse_objects(json.dumps(row),token,spec,1)


def test_store_harness_builds_and_runs_real_native_object_mutation(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native C compiler missing')
    spec=memory_spec(store_finding())
    scope={'name':'arbitrary_store','returnType':'uint64_t','parameterType':'uint64_t *','valueParameterType':'uint64_t'}
    source=tmp_path/'harness.c'
    source.write_text(harness(scope,spec,4)+'\nuint64_t arbitrary_store(uint64_t *p,uint64_t x){__asm__ volatile("movq %1,24(%0)"::"r"(p),"r"(x):"memory");return p[3];}\n')
    result=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',str(source),'-o',str(tmp_path/'program')],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    result=subprocess.run([str(tmp_path/'program'),'a'*64],capture_output=True,text=True)
    assert result.returncode==0
    assert len(parse_objects(result.stdout,'a'*64,spec,4))==4


@pytest.mark.parametrize('value',[0,18,67,2047])
def test_compiler_literal_is_closed_and_never_assigned_a_placeholder_register(value):
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate, validate_closed_compiler_fragment_candidate
    from riscv2x86_py.schema import AsmFragment, AsmOperand
    from riscv2x86_py.assemble import materialize_template
    raw,fragment=memory_candidate()
    literal=expr(node('IntegerLiteral',value=str(value),valueCategory='prvalue'))
    facts=raw['compilerExpressionFacts'];facts['slots'][0]['expression']=literal
    facts['factsIdentity']=_hash({k:v for k,v in facts.items() if k!='factsIdentity'})
    fragment.update(outputs=[],inputs=[{'constraint':'i','compilerType':ctype()}])
    closed=close_compiler_fragment_candidate(raw,fragment,source_digest=S,function_identity=F)
    validate_closed_compiler_fragment_candidate(closed)
    carrier=closed['operandCarriers'][0]
    assert carrier['constantValue']==value and carrier['declarationIdentity']==''
    asm=AsmFragment(id='fragment',rawAsmText='addi x10,x10,%0',inputs=[AsmOperand(constraint='i')],
        compilerFragmentAuthority={'candidate':closed})
    result=materialize_template(asm)
    assert result.normalized_asm==f'addi x10,x10,{value}'
    assert result.operand_bindings==[]


def test_memory_lvalue_compiler_provenance_consumes_replayed_expression_role():
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
    from riscv2x86_py.compiler_provenance import bind_compiler_provenance
    raw,fragment=memory_candidate();key=raw['fragmentBindingKey']
    raw['candidateIdentity']=_hash({'schemaVersion':'riscv2x86.compiler-fragment-binding-key.v2',**key})
    facts=raw['compilerExpressionFacts'];facts['candidateIdentity']=raw['candidateIdentity']
    facts['factsIdentity']=_hash({k:v for k,v in facts.items() if k!='factsIdentity'})
    closed=close_compiler_fragment_candidate(raw,fragment,source_digest=S,function_identity=F)
    authority={'schemaVersion':'riscv2x86.compiler-fragment-authority.v2','candidate':closed,
        'sourceDigest':S,'functionIdentity':F,'fragmentId':'fragment','targetTriple':'riscv64-linux-gnu',
        'fragmentBindingKey':key,'compilerTypeBindings':{'0':{'operandIndex':0,
            'valueNodeIdentity':closed['operandBindings'][0]['valueNodeIdentity'],'compilerType':ctype()}}}
    authority['authorityIdentity']=_hash(authority);fragment['compilerFragmentAuthority']=authority
    b=closed['operandBindings'][0]
    operand=SimpleNamespace(operand_index=0,declaration_id='',value_node_identity=b['valueNodeIdentity'],
        access_mode='read_write',width_bits=64,signedness='unsigned')
    sidecar=SimpleNamespace(fragment_id='fragment',operands=[operand],authority_identity=SHA)
    assert bind_compiler_provenance(fragment,sidecar)
    changed=deepcopy(fragment);changed['compilerFragmentAuthority']['compilerTypeBindings']['0']['compilerType']['widthBits']=32
    a=changed['compilerFragmentAuthority'];a['authorityIdentity']=_hash({k:v for k,v in a.items() if k!='authorityIdentity'})
    with pytest.raises(ValueError):bind_compiler_provenance(changed,sidecar)


@pytest.mark.parametrize('memory_only',[False,True])
def test_atomic_storage_sidecar_compiler_consumption_has_no_scalar_signedness(memory_only):
    from tests.test_l2_atomic_production import atomic_finding
    from riscv2x86_py.l2_atomic_authority import materialize_atomic_authority
    from riscv2x86_py.compiler_provenance import bind_compiler_provenance
    f,functions,_,_=atomic_finding(expression=not memory_only,memory_only=memory_only)
    sidecar=materialize_atomic_authority(f,functions,SHA)
    assert sidecar is not None
    receipt=bind_compiler_provenance(f['fragment'],sidecar)
    assert receipt['canonicalAuthorityIdentity']==sidecar.authority_identity


@pytest.mark.parametrize('mutation',['call','wrong-base','negative','extra-return'])
def test_store_scope_rejects_unbound_or_effectful_outer_code(mutation):
    from riscv2x86_py.compiler_continuation_sites import memory_store_function_scope
    fn={'inner':[{'kind':'ParmVarDecl','id':'p'},{'kind':'ParmVarDecl','id':'x'},
        {'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt'},
            {'kind':'ReturnStmt','inner':[{'kind':'ArraySubscriptExpr','inner':[
                {'kind':'ImplicitCastExpr','castKind':'LValueToRValue','inner':[
                    {'kind':'DeclRefExpr','referencedDecl':{'id':'p'}}]},
                {'kind':'IntegerLiteral','value':'3'}]}]}]}]}
    kwargs={'source_digest':SHA,'function_identity':SHA,'source_range':lambda _: (0,20)}
    assert memory_store_function_scope(fn,**kwargs)['returnElementIndex']==3
    statements=fn['inner'][-1]['inner']
    if mutation=='call':statements.insert(0,{'kind':'CallExpr'})
    if mutation=='wrong-base':statements[1]['inner'][0]['inner'][0]['inner'][0]['referencedDecl']['id']='x'
    if mutation=='negative':statements[1]['inner'][0]['inner'][1]['value']='-1'
    if mutation=='extra-return':statements.append({'kind':'ReturnStmt','inner':[]})
    assert memory_store_function_scope(fn,**kwargs) is None


@pytest.mark.parametrize('model',[None,{'schemaVersion':'unused'}])
def test_store_contract_requires_v2_and_actual_write_property_binding(model):
    from tests.test_l3_memory_trace import contract
    from riscv2x86_py.l3_cache_model import DEFAULT
    from riscv2x86_py.l3_qemu_memory_route import parse_contract, STORE_CONTRACT_SCHEMA
    raw=contract(None if model is None else DEFAULT)
    raw['schemaVersion']=STORE_CONTRACT_SCHEMA
    raw['spec']=memory_spec(store_finding())
    raw['deployment']['spec']=raw['spec']
    for binding in raw['propertyBindings']:
        if binding['dimension']=='access_pattern':binding['obligationIds']=['memory:approved-write']
    parsed=parse_contract(raw)
    assert parsed.required_access_pattern[0].access=='write'
    bad=deepcopy(raw);bad['schemaVersion']='riscv2x86.compiler-region-trace-experiment.v1'
    with pytest.raises(ValueError):parse_contract(bad)
    for binding in raw['propertyBindings']:
        if binding['dimension']=='access_pattern':binding['obligationIds']=['memory:approved-read']
    with pytest.raises(ValueError):parse_contract(raw)
