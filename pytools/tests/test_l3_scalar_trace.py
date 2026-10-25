"""Real compiler fixtures and strict trace/contract checks, not QEMU success."""
from copy import deepcopy
import json
import shutil
import subprocess

import pytest

from riscv2x86_py.l3_property_obligations import analyze,check_properties,validate,POLICY
from riscv2x86_py.l3_scalar_trace import scalar_spec,parse_samples,scalar_harness
from riscv2x86_py.l3_trace_intent import produce
from riscv2x86_py.l3_trace_support import identity
from riscv2x86_py.l3_qemu_backend import parse_capture
from riscv2x86_py.l3_qemu_memory_route import normalize,parse_contract,SCALAR_CONTRACT_SCHEMA
from tests.test_static_operand_production import literal_finding


def finding(tmp_path):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    f,fn=literal_finding();frontend=tmp_path/'frontend';frontend.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},[fn],frontend)==1
    f['translationOutcome']='emitted'
    return f


def request(f):
    a=f['approvalArtifact']; sidecar=a['l2AuthoritySidecar']
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    value={'schemaVersion':'riscv2x86.l3-intent-producer-request.v1','producerIdentity':identity('producer'),
        'candidates':[{'finding':f,'translationArtifact':{'proof_identity':a['proofIdentity'],
            'effect_relation_set_identity':l2_authority_sidecar_from_dict(sidecar).effect_relation_set_identity}}]}
    return dict(value,requestIdentity=identity(value))


def contract(f):
    ob=analyze(f);profile=produce(request(f))['profiles'][0]
    from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
    f=deepcopy(f);f['l3IntentProfile']=profile
    req=classify_l3_requirements({'findings':[f]}).requirements[0]
    spec=scalar_spec(f);props=ob['requiredProperties']
    from riscv2x86_py.l3_memory_intent import LIMITATIONS
    return {'schemaVersion':SCALAR_CONTRACT_SCHEMA,'experimentId':'scalar-trace','translationPlanId':'plan',
        'proofIdentity':ob['proofIdentity'],'intentProfileIdentity':profile['profileIdentity'],
        'requirementIdentity':req['requirementIdentity'],'approvedTargetRelationIdentity':ob['approvedTargetRelationIdentity'],
        'programId':spec['programId'],'fragmentId':spec['fragmentId'],'spec':spec,
        'deployment':{'spec':spec,'sampleCount':4},'backendPath':'not-a-backend','backendDigest':identity('backend'),
        'cacheModel':None,'requiredProperties':props,'propertyBindings':[
            dict(p,comparatorId='logical-access-contract.v1',obligationIds=['memory:empty-executed-region']) for p in props],
        'sampleCount':4,'knownNonEquivalences':LIMITATIONS,'propertyObligations':ob}


def test_obligation_first_scalar_is_real_required_experiment_not_none(tmp_path):
    f=finding(tmp_path);ob=analyze(f);assert validate(ob)==ob
    assert ob['policy']==POLICY and ob['physicalMicroarchitectureClaimed'] is False
    assert ob['requiredProperties'][0]['dimension']=='access_pattern'
    response=produce(request(f));assert response['dispositions']==[]
    profile=response['profiles'][0];assert profile['complete'] and profile['intentKind']=='memory_access'
    parsed=parse_contract(contract(f));assert parsed.required_access_pattern==()
    assert parsed.payload['propertyBindings'][0]['obligationIds']==['memory:empty-executed-region']
    assert f['approvalArtifact']['l2AuthoritySidecar']['memoryObjects']==[]


@pytest.mark.parametrize('mutation',['proof','shape','sidecar','boundary','effect'])
def test_missing_or_changed_facts_never_discharge_an_obligation(tmp_path,mutation):
    f=finding(tmp_path);req=request(f);a=f['approvalArtifact']
    if mutation=='proof':a['proofIdentity']=identity('other')
    if mutation=='shape':f['l2SemanticProfile']['memoryShape']['complete']=False
    if mutation=='sidecar':a['l2AuthoritySidecar']['complete']=False
    if mutation=='boundary':a['l2FragmentOperandBoundary']['complete']=False
    if mutation=='effect':a['l2EffectProofFacts']['sourceEffects']=[]
    with pytest.raises((ValueError,KeyError)):analyze(f)
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    assert not produce(req)['profiles'][0]['complete']


def test_chosen_model_cannot_erase_known_obligations(tmp_path):
    f=finding(tmp_path);before=analyze(f)
    from riscv2x86_py.l3_cache_model import DEFAULT
    result=produce(request(f),DEFAULT)
    assert result['profiles'][0]['requiredProperties']==before['requiredProperties']
    assert not result['profiles'][0]['complete']
    assert result['dispositions'][0]['reasonCodes']==['L3_SCALAR_OBJECT_RELATIVE_CACHE_MODEL_UNSUPPORTED']
    with pytest.raises(ValueError):check_properties(before,[])


@pytest.mark.parametrize('mutation',['policy','dimension','deletion','binding','downgrade','width'])
def test_rehashed_contract_cannot_weaken_scalar_comparison(tmp_path,mutation):
    value=contract(finding(tmp_path))
    if mutation=='policy':value['propertyObligations']['policy']={}
    if mutation=='dimension':value['propertyObligations']['decisions']=[]
    if mutation=='deletion':value['requiredProperties']=[]
    if mutation=='binding':value['propertyBindings'][0]['obligationIds']=[]
    if mutation=='downgrade':value['schemaVersion']='riscv2x86.compiler-region-trace-experiment.v1'
    if mutation=='width':value['spec']['width']=8
    ob=value['propertyObligations'];ob['obligationIdentity']=identity({k:v for k,v in ob.items() if k!='obligationIdentity'})
    with pytest.raises(ValueError):parse_contract(value)


def test_zero_data_events_requires_actual_entry_exit_and_footer():
    token='a'*64;region={'start':4096,'end':4100}
    trace=f'H 1 {token} riscv64 1000 1004\nB 0 1000\nE 0 1004\nF 1 1 0 0\n'
    assert parse_capture(trace,token=token,target='riscv64',region=region,calls=1)==[]
    for bad in ('',trace.replace('B 0 1000\n',''),trace.replace('E 0 1004\n',''),trace.replace('F 1 1 0 0','F 0 0 0 0')):
        with pytest.raises(ValueError):parse_capture(bad,token=token,target='riscv64',region=region,calls=1)
    assert normalize([{'sample':0,'address':1,'size':8,'access':'read'}],[],{'access':'none'})[1]


def test_scalar_harness_runs_real_native_and_reports_inputs(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC missing')
    source=tmp_path/'harness.c';scope={'returnType':'uint64_t','name':'arbitrary','parameterType':'uint64_t'}
    source.write_text(scalar_harness(scope,4)+'\nuint64_t arbitrary(uint64_t x){return x+67;}\n')
    p=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',str(source),'-o',str(tmp_path/'program')],capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    result=subprocess.run([str(tmp_path/'program'),'a'*64],capture_output=True,text=True)
    rows=parse_samples(result.stdout,'a'*64,4)
    assert all(int(x['value'],16)==int(x['input'],16)+67 for x in rows)
    with pytest.raises(ValueError):parse_samples(result.stdout,'b'*64,4)
    with pytest.raises(ValueError):parse_samples(result.stdout,'a'*64,5)


def test_registry_accepts_only_explicit_empty_stream_comparator(tmp_path):
    from riscv2x86_py.l3_provider_resolution import _contract_covers_properties
    from riscv2x86_py.l3_intent_requirements import parse_l3_intent_profile
    f=finding(tmp_path);profile=parse_l3_intent_profile(produce(request(f))['profiles'][0])
    raw=contract(f);parsed=parse_contract(raw)
    assert _contract_covers_properties(parsed,profile)
    # A label or an empty tuple alone does not enable the new comparator.
    from dataclasses import replace
    old=dict(raw,schemaVersion='riscv2x86.compiler-region-trace-experiment.v1')
    with pytest.raises(ValueError,match='logical access pattern'):
        replace(parsed,payload=old)


@pytest.mark.parametrize('dimension',['control_flow','synchronization'])
def test_unavailable_mechanism_retains_known_required_properties(tmp_path,dimension):
    from dataclasses import replace
    from riscv2x86_py.l2_semantic_profile import profile_from_finding
    f=finding(tmp_path);p=profile_from_finding(f)
    if dimension=='control_flow':p=replace(p,control_flow_shape=replace(p.control_flow_shape,internal_branch=True),profile_identity='')
    else:p=replace(p,ordering_shape=replace(p.ordering_shape,memory_barrier=True),profile_identity='')
    f['l2SemanticProfile']=p.to_dict()
    ob=analyze(f);response=produce(request(f));profile=response['profiles'][0]
    assert not profile['complete'] and profile['programId']==ob['programId']
    assert any(x['dimension']==dimension for x in profile['requiredProperties'])
    assert response['dispositions'][0]['reasonCodes']==['L3_TRACE_REQUIRED_MECHANISM_UNAVAILABLE:'+dimension]


@pytest.mark.parametrize('mutation',['none','function','type','outside-effects','digest'])
def test_scalar_deployment_uses_compiler_scope_not_function_name(tmp_path,monkeypatch,mutation):
    from riscv2x86_py.l3_trace_deployment import function_scope
    from riscv2x86_py.l3_trace_support import digest
    f=finding(tmp_path);source=tmp_path/'source.c';source.write_text('fixture: not a production build')
    b=f['approvalArtifact']['l2FragmentOperandBoundary'];fid=b['functionId']
    scope={'scope':'single_asm_no_other_memory_or_control_effects','sourceDigest':digest(source),
           'functionIdentity':fid,'scopeIdentity':identity('scope')}
    fn={'name':f['fragment']['enclosingFunction'],'returnType':'uint64_t','parameterTypes':['uint64_t'],
        'functionId':fid,'compilerAtomicFunctionScope':scope}
    monkeypatch.setattr('riscv2x86_py.mechanism_route_checks.compiler_bound_finding',lambda *a:(f,{'functions':[fn]}))
    if mutation=='function':fn['functionId']=identity('other')
    if mutation=='type':fn['parameterTypes']=['uint64_t *']
    if mutation=='outside-effects':scope['scope']='unknown'
    if mutation=='digest':scope['sourceDigest']=identity('stale')
    if mutation=='none':assert function_scope(source,'report',f)['name']==fn['name']
    else:
        with pytest.raises(ValueError,match='SCALAR_SCOPE'):function_scope(source,'report',f)
