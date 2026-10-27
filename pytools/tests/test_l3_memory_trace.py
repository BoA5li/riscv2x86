"""Trace protocol/model and native compiler tests; no simulated hardware claim."""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from riscv2x86_py.l3_cache_model import DEFAULT, evaluate, validate
from riscv2x86_py.l3_memory_intent import memory_spec, produce
from riscv2x86_py.l3_intent_requirements import _hash, classify_l3_requirements, parse_l3_requirement_manifest
from riscv2x86_py.l3_qemu_backend import parse_capture
from riscv2x86_py.l3_qemu_memory_route import normalize, parse_objects, parse_contract, CONTRACT_SCHEMA
from riscv2x86_py.l3_trace_deployment import label_assembly, harness
from riscv2x86_py.l3_trace_support import Elf, identity, run

SHA='sha256:'+'a'*64


def finding():
    return {'fragment':{'id':'fragment:any-renamed-location'},'translationOutcome':'emitted',
        'approvalArtifact':{'proofStatus':'approved','architectureSemanticsPreserved':True,
            'shellSemanticsPreserved':True,'l2MemoryProofFacts':{'complete':True,
                'fragmentId':'fragment:any-renamed-location','accessKind':'load','nonAtomic':True,
                'widthBytes':8,'byteOffset':24,'addressOperandIndex':1},
            'l2FragmentOperandBoundary':{'complete':True,'fragmentId':'fragment:any-renamed-location','programId':SHA},
            'l2AuthoritySidecar':{'complete':True,'fragmentId':'fragment:any-renamed-location','authorityIdentity':SHA,
                'memoryObjects':[{'objectId':'private:argument','sizeBytes':32,'minimumAlignment':8,'complete':True,
                    'originKind':'function_argument','lifetimeScope':'function_call','writableRanges':[],
                    'readableRanges':[[24,32]]}],
                'sourceEffects':[{'effectId':'read:bound','effectKind':'ReadMemory','complete':True}],
                'approvedEffectRelations':[{'sourceEffectId':'read:bound','targetEffectIds':['target:read'],
                    'relationKind':'exact','complete':True}],
                'operands':[{'operandIndex':1,'typeKind':'pointer','parameterIndex':0,'accessMode':'address'}]}}}


def intent(model=None):
    f=finding()
    request={'schemaVersion':'riscv2x86.l3-intent-producer-request.v1','producerIdentity':SHA,
        'candidates':[{'finding':f,'translationArtifact':{'proof_identity':SHA,'effect_relation_set_identity':SHA}}]}
    request['requestIdentity']=_hash(request)
    profile=produce(request,model)['profiles'][0]
    f['l3IntentProfile']=profile
    manifest=classify_l3_requirements({'findings':[f]})
    return profile,manifest.to_dict(),f


def contract(model=None):
    profile,manifest,f=intent(model); req=manifest['requirements'][0]; spec=memory_spec(f)
    properties=profile['requiredProperties']
    return {'schemaVersion':CONTRACT_SCHEMA,'experimentId':'registered-trace','translationPlanId':'approved-plan',
        'proofIdentity':SHA,'intentProfileIdentity':profile['profileIdentity'],'requirementIdentity':req['requirementIdentity'],
        'approvedTargetRelationIdentity':SHA,'programId':SHA,'fragmentId':spec['fragmentId'],'spec':spec,
        'deployment':{'spec':spec,'sampleCount':4},'backendPath':'/not-a-real-backend','backendDigest':SHA,
        'cacheModel':model,'requiredProperties':properties,'propertyBindings':[
            dict(p,comparatorId='object-relative-cache-model.v1' if p['dimension']=='cache_model' else 'logical-access-contract.v1',
                 obligationIds=['fragment-stream-lru-state'] if p['dimension']=='cache_model' else ['memory:approved-read'])
            for p in properties],'sampleCount':4,'knownNonEquivalences':profile['notClaimedProperties']}


@pytest.mark.parametrize('model',[None,DEFAULT])
def test_registered_intent_and_contract_retain_full_properties(model):
    profile,manifest,f=intent(model)
    assert parse_l3_requirement_manifest(manifest).to_dict()==manifest
    assert manifest['requirements'][0]['eligibilityStatus']=='eligible'
    assert ('cache_model' in {p['dimension'] for p in profile['requiredProperties']}) == (model is not None)
    parsed=parse_contract(contract(model))
    assert parsed.preservation_level=='bounded_execution_intent'
    assert parsed.sample_count==4
    assert parsed.required_access_pattern[0].offset==24
    assert profile['observationBoundary']['kind']=='compiler-asm-region'


@pytest.mark.parametrize('mutation',['no-proof','atomic','wrong-relation','no-boundary','write','width','alignment','parameter','multi-effect'])
def test_unproved_or_uncovered_memory_inputs_are_rejected(mutation):
    f=finding(); a=f['approvalArtifact']; auth=a['l2AuthoritySidecar']; facts=a['l2MemoryProofFacts']
    if mutation=='no-proof': a['proofStatus']='pending'
    if mutation=='atomic': facts['nonAtomic']=False
    if mutation=='wrong-relation': auth['approvedEffectRelations'][0]['sourceEffectId']='unrelated'
    if mutation=='no-boundary': a['l2FragmentOperandBoundary']['complete']=False
    if mutation=='write': auth['memoryObjects'][0]['writableRanges']=[[0,32]]
    if mutation=='width': facts['widthBytes']=16
    if mutation=='alignment': auth['memoryObjects'][0]['minimumAlignment']=128
    if mutation=='parameter': auth['operands'][0]['parameterIndex']=1
    if mutation=='multi-effect': auth['sourceEffects'].append(deepcopy(auth['sourceEffects'][0]))
    with pytest.raises(ValueError): memory_spec(f)


def test_cache_model_line_split_lru_and_empty_initial_state():
    model=dict(DEFAULT,lineBytes=8,setCount=1,ways=2)
    events=[{'offset':n,'size':1,'access':'read'} for n in (0,8,0,16,8)]
    result=evaluate(events,model)
    assert [e['hit'] for e in result['outcomes']]==[False,False,True,False,False]
    assert result['hits']==1 and result['misses']==4
    assert evaluate([{'offset':7,'size':2,'access':'read'}],model)['misses']==2
    assert result==evaluate(events,model)
    assert not result['physicalMicroarchitectureClaimed']


@pytest.mark.parametrize('field,value',[('lineBytes',3),('ways',True),('setCount',0),('initialState','warm'),
                                        ('addressMapping','physical'),('stream','whole-program')])
def test_cache_model_never_silently_changes_scope(field,value):
    with pytest.raises(ValueError): validate(dict(DEFAULT,**{field:value}))


TOKEN='a'*64
REGION={'start':0x1000,'end':0x1004}
TRACE=f'H 1 {TOKEN} riscv64 1000 1004\nB 0 1000\nM 0 0 1000 2018 8 R\nE 0 1004\nF 1 1 1 0\n'


def parse(text):
    return parse_capture(text,token=TOKEN,target='riscv64',region=REGION,calls=1)


def test_actual_access_protocol_requires_closed_scope_and_object_binding():
    events=parse(TRACE)
    objects=parse_objects(json.dumps({'token':TOKEN,'sample':0,'objectBase':'2000','objectSize':32,
                                     'value':'0102030405060708'}),TOKEN,memory_spec(finding()),1)
    normalized,reasons=normalize(events,objects,memory_spec(finding()))
    assert reasons==[] and normalized[0]['offset']==24
    assert normalize(events+events,objects,memory_spec(finding()))[1]
    bad=deepcopy(events);bad[0]['access']='write'
    assert normalize(bad,objects,memory_spec(finding()))[1]


@pytest.mark.parametrize('text',[
    TRACE.replace('F 1 1 1 0\n',''),TRACE.replace('F 1 1 1 0','F 1 1 1 1'),
    TRACE.replace('B 0 1000\n',''),TRACE.replace('M 0 0','M 1 0'),TRACE.replace('1000 2018 8','1004 2018 8'),
    TRACE+'B 1 1000\n',TRACE.replace('E 0 1004','E 1 1004'),TRACE.replace(' 8 R',' 3 R'),
    TRACE.replace(TOKEN,'b'*64),TRACE.replace('riscv64','x86_64')])
def test_partial_stale_reordered_or_outside_region_capture_rejects(text):
    with pytest.raises(ValueError): parse(text)


@pytest.mark.parametrize('mutation',['missing-property','wrong-dimension','wrong-binding','wrong-spec','bad-samples'])
def test_contract_cannot_drop_or_rename_model_obligations(mutation):
    raw=contract(DEFAULT)
    if mutation=='missing-property':raw['requiredProperties'].pop()
    if mutation=='wrong-dimension':raw['requiredProperties'][0]['dimension']='performance_trend'
    if mutation=='wrong-binding':raw['propertyBindings'][0]['comparatorId']='timing.v1'
    if mutation=='wrong-spec':raw['spec']['access']='write'
    if mutation=='bad-samples':raw['sampleCount']=1
    with pytest.raises(ValueError):parse_contract(raw)


@pytest.mark.parametrize('text',['nop\n','#APP\nnop\n','#APP\nnop\n#NO_APP\n#APP\nnop\n#NO_APP\n'])
def test_compiler_region_is_not_guessed_without_unique_app_boundary(text):
    with pytest.raises(ValueError):label_assembly(text)


def test_real_native_compiler_labels_are_zero_byte_and_deployed_code_is_identical(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    source=tmp_path/'renamed.c'
    source.write_text('#include <stdint.h>\nuint64_t renamed(const uint64_t *p){uint64_t x;__asm__ volatile("movq 24(%1), %0":"=r"(x):"r"(p):"memory");return x;}\n')
    run([cc,'-O0','-fPIC','-c',source,'-o',tmp_path/'original.o'],tmp_path,'original')
    run([cc,'-O0','-fPIC','-S',source,'-o',tmp_path/'compiler.s'],tmp_path,'assembly')
    marked=tmp_path/'marked.s'; marked.write_text(label_assembly((tmp_path/'compiler.s').read_text()))
    run([cc,'-c',marked,'-o',tmp_path/'marked.o'],tmp_path,'marked')
    assert Elf(tmp_path/'original.o').code('renamed')==Elf(tmp_path/'marked.o').code('renamed')
    scope={'name':'renamed','returnType':'uint64_t','parameterType':'const uint64_t *'}
    wrapper=tmp_path/'harness.c';wrapper.write_text(harness(scope,memory_spec(finding()),4))
    run([cc,'-std=gnu11','-Wall','-Wextra','-Werror','-no-pie',wrapper,tmp_path/'marked.o','-o',tmp_path/'program'],tmp_path,'link')
    final=Elf(tmp_path/'program'); region=final.region('renamed')
    assert final.code('renamed')==Elf(tmp_path/'original.o').code('renamed')
    assert region['start']<region['end']<region['functionStart']+region['functionSize']
    stdout=run([tmp_path/'program',TOKEN],tmp_path,'native').stdout
    objects=parse_objects(stdout,TOKEN,memory_spec(finding()),4)
    expected=[bytes((0x31+17*i+sample)&255 for i in range(24,32))[::-1].hex() for sample in range(4)]
    assert [x['value'] for x in objects]==expected
    # This checks real GCC region deployment, not RISC-V or QEMU acceptance.


def test_command_failure_and_timeout_leave_durable_diagnostics(tmp_path):
    import sys
    with pytest.raises(ValueError,match='COMMAND_FAILED'):
        run([sys.executable,'-c','raise SystemExit(4)'],tmp_path,'failed')
    assert json.loads((tmp_path/'failed.command.json').read_text())['returnCode']==4
    with pytest.raises(ValueError,match='TIMEOUT'):
        run([sys.executable,'-c','import time; time.sleep(2)'],tmp_path,'timeout',0.02)
    assert json.loads((tmp_path/'timeout.command.json').read_text())['timedOut']


@pytest.mark.parametrize('version',['phase6-approval-v1','phase6-approval-v2','phase6-functional-fallback-v1'])
def test_registered_generic_approval_versions_use_producer_fnv_protocol(version):
    from riscv2x86_py.approved_replacement import approved_replacement
    from riscv2x86_py.translate import _approval_digest
    value={'fragment':{'id':'unrelated-location'},'suggestedReplacement':'__asm__ volatile ("nop");',
        'approvalArtifact':{'artifactVersion':version,'sourceFragmentId':'unrelated-location'}}
    value['approvalArtifact']['replacementDigest']=_approval_digest(value['suggestedReplacement'])
    assert approved_replacement(value)==value['suggestedReplacement']
    value['suggestedReplacement']='__asm__ volatile ("different");'
    with pytest.raises(ValueError,match='CANDIDATE_APPROVAL_TEXT_MISMATCH'):approved_replacement(value)


def test_model_geometry_cannot_be_injected_into_legacy_contract():
    from dataclasses import replace
    parsed=parse_contract(contract(DEFAULT))
    with pytest.raises(ValueError):replace(parsed,payload={'schemaVersion':'riscv2x86.microarchitecture-experiment-contract.v1'})


def test_explicit_backend_inventory_uses_normal_translation_and_l3_registry(tmp_path,monkeypatch):
    from riscv2x86_py import automatic_batch_cli as auto
    from riscv2x86_py import l3_qemu_backend
    from riscv2x86_py.l3_intent_ingress import validate_manifest
    source=tmp_path/'renamed.c';source.write_text('unsigned long renamed(const unsigned long *p){return *p;}\n')
    frontend=tmp_path/'frontend';frontend.write_text('fixture not executed');frontend.chmod(0o755)
    backend=tmp_path/'backend.json';backend.write_text('{}')
    monkeypatch.setattr(l3_qemu_backend,'validate_backend',lambda *a:{'backendIdentity':SHA,'sourceExecutor':'/fixture/source','targetExecutor':'/fixture/target'})
    monkeypatch.setattr(auto,'inspect_entry_points',lambda *a:(False,({'name':'renamed','arity':1,
        'returnType':'unsigned long','parameterTypes':['const unsigned long *']},)))
    inventory=tmp_path/'inventory'
    auto.prepare_automatic_inventory(source,inventory,frontend=frontend,l3_memory_backend=backend,
        timeout=240,l3_producer_timeout=600)
    case=inventory/'cases/renamed'
    descriptor=json.loads((case/'riscv2x86-evaluation.json').read_text())['request']
    assert '--l3-intent-producer' in descriptor['translationCommand']
    assert set(descriptor['runtimeRegistryTemplate']['validators'])=={'L0','L1','L2','L3'}
    assert descriptor['runtimeRegistryTemplate']['validators']['L3']['type']=='l3-memory-trace-route'
    metadata=json.loads((inventory/'automatic-inventory.json').read_text())['l3ObservationEnvironment']
    assert metadata['backendIdentity']==SHA and metadata['prerequisiteEnvironmentRecordedSeparately']
    assert not metadata['physicalMicroarchitectureClaimed']
    plan=json.loads((case/'validation-plan.json').read_text());assert plan['profile']=='microarch'
    manifest=json.loads((case/'memory-intent-producer.json').read_text())
    validate_manifest(manifest,source)
    assert manifest['timeoutSeconds']==600
    assert plan['timeoutSeconds']==240


def test_driver_records_preparation_failure_before_any_execution(tmp_path):
    import sys
    root=Path(__file__).resolve().parents[2]
    result=subprocess.run([sys.executable,str(root/'experiment/run_l3_memory_trace.py'),'--input','missing.c',
        '--frontend','missing','--backend',str(tmp_path/'missing.json'),'--output',str(tmp_path/'run')],
        capture_output=True,text=True,check=False)
    assert result.returncode==2
    status=json.loads((tmp_path/'run/run-status.json').read_text())
    assert status['currentStage']=='input_validation' and status['blockers']
    assert not status['productionAcceptanceComplete'] and not status['steps']


def test_independent_executable_image_rebuild_preserves_code_and_data_not_file_metadata(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    images=[]
    for directory in ('one','two'):
        work=tmp_path/directory;work.mkdir()
        source=work/'program.c';source.write_text('#include <stdio.h>\nint main(void){puts("real-image");return 0;}\n')
        run([cc,'-O0','-no-pie','-Wl,--build-id=none',source,'-o',work/'program'],work,'build')
        images.append(Elf(work/'program').execution_image())
    assert images[0]==images[1]
    path=tmp_path/'two/program';data=path.read_bytes();assert b'real-image' in data
    path.write_bytes(data.replace(b'real-image',b'FAKE-image',1))
    assert Elf(path).execution_image()!=images[0]


def test_rehashed_contract_cannot_switch_the_selected_cache_geometry():
    from riscv2x86_py.l3_qemu_memory_route import validate_profile_scope
    from riscv2x86_py.l3_intent_requirements import parse_l3_intent_profile
    profile,_,f=intent(DEFAULT)
    validate_profile_scope(parse_l3_intent_profile(profile),memory_spec(f),DEFAULT)
    with pytest.raises(ValueError,match='REGISTERED_INTENT_SCOPE_MISMATCH'):
        validate_profile_scope(parse_l3_intent_profile(profile),memory_spec(f),dict(DEFAULT,lineBytes=128))
