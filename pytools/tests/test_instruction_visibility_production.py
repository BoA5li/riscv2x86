"""Protocol/approval tests. Real ISA-runner tests require production tools."""
from dataclasses import replace, asdict
from copy import deepcopy
from types import SimpleNamespace as NS
import json
import pytest
from riscv2x86_py.semantic_content import semantic_identity
from riscv2x86_py.instruction_stream_domain import SCHEMA,validate_domain


def domain():
    payload={'schemaVersion':SCHEMA,'sourceDigest':'sha256:'+'1'*64,
        'fragmentId':'fragment:fence-i','targetEnvironmentId':'phase6:x86','targetCpuProfileId':'cpu:x86-64-v1',
        'sourceExecution':{'runnerIdentity':'sha256:'+'2'*64,'logicalHartIdentity':'logical-hart:0','pinnedCpu':0,'threadCount':1},
        'targetExecution':{'runnerIdentity':'sha256:'+'3'*64,'logicalHartIdentity':'logical-hart:0','pinnedCpu':0,'threadCount':1},
        'memoryDomain':{'kind':'ordinary_cacheable_coherent_memory','targetProtocol':'x86-local-serializing-smc-v1',
                        'buildContract':'automatic-gcc-separate-tu-no-lto-v1'},
        'coverage':'all_prior_visible_instruction_stores_on_bound_hart'}
    return {**payload,'domainIdentity':semantic_identity(payload)}


def approval_fixture():
    from tests.test_instruction_stream_sync_contracts import _contract
    from riscv2x86_py.instruction_stream_sync_contracts import prove_instruction_stream_sync
    from riscv2x86_py.l2_instruction_stream import close_instruction_stream_approval
    from riscv2x86_py.schema import AsmFragment
    contract=replace(_contract(),domain_authority=domain())
    proof=prove_instruction_stream_sync(contract)
    assert proof.approved
    fragment=AsmFragment(id='fragment:fence-i',isVolatile=True,clobbers=['memory'])
    base={'proofStatus':'approved','sourceFragmentId':fragment.id,'preservationMode':'architecture_equivalent',
        'planId':'phase6b:runtime_helper','constraintsId':'phase6c:'+contract.semantic_contract_id,
        'targetEnvironmentId':'phase6:x86','targetCpuProfileId':'cpu:x86-64-v1',
        'runtimeContractId':contract.runtime_adapter_identity,'runtimeContractVersion':contract.semantic_version,
        'requiredHeaders':[contract.required_header],'requiredLibraries':[contract.runtime_library],
        'requiredScope':'local_hart'}
    return fragment,*close_instruction_stream_approval(base,proof,fragment,bytes.fromhex('0f100000'),
        'automatic-gcc-separate-tu-no-lto-v1')


def test_instruction_visibility_approval_closes_phase7_and_runtime_authority():
    from riscv2x86_py.l2_instruction_stream import validate_instruction_stream_approval
    from riscv2x86_py.automatic_l2_authority import _instruction_stream_authority
    from riscv2x86_py.pipeline import phase7_gate_inline_asm
    fragment,approval,text=approval_fixture()
    assert validate_instruction_stream_approval(approval,fragment,text,source_digest='sha256:'+'1'*64)
    assert phase7_gate_inline_asm(fragment,NS(kind='runtime_c',replacement=text,metadata={'approvalArtifact':approval}))==[]
    finding={'fragment':asdict(fragment),'approvalArtifact':approval,'sourceDigest':'sha256:'+'1'*64,
             'machineCodeHex':'0f100000','suggestedReplacement':text}
    sidecar=_instruction_stream_authority(finding,(), 'sha256:'+'4'*64)
    assert sidecar.complete and not sidecar.operands and sidecar.runtime_contracts
    finding['machineCodeHex']='13000000'
    assert _instruction_stream_authority(finding,(), 'sha256:'+'4'*64) is None


@pytest.mark.parametrize('mutation',['source','scope','memory','cpu','hart'])
def test_domain_rejects_rehashed_unsupported_assumptions(mutation):
    value=domain()
    if mutation=='source':value['sourceDigest']=''
    if mutation=='scope':value['coverage']='one_arbitrary_object'
    if mutation=='memory':value['memoryDomain']['kind']='mmio'
    if mutation=='cpu':value['targetExecution']['pinnedCpu']=True
    if mutation=='hart':value['targetExecution']['logicalHartIdentity']='different'
    value['domainIdentity']=semantic_identity({k:v for k,v in value.items() if k!='domainIdentity'})
    with pytest.raises(ValueError):
        validate_domain(value,fragment_id='fragment:fence-i',environment_id='phase6:x86',cpu_profile='cpu:x86-64-v1')


@pytest.mark.parametrize('field',['proofIdentity','runtimeContractId','replacementDigest','l2EffectProofFacts','runtimeShellProof'])
def test_instruction_approval_mutations_are_rejected(field):
    from riscv2x86_py.l2_instruction_stream import validate_instruction_stream_approval
    fragment,approval,text=approval_fixture();approval=deepcopy(approval)
    if field=='l2EffectProofFacts':approval[field]['relations'][0]['preservedProperties']=[]
    elif field=='runtimeShellProof':approval[field]['clobbers']=[]
    else:approval[field]='invalid'
    with pytest.raises((ValueError,TypeError,KeyError)):
        validate_instruction_stream_approval(approval,fragment,text)


def trace(side,request,values=(1,7),observed=None):
    events=[]
    for i,value in enumerate(values):
        code=((value<<20)|0x513).to_bytes(4,'little').hex()+'67800000' if side=='source' else 'b8'+value.to_bytes(4,'little').hex()+'c3'
        record={'executedCall':i+1,'site':'fragment:fence-i'}
        events.extend([{'eventIndex':len(events),'kind':'code_write','objectIdentity':'code-object','codeHex':code},
            {'eventIndex':len(events)+1,'kind':'synchronize','fragmentId':'fragment:fence-i',
             'traceRecord':{'origin':'execution_trace','executionSiteIdentity':'site:fragment',
                'recordPayload':record,'recordIdentity':semantic_identity(record)}},
            {'eventIndex':len(events)+2,'kind':'instruction_fetch','objectIdentity':'code-object',
             'observedValue':value if observed is None else observed}])
    return {'schemaVersion':'riscv2x86.instruction-visibility-observation.v1','fragmentId':'fragment:fence-i',
        'executionIdentity':request['executionIdentity'],'executionPlanIdentity':request['executionPlanIdentity'],
        'side':side,'programDigest':request[side+'Program']['digest'],
        'executionContext':domain()[side+'Execution'],'events':events,'termination':'normal'}


def request():
    return {'fragmentId':'fragment:fence-i','executionIdentity':'sha256:'+'5'*64,
        'executionPlanIdentity':'sha256:'+'6'*64,'sourceProgram':{'digest':'sha256:'+'7'*64},
        'targetProgram':{'digest':'sha256:'+'8'*64}}


def test_observation_checks_actual_fetch_result_instead_of_predicting_it():
    from riscv2x86_py.l2_instruction_visibility_runner import validate_observation
    r=request()
    source,valid=validate_observation(trace('source',r),r,'source',domain())
    target,target_valid=validate_observation(trace('target',r),r,'target',domain())
    assert valid and target_valid and source==target
    stale,valid=validate_observation(trace('target',r,observed=1),r,'target',domain())
    assert not valid and stale!=source


@pytest.mark.parametrize('mutation',['execution','context','no_trace','same_version','order'])
def test_runtime_observation_contract_mutations(mutation):
    from riscv2x86_py.l2_instruction_visibility_runner import validate_observation
    r=request();value=trace('target',r)
    if mutation=='execution':value['executionIdentity']='other'
    if mutation=='context':value['executionContext']['threadCount']=2
    if mutation=='no_trace':value['events'][1]['traceRecord']['origin']='predicted'
    if mutation=='same_version':value=trace('target',r,values=(1,1))
    if mutation=='order':value['events'][0],value['events'][1]=value['events'][1],value['events'][0]
    with pytest.raises(ValueError): validate_observation(value,r,'target',domain())


def test_real_renderer_entry_produces_replayable_v3_artifact():
    from tests.test_instruction_stream_sync_contracts import _contract
    from riscv2x86_py.instruction_stream_sync_contracts import InstructionStreamSyncRegistry,instruction_stream_environment_id
    from riscv2x86_py.translate import _render_instruction_stream_sync
    from riscv2x86_py.phase6c_constraints import FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT
    from riscv2x86_py.schema import AsmFragment
    environment=FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT
    d=domain(); d['targetEnvironmentId']=instruction_stream_environment_id(environment)
    d['targetCpuProfileId']=environment.target_cpu_profile_id
    d['domainIdentity']=semantic_identity({k:v for k,v in d.items() if k!='domainIdentity'})
    contract=replace(_contract(),domain_authority=d,target_environment_id=d['targetEnvironmentId'],target_cpu_profile_id=d['targetCpuProfileId'])
    registry=InstructionStreamSyncRegistry(version='test-v3',source_digest=d['sourceDigest'],contracts=(contract,),schema_version='riscv2x86.instruction-stream-sync-registry.v3')
    fragment=AsmFragment(id='fragment:fence-i',isVolatile=True,clobbers=['memory'])
    context=NS(fragment=fragment,decision=None,xlen=64,instruction_count=1,blocks=[],sourceModel=None)
    result,reason=_render_instruction_stream_sync(context=context,target_environment=environment,registry=registry,
        machine_code=bytes.fromhex('0f100000'),target_build_contract='automatic-gcc-separate-tu-no-lto-v1')
    assert result is not None, reason
    artifact=result.metadata['approvalArtifact']
    assert artifact['artifactVersion']=='phase6-instruction-stream-sync-v3'
    assert artifact['l2EffectProofFacts']['relations'][0]['runtimeContractId']==contract.runtime_adapter_identity
    assert result.replacement.count(contract.helper_symbol+'();')==1


def test_v3_domain_is_explicit_and_not_silently_accepted_as_v2():
    import re
    from tests.test_instruction_stream_sync_contracts import _contract
    from riscv2x86_py.semantic_content import semantic_payload
    from riscv2x86_py.instruction_stream_sync_contracts import instruction_stream_sync_registry_from_dict
    def camel(value):
        if isinstance(value,dict):
            return {re.sub(r'_([a-z])',lambda m:m.group(1).upper(),k):camel(v) for k,v in value.items()}
        if isinstance(value,list):return [camel(x) for x in value]
        return value
    contract=replace(_contract(),domain_authority=domain())
    raw={'schemaVersion':'riscv2x86.instruction-stream-sync-registry.v3','version':'test-v3',
        'sourceDigest':domain()['sourceDigest'],'contracts':[camel(semantic_payload(contract))]}
    registry=instruction_stream_sync_registry_from_dict(raw)
    assert registry.schema_version==raw['schemaVersion']
    assert registry.resolve('fragment:fence-i','phase6:x86').domain_authority['coverage']==domain()['coverage']
    raw['schemaVersion']='riscv2x86.instruction-stream-sync-registry.v2'
    with pytest.raises(ValueError):instruction_stream_sync_registry_from_dict(raw)


def test_domain_snapshot_cannot_be_mutated_after_contract_creation():
    from tests.test_instruction_stream_sync_contracts import _contract
    d=domain();contract=replace(_contract(),domain_authority=d)
    d['targetExecution']['pinnedCpu']=23
    assert contract.domain_authority['targetExecution']['pinnedCpu']==0
    with pytest.raises(TypeError):contract.domain_authority['targetExecution']['pinnedCpu']=23


@pytest.mark.parametrize('stale_side',[None,'source','target'])
def test_provider_protocol_execution_identity_and_audit_with_mocked_executors(tmp_path,monkeypatch,stale_side):
    """Tests execution/reader contracts, not real source/target ISA execution."""
    import os,sys,subprocess
    from pathlib import Path
    from tests.test_instruction_stream_sync_contracts import _contract
    from riscv2x86_py.l2_instruction_stream import close_instruction_stream_approval
    from riscv2x86_py.instruction_stream_sync_contracts import prove_instruction_stream_sync
    from riscv2x86_py.l2_instruction_visibility_runner import run,runner_identity,validate_persisted_result
    from riscv2x86_py.l2_explicit_harness import ExplicitL2HarnessRunnerConfig,_file_digest
    from riscv2x86_py.automatic_l2_authority import _instruction_stream_authority
    from riscv2x86_py.schema import AsmFragment
    from riscv2x86_py.validation_status import ValidationStatus
    source_script=tmp_path/'source.py';source_script.write_text('# explicit mocked source observer\n')
    target_script=tmp_path/'target.py';target_script.write_text('# explicit mocked target observer\n')
    commands={'source':(sys.executable,str(source_script)),'target':(sys.executable,str(target_script))}
    d=domain();cpu=min(os.sched_getaffinity(0))
    for side,path in (('source',source_script),('target',target_script)):
        d[side+'Execution']['runnerIdentity']=runner_identity(commands[side],_file_digest(path))
        d[side+'Execution']['pinnedCpu']=cpu
    d['domainIdentity']=semantic_identity({k:v for k,v in d.items() if k!='domainIdentity'})
    contract=replace(_contract(),domain_authority=d);proof=prove_instruction_stream_sync(contract)
    fragment,base,_=approval_fixture()
    approval,text=close_instruction_stream_approval(base,proof,fragment,bytes.fromhex('0f100000'),
        'automatic-gcc-separate-tu-no-lto-v1')
    finding={'fragment':asdict(fragment),'approvalArtifact':approval,'sourceDigest':d['sourceDigest'],
        'machineCodeHex':'0f100000','suggestedReplacement':text}
    sidecar=_instruction_stream_authority(finding,(), 'sha256:'+'4'*64)
    artifact=NS(fragment_id=fragment.id,proof_identity=approval['proofIdentity'],l2_authority_complete=True,
        l2_authority_identity=sidecar.authority_identity,effect_relation_set_identity=sidecar.effect_relation_set_identity,
        l2_semantic_profile_identity='sha256:'+'9'*64,target_route='local-iss',renderer_semantic_contract_id='local-iss-v1',
        runtime_contract_id=contract.runtime_adapter_identity,runtime_contract_version=contract.semantic_version)
    raw={'schemaVersion':'riscv2x86.explicit-l2-harness-manifest.v1','harnessId':'test-harness','harnessVersion':'v1',
        'producerDigest':'sha256:'+'a'*64,'supportedFragmentIdentities':[fragment.id],'supportedSemanticProfiles':[],
        'contractId':'test-contract','providedDimensions':['memory_effects','shell_semantics'],'executionProfile':'test-profile',
        'sourceHarnessDigest':_file_digest(source_script),'targetHarnessDigest':_file_digest(target_script),
        'observationSchemaVersion':'riscv2x86.instruction-visibility-observation.v1',
        'relationSetIdentity':sidecar.effect_relation_set_identity,'nonInterferenceProofIdentity':'sha256:'+'b'*64,'complete':True}
    raw['manifestIdentity']=semantic_identity(raw)
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps(raw))
    report=tmp_path/'report.json';report.write_text(json.dumps({'findings':[finding]}))
    config=ExplicitL2HarnessRunnerConfig(str(manifest),str(source_script),str(target_script),
        commands['source'],commands['target'],'test-contract',10)
    programs={}
    for side in ('source','target'):
        path=tmp_path/(side+'.object');path.write_bytes(side.encode())
        programs[side+'_program_artifact']=NS(artifact_path=str(path),artifact_digest=_file_digest(path),build_identity='sha256:'+'c'*64)
    captured=[]
    def execute(command,**kwargs):
        r=json.loads(kwargs['input']);captured.append((command,r))
        value=trace(r['side'],r,observed=1 if r['side']==stale_side else None)
        value['executionContext']=d[r['side']+'Execution']
        return NS(returncode=0,stdout=json.dumps(value),stderr='')
    monkeypatch.setattr(subprocess,'run',execute)
    result=run(config,str(report),translation_artifact=artifact,l2_provider_id='instruction-observer',
        target_environment=NS(target_isa='x86_64',source_isa='rv64gc'),**programs)
    expected=ValidationStatus.VERIFIED if stale_side is None else ValidationStatus.FAILED if stale_side=='target' else ValidationStatus.INCONCLUSIVE
    assert result.status is expected,result.detail
    detail=json.loads(result.detail)
    assert len(captured)==2 and all('--cpu-list' in c for c,_ in captured)
    assert captured[0][1]['executionIdentity']==captured[1][1]['executionIdentity']==detail['executionIdentity']
    validate_persisted_result(detail)
    detail['observations']['target']['events'][-1]['observedValue']=123
    with pytest.raises(ValueError):validate_persisted_result(detail)


def test_native_registered_helper_observes_two_actual_code_versions(tmp_path):
    """Real x86 SMC probe; deliberately not labelled RISC-V equivalence."""
    import os,platform,shutil,subprocess
    from pathlib import Path
    if platform.machine() not in ('x86_64','amd64'):pytest.skip('requires x86-64')
    gcc=shutil.which('gcc');taskset=shutil.which('taskset')
    if not gcc or not taskset or not hasattr(os,'sched_getaffinity'):pytest.skip('requires native probe tools')
    _,_,statement=approval_fixture()
    source=tmp_path/'probe.c'
    source.write_text('#define _GNU_SOURCE\n#include <stdint.h>\n#include <stdio.h>\n#include <sys/mman.h>\n'
        '#include "riscv2x86_runtime_helpers.h"\n'
        'static void sync_probe(void) { '+statement+' }\n'
        'int main(void) { unsigned char *p=mmap(0,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);\n'
        'if (p==MAP_FAILED) return 77;\n'
        'uint32_t (*call)(void)=(uint32_t (*)(void))(void *)p;\n'
        'uint32_t versions[2]={1,7};\n'
        'for(unsigned int i=0;i<2;i++){ p[0]=0xb8;p[1]=(unsigned char)versions[i];p[2]=0;p[3]=0;p[4]=0;p[5]=0xc3;\n'
        'sync_probe();uint32_t observed=call();printf("%u\\n",observed);if(observed!=versions[i])return 1;}\n'
        'return munmap(p,4096)!=0;}\n')
    root=Path(__file__).resolve().parents[2];binary=tmp_path/'probe'
    result=subprocess.run([gcc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fno-lto',
        '-I'+str(root/'runtime/include'),str(source),str(root/'runtime/riscv2x86_runtime_helpers.c'),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    result=subprocess.run([taskset,'--cpu-list',str(min(os.sched_getaffinity(0))),str(binary)],capture_output=True,text=True)
    if result.returncode==77:pytest.skip('environment does not permit executable code allocation')
    assert result.returncode==0,result.stderr
    assert result.stdout.splitlines()==['1','7']
