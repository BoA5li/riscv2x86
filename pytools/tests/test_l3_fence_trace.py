"""Fence semantics, real native bytes, protocol, lifecycle and audit consumption.

Synthetic proof/driver fixtures test consumers only; they are not production
QEMU calibration or hardware ordering evidence.
"""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py.l3_trace_support import identity,digest,Elf
from riscv2x86_py.l3_fence_machine import mechanism,region_mechanism
from riscv2x86_py.l3_fence_spec import samples,harness,parse_samples,spec
from riscv2x86_py.l3_fence_compare import report,comparison


def fixture(tmp_path):
    from tests.test_l2_fence_ordering_relations import _facts,_finding
    from riscv2x86_py.l2_effect_proof import effect_proof_facts_from_dict
    from riscv2x86_py.automatic_l2_authority import _fence_authority
    facts=_facts(source_hardware_ordering=True,source_ordering='rw_rw',source_scope='system',
                 target_ordering='rw_rw',relation_kind='exact',target_semantic_contract_id='x86.gnu-att.mfence.ordinary-rw.v2')
    f=_finding(facts);a=f['approvalArtifact'];f['sourceDigest']=identity('source')
    proof=effect_proof_facts_from_dict(a['l2EffectProofFacts'])
    proof=replace(proof,source_effects=tuple(sorted(proof.source_effects,key=lambda e:e.effect_id)),
                  target_effects=tuple(sorted(proof.target_effects,key=lambda e:e.effect_id)),
                  relations=tuple(sorted((replace(r,relation_kind='exact') for r in proof.relations),key=lambda r:r.relation_id)))
    a['l2EffectProofFacts']=proof.to_dict()
    function={'name':'synchronize_domain','functionId':identity('function'),'sourceDigest':f['sourceDigest'],
              'arity':0,'parameterTypes':[],'returnType':'void'}
    scope={'schemaVersion':'riscv2x86.compiler-atomic-function-scope.v1','sourceDigest':f['sourceDigest'],
           'functionIdentity':function['functionId'],'asmBegin':10,'asmEnd':20,'scope':'single_asm_no_other_memory_or_control_effects'}
    function['compilerAtomicFunctionScope']=dict(scope,scopeIdentity=identity(scope))
    f['fragment']['compilerFragmentAuthority']={'fragmentId':f['fragment']['id'],'sourceDigest':f['sourceDigest'],'functionIdentity':function['functionId']}
    sidecar=_fence_authority(f,[function],identity('frontend'))
    assert sidecar is not None
    a['l2AuthoritySidecar']=sidecar.to_dict()
    a['l2FragmentOperandBoundary']={'fragmentId':f['fragment']['id'],'programId':identity('program'),'complete':True}
    return f,[function]


@pytest.mark.parametrize('code,machine,kind',[
    ('0f003003',243,'ordinary-rw-fence'),('0f001002',243,'partial-or-io-fence'),
    ('13000000',243,'nop'),('0100',243,'nop'),('0faef0',62,'ordinary-rw-fence'),
    ('0faee8',62,'partial-fence'),('0faef8',62,'partial-fence'),('90',62,'nop'),
    ('0f003083',243,'other'),('0f003013',243,'other'),('f00faef0',62,'other'),
])
def test_binary_mechanism_classification(code,machine,kind):
    decoded=mechanism(bytes.fromhex(code),machine)
    assert decoded['kind']==kind and decoded['globalSequentialConsistencyClaimed'] is False


def test_spec_replays_existing_fence_authority(tmp_path):
    f,functions=fixture(tmp_path);value=spec(f,functions)
    assert value['kind']=='memory-fence'
    assert value['obligations']['synchronizationObligations']['basisComplete']
    from riscv2x86_py.l3_execution_plan import build
    assert build([f],functions,{'fence'})['complete']
    assert not build([f],functions,{'memory','control','scalar-program'})['complete']


@pytest.mark.parametrize('mutation',['source','function','scope','signature','contract','relation','anchor'])
def test_spec_refuses_incomplete_or_changed_authority(tmp_path,mutation):
    f,functions=fixture(tmp_path);a=f['approvalArtifact']
    if mutation=='source':f['sourceDigest']=identity('other')
    if mutation=='function':functions[0]['functionId']=identity('other')
    if mutation=='scope':functions[0]['compilerAtomicFunctionScope']['scope']='unbounded'
    if mutation=='signature':functions[0]['parameterTypes']=['uint64_t']
    if mutation=='contract':a['rendererSemanticContractId']='unreviewed'
    if mutation=='relation':a['l2FenceProofFacts']['relationKind']='strengthened'
    if mutation=='anchor':a['l2FenceProofFacts']['effectRoles']['before:read']='source-operation'
    with pytest.raises((ValueError,KeyError)):spec(f,functions)


def test_native_deployment_keeps_function_and_observes_only_app_bytes(tmp_path):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native compiler unavailable')
    from riscv2x86_py.l3_fence_deployment import build_side
    source=tmp_path/'unrelated.c';source.write_text('void unrelated(void){__asm__ volatile("mfence":::"memory");}')
    obj=tmp_path/'reference.o'
    subprocess.run([gcc,'-O0','-std=gnu11','-fno-lto','-fPIC','-c',source,'-o',obj],check=True,capture_output=True)
    artifact=SimpleNamespace(artifact_id='target',artifact_path=str(obj),artifact_digest=digest(obj),build_identity=identity('build'))
    plan=samples(None);function={'name':'unrelated'}
    result=build_side(source,'target',plan,function,{'targetCompiler':gcc},artifact,tmp_path/'deployed')
    elf=Elf(result['executionArtifact']['artifactPath'])
    assert result['machineMechanism']['kind']=='ordinary-rw-fence'
    assert result['region']['end']-result['region']['start']==3
    assert elf.code('unrelated')==Elf(obj).code('unrelated')
    token='a'*64
    run=subprocess.run([result['executionArtifact']['artifactPath'],token],capture_output=True,text=True,check=True)
    assert len(parse_samples(run.stdout,token,plan))==3


def reports(tmp_path):
    f,functions=fixture(tmp_path);value=spec(f,functions);plan=samples(value)
    tool=tmp_path/'tool';tool.write_text('test executor')
    backend={s+'Executor':str(tool) for s in ('source','target')}
    backend.update(backendIdentity=identity('backend'),sourceRunnerArguments=[],targetRunnerArguments=[])
    deployment={'spec':value,'samplePlan':plan,'deploymentIdentity':identity('deployment'),'sides':{}}
    result={}
    for side,machine,code in (('source',243,'0f003003'),('target',62,'0faef0')):
        reg={'start':0x1000,'end':0x1000+len(bytes.fromhex(code)),'exits':[0x1000+len(bytes.fromhex(code))]}
        deployment['sides'][side]={'region':reg,'machineMechanism':mechanism(bytes.fromhex(code),machine)}
        observed={'paths':[{'pcs':[reg['start']],'exit':reg['end']} for _ in plan['inputs']],'memory':[]}
        rows=[{'sample':i,'token':'a'*64,'completed':True} for i in range(3)]
        result[side]=report(side,backend,deployment,observed,rows,{})
    return result,value,deployment,backend


def test_real_event_roles_and_static_contract_are_not_conflated(tmp_path):
    r,value,_,_=reports(tmp_path);cmp=comparison(r,value)
    assert cmp['memory']['status']==cmp['synchronization']['status']=='verified'
    assert cmp['synchronization']['physicalMemoryOrderMeasured'] is False
    assert cmp['synchronization']['subpropertyResults']['sync.ordering-contract']['verificationMethod']=='static-approved-contract'
    assert r['source']['memory']==[]
    assert len(r['source']['fenceEvents'])==3


@pytest.mark.parametrize('mutation',['missing','partial','memory','incomplete','contract'])
def test_comparison_rejects_supported_counterexamples(tmp_path,mutation):
    r,value,dep,backend=reports(tmp_path)
    if mutation in ('missing','partial'):
        m=mechanism(bytes.fromhex('90' if mutation=='missing' else '0faee8'),62)
        r['target']['mechanism']=m
        for e in r['target']['fenceEvents']:e.update(kind=m['kind'],mechanismIdentity=m['mechanismIdentity'])
    if mutation=='memory':r['target']['memory']=[{'access':'write','address':0x2000}]
    if mutation=='incomplete':r['target']['fenceEvents'][0]['completed']=False
    if mutation=='contract':value['obligations']['synchronizationObligations']['basis']['targetOrderingContract']['hardwareOrdering']=False
    cmp=comparison(r,value)
    assert any(x['status']=='failed' for x in cmp.values())


@pytest.mark.parametrize('mutation',['missing','extra','wrong-token','not-completed','duplicate'])
def test_completion_protocol_is_not_inferred_from_empty_output(mutation):
    plan=samples(None);token='a'*64
    rows=[{'sample':i,'token':token,'completed':True} for i in range(3)]
    if mutation=='missing':rows.pop()
    if mutation=='extra':rows.append(rows[0])
    if mutation=='wrong-token':rows[0]['token']='b'*64
    if mutation=='not-completed':rows[0]['completed']=False
    if mutation=='duplicate':rows[1]['sample']=0
    with pytest.raises(ValueError):parse_samples('\n'.join(json.dumps(x) for x in rows),token,plan)


def test_manifest_and_selection_dependency_sets_include_real_route():
    from riscv2x86_py.l3_fence_intent import DEPENDENCIES
    from riscv2x86_py.l3_fence_backend import DEPENDENCIES as bd
    root=Path(__file__).resolve().parents[1]/'riscv2x86_py'
    assert all((root/name).is_file() for name in (*DEPENDENCIES,*bd))
    from riscv2x86_py.l3_fence_route import build_route
    assert callable(build_route)


@pytest.fixture
def calibration_tools(tmp_path,monkeypatch):
    """Fake external tools test lifecycle; do not substitute for real probes."""
    from riscv2x86_py import l3_fence_backend as b
    control_path=tmp_path/'control.json';control_path.write_text('{}')
    base={k:[] if k.endswith('Arguments') else '/fake/tool' for k in b.control.TOOLS}
    monkeypatch.setattr(b.control,'validate',lambda _:base)
    def reg(_):return {'start':0x1000,'end':0x1004,'exits':[0x1004]}
    # Calibration replay reopens all records, so bind kind by each binary path.
    class FakeElf:
        def __init__(self,path):self.path=Path(path);self.machine=243 if 'source' in self.path.parts else 62
    def mech(elf,region):
        kind=elf.path.parent.name
        return {'kind':{'full':'ordinary-rw-fence','missing':'nop','partial':'partial-or-io-fence' if elf.machine==243 else 'partial-fence'}[kind]}
    monkeypatch.setattr(b,'Elf',FakeElf);monkeypatch.setattr(b,'region',reg);monkeypatch.setattr(b,'region_mechanism',mech)
    def command(value,side,binary,region,trace,token):return ['/fake/executor',str(binary),token]
    monkeypatch.setattr(b,'command',command)
    def run(cmd,work,tag):
        Path(cmd[-1]).write_text('test-binary')
        from riscv2x86_py.l3_trace_support import save
        save(Path(work)/(tag+'.command.json'),{'command':list(map(str,cmd)),'returnCode':0,'timedOut':False})
    monkeypatch.setattr(b,'run',run)
    def capture(value,side,binary,region,directory,calls,timeout):
        directory=Path(directory);directory.mkdir();trace=directory/'guest-trace.log';token='a'*64
        target='riscv64' if side=='source' else 'x86_64'
        trace.write_text('H 2 '+token+' '+target+' 1000 1004\nB 0 1000\nP 0 0 1000\nX 0 1004\nF 1 1 1 0 0\n')
        from riscv2x86_py.l3_trace_support import save
        cp=directory/'execute.command.json';save(cp,{'command':command(value,side,binary,region,trace,token),'returnCode':0,'timedOut':False,'stdout':'','stderr':''})
        return {},'',{'token':token,'rawTracePath':str(trace),'rawTraceDigest':digest(trace),'commandRecordDigest':digest(cp)}
    monkeypatch.setattr(b.control,'capture',capture)
    return b,control_path,tmp_path/'output'


def test_backend_preparation_replays_all_six_probes_and_mutation(calibration_tools):
    b,base,out=calibration_tools
    value=b.prepare(base,out);assert b.validate(out/'backend.json')==value
    state=json.loads((out/'build-status.json').read_text())
    assert state['complete'] and len(state['calibrationCompleted'])==6
    assert state['semanticApproval'] is False
    raw=Path(value['calibration'][0]['evidence']['rawTracePath']);raw.write_text('missing')
    with pytest.raises(ValueError):b.validate(value)


@pytest.mark.parametrize('side,kind',[(s,k) for s in ('source','target') for k in ('full','partial','missing')])
def test_any_calibration_failure_prevents_publication(calibration_tools,monkeypatch,side,kind):
    b,base,out=calibration_tools;original=b.check_calibration
    def check(value,record):
        if (record['side'],record['kind'])==(side,kind):raise ValueError('injected calibration mismatch')
        original(value,record)
    monkeypatch.setattr(b,'check_calibration',check)
    with pytest.raises(ValueError):b.prepare(base,out)
    assert not (out/'backend.json').exists()
    state=json.loads((out/'build-status.json').read_text())
    assert not state['complete'] and state['calibrationCurrent']=={'side':side,'kind':kind}


@pytest.mark.parametrize('mutation',[None,'context','result','status','evidence','prior','requirement'])
def test_independent_audit_consumer_recomputes_closure(tmp_path,monkeypatch,mutation):
    # Replay boundary is mocked here; this tests the audit consumer, not QEMU.
    from dataclasses import asdict
    from riscv2x86_py import l3_fence_route as route
    from riscv2x86_py.l3_fence_intent import produce
    from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
    from riscv2x86_py.l3_execution_context import L3ExecutionContext
    from tests.test_l3_scalar_trace import request
    from tests.test_l3_production_ingress import program
    from tests.test_translation_validation import _translation
    f,functions=fixture(tmp_path);request_body=request(f)
    request_body['candidates'][0]['compilerFunctions']=functions
    request_body['requestIdentity']=identity({k:v for k,v in request_body.items() if k!='requestIdentity'})
    f['l3IntentProfile']=produce(request_body)['profiles'][0]
    manifest=classify_l3_requirements({'findings':[f]});req=manifest.requirements[0]
    assert req['eligibilityStatus']=='eligible'
    source,target=program(tmp_path,'source'),program(tmp_path,'target')
    artifact=replace(_translation(),fragment_id=req['fragmentId'],proof_identity=req['proofIdentity'],effect_relation_set_identity=req['approvedTargetRelationIdentity'])
    observed,value,deployment,_=reports(tmp_path)
    contract={'requirement':req,'deployment':deployment,'contractIdentity':identity('contract')}
    context=L3ExecutionContext.create(source,target);bindings={side:context.request_binding(side) for side in ('source','target')}
    prior=[SimpleNamespace(evidence_identity=identity(str(i))) for i in range(3)]
    fragment,cmp=route.dimensions(contract,observed,bindings,artifact,source,target,prior,'architectural')
    detail={'platformReports':observed,'executionBindings':bindings,'fragmentResult':fragment,'comparison':cmp,
            'propertyObligations':value['obligations'],'physicalMicroarchitectureClaimed':False,'reasonCodes':[]}
    layers=[{'level':level,'status':'verified','evidenceIdentity':prior[i].evidence_identity,'detail':json.dumps({'claimScope':'architectural'})}
            for i,level in enumerate(('L0','L1','L2'))]
    layers.append({'level':'L3','status':'verified','evidenceIdentity':identity(detail),'detail':json.dumps(detail)})
    raw=dict(asdict(artifact),preservation_mode=artifact.preservation_mode.value,ignored_source_state=list(artifact.ignored_source_state))
    evaluation={'status':'verified','sourceProgramArtifact':asdict(source),'targetProgramArtifact':asdict(target),
                'translationEvaluationLink':{'l3Requirements':manifest.to_dict()},
                'attempts':[{'translationArtifact':raw,'status':'verified','validation':{'status':'verified','layers':layers}}]}
    monkeypatch.setattr(route,'replay',lambda *args:contract)
    assert route.audit_result(evaluation)['productionAcceptanceComplete']
    if mutation is None:return
    if mutation=='context':detail['executionBindings']['source']['contextIdentity']=identity('wrong')
    if mutation=='result':detail['fragmentResult']['dimensionResults']={}
    if mutation=='status':layers[3]['status']='not_run'
    if mutation=='evidence':layers[3]['evidenceIdentity']=identity('wrong')
    if mutation=='prior':layers[1]['evidenceIdentity']=identity('wrong')
    if mutation=='requirement':evaluation['translationEvaluationLink']['l3Requirements']['requirements'][0]['requiredProperties'].pop()
    layers[3]['detail']=json.dumps(detail)
    if mutation!='evidence':layers[3]['evidenceIdentity']=identity(detail)
    with pytest.raises((ValueError,KeyError)):route.audit_result(evaluation)


def test_driver_preserves_primary_configuration_failure(tmp_path,monkeypatch,capsys):
    from riscv2x86_py import l3_fence_backend
    path=Path(__file__).resolve().parents[2]/'experiment/run_l3_fence_trace.py'
    loader=importlib.util.spec_from_file_location('fence_driver',path);module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    tool=tmp_path/'tool';tool.write_text('tool');out=tmp_path/'run'
    monkeypatch.setattr(l3_fence_backend,'validate',lambda _: {})
    def run(cmd,stdout,**kwargs):
        stdout.write('configuration rejected: compiler prerequisite missing\n');stdout.flush()
        return SimpleNamespace(returncode=2)
    monkeypatch.setattr(module.subprocess,'run',run)
    monkeypatch.setattr(sys,'argv',[str(path),'--input',str(tool),'--frontend',str(tool),'--backend',str(tool),'--output',str(out)])
    assert module.main()==2
    status=json.loads((out/'run-status.json').read_text())
    assert status['currentStage']=='normal_production'
    assert not status['productionAcceptanceComplete']
    assert 'compiler prerequisite missing' in status['normalProductionLogTail']
    assert status['steps'][0]['returnCode']==2
