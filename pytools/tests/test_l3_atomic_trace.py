"""Direct atomic route checks; fixture proof/PC data are not production evidence."""
from copy import deepcopy
from dataclasses import replace,asdict
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py.l3_trace_support import Elf,identity,digest
from riscv2x86_py.l3_atomic_machine import atomic_instruction,decode,function_mechanism,satisfies
from riscv2x86_py.l3_atomic_spec import spec,samples,harness,parse_samples


def rv(op='fetch_add',width=64,order='relaxed',rd=12):
    aq=order in ('acquire','acq_rel');rl=order in ('release','acq_rel')
    word=({'fetch_add':0,'exchange':1,'fetch_xor':4,'fetch_or':8,'fetch_and':12}[op]<<27)|(aq<<26)|(rl<<25)|(11<<20)|(10<<15)|((3 if width==64 else 2)<<12)|(rd<<7)|0x2f
    return word.to_bytes(4,'little')


def fixture(tmp_path,operation="fetch_add"):
    from tests.test_l3_atomic_eligibility import atomic_fixture
    f,functions=atomic_fixture(tmp_path,operation=operation);fn=functions[0];key=f['fragment']['compilerFragmentAuthority']['fragmentBindingKey']
    scope={'schemaVersion':'riscv2x86.compiler-atomic-function-scope.v1','sourceDigest':fn['sourceDigest'],'functionIdentity':fn['functionId'],
           'asmBegin':key['beginOffset'],'asmEnd':key['endOffset'],'scope':'single_asm_no_other_memory_or_control_effects'}
    fn['compilerAtomicFunctionScope']=dict(scope,scopeIdentity=identity(scope))
    return f,functions


@pytest.mark.parametrize('op',['fetch_add','exchange'])
@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('order',['relaxed','acquire','release','acq_rel'])
def test_decode_rv_amo_roles_and_order(op,width,order):
    a=atomic_instruction(rv(op,width,order),243)
    assert (a['operation'],a['width'],a['ordering'],a['addressRegister'],a['inputRegister'],a['resultRegister'])==(op,width,order,10,11,12)
    assert satisfies(a,{'rmw_operation':op,'width_bits':width,'success_ordering':order},'source')
    if order=='relaxed':assert not satisfies(a,{'rmw_operation':op,'width_bits':width,'success_ordering':'acquire'},'source')


@pytest.mark.parametrize('code,kind,width', [('f0480fc137','x86-locked-xadd',64),('f00fc137','x86-locked-xadd',32),
    ('488737','x86-memory-xchg',64),('8737','x86-memory-xchg',32),('480fc137','x86-unlocked-xadd',64),('0fc137','x86-unlocked-xadd',32)])
def test_decode_x86_memory_atomic_and_unlocked_counterexample(code,kind,width):
    a=atomic_instruction(bytes.fromhex(code),62)
    assert (a['mechanism'],a['width'])==(kind,width)
    assert satisfies(a,{'rmw_operation':a['operation'],'width_bits':width},'target')==(kind!='x86-unlocked-xadd')


@pytest.mark.parametrize('code,machine',[('f0480fc1f7',62),('4887f7',62),('0f000000',243),('2f300010',243)])
def test_register_forms_and_non_rmw_encodings_are_not_memory_atomics(code,machine):
    assert atomic_instruction(bytes.fromhex(code),machine) is None


def test_spec_and_normal_planner_require_atomic_capability(tmp_path):
    f,functions=fixture(tmp_path);value=spec(f,functions)
    assert value['operation']['rmw_operation']=='fetch_add'
    from riscv2x86_py.l3_execution_plan import build
    assert build([f],functions,{'atomic'})['complete']
    assert not build([f],functions,{'memory','control','fence','scalar-program'})['complete']


@pytest.mark.parametrize('mutation',['scope','function','width','source','renderer','sidecar'])
def test_spec_rejects_changed_authority(tmp_path,mutation):
    f,functions=fixture(tmp_path)
    if mutation=='scope':functions[0]['compilerAtomicFunctionScope']['scope']='unbounded'
    if mutation=='function':functions[0]['functionId']=identity('wrong')
    if mutation=='width':f['approvalArtifact']['l2AtomicProofFacts']['widthRoles']['memoryAccessWidth']=32
    if mutation=='source':f['sourceDigest']=identity('wrong')
    if mutation=='renderer':f['approvalArtifact']['rendererSemanticContractId']='unapproved'
    if mutation=='sidecar':f['approvalArtifact']['l2AuthoritySidecar']['complete']=False
    with pytest.raises((ValueError,KeyError,TypeError)):spec(f,functions)


def native_spec(width=64,op='fetch_add',discard=False):
    return {'operation':{'width_bits':width,'rmw_operation':op,'alignment_bytes':width//8,'result_semantics':'none' if discard else 'old_value','memory_object_identity':'object','success_ordering':'relaxed'},
        'parameterTypes':['uint'+str(width)+'_t *','uint64_t'],'pointerParameter':0,'valueParameter':1,'returnType':'void' if discard else 'uint64_t',
        'widthRoles':{'inputCarrierWidth':64,'resultCarrierWidth':0 if discard else 64,'resultExtension':'sign_extend' if width==32 and not discard else 'none' if discard else 'identity'}}


@pytest.mark.parametrize('width,op,discard',[(w,o,d) for w in (32,64) for o in ('fetch_add','exchange') for d in (False,True)])
def test_real_native_builtin_deployment_retains_original_function_bytes(tmp_path,width,op,discard):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    from riscv2x86_py.l3_atomic_deployment import build_side
    value=native_spec(width,op,discard);plan=samples(value)
    builtin='__atomic_fetch_add' if op=='fetch_add' else '__atomic_exchange_n'
    call=builtin+'(p,(uint'+str(width)+'_t)v,__ATOMIC_RELAXED)'
    body=call+';' if discard else 'return '+('(uint64_t)(int64_t)(int32_t)' if width==32 else '')+call+';'
    c=tmp_path/'unrelated.c';c.write_text('#include <stdint.h>\n'+value['returnType']+' unrelated('+','.join([value['parameterTypes'][0]+'p','uint64_t v'])+'){'+body+'}')
    obj=tmp_path/'original.o';subprocess.run([cc,'-O0','-std=gnu11','-fno-lto','-fPIC','-c',c,'-o',obj],check=True,capture_output=True)
    artifact=SimpleNamespace(artifact_path=str(obj),artifact_digest=digest(obj),artifact_id='target',build_identity=identity('build'))
    dep=build_side(c,'target',plan,{'name':'unrelated'},{'targetCompiler':cc},artifact,tmp_path/'deployment',value)
    assert Elf(obj).code('unrelated')==Elf(dep['executionArtifact']['artifactPath']).code('unrelated')
    token='a'*64;r=subprocess.run([dep['executionArtifact']['artifactPath'],token],check=True,capture_output=True,text=True)
    rows=parse_samples(r.stdout,token,plan)
    assert len(rows)==plan['distinctInputCount']
    assert satisfies(dep['machineMechanism']['instruction'],value['operation'],'target')
    for row in rows:
        old=int(row['old'],16);val=int(row['input'],16);mask=(1<<width)-1
        assert int(row['after'][0],16)==((old+val)&mask if op=='fetch_add' else val&mask)


def reports(tmp_path):
    from riscv2x86_py.l3_atomic_compare import report
    from riscv2x86_py.l3_sync_obligations import build
    f,functions=fixture(tmp_path);value=spec(f,functions);plan=samples(value)
    tool=tmp_path/'tool';tool.write_text('executor');backend={'backendIdentity':identity('backend'),'calibration':[]}
    deployment={'spec':value,'samplePlan':plan,'deploymentIdentity':identity('dep'),'sides':{}};result={}
    atom=value['operation'];width=atom['width_bits'];order=atom['success_ordering']
    for side,code,machine in [('source',rv(width=width,order=order),243),('target',bytes.fromhex('f0480fc137'),62)]:
        insn=atomic_instruction(code,machine);reg={'start':0x1000,'end':0x1000+len(code),'exits':[0x1000+len(code)]}
        mech={'instruction':insn,'mechanismIdentity':identity(insn)}
        deployment['sides'][side]={'machineMechanism':mech,'region':reg}
        backend.update({side+'Executor':str(tool),side+'RunnerArguments':[]})
        backend['calibration'].append({'case':{'side':side},'instruction':insn,'callbackAccessKinds':['write']})
        rows=[];memory=[]
        for i,item in enumerate(plan['inputs']):
            old=int(item['old'],16);val=int(item['input'],16);mask=(1<<width)-1
            rows.append({'sample':i,'token':'a'*64,'objectBase':'0000000000002000',**item,'result':f'{old:016x}',
                         'after':[f'{(old+val)&mask:016x}','0000000000000031','0000000000000072','0000000000000053']})
            memory.append({'sample':i,'pc':reg['start'],'address':0x2000,'size':width//8,'access':'write'})
        observed={'paths':[{'pcs':[reg['start']],'exit':reg['end']} for _ in rows],'memory':memory}
        result[side]=report(side,backend,deployment,observed,rows,{})
    return result,value,deployment,backend


def test_comparison_keeps_actual_callback_shape_and_static_atomicity_distinct(tmp_path):
    from riscv2x86_py.l3_atomic_compare import comparison
    r,value,_,_=reports(tmp_path);cmp=comparison(r,value)
    assert cmp['memory']['status']==cmp['synchronization']['status']=='verified'
    assert cmp['synchronization']['concurrentAtomicityMeasured'] is False
    assert all(e['rawCallbackAccesses']==[{'offsetBytes':0,'widthBytes':8,'access':'write'}] for e in r['source']['atomicEvents'])


@pytest.mark.parametrize('mutation',['mechanism','width','address','value','guard','result','completion'])
def test_observation_comparison_rejects_supported_counterexamples(tmp_path,mutation):
    from riscv2x86_py.l3_atomic_compare import comparison,report
    r,value,dep,backend=reports(tmp_path);t=r['target'];observed={'paths':deepcopy(t['rawPaths']),'memory':deepcopy(t['memory'])};rows=deepcopy(t['samples'])
    if mutation=='mechanism':dep['sides']['target']['machineMechanism']['instruction']['mechanism']='x86-unlocked-xadd';backend['calibration'][1]['instruction']['mechanism']='x86-unlocked-xadd'
    if mutation=='width':observed['memory'][0]['size']=4
    if mutation=='address':observed['memory'][0]['address']+=8
    if mutation=='value':rows[0]['after'][0]='0000000000001234'
    if mutation=='guard':rows[0]['after'][1]='0000000000000000'
    if mutation=='result':rows[0]['result']='0000000000001234'
    if mutation=='completion':observed['paths'][0]['exit']+=1
    r['target']=report('target',backend,dep,observed,rows,{})
    assert any(c['status']=='failed' for c in comparison(r,value).values())


@pytest.mark.parametrize('mutation',['token','input','duplicate','missing'])
def test_sample_protocol_rejects_misattribution(tmp_path,mutation):
    r,value,dep,_=reports(tmp_path);rows=deepcopy(r['source']['samples'])
    if mutation=='token':rows[0]['token']='b'*64
    if mutation=='input':rows[0]['input']='ffffffffffffffff' if rows[0]['input']!='ffffffffffffffff' else '0000000000000000'
    if mutation=='duplicate':rows[1]['sample']=0
    if mutation=='missing':rows.pop()
    with pytest.raises(ValueError):parse_samples('\n'.join(json.dumps(row) for row in rows),'a'*64,dep['samplePlan'])


def test_unknown_calls_and_retry_loops_require_separate_capability():
    for code in ('e800000000c3','ebfec3','f0480fb137c3'):
        with pytest.raises(ValueError):decode(bytes.fromhex(code),0x1000,62)


@pytest.mark.parametrize('case_index',[i for i in range(32,42)])
def test_real_native_calibration_probes_verify_old_and_new_values(tmp_path,case_index):
    from riscv2x86_py.l3_atomic_backend import CASES,probe,instruction,region
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    case=CASES[case_index];assert case['side']=='target'
    asm=tmp_path/'probe.S';asm.write_text(probe(case));binary=tmp_path/'probe'
    r=subprocess.run([cc,'-nostdlib','-nostartfiles','-static','-no-pie',asm,'-o',binary],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    a=instruction(Elf(binary),region(Elf(binary)))
    assert a['operation']==case['operation'] and a['width']==case['width']
    assert subprocess.run([binary],check=False).returncode==0


@pytest.fixture
def calibration_tools(tmp_path,monkeypatch):
    """External tool fixtures; real shape/parser/checkpoint consumers are used."""
    from riscv2x86_py import l3_atomic_backend as b
    path=tmp_path/'control.json';path.write_text('{}');base={k:[] if k.endswith('Arguments') else '/fake/tool' for k in b.control.TOOLS}
    monkeypatch.setattr(b.control,'validate',lambda _:base)
    def code(case):
        if case['side']=='source':return rv(case['operation'],case['width'],case['ordering'],0 if case['discard'] else 12)
        if case.get('implementation')=='cas-loop':
            wide=case['width']==64
            initial=(bytes.fromhex('48c7c000000000') if wide else bytes.fromhex('b800000000')) if case['retry'] else bytes.fromhex('488b07' if wide else '8b07')
            body=bytes.fromhex('4989c04889c2' if wide else '4189c089c2')
            body+=(b'\x48' if wide else b'')+bytes([{'fetch_and':0x21,'fetch_or':9,'fetch_xor':0x31}[case['operation']],0xf2])
            body+=(b'\xf0' if case['locked'] else b'')+(b'\x48' if wide else b'')+bytes.fromhex('0fb117')
            if case['predicate']=='setcc':body+=bytes.fromhex('0f94c184c9')
            body+=bytes([0x74 if case['predicate']=='setcc' else 0x75,(-len(body)-2)&255])
            return initial+body
        return (b'\xf0' if case['locked'] and case['operation']!='exchange' else b'')+(b'\x48' if case['width']==64 else b'')+(
            bytes([{'fetch_add':1,'fetch_and':0x21,'fetch_or':9,'fetch_xor':0x31}[case['operation']]]) if case['discard'] else b'\x0f\xc1' if case['operation']=='fetch_add' else b'\x87')+b'\x37'
    class FakeElf:
        def __init__(self,p):
            self.case=b.CASES[int(Path(p).parent.name)];self.machine=243 if self.case['side']=='source' else 62
            self.code=code(self.case);self.sections=[(0,0,4,0x1000,0,len(self.code))]
        def symbol(self,name):return (0x1000 if name=='begin' else 0x1000+len(self.code) if name=='end' else 0x2000,0,0,0)
        def slice(self,start,size):return self.code[start:start+size]
    monkeypatch.setattr(b,'Elf',FakeElf)
    def command(value,side,binary,region,trace,token):return ['/fake/executor',str(binary),token]
    monkeypatch.setattr(b.control,'command',command)
    def run(cmd,work,tag):
        Path(cmd[-1]).write_text('test binary')
        from riscv2x86_py.l3_trace_support import save
        save(Path(work)/(tag+'.command.json'),{'command':list(map(str,cmd)),'returnCode':0,'timedOut':False})
    monkeypatch.setattr(b,'run',run)
    def capture(value,side,binary,region,directory,calls,timeout):
        d=Path(directory);d.mkdir();trace=d/'guest-trace.log';token='a'*64;t='riscv64' if side=='source' else 'x86_64';end=format(region['end'],'x');elf=FakeElf(binary);width=elf.case['width']//8
        machine=b.retry_machine(elf,region,elf.case) if elf.case.get('implementation')=='cas-loop' else None
        pcs=machine['retry']['prefixPCs']+machine['retry']['loopPCs']*(2 if elf.case['retry'] else 1) if machine else [region['start']]
        lines=['H 2 '+token+' '+t+' 1000 '+end,'B 0 1000'];memory_count=0;attempt=0
        for step,pc in enumerate(pcs):
            lines.append('P '+str(step)+' 0 '+format(pc,'x'));kind=None
            if machine:
                if pc==machine['retry']['casPC']:
                    attempt+=1;kind='R' if elf.case['retry'] and attempt==1 else 'W'
                elif pc in {r['pc'] for r in machine['retry']['initialMemory']}:kind='R'
            else:kind='W'
            if kind:
                lines.append('M '+str(memory_count)+' 0 '+format(pc,'x')+' 2000 '+str(width)+' '+kind);memory_count+=1
        lines+=['X 0 '+end,'F 1 1 '+str(len(pcs))+' '+str(memory_count)+' 0']
        trace.write_text('\n'.join(lines)+'\n')
        from riscv2x86_py.l3_trace_support import save
        cp=d/'execute.command.json';save(cp,{'command':command(value,side,binary,region,trace,token),'returnCode':0,'timedOut':False,'stdout':'','stderr':''})
        e={'token':token,'rawTracePath':str(trace),'rawTraceDigest':digest(trace),'commandRecordDigest':digest(cp)}
        return b.parse_capture(trace.read_text(),token,t,region,1),'',e
    monkeypatch.setattr(b.control,'capture',capture)
    return b,path,tmp_path/'output'


def test_all_calibration_records_are_replayed_and_rehashed_raw_tamper_rejected(calibration_tools):
    b,path,out=calibration_tools;value=b.prepare(path,out);assert b.validate(out/'backend.json')==value
    state=json.loads((out/'build-status.json').read_text())
    assert state['complete'] and len(state['calibrationCompleted'])==len(b.CASES) and state['semanticApproval'] is False
    r=value['calibration'][0];trace=Path(r['evidence']['rawTracePath']);trace.write_text(trace.read_text().replace('2000','2008'))
    r['evidence']['rawTraceDigest']=digest(trace);value['backendIdentity']=identity({k:v for k,v in value.items() if k!='backendIdentity'})
    with pytest.raises(ValueError):b.validate(value)


@pytest.mark.parametrize('index',range(138))
def test_any_calibration_failure_preserves_progress_and_prevents_publication(calibration_tools,monkeypatch,index):
    b,path,out=calibration_tools;original=b.check_calibration
    def check(value,record,base):
        if record['case']==b.CASES[index]:raise ValueError('injected calibration failure')
        original(value,record,base)
    monkeypatch.setattr(b,'check_calibration',check)
    with pytest.raises(ValueError):b.prepare(path,out)
    assert not (out/'backend.json').exists()
    state=json.loads((out/'build-status.json').read_text())
    assert not state['complete'] and state['calibrationCurrent']==b.CASES[index]


@pytest.mark.parametrize('mutation',[None,'context','result','status','evidence','prior','requirement','drop-atomic-property'])
def test_independent_audit_consumer_closes_atomic_subproperties(tmp_path,monkeypatch,mutation):
    from riscv2x86_py import l3_atomic_route as route
    from riscv2x86_py.l3_atomic_intent import produce
    from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
    from riscv2x86_py.l3_execution_context import L3ExecutionContext
    from tests.test_l3_scalar_trace import request
    from tests.test_l3_production_ingress import program
    from tests.test_translation_validation import _translation
    f,functions=fixture(tmp_path);request_body=request(f);request_body['candidates'][0]['compilerFunctions']=functions
    request_body['requestIdentity']=identity({k:v for k,v in request_body.items() if k!='requestIdentity'})
    f['l3IntentProfile']=produce(request_body)['profiles'][0]
    manifest=classify_l3_requirements({'findings':[f]});req=manifest.requirements[0];assert req['eligibilityStatus']=='eligible'
    source,target=program(tmp_path,'source'),program(tmp_path,'target');artifact=replace(_translation(),fragment_id=req['fragmentId'],proof_identity=req['proofIdentity'],effect_relation_set_identity=req['approvedTargetRelationIdentity'])
    observed,value,deployment,_=reports(tmp_path);contract={'requirement':req,'deployment':deployment,'contractIdentity':identity('contract')}
    context=L3ExecutionContext.create(source,target);bindings={s:context.request_binding(s) for s in ('source','target')};prior=[SimpleNamespace(evidence_identity=identity(str(i))) for i in range(3)]
    fragment,cmp=route.dimensions(contract,observed,bindings,artifact,source,target,prior,'architectural')
    detail={'platformReports':observed,'executionBindings':bindings,'fragmentResult':fragment,'comparison':cmp,'propertyObligations':value['obligations'],'physicalMicroarchitectureClaimed':False,'reasonCodes':[]}
    layers=[{'level':level,'status':'verified','evidenceIdentity':prior[i].evidence_identity,'detail':json.dumps({'claimScope':'architectural'})} for i,level in enumerate(('L0','L1','L2'))]
    layers.append({'level':'L3','status':'verified','evidenceIdentity':identity(detail),'detail':json.dumps(detail)})
    raw=dict(asdict(artifact),preservation_mode=artifact.preservation_mode.value,ignored_source_state=list(artifact.ignored_source_state))
    evaluation={'status':'verified','sourceProgramArtifact':asdict(source),'targetProgramArtifact':asdict(target),'translationEvaluationLink':{'l3Requirements':manifest.to_dict()},
                'attempts':[{'translationArtifact':raw,'status':'verified','validation':{'status':'verified','layers':layers}}]}
    monkeypatch.setattr(route,'replay',lambda *args:contract)
    assert route.audit_result(evaluation)['productionAcceptanceComplete']
    if mutation is None:return
    if mutation=='context':detail['executionBindings']['source']['contextIdentity']=identity('wrong')
    if mutation=='result':detail['fragmentResult']['dimensionResults']={}
    if mutation=='drop-atomic-property':detail['comparison']['synchronization']['subpropertyResults'].pop('sync.atomic-mechanism')
    if mutation=='status':layers[3]['status']='not_run'
    if mutation=='evidence':layers[3]['evidenceIdentity']=identity('wrong')
    if mutation=='prior':layers[1]['evidenceIdentity']=identity('wrong')
    if mutation=='requirement':evaluation['translationEvaluationLink']['l3Requirements']['requirements'][0]['requiredProperties'].pop()
    layers[3]['detail']=json.dumps(detail)
    if mutation!='evidence':layers[3]['evidenceIdentity']=identity(detail)
    with pytest.raises((ValueError,KeyError)):route.audit_result(evaluation)


def test_driver_preserves_primary_failure_and_does_not_attempt_acceptance(tmp_path,monkeypatch):
    from riscv2x86_py import l3_atomic_backend
    p=Path(__file__).resolve().parents[2]/'experiment/run_l3_atomic_trace.py';loader=importlib.util.spec_from_file_location('atomic_driver',p)
    module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    tool=tmp_path/'tool';tool.write_text('tool');out=tmp_path/'run'
    monkeypatch.setattr(l3_atomic_backend,'validate',lambda _: {})
    def run(cmd,stdout,**kwargs):
        stdout.write('configuration rejected: compiler prerequisite missing\n');stdout.flush();return SimpleNamespace(returncode=2)
    monkeypatch.setattr(module.subprocess,'run',run)
    monkeypatch.setattr(sys,'argv',[str(p),'--input',str(tool),'--frontend',str(tool),'--backend',str(tool),'--output',str(out)])
    assert module.main()==2
    status=json.loads((out/'run-status.json').read_text())
    assert status['currentStage']=='normal_production' and not status['productionAcceptanceComplete']
    assert 'compiler prerequisite missing' in status['normalProductionLogTail']


def test_changed_callback_shape_cannot_silently_enable_a_mechanism(tmp_path):
    from riscv2x86_py.l3_atomic_backend import callback_shape
    r,value,dep,backend=reports(tmp_path)
    insn=dep['sides']['source']['machineMechanism']['instruction']
    backend['calibration'].clear()
    with pytest.raises(ValueError):callback_shape(backend,'source',insn)


def test_object_extent_drives_harness_allocation_and_full_guard_observation(tmp_path):
    value=native_spec(32);value['objectSizeBytes']=64;plan=samples(value)
    assert plan['objectCellCount']==16
    text=harness('operation',value,plan)
    assert 'object[16]' in text and 'j<16' in text


def test_result_discarding_add_cannot_prove_old_value_return():
    a=atomic_instruction(bytes.fromhex('f0480137'),62)
    assert a['mechanism']=='x86-locked-add'
    atom={'rmw_operation':'fetch_add','width_bits':64,'result_semantics':'old_value'}
    assert not satisfies(a,atom,'target')
    atom['result_semantics']='none';assert satisfies(a,atom,'target')


def test_rehashed_retry_trace_cannot_erase_failed_attempt(calibration_tools):
    b,path,out=calibration_tools;value=b.prepare(path,out)
    record=next(r for r in value['calibration'] if r['case'].get('retry'))
    trace=Path(record['evidence']['rawTracePath'])
    # This remains a syntactically complete capture, but claims one attempt for
    # a probe whose actual canonical machine program forces an initial failure.
    machine=b.retry_machine(b.Elf(record['binary']),b.region(b.Elf(record['binary'])),record['case'])
    pcs=machine['retry']['prefixPCs']+machine['retry']['loopPCs']
    token=record['evidence']['token'];start=machine['region']['start'];end=machine['region']['end']
    lines=['H 2 '+token+' x86_64 '+format(start,'x')+' '+format(end,'x'),'B 0 '+format(start,'x')];n=0
    for step,pc in enumerate(pcs):
        lines.append('P '+str(step)+' 0 '+format(pc,'x'))
        if pc==machine['retry']['casPC']:
            lines.append('M 0 0 '+format(pc,'x')+' 2000 '+str(record['case']['width']//8)+' W');n+=1
    lines+=['X 0 '+format(end,'x'),'F 1 1 '+str(len(pcs))+' '+str(n)+' 0']
    trace.write_text('\n'.join(lines)+'\n')
    record['evidence']['rawTraceDigest']=digest(trace)
    record['callbackAccessKinds']=['write']
    value['backendIdentity']=identity({k:v for k,v in value.items() if k!='backendIdentity'})
    with pytest.raises(ValueError,match='ATTEMPT_MISMATCH'):b.validate(value)
