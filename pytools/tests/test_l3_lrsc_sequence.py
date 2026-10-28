from copy import deepcopy
from pathlib import Path
import json
import subprocess
import pytest
from tests.test_lrsc_sequence_contract import code
from tests.test_lrsc_target import translated_case,finding_case
from riscv2x86_py.l3_lrsc_machine import source,target,attempts
from riscv2x86_py.l3_trace_support import Elf,identity


def invocation(width=64,operation='fetch_add',word=False):
    _,_,_,m,_=translated_case(width,operation,word)
    return {'pointerParameter':0,'valueParameter':1,'operation':{'width_bits':width,'rmw_operation':operation,'alignment_bytes':width//8},
        'sourceSequence':m.lrsc_sequence.to_dict()}


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
@pytest.mark.parametrize('compressed',[False,True])
@pytest.mark.parametrize('registers',[(5,6,9,10,11),(12,13,14,10,11)])
def test_final_rv_loop_proof_and_actual_path_partition(width,operation,compressed,registers):
    inv=invocation(width,operation)
    # Input address/value remain ABI a0/a1; old=t0, next=t1, status=s1.
    raw=code(width,registers=registers,operation=operation,compressed=compressed)
    raw+=((registers[0]<<15)|(10<<7)|0x13).to_bytes(4,'little')+bytes.fromhex('67800000')
    m=source(raw,0x1000,inv);r=m['retry'];p={'pcs':r['loopPCs']*2,'exit':m['region']['end']}
    assert attempts(m,p)==2
    for changed in ({'pcs':p['pcs'][:-1],'exit':p['exit']},{'pcs':p['pcs'],'exit':p['exit']+2}):
        with pytest.raises(ValueError):attempts(m,changed)


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
@pytest.mark.parametrize('optimization',['-O0','-O2'])
def test_real_compiled_target_machine_has_proved_cas_invariant(tmp_path,width,operation,optimization):
    _,_,_,_,result=translated_case(width,operation)
    text='unsigned long probe('+('unsigned int' if width==32 else 'unsigned long')+' *p,unsigned long value){unsigned long old,next,status;'+result.replacement+'return old;}'
    src=tmp_path/'probe.c';obj=tmp_path/'probe.o';src.write_text(text)
    r=subprocess.run(['gcc',optimization,'-fPIC','-c',str(src),'-o',str(obj)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    elf=Elf(obj);m=target(elf.code('probe'),elf.symbol('probe')[0],invocation(width,operation))
    assert m['instruction']['mechanism']=='x86-locked-cas-loop'
    p=m['retry'];assert attempts(m,{'pcs':p['prefixPCs']+p['loopPCs']*2,'exit':m['region']['end']})==2


def finding_spec():
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    f,functions,_,_=finding_case();fn=functions[0];f['fragment']['enclosingFunction']='probe'
    fn.update(arity=2,parameterTypes=['unsigned long *','unsigned long'],pointerParameters=[0],returnType='unsigned long')
    key=f['fragment']['compilerFragmentAuthority']['fragmentBindingKey']
    scope={'scope':'single_asm_no_other_memory_or_control_effects','functionIdentity':fn['functionId'],
        'sourceDigest':fn['sourceDigest'],'asmBegin':key['beginOffset'],'asmEnd':key['endOffset']}
    fn['compilerAtomicFunctionScope']=dict(scope,scopeIdentity=identity(scope))
    return f,functions


def test_machine_rejects_wrong_width_operation_and_source_binding():
    inv=invocation();raw=code(64,registers=(5,6,9,10,11))+bytes.fromhex('1385020067800000')
    for key,value in [('operation','fetch_xor'),('memory_width_bits',32),('lr_ordering_bits',[False,False])]:
        v=deepcopy(inv);v['sourceSequence'][key]=value
        with pytest.raises(ValueError):source(raw,0x1000,v)
    # ABI input/address binding must be independently proved in the final ELF.
    v=deepcopy(inv);v['pointerParameter']=1
    with pytest.raises(ValueError):source(raw,0x1000,v)


def test_sequence_spec_and_normal_mechanism_planner(tmp_path):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    from riscv2x86_py.l3_lrsc_spec import spec
    from riscv2x86_py.l3_execution_plan import build
    from riscv2x86_py.l3_trace_support import digest
    f,functions=finding_spec();f['translationOutcome']='emitted';f['sourceDigest']=functions[0]['sourceDigest']
    frontend=tmp_path/'frontend';frontend.write_text('identity')
    assert materialize_automatic_l2_authority({'findings':[f]},functions,frontend)==1
    program=identity({'schemaVersion':'riscv2x86.automatic-program.v1','producerDigest':digest(frontend)})
    boundaries,_,_=materialize_fragment_execution_authority([f],functions[0],program)
    f['approvalArtifact']['l2FragmentOperandBoundary']=boundaries[f['fragment']['id']].to_dict()
    value=spec(f,functions)
    from tests.test_l3_scalar_trace import request
    from riscv2x86_py.l3_lrsc_intent import produce
    req=request(f);req['candidates'][0]['compilerFunctions']=functions
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    profile=produce(req)['profiles'][0]
    assert profile['complete'] and profile['sourceCapabilities']==['qemu-attributed-lrsc-sequence-v1']
    assert [p['dimension'] for p in profile['requiredProperties']]==['control_flow','access_pattern','synchronization']
    assert value['sourceMechanism']=='lrsc-sequence'
    assert build([f],functions,{'lrsc'})['complete']
    assert not build([f],functions,{'atomic'})['complete']
    f['approvalArtifact']['l2LrscProofFacts']['complete']=False
    with pytest.raises(ValueError):spec(f,functions)


def trace_fixture():
    inv=invocation();raw=code(64,registers=(5,6,9,10,11))+bytes.fromhex('1385020067800000')
    m=source(raw,0x1000,inv);pcs=m['retry']['loopPCs']*2;memory=[];timeline=[]
    for step,pc in enumerate(pcs):
        kinds=['read'] if step in (0,4) else ['write'] if step==6 else []
        for kind in kinds:
            timeline.append({'step':step,'memoryIndex':len(memory)})
            memory.append({'sample':0,'pc':pc,'address':0x3000,'size':8,'access':kind})
    observed={'paths':[{'pcs':pcs,'exit':m['region']['end']}],'memory':memory,'memoryTimeline':timeline}
    backend={'calibration':[{'case':{'side':'source','width':64,'bits':9},'callbackShapes':{'failure':[],'success':['write']}}]}
    return inv,m,observed,backend


def test_all_source_attempts_retained_and_missing_failure_callback_is_calibrated():
    from riscv2x86_py.l3_lrsc_observation import observe
    inv,m,o,b=trace_fixture();result=observe(m,b,o,0,0,{'objectBase':'0000000000003000'},inv['operation'],32)
    assert result['bound'] and result['attemptCount']==2
    assert [a['outcome'] for a in result['attempts']]==['failure','success']
    assert result['attempts'][0]['callbackObserved'] is False
    assert not result['attempts'][0]['failedStatusValueObserved']
    b['calibration'][0]['callbackShapes'].pop('failure')
    with pytest.raises(ValueError,match='UNCALIBRATED'):observe(m,b,o,0,0,{'objectBase':'0000000000003000'},inv['operation'],32)


@pytest.mark.parametrize('mutation',['pc','address','width','sample','extra'])
def test_misattributed_callback_is_never_verified(mutation):
    from riscv2x86_py.l3_lrsc_observation import observe
    inv,m,o,b=trace_fixture()
    if mutation=='pc':o['memory'][0]['pc']+=4
    if mutation=='address':o['memory'][0]['address']+=8
    if mutation=='width':o['memory'][0]['size']=4
    if mutation=='sample':o['memory'][0]['sample']=1
    if mutation=='extra':
        o['memory'].append(dict(o['memory'][0]));o['memoryTimeline'].append({'step':1,'memoryIndex':3})
    assert not observe(m,b,o,0,0,{'objectBase':'0000000000003000'},inv['operation'],32)['bound']


@pytest.mark.parametrize('case_index',[64,65,66,67])
def test_real_native_calibration_programs_exit_only_after_correct_cas_result(tmp_path,case_index):
    from riscv2x86_py.l3_lrsc_backend import CASES,probe,build_command
    case=CASES[case_index];assembly=tmp_path/'probe.S';binary=tmp_path/'probe';assembly.write_text(probe(case))
    r=subprocess.run(build_command({'targetCompiler':'gcc'},case,assembly,binary),capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    assert subprocess.run([str(binary)],timeout=10).returncode==0


@pytest.mark.parametrize('scenario',['loop','escape','partial'])
def test_actual_loop_plugin_callbacks_do_not_reopen_active_invocation(tmp_path,scenario):
    from tests.test_l3_control_backend import HEADER
    from riscv2x86_py.l3_lrsc_backend import parse_capture
    header=tmp_path/'include/qemu/qemu-plugin.h';header.parent.mkdir(parents=True);header.write_text(HEADER)
    plugin=Path(__file__).resolve().parents[2]/'runtime/l3_qemu_lrsc_trace.c'
    trace=tmp_path/'trace';src=tmp_path/'driver.c';binary=tmp_path/'driver';token='a'*64
    action='instruction(0,(void*)0x1000);instruction(0,(void*)0x1004);instruction(0,(void*)0x2000);' if scenario=='loop' else 'instruction(0,(void*)0x3000);' if scenario=='escape' else ''
    src.write_text('#include "'+str(plugin)+'"\nint main(void){qemu_info_t info={0,"riscv64"};char *args[]={"start=0x1000","end=0x1008","exits=0x2000","limit=4096","output='+str(trace)+'","token='+token+'"};if(qemu_plugin_install(0,&info,6,args))return 2;instruction(0,(void*)0x1000);instruction(0,(void*)0x1004);'+action+'finish(0,0);return 0;}')
    r=subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-I'+str(header.parents[1]),str(src),'-o',str(binary)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    assert subprocess.run([str(binary)]).returncode==0
    if scenario=='loop':
        parsed=parse_capture(trace.read_text(),token,'riscv64',{'start':0x1000,'end':0x1008,'exits':[0x2000]},1)
        assert parsed['paths'][0]['pcs']==[0x1000,0x1004]*2
    else:
        with pytest.raises(ValueError):parse_capture(trace.read_text(),token,'riscv64',{'start':0x1000,'end':0x1008,'exits':[0x2000]},1)


def test_comparison_preserves_control_obligation_and_all_raw_attempts(tmp_path):
    from riscv2x86_py.l3_lrsc_compare import report,comparison
    inv,sm,so,backend=trace_fixture();inv['operation'].update(memory_object_identity='object',result_semantics='old_value')
    inv['widthRoles']={'resultExtension':'identity','resultCarrierWidth':64}
    inv['obligations']={'synchronizationObligations':{'basisComplete':True,'requiredSubproperties':[{'propertyId':p} for p in ('sync.compiler-contract','sync.atomic-mechanism','sync.atomic-outcome','sync.ordering-contract')]}}
    # Minimal actual x86 machine bytes: load; compute; locked CAS; failure jump;
    # status=0; return. The parser independently proves this region.
    raw=bytes.fromhex('488b074889c24801f2f0480fb11775f348c7c100000000c3')
    tm=target(raw,0x2000,inv);r=tm['retry'];pcs=r['prefixPCs']+r['loopPCs'];memory=[];timeline=[]
    for i,pc in enumerate(pcs):
        kinds=['read'] if pc==tm['region']['start'] else ['read','write'] if pc==r['casPC'] else []
        for kind in kinds:
            timeline.append({'step':i,'memoryIndex':len(memory)});memory.append({'sample':0,'pc':pc,'address':0x3000,'size':8,'access':kind})
    to={'paths':[{'pcs':pcs,'exit':tm['region']['end']}],'memory':memory,'memoryTimeline':timeline}
    backend['calibration'].append({'case':{'side':'target','width':64,'bits':0},'callbackShapes':{'failure':[],'success':['read','write']}})
    backend.update(backendIdentity='backend',sourceExecutor='/usr/bin/gcc',targetExecutor='/usr/bin/gcc',sourceRunnerArguments=[],targetRunnerArguments=[])
    dep={'sides':{'source':{'machineMechanism':sm,'region':sm['region']},'target':{'machineMechanism':tm,'region':tm['region']}},'spec':inv,'samplePlan':{'objectCellCount':4},'deploymentIdentity':'deployment'}
    row={'objectBase':'0000000000003000','old':'0000000000000007','input':'0000000000000003','result':'0000000000000007','after':['000000000000000a','0000000000000031','0000000000000072','0000000000000053']}
    reports={side:report(side,backend,dep,observed,[row],{}) for side,observed in (('source',so),('target',to))}
    result=comparison(reports,inv)
    assert set(result)=={'control','memory','synchronization'} and all(x['status']=='verified' for x in result.values())
    assert reports['source']['atomicEvents'][0]['retryObservation']['attemptCount']==2
    assert reports['target']['atomicEvents'][0]['retryObservation']['attemptCount']==1
    reports['target']['atomicEvents'][0]['actualReturnedValue']='0000000000000008'
    assert comparison(reports,inv)['synchronization']['status']=='failed'


def test_actual_word_arithmetic_and_operand_permutation_machine(tmp_path):
    _,_,_,_,result=translated_case(32,'fetch_add',True,(3,2,0,1,5,4))
    src=tmp_path/'p.c';obj=tmp_path/'p.o';src.write_text('unsigned long probe(unsigned long value,unsigned int *p){unsigned long old,next,status;'+result.replacement+'return old;}')
    r=subprocess.run(['gcc','-O0','-fPIC','-c',str(src),'-o',str(obj)],capture_output=True,text=True);assert r.returncode==0,r.stderr
    elf=Elf(obj);inv=invocation(32,'fetch_add',True);inv.update(pointerParameter=1,valueParameter=0)
    assert target(elf.code('probe'),elf.symbol('probe')[0],inv)['instruction']['width']==32
    raw=code(32,word_alu=True,registers=(5,6,9,11,10))+bytes.fromhex('1385020067800000')
    assert source(raw,0x1000,inv)['instruction']['width']==32


def test_backend_calibration_failure_keeps_primary_error_and_publishes_no_backend(tmp_path,monkeypatch):
    from tests.test_l3_control_backend import HEADER
    from riscv2x86_py import l3_lrsc_backend as backend
    header=tmp_path/'source/include/qemu/qemu-plugin.h';header.parent.mkdir(parents=True);header.write_text(HEADER)
    control=tmp_path/'control.json';control.write_text('{}')
    tools={k:[] if k.endswith('Arguments') else '/usr/bin/gcc' for k in backend.control.TOOLS}
    monkeypatch.setattr(backend.control,'validate',lambda *a,**kw:dict(tools,files={str(header):'header'}))
    out=tmp_path/'backend'
    # Real native compilation builds the plugin; the first RISC-V probe cannot
    # be assembled by this deliberately wrong compiler and must block publication.
    with pytest.raises(ValueError,match='COMMAND_FAILED'):backend.prepare(control,out)
    status=json.loads((out/'build-status.json').read_text())
    assert status['complete'] is False and status['failedStage']=='calibration'
    assert not (out/'backend.json').exists() and not status['calibrationCompleted']
    assert 'COMMAND_FAILED' in status['error']


@pytest.mark.parametrize('change',['unlock','predicate','stale-operation','wrong-width','wrong-object'])
def test_target_machine_counterexamples_cannot_obtain_approval(change):
    inv=invocation();raw=bytes.fromhex('488b074889c24801f2f0480fb11775f348c7c100000000c3')
    if change=='unlock':raw=raw.replace(bytes.fromhex('f0480fb1'),bytes.fromhex('90480fb1'))
    if change=='predicate':raw=raw.replace(bytes.fromhex('75f3'),bytes.fromhex('74f3'))
    if change=='stale-operation':inv['operation']['rmw_operation']='fetch_xor'
    if change=='wrong-width':inv['operation']['width_bits']=32
    if change=='wrong-object':inv.update(pointerParameter=1,valueParameter=0)
    with pytest.raises(ValueError):target(raw,0x2000,inv)
