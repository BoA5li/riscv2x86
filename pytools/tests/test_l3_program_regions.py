"""Compiler/proof fixtures, native byte equality and real C plugin callbacks."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py.l3_trace_support import identity,Elf
from riscv2x86_py.l3_program_backend import parse_capture


def fixture(tmp_path):
    from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
    from riscv2x86_py.compiler_integer_signature import export as signature
    from riscv2x86_py.compiler_program_regions import export
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from tests.test_compiler_expression_contracts import ctype
    from tests.l2_profile_fixtures import profile_dict
    from tests.l2_effect_proof_fixtures import attach_effect_proof
    source=b'unsigned long renamed(unsigned long x){unsigned long tmp;unsigned long out;__asm__ volatile("movq %1,%0":"=r"(tmp):"r"(x));__asm__ volatile("movq %1,%0":"=r"(out):"r"(tmp));return out;}'
    def extent(a,b):return {'begin':{'offset':a,'line':1,'col':a+1},'end':{'offset':b-1,'tokLen':1}}
    def ref(n,p):return {'kind':'DeclRefExpr','range':extent(p,p+len(n)),'referencedDecl':{'id':'ast:'+n},'type':{'qualType':'unsigned long'},'valueCategory':'lvalue'}
    first=source.index(b'__asm__');second=source.index(b'__asm__',first+1);ends=[source.index(b';',p)+1 for p in (first,second)]
    asms=[]
    for a,b,n,m in zip((first,second),ends,('tmp','out'),('x','tmp')):
        asms.append({'kind':'GCCAsmStmt','range':extent(a,b),'numOutputs':1,'outputConstraints':['=r'],
            'inner':[ref(n,source.index(('('+n+')').encode(),a)+1),ref(m,source.index(('('+m+')').encode(),a)+1)]})
    decls=[{'kind':'DeclStmt','inner':[{'kind':'VarDecl','id':'ast:'+n,'name':n,'type':{'qualType':'unsigned long'},'range':extent(source.index(('long '+n).encode()),source.index(('long '+n).encode())+5+len(n))}]} for n in ('tmp','out')]
    ast={'kind':'FunctionDecl','name':'renamed','range':extent(0,len(source)),'inner':[
        {'kind':'ParmVarDecl','id':'ast:x','name':'x','type':{'qualType':'unsigned long'},'range':extent(22,37)},
        {'kind':'CompoundStmt','inner':decls+asms+[{'kind':'ReturnStmt','inner':[ref('out',source.index(b'out;',ends[1]))]}]}]}
    S=identity('source');F=identity('function');boundary=_l2_operand_boundary_facts(ast,source_digest=S,function_identity=F,source_file='/tmp/renamed.c',source_bytes=source)
    fn={'name':'renamed','functionId':F,'sourceDigest':S,'sourceFile':'/tmp/renamed.c','arity':1,'parameterTypes':['unsigned long'],'returnType':'unsigned long','l2OperandBoundary':boundary}
    fn['compilerIntegerCallSignature']=signature(fn,fn['parameterTypes'],fn['returnType'],lambda t:t)
    fn['compilerProgramRegions']=export(ast,source_digest=S,function_identity=F,source_range=lambda n:(n['range']['begin']['offset'],n['range']['end']['offset']+1))
    findings=[]
    for raw,(a,b),n,m in zip(boundary['fragmentCandidates'],zip((first,second),ends),('tmp','out'),('x','tmp')):
        fid='/tmp/renamed.c:1:'+str(a+1)
        fragment={'id':fid,'enclosingFunction':'renamed','file':'/tmp/renamed.c','line':1,'column':a+1,'beginOffset':a,'endOffset':b,
            'outputs':[{'constraint':'=r','exprText':n,'compilerType':ctype()}],'inputs':[{'constraint':'r','exprText':m,'compilerType':ctype()}]}
        closed=close_compiler_fragment_candidate(raw,fragment,source_digest=S,function_identity=F)
        authority={'schemaVersion':'riscv2x86.compiler-fragment-authority.v2','sourceDigest':S,'functionIdentity':F,'fragmentId':fid,'targetTriple':'riscv64-linux-gnu','fragmentBindingKey':raw['fragmentBindingKey'],'candidate':closed,
            'compilerTypeBindings':{str(v['operandIndex']):{'operandIndex':v['operandIndex'],'valueNodeIdentity':v['valueNodeIdentity'],'compilerType':ctype()} for v in closed['operandBindings']}}
        authority['authorityIdentity']=identity(authority);fragment['compilerFragmentAuthority']=authority
        f={'fragment':fragment,'sourceDigest':S,'translationOutcome':'emitted','approvalArtifact':{'proofStatus':'approved','architectureSemanticsPreserved':True,'shellSemanticsPreserved':True,'planId':S,'constraintsId':F},'l2SemanticProfile':profile_dict(fid)}
        attach_effect_proof(f['approvalArtifact'],fid);findings.append(f)
    front=tmp_path/'frontend';front.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':findings},[fn],front)==2
    return source,findings,fn


def test_complete_program_spec_replays_authority_and_dependency(tmp_path):
    from riscv2x86_py.l3_program_spec import spec
    from riscv2x86_py.l3_program_intent import produce
    from tests.test_l3_scalar_trace import request
    source,findings,fn=fixture(tmp_path);s=spec(findings,[fn])
    assert len(s['members'])==2 and s['executionPlan']['complete']
    assert len(findings[0]['approvalArtifact']['l2FragmentDependencyGraph']['edges'])==1
    req=request(findings[0]);req['candidates']=[request(f)['candidates'][0] for f in findings]
    for c in req['candidates']:c['compilerFunctions']=[fn]
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    result=produce(req)
    assert len(result['profiles'])==2 and all(p['complete'] for p in result['profiles']) and not result['dispositions']
    req['candidates'].pop();req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    assert not produce(req)['profiles'][0]['complete']


@pytest.mark.parametrize('change',['missing','proof','dependency','scope','object','signedness'])
def test_program_spec_rejects_incomplete_or_mutated_members(tmp_path,change):
    from riscv2x86_py.l3_program_spec import spec
    _,findings,fn=fixture(tmp_path)
    if change=='missing':findings.pop()
    if change=='proof':findings[1]['approvalArtifact']['proofIdentity']=identity('bad')
    if change=='dependency':findings[0]['approvalArtifact']['l2FragmentDependencyGraph']['edges']=[]
    if change=='scope':fn['compilerProgramRegions']['sites'].pop()
    if change=='object':findings[1]['approvalArtifact']['l2AuthoritySidecar']['memoryObjects']=[{}]
    if change=='signedness':fn['compilerIntegerCallSignature']['parameters'][0]['signed']=True
    with pytest.raises((KeyError,ValueError,TypeError)):spec(findings,[fn])


def test_native_labels_preserve_whole_function_bytes_and_dataflow(tmp_path):
    from riscv2x86_py.l3_program_deployment import instrument,label_assembly
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    source,_,fn=fixture(tmp_path)
    for name,data in [('original',source),('marked',instrument(source,fn['compilerProgramRegions']['sites']))]:
        c=tmp_path/(name+'.c');c.write_bytes(data)
        asm=tmp_path/(name+'.s')
        r=subprocess.run([cc,'-O0','-fPIC','-S',str(c),'-o',str(asm)],capture_output=True,text=True);assert r.returncode==0,r.stderr
        if name=='marked':asm.write_text(label_assembly(asm.read_text(),2))
        r=subprocess.run([cc,'-shared',str(asm),'-o',str(tmp_path/(name+'.so'))],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
    a,b=Elf(tmp_path/'original.so'),Elf(tmp_path/'marked.so')
    assert a.code('renamed')==b.code('renamed')
    assert b.symbol('__rv2x86_r0_end')[0]<=b.symbol('__rv2x86_r1_begin')[0]
    # Only one 64-bit register MOV belongs to each region. Compiler loads and
    # stores used to pass values between C statements must remain outside it.
    from riscv2x86_py.l3_control_machine import decode
    code=b.code('renamed');start=b.symbol('renamed')[0]
    for i in range(2):
        a=b.symbol('__rv2x86_r'+str(i)+'_begin')[0];end=b.symbol('__rv2x86_r'+str(i)+'_end')[0]
        instructions=decode(code[a-start:end-start],a,62)
        assert len(instructions)==1 and instructions[0]['op']=='move'
    import ctypes
    f=ctypes.CDLL(str(tmp_path/'marked.so')).renamed;f.argtypes=[ctypes.c_ulong];f.restype=ctypes.c_ulong
    for value in (0,1,2**63,2**64-1):assert f(value)==value


@pytest.mark.parametrize('scenario',['valid','memory','skip','reentry','partial','cpu'])
def test_actual_program_plugin_callbacks(tmp_path,scenario):
    from tests.test_l3_control_backend import HEADER
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    h=tmp_path/'include/qemu/qemu-plugin.h';h.parent.mkdir(parents=True);h.write_text(HEADER)
    plugin=Path(__file__).resolve().parents[2]/'runtime/l3_qemu_program_trace.c';trace=tmp_path/'trace';token='a'*64
    normal='instruction(0,(void*)0x1000);instruction(0,(void*)0x1004);instruction(0,(void*)0x1010);'
    action=normal+('memory(0,3,0x2000,(void*)0x1010);' if scenario=='memory' else '')+'instruction(0,(void*)0x1014);'
    if scenario=='skip':action='instruction(0,(void*)0x1010);'
    if scenario=='reentry':action='instruction(0,(void*)0x1000);instruction(0,(void*)0x1000);'
    if scenario=='partial':action=normal
    if scenario=='cpu':action=action+'instruction(1,(void*)0x3000);'
    c=tmp_path/'driver.c';binary=tmp_path/'driver'
    c.write_text('#include "'+str(plugin)+'"\nint main(void){qemu_info_t info={false,"riscv64"};char *args[]={"regions=0x1000:0x1004;0x1010:0x1014","output='+str(trace)+'","token='+token+'"};if(qemu_plugin_install(1,&info,3,args))return 2;'+action+'finish(1,NULL);return 0;}')
    r=subprocess.run([cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(h.parents[1]),str(c),'-o',str(binary)],capture_output=True,text=True);assert r.returncode==0,r.stderr
    r=subprocess.run([str(binary)],capture_output=True,text=True);assert r.returncode==0 and not r.stderr
    regions=[{'start':4096,'end':4100},{'start':4112,'end':4116}]
    if scenario in ('valid','memory'):
        events=parse_capture(trace.read_text(),token,'source',regions,1);assert bool(events)==(scenario=='memory')
    else:
        with pytest.raises(ValueError):parse_capture(trace.read_text(),token,'source',regions,1)


def test_property_comparison_keeps_regions_separate_and_never_hides_failure():
    from riscv2x86_py.l3_program_route import project,comparison
    row={'sample':0,'inputs':['0000000000000001'],'value':'0000000000000001'}
    reports={s:{'events':[],'samples':[dict(row,token=s)],'environment':{}} for s in ('source','target')}
    group={'groupIdentity':identity('capture'),'reports':reports}
    assert comparison(project(group,0))['status']=='verified'
    reports['target']['events']=[{'region':1,'sample':0,'access':'W'}]
    assert comparison(project(group,0))['status']=='verified'
    assert comparison(project(group,1))['status']=='failed'
    reports['target']['samples'][0]['value']='0000000000000002'
    assert comparison(project(group,0))['status']=='failed'


def test_plan_selection_preserves_missing_mechanism_obligations(tmp_path):
    from riscv2x86_py.l3_execution_plan import build
    from riscv2x86_py.l3_mechanism_selection import plan,produce
    from tests.test_l3_scalar_trace import request
    from tests.test_l3_atomic_eligibility import atomic_fixture
    _,findings,fn=fixture(tmp_path)
    p,kind=plan(findings,[fn],{'scalar-program':{}})
    assert p['complete'] and kind=='scalar-program'
    with pytest.raises(ValueError,match='CAPABILITY'):plan(findings,[fn],{'memory':{}})
    atomic,functions=atomic_fixture(tmp_path);p=build([atomic],functions,{'memory','control','scalar-program'})
    assert not p['complete'] and {x['dimension'] for x in p['members'][0]['obligations']['requiredProperties']}=={'access_pattern','synchronization'}
    req=request(atomic);req['candidates'][0]['compilerFunctions']=functions;req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    result=produce(req,{'memory':{}})
    assert not result['profiles'][0]['complete'] and {p['dimension'] for p in result['profiles'][0]['requiredProperties']}=={'access_pattern','synchronization'}


@pytest.mark.parametrize('mutation',[None,'drop-member','context','result','wrong-capture','status'])
def test_audit_consumer_closes_all_members_and_bindings(tmp_path,monkeypatch,mutation):
    # Replayed-capture fixtures test the audit consumer, not real execution.
    from dataclasses import asdict,replace
    from types import SimpleNamespace
    import riscv2x86_py.l3_program_route as route
    import riscv2x86_py.l3_intent_ingress as ingress
    from riscv2x86_py.l3_program_intent import produce
    from riscv2x86_py.l3_program_spec import spec
    from riscv2x86_py.l3_intent_requirements import classify_l3_requirements,parse_l3_intent_profile
    from riscv2x86_py.l3_execution_context import L3ExecutionContext
    from tests.test_l3_scalar_trace import request
    from tests.test_l3_production_ingress import program
    from tests.test_translation_validation import _translation
    _,findings,fn=fixture(tmp_path);s=spec(findings,[fn]);req=request(findings[0]);req['candidates']=[request(f)['candidates'][0] for f in findings]
    for c in req['candidates']:c['compilerFunctions']=[fn]
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'});profiles=produce(req)['profiles']
    for f,p in zip(findings,profiles):f['l3IntentProfile']=p
    manifest=classify_l3_requirements({'findings':findings});report=tmp_path/'translated_report.json';report.write_text(json.dumps({'findings':findings}))
    source,target=program(tmp_path,'source'),program(tmp_path,'target')
    group={'schemaVersion':'fixture','requirements':list(manifest.requirements),'deployment':{'spec':s,'inputs':{'report':str(report),'source':source.artifact_path}},
        'reports':{side:{'events':[],'samples':[{'sample':0,'value':'1','token':side}],'environment':{'side':side}} for side in ('source','target')}}
    group['groupIdentity']=identity(group);path=tmp_path/'group.json';path.write_text(json.dumps(group))
    monkeypatch.setattr(route,'replay_group',lambda g,*args:g)
    monkeypatch.setattr(ingress,'validate_receipt',lambda f,*args:parse_l3_intent_profile(f['l3IntentProfile']))
    value={'status':'verified','sourceProgramArtifact':asdict(source),'targetProgramArtifact':asdict(target),'translationEvaluationLink':{'l3Requirements':manifest.to_dict()},'attempts':[]}
    for i,r in enumerate(manifest.requirements):
        a=replace(_translation(),fragment_id=r['fragmentId'],proof_identity=r['proofIdentity'],effect_relation_set_identity=r['approvedTargetRelationIdentity'])
        idx=[m['fragmentId'] for m in s['members']].index(r['fragmentId']);reports=route.project(group,idx);prior=[SimpleNamespace(evidence_identity=identity(str(n))) for n in range(3)]
        result,cmp=route.fragment_result(r,group,reports,a,source,target,prior);context=L3ExecutionContext.create(source,target)
        d={'programCapturePath':str(path),'programCaptureDigest':route.digest(path),'programCaptureIdentity':group['groupIdentity'],'platformReports':reports,
            'fragmentResult':result,'comparison':cmp,'reasonCodes':cmp['reasonCodes'],'executionBindings':{side:context.request_binding(side) for side in ('source','target')},'physicalMicroarchitectureClaimed':False}
        raw=dict(asdict(a),preservation_mode=a.preservation_mode.value,ignored_source_state=list(a.ignored_source_state))
        layers=[{'level':lev,'status':'verified','evidenceIdentity':prior[n].evidence_identity,'detail':json.dumps({'claimScope':'architectural'})} for n,lev in enumerate(('L0','L1','L2'))]
        layers.append({'level':'L3','status':'verified','evidenceIdentity':identity(d),'detail':json.dumps(d)})
        value['attempts'].append({'fragmentId':r['fragmentId'],'translationArtifact':raw,'status':'verified','validation':{'status':'verified','layers':layers}})
    assert route.audit_result(value)['programExecutionUnitCount']==1
    if mutation is None:return
    if mutation=='drop-member':value['attempts'].pop()
    else:
        layers=value['attempts'][0]['validation']['layers'];d=json.loads(layers[3]['detail'])
        if mutation=='context':d['executionBindings']['source']['invocationId']='changed'
        if mutation=='result':d['fragmentResult']['dimensionResults']={}
        if mutation=='wrong-capture':d['programCaptureIdentity']=identity('wrong')
        if mutation=='status':layers[3]['status']='not_run'
        layers[3]['detail']=json.dumps(d);layers[3]['evidenceIdentity']=identity(d)
    with pytest.raises((ValueError,KeyError)):route.audit_result(value)


@pytest.mark.parametrize('kind',['memory','control','scalar-program','fence'])
def test_common_dispatch_selects_only_proof_bound_mechanism(tmp_path,monkeypatch,kind):
    # Lifecycle dispatch fixture; factories below do not execute an experiment.
    import riscv2x86_py.l3_mechanism_selection as selection
    from riscv2x86_py.translation_validation import ValidationLayerResult,ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    if kind=='scalar-program':_,findings,fn=fixture(tmp_path)
    elif kind=='fence':
        from tests.test_l3_fence_trace import fixture as fence_fixture
        finding,functions=fence_fixture(tmp_path);findings=[finding];fn=functions[0]
    elif kind=='control':
        from tests.test_l3_control_spec import fixture as control_fixture
        finding,fn=control_fixture(tmp_path);findings=[finding]
    else:
        from tests.test_l3_scalar_trace import finding
        findings=[finding(tmp_path)];fn={}
    report=tmp_path/'translated_report.json';report.write_text(json.dumps({'findings':findings}));report.with_name('compiler-candidates.json').write_text(json.dumps({'functions':[fn]}))
    selectors=tmp_path/'selection.json';selectors.write_text('fixture');backend=tmp_path/'backend.json';backend.write_text('fixture')
    monkeypatch.setattr(selection,'load',lambda _: {kind:{'path':str(backend),'digest':selection.digest(backend)}})
    import importlib
    module=importlib.import_module('riscv2x86_py.'+{'memory':'l3_qemu_memory_route','control':'l3_control_route','scalar-program':'l3_program_route','fence':'l3_fence_route'}[kind]);seen=[]
    wanted=ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,detail='dispatch fixture')
    def factory(config):seen.append(config);return lambda **kw:wanted
    monkeypatch.setattr(module,'build_route',factory)
    c={'schemaVersion':'riscv2x86.l3-mechanism-route.v1','selectionPath':str(selectors),'selectionDigest':selection.digest(selectors),
        'routeConfig':{'schemaVersion':'riscv2x86.compiler-region-trace-route.v1','reportPath':str(report),'workDirectory':str(tmp_path/'work/member'),'clang':'compiler'}}
    assert selection.build_route(c)()==wanted
    assert len(seen)==1 and seen[0]['backendPath']==str(backend)
    if kind=='memory':assert 'clang' not in seen[0]
    if kind in {'control','fence'}:assert seen[0]['sampleCount'] is None
    if kind=='scalar-program':assert seen[0]['sampleCount']==8 and Path(seen[0]['workDirectory']).name=='program'


def test_native_direct_jump_and_eliminated_copy_have_different_transfer_witnesses(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    from riscv2x86_py.l3_control_machine import graph
    from riscv2x86_py.l3_control_route import comparison
    observations={}
    import ctypes
    for side,body in [('source','jmp 1f\\n1: movq %1,%0'),('target','movq %1,%0')]:
        c=tmp_path/(side+'.c');binary=tmp_path/(side+'.so')
        c.write_text('unsigned long f(unsigned long x){unsigned long out;__asm__ volatile(".globl begin\\nbegin:\\n'+body+'\\n.globl end\\nend:":"=r"(out):"r"(x));return out;}')
        r=subprocess.run([cc,'-O0','-fPIC','-shared',str(c),'-o',str(binary)],capture_output=True,text=True);assert r.returncode==0,r.stderr
        elf=Elf(binary);a=elf.symbol('begin')[0];end=elf.symbol('end')[0]
        witness=graph(elf.code('f'),elf.symbol('f')[0],{'start':a,'end':end,'exits':[end]},62)
        fun=ctypes.CDLL(str(binary)).f;fun.argtypes=[ctypes.c_ulong];fun.restype=ctypes.c_ulong
        assert fun(2**64-1)==2**64-1
        observations[side]={'controlEvents':[{'continuation':'target','value':'ffffffffffffffff','reasonCodes':[],
            'actualTransferShape':[t['kind'] for t in witness['paths'][0]['transfers']]}],'memory':[]}
    cmp=comparison(observations,{'predicate':None})
    assert cmp['control']['logicalContinuation']=='verified' and cmp['control']['actualTransferShape']=='failed'
