from copy import deepcopy
import json
import subprocess
import shutil
import pytest
from riscv2x86_py.l3_trace_support import identity,Elf
from riscv2x86_py.l3_control_spec import spec,signature,samples,harness,parse_samples
from riscv2x86_py.l3_control_route import observed_events,comparison


def fixture(tmp_path,kind='branch',condition='unsigned_less'):
    from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from tests.test_l2_control_flow_observation import _safe_facts,_finding
    from tests.test_compiler_expression_contracts import ctype
    from riscv2x86_py.compiler_integer_signature import export
    from dataclasses import replace
    names=['out','a','b','t','n'] if kind=='branch' else ['out','a','b'];params=names[1:]
    source=('unsigned long arbitrary('+','.join('unsigned long '+n for n in params)+'){unsigned long out;__asm__ volatile("structured fixture" : "=r"(out) : '+','.join('"r"('+n+')' for n in params)+');return out;}').encode()
    def extent(a,b):return {'begin':{'offset':a,'line':1,'col':a+1},'end':{'offset':b-1,'tokLen':1}}
    def ref(name,pos):return {'kind':'DeclRefExpr','range':extent(pos,pos+len(name)),'referencedDecl':{'id':'ast:'+name},'type':{'qualType':'unsigned long'},'valueCategory':'lvalue'}
    begin=source.index(b'__asm__');end=source.index(b';',begin)+1
    asm={'kind':'GCCAsmStmt','range':extent(begin,end),'numOutputs':1,'outputConstraints':['=r'],
         'inner':[ref(n,source.index(('('+n+')').encode(),begin)+1) for n in names]}
    ast={'kind':'FunctionDecl','name':'arbitrary','range':extent(0,len(source)),'inner':[
        *[{'kind':'ParmVarDecl','id':'ast:'+n,'name':n,'range':extent(source.index(('long '+n).encode())+5,source.index(('long '+n).encode())+5+len(n)),'type':{'qualType':'unsigned long'}} for n in params],
        {'kind':'CompoundStmt','inner':[{'kind':'DeclStmt','inner':[{'kind':'VarDecl','id':'ast:out','name':'out','range':extent(source.index(b'long out'),source.index(b'long out')+8),'type':{'qualType':'unsigned long'}}]},asm,{'kind':'ReturnStmt','inner':[ref('out',source.index(b'out;',end))]}]}]}
    S=identity('source');F=identity('function');boundary=_l2_operand_boundary_facts(ast,source_digest=S,function_identity=F,source_file='/tmp/arbitrary.c',source_bytes=source)
    raw=boundary['fragmentCandidates'][0];fid='/tmp/arbitrary.c:1:'+str(begin+1)
    facts=_safe_facts(fid,kind)
    if kind=='branch':facts=replace(facts,condition_kind=condition,facts_identity='')
    f=_finding(fid,'arbitrary',names,facts);fragment=f['fragment']
    fragment.update(file='/tmp/arbitrary.c',line=1,column=begin+1,beginOffset=begin,endOffset=end)
    for operand,n in zip(fragment['outputs']+fragment['inputs'],names):operand.update(compilerType=ctype(),exprText=n)
    closed=close_compiler_fragment_candidate(raw,fragment,source_digest=S,function_identity=F)
    authority={'schemaVersion':'riscv2x86.compiler-fragment-authority.v2','sourceDigest':S,'functionIdentity':F,'fragmentId':fid,'targetTriple':'riscv64-linux-gnu','fragmentBindingKey':raw['fragmentBindingKey'],'candidate':closed,
      'compilerTypeBindings':{str(b['operandIndex']):{'operandIndex':b['operandIndex'],'valueNodeIdentity':b['valueNodeIdentity'],'compilerType':ctype()} for b in closed['operandBindings']}}
    authority['authorityIdentity']=identity(authority);fragment['compilerFragmentAuthority']=authority
    fn={'name':'arbitrary','functionId':F,'sourceDigest':S,'sourceFile':'/tmp/arbitrary.c','arity':len(params),'parameterTypes':['unsigned long']*len(params),'returnType':'unsigned long','l2OperandBoundary':boundary}
    scope={'schemaVersion':'riscv2x86.compiler-atomic-function-scope.v1','sourceDigest':S,'functionIdentity':F,'asmBegin':begin,'asmEnd':end-1,'scope':'single_asm_no_other_memory_or_control_effects'}
    fn['compilerAtomicFunctionScope']=dict(scope,scopeIdentity=identity(scope));fn['compilerIntegerCallSignature']=export(fn,fn['parameterTypes'],fn['returnType'],lambda t:t)
    front=tmp_path/'frontend';front.write_text('fixture');assert materialize_automatic_l2_authority({'findings':[f]},[fn],front)==1
    f.update(translationOutcome='emitted',sourceDigest=S)
    return f,fn


@pytest.mark.parametrize('kind,cond',[('branch','unsigned_less'),('branch','equal'),('branch','not_equal'),('jump','')])
def test_proof_bound_spec_and_observed_coverage_plan(tmp_path,kind,cond):
    from riscv2x86_py.l3_control_intent import produce
    from tests.test_l3_scalar_trace import request
    f,fn=fixture(tmp_path,kind,cond);s=spec(f,[fn]);call=signature(fn);plan=samples(s,call)
    assert s['requiredControlObligations']==['logical-continuation','actual-transfer-shape']
    assert len(plan['inputs'])>=5
    req=request(f);req['candidates'][0]['compilerFunctions']=[fn];req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    response=produce(req);assert response['profiles'][0]['complete'] and not response['dispositions']
    assert [x['dimension'] for x in response['profiles'][0]['requiredProperties']]==['control_flow','access_pattern']


@pytest.mark.parametrize('mutation',['proof','function','scope','authority','effect','binding'])
def test_changed_bound_facts_do_not_enable_control(tmp_path,mutation):
    f,fn=fixture(tmp_path)
    if mutation=='proof':f['approvalArtifact']['proofIdentity']=identity('wrong')
    if mutation=='function':fn['functionId']=identity('wrong')
    if mutation=='scope':fn['compilerAtomicFunctionScope']['scope']='unproved'
    if mutation=='authority':f['approvalArtifact']['l2AuthoritySidecar']['complete']=False
    if mutation=='effect':f['approvalArtifact']['l2EffectProofFacts']['sourceEffects']=[]
    if mutation=='binding':f['fragment']['compilerFragmentAuthority']['compilerTypeBindings']['1']['compilerType']['widthBits']=32
    with pytest.raises((ValueError,KeyError,TypeError)):spec(f,[fn])


def test_native_control_call_plan_covers_equality_and_preserves_types(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    f,fn=fixture(tmp_path,condition='equal');control=spec(f,[fn]);call=signature(fn);plan=samples(control,call)
    c=tmp_path/'h.c';exe=tmp_path/'run'
    c.write_text(harness('arbitrary',call,plan)+'unsigned long arbitrary(unsigned long a,unsigned long b,unsigned long t,unsigned long n){return a==b?t:n;}')
    built=subprocess.run([cc,'-Wall','-Wextra','-Werror','-fsanitize=undefined',str(c),'-o',str(exe)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    run=subprocess.run([str(exe),'a'*64],capture_output=True,text=True)
    assert run.returncode==0 and not run.stderr
    rows=parse_samples(run.stdout,'a'*64,plan)
    assert {int(r['inputs'][0],16)==int(r['inputs'][1],16) for r in rows}=={True,False}
    for r in rows:assert r['value']==r['inputs'][2 if r['inputs'][0]==r['inputs'][1] else 3]
    with pytest.raises(ValueError):parse_samples(run.stdout,'b'*64,plan)


def test_asm_goto_zero_byte_continuation_markers_native(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    from riscv2x86_py.l3_control_deployment import instrument,label_assembly,region_of
    from riscv2x86_py.l3_control_machine import graph
    source=b'unsigned long f(unsigned long x){__asm__ goto("testq %0,%0; je %l[taken]":::"cc":taken);return 0;taken:return 1;}'
    source=source.replace(b':::"cc"',b'::"r"(x):"cc"')
    original=tmp_path/'original.c';original.write_bytes(source)
    old=tmp_path/'old.so';r=subprocess.run([cc,'-O0','-fPIC','-shared',str(original),'-o',str(old)],capture_output=True,text=True);assert r.returncode==0,r.stderr
    sites={'fallthroughBegin':source.index(b'return 0'),'labels':[{'label':'taken','statementBegin':source.index(b'return 1')}]};sites['siteFactsIdentity']=identity(sites)
    marked_c=tmp_path/'marked.c';marked_c.write_bytes(instrument(source,sites));assembly=tmp_path/'c.s'
    r=subprocess.run([cc,'-O0','-fPIC','-S',str(marked_c),'-o',str(assembly)],capture_output=True,text=True);assert r.returncode==0,r.stderr
    asm=tmp_path/'m.s';asm.write_text(label_assembly(assembly.read_text(),True));new=tmp_path/'new.so'
    r=subprocess.run([cc,'-shared',str(asm),'-o',str(new)],capture_output=True,text=True);assert r.returncode==0,r.stderr
    a,b=Elf(old),Elf(new);assert a.code('f')==b.code('f')
    region=region_of(b,'f',True);g=graph(b.code('f'),b.symbol('f')[0],region,62)
    assert len(g['paths'])==2 and len({p['exit'] for p in g['paths']})==2


def test_jump_elimination_is_counterexample_not_unsupported():
    source={'controlEvents':[{'continuation':'target','value':'0000000000000001','reasonCodes':[],'actualTransferShape':['direct']}],'memory':[]}
    target=deepcopy(source);target['controlEvents'][0]['actualTransferShape']=[]
    cmp=comparison({'source':source,'target':target},{'predicate':None})
    assert cmp['control']['logicalContinuation']=='verified'
    assert cmp['control']['actualTransferShape']=='failed' and cmp['control']['status']=='failed'
    assert cmp['memory']['status']=='verified'


@pytest.mark.parametrize('eliminated',[False,True])
def test_property_results_close_against_external_requirements(tmp_path,eliminated):
    from types import SimpleNamespace
    from riscv2x86_py.l3_control_route import dimensions
    from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
    from riscv2x86_py.l3_evidence_closure import validate_fragment_against_requirement
    from riscv2x86_py.l3_control_intent import produce
    from tests.test_l3_scalar_trace import request
    f,fn=fixture(tmp_path,'jump');s=spec(f,[fn]);req=request(f)
    req['candidates'][0]['compilerFunctions']=[fn]
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    f['l3IntentProfile']=produce(req)['profiles'][0]
    manifest=classify_l3_requirements({'findings':[f]})
    external=manifest.requirements[0]
    source={'controlEvents':[{'continuation':'target','value':'0000000000000001','reasonCodes':[],'actualTransferShape':['direct']}],
            'memory':[],'environment':{'side':'source'}}
    target=deepcopy(source);target['environment']={'side':'target'}
    if eliminated:target['controlEvents'][0]['actualTransferShape']=[]
    reports={'source':source,'target':target}
    artifact=SimpleNamespace(identity=identity('artifact'))
    program=SimpleNamespace(artifact_digest=identity('program'))
    prior=[SimpleNamespace(evidence_identity=identity(str(i))) for i in range(3)]
    result,cmp=dimensions({'requirement':external,'deployment':{'spec':s,'deploymentIdentity':identity('deployment')},'contractIdentity':identity('contract')},
        reports,{'source':{'contextIdentity':identity('context')}},artifact,program,program,prior,'architectural')
    assert result['status']==('failed' if eliminated else 'verified')
    assert validate_fragment_against_requirement(result,external,source_report=source,target_report=target)==result


@pytest.mark.parametrize('kind,swapped,inverted',[
    ('equal','equal',False),('not_equal','equal',True),
    ('signed_greater','signed_less',False),('signed_less_equal','signed_less',True),
    ('unsigned_greater_equal','unsigned_less',True)])
def test_predicate_normalization_preserves_inversion_and_signedness(kind,swapped,inverted):
    from riscv2x86_py.l3_control_route import predicate_normal
    original={'kind':kind,'left':'parameter:0','right':'parameter:1'}
    (normalized,left,right),negative=predicate_normal(original)
    assert normalized==swapped and negative==inverted
    from riscv2x86_py.l3_control_machine import condition,value_of
    for inputs in ([0,0],[0,1],[2**64-1,1],[2**63,2**63-1]):
        assert condition(kind,*inputs)==(condition(normalized,value_of(left,inputs),value_of(right,inputs)) ^ negative)
