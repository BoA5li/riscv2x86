"""Joint proof fixtures and real native execution; not dual-ISA acceptance."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py.l3_trace_support import identity,Elf


def fixture(tmp_path,pointer=0,scalar_template='movq %1,%0;addq %2,%0',value_program=None,include_fence=False,width=8,sign_extend=False,signed_object=False):
    from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts,_source_range
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
    from riscv2x86_py.compiler_memory_signature import export as signature
    from riscv2x86_py.compiler_joint_scope import export
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from tests.test_compiler_expression_contracts import ctype
    from tests.l2_profile_fixtures import profile_dict
    from tests.l2_effect_proof_fixtures import attach_effect_proof
    from tests.test_l2_memory_object_observation import _facts
    from riscv2x86_py.l2_effect_proof import effect_proof_facts_from_dict
    from riscv2x86_py.l2_semantic_profile import L2PatternKind,L2MemoryShape,l2_fragment_semantic_profile_from_dict
    pointee={1:'signed char' if signed_object else 'unsigned char',2:'short' if signed_object else 'unsigned short',4:'int' if signed_object else 'unsigned int',8:'long' if signed_object else 'unsigned long'}[width]
    args='unsigned long *address,unsigned long input' if pointer==0 else 'unsigned long input,unsigned long *address'
    source=('unsigned long unrelated('+args+'){unsigned long loaded;unsigned long result;'
        '__asm__ volatile("movq 8(%1),%0":"=r"(loaded):"r"(address):"memory");'
        '__asm__ volatile("'+scalar_template+'":"=&r"(result):"r"(loaded),"r"(input):"cc");'
        '__asm__ volatile("movq %0,16(%1)"::"r"(result),"r"(address):"memory");return result;}').encode()
    if width!=8:
        load={1:'movsbq' if sign_extend else 'movzbq',2:'movswq' if sign_extend else 'movzwq',4:'movslq' if sign_extend else 'movl'}[width]
        dest='%k0' if width==4 and not sign_extend else '%0'
        source=source.replace(b'movq 8(%1),%0',(load+' 8(%1),'+dest).encode()).replace(b'movq %0,16(%1)',('mov'+{1:'b',2:'w',4:'l'}[width]+' %'+{1:'b',2:'w',4:'k'}[width]+'0,16(%1)').encode())
    source=source.replace(b'unsigned long *address',(pointee+' *address').encode())
    if include_fence:
        source=source.replace(b'__asm__ volatile("'+scalar_template.encode(),b'__asm__ volatile("mfence"::: "memory");__asm__ volatile("'+scalar_template.encode())
    def extent(a,b):return {'begin':{'offset':a,'line':1,'col':a+1},'end':{'offset':b-1,'tokLen':1}}
    types={'address':pointee+' *','input':'unsigned long','loaded':'unsigned long','result':'unsigned long'}
    pointertype=ctype(canonicalType=pointee+' *',isPointer=True,isInteger=False,pointeeType=pointee,pointeeWidthBits=width*8,pointeeAlignmentBytes=width,pointeeIsInteger=True,expressionRepeatable=True)
    def ref(n,p):return {'kind':'DeclRefExpr','range':extent(p,p+len(n)),'referencedDecl':{'id':'ast:'+n},'type':{'qualType':types[n]},'valueCategory':'lvalue'}
    starts=[];pos=0
    while True:
        pos=source.find(b'__asm__',pos)
        if pos<0:break
        starts.append(pos);pos+=1
    # Compiler token ranges, not source parsing, define statement placement.
    ends=[source.index(b');',a)+1 for a in starts]
    names=[(['loaded'],['address']),(['result'],['loaded','input']),([],['result','address'])]
    if include_fence:names.insert(1,([],[]))
    asms=[]
    for a,b,(outs,ins) in zip(starts,ends,names):
        asms.append({'kind':'GCCAsmStmt','range':extent(a,b),'numOutputs':len(outs),'outputConstraints':['=&r' if outs==['result'] else '=r'] if outs else [],
            'inner':[ref(n,source.index(('('+n+')').encode(),a)+1) for n in outs+ins]})
    params=[]
    for name in (('address','input') if pointer==0 else ('input','address')):
        a=source.index(name.encode());params.append({'kind':'ParmVarDecl','id':'ast:'+name,'name':name,'type':{'qualType':types[name]},'range':extent(a,a+len(name))})
    decls=[]
    for n in ('loaded','result'):
        a=source.index(('long '+n).encode());decls.append({'kind':'DeclStmt','inner':[{'kind':'VarDecl','id':'ast:'+n,'name':n,'type':{'qualType':types[n]},'range':extent(a,a+5+len(n))}]})
    ret=source.index(b'return result');ast={'kind':'FunctionDecl','name':'unrelated','type':{'qualType':'unsigned long ('+','.join(types[n] for n in (('address','input') if pointer==0 else ('input','address')))+')'},'range':extent(0,len(source)),
        'inner':params+[{'kind':'CompoundStmt','inner':decls+asms+[{'kind':'ReturnStmt','range':extent(ret,ret+13),'inner':[ref('result',ret+7)]}]}]}
    S=identity(source.decode());F=identity('joint-fixture-function');path=tmp_path/'joint.c'
    boundary=_l2_operand_boundary_facts(ast,source_digest=S,function_identity=F,source_file=str(path),source_bytes=source,type_resolver=lambda t:t)
    fn={'name':'unrelated','functionId':F,'sourceDigest':S,'sourceFile':str(path),'arity':2,'parameterTypes':[types[p['name']] for p in params],
        'returnType':'unsigned long','pointerParameters':[pointer],'l2OperandBoundary':boundary}
    fn['compilerMemoryCallSignature']=signature(fn,fn['parameterTypes'],fn['returnType'],lambda t:t)
    fn['compilerJointScope']=export(ast,source_digest=S,function_identity=F,source_range=_source_range,resolve=lambda t:t)
    findings=[]
    for index,(raw,a,b,(outs,ins)) in enumerate(zip(boundary['fragmentCandidates'],starts,ends,names)):
        fid=str(path)+':1:'+str(a+1)
        def operand(n,out):return {'constraint':'=&r' if out and n=='result' else '=r' if out else 'r','exprText':n,'compilerType':pointertype if n=='address' else ctype()}
        frag={'id':fid,'enclosingFunction':'unrelated','file':str(path),'line':1,'column':a+1,'beginOffset':a,'endOffset':b,
            'outputs':[operand(n,True) for n in outs],'inputs':[operand(n,False) for n in ins],'clobbers':['cc'] if outs==['result'] else ['memory']}
        closed=close_compiler_fragment_candidate(raw,frag,source_digest=S,function_identity=F)
        authority={'schemaVersion':'riscv2x86.compiler-fragment-authority.v2','sourceDigest':S,'functionIdentity':F,'fragmentId':fid,'targetTriple':'riscv64-linux-gnu','fragmentBindingKey':raw['fragmentBindingKey'],'candidate':closed,
            'compilerTypeBindings':{str(v['operandIndex']):{'operandIndex':v['operandIndex'],'valueNodeIdentity':v['valueNodeIdentity'],'compilerType':pointertype if (outs+ins)[v['operandIndex']]=='address' else ctype()} for v in closed['operandBindings']}}
        authority['authorityIdentity']=identity(authority);frag['compilerFragmentAuthority']=authority
        role='fence' if include_fence and index==1 else 'load' if index==0 else 'store' if index==len(names)-1 else 'scalar'
        kind={'load':L2PatternKind.MEMORY_LOAD,'scalar':L2PatternKind.SCALAR,'store':L2PatternKind.MEMORY_STORE,'fence':L2PatternKind.FENCE}[role]
        if role=='scalar' and value_program is not None:kind=L2PatternKind.COMPOSITE
        profile=l2_fragment_semantic_profile_from_dict(profile_dict(fid,kind))
        if role in {'load','store'}:profile=replace(profile,memory_shape=L2MemoryShape(role=='load',role=='store',False,False,True),profile_identity='')
        if role=='fence':
            from tests.test_l2_fence_ordering_relations import _profile
            profile=_profile(fid)
        f={'fragment':frag,'sourceDigest':S,'translationOutcome':'emitted','rewriteBeginOffset':a,'rewriteEndOffset':b+1,'rawSourceText':source[a:b+1].decode(),
            'approvalArtifact':{'proofStatus':'approved','architectureSemanticsPreserved':True,'shellSemanticsPreserved':True,'planId':S,'constraintsId':F},'l2SemanticProfile':profile.to_dict()}
        attach_effect_proof(f['approvalArtifact'],fid,'scalar' if role=='scalar' else 'memory')
        if role=='fence':
            # Rebuild identity-bearing facts for this compiler-bound member.
            from tests.test_l2_fence_ordering_relations import _facts as fence_facts,_finding
            facts=fence_facts(fragment_id=fid,source_hardware_ordering=True,source_ordering='rw_rw',source_scope='system',target_ordering='rw_rw',relation_kind='exact',target_semantic_contract_id='x86.gnu-att.mfence.ordinary-rw.v2')
            approval=_finding(facts)['approvalArtifact']
            proof=effect_proof_facts_from_dict(approval['l2EffectProofFacts'])
            approval['l2EffectProofFacts']=replace(proof,source_effects=tuple(sorted(proof.source_effects,key=lambda e:e.effect_id)),target_effects=tuple(sorted(proof.target_effects,key=lambda e:e.effect_id)),relations=tuple(sorted((replace(r,relation_kind='exact') for r in proof.relations),key=lambda r:r.relation_id))).to_dict()
            f['approvalArtifact']=approval
        if role=='scalar' and value_program is not None:
            from .test_versioned_gpr_program import _ID
            from riscv2x86_py.versioned_program_contract import export as export_boundary
            a=f['approvalArtifact'];a.update(sourceModelId=S,rendererSemanticContractId=_ID)
            a['l2VersionedProgramBoundary']=export_boundary(value_program,a,fid)
        if role in {'load','store'}:
            facts=_facts(fragment_id=fid,access_kind=role,byte_offset=8 if role=='load' else 16,value_operand_index=0,address_operand_index=1)
            if width!=8:
                facts=replace(facts,width_bytes=width,required_alignment=width,carrier_width_bits=64,value_projection=('sign_extend' if sign_extend else 'zero_extend') if role=='load' else 'low_bits',schema_version='riscv2x86.l2-memory-proof-facts.v4' if role=='load' else 'riscv2x86.l2-memory-proof-facts.v3',facts_identity='')
            f['approvalArtifact']['l2MemoryProofFacts']=facts.to_dict()
            if role=='store':
                ef=effect_proof_facts_from_dict(f['approvalArtifact']['l2EffectProofFacts'])
                f['approvalArtifact']['l2EffectProofFacts']=replace(ef,source_effects=tuple(replace(e,effect_kind='WriteMemory') for e in ef.source_effects),target_effects=tuple(replace(e,effect_kind='WriteMemory') for e in ef.target_effects)).to_dict()
        findings.append(f)
    front=tmp_path/'frontend';front.write_text('fixture')
    assert fn['compilerJointScope'] is not None
    count=materialize_automatic_l2_authority({'findings':findings},[fn],front)
    assert count==len(names),[(f['approvalArtifact'].get('l2AuthorityMaterializationReasonCode'),f['approvalArtifact'].get('l2ScalarAuthorityDecision'),f['approvalArtifact']['l2FragmentOperandBoundary'].get('reasonCodes')) for f in findings]
    return source,findings,fn


def test_joint_spec_and_planning_replay_all_members(tmp_path):
    from riscv2x86_py.l3_joint_spec import spec
    from riscv2x86_py.l3_mechanism_selection import plan
    source,findings,fn=fixture(tmp_path)
    p=spec(findings,[fn]);assert len(p['members'])==3
    selected,kind=plan(findings,[fn],{'joint':{}})
    assert kind=='joint' and selected['complete'] and all(m['obligations']['requiredProperties'] for m in selected['members'])
    with pytest.raises(ValueError):plan(findings,[fn],{'memory':{}})


@pytest.mark.parametrize('pointer',[0,1])
def test_native_whole_call_snapshots_and_original_machine_bytes(tmp_path,pointer):
    from riscv2x86_py.l3_joint_spec import spec,sample_plan
    from riscv2x86_py.l3_joint_observation import harness,instrument,parse_l2,parse_samples
    from riscv2x86_py.l3_joint_deployment import instrument as markers,label_assembly
    source,findings,fn=fixture(tmp_path,pointer);p=spec(findings,[fn]);plan=sample_plan(p)
    h=tmp_path/'harness.c';h.write_text(harness(p,plan));c=tmp_path/'variant.c';c.write_bytes(instrument(source,p['scope']['sites'],p));exe=tmp_path/'variant'
    done=subprocess.run([shutil.which('gcc'),'-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(h),str(c),'-o',str(exe)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    r=subprocess.run([str(exe),'a'*64],capture_output=True,text=True);assert r.returncode==0
    observed=parse_l2(r.stdout,'a'*64,p,plan)
    assert len(observed['boundaries'])==48 and len(observed['samples'])==8
    original=tmp_path/'original.c';original.write_bytes(source);binary=tmp_path/'original'
    done=subprocess.run([shutil.which('gcc'),'-std=gnu11','-O0','-Wall','-Wextra','-Werror',str(h),str(original),'-o',str(binary)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    raw=subprocess.run([str(binary),'a'*64],capture_output=True,text=True);rows=parse_samples(raw.stdout,'a'*64,p,plan)
    assert observed['samples']==[{k:v for k,v in x.items() if k not in {'token','objectBase'}} for x in rows]
    for sample,row in enumerate(rows):
        initial=bytes.fromhex(plan['inputs'][sample]['initialObjectHex']);inp=int(plan['inputs'][sample]['arguments'][1-pointer],16)
        expected=(int.from_bytes(initial[8:16],'little')+inp)&((1<<64)-1)
        assert int(row['value'],16)==expected
        assert int.from_bytes(bytes.fromhex(row['objectHex'])[16:24],'little')==expected
    for label,data in [('plain',source),('marked',markers(source,p['scope']['sites']))]:
        c=tmp_path/(label+'.c');c.write_bytes(data);asm=tmp_path/(label+'.s');obj=tmp_path/(label+'.o')
        done=subprocess.run([shutil.which('gcc'),'-O0','-fPIC','-S',str(c),'-o',str(asm)],capture_output=True,text=True);assert done.returncode==0,done.stderr
        if label=='marked':asm.write_text(label_assembly(asm.read_text(),3))
        done=subprocess.run([shutil.which('gcc'),'-c',str(asm),'-o',str(obj)],capture_output=True,text=True);assert done.returncode==0,done.stderr
    assert Elf(tmp_path/'plain.o').code('unrelated')==Elf(tmp_path/'marked.o').code('unrelated')
    missing=r.stdout.splitlines();del missing[2]
    with pytest.raises(ValueError):parse_l2('\n'.join(missing),'a'*64,p,plan)


@pytest.mark.parametrize('change',['missing','proof','scope','object','return','uninitialized','pointer-write','synchronization','mixed-width'])
def test_joint_spec_refuses_missing_or_uncovered_authority(tmp_path,change):
    from riscv2x86_py.l3_joint_spec import spec
    source,findings,fn=fixture(tmp_path)
    if change=='missing':findings.pop()
    if change=='proof':findings[1]['approvalArtifact']['proofIdentity']=identity('wrong')
    if change=='scope':fn['compilerJointScope']['sites'].pop()
    if change=='object':findings[2]['approvalArtifact']['l2AuthoritySidecar']['memoryObjects'][0]['sizeBytes']=16
    if change=='return':fn['l2OperandBoundary']['returnDeclarationId']='absent'
    if change=='uninitialized':findings.reverse();fn['compilerJointScope']['sites'].reverse()
    if change=='pointer-write':findings[0]['fragment']['inputs'][0]['constraint']='+r'
    if change=='synchronization':findings[1]['l2SemanticProfile']['patternKind']='fence'
    if change=='mixed-width':findings[0]['approvalArtifact']['l2MemoryProofFacts']['widthBytes']=4
    with pytest.raises((ValueError,KeyError,TypeError)):spec(findings,[fn])


@pytest.mark.parametrize('change',['offset','width','direction','extra','missing','output','sample'])
def test_comparison_rejects_mutated_real_call_evidence(tmp_path,change):
    from riscv2x86_py.l3_joint_spec import spec,sample_plan
    from riscv2x86_py.l3_joint_observation import harness,parse_samples
    from riscv2x86_py.l3_joint_route import project,comparison
    source,findings,fn=fixture(tmp_path);p=spec(findings,[fn]);plan=sample_plan(p)
    c=tmp_path/'original.c';c.write_bytes(source);h=tmp_path/'h.c';h.write_text(harness(p,plan));exe=tmp_path/'native'
    done=subprocess.run([shutil.which('gcc'),'-O0',str(h),str(c),'-o',str(exe)],capture_output=True,text=True);assert done.returncode==0,done.stderr
    r=subprocess.run([str(exe),'a'*64],capture_output=True,text=True);rows=parse_samples(r.stdout,'a'*64,p,plan)
    events=[{'sample':i,'region':region,'pc':100+region,'address':int(row['objectBase'],16)+offset,'size':8,'access':access}
        for i,row in enumerate(rows) for region,offset,access in ((0,8,'read'),(2,16,'write'))]
    group={'groupIdentity':identity('group'),'deployment':{'spec':p},'reports':{s:{'events':deepcopy(events),'samples':deepcopy(rows),'environment':{}} for s in ('source','target')}}
    assert all(comparison(project(group,i))['status']=='verified' for i in range(3))
    target=group['reports']['target'];e=target['events'][0]
    if change=='offset':e['address']+=8
    if change=='width':e['size']=4
    if change=='direction':e['access']='write'
    if change=='extra':target['events'].append(deepcopy(e))
    if change=='missing':target['events'].pop(0)
    if change=='output':target['samples'][0]['value']='ffffffffffffffff'
    if change=='sample':e['sample']=99
    assert comparison(project(group,0))['status']=='failed'


def test_joint_receipts_preserve_all_requirements_and_static_assessment(tmp_path):
    from riscv2x86_py.l3_joint_intent import produce
    from riscv2x86_py.l3_capability_assessment import assess
    from tests.test_l3_scalar_trace import request
    from riscv2x86_py.l3_intent_requirements import _hash
    _,findings,fn=fixture(tmp_path);value=request(findings[0]);value['candidates']=[request(f)['candidates'][0] for f in findings]
    for c in value['candidates']:c['compilerFunctions']=[fn]
    value['requestIdentity']=_hash({k:v for k,v in value.items() if k!='requestIdentity'})
    result=produce(value)
    assert len(result['profiles'])==3 and all(p['complete'] for p in result['profiles'])
    assert len({p['observationBoundary']['identity'] for p in result['profiles']})==1
    assessment=assess(findings,[fn],{'joint'})
    assert assessment['staticPrerequisitesComplete']
    assert not assessment['semanticApproval'] and not assessment['productionAcceptanceComplete']
    assert set(assessment['runtimeStages'].values())=={'not_run'}
    value['candidates'].pop();value['requestIdentity']=_hash({k:v for k,v in value.items() if k!='requestIdentity'})
    result=produce(value);assert not any(p['complete'] for p in result['profiles'])


@pytest.mark.parametrize('access',['read','write'])
def test_actual_program_plugin_callback_handles_joint_memory(tmp_path,access):
    from tests.test_l3_control_backend import HEADER
    from riscv2x86_py.l3_joint_backend import parse_capture
    header=tmp_path/'include/qemu/qemu-plugin.h';header.parent.mkdir(parents=True);header.write_text(HEADER)
    plugin=Path(__file__).resolve().parents[2]/'runtime/l3_qemu_program_trace.c'
    src=tmp_path/'callback.c';binary=tmp_path/'callback';trace=tmp_path/'trace';token='a'*64
    info=3 if access=='read' else 259
    src.write_text('#include "'+str(plugin)+'"\nint main(void){qemu_info_t i={false,"riscv64"};char *args[]={"regions=0x1000:0x1004;0x1010:0x1014","output='+str(trace)+'","token='+token+'"};if(qemu_plugin_install(1,&i,3,args))return 2;instruction(0,(void*)0x1000);memory(0,'+str(info)+',0x2000,(void*)0x1000);instruction(0,(void*)0x1004);instruction(0,(void*)0x1010);instruction(0,(void*)0x1014);finish(1,NULL);return 0;}')
    done=subprocess.run([shutil.which('gcc'),'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(header.parents[1]),str(src),'-o',str(binary)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    run=subprocess.run([str(binary)],capture_output=True,text=True);assert run.returncode==0
    events=parse_capture(trace.read_text(),token,'source',[{'start':0x1000,'end':0x1004},{'start':0x1010,'end':0x1014}],1)
    assert len(events)==1 and events[0]['size']==8 and events[0]['access']=={'read':'R','write':'W'}[access]


def test_native_write_calibration_is_real_executable_code(tmp_path):
    from riscv2x86_py.l3_joint_backend import probe,regions_of
    for kind in ('empty','read','write','skip','fence','nop-fence'):
        asm=tmp_path/(kind+'.S');binary=tmp_path/kind;asm.write_text(probe('target',kind))
        done=subprocess.run([shutil.which('gcc'),'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',str(asm),'-o',str(binary)],capture_output=True,text=True)
        assert done.returncode==0,done.stderr
        assert subprocess.run([str(binary)],check=False).returncode==0
        elf=Elf(binary);r=regions_of(elf);assert len(r)==2
        if kind in {'fence','nop-fence'}:
            from riscv2x86_py.l3_fence_machine import region_mechanism
            assert (region_mechanism(elf,r[1])['kind']=='ordinary-rw-fence')==(kind=='fence')
        if kind=='write':
            start,_,section,_=elf.symbol('b1');sec=elf.sections[section]
            code=elf.data[sec[4]+start-sec[3]:sec[4]+r[1]['end']-sec[3]]
            assert b'\x48\x89\x07' in code


@pytest.mark.parametrize('change',['return','boundary','truncated'])
def test_complete_semantic_counterexamples_are_distinct_from_missing_evidence(tmp_path,change):
    from riscv2x86_py.l3_joint_spec import spec,sample_plan
    from riscv2x86_py.l3_joint_observation import harness,instrument,parse_l2,JointSemanticMismatch
    source,findings,fn=fixture(tmp_path);p=spec(findings,[fn]);plan=sample_plan(p)
    h=tmp_path/'h.c';h.write_text(harness(p,plan));c=tmp_path/'c.c';c.write_bytes(instrument(source,p['scope']['sites'],p));exe=tmp_path/'run'
    build=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(h),str(c),'-o',str(exe)],capture_output=True,text=True)
    assert build.returncode==0,build.stderr
    lines=subprocess.run([str(exe),'a'*64],capture_output=True,text=True,check=True).stdout.splitlines()
    if change=='truncated':
        lines.pop(0)
        with pytest.raises(ValueError) as error:parse_l2('\n'.join(lines),'a'*64,p,plan)
        assert not isinstance(error.value,JointSemanticMismatch)
    else:
        if change=='return':
            i=next(i for i,line in enumerate(lines) if line.startswith('{'))
            row=json.loads(lines[i]);row['value']=f'{int(row["value"],16)^1:016x}';lines[i]=json.dumps(row)
        else:
            parts=lines[1].split();parts[5]=f'{int(parts[5],16)^1:016x}';lines[1]=' '.join(parts)
        with pytest.raises(JointSemanticMismatch) as error:parse_l2('\n'.join(lines),'a'*64,p,plan)
        assert len(error.value.observation['boundaries'])==48
        assert len(error.value.observation['samples'])==8


def test_raw_memory_direction_is_normalized_at_platform_boundary(tmp_path):
    from riscv2x86_py.l3_joint_route import platform
    executable=tmp_path/'executor';executable.write_bytes(b'executor')
    b={'backendIdentity':'backend','sourceExecutor':str(executable),'sourceRunnerArguments':[]}
    d={'deploymentIdentity':'deployment'}
    raw=[{'access':'R','region':0},{'access':'W','region':2}]
    result=platform('source',b,d,raw,[],{})
    assert [e['access'] for e in result['events']]==['read','write']
    assert [e['access'] for e in raw]==['R','W']
    with pytest.raises(KeyError):platform('source',b,d,[{'access':'unknown'}],[],{})


@pytest.mark.parametrize('shape',['pointer-first','pointer-last','initializer','call'])
def test_real_compiler_joint_scope_requires_direct_typed_shell(tmp_path,shape):
    import os
    from riscv2x86_py.automatic_batch_cli import inspect_entry_points
    clang=os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    if not clang or not Path(clang).is_file():pytest.skip('real Clang AST inspection unavailable')
    args='unsigned long *address,unsigned long input' if shape!='pointer-last' else 'unsigned long input,unsigned long *address'
    body=('unsigned long loaded'+('=0' if shape=='initializer' else '')+',result;'
        '__asm__ volatile("ld %0,8(%1)":"=r"(loaded):"r"(address):"memory");'
        '__asm__ volatile("add %0,%1,%2":"=r"(result):"r"(loaded),"r"(input));'
        '__asm__ volatile("sd %0,16(%1)"::"r"(result),"r"(address):"memory");'
        +('result=external(result);' if shape=='call' else '')+'return result;')
    source=tmp_path/'scope.c';source.write_text(('extern unsigned long external(unsigned long);' if shape=='call' else '')+'unsigned long inspect_me('+args+'){'+body+'}')
    _,functions=inspect_entry_points(source,clang=clang)
    assert len(functions)==1
    scope=functions[0].get('compilerJointScope')
    if shape in {'initializer','call'}:assert scope is None
    else:
        assert scope['pointerParameter']==int(shape=='pointer-last')
        assert len(scope['sites'])==3
