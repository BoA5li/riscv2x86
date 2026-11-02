"""Native/authority fixtures for the compiler-driven register-call contract.

These tests do not claim RISC-V/QEMU production execution.
"""
from copy import deepcopy
import json
import subprocess
import pytest
from riscv2x86_py.l3_trace_support import identity,Elf
from riscv2x86_py.atomic_call_contract import bind,argument_values
from riscv2x86_py.compiler_memory_signature import export
from tests.test_l3_lrsc_persistence import approved_spec


def extend_call(finding,functions,n,pointer,value):
    fn=functions[0];boundary=fn['l2OperandBoundary'];old=boundary['parameterDeclarationIds']
    types=['uint32_t' if i%2 else 'uint64_t' for i in range(n)]
    types[pointer]=fn['parameterTypes'][0];types[value]='uint64_t'
    decls=[identity({'auxiliary':i}) for i in range(n)]
    decls[pointer]=old[0];decls[value]=old[1]
    boundary['parameterDeclarationIds']=decls
    for i,d in enumerate(decls):
        if d not in boundary['declarations']:boundary['declarations'][d]={'name':'aux'+str(i),'type':types[i]}
    fn.update(arity=n,parameterTypes=types,pointerParameters=[pointer])
    def resolve(t):
        return {'uint64_t':'unsigned long','uint32_t':'unsigned int'}.get(t,t)
    fn['compilerMemoryCallSignature']=export(fn,types,fn['returnType'],resolve)
    return fn


def fresh_spec(tmp_path,width,n,pointer,value):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    from riscv2x86_py.l3_lrsc_spec import spec
    from riscv2x86_py.l3_trace_support import digest
    f,functions,_=approved_spec(tmp_path,width,'fetch_xor')
    fn=extend_call(f,functions,n,pointer,value)
    frontend=tmp_path/'call-frontend';frontend.write_text('compiler call fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},functions,frontend)==1
    program=identity({'schemaVersion':'riscv2x86.automatic-program.v1','producerDigest':digest(frontend)})
    boundaries,_,_=materialize_fragment_execution_authority([f],fn,program)
    f['approvalArtifact']['l2FragmentOperandBoundary']=boundaries[f['fragment']['id']].to_dict()
    return f,fn,spec(f,functions)


def definition(fn,translation,pointer,value):
    params=[]
    for i,t in enumerate(fn['parameterTypes']):
        name='p' if i==pointer else 'value' if i==value else 'aux'+str(i)+' __attribute__((unused))'
        params.append(t+' '+name)
    return '#include <stdint.h>\n'+fn['returnType']+' probe('+','.join(params)+'){uint64_t old,next,status;'+translation.replacement+'return old;}\n'


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('n,pointer,value',[(3,2,0),(3,0,2),(4,1,3),(4,3,2)])
def test_fresh_spec_harness_and_native_machine_bind_all_argument_lanes(width,n,pointer,value,tmp_path):
    from tests.test_lrsc_target import translated_case
    from riscv2x86_py.l3_lrsc_spec import samples,harness,parse_samples
    from riscv2x86_py.l3_lrsc_machine import target,source
    from tests.test_lrsc_sequence_contract import code
    from riscv2x86_py.lrsc_output_observation import completion_values
    f,fn,spec=fresh_spec(tmp_path,width,n,pointer,value)
    assert spec['schemaVersion']=='riscv2x86.atomic-observation-spec.v3'
    assert (spec['pointerParameter'],spec['valueParameter'])==(pointer,value)
    assert spec==json.loads(json.dumps(spec))
    plan=samples(spec)
    _,_,_,_,translation=translated_case(width,'fetch_xor')
    implementation=tmp_path/'implementation.c';implementation.write_text(definition(fn,translation,pointer,value))
    wrapper=tmp_path/'harness.c';wrapper.write_text(harness('probe',spec,plan))
    binary=tmp_path/'program';obj=tmp_path/'probe.o'
    for args in (['-c',str(implementation),'-o',str(obj)],[str(wrapper),str(implementation),'-o',str(binary)]):
        result=subprocess.run(['gcc','-std=gnu11','-O0','-Wall','-Wextra','-Werror',*args],capture_output=True,text=True)
        assert result.returncode==0,result.stderr
    result=subprocess.run([str(binary),'a'*64],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    rows=parse_samples(result.stdout,'a'*64,plan)
    for row in rows:
        assert int(row['result'],16)==completion_values(width,64,'fetch_xor',int(row['old'],16),int(row['input'],16))['old']
    elf=Elf(obj)
    assert target(elf.code('probe'),elf.symbol('probe')[0],spec)['machine']==62
    raw=code(width,'fetch_xor',registers=(5,6,9,10+pointer,10+value))
    raw+=bytes.fromhex('1385020067800000')
    assert source(raw,0x1000,spec)['machine']==243
    changed=deepcopy(rows);aux=next(i for i in range(n) if i not in (pointer,value));changed[0]['arguments'][aux]='f'*16
    with pytest.raises(ValueError,match='ARGUMENT_BINDING_MISMATCH'):
        parse_samples('\n'.join(json.dumps(r) for r in changed),'a'*64,plan)
    wrong=deepcopy(spec);wrong['valueParameter']=aux
    with pytest.raises(ValueError,match='PARAMETER_BINDING'):source(raw,0x1000,wrong)


@pytest.mark.parametrize('width',[32,64])
def test_l2_records_auxiliary_inputs_and_rejects_argument_tampering(width,tmp_path):
    from tests.test_lrsc_target import translated_case
    from riscv2x86_py.l2_lrsc_authority import validate
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.automatic_l2_atomic import atomic_wrapper,atomic_events
    f,fn,spec=fresh_spec(tmp_path,width,4,3,1)
    authority=l2_authority_sidecar_from_dict(f['approvalArtifact']['l2AuthoritySidecar'])
    atom,_,_=validate(f)
    atom.update(call_contract=spec['callContract'],observed_return_role='old',sequence_arithmetic_width_bits=64)
    _,_,_,_,translation=translated_case(width,'fetch_xor')
    c=tmp_path/'c.c';c.write_text(definition(fn,translation,3,1))
    wrapper=tmp_path/'wrapper.c';wrapper.write_text(atomic_wrapper(fn,atom,authority));binary=tmp_path/'program'
    result=subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror',str(c),str(wrapper),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    events=atomic_events(result.stdout,atom)
    assert len(events)==8 and all(e['approvedValueRelationHolds'] and len(e['integerArguments'])==3 for e in events)
    lines=result.stdout.splitlines();parts=lines[0].rsplit(';',1);parts[1]='ffffffffffffffff,'+','.join(parts[1].split(',')[1:]);lines[0]=';'.join(parts)
    with pytest.raises(ValueError,match='ARGUMENTS_MISMATCH'):atomic_events('\n'.join(lines),atom)


@pytest.mark.parametrize('mutation',['declarations','identity','type','arity','pointer','value','signed'])
def test_rehashed_but_unbound_call_contract_is_rejected(mutation,tmp_path):
    from riscv2x86_py.l2_lrsc_authority import validate
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    f,fn,spec=fresh_spec(tmp_path,64,4,3,1);fn=deepcopy(fn)
    atom,_,_=validate(f);sidecar=l2_authority_sidecar_from_dict(f['approvalArtifact']['l2AuthoritySidecar'])
    raw=fn['compilerMemoryCallSignature']
    if mutation=='declarations':raw['parameters'][0]['declarationIdentity']='wrong'
    elif mutation=='identity':raw['functionIdentity']=identity('wrong')
    elif mutation=='type':raw['parameters'][0]['widthBits']=16
    elif mutation=='arity':fn['arity']=5
    elif mutation=='pointer':fn['pointerParameters']=[0]
    elif mutation=='value':fn['l2OperandBoundary']['parameterDeclarationIds'][1]=identity('different')
    elif mutation=='signed':raw['parameters'][0].update(signed=True,cType='long')
    raw['factsIdentity']=identity({k:v for k,v in raw.items() if k!='factsIdentity'})
    with pytest.raises(ValueError):bind(fn,atom,sidecar)


@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor','exchange'])
def test_direct_atomic_proof_spec_and_native_machine_support_call_contract(operation,tmp_path):
    from tests.test_l3_atomic_trace import fixture
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    from riscv2x86_py.l3_atomic_spec import spec,samples,harness,parse_samples
    from riscv2x86_py.l3_trace_support import digest
    from riscv2x86_py.l3_atomic_machine import function_mechanism,satisfies
    f,functions=fixture(tmp_path,operation);fn=functions[0]
    # Bind the compiler pointer and value declarations explicitly.
    by={o['operandIndex']:o for o in f['approvalArtifact']['l2AuthoritySidecar']['operands']}
    atom=f['approvalArtifact']['l2AtomicProofFacts']['atomicOperation']
    pointer_decl=(atom['address_projection']['baseDeclarationIdentity'] if atom.get('address_projection') else by[atom['address_operand_index']]['declarationId'])
    value_decl=by[atom['value_operand_index']]['declarationId']
    fn['l2OperandBoundary']['parameterDeclarationIds']=[pointer_decl,value_decl]
    fn['parameterTypes']=['unsigned long *','unsigned long']
    extend_call(f,functions,4,3,1)
    front=tmp_path/'front';front.write_text('direct proof fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},functions,front)==1
    program=identity({'schemaVersion':'riscv2x86.automatic-program.v1','producerDigest':digest(front)})
    boundaries,_,_=materialize_fragment_execution_authority([f],fn,program)
    f['approvalArtifact']['l2FragmentOperandBoundary']=boundaries[f['fragment']['id']].to_dict()
    value=spec(f,functions);plan=samples(value)
    assert value['callContract']['valueParameter']==1 and value['callContract']['pointerParameter']==3
    builtin={'exchange':'__atomic_exchange_n'}.get(operation,'__atomic_'+operation)
    decl=[]
    for i,t in enumerate(fn['parameterTypes']):
        decl.append(t+' '+('p' if i==3 else 'v' if i==1 else 'u'+str(i)+' __attribute__((unused))'))
    name=fn['name'];body='#include <stdint.h>\nunsigned long '+name+'('+','.join(decl)+'){return '+builtin+'(p,v,__ATOMIC_RELAXED);}'
    c=tmp_path/'impl.c';c.write_text(body);wrap=tmp_path/'driver.c';wrap.write_text(harness(name,value,plan))
    obj=tmp_path/'impl.o';binary=tmp_path/'program'
    for args in (['-c',str(c),'-o',str(obj)],[str(c),str(wrap),'-o',str(binary)]):
        r=subprocess.run(['gcc','-O0','-Wall','-Wextra','-Werror',*args],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
    machine=function_mechanism(Elf(obj),name,value)
    assert satisfies(machine['instruction'],value['operation'],'target')
    r=subprocess.run([str(binary),'a'*64],capture_output=True,text=True,timeout=10)
    rows=parse_samples(r.stdout,'a'*64,plan)
    assert len(rows)==plan['distinctInputCount']


def test_control_entry_selection_does_not_use_unrelated_function_count(tmp_path,monkeypatch):
    from riscv2x86_py import l3_control_deployment as module,mechanism_route_checks,automatic_batch_cli,approved_replacement
    f={'fragment':{'id':'fragment'},'rewriteBeginOffset':1,'rewriteEndOffset':2,'rawSourceText':'X'}
    fn={'functionId':'entry'};other={'functionId':'other'}
    monkeypatch.setattr(mechanism_route_checks,'compiler_bound_finding',lambda *a:(f,{'functions':[other,fn]}))
    monkeypatch.setattr(module,'control_spec',lambda *a:{'functionId':'entry'})
    monkeypatch.setattr(module,'signature',lambda *a:{'signature':'fixture'})
    monkeypatch.setattr(module,'samples',lambda *a:{'samples':'fixture'})
    monkeypatch.setattr(automatic_batch_cli,'inspect_entry_points',lambda *a,**kw:(False,[fn,other]))
    monkeypatch.setattr(approved_replacement,'approved_replacement',lambda f:'Y')
    src=tmp_path/'source';target=tmp_path/'target';src.write_text('aXz');target.write_text('aYz')
    assert module.bound_inputs(src,target,'report',f,'clang')[-1]==fn
    monkeypatch.setattr(automatic_batch_cli,'inspect_entry_points',lambda *a,**kw:(False,[fn,fn,other]))
    with pytest.raises(ValueError,match='COMPILER_FACT_REBUILD_MISMATCH'):
        module.bound_inputs(src,target,'report',f,'clang')


def test_unrelated_native_function_keeps_marked_control_region_bytes(tmp_path):
    from riscv2x86_py.l3_control_deployment import label_assembly,region_of
    from riscv2x86_py.l3_control_machine import graph
    c=tmp_path/'control.c';assembly=tmp_path/'control.s';marked=tmp_path/'marked.s';original=tmp_path/'original.so';rebuilt=tmp_path/'rebuilt.so'
    c.write_text('unsigned long route(unsigned long a,unsigned long b,unsigned long yes,unsigned long no){unsigned long out;'
        '__asm__ volatile("cmpq %2,%1\\n\\tje 1f\\n\\tmovq %4,%0\\n\\tjmp 2f\\n1: movq %3,%0\\n2:" :"=&r"(out):"r"(a),"r"(b),"r"(yes),"r"(no):"cc");return out;}\n'
        'unsigned long not_called(unsigned long x){return x+1;}\n')
    for args in (['-shared',str(c),'-o',str(original)],['-S',str(c),'-o',str(assembly)]):
        r=subprocess.run(['gcc','-O0','-fPIC','-Wall','-Wextra','-Werror',*args],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
    marked.write_text(label_assembly(assembly.read_text(),False))
    r=subprocess.run(['gcc','-shared',str(marked),'-o',str(rebuilt)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    a,b=Elf(original),Elf(rebuilt)
    assert a.code('route')==b.code('route')
    region=region_of(b,'route',False)
    value=graph(b.code('route'),b.symbol('route')[0],region,62)
    assert len(value['paths'])==2
