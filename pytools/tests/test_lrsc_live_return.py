"""Completion sinks are actual C returns, never synthetic register readings."""
from copy import deepcopy
import subprocess

import pytest

from tests.test_lrsc_target import finding_case, translated_case
from tests.test_l3_lrsc_sequence import invocation
from tests.test_lrsc_sequence_contract import code
from riscv2x86_py.lrsc_output_observation import return_role, completion_values
from riscv2x86_py.l3_lrsc_machine import source, target
from riscv2x86_py.l3_trace_support import Elf


def bind_return(finding, function, model, role):
    candidate=finding['fragment']['compilerFragmentAuthority']['candidate']
    index=dict(model.lrsc_sequence.role_operand_indexes)[role]
    binding=candidate['operandBindings'][index]
    function['l2OperandBoundary']['returnDeclarationId']=binding['declarationIdentity']
    candidate['downstreamUses']=[{'valueNodeIdentity':binding['valueNodeIdentity'],
                                'useKind':'function_return','complete':True}]


@pytest.mark.parametrize('role',['old','next','status'])
def test_return_sink_comes_from_compiler_declaration_and_complete_use_graph(role):
    f,functions,model,_=finding_case()
    bind_return(f,functions[0],model,role)
    assert return_role(f,functions[0],model)==role
    candidate=f['fragment']['compilerFragmentAuthority']['candidate']
    for kind in ('memory_store','call_argument','c_expression','branch_condition'):
        changed=deepcopy(f)
        changed['fragment']['compilerFragmentAuthority']['candidate']['downstreamUses'][0]['useKind']=kind
        with pytest.raises(ValueError,match='ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED'):
            return_role(changed,functions[0],model)
    candidate['downstreamUseEnumerationComplete']=False
    with pytest.raises(ValueError,match='ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED'):return_role(f,functions[0],model)


@pytest.mark.parametrize('role',['next','status'])
def test_other_live_output_is_not_silently_discarded(role):
    f,functions,model,_=finding_case()
    bind_return(f,functions[0],model,role)
    c=f['fragment']['compilerFragmentAuthority']['candidate']
    old=c['operandBindings'][dict(model.lrsc_sequence.role_operand_indexes)['old']]
    c['downstreamUses'].append({'valueNodeIdentity':old['valueNodeIdentity'],'useKind':'function_return','complete':True})
    with pytest.raises(ValueError,match='ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED:old'):
        return_role(f,functions[0],model)


@pytest.mark.parametrize('width,word',[(32,False),(32,True),(64,False)])
@pytest.mark.parametrize('role',['old','next','status'])
def test_source_final_bytes_bind_selected_output_not_just_any_output(width,word,role):
    inv=invocation(width,word=word)
    inv['returnRole']=role
    registers=(5,6,9,10,11)
    reg={'old':5,'next':6,'status':9}[role]
    raw=code(width,registers=registers,word_alu=word)
    raw+=((reg<<15)|(10<<7)|0x13).to_bytes(4,'little')+bytes.fromhex('67800000')
    assert source(raw,0x1000,inv)['machine']==243
    inv['returnRole']='status' if role!='status' else 'old'
    with pytest.raises(ValueError,match='RETURN_OR_STACK'):source(raw,0x1000,inv)


@pytest.mark.parametrize('width,operation,word',[(w,op,False) for w in (32,64)
    for op in ('fetch_add','fetch_and','fetch_or','fetch_xor')]+[(32,'fetch_add',True)])
@pytest.mark.parametrize('role',['old','next','status'])
@pytest.mark.parametrize('optimization',['-O0','-O2'])
def test_actual_native_return_and_final_cas_bytes(width,operation,word,role,optimization,tmp_path):
    from riscv2x86_py.lrsc_source import reference_attempt
    _,_,_,model,result=translated_case(width,operation,word)
    values=(0,1,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,1<<63,(1<<64)-1)
    rows=[]
    for initial in values:
        for arg in values:
            expected=reference_attempt(model.lrsc_sequence,loaded_value=initial&((1<<width)-1),input_value=arg,sc_status=0)
            actual=completion_values(width,model.lrsc_sequence.arithmetic_width_bits,operation,initial,arg)
            assert actual=={k:expected[k] for k in ('old','next','status')}
            rows.append('{'+','.join(hex(x)+'ULL' for x in (initial,arg,expected[role],expected['storeValue']))+'}')
    text='#include <stdint.h>\n'
    text+=f'uint64_t probe(uint{width}_t *p,uint64_t value){{uint64_t old,next,status;'+result.replacement+f'return {role};'+'}\n'
    text+='int main(void){const uint64_t rows[][4]={'+','.join(rows)+'};'
    text+=f'for(unsigned i=0;i<sizeof(rows)/sizeof(rows[0]);i++){{uint{width}_t object[4] __attribute__((aligned(16)))={{rows[i][0],0x31,0x72,0x53}};'
    text+='uint64_t r=probe(object,rows[i][1]);if(r!=rows[i][2]||object[0]!=rows[i][3]||object[1]!=0x31||object[2]!=0x72||object[3]!=0x53)return 1;}return 0;}'
    c=tmp_path/'probe.c';obj=tmp_path/'probe.o';binary=tmp_path/'probe';c.write_text(text)
    for args in (['-c',str(c),'-o',str(obj)],[str(c),'-o',str(binary)]):
        r=subprocess.run(['gcc','-std=gnu11',optimization,'-Wall','-Wextra','-Werror',*args],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
    assert subprocess.run([str(binary)],timeout=10).returncode==0
    elf=Elf(obj);inv=invocation(width,operation,word);inv['returnRole']=role
    assert target(elf.code('probe'),elf.symbol('probe')[0],inv)['machine']==62
    inv['returnRole']='old' if role!='old' else 'next'
    with pytest.raises(ValueError,match='RETURN_VALUE_OR_STACK'):
        target(elf.code('probe'),elf.symbol('probe')[0],inv)


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('role',['next','status'])
def test_live_return_spec_is_rebuilt_from_proof_and_survives_json(width,role,tmp_path):
    import json
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    from riscv2x86_py.l3_lrsc_spec import spec
    from riscv2x86_py.l3_trace_support import identity,digest
    from tests.test_l3_lrsc_sequence import finding_spec
    # The production compiler join independently rederives the actual AST;
    # this fixture exercises the proof -> sidecar -> spec boundary only.
    f,functions=finding_spec();fn=functions[0]
    if width==32:
        from tests.test_l3_lrsc_persistence import approved_spec
        f,functions,_=approved_spec(tmp_path,width,'fetch_add');fn=functions[0]
    roles=dict(f['approvalArtifact']['l2LrscProofFacts']['sourceSequence']['role_operand_indexes'])
    binding=f['fragment']['compilerFragmentAuthority']['candidate']['operandBindings'][roles[role]]
    fn['l2OperandBoundary']['returnDeclarationId']=binding['declarationIdentity']
    f['translationOutcome']='emitted';f['sourceDigest']=fn['sourceDigest']
    frontend=tmp_path/'live-frontend';frontend.write_text('live output fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},functions,frontend)==1
    program=identity({'schemaVersion':'riscv2x86.automatic-program.v1','producerDigest':digest(frontend)})
    boundaries,_,_=materialize_fragment_execution_authority([f],fn,program)
    f['approvalArtifact']['l2FragmentOperandBoundary']=boundaries[f['fragment']['id']].to_dict()
    value=spec(f,functions)
    assert value['returnRole']==role
    assert value['schemaVersion']=='riscv2x86.atomic-observation-spec.v2'
    assert value==json.loads(json.dumps(value))


def test_control_symbolic_move_does_not_treat_value_tuple_as_stack_address():
    from riscv2x86_py.l3_control_machine import step
    state={'registers':{5:('value-token',)},'memory':{},'compare':None}
    step(state,{'op':'add','rs':5,'rd':10,'imm':0},243)
    assert state['registers'][10]==('value-token',)
    with pytest.raises(ValueError,match='VALUE_ARITHMETIC_UNSUPPORTED'):
        step(state,{'op':'add','rs':5,'rd':10,'imm':8},243)
    state['registers'][5]=('stack',-16)
    step(state,{'op':'add','rs':5,'rd':10,'imm':8},243)
    assert state['registers'][10]==('stack',-8)


@pytest.mark.parametrize('kind',['atomic','lrsc'])
def test_deployment_selects_entry_identity_without_requiring_unrelated_functions_absent(kind,tmp_path,monkeypatch):
    import importlib
    from riscv2x86_py import mechanism_route_checks,automatic_batch_cli,approved_replacement
    module=importlib.import_module('riscv2x86_py.l3_'+kind+'_deployment')
    finding={'fragment':{'id':'fragment'},'rewriteBeginOffset':1,'rewriteEndOffset':2,'rawSourceText':'X'}
    function={'functionId':'entry','parameterTypes':['unsigned long *','unsigned long']}
    unrelated={'functionId':'unrelated','parameterTypes':[]}
    snapshot={'functions':[unrelated,function]}
    monkeypatch.setattr(mechanism_route_checks,'compiler_bound_finding',lambda *a:(finding,snapshot))
    monkeypatch.setattr(automatic_batch_cli,'inspect_entry_points',lambda *a,**kw:(False,[function,unrelated]))
    monkeypatch.setattr(approved_replacement,'approved_replacement',lambda f:'Y')
    monkeypatch.setattr(module,'spec',lambda f,functions:{'functionId':'entry'})
    monkeypatch.setattr(module,'samples',lambda s:{'sample':'plan'})
    src=tmp_path/'source.c';target=tmp_path/'target.c';src.write_text('aXz');target.write_text('aYz')
    assert module.bound_inputs(src,target,'report',finding,'clang')[2]==function
    monkeypatch.setattr(automatic_batch_cli,'inspect_entry_points',lambda *a,**kw:(False,[function,function,unrelated]))
    with pytest.raises(ValueError,match='COMPILER_REBUILD_MISMATCH'):
        module.bound_inputs(src,target,'report',finding,'clang')
    snapshot['functions']=[unrelated,function,function]
    with pytest.raises(ValueError,match='COMPILER_FINDING_MISMATCH'):
        module.bound_inputs(src,target,'report',finding,'clang')


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('role',['old','next','status'])
def test_l2_actual_call_observation_compares_full_return_and_all_object_bytes(width,role,tmp_path):
    from riscv2x86_py.automatic_l2_atomic import atomic_wrapper,atomic_events
    from riscv2x86_py.l2_lrsc_authority import materialize,validate
    f,functions,model,translation=finding_case(width,'fetch_xor')
    fn=functions[0]
    bindings=f['fragment']['compilerFragmentAuthority']['candidate']['operandBindings']
    index=dict(model.lrsc_sequence.role_operand_indexes)[role]
    fn['l2OperandBoundary']['returnDeclarationId']=bindings[index]['declarationIdentity']
    fn.update(arity=2,parameterTypes=[f'uint{width}_t *','uint64_t'],pointerParameters=[0],returnType='uint64_t')
    atom,_,_=validate(f)
    atom.update(observed_return_role=role,sequence_arithmetic_width_bits=64)
    authority=materialize(f,functions,'sha256:'+'f'*64)
    assert authority is not None
    wrapper=tmp_path/'harness.c';implementation=tmp_path/'impl.c';binary=tmp_path/'program'
    wrapper.write_text(atomic_wrapper(fn,atom,authority))
    implementation.write_text('#include <stdint.h>\n'+f'uint64_t probe(uint{width}_t *p,uint64_t value)'+'{uint64_t old,next,status;'+translation.replacement+f'return {role};'+'}\n')
    r=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(wrapper),str(implementation),'-o',str(binary)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
    assert r.returncode==0,r.stderr
    events=atomic_events(r.stdout,atom)
    assert len(events)==8 and all(e['approvedValueRelationHolds'] for e in events)
    # Corrupt only high result bits: correct low-width memory is insufficient.
    rows=r.stdout.splitlines();fields=rows[0].split(';');fields[3]=f'{int(fields[3],16)^(1<<63):016x}'
    rows[0]=';'.join(fields)
    assert not atomic_events('\n'.join(rows),atom)[0]['approvedValueRelationHolds']
    # Output observation cannot be shortened by a narrower C return.
    changed=dict(fn,returnType='uint32_t')
    with pytest.raises(ValueError,match='UNSIGNED_XLEN_RETURN_REQUIRED'):
        atomic_wrapper(changed,atom,authority)
