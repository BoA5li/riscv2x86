"""Noncommutative sequence semantics, native outputs and independent rejection."""
from copy import deepcopy
from dataclasses import replace
import json
import random
import subprocess
import pytest
from tests.test_lrsc_sequence_contract import code
from tests.test_lrsc_target import translated_case
from tests.test_l3_lrsc_sequence import invocation
from riscv2x86_py.lrsc_sequence import candidate, successful_projection, SequenceError
from riscv2x86_py.lrsc_source import reference_attempt
from riscv2x86_py.lrsc_target import expected_contract, symbolic_proof
from riscv2x86_py.lrsc_output_observation import completion_values
from riscv2x86_py.l3_lrsc_machine import source, target, expression
from riscv2x86_py.l3_trace_support import Elf


@pytest.mark.parametrize('width,word',[(32,False),(32,True),(64,False)])
@pytest.mark.parametrize('compressed',[False,True])
def test_subtraction_operand_order_is_owned_by_encoding(width,word,compressed):
    raw=code(width,'fetch_sub',word_alu=word,compressed=compressed)
    q=candidate(raw,base_address=0x4000)
    assert q['operation']=='fetch_sub'
    alu=int.from_bytes(raw[4:8],'little');left=(alu>>15)&31;right=(alu>>20)&31
    swapped=(alu&~((31<<15)|(31<<20)))|(left<<20)|(right<<15)
    with pytest.raises(SequenceError,match='NONCOMMUTATIVE_OPERAND_ORDER'):
        candidate(raw[:4]+swapped.to_bytes(4,'little')+raw[8:])
    assert expression('sub','old','input',64)!=expression('sub','input','old',64)
    assert expression('add','old','input',64)==expression('add','input','old',64)


@pytest.mark.parametrize('width,word',[(32,False),(32,True),(64,False)])
def test_all_completion_bits_and_failed_sc_have_separate_meanings(width,word):
    _,_,_,model,_=translated_case(width,'fetch_sub',word)
    arithmetic=32 if word else 64
    raw=code(width,'fetch_sub',word_alu=word)
    rand=random.Random(0x139)
    pairs=[(a,b) for a in (0,1,0x7fffffff,0x80000000,0xffffffff,(1<<64)-1)
           for b in (0,1,0x7fffffff,0x80000000,0xffffffff,(1<<64)-1)]
    pairs += [(rand.getrandbits(width),rand.getrandbits(64)) for _ in range(200)]
    for a,b in pairs:
        loaded=a&((1<<width)-1)
        signed=loaded-(1<<width) if loaded&(1<<(width-1)) else loaded
        old=signed&((1<<64)-1)
        n=(old-b)&((1<<arithmetic)-1)
        if word and n&(1<<31):n-=1<<32
        n&=(1<<64)-1
        expected={'old':old,'next':n,'status':0}
        assert completion_values(width,arithmetic,'fetch_sub',a,b)==expected
        projected=successful_projection(candidate(raw),old=a,input_value=b)
        assert (projected['oldRegisterValue'],projected['nextRegisterValue'],projected['storedValue'])==(old,n,n&((1<<width)-1))
        row=reference_attempt(model.lrsc_sequence,loaded_value=loaded,input_value=b,sc_status=37)
        assert row['status']==37 and row['storeValue'] is None and row['nextState']=='load_reserved'
    contract=expected_contract(model)
    assert symbolic_proof(contract)['allBitPatterns']
    wrong=replace(contract,program=tuple(('add',*i[1:]) if i[0]=='sub' else i for i in contract.program))
    with pytest.raises(ValueError,match='PROGRAM_NOT_REGISTERED'):symbolic_proof(wrong)


@pytest.mark.parametrize('width,word',[(32,False),(32,True),(64,False)])
@pytest.mark.parametrize('role',['old','next','status'])
@pytest.mark.parametrize('optimization',['-O0','-O2'])
def test_actual_native_return_and_final_machine_invariant(tmp_path,width,word,role,optimization):
    _,_,_,_,translation=translated_case(width,'fetch_sub',word)
    inv=invocation(width,'fetch_sub',word);inv['returnRole']=role
    c=tmp_path/'c.c';obj=tmp_path/'probe.o';binary=tmp_path/'program'
    c.write_text('#include <stdint.h>\nuint64_t probe(uint'+str(width)+'_t *p,uint64_t value){uint64_t old,next,status;'
        +translation.replacement+'return '+role+';}\nint main(void){uint'+str(width)+'_t x=1;uint64_t y=probe(&x,3);'
        +'return !(x==(uint'+str(width)+'_t)-2 && y=='+{'old':'1','next':'UINT64_MAX-1','status':'0'}[role]+');}\n')
    for args in (['-c',str(c),'-o',str(obj)],[str(c),'-o',str(binary)]):
        r=subprocess.run(['gcc',optimization,'-Wall','-Wextra','-Werror',*args],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
    assert subprocess.run([str(binary)],timeout=10).returncode==0
    elf=Elf(obj);raw=elf.code('probe');base=elf.symbol('probe')[0]
    actual=target(raw,base,inv)
    assert actual==json.loads(json.dumps(actual))
    sub=[r for r in actual['instructions'] if r['op']=='sub'];assert len(sub)==1
    # Change the actual operation to ADD, without changing registers or offsets.
    at=sub[0]['pc']-base;changed=bytearray(raw)
    opcode=at+(1 if 0x40<=changed[at]<=0x4f else 0)
    assert changed[opcode] in (0x29,0x2b)
    changed[opcode]-=0x28
    with pytest.raises(ValueError,match='CAS_RECOMPUTATION'):target(bytes(changed),base,inv)
    q=candidate(code(width,'fetch_sub',word_alu=word))
    reg=q[{'old':'oldRegister','next':'nextRegister','status':'statusRegister'}[role]]
    rv=code(width,'fetch_sub',word_alu=word)+((reg<<15)|(10<<7)|0x13).to_bytes(4,'little')+bytes.fromhex('67800000')
    assert source(rv,0x1000,inv)['machine']==243


def test_subtraction_does_not_register_a_nonexistent_direct_rv_amo():
    from riscv2x86_py.l3_atomic_semantics import OPERATIONS,result
    assert 'fetch_sub' not in OPERATIONS
    with pytest.raises(ValueError,match='OPERATION_UNSUPPORTED'):result('fetch_sub',1,3,64)
