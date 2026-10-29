"""Strict real native compilation of the shared L2/L3 harness generator."""
import shutil
import subprocess

import pytest

from riscv2x86_py.l3_joint_observation import harness, parse_samples


@pytest.mark.parametrize('arity,pointer', [(n,p) for n in range(1,5) for p in range(n)])
def test_typed_call_harness_builds_and_executes_without_unused_tables(tmp_path, arity, pointer):
    compiler = shutil.which('gcc')
    if not compiler:
        pytest.skip('real native gcc required')
    parameters = [{'cType':'uint64_t'} for _ in range(arity)]
    parameters[pointer] = {'cType':'uint64_t *','pointee':{'cType':'uint64_t'}}
    program = {'functionName':'independent_probe','specIdentity':'sha256:'+'1'*64,
        'pointerParameter':pointer,'object':{'size':32,'alignment':8},
        'callSignature':{'parameters':parameters,'result':{'cType':'uint64_t'}}}
    plan = {'planIdentity':'sha256:'+'2'*64,'inputs':[
        {'arguments':['' if i==pointer else format(sample+i,'016x') for i in range(arity)],
         'initialObjectHex':'00'*32} for sample in range(8)]}
    generated = harness(program,plan)
    assert generated == harness(program,plan)
    assert ('static const uint64_t args[' in generated) == (arity>1)
    h = tmp_path/'harness.c';h.write_text(generated)
    source = tmp_path/'callee.c'
    names = ['a'+str(i) for i in range(arity)]
    expression = '+'.join(names[i] for i in range(arity) if i!=pointer) or '0'
    source.write_text('#include <stdint.h>\nuint64_t independent_probe('+','.join(p['cType']+' '+n for p,n in zip(parameters,names))+') {'+names[pointer]+'[0]='+expression+';return '+names[pointer]+'[0];}')
    for opt in ('-O0','-O2','-O3'):
        binary = tmp_path/'probe'
        r = subprocess.run([compiler,'-std=gnu11',opt,'-Wall','-Wextra','-Werror',str(h),str(source),'-o',str(binary)],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
        r = subprocess.run([str(binary),'a'*64],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
        rows = parse_samples(r.stdout,'a'*64,program,plan)
        for sample,row in enumerate(rows):
            expected = sum(sample+i for i in range(arity) if i!=pointer)
            assert int(row['value'],16)==expected
            assert int.from_bytes(bytes.fromhex(row['objectHex'])[:8],'little')==expected
