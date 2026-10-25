"""ABI/sample replay tests run native C; they are not dual-ISA L3 evidence."""
from copy import deepcopy
import json
import shutil
import subprocess

import pytest

from riscv2x86_py.l3_scalar_call import sample_plan, call_signature, validate_signature
from riscv2x86_py.l3_scalar_trace import scalar_harness, parse_samples
from riscv2x86_py.l3_trace_support import identity


def signature(signed=(False, False), result=False):
    def item(i, sign):
        return {'declarationIdentity':identity(i),'typeIdentity':identity(('type',sign)),
                'widthBits':64,'signed':sign,'cType':'int64_t' if sign else 'uint64_t'}
    body={'schemaVersion':'riscv2x86.l3-scalar-call.v1','functionIdentity':identity('fn'),
          'sourceDigest':identity('source'),'abi':'linux-lp64-integer64',
          'parameters':[item(i,s) for i,s in enumerate(signed)],'result':item('out',result)}
    return dict(body,signatureIdentity=identity(body))


@pytest.mark.parametrize('signed,result',[( (False,),False),((False,False),False),
    ((True,True),True),((True,True),False),((True,False,True),True),((False,True,False,True),False)])
def test_vector_harness_native_defined_conversions_and_replay(tmp_path,signed,result):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    sig=signature(signed,result); plan=sample_plan(sig,16)
    scope={'name':'unrelated','callSignature':sig}
    # Return the final argument: checks negative signed argument/result without
    # introducing signed arithmetic overflow in the independent C fixture.
    params=','.join(p['cType']+' x'+str(i) for i,p in enumerate(sig['parameters']))
    unused=''.join('(void)x'+str(i)+';' for i in range(len(signed)-1))
    last='x'+str(len(signed)-1)
    # Same signedness for result is unnecessary: use a constant negative result
    # for the signed-return/mixed case, avoiding implementation-defined casts.
    expression=last if signed[-1]==result else '-INT64_C(1)' if result else '(uint64_t)'+last
    source=tmp_path/'test.c';source.write_text(scalar_harness(scope,16)+
        f'\n{sig["result"]["cType"]} unrelated({params}){{{unused}return {expression};}}\n')
    program=tmp_path/'program'
    built=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(source),'-o',str(program)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    run=subprocess.run([str(program),'a'*64],capture_output=True,text=True)
    assert run.returncode==0 and not run.stderr,run.stderr
    rows=parse_samples(run.stdout,'a'*64,16,sig)
    expected=[r[-1] for r in plan['inputs']] if expression!='-INT64_C(1)' else ['ffffffffffffffff']*16
    assert [r['value'] for r in rows]==expected
    for mutation in ('swap','signed','order','partial','extra','plan','token'):
        bad=deepcopy(rows)
        if mutation=='swap' and len(signed)>1:bad[0]['inputs'].reverse()
        elif mutation=='swap':bad[0]['inputs'][0]='0000000000000002'
        if mutation=='signed':bad[0]['inputs'][0]='-1'
        if mutation=='order':bad.reverse()
        if mutation=='partial':bad.pop()
        if mutation=='extra':bad.append(bad[-1])
        if mutation=='plan':bad[0]['planIdentity']=identity('other')
        if mutation=='token':bad[0]['token']='b'*64
        with pytest.raises(ValueError):parse_samples('\n'.join(map(json.dumps,bad)),'a'*64,16,sig)


def test_signature_consumes_closed_compiler_type_facts(tmp_path):
    from tests.test_static_operand_production import literal_finding
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    f,fn=literal_finding();frontend=tmp_path/'frontend';frontend.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},[fn],frontend)==1
    sig=call_signature(fn,f)
    assert validate_signature(sig)==sig
    assert sig['parameters'][0]['signed'] is False
    for mutation in ('arity','type','declaration','source','return'):
        bad=deepcopy(fn)
        if mutation=='arity':bad['arity']=2
        if mutation=='type':bad['parameterTypes']=['int64_t']
        if mutation=='declaration':bad['l2OperandBoundary']['parameterDeclarationIds']=['missing']
        if mutation=='source':bad['sourceDigest']=identity('other')
        if mutation=='return':bad['returnType']='int64_t'
        with pytest.raises((ValueError,KeyError)):call_signature(bad,f)


@pytest.mark.parametrize('mutation',['signed','width','duplicate','abi','ctype','version'])
def test_rehashed_signature_does_not_allow_unsupported_domain(mutation):
    sig=signature()
    if mutation=='signed':sig['parameters'][0]['signed']='false'
    if mutation=='width':sig['parameters'][0]['widthBits']=32
    if mutation=='duplicate':sig['parameters'][1]=sig['parameters'][0]
    if mutation=='abi':sig['abi']='unknown'
    if mutation=='ctype':sig['result']['cType']='void *'
    if mutation=='version':sig['schemaVersion']='old'
    sig['signatureIdentity']=identity({k:v for k,v in sig.items() if k!='signatureIdentity'})
    with pytest.raises(ValueError):sample_plan(sig,4)


@pytest.mark.parametrize('mutation',['samples','signature','version','downgrade'])
def test_vector_contract_binds_sample_plan_and_version(tmp_path,mutation):
    from tests.test_l3_scalar_trace import contract,finding
    from riscv2x86_py.l3_qemu_memory_route import VECTOR_CONTRACT_SCHEMA,parse_contract
    raw=contract(finding(tmp_path));raw['schemaVersion']=VECTOR_CONTRACT_SCHEMA
    sig=signature();raw['deployment'].update(schemaVersion='riscv2x86.compiler-region-execution-deployment.v2',functionScope={'callSignature':sig})
    raw['samplePlan']=sample_plan(sig,4)
    assert parse_contract(raw)
    if mutation=='samples':raw['samplePlan']['inputs'][0].reverse()
    if mutation=='signature':sig['parameters'][0]['signed']=True
    if mutation=='version':raw['deployment']['schemaVersion']='riscv2x86.compiler-region-execution-deployment.v1'
    if mutation=='downgrade':raw['schemaVersion']='riscv2x86.compiler-region-trace-experiment.v3'
    with pytest.raises(ValueError):parse_contract(raw)
