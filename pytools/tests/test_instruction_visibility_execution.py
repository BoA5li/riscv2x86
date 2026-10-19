from dataclasses import asdict,replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import pytest
from tests import test_instruction_visibility_production as fixture
from riscv2x86_py.instruction_visibility_harness import observe,probe_bytes
from riscv2x86_py.l2_instruction_visibility_runner import validate_observation,SCHEMA
from riscv2x86_py.semantic_content import semantic_identity


def inputs(tmp_path,monkeypatch,cpu):
    original=fixture.domain()
    for side in ('source','target'):original[side+'Execution']['pinnedCpu']=cpu
    original['domainIdentity']=semantic_identity({k:v for k,v in original.items() if k!='domainIdentity'})
    monkeypatch.setattr(fixture,'domain',lambda:original)
    fragment,approval,text=fixture.approval_fixture()
    fragment.enclosingFunction='sync_probe'
    from riscv2x86_py.compiler_instruction_sync_scope import instruction_sync_scope
    fragment.compilerFragmentAuthority={'sourceDigest':'sha256:'+'1'*64,'functionIdentity':'sha256:'+'4'*64,
        'fragmentBindingKey':{'beginOffset':10,'endOffset':20}}
    ast={'name':'sync_probe','type':{'qualType':'void (void)'},'inner':[
        {'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt'}]}]}
    approval['l2InstructionSyncFunctionScope']=instruction_sync_scope(ast,source_digest='sha256:'+'1'*64,
        function_identity='sha256:'+'4'*64,source_range=lambda n:(10,20))
    report={'findings':[{'fragment':asdict(fragment),'approvalArtifact':approval,
        'suggestedReplacement':text,'sourceDigest':'sha256:'+'1'*64}]}
    path=tmp_path/'report.json';path.write_text(json.dumps(report))
    return path,text,original


@pytest.mark.parametrize('side',['target','source'])
def test_actual_shared_library_call_and_modified_code_observation(tmp_path,monkeypatch,side):
    gcc=shutil.which('gcc' if side=='target' else 'riscv64-linux-gnu-gcc')
    qemu=shutil.which('qemu-riscv64')
    if not gcc or (side=='source' and not qemu):pytest.skip('requires real source ISA tools')
    if not hasattr(os,'sched_getaffinity'):pytest.skip('requires affinity')
    previous=os.sched_getaffinity(0);cpu=min(previous)
    report,text,domain=inputs(tmp_path,monkeypatch,cpu)
    root=Path(__file__).resolve().parents[2];source=tmp_path/'sync.c';library=tmp_path/'sync.so'
    source.write_text(('#include "riscv2x86_runtime_helpers.h"\n' if side=='target' else '')+
        'void sync_probe(void) {'+(text if side=='target' else '__asm__ volatile("fence.i" ::: "memory");')+'}\n')
    command=[gcc,'-shared','-fPIC','-O0','-fno-lto','-I'+str(root/'runtime/include'),str(source)]
    if side=='target':command.append(str(root/'runtime/riscv2x86_runtime_helpers.c'))
    built=subprocess.run([*command,'-o',str(library)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    digest='sha256:'+__import__('hashlib').sha256(library.read_bytes()).hexdigest()
    request={'schemaVersion':SCHEMA,'side':side,'fragmentId':'fragment:fence-i','domainAuthority':domain,
        'executionIdentity':'sha256:'+'5'*64,'executionPlanIdentity':'sha256:'+'6'*64,
        side+'Program':{'path':str(library),'digest':digest}}
    runner=(qemu,'-L','/usr/riscv64-linux-gnu') if side=='source' else ()
    try:
        os.sched_setaffinity(0,{cpu})
        observation=observe(request,side=side,symbol='sync_probe',approval_path=report,compiler=gcc,runner=runner)
    finally:os.sched_setaffinity(0,previous)
    projection,valid=validate_observation(observation,request,side,domain)
    assert valid
    assert [e['observedValue'] for e in observation['events'] if e['kind']=='instruction_fetch']==[1,7]
    record=observation['events'][1]['traceRecord']['recordPayload']
    assert record['callReturned'] and record['rawOutput'].split()[1]=='1'
    changed=json.loads(json.dumps(observation));changed['events'][-1]['observedValue']=1
    assert not validate_observation(changed,request,side,domain)[1]


@pytest.mark.parametrize('value',[-1,2048,True])
def test_probe_width_domain_is_explicit(value):
    with pytest.raises(ValueError,match='VALUE_UNSUPPORTED'):probe_bytes(value,'target')
