"""Real RV64 mulhu -> x86 C API run; upstream binding is a protocol fixture.

Requires actual cross GCC and QEMU. No emulation/ELF-header replacement is used
when tools are absent. These tests do not certify the mocked candidate producer.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from riscv2x86_py import native_api_experiment as run
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_api_contract as api
from .test_native_api_contract import MODEL


@pytest.fixture
def real_api(tmp_path,monkeypatch):
    cc=shutil.which('riscv64-linux-gnu-gcc');qemu=shutil.which('qemu-riscv64');host=shutil.which('gcc');ar=shutil.which('ar')
    if not all((cc,qemu,host,ar)):pytest.skip('real RISC-V GCC, QEMU and native GCC/ar required')
    libc=Path(subprocess.check_output([cc,'-print-file-name=libc.so.6'],text=True).strip()).resolve()
    prefix=libc.parent.parent
    if not (prefix/'lib/ld-linux-riscv64-lp64d.so.1').is_file():pytest.skip('explicit RV64 LP64D loader prefix unavailable')
    root=tmp_path;unit=root/'unit';unit.mkdir()
    source=b'unsigned long high(unsigned long a,unsigned long b){unsigned long out; __asm__("mulhu %0,%1,%2":"=r"(out):"r"(a),"r"(b)); return out;}\n'
    target=b'unsigned long high(unsigned long a,unsigned long b){return (unsigned long)(((unsigned __int128)a*b)>>64);}\n'
    (unit/'source.i').write_bytes(source);(unit/'candidate.i').write_bytes(target)
    flags=['-O2','-march=rv64gc','-mabi=lp64d']
    subprocess.run([cc,*flags,'-x','cpp-output','-c',str(unit/'source.i'),'-o',str(unit/'source.o')],check=True,capture_output=True)
    (unit/'baseline.c').write_text('int baseline(void){return 0;}\n')
    subprocess.run([cc,*flags,'-c',str(unit/'baseline.c'),'-o',str(unit/'baseline.o')],check=True,capture_output=True)
    library=unit/'baseline.a';subprocess.run([ar,'cq',str(library),str(unit/'baseline.o')],check=True,capture_output=True)
    targetlib=unit/'target.so'
    subprocess.run([host,'-O2','-fPIC','-shared','-x','cpp-output',str(unit/'candidate.i'),'-o',str(targetlib)],check=True,capture_output=True)
    sig={'type':{'qualType':'unsigned long (unsigned long, unsigned long)'},'variadic':False,'attributes':[],
         'parameters':[{'qualType':'unsigned long'},{'qualType':'unsigned long'}]}
    definition={'astPath':['inner',0],'linkerName':'high','signature':sig,'functionEvidenceIdentity':'fixture-function','storageClass':None}
    report={'contractEvidenceIdentity':'fixture-contract','programScope':{'localScopes':{'candidate':{'rootAstPaths':[['inner',0]]}}},
        'declarationJoins':[{'candidateAstPath':['inner',0],'byteLineageDeclarationCorrespondenceVerified':True,
                            'sourceSignature':sig,'candidateSignature':sig}],
        'dataModels':{'source':MODEL,'candidate':MODEL,'nativeTarget':MODEL},
        'graphs':{name:{'typeGraph':[],'functionDefinitions':[definition]} for name in ('source','candidate','nativeTarget')}}
    candidate={'candidatePath':str(unit/'candidate.i'),'sourceObjectDigest':d.digest(unit/'source.o'),
               'sourceFlags':flags,'targetFlags':['-O2'],'targetCompiler':host}
    candidatefile=unit/'candidate.json';candidatefile.write_text(json.dumps(candidate))
    env={'PATH':os.environ['PATH'],'LC_ALL':'C'}
    plan={'candidatePath':str(candidatefile),'environment':env}
    deployed={'deploymentIdentity':'fixture-deployment','artifacts':[{'stage':'derived-library',**d.snapshot(targetlib)}],
              'definitions':[{'verified':True,'symbol':{'name':'high'}}]}
    receipt={'context':{'nativeCompiler':cc,'workingDirectory':str(unit)}}
    contractfile=root/'contracts.json';contractfile.write_text(json.dumps(report))
    # Only the already-tested upstream canonical-input / audit protocol is mocked.
    monkeypatch.setattr(run,'context',lambda path:(report,deployed,plan,candidate,receipt,{'inputBytes':source}))
    domain={'schemaVersion':'riscv2x86.native-api-bound-domain.v1','contractEvidenceIdentity':'fixture-contract',
            'functionEvidenceIdentity':'fixture-function','domain':{'schemaVersion':api.SCHEMA,
              'claimScope':'bounded-api-under-declared-preconditions','preconditions':[],
              'cases':[{'arguments':[{'integer':a},{'integer':b}],'objects':[]}
                       for a,b in [(0,1),(1,2),(2**64-1,2**64-1),(2**63,3)]]}}
    domainfile=root/'domain.json';domainfile.write_text(json.dumps(domain))
    result=run.acquire(contractfile,domainfile,['inner',0],library,root/'api',source_launcher=qemu,
                       launcher_arguments=['-L',str(prefix)],timeout=60)
    return root,result


def test_real_cross_isa_api_execution_and_integrity(real_api):
    root,result=real_api
    assert result['compilerDeclarationWitnessesComplete'] and result['processObservationStatus']=='verified'
    assert result['harnessObservationProtocolComplete']
    assert not result['semanticApproval'] and not result['nativeAbiClosureVerified']
    assert run.check(root/'api/result.json')==result


def test_rehashed_command_cannot_replace_the_actual_profile(real_api):
    root,_=real_api;path=root/'api/run-target/execution.json';row=d.read(path)
    row['arguments']=['/different/program']
    path.write_text(json.dumps(d.seal({k:v for k,v in row.items() if k!='apiExecutionIdentity'},'apiExecutionIdentity')))
    with pytest.raises(ValueError,match='EXECUTION_PROFILE'):run.check(root/'api/result.json')


def test_header_prototype_can_supply_native_type_but_not_assembly_behavior():
    from .test_native_api_contract import SIG
    definition={'astPath':['inner',0],'linkerName':'api_entry','signature':SIG,'functionEvidenceIdentity':'fn'}
    report={'programScope':{'localScopes':{'candidate':{'rootAstPaths':[['inner',0]]}}},
      'declarationJoins':[{'candidateAstPath':['inner',0],'byteLineageDeclarationCorrespondenceVerified':True,
                          'sourceSignature':SIG,'candidateSignature':SIG}],
      'dataModels':{n:MODEL for n in ('source','candidate','nativeTarget')},
      'graphs':{n:{'typeGraph':[],'functionDefinitions':[definition]} for n in ('source','candidate','nativeTarget')}}
    # No native C function body is invented for an assembly-backed provider.
    report['graphs']['nativeTarget']['functionDefinitions']=[]
    report['graphs']['nativeTarget']['functionDeclarations']=[definition,deepcopy(definition)]
    _,interface=run.selection(report,['inner',0])
    assert interface['parameters'][0]['kind']=='pointer'
    bad=deepcopy(definition);bad['signature']['parameters'][2]={'qualType':'unsigned int'}
    report['graphs']['nativeTarget']['functionDeclarations'].append(bad)
    with pytest.raises(ValueError,match='MISMATCH'):run.selection(report,['inner',0])


def test_target_crash_or_missing_protocol_is_a_failure_with_valid_source():
    assert run.observation_status(0,-11,True,False,['exit-code'])=='failed'
    assert run.observation_status(0,0,True,False,[])=='failed'
    assert run.observation_status(-11,-11,False,False,[])=='inconclusive'
    assert run.observation_status(0,0,True,True,[])=='verified'
