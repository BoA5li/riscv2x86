from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest

from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py.project_instance_eligibility import bind_slice
from riscv2x86_py import project_native_macro_preflight as module


def test_source_slice_requires_dependency_content_and_explicit_files(tmp_path):
    path=tmp_path/'header.h';path.write_text('abcdefgh')
    deps=[{'resolvedPath':str(path),'digest':digest(path)}]
    a={'file':'header.h','offset':1,'tokLen':1};b={'file':'header.h','offset':4,'tokLen':1}
    value=bind_slice(a,b,tmp_path,deps)
    assert value['beginOffset']==1 and value['endOffset']==5
    with pytest.raises(ValueError):bind_slice(a,{'offset':4,'tokLen':1},tmp_path,deps)
    with pytest.raises(ValueError):bind_slice(dict(a,offset=True),b,tmp_path,deps)
    with pytest.raises(ValueError):bind_slice(dict(a,file='<scratch space>'),b,tmp_path,deps)
    path.write_text('ABCDefgh')
    with pytest.raises(ValueError,match='CONTENT_MISMATCH'):bind_slice(a,b,tmp_path,deps)


def fixture(tmp_path,monkeypatch,*,mismatch=False,failed=None,mutate=False):
    source=tmp_path/'original.c';source.write_text('typedef unsigned long word; word f(word x){return x;}\n')
    context={'contextIdentity':'context','sourcePath':str(source),'sourceDigest':digest(source),
             'workingDirectory':str(tmp_path),'nativeCompiler':sys.executable}
    manifest={'compilerCommand':[sys.executable,'--target=riscv64-linux-gnu','-std=c99',
        '-fsyntax-only','-Xclang','-ast-dump=json',str(source)],'dependencyIdentity':'dependencies'}
    report={'records':[{'context':context,'inspection':{'snapshot':{'dependencyManifest':manifest}}}]}
    report_path=tmp_path/'contexts.json';report_path.write_text(json.dumps(report))
    eligibility={'eligibilityInventoryIdentity':'eligibility','records':[{
        'contextIdentity':'context','inspectionReportPath':str(report_path),'inspectionReportDigest':digest(report_path)}]}
    monkeypatch.setattr(module,'validate_eligibility',lambda _:None)
    monkeypatch.setattr(module,'validate_context',lambda _:None)
    monkeypatch.setattr(module,'validate_dependencies',lambda _:None)
    monkeypatch.setattr(module,'source_arguments',lambda _:['-std=c99'])
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        if failed is not None and '-dD' in command:
            return SimpleNamespace(returncode=failed,stdout=b'partial',stderr=b'definitions failed')
        if '-M' in command:
            text=f'rv2x86_call_inventory: {source}\n'
        elif '-dD' in command:text='#define VALUE 1\nint f(int x){return x;}\n'
        elif '-dM' in command:text='#define __riscv 1\n'
        elif '--target=riscv64-linux-gnu' in command and mismatch:text='int f(int x){return x+1;}\n'
        else:text='int f(int x){return x;}\n'
        if mutate and '-dM' in command:source.write_text('changed\n')
        return SimpleNamespace(returncode=0,stdout=text.encode(),stderr=b'')
    monkeypatch.setattr(module.subprocess,'run',run)
    return eligibility,calls


def test_capture_protocol_keeps_bytes_and_independent_replay(tmp_path,monkeypatch):
    value,calls=fixture(tmp_path,monkeypatch)
    receipt=module.acquire(value,'context',tmp_path/'capture')
    assert receipt['sourcePreprocessingMatched'] is True
    assert receipt['nativeCompilerActivationConfirmed'] is False
    assert receipt['macroArgumentGraphComplete'] is False
    assert receipt['editAuthorizationComplete'] is False
    assert len(receipt['commands'])==6 and len(calls)==6
    result=module.replay(receipt,value,tmp_path/'replay')
    assert result['nativePreprocessingReplayComplete'] is True
    assert result['semanticApproval'] is False
    with pytest.raises(FileExistsError):module.acquire(value,'context',tmp_path/'capture')


def test_token_difference_is_not_normalized_away(tmp_path,monkeypatch):
    value,_=fixture(tmp_path,monkeypatch,mismatch=True)
    with pytest.raises(ValueError,match='PREPROCESSING_MISMATCH'):module.acquire(value,'context',tmp_path/'capture')
    receipt=json.loads((tmp_path/'capture/preflight.json').read_text())
    assert receipt['sourcePreprocessingMatched'] is False and receipt['firstDifference']
    state=json.loads((tmp_path/'capture/run-status.json').read_text())
    assert state['status']=='failed' and state['acquisitionComplete'] is False


def test_actual_exit_is_preserved_and_failed_output_not_approved(tmp_path,monkeypatch):
    from riscv2x86_py.project_acquisition import StageFailure
    value,_=fixture(tmp_path,monkeypatch,failed=7)
    with pytest.raises(StageFailure) as failure:module.acquire(value,'context',tmp_path/'capture')
    assert failure.value.code==7
    state=json.loads((tmp_path/'capture/run-status.json').read_text())
    assert state['primaryFailure']['returnCode']==7
    assert not state['acquisitionComplete'] and not (tmp_path/'capture/preflight.json').exists()


def test_source_change_during_capture_is_detected(tmp_path,monkeypatch):
    value,_=fixture(tmp_path,monkeypatch,mutate=True)
    with pytest.raises(ValueError,match='DEPENDENCIES_CHANGED'):module.acquire(value,'context',tmp_path/'capture')


def test_changed_artifact_cannot_be_replayed(tmp_path,monkeypatch):
    value,_=fixture(tmp_path,monkeypatch)
    receipt=module.acquire(value,'context',tmp_path/'capture')
    Path(receipt['commands'][0]['stdoutPath']).write_text('forged')
    with pytest.raises(ValueError,match='ARTIFACT_CHANGED'):module.replay(receipt,value,tmp_path/'replay')


def test_timeout_has_persistent_failure_and_no_complete_receipt(tmp_path,monkeypatch):
    value,_=fixture(tmp_path,monkeypatch)
    def fail(*args,**kwargs):raise subprocess.TimeoutExpired('compiler',1)
    monkeypatch.setattr(module.subprocess,'run',fail)
    with pytest.raises(subprocess.TimeoutExpired):module.acquire(value,'context',tmp_path/'capture')
    state=json.loads((tmp_path/'capture/run-status.json').read_text())
    assert state['status']=='failed' and not state['acquisitionComplete']


def test_native_existing_high_multiply_helper_against_wide_reference(tmp_path):
    import ctypes
    import random
    import shutil
    cc=shutil.which('gcc')
    if cc is None:pytest.skip('native GCC required for existing runtime helper integration')
    repo=Path(__file__).parents[2];library=tmp_path/'helper.so'
    subprocess.run([cc,'-shared','-fPIC',str(repo/'runtime/riscv2x86_runtime_helpers.c'),
                    '-I'+str(repo/'runtime/include'),'-o',str(library)],capture_output=True,check=True)
    function=ctypes.CDLL(str(library)).riscv2x86_rt_rv64_mulhu_u64
    function.argtypes=[ctypes.c_uint64,ctypes.c_uint64];function.restype=ctypes.c_uint64
    seeds=[0,1,2,2**32-1,2**32,2**63,2**64-2,2**64-1]
    generator=random.Random(1823)
    pairs=[(a,b) for a in seeds for b in seeds]+[(generator.getrandbits(64),generator.getrandbits(64)) for _ in range(128)]
    for a,b in pairs:assert function(a,b)==(a*b)>>64
