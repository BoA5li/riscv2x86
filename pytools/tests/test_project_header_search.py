from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import pytest

from riscv2x86_py import project_header_search as h
from riscv2x86_py.project_build_records import identity,record
from riscv2x86_py.project_compile_context import derive,acquire as inspect_context
from riscv2x86_py.compiler_call_dependencies import acquire,validate


def protocol(paths=(), quotes=()):
    return '#include "..." search starts here:\n'+''.join(' '+str(p)+'\n' for p in quotes)+\
        '#include <...> search starts here:\n'+''.join(' '+str(p)+'\n' for p in paths)+'End of search list.\n'


def context(tmp_path):
    source=tmp_path/'entry.c';source.write_text('unsigned long entry(void){return 1;}\n')
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC required')
    return derive(record([cc,'-std=gnu11','-c',str(source),'-o',str(tmp_path/'x.o')],tmp_path,{'kind':'test'}))


def fake_compilers(monkeypatch, ctx, dirs):
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        if '-v' in command:
            return SimpleNamespace(returncode=0,stdout='',stderr=protocol(dirs))
        if '-M' in command:
            return SimpleNamespace(returncode=0,stderr='',stdout='rv2x86_call_inventory: '+ctx['sourcePath']+'\n')
        return SimpleNamespace(returncode=0,stderr='',stdout=json.dumps({'kind':'TranslationUnitDecl','inner':[]}))
    monkeypatch.setattr(h.subprocess,'run',run)
    return calls


def test_parse_keeps_order_and_resolves_relative_paths(tmp_path):
    (tmp_path/'quote').mkdir(); (tmp_path/'a b').mkdir();(tmp_path/'target').mkdir()
    rows=h.parse_search(protocol(['a b','target'],['quote']),tmp_path)
    assert [(r['kind'],r['resolvedPath']) for r in rows]==[
        ('quote',str(tmp_path/'quote')),('angle',str(tmp_path/'a b')),('angle',str(tmp_path/'target'))]


@pytest.mark.parametrize('text',['',protocol()+'End of search list.\n',
    '#include <...> search starts here:\n#include "..." search starts here:\nEnd of search list.\n',
    '#include "..." search starts here:\n#include <...> search starts here:\n /unknown (framework directory)\nEnd of search list.\n'])
def test_incomplete_ambiguous_or_unsupported_protocol_blocks(tmp_path,text):
    with pytest.raises(ValueError):h.parse_search(text,tmp_path)


def test_real_native_gcc_search_is_bound_and_replayed(tmp_path):
    ctx=context(tmp_path); receipt=h.acquire(ctx)
    assert h.validate(receipt,context=ctx)==receipt
    assert receipt['probe']['directories']
    assert not receipt['semanticApproval'] and not receipt['compilerEquivalenceVerified']
    assert '-nostdinc' in h.projection(receipt)


def test_project_acquisition_binds_headers_and_roundtrip_dependencies(tmp_path,monkeypatch):
    ctx=context(tmp_path);target=tmp_path/'target';target.mkdir()
    calls=fake_compilers(monkeypatch,ctx,[target])
    observed=inspect_context(ctx,clang=sys.executable)
    manifest=observed['snapshot']['dependencyManifest']
    assert manifest['schemaVersion']=='riscv2x86.compiler-call-dependencies.v2'
    assert validate(manifest)==manifest
    assert any('-isystem' in cmd and str(target) in cmd for cmd in calls if '-M' in cmd)
    assert not observed['compilerEquivalenceVerified']
    restored=json.loads(json.dumps(manifest));assert validate(restored)==manifest


def test_rehashed_search_order_and_source_changes_cannot_pass(tmp_path,monkeypatch):
    ctx=context(tmp_path);a=tmp_path/'a';b=tmp_path/'b';a.mkdir();b.mkdir()
    fake_compilers(monkeypatch,ctx,[a,b]);receipt=h.acquire(ctx)
    bad=deepcopy(receipt);bad['probe']['directories'].reverse()
    bad['headerSearchIdentity']=identity({k:v for k,v in bad.items() if k!='headerSearchIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):h.validate(bad)
    Path(ctx['sourcePath']).write_text('changed')
    with pytest.raises(ValueError,match='SOURCE_CHANGED'):h.validate(receipt)


def test_inspector_wrong_search_order_is_not_accepted(tmp_path,monkeypatch):
    ctx=context(tmp_path);a=tmp_path/'a';b=tmp_path/'b';a.mkdir();b.mkdir()
    def run(command,**kwargs):
        return SimpleNamespace(returncode=0,stdout='',stderr=protocol([b,a] if '--target=riscv64-linux-gnu' in command else [a,b]))
    monkeypatch.setattr(h.subprocess,'run',run)
    with pytest.raises(ValueError,match='ORDER_MISMATCH'):
        acquire(ctx['sourcePath'],clang=sys.executable,target='riscv64',working_directory=tmp_path,
                compile_args=ctx['inspectionArguments'],native_context=ctx)


def test_profile_is_exact_and_missing_match_does_not_fallback(tmp_path,monkeypatch):
    ctx=context(tmp_path);value={'schemaVersion':h.PROFILE_SCHEMA,'contexts':[ctx]};value['profileIdentity']=identity(value)
    path=tmp_path/'profile.json';path.write_text(json.dumps(value));monkeypatch.setenv(h.PROFILE_ENV,str(path))
    assert h.configured_context(ctx['sourcePath'],ctx['inspectionArguments'],tmp_path)==ctx
    with pytest.raises(ValueError,match='MATCH_REQUIRED'):h.configured_context(ctx['sourcePath'],['-O3'],tmp_path)


def test_projection_does_not_turn_explicit_project_I_into_system_include(tmp_path):
    explicit=tmp_path/'project';system=tmp_path/'system';explicit.mkdir();system.mkdir()
    value={'inspectionArguments':['-I',str(explicit)],'probe':{
        'workingDirectory':str(tmp_path),'searchEnvironment':{},'directories':h.parse_search(protocol([explicit,system]),tmp_path)}}
    assert h.projection(value)==['-nostdinc','-isystem',str(system)]


def test_rehashed_native_probe_cannot_inject_outputs(tmp_path,monkeypatch):
    ctx=context(tmp_path);fake_compilers(monkeypatch,ctx,[]);receipt=h.acquire(ctx)
    receipt['nativeArguments']+=['-o',str(tmp_path/'injected')]
    receipt['headerSearchIdentity']=identity({k:v for k,v in receipt.items() if k!='headerSearchIdentity'})
    with pytest.raises(ValueError):h.validate(receipt)
    assert not (tmp_path/'injected').exists()


def test_native_probe_errors_are_not_silently_replaced_by_host_paths(tmp_path,monkeypatch):
    ctx=context(tmp_path)
    monkeypatch.setattr(h.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=1,stdout='',stderr='toolchain failed'))
    with pytest.raises(ValueError,match='PROBE_FAILED'):h.acquire(ctx)


def test_real_riscv_clang_stdio_and_native_header_binding(tmp_path):
    clang=os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    cc=os.environ.get('RV2X86_TEST_RISCV_CC') or shutil.which('riscv64-linux-gnu-gcc-7') or shutil.which('riscv64-linux-gnu-gcc')
    if not clang or not cc:pytest.skip('real Clang and RISC-V GCC required')
    source=tmp_path/'entry.c';source.write_text('#include <stdio.h>\nunsigned long entry(void){return sizeof(FILE);}\n')
    ctx=derive(record([cc,'-std=gnu11','-march=rv64gc','-mabi=lp64d','-c',str(source),'-o',str(tmp_path/'x.o')],tmp_path,{'kind':'test'}))
    result=inspect_context(ctx,clang=clang)
    manifest=result['snapshot']['dependencyManifest']
    assert validate(manifest)==manifest
    assert any('stdio.h' in row['resolvedPath'] for row in manifest['dependencies'])
    assert not result['semanticApproval']


def test_configured_context_reaches_legacy_acquisition_and_replay_is_bound(tmp_path,monkeypatch):
    ctx=context(tmp_path);target=tmp_path/'target';target.mkdir()
    fake_compilers(monkeypatch,ctx,[target])
    profile={'schemaVersion':h.PROFILE_SCHEMA,'contexts':[ctx]};profile['profileIdentity']=identity(profile)
    path=tmp_path/'contexts.json';path.write_text(json.dumps(profile));monkeypatch.setenv(h.PROFILE_ENV,str(path))
    result=acquire(ctx['sourcePath'],clang=sys.executable,target='riscv64',compile_args=ctx['inspectionArguments'],working_directory=tmp_path)
    manifest=result['dependencyManifest']
    assert manifest['schemaVersion']=='riscv2x86.compiler-call-dependencies.v2'
    monkeypatch.delenv(h.PROFILE_ENV)
    assert validate(manifest)==manifest
    bad=deepcopy(manifest);bad['inspectionHeaderSearch']['directories']=[]
    bad['dependencyIdentity']=identity({k:v for k,v in bad.items() if k!='dependencyIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):validate(bad)


def test_project_operation_supplies_context_without_process_global_profile(tmp_path,monkeypatch):
    from tests.test_project_build_contract import contract
    from riscv2x86_py.project_validation_operation import operation
    c=contract(tmp_path);ctx=c['sourceContext'];fake_compilers(monkeypatch,ctx,[])
    monkeypatch.delenv(h.PROFILE_ENV,raising=False)
    with operation(c):
        result=acquire(ctx['sourcePath'],clang=sys.executable,target='riscv64',
            compile_args=ctx['inspectionArguments'],working_directory=ctx['workingDirectory'])
    assert result['dependencyManifest']['nativeHeaderSearch']['contextIdentity']==ctx['contextIdentity']
    assert validate(result['dependencyManifest'])
