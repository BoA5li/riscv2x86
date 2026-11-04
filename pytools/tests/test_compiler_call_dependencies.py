"""Dependency acquisition consistency; no fake compiler output is acceptance."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import pytest

from riscv2x86_py.compiler_call_dependencies import acquire, parse_dependencies, validate
from tests.test_compiler_call_inventory import function


def test_make_escaping_and_continuation():
    assert parse_dependencies('rv2x86_call_inventory: a.c dir\\ name/h\\#1.h \\\n dollar$$.h colon\\:x.h\n') == ['a.c','colon:x.h','dir name/h#1.h','dollar$.h']


@pytest.mark.parametrize('text', ['other: x.c', 'rv2x86_call_inventory:',
    'rv2x86_call_inventory: $HOME/x', 'rv2x86_call_inventory: a\nother: b'])
def test_ambiguous_make_rules_reject(text):
    with pytest.raises(ValueError): parse_dependencies(text)


def prepare(tmp_path, monkeypatch, *, changed=False):
    source = tmp_path/'entry.c'; source.write_text('void entry(void) {}\n')
    header = tmp_path/'a header.h'; header.write_text('#define X 1\n')
    dependencies = 'rv2x86_call_inventory: '+str(source)+' '+str(header).replace(' ', '\\ ')+'\n'
    def run(command, **kwargs):
        if '-M' in command:
            return SimpleNamespace(returncode=0, stdout=dependencies, stderr='')
        if changed: header.write_text('#define X 2\n')
        return SimpleNamespace(returncode=0, stdout=json.dumps(
            {'kind':'TranslationUnitDecl','inner':[function('entry')]}), stderr='')
    monkeypatch.setattr('riscv2x86_py.compiler_call_dependencies.subprocess.run', run)
    return source, header


def test_dependency_content_is_rechecked_and_never_grants_semantic_approval(tmp_path, monkeypatch):
    source, header = prepare(tmp_path, monkeypatch)
    result = acquire(source, clang=sys.executable, target='riscv64')
    manifest = result['dependencyManifest']
    assert validate(manifest)['acquisitionConsistent'] is True
    assert not result['dependencyClosureVerified']
    assert not manifest['semanticApproval'] and not manifest['linkClosureVerified']
    assert not manifest['immutableSnapshot']
    header.write_text('#define X 3\n')
    with pytest.raises(ValueError, match='CONTENT_CHANGED'): validate(manifest)


def test_header_modified_during_ast_acquisition_rejects(tmp_path, monkeypatch):
    source, _ = prepare(tmp_path, monkeypatch, changed=True)
    with pytest.raises(ValueError, match='CONTENT_CHANGED'):
        acquire(source, clang=sys.executable, target='riscv64')


def test_rehashed_inventory_reference_requires_fresh_compiler_replay(tmp_path,monkeypatch):
    from riscv2x86_py.compiler_value_flow import identity
    source,_=prepare(tmp_path,monkeypatch)
    manifest=acquire(source,clang=sys.executable,target='riscv64')['dependencyManifest']
    manifest['inventoryIdentity']=identity('different-inventory')
    manifest['dependencyIdentity']=identity({k:v for k,v in manifest.items() if k!='dependencyIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):validate(manifest)


@pytest.mark.parametrize('args', [['@options'], ['-Xclang','-load'], ['-MF','other'], ['-include']])
def test_unsupported_acquisition_recipe_cannot_redirect_compiler_outputs(tmp_path, monkeypatch, args):
    source, _ = prepare(tmp_path, monkeypatch)
    with pytest.raises(ValueError): acquire(source, clang=sys.executable, target='riscv64', compile_args=args)


def test_rehashed_manifest_cannot_claim_immutable_or_link_closure(tmp_path, monkeypatch):
    from riscv2x86_py.compiler_value_flow import identity
    source, _ = prepare(tmp_path, monkeypatch)
    manifest = acquire(source, clang=sys.executable, target='riscv64')['dependencyManifest']
    for flag in ('immutableSnapshot','semanticApproval','linkClosureVerified','productionAcceptanceComplete'):
        other = deepcopy(manifest); other[flag] = True
        other['dependencyIdentity'] = identity({k:v for k,v in other.items() if k != 'dependencyIdentity'})
        with pytest.raises(ValueError): validate(other)


def test_real_clang_header_and_space_paths(tmp_path):
    import os
    clang = os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    if not clang: pytest.skip('real Clang required')
    header = tmp_path/'a header.h'; header.write_text('static unsigned helper(unsigned x){return x;}\n')
    source = tmp_path/'entry.c'; source.write_text('#include "a header.h"\nunsigned entry(unsigned x){return helper(x);}\n')
    result = acquire(source, clang=clang, target='riscv64')
    assert validate(result['dependencyManifest'])
    assert str(header) in {r['resolvedPath'] for r in result['dependencyManifest']['dependencies']}
    assert not result['dependencyClosureVerified']  # Header function proof remains separate.


def test_paired_isysroot_is_consumed_consistently_and_replayed(tmp_path,monkeypatch):
    source,_=prepare(tmp_path,monkeypatch)
    result=acquire(source,clang=sys.executable,target='riscv64',compile_args=['-isysroot',str(tmp_path)])
    command=result['compilerCommand']
    assert command[command.index('-isysroot')+1]==str(tmp_path)
    assert validate(result['dependencyManifest'])['acquisitionConsistent']
    with pytest.raises(ValueError,match='INCOMPLETE'):
        acquire(source,clang=sys.executable,target='riscv64',compile_args=['-isysroot'])
