"""Synthetic filesystem/runtime fixtures; no real Ghidra execution claim."""
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py import ghidra_configuration as config
from riscv2x86_py import ghidra_runtime as runtime


def installation(root):
    (root/'support').mkdir(parents=True)
    launcher=root/'support/pythonRun';launcher.write_text('#!/bin/sh\nexit 0\n');launcher.chmod(0o755)
    return root


@pytest.mark.parametrize('value',['','  ','\0',False,123])
def test_explicit_invalid_path_never_uses_environment_or_current_directory(tmp_path,value):
    valid=installation(tmp_path/'valid')
    with pytest.raises(config.GhidraConfigurationError):
        config.resolve_install_dir(value,environ={'GHIDRA_INSTALL_DIR':str(valid)})


def test_selection_precedence_and_canonical_paths(tmp_path,monkeypatch):
    first=installation(tmp_path/'first with spaces');second=installation(tmp_path/'second')
    monkeypatch.setattr(config,'DEFAULT_INSTALL_DIR',first)
    assert config.resolve_install_dir(environ={})==first
    assert config.resolve_install_dir(environ={'GHIDRA_INSTALL_DIR':str(second)})==second
    assert config.resolve_install_dir(first,environ={'GHIDRA_INSTALL_DIR':str(second)})==first
    monkeypatch.chdir(tmp_path)
    assert config.resolve_install_dir('second',environ={})==second
    alias=tmp_path/'alias';alias.symlink_to(second,target_is_directory=True)
    assert config.resolve_install_dir(alias,environ={})==second
    with pytest.raises(config.GhidraConfigurationError,match='EMPTY'):
        config.resolve_install_dir(environ={'GHIDRA_INSTALL_DIR':''})


@pytest.mark.parametrize('kind',['absent','file','no-launcher','not-executable'])
def test_directory_and_launcher_are_checked_before_execution(tmp_path,kind):
    root=tmp_path/'root'
    if kind=='file':root.write_text('not directory')
    elif kind=='no-launcher':root.mkdir()
    elif kind=='not-executable':
        installation(root);(root/'support/pythonRun').chmod(0o644)
    with pytest.raises(config.GhidraConfigurationError):config.resolve_install_dir(root,environ={})


def test_runtime_uses_same_selection_and_rejects_cached_installation_switch(tmp_path,monkeypatch):
    first=installation(tmp_path/'first');second=installation(tmp_path/'second');calls=[]
    monkeypatch.setitem(sys.modules,'pyghidra',SimpleNamespace(start=lambda **kw:calls.append(kw)))
    monkeypatch.setattr(runtime,'_runtime_started',False);monkeypatch.setattr(runtime,'_runtime_install_dir',None)
    monkeypatch.setenv('GHIDRA_INSTALL_DIR',str(first))
    runtime.start_ghidra_runtime()
    assert calls==[{'install_dir':first}]
    runtime.start_ghidra_runtime(ghidra_install_dir=str(first));assert len(calls)==1
    monkeypatch.setattr(runtime,'_language_cache',{'language':object()})
    with pytest.raises(runtime.GhidraRuntimeError,match='INSTALLATION_MISMATCH'):
        runtime.load_real_ghidra_language('language',ghidra_install_dir=str(second))
    with pytest.raises(runtime.GhidraRuntimeError,match='EMPTY'):
        runtime.start_ghidra_runtime(ghidra_install_dir='')
