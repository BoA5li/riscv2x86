import os
from pathlib import Path
import sys
import pytest
from riscv2x86_py.project_tool_resolution import resolve_executable
from riscv2x86_py.project_build_records import record
from riscv2x86_py.project_compile_context import derive
from riscv2x86_py.project_build_capture import create,run


def executable(path,text='#!/bin/sh\nexit 0\n'):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);path.chmod(0o755);return path


def test_relative_path_is_resolved_in_action_cwd(tmp_path,monkeypatch):
    caller=tmp_path/'caller';action=tmp_path/'action';caller.mkdir();action.mkdir()
    wrong=executable(caller/'bin/gcc');right=executable(action/'bin/gcc')
    monkeypatch.chdir(caller);monkeypatch.setenv('PATH','bin')
    assert resolve_executable('gcc',action)==right
    assert resolve_executable('./bin/gcc',action)==right
    (action/'x.c').write_text('int x;')
    context=derive(record(['gcc','-c','x.c','-o','x.o'],action,{'kind':'test'}))
    assert context['nativeCompiler']==str(right) and context['inspectionReady']


def test_empty_path_entry_means_action_cwd(tmp_path,monkeypatch):
    tool=executable(tmp_path/'tool');monkeypatch.setenv('PATH','')
    assert resolve_executable('tool',tmp_path)==tool
    tool.chmod(0o644)
    with pytest.raises((OSError,ValueError)):resolve_executable('tool',tmp_path)


def test_run_does_not_execute_a_same_named_program_in_caller_cwd(tmp_path,monkeypatch):
    caller=tmp_path/'caller';action=tmp_path/'action';caller.mkdir();action.mkdir()
    executable(caller/'go','#!/bin/sh\nexit 9\n');executable(action/'go')
    create(tmp_path/'capture',{'python':sys.executable})
    monkeypatch.chdir(caller)
    assert run(tmp_path/'capture/capture.json','test',['./go'],cwd=action)[1]==0
