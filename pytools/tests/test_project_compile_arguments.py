from pathlib import Path
import shutil
import subprocess
import sys
import pytest
from riscv2x86_py.project_build_records import record
from riscv2x86_py.project_compile_context import derive,validate
from riscv2x86_py.project_build_contract import source_arguments,compiler_profile
from riscv2x86_py.project_native_build import build
from riscv2x86_py.project_compile_arguments import action_option


def context(tmp_path,extras):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native GCC required')
    (tmp_path/'x.c').write_text('int entry(void){return 3;}\n')
    return derive(record([gcc,'-std=c99','-ffunction-sections','-fdata-sections',*extras,'-c','x.c'],tmp_path,{'kind':'test'}))


@pytest.mark.parametrize('extras', [
    ['-ox.o','-MMD','-MFx.d','-MTtarget'],
    ['-o','x.o','-Wp,-MMD,x.d'],
    ['-o','x.o','-Wp,-MD,x.d'],
    ['-o','x.o','-MMD','-MF','x.d','-MQtarget'],
])
def test_real_native_replay_redirects_all_dependency_outputs(tmp_path,extras):
    c=context(tmp_path,extras);assert c['inspectionReady'];validate(c)
    args=source_arguments(c)
    assert not any(a.startswith(('-ox.o','-MF','-MT','-MQ','-Wp,')) for a in args)
    assert '-ffunction-sections' in args
    (tmp_path/'x.d').write_text('original evidence\n')
    result=build(c,tmp_path/'replay')
    assert result['nativeCompileReplayed']
    assert (tmp_path/'replay/native.o').is_file()
    assert (tmp_path/'replay/native.d').is_file()
    assert (tmp_path/'x.d').read_text()=='original evidence\n'
    assert not (tmp_path/'x.o').exists()


@pytest.mark.parametrize('flag', ['-Wp,-DNEW','-Wp,-MMD,a.d,-DNEW','-Wp,-MD,','-fplugin=evil.so'])
def test_unsupported_or_ambiguous_options_are_still_blocked(tmp_path,flag):
    c=context(tmp_path,['-o','x.o',flag]);assert not c['inspectionReady']


@pytest.mark.parametrize('flag', ['-MFdep.d','-MTtarget','-MQtarget','-Wp,-MMD,dep.d'])
def test_profiles_cannot_smuggle_action_outputs(tmp_path,flag):
    c=context(tmp_path,['-o','x.o'])
    with pytest.raises(ValueError,match='ACTION_ARGUMENT_FORBIDDEN'):
        compiler_profile(c['nativeCompiler'],['-std=c99',flag],tmp_path,source=c['sourcePath'])


def test_duplicate_output_or_missing_value_is_not_guessed(tmp_path):
    assert not context(tmp_path,['-ox.o','-o','y.o'])['inspectionReady']
    with pytest.raises(ValueError):action_option(['-MF'],0)


def test_explicit_common_linkage_options_cannot_silently_disagree(tmp_path):
    from riscv2x86_py.project_build_contract import make
    c=context(tmp_path,['-fno-common','-o','x.o'])
    with pytest.raises(ValueError,match='SEMANTIC_ARGUMENTS_MISMATCH'):
        make(c,clang=sys.executable,target_compiler=c['nativeCompiler'],
            target_arguments=['-std=c99','-fcommon'],target_directory=tmp_path,
            source_driver_arguments=[],target_driver_arguments=[])
