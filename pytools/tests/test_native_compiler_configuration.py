from pathlib import Path
import shutil
import subprocess

import pytest

from riscv2x86_py.native_compiler_configuration import observe
from riscv2x86_py.project_build_records import record


def test_actual_native_specs_macros_headers_and_defaults_are_bound(tmp_path):
    cc = shutil.which('gcc')
    if cc is None: pytest.skip('native GCC required')
    (tmp_path/'settings.h').write_text('#define ACTUAL_HEADER_SETTING 73\n')
    (tmp_path/'input.c').write_text('#include "settings.h"\nint f(void){return ACTUAL_HEADER_SETTING;}\n')
    argv = [cc, '-O2', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
            '-c', 'input.c', '-o', 'input.o']
    subprocess.run(argv, cwd=tmp_path, check=True)
    # A native observation fixture. It is not a captured cross-ISA build receipt.
    action = record(argv, tmp_path, {'kind': 'unit-observation'})
    value = observe(action, tmp_path/'observed')
    text = (tmp_path/'observed/macros/stdout.log').read_text()
    assert '#define ACTUAL_HEADER_SETTING 73' in text
    assert '#define _FORTIFY_SOURCE 2' in text
    assert any(Path(r['resolvedPath']).name == 'settings.h' for r in value['dependencySnapshots'])
    assert not value['generatedMechanismVerified'] and not value['compilerAbiVerified']
    assert len(value['commands']) == 9
    assert (tmp_path/'observed/specs/stdout.log').stat().st_size > 0
    second = observe(action, tmp_path/'again')
    assert second == value
    (tmp_path/'settings.h').write_text('#define ACTUAL_HEADER_SETTING 74\n')
    third = observe(action, tmp_path/'changed')
    assert third['configurationIdentity'] != value['configurationIdentity']


def test_unknown_compilation_semantics_are_not_stripped(tmp_path):
    cc = shutil.which('gcc')
    if cc is None: pytest.skip('native GCC required')
    source = tmp_path/'source.c'; source.write_text('int f(void){return 0;}')
    action = record([cc, '-fplugin=unreviewed.so', '-c', str(source), '-o', str(tmp_path/'out.o')],
                    tmp_path, {'kind': 'unit-observation'})
    with pytest.raises(ValueError, match='CONTEXT_BLOCKED'):
        observe(action, tmp_path/'out')
    assert not (tmp_path/'out').exists()
