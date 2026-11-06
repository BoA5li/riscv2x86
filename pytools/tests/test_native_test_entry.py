from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from riscv2x86_py import native_test_entry as entry
from riscv2x86_py.project_build_records import record, document, identity
from riscv2x86_py.project_compile_context import digest


def fixture(tmp_path, monkeypatch):
    gcc = shutil.which('gcc')
    if not gcc: pytest.skip('native GCC required to create an ELF fixture')
    source = tmp_path/'driver.c'; source.write_text('int main(void) { return 0; }')
    exe = tmp_path/'driver'
    subprocess.run([gcc, str(source), '-o', str(exe)], capture_output=True, check=True)
    # A deliberately synthetic RV64-header fixture, never executed and never
    # passed off as real cross-compiler integration.
    raw = bytearray(exe.read_bytes()); raw[18:20] = (243).to_bytes(2, 'little'); exe.write_bytes(raw)
    typ = int.from_bytes(raw[16:18], 'little')
    action = record(['gcc', '-o', str(exe), str(source)], tmp_path, {'kind': 'test'})
    action.pop('actionIdentity'); action.update(exitStatusObserved=True, observedReturnCode=0,
        observedOutput={'path': str(exe), 'resolvedPath': str(exe.resolve()), 'digest': digest(exe),
            'elfHeader': {'byteOrder': 'little', 'classBits': 64, 'machine': 243, 'type': typ}})
    action['actionIdentity'] = identity(action)
    records = document([action], [], [], 'test'); records.pop('inventoryIdentity')
    records.update(captureConfig='unit-config', stageSelection='test-stage', importComplete=True,
        selectedRunFailures=[])
    records['inventoryIdentity'] = identity(records)
    path = tmp_path/'records.json'; path.write_text(json.dumps(records))
    from riscv2x86_py import project_build_capture
    monkeypatch.setattr(project_build_capture, 'inventory', lambda *a, **kw: deepcopy(records))
    return path, action, exe, records


def test_metadata_is_bound_to_capture_but_does_not_claim_execution(tmp_path, monkeypatch):
    path, action, exe, _ = fixture(tmp_path, monkeypatch)
    value = entry.acquire(path, action['actionIdentity'])
    assert value['capturedOutputBindingVerified']
    assert value['metadata']['elfMachine'] == 243
    assert 'libc.so.6' in value['metadata']['needed']
    assert value['metadata']['interpreter']
    assert not value['runtimeLibrarySelectionVerified']
    assert not value['testExecutionPerformed'] and not value['productionAcceptanceComplete']
    assert entry.replay(value)['entryMetadataReplayComplete']


def test_changed_executable_or_capture_cannot_be_accepted(tmp_path, monkeypatch):
    path, action, exe, _ = fixture(tmp_path, monkeypatch)
    exe.write_bytes(exe.read_bytes()+b'changed')
    with pytest.raises(ValueError, match='EXECUTABLE_CHANGED'):
        entry.acquire(path, action['actionIdentity'])


def test_unknown_action_does_not_select_a_file_by_name(tmp_path, monkeypatch):
    path, _, _, _ = fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match='EXPLICIT_LINK_ACTION_REQUIRED'):
        entry.acquire(path, 'unrecorded')


@pytest.mark.parametrize('flag', ['runtimeLibrarySelectionVerified', 'testExecutionPerformed',
    'targetAsmExecutionCoverageVerified', 'legalObjectDomainVerified', 'productionAcceptanceComplete'])
def test_rehashed_execution_claim_is_rejected(tmp_path, monkeypatch, flag):
    path, action, _, _ = fixture(tmp_path, monkeypatch)
    value = entry.acquire(path, action['actionIdentity']); value[flag] = True
    value['entryMetadataIdentity'] = identity({k:v for k,v in value.items() if k != 'entryMetadataIdentity'})
    with pytest.raises(ValueError, match='REPLAY_MISMATCH'):
        entry.replay(value)


def test_host_architecture_is_not_accepted_as_rv64(tmp_path, monkeypatch):
    _, _, exe, _ = fixture(tmp_path, monkeypatch)
    raw = bytearray(exe.read_bytes()); raw[18:20] = (62).to_bytes(2, 'little'); exe.write_bytes(raw)
    with pytest.raises(ValueError, match='RV64_EXECUTABLE_REQUIRED'):
        entry.metadata(exe)
