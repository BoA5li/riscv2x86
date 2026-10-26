"""Lifecycle tests use fake tools, never count as real calibration or L3 proof."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
from riscv2x86_py import l3_status as status_io
from riscv2x86_py.l3_trace_support import save


def test_mutable_status_and_immutable_evidence(tmp_path):
    path = tmp_path/'status.json'
    for stage in ('plugin', 'calibration', 'complete'):
        status_io.write_status_atomic(path, {'stage': stage, 'message': '校准'})
        assert json.loads(path.read_text()) == {'stage': stage, 'message': '校准'}
    evidence = tmp_path/'evidence.json'
    save(evidence, {'original': True})
    with pytest.raises(FileExistsError):
        save(evidence, {'original': False})
    assert json.loads(evidence.read_text()) == {'original': True}


@pytest.mark.parametrize('failure', ['serialize', 'replace', 'fsync'])
def test_failed_update_preserves_previous_json(tmp_path, monkeypatch, failure):
    path = tmp_path/'status.json'
    status_io.write_status_atomic(path, {'previous': True})
    def fail(*args): raise OSError('injected write failure')
    if failure != 'serialize': monkeypatch.setattr(status_io.os, failure, fail)
    with pytest.raises((TypeError, OSError)):
        status_io.write_status_atomic(path, {'next': object() if failure == 'serialize' else True})
    assert json.loads(path.read_text()) == {'previous': True}
    assert not list(tmp_path.glob('*.tmp'))


def test_double_failure_retains_primary_error(tmp_path, monkeypatch, capsys):
    def fail(*args): raise OSError('checkpoint unavailable')
    monkeypatch.setattr(status_io, 'write_status_atomic', fail)
    value = {'stage': 'calibration', 'complete': False}
    error = ValueError('negative probe mismatch')
    assert status_io.record_failure(tmp_path/'status.json', value, error) is False
    assert value['failedStage'] == 'calibration'
    assert value['errorType'] == 'ValueError'
    stderr = capsys.readouterr().err
    assert 'negative probe mismatch' in stderr and 'checkpoint unavailable' in stderr


@pytest.fixture
def prepared_tools(tmp_path, monkeypatch):
    from riscv2x86_py import l3_program_backend as backend
    base_path = tmp_path/'base.json'; base_path.write_text('{}')
    header = tmp_path/'include/qemu/qemu-plugin.h'; header.parent.mkdir(parents=True); header.write_text('header')
    base = {k: [] if k.endswith('Arguments') else 'fake-tool' for k in backend.TOOLS}
    base['files'] = {str(header): 'unused'}
    monkeypatch.setattr(backend, 'validate_backend', lambda _: base)
    observed = []; checked = []
    def run(command, directory, tag, *args, **kwargs):
        directory = Path(directory)
        observed.append(json.loads((tmp_path/'output/build-status.json').read_text()))
        Path(command[command.index('-o')+1]).write_bytes(b'fake-binary')
        save(directory/(tag+'.command.json'), {'command': list(map(str, command))})
        return SimpleNamespace(stdout='', stderr='')
    def capture(*args, **kwargs): return [], '', {'testOnly': True}
    monkeypatch.setattr(backend, 'run', run)
    monkeypatch.setattr(backend, 'capture', capture)
    monkeypatch.setattr(backend, 'Elf', lambda _: None)
    monkeypatch.setattr(backend, 'regions_of', lambda _: [])
    monkeypatch.setattr(backend, 'check_calibration', lambda b, r: checked.append((r['side'], r['kind'])))
    def validate(b):
        assert len(b['calibration']) == 6
        assert len(checked) == 6
        assert not (tmp_path/'output/backend.json').exists()
        assert str(Path(status_io.__file__).resolve()) in b['files']
        return b
    monkeypatch.setattr(backend, 'validate', validate)
    return backend, base_path, tmp_path/'output', observed, checked


def test_prepare_reaches_publication_through_real_checkpoints(prepared_tools):
    b, base, output, observed, checked = prepared_tools
    result = b.prepare(base, output)
    status = json.loads((output/'build-status.json').read_text())
    assert status['complete'] is True and status['status'] == 'complete'
    assert status['semanticApproval'] is False and status['backendPublished'] is True
    assert len(status['calibrationCompleted']) == len(checked) == 6
    assert observed[0]['stage'] == 'plugin'
    assert all(x['stage'] == 'calibration' for x in observed[1:])
    assert json.loads((output/'backend.json').read_text()) == result
    with pytest.raises(FileExistsError): b.prepare(base, output)


@pytest.mark.parametrize('point', ['plugin', 'capture', 'validation', 'publication', 'final_status', 'complete'])
def test_prepare_failures_never_report_success(prepared_tools, monkeypatch, point):
    b, base, output, observed, checked = prepared_tools
    error = ValueError('injected ' + point)
    if point == 'plugin':
        def fail(*args, **kwargs): raise error
        monkeypatch.setattr(b, 'run', fail)
    elif point == 'capture':
        def fail(*args, **kwargs): raise error
        monkeypatch.setattr(b, 'capture', fail)
    elif point == 'validation':
        def fail(*args, **kwargs): raise error
        monkeypatch.setattr(b, 'validate', fail)
    elif point == 'publication':
        original = b.save
        def fail(path, value):
            if Path(path).name == 'backend.json': raise error
            return original(path, value)
        monkeypatch.setattr(b, 'save', fail)
    else:
        original = b.write_status_atomic
        def fail(path, value):
            if value['stage'] == point: raise error
            return original(path, value)
        monkeypatch.setattr(b, 'write_status_atomic', fail)
    with pytest.raises(ValueError) as raised: b.prepare(base, output)
    assert raised.value is error
    status = json.loads((output/'build-status.json').read_text())
    assert status['status'] == 'failed' and status['complete'] is False
    assert status['error'] == str(error)
    assert (output/'backend.json').exists() == (point in ('final_status', 'complete'))
    if point == 'capture':
        assert status['calibrationCurrent'] == {'side': 'source', 'kind': 'empty'}
        assert status['calibrationCompleted'] == []


@pytest.mark.parametrize('side,kind', [(s, k) for s in ('source','target') for k in ('empty','read','skip')])
def test_each_calibration_rejection_blocks_publication(prepared_tools, monkeypatch, side, kind):
    b, base, output, observed, checked = prepared_tools
    original = b.check_calibration
    def check(value, record):
        if (record['side'], record['kind']) == (side, kind): raise ValueError('probe mismatch')
        original(value, record)
    monkeypatch.setattr(b, 'check_calibration', check)
    with pytest.raises(ValueError, match='probe mismatch'): b.prepare(base, output)
    status = json.loads((output/'build-status.json').read_text())
    assert status['failedStage'] == 'calibration'
    assert status['calibrationCurrent'] == {'side': side, 'kind': kind}
    assert len(status['calibrationCompleted']) == len(checked)
    assert not (output/'backend.json').exists()


def test_prepare_preserves_business_error_when_failure_checkpoint_breaks(prepared_tools, monkeypatch, capsys):
    b, base, output, observed, checked = prepared_tools
    error = RuntimeError('original tool failure')
    def fail(*args, **kwargs): raise error
    monkeypatch.setattr(b, 'run', fail)
    monkeypatch.setattr(status_io, 'write_status_atomic', lambda *args: (_ for _ in ()).throw(OSError('disk failure')))
    with pytest.raises(RuntimeError) as raised: b.prepare(base, output)
    assert raised.value is error
    assert 'original tool failure' in capsys.readouterr().err
    assert not (output/'backend.json').exists()


def test_program_driver_preserves_validation_error_on_checkpoint_failure(tmp_path, monkeypatch, capsys):
    from riscv2x86_py import l3_program_backend as backend
    path = Path(__file__).resolve().parents[2]/'experiment/run_l3_program_trace.py'
    spec = importlib.util.spec_from_file_location('program_driver_status_test', path)
    driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
    output = tmp_path/'production'
    monkeypatch.setattr(sys, 'argv', ['driver','--input','input.c','--frontend','frontend','--backend','missing','--output',str(output)])
    def reject(*args): raise ValueError('backend invalid')
    monkeypatch.setattr(backend, 'validate', reject)
    def fail(*args): raise OSError('failure checkpoint unavailable')
    monkeypatch.setattr(status_io, 'write_status_atomic', fail)
    assert driver.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result['productionAcceptanceComplete'] is False
    assert result['error'] == 'backend invalid'
    assert result['failedStage'] == 'input_validation'


def test_backend_validation_requires_checkpoint_implementation_binding(prepared_tools, monkeypatch):
    b, base, output, observed, checked = prepared_tools
    # Exercise the production validator, rather than the lifecycle fixture's validator.
    import importlib
    spec = importlib.util.spec_from_file_location('riscv2x86_py._program_validator_test', Path(b.__file__))
    validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)
    value = b.prepare(base, output)
    monkeypatch.setattr(validator, 'validate_backend', lambda _: b.validate_backend(base))
    value['files'].pop(str(Path(status_io.__file__).resolve()))
    value['backendIdentity'] = b.identity({k: v for k, v in value.items() if k != 'backendIdentity'})
    with pytest.raises(ValueError, match='BACKEND_FILES_MISSING'):
        validator.validate(value)


def test_initial_checkpoint_failure_runs_no_tool(prepared_tools, monkeypatch):
    b, base, output, observed, checked = prepared_tools
    error = OSError('initial state cannot be written')
    def fail(*args): raise error
    monkeypatch.setattr(b, 'write_status_atomic', fail)
    with pytest.raises(OSError) as raised: b.prepare(base, output)
    assert raised.value is error
    assert observed == [] and checked == []
    assert not (output/'backend.json').exists()


def test_independent_status_directories_do_not_interfere(tmp_path):
    left, right = tmp_path/'left/status.json', tmp_path/'right/status.json'
    status_io.write_status_atomic(left, {'run': 'left'})
    status_io.write_status_atomic(right, {'run': 'right'})
    status_io.write_status_atomic(left, {'run': 'left', 'stage': 'complete'})
    assert json.loads(right.read_text()) == {'run': 'right'}
