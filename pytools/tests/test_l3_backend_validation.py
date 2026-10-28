"""Lifecycle fixtures: no emulator execution or semantic approval is fabricated."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from riscv2x86_py.l3_backend_validation import BackendValidationSession, checked
from riscv2x86_py.l3_trace_support import digest


def test_reuse_is_local_closing_validation_is_uncached_and_results_are_isolated(tmp_path):
    path = tmp_path/'backend'; path.write_text('valid')
    calls = []
    def validate(value):
        calls.append(1)
        assert Path(value).read_text() == 'valid'
        return {'items': ['valid']}
    with BackendValidationSession() as session:
        value = session.check(validate, path)
        value['items'].clear()
        assert session.check(validate, str(path)) == {'items': ['valid']}
        assert len(calls) == 1
    assert len(calls) == 2  # Mandatory fresh full validation before returning.
    with pytest.raises(ValueError, match='SESSION_CLOSED'):
        session.check(validate, path)
    with BackendValidationSession() as session:
        session.check(validate, path)
    assert len(calls) == 4


@pytest.mark.parametrize('mutation', ['backend', 'dependency', 'valid-replacement'])
def test_changes_during_reuse_cannot_escape_closing_check(tmp_path, mutation):
    path = tmp_path/'backend'; path.write_text('valid')
    dependency = tmp_path/'plugin'; dependency.write_text('original')
    def validate(value):
        assert dependency.read_text() == 'original'
        return {'value': Path(value).read_text()}
    with pytest.raises((AssertionError, ValueError)):
        with BackendValidationSession() as session:
            session.check(validate, path)
            if mutation == 'dependency': dependency.write_text('changed')
            else: path.write_text(mutation)
            # Even if no further caller accesses this backend, closing rejects it.


def test_failed_validation_never_enters_cache(tmp_path):
    calls = []
    def validate(value):
        calls.append(1)
        raise ValueError('missing calibration')
    with BackendValidationSession() as session:
        for _ in range(2):
            with pytest.raises(ValueError, match='missing calibration'):
                session.check(validate, {})
    assert len(calls) == 2


def test_digest_change_gets_fresh_check_not_path_cache(tmp_path):
    path = tmp_path/'backend'; path.write_text('one')
    calls = []
    def validate(value):
        calls.append(1)
        return {'data': Path(value).read_text()}
    with pytest.raises(ValueError, match='RESULT_CHANGED'):
        with BackendValidationSession() as session:
            assert session.check(validate, path)['data'] == 'one'
            path.write_text('two')
            assert session.check(validate, path)['data'] == 'two'
            assert len(calls) == 2


def test_selection_reuses_shared_graph_and_rechecks_before_return(tmp_path, monkeypatch):
    from riscv2x86_py import l3_mechanism_selection as selection
    from riscv2x86_py import l3_control_backend as control
    from riscv2x86_py import l3_qemu_backend as qemu
    from riscv2x86_py import l3_atomic_backend as atomic
    from riscv2x86_py import l3_fence_backend as fence
    from riscv2x86_py import l3_program_backend as program
    base = tmp_path/'qemu'; base.write_text('qemu')
    ctl = tmp_path/'control'; ctl.write_text('control')
    counts = {'qemu': 0, 'control': 0, 'roots': 0}
    def qvalidate(path):
        counts['qemu'] += 1
        return {'backendIdentity': digest(path)}
    def cvalidate(path, *, _context=None):
        counts['control'] += 1
        checked(_context, qvalidate, base)
        return {'backendIdentity': digest(path)}
    def rootvalidate(path, *, _context=None):
        counts['roots'] += 1
        checked(_context, cvalidate, ctl, nested=True)
        return {'backendIdentity': digest(path)}
    monkeypatch.setattr(qemu, 'validate_backend', qvalidate)
    monkeypatch.setattr(control, 'validate', cvalidate)
    for module in (atomic, fence, program):monkeypatch.setattr(module, 'validate', rootvalidate)
    paths = {'memory': str(base), 'control': str(ctl)}
    for kind in ('atomic', 'fence', 'scalar-program'):
        path = tmp_path/kind; path.write_text(kind); paths[kind] = str(path)
    config = tmp_path/'selection.json'
    config.write_text(json.dumps({'schemaVersion': selection.SCHEMA, 'backends': paths}))
    events = []
    assert set(selection.load(config, progress=events.append)) == set(paths)
    # A single initial QEMU/control traversal plus uncached closing traversal.
    assert counts == {'qemu': 3, 'control': 2, 'roots': 6}
    assert any(x['stage']=='backend-revalidation' for x in events)


@pytest.mark.parametrize('budget', [0, -1, 3601, True, 1.5])
def test_inventory_rejects_unbounded_or_invalid_producer_budget(tmp_path, budget):
    from riscv2x86_py.automatic_batch_cli import prepare_automatic_inventory
    source=tmp_path/'input.c';source.write_text('void f(void){}')
    with pytest.raises(ValueError, match='L3_PRODUCER_TIMEOUT_INVALID'):
        prepare_automatic_inventory(source,tmp_path/'inventory',frontend='unused',l3_producer_timeout=budget)
    assert not (tmp_path/'inventory').exists()


def test_common_launcher_dependency_list_pins_validation_implementation():
    from riscv2x86_py.l3_mechanism_selection import producer_dependencies
    assert 'l3_backend_validation.py' in producer_dependencies()


def test_execution_command_records_actual_budget_and_elapsed_time(tmp_path):
    import sys
    from riscv2x86_py.evaluation import _execute
    record = _execute((sys.executable, '-c', 'pass'), tmp_path, 23, 'translation')
    assert record.to_dict()['timeoutSeconds'] == 23
    assert record.to_dict()['elapsedSeconds'] >= 0
    assert not record.timed_out


def test_common_inventory_passes_bound_producer_budget_and_canonical_dependencies(tmp_path, monkeypatch):
    from riscv2x86_py import automatic_batch_cli as auto
    from riscv2x86_py import l3_mechanism_selection as selection
    from riscv2x86_py import l3_atomic_backend as atomic
    from riscv2x86_py.l3_intent_ingress import validate_manifest
    source=tmp_path/'inputs'/'unrelated.c'; source.parent.mkdir();source.write_text('unsigned long f(void){return 7;}')
    frontend=tmp_path/'frontend';frontend.write_text('fixture only');frontend.chmod(0o755)
    backend=tmp_path/'backend.json';backend.write_text('{}')
    config=tmp_path/'selection.json';config.write_text('{}')
    monkeypatch.setattr(selection,'load',lambda _: {'atomic':{'path':str(backend)}})
    monkeypatch.setattr(atomic,'validate',lambda _: {'backendIdentity':'fixture','sourceExecutor':'/fixture/source','targetExecutor':'/fixture/target'})
    monkeypatch.setattr(auto,'inspect_entry_points',lambda *a:(False,({'name':'f','arity':0,'returnType':'unsigned long','parameterTypes':[]},)))
    inventory=tmp_path/'inventory'
    auto.prepare_automatic_inventory(source,inventory,frontend=frontend,l3_mechanism_selections=config,
                                    timeout=240,l3_producer_timeout=600)
    manifest=json.loads(next(inventory.rglob('memory-intent-producer.json')).read_text())
    validate_manifest(manifest,source)
    assert manifest['timeoutSeconds']==600
    cmd=manifest['command']
    package=Path(selection.__file__).resolve().parent
    deps={Path(cmd[i+1]).resolve().relative_to(package).as_posix() for i,x in enumerate(cmd) if x=='--dependency'}
    assert deps==selection.producer_dependencies()
    plan=json.loads(next(inventory.rglob('validation-plan.json')).read_text())
    assert plan['timeoutSeconds']==240
