"""Captured host link/execute/readback tests; no RISC-V/proof ingress claim."""
from copy import deepcopy
from pathlib import Path
import pytest
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py.native_project_l2_entry import ProjectEntry
from riscv2x86_py import l2_typed_entry as t
from .test_native_original_api import native_pair, BODY
from .test_l2_typed_entry import function


@pytest.fixture
def backend(native_pair):
    specpath, request, builds, root, spec = native_pair
    fn, _ = function()
    report = root / 'report.json'; p.write(report, {'functions': [fn]})
    translation = root / 'translation.json'; p.write(translation, {'report': d.snapshot(report)})
    run = root / 'run.json'; p.write(run, {'translation': d.snapshot(translation)})
    spec['run'] = d.snapshot(run); p.write(specpath, spec)
    config = {'schemaVersion': 'riscv2x86.auto-l2-operand-runner.v1',
        'translatedReport': str(report), 'functions': [fn], 'qemuBinary': spec['qemu']['path'],
        'timeoutSeconds': spec['timeoutSeconds'], 'typedProjectEntry': {
            'specPath': str(specpath), 'requestPath': str(request),
            **{s + 'Build': builds[s] for s in ('source', 'target')}}}
    for side in ('source', 'target'):
        value = d.read(builds[side])
        config[side + 'Path'] = value['input']['path']; config[side + 'Digest'] = value['input']['digest']
    entry = ProjectEntry(config); profile = entry.bind(fn)
    work = root / 'operand'; work.mkdir()
    driver = work / 'driver.c'; driver.write_text(t.wrapper(profile))
    return config, entry, driver, work, root


def execute(entry, driver, work, config):
    return entry.execute(driver, Path(config['sourcePath']), Path(config['targetPath']), work, driver.read_text())


def test_original_compilers_separate_cpp_output_body_and_c_driver_readback_without_execution(backend, monkeypatch):
    config, entry, driver, work, root = backend
    source, target = execute(entry, driver, work, config)
    assert source.returncode == target.returncode == 0
    assert entry.comparison['processObservationStatus'] == 'observed-agreement'
    argv = d.read(work / 'body-source/execution.json')['arguments']
    assert ['-x', 'cpp-output'] == argv[1:3]
    argv = d.read(work / 'driver-source/execution.json')['arguments']
    assert argv[-8:-6] != ['-x', 'cpp-output']
    assert argv[argv.index('-std=gnu11') - 2:argv.index('-std=gnu11')] == ['-x', 'c']
    before = {str(f): (f.read_bytes(), f.stat().st_mtime_ns) for f in work.rglob('*') if f.is_file()}
    def forbidden(*args, **kwargs): raise AssertionError('checker executed an external tool')
    monkeypatch.setattr(p, 'command', forbidden)
    reread = ProjectEntry(config, readback=True); reread.bind(config['functions'][0])
    source2, target2 = execute(reread, driver, work, config)
    assert source2.stdout == source.stdout and target2.stdout == target.stdout
    assert before == {str(f): (f.read_bytes(), f.stat().st_mtime_ns) for f in work.rglob('*') if f.is_file()}


def test_changed_recorded_command_cannot_be_consumed(backend):
    config, entry, driver, work, _ = backend; execute(entry, driver, work, config)
    path = work / 'run-source/execution.json'; row = d.read(path)
    row['arguments'].append('unrecorded-input'); p.write(path, row)
    check = ProjectEntry(config, readback=True); check.bind(config['functions'][0])
    with pytest.raises(ValueError, match='RECIPE_CHANGED'): execute(check, driver, work, config)


def test_missing_object_observation_is_inconclusive_not_a_logical_operand_pass(backend):
    config, entry, driver, work, _ = backend; execute(entry, driver, work, config)
    for side in ('source', 'target'):
        path = work / ('run-' + side) / 'stdout.log'
        path.write_bytes(b''.join(l for l in path.read_bytes().splitlines(keepends=True) if not l.startswith(b'case:')))
    check = ProjectEntry(config, readback=True); check.bind(config['functions'][0])
    execute(check, driver, work, config)
    assert check.comparison['processObservationStatus'] != 'observed-agreement'


def test_provider_cannot_swap_the_original_report_or_compiler_function_identity(backend):
    config, entry, driver, work, root = backend
    bad = deepcopy(config); bad['functions'][0]['nativeCompilerDeclarationId'] = 'different'
    with pytest.raises(ValueError, match='ORIGINAL_FUNCTIONS'): ProjectEntry(bad)
    bad = deepcopy(config); bad['sourceDigest'] = 'sha256:' + '0' * 64
    with pytest.raises(ValueError, match='ORIGINAL_BODY'): ProjectEntry(bad)


def test_registry_is_original_requirement_driven_and_keeps_missing_dimensions_required(backend):
    from riscv2x86_py.native_project_l2 import registry_descriptor
    config, _, _, _, root = backend
    descriptor = registry_descriptor(config, ['subject'], root / 'requirements.json', config['translatedReport'], 'resolved.json')
    assert descriptor['type'] == 'requirement-driven'
    provider = descriptor['config']['providers'][0]
    assert provider['validatorType'] == 'automatic-l2-operand-differential'
    assert provider['supportedDimensions'] == ['logical_operands']
    assert provider['fragmentIds'] == ['subject']


def test_campaign_l2_receipt_consumes_original_provider_refusal_and_checks_readonly(backend, native_pair, monkeypatch):
    from types import SimpleNamespace
    from riscv2x86_py import native_original_api as api
    from riscv2x86_py import native_project_l2 as l2
    from riscv2x86_py import native_original_applicability as app
    from riscv2x86_py import translation_attempt, translation_artifact_binding
    from .test_automatic_l2_operand import _artifact
    from .l2_profile_fixtures import profile_dict
    config, _, driver, work, root = backend
    report = d.read(config['translatedReport'])
    report['findings'] = [{'fragment': {'id': 'fragment', 'enclosingFunction': 'exercise',
        'outputs': [{'constraint': '=r'}], 'inputs': [{'constraint': 'r'}]},
        'l2SemanticProfile': profile_dict('fragment')}]
    p.write(config['translatedReport'], report)
    translation = root / 'translation.json'
    archive = root / 'fixture-archive.json'; p.write(archive, {'fixture': 'unapproved upstream input'})
    p.write(translation, {'report': d.snapshot(config['translatedReport']), 'attemptArchive': d.snapshot(archive)})
    p.write(root / 'run.json', {'translation': d.snapshot(translation)})
    # The fixture owns original compiler/translation ingress, not L2 acceptance.
    monkeypatch.setattr(translation_attempt, 'load_translation_attempt_archive', lambda path: SimpleNamespace())
    monkeypatch.setattr(translation_artifact_binding, 'artifacts_from_report', lambda *args:
                        {'finding:0:fragment': _artifact()})
    typed = config['typedProjectEntry']; spec = native_pair[-1]
    spec['run'] = d.snapshot(root / 'run.json'); p.write(typed['specPath'], spec)
    api.acquire(typed['specPath'], typed['requestPath'], root / 'api', builds={s: typed[s + 'Build'] for s in api.SIDES})
    apath = root / 'app.json'
    appvalue = {'project': d.snapshot(typed['specPath']), 'facts': {'instances': [
        {'instanceBindingIdentity': 'instance-1', 'astPath': [0, 1],
         'sourceGuardClassification': 'excluded-under-compiler-query-contracts'}]}}
    p.write(apath, appvalue)
    monkeypatch.setattr(app, 'check', lambda path: deepcopy(appvalue))
    value = l2.acquire(root / 'api/result.json', apath, root / 'l2')
    assert len(value['instances']) == 1
    assert value['instances'][0]['status'] == 'inconclusive'
    assert not value['originalLogicalOperandsVerified'] and not value['semanticApproval']
    assert l2.check(root / 'l2/result.json') == value
    def forbidden(*args, **kwargs): raise AssertionError('readback ran compiler')
    monkeypatch.setattr(p, 'command', forbidden)
    assert l2.check(root / 'l2/result.json') == value
    row = d.read(root / 'l2/result.json'); row['originalLogicalOperandsVerified'] = True
    p.write(root / 'l2/result.json', d.seal({k:v for k,v in row.items() if k != 'projectL2Identity'}, 'projectL2Identity'))
    with pytest.raises(ValueError, match='REDERIVATION'): l2.check(root / 'l2/result.json')
