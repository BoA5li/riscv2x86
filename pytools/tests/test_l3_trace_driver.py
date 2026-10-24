"""Driver lifecycle tests; mocks exercise orchestration, not real L3 evidence."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def driver():
    path = Path(__file__).resolve().parents[2]/'experiment/run_l3_memory_trace.py'
    spec = importlib.util.spec_from_file_location('l3_trace_driver_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('returncode,summary,audit_failure,expected', [
    (2, False, False, 'L3_TRACE_PRODUCTION_FAILED_WITHOUT_SUMMARY'),
    (0, False, False, 'L3_TRACE_PRODUCTION_SUMMARY_MISSING'),
    (2, True, False, 'L3_TRACE_NORMAL_PRODUCTION_FAILED'),
    (0, True, False, None),
    (0, True, True, 'independent-audit-rejected'),
])
def test_driver_lifecycle(tmp_path, monkeypatch, returncode, summary, audit_failure, expected):
    import sys
    import riscv2x86_py.l3_qemu_backend as backend
    import riscv2x86_py.l3_production_acceptance as acceptance
    module = driver()
    inputs = tmp_path/'inputs'; inputs.mkdir()
    source = inputs/'renamed.c'; source.write_text('void renamed(void){}')
    frontend = tmp_path/'frontend'; frontend.write_text('tool')
    manifest = tmp_path/'backend.json'; manifest.write_text('{}')
    output = tmp_path/'production'
    failure = {'exceptionType': 'ValueError', 'failureStage': 'evaluation_orchestration',
               'detail': 'evaluation work directory and source root must not overlap'}
    def run(command, **kwargs):
        if summary:
            root = output/'batch'; root.mkdir()
            report = {'status': 'inconclusive' if returncode else 'verified',
                      'reasonCodes': ['batch.evaluation-orchestration-error'] if returncode else [],
                      'detail': failure['detail'] if returncode else None,
                      'orchestrationFailure': failure if returncode else None, 'attempts': []}
            (root/'result.json').write_text(json.dumps(report))
            (root/'batch-evaluation.json').write_text(json.dumps({'cases': [
                {'caseId': 'renamed', 'resultPath': 'result.json'}]}))
        return SimpleNamespace(returncode=returncode)
    calls = []
    monkeypatch.setattr(module.subprocess, 'run', run)
    monkeypatch.setattr(backend, 'validate_backend', lambda _: {'backendIdentity': 'backend'})
    def audit(report):
        calls.append(report)
        if audit_failure:
            raise ValueError('independent-audit-rejected')
        return {'status': 'verified'}
    monkeypatch.setattr(acceptance, 'audit_evaluation', audit)
    monkeypatch.setattr(sys, 'argv', ['driver', '--input', str(source), '--frontend', str(frontend),
                                    '--backend', str(manifest), '--output', str(output)])
    assert module.main() == (2 if expected else 0)
    status = json.loads((output/'run-status.json').read_text())
    assert status['productionAcceptanceComplete'] == (expected is None)
    assert status['blockers'] == ([expected] if expected else [])
    assert len(calls) == (1 if expected is None or audit_failure else 0)
    if audit_failure:
        assert status['currentStage'] == 'independent_acceptance'
    if returncode and summary:
        assert status['caseDiagnostics'][0]['orchestrationFailure'] == failure
        assert status['currentStage'] == 'normal_production_result'


def test_case_diagnostics_reject_escape(tmp_path):
    outside = tmp_path/'outside.json'; outside.write_text('{}')
    batch = tmp_path/'batch'; batch.mkdir()
    with pytest.raises(ValueError, match='RESULT_PATH_OUTSIDE_BATCH'):
        driver().batch_diagnostics(batch, {'cases': [{'caseId': 'any', 'resultPath': '../outside.json'}]})


def test_case_diagnostics_reject_empty_batch(tmp_path):
    with pytest.raises(ValueError, match='CASES_EMPTY_OR_INVALID'):
        driver().batch_diagnostics(tmp_path, {'cases': []})


def test_evaluator_still_rejects_overlapping_source_and_work(tmp_path):
    from riscv2x86_py.evaluation import run_evaluation
    source = tmp_path/'inputs'; source.mkdir()
    work = source/'production'/'work'
    with pytest.raises(ValueError, match='must not overlap'):
        run_evaluation(SimpleNamespace(source_root=str(source)), work_directory=work)
    assert not work.exists()
