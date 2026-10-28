from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import pytest

from riscv2x86_py.translation_backend_failure import write_failure, read_failure
from riscv2x86_py.evaluation import CommandRecord, _translation_command_failure_result
from riscv2x86_py.validation_status import ValidationStatus
from tests.test_evaluation_runner import _setup


def test_backend_failure_binds_source_command_and_captured_error(tmp_path):
    source = tmp_path/'source.c'; source.write_text('void f(void) {}')
    report = tmp_path/'report.json'
    completed = SimpleNamespace(returncode=1, stdout='', stderr='ValueError: original cause\n')
    (tmp_path/'backend.stdout').write_text(completed.stdout)
    (tmp_path/'backend.stderr').write_text(completed.stderr)
    write_failure(report,source,['translate'],['backend'],completed)
    parsed = read_failure(report,source,['translate'])
    assert parsed['backendExecuted'] is True and parsed['semanticApproval'] is False
    assert parsed['stderr'] == completed.stderr
    assert parsed['artifacts'] == {'':False,'.attempts.json':False}
    with pytest.raises(ValueError):
        read_failure(report,source,['different-command'])
    source.write_text('void g(void) {}')
    with pytest.raises(ValueError):
        read_failure(report,source,['translate'])


def test_evaluation_preserves_original_backend_failure_without_fake_attempt(tmp_path):
    request,_,_ = _setup(tmp_path)
    report = Path(request.translated_report); report.unlink()
    Path(request.attempt_archive).unlink()
    completed = SimpleNamespace(returncode=1,stdout='',stderr='ValueError: original cause\n')
    (report.parent/'backend.stdout').write_text(completed.stdout)
    (report.parent/'backend.stderr').write_text(completed.stderr)
    command = ('translate',)
    write_failure(report,Path(request.source_root)/request.source_relative_path,command,['backend'],completed)
    record = CommandRecord('translation',command,1,'',completed.stderr,False,ValidationStatus.FAILED)
    result = _translation_command_failure_result(request,tmp_path,[record],record,None,None,Path(request.attempt_archive))
    assert result['status'] == 'failed' and result['attempts'] == []
    assert 'evaluation.translation-backend-failed' in result['reasonCodes']
    assert 'evaluation.translation-attempt-archive-missing' in result['reasonCodes']
    assert result['translationEvaluationLink']['backendFailure']['stderr'] == completed.stderr
    assert not report.exists() and not Path(request.attempt_archive).exists()


def test_malformed_diagnostic_never_masks_failed_translation(tmp_path):
    import json
    request,_,_=_setup(tmp_path)
    report=Path(request.translated_report); report.unlink()
    Path(request.attempt_archive).unlink()
    Path(str(report)+'.backend-failure.json').write_text(json.dumps({'stderr':None}))
    record=CommandRecord('translation',('translate',),1,'','original error',False,ValidationStatus.FAILED)
    result=_translation_command_failure_result(request,tmp_path,[record],record,None,None,Path(request.attempt_archive))
    assert result['status']=='failed' and result['attempts']==[]
    assert 'evaluation.translation-backend-diagnostic-invalid' in result['reasonCodes']
    assert result['commands'][0]['stderr']=='original error'
