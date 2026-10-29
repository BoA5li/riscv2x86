"""Partial candidates are archived without invoking a target compiler."""
from dataclasses import replace

import pytest

from tests.test_evaluation_runner import (_setup, run_evaluation, Finding,
    AsmFragment, TranslationOutcome, ValidationOutcome, PublicationOutcome,
    make_translation_attempt_artifact, terminal_attempt_from_finding,
    save_translation_attempt_archive, save_report)
from riscv2x86_py.schema import load_report


@pytest.mark.parametrize('outcome', [TranslationOutcome.UNSUPPORTED, TranslationOutcome.NEEDS_ROUTE,
                                   TranslationOutcome.FAILED, TranslationOutcome.NOT_ATTEMPTED])
def test_partial_program_preserves_root_outcome_without_target_build(tmp_path, outcome):
    request, _, attempt = _setup(tmp_path)
    findings = load_report(request.translated_report)
    missing = Finding(fileName='case.c', fragment=AsmFragment(id='fragment:missing', fileName='case.c'),
        translationOutcome=outcome.value)
    missing.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id='fragment:missing', candidate_kind=outcome.value, candidate_route='',
        candidate_replacement='', candidate_rule_name='', translation_outcome=outcome,
        validation_outcome=ValidationOutcome.NOT_RUN, publication_outcome=PublicationOutcome.WITHHELD,
        reason_codes=('test.proof-unavailable',))
    save_report([*findings,missing],request.translated_report)
    save_translation_attempt_archive((attempt,terminal_attempt_from_finding(missing,1)),request.attempt_archive)
    work = tmp_path/'work'
    result = run_evaluation(request,work_directory=work)
    assert result['status']=='inconclusive'
    assert result['reasonCodes']==['evaluation.program-translation-incomplete']
    assert result['targetProgramArtifact'] is None
    assert 'target-build' not in [c['phase'] for c in result['commands']]
    assert result['attempts'][1]['translationOutcome']==outcome.value
    assert (work/'candidate-staging/case.c').is_file()
    assert not (work/'build/target').exists()
    from riscv2x86_py.l3_coverage_inventory import diagnose
    diagnostic = diagnose(result,work)
    assert diagnostic['firstRecordedBlocker']=={'stage':'translation','status':'inconclusive'}
    assert diagnostic['recordedStages']['target-build']=='not_run'
