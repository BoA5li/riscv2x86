from copy import deepcopy
import pytest
from riscv2x86_py import native_instance_execution as execution
from riscv2x86_py import native_evaluation_coverage as coverage
from .test_phase206_execution_contracts import subject


def mixed():
    finding, selected, app = subject()
    live = deepcopy(app['facts']['instances'][0])
    live.update(instanceBindingIdentity='live', astPath=[1,3], sourceGuardClassification='unknown')
    app['facts']['instances'].append(live)
    selected['instanceBindingIdentities'].append('live')
    finding['physicalEditBinding'] = {'instanceBindingIdentity': 'i'}
    return finding, selected, app


def test_production_identity_selects_one_site_in_mixed_function():
    finding, selected, app = mixed()
    row = execution.classify(finding, selected, app, app['project'])
    assert row['sourceConditionExcluded'] and row['instanceBindingIdentities'] == ['i']
    finding['physicalEditBinding']['instanceBindingIdentity'] = 'live'
    row = execution.classify(finding, selected, app, app['project'])
    assert not row['sourceConditionExcluded'] and row['instanceBindingIdentities'] == ['live']


@pytest.mark.parametrize('kind', ['absent', 'foreign', 'conflicting-path'])
def test_no_function_wide_fallback_for_ambiguous_or_wrong_instance(kind):
    finding, selected, app = mixed()
    if kind == 'absent': finding['physicalEditBinding'] = {}
    elif kind == 'foreign': finding['physicalEditBinding']['instanceBindingIdentity'] = 'foreign'
    else: finding['physicalEditBinding']['astPath'] = [1,3]
    with pytest.raises(ValueError): execution.classify(finding, selected, app, app['project'])


def test_all_findings_and_unselected_edits_remain_in_denominator():
    finding, selected, app = mixed()
    finding['fragment']['id'] = 'excluded'
    disposition = execution.classify(finding, selected, app, app['project'])
    live = {'fragment': {'id': 'live-fragment'}, 'physicalEditBinding': {'instanceBindingIdentity': 'live'}}
    l2 = {'instances': [{'findingId': 'finding:0:excluded', 'fragmentId': 'excluded',
        'sourceConditionExcluded': True, 'instanceExecutionDisposition': disposition,
        'logicalOperandEvidenceChecked': False, 'detail': {'reasonCode': 'L2_TYPED_SOURCE_INSTANCE_EXCLUDED'}}]}
    value = coverage.summarize({'findings': [finding, live]}, app['facts'], l2)
    assert value['counts']['reportFindingCount'] == value['counts']['editedInstanceCount'] == 2
    assert value['counts']['selectedFindingCount'] == 1
    assert value['counts']['logicalOperandCheckedFindingCount'] == 0
    assert value['findings'][1]['status'] == 'not-selected-for-L2'
    assert value['reportAccountingComplete'] and not value['semanticApproval']
    l2['instances'][0]['logicalOperandEvidenceChecked'] = True
    with pytest.raises(ValueError, match='EXCLUDED'): coverage.summarize({'findings': [finding, live]}, app['facts'], l2)


def test_missing_findings_are_accounted_as_missing_not_silently_removed():
    _, _, app = mixed()
    value = coverage.summarize({'findings': []}, app['facts'], {'instances': []})
    assert not value['reportAccountingComplete']
    assert value['unrepresentedEditedInstances'] == ['i', 'live']


def test_original_provider_rejects_duplicate_fragment_subjects():
    from riscv2x86_py.automatic_l2_operand import _finding
    item = {'fragment': {'id': 'same'}}
    assert _finding({'findings':[item]},'same') == item
    assert _finding({'findings':[item,deepcopy(item)]},'same') is None
