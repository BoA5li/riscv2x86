from copy import deepcopy
from riscv2x86_py.program_claim_consumption import consume, RULES


def facts():
    return {'completedStages': ['source-build', 'target-build', 'machine-inventory'],
            'selectedCaseIndices': [0], 'plannedCaseCount': 2,
            'observations': [{'cases': [{'mismatches': []}], 'mismatches': [],
                'executionBudgetFailed': False, 'exitOutsideDeclaredDomain': False, 'loaderListFailed': False}]}


def test_checked_subclaims_never_discharge_missing_program_proof_facts():
    value = consume('project', facts())
    assert len(value['claims']) == 3
    assert {row['reasonCode'] for row in value['obligations']} == set(RULES)
    assert all(row['missingProofFacts'] and not row['fullObligationDischarged'] for row in value['obligations'])
    assert not value['semanticApproval']
    changed = facts(); changed.update(machineAbiClosureVerified=True, semanticApproval=True)
    assert consume('project', changed) == value
    assert consume('another-project', facts())['scopeIdentity'] != value['scopeIdentity']


def test_mismatch_or_budget_does_not_become_checked_output_agreement():
    for field, changed in [('mismatches', ['different']), ('executionBudgetFailed', True),
                           ('exitOutsideDeclaredDomain', True), ('loaderListFailed', True)]:
        data = deepcopy(facts()); data['observations'][0][field] = changed
        result = consume('project', data)
        assert 'selected-process-output-and-exit-agreement' not in {c['kind'] for c in result['claims']}
