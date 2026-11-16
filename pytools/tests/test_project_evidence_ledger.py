"""Coverage ledger consumes original checked progress, never approval flags."""
from copy import deepcopy
import pytest

from riscv2x86_py import project_evidence_ledger as ledger
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.program_validation_obligations import _PROJECT_PHASES


def protocol(tmp_path):
    def write(name, value):
        path = tmp_path / name
        path.write_text(__import__('json').dumps(value))
        return d.snapshot(path)
    spec = write('project.json', {'projectEvaluationIdentity': 'fixture-project',
                                  'gaps': list(_PROJECT_PHASES)})
    original = write('original.json', {'fixture': 'translation'})
    app = write('applicability.json', {'fixture': 'applicability'})
    prefix = {'original': original, 'project': spec, 'applicability': app}
    prep = write('preparation.json', {'facts': {'prefixCheckpoints': prefix}})
    cp = {'preparation': prep}
    for stage in ('source-build', 'target-build', 'machine-inventory', 'case-000000'):
        cp[stage] = write(stage + '.json', {'fixture': stage})
    state = {'checkpoints': cp}
    facts = {'observations': [{'mismatches': [], 'semanticApproval': False}],
             'plannedCaseCount': 2, 'selectedCaseIndices': [0], 'unselectedCaseIndices': [1],
             'observedCaseCount': 1, 'machineFactGaps': [],
             'instanceApplicability': {'sourceExcludedInstanceCount': 1},
             'originalLayerReadiness': {'instances': [{'authorityConsumerReady': False}]}}
    return state, facts


def test_bounded_evidence_keeps_every_global_obligation_and_unselected_case(tmp_path):
    state, facts = protocol(tmp_path)
    value = ledger._derive(state, facts)
    assert {row['reasonCode'] for row in value['obligations']} == set(_PROJECT_PHASES)
    assert value['unselectedCaseIndices'] == [1] and value['observedCaseCount'] == 1
    assert any(row['status'] == 'partial-evidence' for row in value['obligations'])
    assert all(not row['fullObligationDischarged'] for row in value['obligations'])
    assert all(row['status'] == 'inconclusive' for row in value['stageCoverage'].values())
    assert not value['semanticApproval'] and not value['fullProofConsumersConnected']
    assert any('supported-executable' in action for action in value['nextActions'])
    # Unregistered success booleans cannot upgrade any obligation.
    forged = deepcopy(facts)
    forged.update(semanticApproval=True, machineAbiClosureVerified=True)
    assert ledger._derive(state, forged) == value


def test_ledger_propagates_original_checker_failure_instead_of_trusting_summary(tmp_path, monkeypatch):
    progress = tmp_path / 'progress.json'; progress.write_text('{}')
    def reject(path):
        raise ValueError('original checker rejected changed dependency')
    monkeypatch.setattr(ledger.diagnostic, 'check_progress', reject)
    with pytest.raises(ValueError, match='changed dependency'):
        ledger.inspect(progress)


def test_ledger_requires_the_complete_original_obligation_policy(tmp_path):
    state, facts = protocol(tmp_path)
    prep = d.read(state['checkpoints']['preparation']['path'])
    project = prep['facts']['prefixCheckpoints']['project']['path']
    value = d.read(project); value['gaps'].pop()
    __import__('pathlib').Path(project).write_text(__import__('json').dumps(value))
    with pytest.raises(ValueError, match='FULL_PROJECT_OBLIGATION_POLICY'):
        ledger._derive(state, facts)
