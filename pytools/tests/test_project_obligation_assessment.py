from copy import deepcopy
import pytest
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py.program_validation_obligations import project_assessment


def sample():
    spec = {'projectEvaluationIdentity': 'fixture-scope',
            'gaps': ['THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED', *p.GAPS]}
    observation = {'executionBudgetFailed': False, 'loaderListFailed': False,
                   'exitOutsideDeclaredDomain': False, 'mismatches': []}
    return spec, observation


def test_observation_does_not_discharge_preconditions_or_erase_final_requirements():
    spec, observation = sample()
    value = project_assessment(spec, observation)
    assert value['boundedProcessObservableStatus'] == 'observed-match'
    assert value['l1Status'] == 'inconclusive'
    assert len(value['obligations']) == len(spec['gaps'])
    for reason in ('PROGRAM_L2_AUTHORITY_REQUIRED', 'INDEPENDENT_PROGRAM_AUDIT_REQUIRED'):
        assert reason not in value['l1ReasonCodes']
        assert any(r['reasonCode'] == reason and r['status'] == 'evidence-production-required'
                   for r in value['obligations'])
    assert not value['programRequirementsComplete']


@pytest.mark.parametrize('mode', ['mismatch', 'budget', 'exit'])
def test_bad_observations_cannot_be_promoted_to_a_pass(mode):
    spec, observation = sample()
    if mode == 'mismatch': observation['mismatches'] = ['stdout']
    elif mode == 'budget': observation['executionBudgetFailed'] = True
    else: observation['exitOutsideDeclaredDomain'] = True
    value = project_assessment(spec, observation)
    assert value['l1Status'] != 'verified'
    assert value['boundedProcessObservableStatus'] != 'observed-match'


def test_missing_policy_or_injected_boolean_is_not_a_proof():
    spec, observation = sample()
    spec['abiVerified'] = True; observation['allProofsComplete'] = True
    assert project_assessment(spec, observation)['l1Status'] == 'inconclusive'
    shortened = deepcopy(spec); shortened['gaps'] = []
    with pytest.raises(ValueError, match='FULL_OBLIGATION_POLICY_REQUIRED'):
        project_assessment(shortened, observation)
