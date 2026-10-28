from copy import deepcopy
from riscv2x86_py.l3_capability_assessment import assess


def test_assessment_distinguishes_static_completion_from_actual_acceptance(tmp_path):
    from tests.test_l3_program_regions import fixture
    _,findings,fn=fixture(tmp_path)
    result=assess(findings,[fn],{'scalar-program'})
    assert result['staticPrerequisitesComplete'] is True
    assert not result['semanticApproval'] and not result['productionAcceptanceComplete']
    assert set(result['runtimeStages'].values())=={'not_run'}
    missing=assess(findings,[fn],set())
    assert not missing['staticPrerequisitesComplete']
    assert missing['stages'][-2]['stage']=='declared-mechanism-availability'
    assert missing['stages'][-2]['status']=='unresolved'


def test_missing_proof_is_not_a_missing_observer_or_success(tmp_path):
    from tests.test_l3_program_regions import fixture
    _,findings,fn=fixture(tmp_path)
    findings[0]['approvalArtifact']['proofStatus']='rejected'
    result=assess(findings,[fn],{'scalar-program'})
    assert not result['staticPrerequisitesComplete']
    assert result['stages'][0]['stage']=='source-obligations-and-proof-authority'
    assert result['stages'][0]['status']=='unresolved'


def test_joint_composition_cannot_be_approved_by_declaring_all_mechanisms():
    findings=[{'fragment':{'id':'one'},'l2SemanticProfile':{'patternKind':'memory_load'}},
              {'fragment':{'id':'two'},'l2SemanticProfile':{'patternKind':'scalar'}}]
    result=assess(findings,[],{'memory','scalar-program','control','fence','atomic','lrsc'})
    assert not result['staticPrerequisitesComplete']
    assert 'L3_JOINT_REGION_EXECUTION_CONTRACT_REQUIRED' in result['stages'][-1]['reasonCodes'][0]
    assert not result['productionAcceptanceComplete']
