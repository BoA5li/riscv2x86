"""Independent goals must not accept a weaker or incomplete published claim."""
import copy
from hashlib import sha256
import json

import pytest
from riscv2x86_py.route_acceptance import check, validate_matrix, SCHEMA
from riscv2x86_py.l2_results import L2FragmentResult, L2DimensionResult
from riscv2x86_py.l2_dimensions import L2Dimension, L2DimensionStatus, L2ClaimScope


def fixture(tmp_path, scope=L2ClaimScope.ARCHITECTURAL):
    source=tmp_path/'source'/'renamed.c'; source.parent.mkdir();source.write_text('void renamed(void){}')
    dim=L2DimensionResult.create(dimension=L2Dimension.SHELL_SEMANTICS,
        status=L2DimensionStatus.VERIFIED,claim_scope=scope,
        authority_identity='sha256:'+'a'*64,source_observation_identity='sha256:'+'b'*64,
        target_observation_identity='sha256:'+'c'*64,effect_relation_identity='sha256:'+'d'*64,
        execution_identity='sha256:'+'e'*64,relation_kind='runtime_mediated',
        verified_properties=('shell',),not_claimed_properties=(('absolute-value-equivalence',) if scope is L2ClaimScope.APPROVED_FUNCTIONAL_RELATION else ()))
    fragment=L2FragmentResult.close(fragment_id='fragment:renamed',requirement_identity='sha256:'+'f'*64,
        required_dimensions=(L2Dimension.SHELL_SEMANTICS,),dimension_results=(dim,))
    matrix={'schemaVersion':SCHEMA,'cases':[{'caseId':'renamed','sourceRelativePath':'renamed.c',
        'sourceDigest':'sha256:'+sha256(source.read_bytes()).hexdigest(),'levels':['L0','L1','L2'],
        'dimensions':{'shell_semantics':{'relationKinds':['runtime_mediated'],'claimScopes':['architectural']}},
        'notClaimedProperties':['microarchitecture']} ]}
    result={'status':'verified','selectedAttemptIds':[], 'commands':[{'phase':'translation','command':['tool','--source',str(source)]}],
        'attempts':[{'status':'verified','attemptArtifactId':'attempt:1','fragmentId':fragment.fragment_id,'validation':{'layers':[
            {'level':'L0','status':'verified'},{'level':'L1','status':'verified'},
            {'level':'L2','status':'verified','detail':json.dumps(fragment.to_dict()),'evidenceIdentity':fragment.evidence_identity}]}}]}
    path=tmp_path/'results/cases/renamed/evaluation-result.json';path.parent.mkdir(parents=True)
    return matrix,result,path,source


def run(matrix,result,path,source):
    path.write_text(json.dumps(result))
    return check(matrix,results=path.parents[2],source_root=source.parent)


def test_complete_published_claim_matches_independent_goal(tmp_path):
    args=fixture(tmp_path)
    assert run(*args)['goalSatisfied']
    assert run(*args)['semanticApproval'] is False


def test_functional_claim_cannot_satisfy_architectural_goal(tmp_path):
    args=fixture(tmp_path,L2ClaimScope.APPROVED_FUNCTIONAL_RELATION)
    result=run(*args)
    assert not result['goalSatisfied']
    assert 'dimension-claim-mismatch:shell_semantics' in result['cases'][0]['failures']


@pytest.mark.parametrize('mutation',['source','level','dimension','identity','selection','binding','extra'])
def test_mutated_coverage_or_identity_cannot_pass(tmp_path,mutation):
    matrix,result,path,source=fixture(tmp_path)
    if mutation=='source':source.write_text('changed')
    elif mutation=='level':result['attempts'][0]['validation']['layers'][0]['status']='not_run'
    elif mutation=='selection':result['selectedAttemptIds']=['absent']
    elif mutation=='binding':result['commands'][0]['command'][-1]=str(source.parent/'another.c')
    elif mutation=='extra':matrix['cases'][0]['dimensions']['memory_effects']=copy.deepcopy(matrix['cases'][0]['dimensions']['shell_semantics'])
    else:
        layer=result['attempts'][0]['validation']['layers'][2];detail=json.loads(layer['detail'])
        if mutation=='dimension':detail['dimensionResults']={}
        else:detail['dimensionResults']['shell_semantics']['executionIdentity']='sha256:'+'9'*64
        layer['detail']=json.dumps(detail)
    assert not run(matrix,result,path,source)['goalSatisfied']


@pytest.mark.parametrize('field,value',[('caseId','../escape'),('sourceRelativePath','../escape.c'),('levels',['L0']),('dimensions',{})])
def test_invalid_goal_is_configuration_error(tmp_path,field,value):
    matrix,*_=fixture(tmp_path);matrix['cases'][0][field]=value
    with pytest.raises(ValueError):validate_matrix(matrix)
