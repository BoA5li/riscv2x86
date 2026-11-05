from copy import deepcopy
import pytest
from riscv2x86_py.gnu_operand_relations import derive, validate
from riscv2x86_py.gnu_operand_contract import parse_riscv_operand
from riscv2x86_py.project_build_records import identity


def test_whole_asm_relation_keeps_original_constraint_and_permutations():
    value=derive(['=r'],['%r','r'])
    assert value['commutativePairs']==[[1,2]]
    assert value['allowedOperandPermutations']==[[0,1,2],[0,2,1]]
    assert value['operands'][1]['originalConstraint']=='%r'
    assert validate(value)==value
    assert value['semanticCommutativityProofRequired'] is True
    assert value['semanticApproval'] is False
    # Existing consumers still refuse to drop a relation they cannot prove.
    with pytest.raises(ValueError):parse_riscv_operand('%r',output=False)


@pytest.mark.parametrize('outputs,inputs',[
    (['%=r'],['r']),(['=r'],['r','%r']),(['=r'],['%r','%r','r']),
    (['=r'],['%r','r','%r','r']),(['=r'],['r%','r']),
    (['=r'],['%%r','r']),(['=r'],['%+r','r']),
    (['=r'],['%r,m','r']),(['=r'],['%r','9']),
    (['=r'],['%&r','r']),(['=r'],['%{a0}','r'])])
def test_invalid_or_unmodeled_relations_remain_rejected(outputs,inputs):
    with pytest.raises(ValueError):derive(outputs,inputs)


def test_no_commutative_marker_preserves_existing_constraints():
    value=derive(['+&r'],['0','r'])
    assert value['allowedOperandPermutations']==[[0,1,2]]
    assert value['semanticCommutativityProofRequired'] is False
    assert value['operands'][0]['earlyClobber'] is True
    assert value['operands'][1]['matchingOutput']==0


@pytest.mark.parametrize('field,replacement',[
    ('semanticApproval',True),('semanticCommutativityProofRequired',False),
    ('allowedOperandPermutations',[[0,1,2]]),('commutativePairs',[])])
def test_rehashed_relations_do_not_waive_proof(field,replacement):
    value=deepcopy(derive(['=r'],['%r','r']));value[field]=replacement
    value['relationIdentity']=identity({k:v for k,v in value.items() if k!='relationIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):validate(value)
