from copy import deepcopy
from dataclasses import asdict
import pytest
from tests.test_asm_goto_structured_authority import _model, _fragment
from tests.test_canonical_l2_operand import _boundary, _function
from riscv2x86_py.l2_fragment_execution import OperandBinding
from riscv2x86_py.l2_asm_goto import asm_goto_proof_facts, validate_asm_goto_proof_facts
from riscv2x86_py.l2_effect_proof import L2EffectProofFacts,SourceEffectFact,TargetEffectFact,EffectRelationFact,ShellRelationFact
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.automatic_l2_authority import _asm_goto_authority


def finding():
    fragment=asdict(_fragment()); fragment['enclosingFunction']='probe'
    model=_model()
    proof='sha256:'+'2'*64; renderer='sha256:'+'3'*64
    approval={'proofStatus':'approved','proofIdentity':proof,'planId':'plan','constraintsId':'constraints',
        'rendererContractIdentity':renderer}
    approval['l2AsmGotoProofFacts']=asm_goto_proof_facts(fragment['id'],model,approval)
    properties=tuple(sorted(('kind','target','branch_condition','branch_continuation','branch_outcome','value')))
    effect=L2EffectProofFacts(fragment['id'],proof,'plan','constraints',renderer,
        (SourceEffectFact('control','ControlTransfer','asm-goto:'+identity(approval['l2AsmGotoProofFacts']['sourceAuthority']),True),),
        (TargetEffectFact('target:control','ControlTransfer','asm-goto:'+identity(approval['l2AsmGotoProofFacts']['sourceAuthority']),True),),
        (EffectRelationFact('relation:control','control',('target:control',),'exact',properties,(),'', '',True),),
        ShellRelationFact((),(),(),(),True,True,True,True,True,True),True)
    approval['l2EffectProofFacts']=effect.to_dict()
    approval['l2FragmentOperandBoundary']=_boundary(inputs=(OperandBinding(0,'decl:input','sha256:'+'4'*64,
        'input',64,True,'unsigned'),),fragment_id=fragment['id'])
    return {'fragment':fragment,'approvalArtifact':approval,'l2SemanticProfile':{'patternKind':'asm_goto'}},[
        {'name':'probe','l2OperandBoundary':_function({'decl:input':{'name':'x','type':'uint64_t'}},('decl:input',))}]


def test_asm_goto_has_dedicated_proof_owned_sidecar_without_scalar_result():
    raw,functions=finding()
    sidecar=_asm_goto_authority(raw,functions,'sha256:'+'5'*64)
    assert sidecar is not None
    control,=sidecar.control_flow
    assert control.transfer_kind=='asm_goto'
    assert control.result_operand_id==''
    assert len(control.continuations)==2
    assert sidecar.source_effects[0].effect_kind=='ControlTransfer'


@pytest.mark.parametrize('field,value', [('taken_successor_block','wrong'),('predicate_region_identity',''),
    ('machine_continuation_join_identity',''),('lhs_binding','operand:1')])
def test_rehashed_invalid_source_contract_cannot_materialize(field,value):
    raw,functions=finding()
    facts=raw['approvalArtifact']['l2AsmGotoProofFacts']
    facts['sourceAuthority'][field]=value
    facts['factsIdentity']=identity({k:v for k,v in facts.items() if k!='factsIdentity'})
    assert _asm_goto_authority(raw,functions,'sha256:'+'5'*64) is None
