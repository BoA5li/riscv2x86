import pytest
from riscv2x86_py.asm_goto_region import close_predicate_region, AsmGotoRegionError
from riscv2x86_py.pcode_ir import Var, VarKind, Op, Block


def region():
    value=Var(VarKind.REG,'register',10,8,'a0')
    zero=Var(VarKind.CONST,'const',0,8)
    predicate=Var(VarKind.UNIQUE,'unique',1,1)
    target=Var(VarKind.CONST,'const',16,8)
    compare=Op(0,'INT_EQUAL',predicate,[value,zero])
    branch=Op(4,'CBRANCH',None,[target,predicate])
    return Block(0,ops=[compare,branch]),branch


def test_closed_region_identity_covers_operations():
    block, branch=region()
    assert close_predicate_region([block],branch)['complete']
    before=close_predicate_region([block],branch)['regionIdentity']
    block.ops[0].opcode='INT_NOTEQUAL'
    assert close_predicate_region([block],branch)['regionIdentity']!=before


@pytest.mark.parametrize('mutation,reason', [('extra','UNCOVERED_OPERATION'),('write','LIVE_WRITE_UNPROVEN'),
    ('unknown','EFFECT_UNSUPPORTED'),('two_blocks','DOMINANCE_AUTHORITY_REQUIRED'),('reorder','EXIT_NOT_FINAL')])
def test_region_rejects_uncovered_effects_and_missing_dominance(mutation,reason):
    block,branch=region(); blocks=[block]
    if mutation=='extra':
        block.ops.insert(0,Op(0,'COPY',Var(VarKind.UNIQUE,'unique',99,8),[Var(VarKind.CONST,'const',1,8)]))
    elif mutation=='write': block.ops[0].output=Var(VarKind.REG,'register',11,1,'a1')
    elif mutation=='unknown': block.ops[0].opcode='CALLOTHER'
    elif mutation=='two_blocks': blocks.append(Block(8,ops=[]))
    else: block.ops.reverse()
    with pytest.raises(AsmGotoRegionError) as error:
        close_predicate_region(blocks,branch)
    assert error.value.reason_code=='ASM_GOTO_REGION_'+reason
