import pytest
from riscv2x86_py.gnu_operand_contract import parse_riscv_operand

@pytest.mark.parametrize('constraint',['+A','+m','=A','=m'])
def test_memory_role_is_preserved(constraint):
    parsed=parse_riscv_operand(constraint,output=True)
    assert parsed.role=='memory_lvalue'
    assert parsed.access==('read_write' if constraint[0]=='+' else 'output')
    assert parsed.address_in_register==constraint.endswith('A')

@pytest.mark.parametrize('constraint',['=rm','+r,m','{a0}','+&m,r','+A,r'])
def test_unapproved_alternatives_and_fixed_registers_are_not_guessed(constraint):
    with pytest.raises(ValueError):parse_riscv_operand(constraint,output=True)


def test_type_sugar_uses_compiler_declarations_and_rejects_cycles():
    from riscv2x86_py.automatic_batch_cli import _compiler_type_alias_resolver
    def alias(name,base):return {'kind':'TypedefDecl','name':name,'type':{'qualType':base}}
    resolver=_compiler_type_alias_resolver({'inner':[alias('base_word','unsigned long'),alias('word','base_word')]})
    assert resolver('word *')=='unsigned long *'
    assert resolver('different_word *')=='different_word *'
    ambiguous=_compiler_type_alias_resolver({'inner':[alias('word','unsigned long'),alias('word','unsigned int')]})
    assert ambiguous('word *')=='word *'
    cyclic=_compiler_type_alias_resolver({'inner':[alias('a','b'),alias('b','a')]})
    with pytest.raises(ValueError):cyclic('a *')
