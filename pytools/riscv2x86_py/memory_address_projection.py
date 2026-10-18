"""Compiler-owned address projection for an exact, side-effect-free dereference."""
from .compiler_expression import direct_declaration_carrier
from .compiler_operand_type import compiler_operand_type_from_dict
from .compiler_value_flow import identity


def project_memory_address(candidate,index):
    if candidate.get('schemaVersion')!='riscv2x86.closed-compiler-fragment.v2':
        raise ValueError('ATOMIC_MEMORY_EXPRESSION_CLOSURE_REQUIRED')
    evaluation=candidate['expressionEvaluation'];record=evaluation['bindings'][index]
    joined=evaluation['expressionJoin']['operands'][index]
    raw=candidate['expressionClosureInputs']['fragment']
    gnu=(raw['outputs']+raw['inputs'])[index]
    expression=joined['expression']
    while expression['kind']=='ParenExpr':expression=expression['children'][0]
    if (record['role']!='memory_lvalue' or record['access']!='read_write'
            or expression['kind']!='UnaryOperator' or expression['operation']!='*'):
        raise ValueError('ATOMIC_EXACT_DEREFERENCE_REQUIRED')
    base=direct_declaration_carrier(expression['children'][0])
    pointer=compiler_operand_type_from_dict(gnu.get('compilerAddressType'))
    memory=compiler_operand_type_from_dict(joined['compilerType'])
    if (not base or not pointer.is_pointer or not pointer.pointee_is_integer
            or not pointer.side_effect_free or not pointer.expression_repeatable
            or pointer.qualifiers or pointer.pointee_qualifiers
            or pointer.pointee_type_identity!=memory.type_identity):
        raise ValueError('ATOMIC_ADDRESS_PROJECTION_TYPE_UNPROVEN')
    payload={'schemaVersion':'riscv2x86.memory-address-projection.v1',
        'sourceDigest':evaluation['sourceDigest'],'functionIdentity':evaluation['functionIdentity'],
        'candidateIdentity':evaluation['candidateIdentity'],'operandIndex':index,
        'expressionIdentity':record['expressionIdentity'],'evaluationBindingIdentity':record['bindingIdentity'],
        'addressValueNodeIdentity':record['addressNode']['valueNodeIdentity'],
        'baseDeclarationIdentity':base,'compilerPointerType':gnu['compilerAddressType'],
        'offsetBytes':0,'evaluationCount':1,'projectionKind':'address_of_exact_dereference'}
    return {**payload,'projectionIdentity':identity(payload)}
