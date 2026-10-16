from copy import deepcopy

import pytest

from riscv2x86_py.compiler_expression import (
    expression_from_ast, validate_expression, direct_declaration_carrier,
    bind_expression_operands, validate_expression_slots, CompilerExpressionError,
)
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.automatic_batch_cli import _source_range, _decl_identity, _integer_type, _l2_operand_boundary_facts

S, F, D = ('sha256:' + x * 64 for x in ('1', '2', '3'))


def node(kind='DeclRefExpr', *, typ='unsigned long', **extra):
    return {'kind': kind, 'type': {'qualType': typ}, 'valueCategory': 'lvalue',
        'range': {'begin': {'offset': 10}, 'end': {'offset': 15, 'tokLen': 1}},
        **({'referencedDecl': {'id': 'ast:p'}} if kind == 'DeclRefExpr' else {}), **extra}


def expr(raw):
    return expression_from_ast(raw, source_digest=S, function_identity=F,
        declaration_identity=lambda x: D if x == 'ast:p' else '', source_range=_source_range)


def ctype(**extra):
    return {'schemaVersion': 'riscv2x86.clang-operand-type.v1',
        'canonicalType': 'unsigned long', 'widthBits': 64, 'alignmentBytes': 8,
        'isInteger': True, 'isPointer': False, 'isSigned': False,
        'pointeeType': '', 'pointeeWidthBits': 0, 'pointeeAlignmentBytes': 0,
        'pointeeIsInteger': False, 'sideEffectFree': True, 'modifiableLvalue': True,
        'qualifiers': '', 'pointeeQualifiers': '', 'expressionRepeatable': False, **extra}


def test_expression_identity_is_separate_from_declaration_and_cast_is_not_erased():
    raw = node('CStyleCastExpr', typ='unsigned int', valueCategory='prvalue',
        castKind='IntegralCast', inner=[node()])
    result = expr(raw)
    assert result['declarationIdentity'] == ''
    assert result['operation'] == 'IntegralCast'
    assert result['children'][0]['declarationIdentity'] == D
    assert result['expressionIdentity'] != D
    assert direct_declaration_carrier(result) == ''
    assert _decl_identity(raw) == ''


@pytest.mark.parametrize('cast', ['IntegralCast', 'IntegralToBoolean', 'BitCast'])
def test_casts_never_alias_original_declaration(cast):
    raw = node('ImplicitCastExpr', castKind=cast, inner=[node()])
    assert _decl_identity(raw) == ''
    assert direct_declaration_carrier(expr(raw)) == ''


def test_type_preserving_load_and_parentheses_keep_exact_declaration():
    raw = node('ParenExpr', inner=[node('ImplicitCastExpr', castKind='LValueToRValue', inner=[node()])])
    assert _decl_identity(raw) == 'ast:p'
    assert direct_declaration_carrier(expr(raw)) == D


@pytest.mark.parametrize('raw, reason', [
    (node('CallExpr'), 'KIND_UNSUPPORTED'),
    (node('UnaryOperator', opcode='++', inner=[node()]), 'UNARY_UNSUPPORTED'),
    (node('BinaryOperator', opcode='=', inner=[node(), node()]), 'BINARY_UNSUPPORTED'),
    (node('CStyleCastExpr', castKind='PointerToIntegral', inner=[node()]), 'CAST_UNSUPPORTED'),
    (node(referencedDecl={'id':'unbound'}), 'DECLARATION_UNBOUND'),
])
def test_unsupported_evaluation_is_precise(raw, reason):
    with pytest.raises(CompilerExpressionError, match='.') as failure:
        expr(raw)
    assert failure.value.reason_code == 'COMPILER_EXPRESSION_' + reason


@pytest.mark.parametrize('field,value', [('operation','unknown'), ('canonicalType','int'), ('sourceDigest',F)])
def test_expression_mutation_is_rejected(field, value):
    raw = expr(node())
    raw[field] = value
    with pytest.raises(CompilerExpressionError):
        validate_expression(raw, source_digest=S, function_identity=F)


def test_rehashed_unknown_operation_is_still_rejected():
    raw = expr(node('UnaryOperator', opcode='*', inner=[node(typ='unsigned long *')]))
    raw['operation'] = '++'
    raw['expressionIdentity'] = identity({k:v for k,v in raw.items() if k != 'expressionIdentity'})
    with pytest.raises(CompilerExpressionError) as failure:
        validate_expression(raw, source_digest=S, function_identity=F)
    assert failure.value.reason_code == 'COMPILER_EXPRESSION_OPERATION_INVALID'


def candidate(expression):
    facts = {'schemaVersion':'riscv2x86.compiler-expression-slots.v1',
        'sourceDigest':S, 'functionIdentity':F, 'candidateIdentity':D,
        'slots':[{'operandIndex':0, 'complete':True, 'expression':expression, 'reasonCode':'','detail':''}],
        'complete':True}
    facts['factsIdentity'] = identity(facts)
    return {'candidateIdentity':D,'compilerExpressionFacts':facts}


def test_memory_lvalue_retains_expression_without_fabricating_declaration():
    expression = expr(node('UnaryOperator', opcode='*', inner=[node(typ='unsigned long *')]))
    result = bind_expression_operands(candidate(expression), {'id':'fragment',
        'outputs':[{'constraint':'+m', 'compilerType':ctype()}], 'inputs':[]},
        source_digest=S,function_identity=F)
    binding = result['operands'][0]
    assert binding['role'] == 'memory_lvalue'
    assert binding['access'] == 'read_write'
    assert binding['declarationIdentity'] == ''
    assert binding['expression']['children'][0]['declarationIdentity'] == D
    assert result['semanticRouteApproved'] is False
    assert result['joinIdentity'] == identity({k:v for k,v in result.items() if k != 'joinIdentity'})


@pytest.mark.parametrize('mutation, reason', [
    ({'sideEffectFree':False}, 'EVALUATION_CONTRACT_REQUIRED'),
    ({'modifiableLvalue':False}, 'OUTPUT_NOT_MODIFIABLE'),
    ({'canonicalType':'unsigned int','widthBits':32,'alignmentBytes':4}, 'TYPE_MISMATCH'),
])
def test_join_rejects_evaluation_and_type_mismatch(mutation, reason):
    with pytest.raises(CompilerExpressionError) as failure:
        bind_expression_operands(candidate(expr(node())), {'id':'f','outputs':[
            {'constraint':'=r','compilerType':ctype(**mutation)}], 'inputs':[]},
            source_digest=S, function_identity=F)
    assert failure.value.reason_code == 'COMPILER_EXPRESSION_' + reason


def test_index_mutation_cannot_compact_expression_slots():
    facts = candidate(expr(node()))['compilerExpressionFacts']
    facts['slots'][0]['operandIndex'] = 1
    facts['factsIdentity'] = identity({k:v for k,v in facts.items() if k != 'factsIdentity'})
    with pytest.raises(CompilerExpressionError) as failure:
        validate_expression_slots(facts, source_digest=S, function_identity=F,
            candidate_identity=D, operand_count=1)
    assert failure.value.reason_code == 'COMPILER_EXPRESSION_SLOT_INVALID'


@pytest.mark.parametrize('name', ['long double','unsigned long *','character_record','struct long_name','short_alias'])
def test_unknown_c_types_are_not_integer_substring_matches(name):
    assert _integer_type(name)[0] == 0


def test_expression_join_survives_fragment_report_round_trip():
    from dataclasses import asdict
    from riscv2x86_py.schema import _frag_from
    join = bind_expression_operands(candidate(expr(node())), {'id':'f',
        'outputs':[{'constraint':'=r','compilerType':ctype()}], 'inputs':[]},
        source_digest=S,function_identity=F)
    restored = _frag_from({'id':'f','compilerExpressionJoin':join})
    assert asdict(restored)['compilerExpressionJoin'] == join


def test_narrowing_return_cannot_be_misclassified_as_direct_counter_return():
    from riscv2x86_py.automatic_batch_cli import _counter_return_semantics
    output = node(referencedDecl={'id':'ast:counter'})
    result = node('CStyleCastExpr', typ='unsigned int', castKind='IntegralCast', inner=[output])
    function = {'kind':'FunctionDecl','inner':[
        {'kind':'GCCAsmStmt','inner':[output]}, {'kind':'ReturnStmt','inner':[result]}]}
    assert _counter_return_semantics(function)['counterReturnSemantics'] == 'unproved'
