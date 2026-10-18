from copy import deepcopy
from dataclasses import asdict
import pytest
from riscv2x86_py.compiler_expression_evaluation import close_expression_evaluation, validate_expression_evaluation
from riscv2x86_py.compiler_expression import CompilerExpressionError
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.schema import _frag_from
from tests.test_compiler_expression_contracts import candidate, expr, node, ctype, S, F


def close(constraint, expression=None):
    raw = candidate(expression or expr(node()))
    fragment = {'id': 'fragment', 'outputs': [{'constraint': constraint, 'compilerType': ctype()}], 'inputs': []}
    result = close_expression_evaluation(raw, fragment, source_digest=S, function_identity=F)
    return raw, fragment, result


@pytest.mark.parametrize('constraint, phases', [('=r',['after']), ('+r',['before','after']), ('=&r',['after'])])
def test_access_phases_are_explicit(constraint, phases):
    raw, fragment, result = close(constraint)
    binding, = result['bindings']
    assert [n['phase'] for n in binding['valueNodes']] == phases
    assert len({n['valueNodeIdentity'] for n in binding['valueNodes']}) == len(phases)
    assert binding['earlyClobber'] == ('&' in constraint)
    assert result['semanticRouteApproved'] is False
    assert validate_expression_evaluation(result, raw, fragment, source_digest=S, function_identity=F) == result


def test_memory_lvalue_keeps_address_and_contents_separate():
    expression = expr(node('UnaryOperator', opcode='*', inner=[node(typ='unsigned long *')]))
    _, _, result = close('+m', expression)
    binding, = result['bindings']
    assert binding['declarationIdentity'] == ''
    assert binding['objectAuthorityDisposition'] == 'required'
    assert binding['addressNode']['valueKind'] == 'lvalue_address'
    assert binding['addressNode']['valueNodeIdentity'] not in {n['valueNodeIdentity'] for n in binding['valueNodes']}
    assert all(n['valueKind'] == 'memory_contents' for n in binding['valueNodes'])


@pytest.mark.parametrize('field, value', [('access','input'), ('expressionIdentity',S),
    ('declarationIdentity','invented'), ('earlyClobber',True), ('evaluationCount',2)])
def test_rehashed_carrier_mutation_is_not_authority(field, value):
    raw, fragment, result = close('=r')
    result['bindings'][0][field] = value
    result['bindings'][0]['bindingIdentity'] = identity({k:v for k,v in result['bindings'][0].items() if k != 'bindingIdentity'})
    result['evaluationIdentity'] = identity({k:v for k,v in result.items() if k != 'evaluationIdentity'})
    with pytest.raises(CompilerExpressionError, match='differs'):
        validate_expression_evaluation(result, raw, fragment, source_digest=S, function_identity=F)


def test_fragment_serialization_retains_evaluation():
    _, _, result = close('=r')
    assert asdict(_frag_from({'id':'fragment','compilerExpressionEvaluation':result}))['compilerExpressionEvaluation'] == result


def memory_candidate():
    expression = expr(node('UnaryOperator', opcode='*', inner=[node(typ='unsigned long *')]))
    raw = candidate(expression)
    raw.update(schemaVersion='riscv2x86.compiler-fragment-boundary-candidate.v4',
        fragmentBindingKey={'sourceDigest':S,'functionIdentity':F,'beginOffset':10,'endOffset':20},
        operandCarriers=[], valueNodes=[], downstreamUses=[], downstreamUseEnumerationComplete=True,
        compilerStructureComplete=False, operandClassificationComplete=False,
        reasonCodes=['L2_FRAGMENT_DECLARATION_IDENTITY_MISSING','L2_FRAGMENT_VALUE_NODE_MISSING'],
        operandSlotFacts={'slots':[{'operandIndex':0,'complete':False}]})
    fragment={'id':'fragment','outputs':[{'constraint':'+m','compilerType':ctype()}], 'inputs':[]}
    return raw, fragment


def test_production_closure_consumes_non_declaration_memory_slot():
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate, validate_closed_compiler_fragment_candidate
    raw, fragment=memory_candidate()
    closed=close_compiler_fragment_candidate(raw, fragment, source_digest=S,function_identity=F)
    assert closed['schemaVersion']=='riscv2x86.closed-compiler-fragment.v2'
    carrier,=closed['operandCarriers']
    assert carrier['declarationIdentity']==''
    assert carrier['carrierKind']=='memory_lvalue'
    assert closed['expressionEvaluation']['bindings'][0]['objectAuthorityDisposition']=='required'
    validate_closed_compiler_fragment_candidate(closed)
    fragment['compilerFragmentAuthority']={'candidate':closed}
    import json
    json.dumps(closed)  # Closure provenance must be a detached immutable snapshot.


@pytest.mark.parametrize('field,value', [('access','output'),('valueNodeIdentity',S),('widthBits',32)])
def test_expression_closure_rehashed_mutation_fails(field,value):
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate, validate_closed_compiler_fragment_candidate
    raw, fragment=memory_candidate()
    closed=close_compiler_fragment_candidate(raw,fragment,source_digest=S,function_identity=F)
    closed['operandBindings'][0][field]=value
    closed['closureIdentity']=identity({k:v for k,v in closed.items() if k!='closureIdentity'})
    with pytest.raises(ValueError,match='CLOSURE_MISMATCH'):
        validate_closed_compiler_fragment_candidate(closed)
