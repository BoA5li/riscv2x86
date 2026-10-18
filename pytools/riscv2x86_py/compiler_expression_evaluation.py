"""Content-addressed evaluation carriers, distinct from declaration carriers.

This closes identity, GNU access and evaluation phases. It does not establish
memory-object provenance, bounds, aliasing, target lowering or proof approval.
"""
from collections.abc import Mapping
from copy import deepcopy
import re

from .compiler_expression import CompilerExpressionError, bind_expression_operands
from .compiler_value_flow import identity
from .compiler_operand_type import compiler_operand_type_from_dict

SCHEMA = 'riscv2x86.compiler-expression-evaluation.v1'
_SHA = re.compile(r'sha256:[0-9a-f]{64}')


def _reject(code, detail):
    raise CompilerExpressionError('COMPILER_EVALUATION_' + code, detail)


def _node(join, operand, phase, kind):
    payload = {'schemaVersion': 'riscv2x86.compiler-expression-value.v1',
        'sourceDigest': join['sourceDigest'], 'functionIdentity': join['functionIdentity'],
        'candidateIdentity': join['candidateIdentity'],
        'operandIndex': operand['operandIndex'],
        'expressionIdentity': operand['expressionIdentity'],
        'compilerTypeIdentity': operand['compilerTypeIdentity'],
        'phase': phase, 'valueKind': kind}
    return {**payload, 'valueNodeIdentity': identity(payload)}


def close_expression_evaluation(candidate, fragment, *, source_digest, function_identity):
    join = bind_expression_operands(candidate, fragment, source_digest=source_digest,
                                    function_identity=function_identity)
    if any(not isinstance(x, str) or _SHA.fullmatch(x) is None for x in
           (source_digest, function_identity, candidate.get('candidateIdentity'))):
        _reject('IDENTITY_INVALID', 'Source/function/candidate must be content identities')
    raw_operands = fragment['outputs'] + fragment['inputs']
    records = []
    for item, raw in zip(join['operands'], raw_operands):
        typ = compiler_operand_type_from_dict(item['compilerType'])
        if typ.qualifiers or typ.pointee_qualifiers:
            _reject('QUALIFIER_CONTRACT_REQUIRED', 'Qualified evaluation requires a dedicated visibility contract')
        constraint = raw['constraint']
        body = constraint.lstrip('=+&%')
        tied = int(body) if body.isdecimal() else None
        if tied is not None:
            if tied >= len(fragment['outputs']) or tied == item['operandIndex']:
                _reject('TIED_OPERAND_INVALID', 'Matching constraint must reference a distinct output')
            target = join['operands'][tied]
            if target['compilerTypeIdentity'] != item['compilerTypeIdentity']:
                _reject('TIED_TYPE_MISMATCH', 'Matching carriers have incompatible compiler types')
        role, access = item['role'], item['access']
        # Output memory lvalues denote storage, not a scalar post-value. The
        # address and read/write events are deliberately separate obligations.
        phases = (['before'] if access == 'input' else ['after'] if access == 'output'
                  else ['before', 'after'])
        values = [_node(join, item, phase, 'memory_contents' if role == 'memory_lvalue'
                        else 'pointer' if role == 'address_value' else 'integer')
                  for phase in phases]
        address = _node(join, item, 'address', 'lvalue_address') if role == 'memory_lvalue' else None
        record = {'operandIndex': item['operandIndex'], 'role': role, 'access': access,
            'expressionIdentity': item['expressionIdentity'],
            'declarationIdentity': item['declarationIdentity'],
            'compilerTypeIdentity': item['compilerTypeIdentity'],
            'sourceConstraint': constraint, 'tiedOperandIndex': tied,
            'earlyClobber': '&' in constraint, 'evaluationCount': 1,
            'sideEffectFree': True, 'valueNodes': values, 'addressNode': address,
            'objectAuthorityDisposition': 'required' if role in {'address_value', 'memory_lvalue'} else 'not_applicable'}
        record['bindingIdentity'] = identity(record)
        records.append(record)
    result = {'schemaVersion': SCHEMA, 'sourceDigest': source_digest,
        'functionIdentity': function_identity, 'candidateIdentity': candidate['candidateIdentity'],
        'fragmentId': join['fragmentId'], 'expressionJoin': join, 'bindings': records,
        'complete': True, 'semanticRouteApproved': False}
    result['evaluationIdentity'] = identity(result)
    return result


def validate_expression_evaluation(raw, candidate, fragment, *, source_digest, function_identity):
    """Rebuild from independently bound producer facts, not just rehash raw."""
    if not isinstance(raw, Mapping) or raw.get('schemaVersion') != SCHEMA:
        _reject('SCHEMA_INVALID', 'Unsupported evaluation carrier schema')
    expected = close_expression_evaluation(candidate, fragment,
        source_digest=source_digest, function_identity=function_identity)
    if dict(raw) != expected:
        _reject('BINDING_MISMATCH', 'Evaluation carrier differs from compiler facts or GNU operand roles')
    return deepcopy(expected)
