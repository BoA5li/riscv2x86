"""Compiler-bound integer return expressions, separate from carrier identities.

The AST records conversions without granting permission to execute them. The
load consumer admits only value-preserving/injective integer conversion chains;
no narrowing, implementation-defined signed conversion or arithmetic is hidden.
"""
import re

from .compiler_expression import expression_from_ast, validate_expression
from .compiler_memory_signature import type_fact
from .compiler_value_flow import identity
from .l3_trace_support import require_json_document, require_json_match

SCHEMA = 'riscv2x86.compiler-return-binding.v1'
_FIELDS = {'schemaVersion', 'sourceDigest', 'functionIdentity', 'returnRange',
           'expression', 'resultType', 'factsIdentity'}


def export(node, *, source_digest, function_identity, declaration_identity,
           source_range, result_type, type_resolver):
    children = node.get('inner', [])
    extent = source_range(node)
    if node.get('kind') != 'ReturnStmt' or len(children) != 1 or extent is None:
        raise ValueError('COMPILER_RETURN_EXPRESSION_REQUIRED')
    result = type_fact(type_resolver(result_type))
    if result is None or result['kind'] != 'integer':
        raise ValueError('COMPILER_RETURN_INTEGER_TYPE_REQUIRED')
    expression = expression_from_ast(children[0], source_digest=source_digest,
        function_identity=function_identity, declaration_identity=declaration_identity,
        source_range=source_range, type_resolver=type_resolver)
    body = {'schemaVersion': SCHEMA, 'sourceDigest': source_digest,
        'functionIdentity': function_identity, 'returnRange': list(extent),
        'expression': expression, 'resultType': result}
    return dict(body, factsIdentity=identity(body))


def _integer(text):
    value = type_fact(text)
    if value is None or value['kind'] != 'integer':
        raise ValueError('L3_MEMORY_LOAD_RETURN_CONVERSION_UNSUPPORTED')
    return value


def analyze(binding, *, source_digest, function_identity, result_type):
    """Return leaf declaration/type and ordered C conversions; validate all AST nodes."""
    require_json_document(binding, 'L3_MEMORY_LOAD_RETURN_JSON_INVALID')
    if not isinstance(binding, dict) or set(binding) != _FIELDS or binding['schemaVersion'] != SCHEMA:
        raise ValueError('L3_MEMORY_LOAD_RETURN_BINDING_REQUIRED')
    if (binding['factsIdentity'] != identity({k:v for k,v in binding.items() if k != 'factsIdentity'})
            or binding['sourceDigest'] != source_digest or binding['functionIdentity'] != function_identity
            or re.fullmatch(r'sha256:[0-9a-f]{64}', source_digest) is None
            or re.fullmatch(r'sha256:[0-9a-f]{64}', function_identity) is None):
        raise ValueError('L3_MEMORY_LOAD_RETURN_BINDING_IDENTITY_MISMATCH')
    require_json_match(binding['resultType'], result_type, 'L3_MEMORY_LOAD_RETURN_TYPE_MISMATCH')
    result = _integer(result_type['cType'])
    require_json_match(result, result_type, 'L3_MEMORY_LOAD_RETURN_TYPE_MISMATCH')
    expression = binding['expression']
    validate_expression(expression, source_digest=source_digest, function_identity=function_identity)
    extent = binding['returnRange']
    if (not isinstance(extent, list) or len(extent) != 2 or any(type(x) is not int for x in extent)
            or not 0 <= extent[0] <= expression['sourceRange'][0] < expression['sourceRange'][1] <= extent[1]):
        raise ValueError('L3_MEMORY_LOAD_RETURN_RANGE_INVALID')
    require_json_match(_integer(expression['canonicalType']), result_type,
                       'L3_MEMORY_LOAD_RETURN_TYPE_MISMATCH')

    def walk(node):
        typ = _integer(node['canonicalType'])
        if node['kind'] == 'DeclRefExpr':
            return node['declarationIdentity'], typ, []
        if node['kind'] not in {'ParenExpr', 'ImplicitCastExpr', 'CStyleCastExpr'}:
            raise ValueError('L3_MEMORY_LOAD_RETURN_CONVERSION_UNSUPPORTED')
        child = node['children'][0]
        declaration, leaf, steps = walk(child)
        before = _integer(child['canonicalType'])
        operation = node['operation']
        if node['kind'] == 'ParenExpr' or operation in {'NoOp', 'LValueToRValue'}:
            require_json_match(before, typ, 'L3_MEMORY_LOAD_RETURN_TYPE_MISMATCH')
        elif operation == 'IntegralCast':
            # All input values must be represented unambiguously. Unsigned
            # destinations use defined modulo conversion; signed destinations
            # must represent the entire preceding type's range.
            if (typ['widthBits'] < before['widthBits']
                    or typ['signed'] and (not before['signed'] and typ['widthBits'] <= before['widthBits'])):
                raise ValueError('L3_MEMORY_LOAD_RETURN_CONVERSION_UNSUPPORTED')
            steps.append({'fromType': before, 'toType': typ})
        else:
            raise ValueError('L3_MEMORY_LOAD_RETURN_CONVERSION_UNSUPPORTED')
        return declaration, leaf, steps

    declaration, leaf, steps = walk(expression)
    return {'declarationIdentity': declaration, 'inputType': leaf,
            'resultType': result, 'conversions': steps}


def evaluate(value, relation):
    """C integer conversion chain, preserving every intermediate conversion."""
    for step in relation['conversions']:
        typ = step['toType']
        value &= (1 << typ['widthBits']) - 1
        if typ['signed'] and value & (1 << (typ['widthBits'] - 1)):
            value -= 1 << typ['widthBits']
    return value
