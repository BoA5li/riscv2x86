"""Typed local contracts for native-input integer translations.

No project names, source line numbers, macro names or observed constant values
select a rule. The finite rules reject side effects, volatile reads, unknown
casts and unsupported types. These are local proofs, not whole-program claims.
"""
from copy import deepcopy

from .project_build_records import identity
from .compiler_native_calls import resolve


def integer_type(node, model):
    facts = node.get('type', {})
    name = facts.get('desugaredQualType', facts.get('qualType', ''))
    types = {
        'int': (int(model['__SIZEOF_INT__'])*8, True),
        'unsigned int': (int(model['__SIZEOF_INT__'])*8, False),
        'long': (int(model['__SIZEOF_LONG__'])*8, True),
        'unsigned long': (int(model['__SIZEOF_LONG__'])*8, False),
        'long long': (int(model['__SIZEOF_LONG_LONG__'])*8, True),
        'unsigned long long': (int(model['__SIZEOF_LONG_LONG__'])*8, False),
        '__int128': (128, True), 'unsigned __int128': (128, False),
    }
    if name not in types:
        raise ValueError('NATIVE_INTEGER_TYPE_CONTRACT_REQUIRED:'+name)
    bits, signed = types[name]
    return {'bits': bits, 'signed': signed}


def term(node, model, declaration_key):
    """Normalize only explicitly supported typed integer expression semantics."""
    kind = node.get('kind'); children = node.get('inner', [])
    typ = integer_type(node, model)
    if kind == 'ParenExpr':
        if len(children) != 1 or integer_type(children[0], model) != typ:
            raise ValueError('NATIVE_INTEGER_PAREN_TYPE_MISMATCH')
        return term(children[0], model, declaration_key)
    if kind == 'IntegerLiteral':
        value = node.get('value')
        if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
            raise ValueError('NATIVE_INTEGER_LITERAL_VALUE_INVALID')
        number = int(value)
        if number >= 1 << (typ['bits']-int(typ['signed'])):
            raise ValueError('NATIVE_INTEGER_LITERAL_OUT_OF_RANGE')
        return {'op': 'constant', 'type': typ, 'value': number}
    if kind == 'DeclRefExpr':
        ref = node.get('referencedDecl', {})
        if ref.get('kind') not in {'VarDecl', 'ParmVarDecl'} or not ref.get('id'):
            raise ValueError('NATIVE_INTEGER_VARIABLE_BINDING_REQUIRED')
        return {'op': 'value', 'type': typ, 'declaration': declaration_key(ref['id'])}
    if kind in {'ImplicitCastExpr', 'CStyleCastExpr'}:
        if len(children) != 1:
            raise ValueError('NATIVE_INTEGER_CAST_ARITY_INVALID')
        cast = node.get('castKind')
        if cast not in {'LValueToRValue', 'NoOp', 'IntegralCast'}:
            raise ValueError('NATIVE_INTEGER_CAST_CONTRACT_REQUIRED:'+str(cast))
        child = term(children[0], model, declaration_key)
        if cast in {'LValueToRValue', 'NoOp'} and child['type'] != typ:
            raise ValueError('NATIVE_INTEGER_CAST_TYPE_MISMATCH')
        if child['type'] == typ:
            return child
        if typ['signed'] and (child['type']['bits'] > typ['bits'] or
                (not child['type']['signed'] and child['type']['bits'] >= typ['bits'])):
            if child['op'] != 'constant' or child['value'] >= 1 << (typ['bits']-1):
                raise ValueError('NATIVE_INTEGER_IMPLEMENTATION_DEFINED_CONVERSION_REQUIRED')
        return {'op': 'integer-conversion', 'type': typ, 'argument': child}
    if kind == 'UnaryOperator' and node.get('opcode') == '!' and len(children) == 1:
        if typ != {'bits': int(model['__SIZEOF_INT__'])*8, 'signed': True}:
            raise ValueError('NATIVE_INTEGER_LOGICAL_RESULT_TYPE_INVALID')
        return {'op': '!', 'type': typ, 'arguments': [term(children[0], model, declaration_key)]}
    if kind == 'BinaryOperator' and len(children) == 2:
        op = node.get('opcode')
        if op not in {'*', '>>', '>=', '>', '<', '<=', '==', '!=', '&&', '||'}:
            raise ValueError('NATIVE_INTEGER_OPERATOR_CONTRACT_REQUIRED:'+str(op))
        args = [term(child, model, declaration_key) for child in children]
        if op in {'*', '>>'}:
            if typ['signed'] or args[0]['type'] != typ:
                raise ValueError('NATIVE_INTEGER_UNSIGNED_ARITHMETIC_REQUIRED')
            if op == '*' and args[1]['type'] != typ:
                raise ValueError('NATIVE_INTEGER_MULTIPLICAND_TYPE_MISMATCH')
            if op == '>>' and (args[1]['op'] != 'constant' or not 0 <= args[1]['value'] < typ['bits']):
                raise ValueError('NATIVE_INTEGER_SHIFT_RANGE_REQUIRED')
        else:
            if typ != {'bits': int(model['__SIZEOF_INT__'])*8, 'signed': True}:
                raise ValueError('NATIVE_INTEGER_PREDICATE_RESULT_TYPE_INVALID')
            if op not in {'&&', '||'} and args[0]['type'] != args[1]['type']:
                raise ValueError('NATIVE_INTEGER_USUAL_CONVERSIONS_REQUIRED')
        return {'op': op, 'type': typ, 'arguments': args}
    raise ValueError('NATIVE_INTEGER_EXPRESSION_CONTRACT_REQUIRED:'+str(kind))


def builtin_contract(call, model, declaration_key):
    evidence = resolve(call)
    if evidence['classification'] != 'compiler-builtin':
        raise ValueError('NATIVE_INTEGER_COMPILER_BUILTIN_REQUIRED')
    name = evidence['declaration']['name']; args = evidence['argumentAsts']
    if name == '__builtin_constant_p':
        if len(args) != 1 or args[0].get('kind') != 'IntegerLiteral':
            raise ValueError('NATIVE_CONSTANT_QUERY_LITERAL_CONTRACT_REQUIRED')
        argument = term(args[0], model, declaration_key)
        if integer_type(call, model) != {'bits': int(model['__SIZEOF_INT__'])*8, 'signed': True}:
            raise ValueError('NATIVE_CONSTANT_QUERY_RESULT_TYPE_INVALID')
        body = {'operation': 'compiler-integer-literal-constant-query',
            'argument': argument, 'result': 1, 'argumentEvaluation': 'unevaluated',
            'requiredWitness': 'source-and-target-compiler-static-assert'}
    elif name == '__builtin_expect':
        if len(args) != 2:
            raise ValueError('NATIVE_EXPECT_ARITY_INVALID')
        normalized = [term(arg, model, declaration_key) for arg in args]
        result_type = integer_type(call, model)
        if result_type != {'bits': int(model['__SIZEOF_LONG__'])*8, 'signed': True} or any(
                item['type'] != result_type for item in normalized):
            raise ValueError('NATIVE_EXPECT_LONG_CONVERSION_REQUIRED')
        expected = normalized[1]
        while expected['op'] == 'integer-conversion':
            expected = expected['argument']
        if expected['op'] != 'constant':
            raise ValueError('NATIVE_EXPECT_CONSTANT_HINT_REQUIRED')
        body = {'operation': 'typed-value-with-branch-expectation',
            'arguments': normalized, 'result': deepcopy(normalized[0]),
            'targetDisposition': 'preserve-original-builtin-call',
            'physicalBranchPredictionEquivalenceClaimed': False}
    else:
        raise ValueError('NATIVE_BUILTIN_CONTRACT_UNSUPPORTED:'+str(name))
    return dict(body, contractIdentity=identity(body))


def decode_mulhu(code, bindings):
    """Decode the RV64 M-extension word, then join actual materializer bindings."""
    if not isinstance(code, bytes) or len(code) != 4:
        raise ValueError('NATIVE_SINGLE_INSTRUCTION_REQUIRED')
    word = int.from_bytes(code, 'little')
    if word & 0x7f != 0x33 or (word >> 12) & 7 != 3 or word >> 25 != 1:
        raise ValueError('NATIVE_INSTRUCTION_SEMANTICS_UNSUPPORTED')
    actual = [(word >> 7) & 31, (word >> 15) & 31, (word >> 20) & 31]
    expected = [bindings.get(i) for i in range(3)]
    if any(type(r) is not int or not 1 <= r <= 31 for r in expected) or actual != expected:
        raise ValueError('NATIVE_MACHINE_OPERAND_BINDING_MISMATCH')
    return {'operation': 'rv64-unsigned-multiply-high', 'widthBits': 64,
            'instructionBytes': code.hex(), 'operandRegisters': actual}


def multiply_high_term(left, right):
    wide = {'bits': 128, 'signed': False}; narrow = {'bits': 64, 'signed': False}
    def extend(argument):
        return {'op': 'integer-conversion', 'type': wide, 'argument': argument}
    return {'op': 'integer-conversion', 'type': narrow, 'argument': {
        'op': '>>', 'type': wide, 'arguments': [
            {'op': '*', 'type': wide, 'arguments': [extend(left), extend(right)]},
            {'op': 'constant', 'type': {'bits': 32, 'signed': True}, 'value': 64}]}}
