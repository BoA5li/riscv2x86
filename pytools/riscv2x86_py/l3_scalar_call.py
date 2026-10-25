"""Compiler-bound LP64 integer calls and a deterministic, replayable sample plan.

The initial ABI domain is 1..4 integer parameters and an integer result, all
64 bits. Types come from the closed compiler operand authority, not C spelling.
No out-of-range unsigned-to-signed conversion is used by the harness.
"""
from .l3_trace_support import identity

SCHEMA = 'riscv2x86.l3-scalar-call.v1'
_C_TYPES = {'long': True, 'long int': True, 'signed long': True,
            'long long': True, 'long long int': True, 'signed long long': True,
            'unsigned long': False, 'unsigned long int': False,
            'unsigned long long': False, 'unsigned long long int': False,
            'int64_t': True, 'uint64_t': False}


def call_signature(function, finding):
    from .compiler_operand_type import compiler_operand_type_from_dict
    from .compiler_provenance import bind_compiler_provenance
    from .l2_authority import l2_authority_sidecar_from_dict
    sidecar = l2_authority_sidecar_from_dict(finding['approvalArtifact']['l2AuthoritySidecar'])
    bind_compiler_provenance(finding['fragment'], sidecar)
    authority = finding['fragment']['compilerFragmentAuthority']
    boundary = function['l2OperandBoundary']
    params = boundary['parameterDeclarationIds']
    if (not 1 <= len(params) <= 4 or len(set(params)) != len(params)
            or function['arity'] != len(params) or len(function['parameterTypes']) != len(params)
            or function['functionId'] != authority['functionIdentity']
            or function['sourceDigest'] != authority['sourceDigest']):
        raise ValueError('L3_SCALAR_CALL_SIGNATURE_UNSUPPORTED')

    def item(declaration, spelling):
        if boundary['declarations'][declaration]['type'] != spelling:
            raise ValueError('L3_SCALAR_CALL_DECLARATION_TYPE_MISMATCH')
        records = [authority['compilerTypeBindings'][str(b['operandIndex'])]['compilerType']
                   for b in authority['candidate']['operandBindings']
                   if b['declarationIdentity'] == declaration]
        if not records or any(r != records[0] for r in records):
            raise ValueError('L3_SCALAR_CALL_TYPE_AUTHORITY_MISSING')
        typ = compiler_operand_type_from_dict(records[0])
        bindings = [b for b in authority['candidate']['operandBindings'] if b['declarationIdentity'] == declaration]
        if (not typ.is_integer or typ.is_pointer or typ.width_bits != 64
                or typ.alignment_bytes != 8 or typ.qualifiers or not typ.side_effect_free
                or _C_TYPES.get(typ.canonical_type) is not typ.is_signed
                or any(b['signedness'] != ('signed' if typ.is_signed else 'unsigned') for b in bindings)):
            raise ValueError('L3_SCALAR_CALL_INTEGER64_REQUIRED')
        return {'declarationIdentity': declaration, 'typeIdentity': typ.type_identity,
                'widthBits': 64, 'signed': typ.is_signed,
                'cType': typ.canonical_type}

    body = {'schemaVersion': SCHEMA, 'functionIdentity': function['functionId'],
            'sourceDigest': authority['sourceDigest'], 'abi': 'linux-lp64-integer64',
            'parameters': [item(d, t) for d, t in zip(params, function['parameterTypes'])],
            'result': item(boundary['returnDeclarationId'], function['returnType'])}
    return dict(body, signatureIdentity=identity(body))


def validate_signature(value):
    fields = {'schemaVersion', 'functionIdentity', 'sourceDigest', 'abi', 'parameters', 'result', 'signatureIdentity'}
    if (not isinstance(value, dict) or set(value) != fields or value['schemaVersion'] != SCHEMA
            or value['abi'] != 'linux-lp64-integer64'
            or value['signatureIdentity'] != identity({k: v for k, v in value.items() if k != 'signatureIdentity'})
            or not isinstance(value['parameters'], list) or not 1 <= len(value['parameters']) <= 4):
        raise ValueError('L3_SCALAR_CALL_SIGNATURE_INVALID')
    from .l3_intent_requirements import _sha
    for key in ('functionIdentity', 'sourceDigest'):
        _sha(value[key], key)
    for item in value['parameters'] + [value['result']]:
        if (not isinstance(item, dict) or set(item) != {'declarationIdentity', 'typeIdentity', 'widthBits', 'signed', 'cType'}
                or type(item['signed']) is not bool or type(item['widthBits']) is not int or item['widthBits'] != 64
                or _C_TYPES.get(item['cType']) is not item['signed']
                or not isinstance(item['declarationIdentity'], str) or not item['declarationIdentity']):
            raise ValueError('L3_SCALAR_CALL_TYPE_INVALID')
        _sha(item['typeIdentity'], 'typeIdentity')
    if len({p['declarationIdentity'] for p in value['parameters']}) != len(value['parameters']):
        raise ValueError('L3_SCALAR_CALL_PARAMETER_DUPLICATED')
    return value


def sample_plan(signature, count):
    validate_signature(signature)
    if type(count) is not int or not 2 <= count <= 16:
        raise ValueError('L3_TRACE_SAMPLE_COUNT_INVALID')
    # Distinct lanes expose accidental permutations. The bounded plan includes
    # zero, positive, negative and signed/unsigned boundaries (all eight seeds
    # in each lane when at least eight calls are selected).
    seeds = (0, 1, 0xffffffffffffffff, 0x8000000000000000,
             0x7fffffffffffffff, 63, 64, 0x1020304050607080)
    rows = [[f'{(seeds[(sample + index) % len(seeds)] ^ (sample // len(seeds))):016x}'
             for index in range(len(signature['parameters']))] for sample in range(count)]
    body = {'schemaVersion': 'riscv2x86.l3-scalar-samples.v1',
            'signatureIdentity': signature['signatureIdentity'], 'inputs': rows,
            'coverageClaim': 'listed-input-vectors-only'}
    return dict(body, planIdentity=identity(body))
