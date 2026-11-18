"""Finite compiler-bound entry contracts for the ORIGINAL operand validator.

This admits a call shape, never an asm proof, legal callee memory accesses or
machine ABI. Pointer carriers in the boundary protocol are object/offset tokens;
they cannot be consumed as architectural integer/address operand observations.
"""
from . import native_api_contract as api
from .native_external_providers import checked
from .project_build_records import identity
from .l2_execution_requirements import plan as requirements

SCHEMA = 'riscv2x86.l2-finite-typed-entry.v1'


def bind(function, selected, domain):
    from .native_original_api import MODEL
    checked({k: v for k, v in selected.items() if k != 'interface'}, 'functionBindingIdentity')
    if selected['interface'] != api.signature(selected['signature'], MODEL):
        raise ValueError('L2_TYPED_INTERFACE_REDERIVATION_MISMATCH')
    requirement = requirements(function, 'entry-signature-query')
    signature = requirement['compilerSignature']
    if signature is None:
        raise ValueError('L2_TYPED_COMPILER_SIGNATURE_REQUIRED')
    if (selected['compilerDeclarationIdentity'] != function.get('nativeCompilerDeclarationId')
            or selected['sourceDigest'] != signature['sourceDigest']
            or selected['name'] != function['name']):
        raise ValueError('L2_TYPED_COMPILER_DECLARATION_JOIN_MISMATCH')
    interface = selected['interface']
    if (signature['variadic'] or selected['signature'].get('variadic')
            or selected['signature'].get('attributes') or interface.get('declarationAttributes')
            or len(signature['parameters']) != len(interface['parameters'])
            or signature['resultType'] != interface['return']['cType']
            or any(p['canonicalType'] != t['cType'] for p, t in zip(signature['parameters'], interface['parameters']))):
        raise ValueError('L2_TYPED_COMPILER_SIGNATURE_MISMATCH')
    cases = api.validate(domain, interface)
    body = {'schemaVersion': SCHEMA, 'functionIdentity': function['functionId'],
            'compilerSignatureIdentity': signature['signatureIdentity'], 'selection': selected,
            'domain': domain, 'sampleCount': len(cases),
            'pointerParameterIndices': [i for i, t in enumerate(interface['parameters']) if t['kind'] == 'pointer'],
            'scope': 'finite-typed-entry-under-declared-preconditions-not-callee-legality-or-machine-ABI'}
    return dict(body, entryIdentity=identity(body))


def validate(entry, function):
    checked(entry, 'entryIdentity')
    if entry != bind(function, entry['selection'], entry['domain']):
        raise ValueError('L2_TYPED_ENTRY_REDERIVATION_MISMATCH')
    return entry


def validate_observations(entry, observation_plan, operands=()):
    """A logical object token must never become a numeric pointer observation."""
    pointers = set(entry['pointerParameterIndices'])
    if any(o.get('typeKind') != 'integer' for o in operands):
        raise ValueError('L2_TYPED_NONINTEGER_OPERAND_RELATION_REQUIRED')
    for binding in observation_plan.authority.bindings:
        if binding.parameter_index in pointers:
            raise ValueError('L2_TYPED_POINTER_OPERAND_RELATION_REQUIRED')
        if (entry['selection']['interface']['return']['kind'] == 'void'
                and binding.closure_kind == 'sink' and binding.observation_kind == 'function_return'):
            raise ValueError('L2_TYPED_VOID_RETURN_OBSERVATION_FORBIDDEN')


def wrapper(entry):
    text, _ = api.harness(entry['selection']['name'], entry['selection']['interface'], entry['domain'],
                          operand_trace=True)
    return ('#include <stdarg.h>\n' + text +
        '\nvoid __r2x_l2_observe(unsigned n,...){va_list a;va_start(a,n);printf("internal_trace");'
        'for(unsigned i=0;i<n;i++)printf(";%016llx",va_arg(a,unsigned long long));'
        'printf("\\n");va_end(a);}\n')
