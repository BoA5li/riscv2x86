"""Classify compiler AST callees without granting builtin semantics authority.

BuiltinFnToFnPtr is compiler evidence, unlike a reserved-looking identifier.
Only transparent compiler conversions are traversed. Argument ASTs are kept:
in particular constant_p arguments must never become ordinary runtime calls.
"""
from copy import deepcopy

from .project_build_records import identity

CONTEXT_V1 = 'riscv2x86.native-call-contexts.v1'
CONTEXT_V2 = 'riscv2x86.native-call-contexts.v2'

# These are language intrinsic contracts, not project-specific matching rules.
# Naming a contract does not prove that GCC and Clang instantiate it equally.
BUILTINS = {
    '__builtin_constant_p': (1, 'compile-time-constant-query',
        ['NATIVE_CONSTANT_QUERY_LOWERING_REQUIRED',
         'SOURCE_TARGET_CONSTANT_QUERY_REFINEMENT_REQUIRED']),
    '__builtin_expect': (2, 'value-with-branch-expectation',
        ['TYPED_ARGUMENT_EVALUATION_AND_VALUE_PROOF_REQUIRED',
         'BRANCH_HINT_CLAIM_SCOPE_REQUIRED']),
}


def resolve(call, *, schema=CONTEXT_V2):
    if schema not in (CONTEXT_V1, CONTEXT_V2):
        raise ValueError('NATIVE_CONTEXT_SCHEMA_UNSUPPORTED')
    children = call.get('inner', [])
    callee = children[0] if children else {}
    builtin = False; conversions = []; blocker = None
    allowed = {'FunctionToPointerDecay', 'NoOp'}
    if schema == CONTEXT_V2:
        allowed.add('BuiltinFnToFnPtr')
    while callee.get('kind') in {'ImplicitCastExpr', 'ParenExpr'}:
        inner = callee.get('inner', [])
        cast = callee.get('castKind')
        conversions.append({'kind': callee['kind'], 'castKind': cast,
                            'type': deepcopy(callee.get('type'))})
        if len(inner) != 1 or (callee['kind'] == 'ImplicitCastExpr' and cast not in allowed):
            blocker = 'UNSUPPORTED_OR_MALFORMED_CALLEE_CONVERSION'
            callee = {}; break
        builtin |= callee['kind'] == 'ImplicitCastExpr' and cast == 'BuiltinFnToFnPtr'
        callee = inner[0]
    ref = callee.get('referencedDecl', {}) if callee.get('kind') == 'DeclRefExpr' else {}
    direct = ref.get('kind') == 'FunctionDecl' and isinstance(ref.get('id'), str)
    if builtin and not direct:
        blocker = 'BUILTIN_FUNCTION_DECLARATION_REQUIRED'
    classification = 'compiler-builtin' if builtin and direct else 'direct' if direct else 'unresolved'
    body = {'classification': classification, 'declaration': deepcopy(ref) if direct else None,
        'calleeAst': deepcopy(children[0]) if children else None,
        'conversionChain': conversions, 'resolutionBlocker': blocker,
        'argumentAsts': deepcopy(children[1:]), 'resultType': deepcopy(call.get('type')),
        'semanticContract': None, 'semanticContractVerified': False}
    if classification == 'compiler-builtin':
        contract = BUILTINS.get(ref.get('name'))
        obligations = ['COMPILER_BUILTIN_SEMANTICS_REQUIRED']
        if contract:
            arity, operation, obligations = contract
            obligations = list(obligations)
            if len(children)-1 != arity:
                obligations.append('BUILTIN_ARGUMENT_ARITY_MISMATCH')
            body['semanticContract'] = {'operation': operation, 'expectedArity': arity,
                'argumentCountMatches': len(children)-1 == arity}
        body['semanticObligations'] = obligations
    return dict(body, callEvidenceIdentity=identity(body))
