"""Compiler-bound execution planning; never invent ABI or pointer domains."""
from .project_build_records import identity

SIGNATURE = 'riscv2x86.compiler-execution-signature.v1'


def export_signature(function, node, resolve):
    """Preserve canonical compiler declarations beyond scalar harness limits."""
    parameters = [p for p in node.get('inner', []) if p.get('kind') == 'ParmVarDecl']
    declarations = function['l2OperandBoundary']['parameterDeclarationIds']
    if len(parameters) != len(declarations):
        raise ValueError('EXECUTION_SIGNATURE_PARAMETER_PARTITION_MISMATCH')
    rows = []
    for index, (parameter, declaration) in enumerate(zip(parameters, declarations)):
        typ = parameter.get('type', {})
        rows.append({'parameterIndex': index, 'declarationIdentity': declaration,
            'spelling': typ.get('qualType', ''),
            'canonicalType': resolve(typ.get('desugaredQualType') or typ.get('qualType', ''))})
    body = {'schemaVersion': SIGNATURE, 'functionIdentity': function['functionId'],
        'sourceDigest': function['sourceDigest'], 'parameters': rows,
        'resultType': resolve(function['returnType']), 'variadic': node.get('variadic', False),
        'scope': 'compiler-declarations-not-machine-ABI-or-legal-input-domain'}
    return dict(body, signatureIdentity=identity(body))


def plan(function, fragment_id):
    """Specific missing contracts, bound to actual signature/fragment subjects.

    A request is not a receipt and never changes original harness admission.
    Pointer classification uses the existing finite compiler type grammar, not
    project/function names, and supplies no guessed size, alias or effect fact.
    """
    from .automatic_batch_cli import _INTEGER_TYPE, _INTEGER_POINTER_TYPE
    signature = function.get('compilerExecutionSignature')
    requests = []
    def need(code, subject):
        requests.append({'reasonCode': code, 'subject': subject})
    def valid_signature(value):
        if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'functionIdentity',
                'sourceDigest', 'parameters', 'resultType', 'variadic', 'scope', 'signatureIdentity'}
                or type(value.get('variadic')) is not bool
                or not isinstance(value.get('resultType'), str) or not value['resultType']
                or value.get('scope') != 'compiler-declarations-not-machine-ABI-or-legal-input-domain'):
            return False
        rows = value['parameters']; arity = function.get('arity')
        declarations = (function.get('l2OperandBoundary') or {}).get('parameterDeclarationIds')
        spellings = function.get('parameterTypes')
        if (type(arity) is not int or not isinstance(rows, list) or len(rows) != arity
                or not isinstance(declarations, list) or len(declarations) != arity
                or not isinstance(spellings, list) or len(spellings) != arity):
            return False
        return all(isinstance(row, dict) and set(row) == {'parameterIndex',
            'declarationIdentity', 'spelling', 'canonicalType'}
            and type(row['parameterIndex']) is int and row['parameterIndex'] == index
            and row['declarationIdentity'] == declarations[index]
            and row['spelling'] == spellings[index]
            and isinstance(row['canonicalType'], str) and bool(row['canonicalType'])
            for index, row in enumerate(rows))
    if (not valid_signature(signature) or signature.get('schemaVersion') != SIGNATURE
            or signature.get('signatureIdentity') != identity({k:v for k,v in signature.items() if k != 'signatureIdentity'})
            or signature.get('functionIdentity') != function.get('functionId')
            or signature.get('sourceDigest') != function.get('sourceDigest')):
        need('COMPILER_EXECUTION_SIGNATURE_REQUIRED', {'functionIdentity': function.get('functionId')})
        signature = None
    else:
        for parameter in signature['parameters']:
            typ = parameter['canonicalType']
            subject = {'parameterIndex': parameter['parameterIndex'],
                'declarationIdentity': parameter['declarationIdentity'], 'canonicalType': typ}
            if not parameter['declarationIdentity']:
                need('CALL_ARGUMENT_DECLARATION_BINDING_REQUIRED', subject)
            if _INTEGER_POINTER_TYPE.fullmatch(typ):
                need('POINTER_OBJECT_BOUNDS_INITIALIZATION_LIFETIME_ALIAS_AND_EFFECTS_REQUIRED', subject)
            elif not _INTEGER_TYPE.fullmatch(typ):
                need('CALL_ARGUMENT_TYPE_CONTRACT_REQUIRED', subject)
        if signature['variadic']:
            need('VARIADIC_CALL_CONTRACT_REQUIRED', {'functionIdentity': function['functionId']})
        if signature['resultType'] == 'void':
            need('FRAGMENT_VALUE_AND_EFFECT_OBSERVATION_REQUIRED', {'fragmentId': fragment_id})
    if function.get('compilerHarnessSignatureSupported') is not True:
        need('ORIGINAL_PROJECT_ENTRY_ARGUMENT_AND_OBSERVATION_BINDING_REQUIRED',
             {'functionIdentity': function.get('functionId'), 'arity': function.get('arity')})
    need('CANONICAL_INSTANCE_EXECUTION_EVENT_BINDING_REQUIRED', {'fragmentId': fragment_id})
    body = {'schemaVersion': 'riscv2x86.l2-execution-requirements.v1',
        'functionIdentity': function.get('functionId'), 'fragmentId': fragment_id,
        'compilerSignature': signature, 'requests': requests,
        'scope': 'missing-contract-plan-not-harness-admission-or-L2-authority',
        'executionAuthorityGranted': False}
    return dict(body, planIdentity=identity(body))
