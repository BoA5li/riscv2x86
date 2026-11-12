"""Finite inspection-level constant initializer proofs via the integer core.

These establish an expression's value when evaluated, not object existence,
native compiler equivalence, lifetime, bounds, aliases or input legality.
"""
from .native_integer_contracts import term, integer_type
from .project_build_records import identity


def constant_value(expression):
    if expression['op']=='constant':return expression['value']
    if expression['op']=='integer-conversion':
        value=constant_value(expression['argument']);typ=expression['type']
        if typ['signed']:
            if not -(1<<(typ['bits']-1))<=value<(1<<(typ['bits']-1)):
                raise ValueError('INITIALIZER_SIGNED_CONVERSION_CONTRACT_REQUIRED')
            return value
        return value % (1<<typ['bits'])
    raise ValueError('INITIALIZER_CONSTANT_OPERATION_NOT_MODELED')


def derive(graph, model):
    rows=[]
    def no_reference(_):raise ValueError('INITIALIZER_RUNTIME_DECLARATION_VALUE_REQUIRED')
    for obj in graph['objectDeclarations']:
        body={'objectEvidenceIdentity':obj['objectEvidenceIdentity'],
              'inspectionTypedConstantInitializerVerified':False,'normalizedTerm':None,'value':None,
              'nativeInitializationSemanticsVerified':False,'runtimeObjectIdentityVerified':False}
        try:
            if not model or model.get('__CHAR_BIT__')!='8':raise ValueError('INITIALIZER_DATA_MODEL_REQUIRED')
            if len(obj['initializerAst'])!=1:raise ValueError('EXPLICIT_SINGLE_INITIALIZER_REQUIRED')
            expression=term(obj['initializerAst'][0],model,no_reference)
            if integer_type({'type':obj['type']},model)!=expression['type']:
                raise ValueError('INITIALIZER_OBJECT_TYPE_RELATION_REQUIRED')
            value=constant_value(expression)
            body.update(inspectionTypedConstantInitializerVerified=True,normalizedTerm=expression,value=value,reasonCodes=[])
        except (ValueError,KeyError,TypeError) as exc:
            body['reasonCodes']=[str(exc)]
        rows.append(dict(body,initializerEvidenceIdentity=identity(body)))
    return rows
