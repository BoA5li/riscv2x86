"""Proof/compiler-bound unsigned ordinary-store invocation and object observation."""
from .compiler_memory_signature import SCHEMA, type_fact
from .compiler_value_flow import identity as compiler_identity
from .l3_trace_support import identity, require_json_document, require_json_match


def bind(function, finding, spec):
    call=function.get('compilerMemoryCallSignature')
    if not isinstance(call,dict):raise ValueError('L3_MEMORY_CALL_TYPE_AUTHORITY_REQUIRED')
    require_json_document(call,'L3_MEMORY_CALL_JSON_INVALID')
    if (set(call)!={'schemaVersion','functionIdentity','sourceDigest','targetABI','parameters','result','factsIdentity'}
            or call['schemaVersion']!=SCHEMA or call['targetABI']!='linux-lp64'
            or call['factsIdentity']!=compiler_identity({k:v for k,v in call.items() if k!='factsIdentity'})
            or call['functionIdentity']!=function['functionId'] or call['sourceDigest']!=function['sourceDigest']):
        raise ValueError('L3_MEMORY_CALL_TYPE_AUTHORITY_INVALID')
    params=call['parameters'];result=call['result']
    if len(params)!=2 or function['arity']!=2:raise ValueError('L3_MEMORY_CALL_ARITY_UNSUPPORTED')
    for p in params:
        require_json_match(type_fact(p['cType']),{k:v for k,v in p.items() if k!='declarationIdentity'},'L3_MEMORY_CALL_TYPE_INVALID')
    require_json_match(type_fact(result['cType']),result,'L3_MEMORY_CALL_RESULT_TYPE_INVALID')
    facts=finding['approvalArtifact']['l2MemoryProofFacts']
    authority=finding['approvalArtifact']['l2AuthoritySidecar']
    operands={o['operandIndex']:o for o in authority['operands']}
    pointer=operands[facts['addressOperandIndex']]['parameterIndex']
    value=operands[facts['valueOperandIndex']]['parameterIndex']
    if type(pointer) is not int or type(value) is not int or {pointer,value}!={0,1}:
        raise ValueError('L3_MEMORY_CALL_PARAMETER_BINDING_INVALID')
    p,v=params[pointer],params[value]
    if (p['kind']!='pointer' or p['pointee']['signed'] or p['pointee']['widthBits']!=spec['width']*8
            or v['kind']!='integer' or v['signed'] or v['widthBits']<spec['width']*8):
        raise ValueError('L3_MEMORY_CALL_STORE_TYPE_UNSUPPORTED')
    decls=function['l2OperandBoundary']['parameterDeclarationIds']
    if [p['declarationIdentity'] for p in params]!=decls:
        raise ValueError('L3_MEMORY_CALL_DECLARATION_BINDING_INVALID')
    scope=function.get('compilerStoreFunctionScope') or {}
    if (scope.get('sourceDigest')!=call['sourceDigest'] or scope.get('functionIdentity')!=call['functionIdentity']
            or scope.get('scopeIdentity')!=compiler_identity({k:v for k,v in scope.items() if k!='scopeIdentity'})):
        raise ValueError('L3_MEMORY_CALL_SHELL_AUTHORITY_REQUIRED')
    if scope.get('scope')=='single_asm_void':
        if result['kind']!='void':raise ValueError('L3_MEMORY_CALL_RETURN_BINDING_INVALID')
    elif scope.get('scope')=='single_asm_and_bound_object_return':
        index=scope.get('returnElementIndex')
        if (result['kind']!='integer' or result['signed'] or result['widthBits']<spec['width']*8
                or scope.get('returnObjectParameterIndex')!=pointer or type(index) is not int
                or index*spec['width']!=spec['offset']):
            raise ValueError('L3_MEMORY_CALL_RETURN_BINDING_INVALID')
    else:raise ValueError('L3_MEMORY_CALL_SHELL_UNSUPPORTED')
    key=finding['fragment']['compilerFragmentAuthority']['fragmentBindingKey']
    if (scope.get('asmBegin'),scope.get('asmEnd'))!=(key['beginOffset'],key['endOffset']):
        raise ValueError('L3_MEMORY_CALL_REGION_BINDING_INVALID')
    body={'schemaVersion':'riscv2x86.l3-memory-call.v1','compilerSignature':call,
        'pointerParameter':pointer,'valueParameter':value,'returnKind':result['kind'],
        'scopeIdentity':scope['scopeIdentity'],'widthBytes':spec['width']}
    return dict(body,callIdentity=identity(body))


def store_value(sample, width):
    if type(sample) is not int or sample<0 or type(width) is not int or width not in (1,2,4,8):
        raise ValueError('L3_MEMORY_STORE_SAMPLE_INVALID')
    return (0x1020304050607080+sample)&((1<<(width*8))-1)
