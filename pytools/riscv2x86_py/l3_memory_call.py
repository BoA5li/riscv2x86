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
    if (p['kind']!='pointer' or p.get('pointeeQualifiers') or p['pointee']['signed'] or p['pointee']['widthBits']!=spec['width']*8
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


def bind_load(function, finding, spec):
    """One typed pointer, a compiler-bound scalar result, actual IR projection."""
    call=function.get('compilerMemoryCallSignature')
    require_json_document(call,'L3_MEMORY_LOAD_CALL_JSON_INVALID')
    if (not isinstance(call,dict) or set(call)!={'schemaVersion','functionIdentity','sourceDigest','targetABI','parameters','result','factsIdentity'}
            or call['schemaVersion']!=SCHEMA or call['targetABI']!='linux-lp64'
            or call['factsIdentity']!=compiler_identity({k:v for k,v in call.items() if k!='factsIdentity'})
            or call['functionIdentity']!=function['functionId'] or call['sourceDigest']!=function['sourceDigest']
            or function.get('arity')!=1 or len(call['parameters'])!=1):
        raise ValueError('L3_MEMORY_LOAD_CALL_SIGNATURE_INVALID')
    pointer=call['parameters'][0];result=call['result']
    require_json_match(type_fact(pointer['cType']),{k:v for k,v in pointer.items() if k!='declarationIdentity'},'L3_MEMORY_LOAD_POINTER_TYPE_INVALID')
    require_json_match(type_fact(result['cType']),result,'L3_MEMORY_LOAD_RESULT_TYPE_INVALID')
    if pointer['kind']!='pointer' or pointer['pointee']['widthBits']!=spec['width']*8 or result['kind']!='integer':
        raise ValueError('L3_MEMORY_LOAD_TYPE_DOMAIN_UNSUPPORTED')
    from .l2_memory_object import memory_proof_facts_from_dict
    a=finding['approvalArtifact'];facts=memory_proof_facts_from_dict(a['l2MemoryProofFacts'])
    if facts.access_kind!='load' or not facts.complete or facts.fragment_id!=finding['fragment']['id'] or facts.width_bytes!=spec['width']:
        raise ValueError('L3_MEMORY_LOAD_PROOF_BINDING_INVALID')
    operands={o['operandIndex']:o for o in a['l2AuthoritySidecar']['operands']}
    address=operands[facts.address_operand_index];value=operands[facts.value_operand_index]
    boundary=function['l2OperandBoundary']
    if (address['parameterIndex']!=0 or type(address['parameterIndex']) is not int
            or pointer['declarationIdentity']!=address['declarationId']
            or boundary['parameterDeclarationIds']!=[pointer['declarationIdentity']]
            or boundary.get('returnDeclarationId')!=value['declarationId']
            or value['typeKind']!='integer' or value['accessMode']!='output'
            or value['signedness'] not in {'signed','unsigned'}
            or not facts.matches_value_width(value['widthBits'])
            or result['widthBits']<value['widthBits']):
        raise ValueError('L3_MEMORY_LOAD_VALUE_BINDING_INVALID')
    scope=function.get('compilerAtomicFunctionScope') or {}
    key=finding['fragment']['compilerFragmentAuthority']['fragmentBindingKey']
    if (scope.get('scope')!='single_asm_no_other_memory_or_control_effects'
            or scope.get('scopeIdentity')!=compiler_identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
            or scope.get('sourceDigest')!=call['sourceDigest'] or scope.get('functionIdentity')!=call['functionIdentity']
            or (scope.get('asmBegin'),scope.get('asmEnd'))!=(key['beginOffset'],key['endOffset'])):
        raise ValueError('L3_MEMORY_LOAD_SHELL_AUTHORITY_REQUIRED')
    projection=facts.value_projection or 'identity'
    body={'schemaVersion':'riscv2x86.l3-memory-load-call.v1','compilerSignature':call,
        'pointerParameter':0,'widthBytes':spec['width'],'outputWidthBits':value['widthBits'],
        'outputSigned':value['signedness']=='signed','valueProjection':projection,
        'proofFactsIdentity':facts.facts_identity,'scopeIdentity':scope['scopeIdentity']}
    return validate_load_call(dict(body,callIdentity=identity(body)))


def validate_load_call(call):
    require_json_document(call,'L3_MEMORY_LOAD_CALL_JSON_INVALID')
    fields={'schemaVersion','compilerSignature','pointerParameter','widthBytes','outputWidthBits','outputSigned',
            'valueProjection','proofFactsIdentity','scopeIdentity','callIdentity'}
    if (not isinstance(call,dict) or set(call)!=fields or call['schemaVersion']!='riscv2x86.l3-memory-load-call.v1'
            or call['callIdentity']!=identity({k:v for k,v in call.items() if k!='callIdentity'})
            or type(call['pointerParameter']) is not int or call['pointerParameter']!=0
            or type(call['widthBytes']) is not int or call['widthBytes'] not in (1,2,4,8)
            or type(call['outputWidthBits']) is not int or call['outputWidthBits'] not in (8,16,32,64)
            or type(call['outputSigned']) is not bool
            or not ((call['valueProjection']=='identity' and call['widthBytes']*8==call['outputWidthBits'])
                or (call['valueProjection'] in {'sign_extend','zero_extend'} and call['widthBytes']*8<call['outputWidthBits']))):
        raise ValueError('L3_MEMORY_LOAD_CALL_INVALID')
    signature=call['compilerSignature']
    if (not isinstance(signature,dict) or set(signature)!={'schemaVersion','functionIdentity','sourceDigest','targetABI','parameters','result','factsIdentity'}
            or signature['schemaVersion']!=SCHEMA or signature['targetABI']!='linux-lp64'
            or signature['factsIdentity']!=compiler_identity({k:v for k,v in signature.items() if k!='factsIdentity'})
            or not isinstance(signature['parameters'],list) or len(signature['parameters'])!=1):
        raise ValueError('L3_MEMORY_LOAD_CALL_SIGNATURE_INVALID')
    p=signature['parameters'][0];r=signature['result']
    require_json_match(type_fact(p['cType']),{k:v for k,v in p.items() if k!='declarationIdentity'},'L3_MEMORY_LOAD_CALL_POINTER_INVALID')
    require_json_match(type_fact(r['cType']),r,'L3_MEMORY_LOAD_CALL_RESULT_INVALID')
    if p['kind']!='pointer' or p['pointee']['widthBits']!=call['widthBytes']*8 or r['kind']!='integer' or r['widthBits']<call['outputWidthBits']:
        raise ValueError('L3_MEMORY_LOAD_CALL_TYPE_INVALID')
    return call


def load_initial_bytes(spec,sample):
    size=((spec['size']+spec['width']-1)//spec['width'])*spec['width']
    data=bytearray((0x31+17*i+sample)&255 for i in range(size))
    bits=spec['width']*8
    raw=(0,(1<<(bits-1))-1,1<<(bits-1),(1<<bits)-1)[sample%4]
    data[spec['offset']:spec['offset']+spec['width']]=raw.to_bytes(spec['width'],'little')
    return bytes(data)


def load_value(raw,call):
    """Reference bit-vector projection followed by the declared C conversion."""
    validate_load_call(call)
    bits=call['widthBytes']*8;out=call['outputWidthBits'];value=raw&((1<<bits)-1)
    if call['valueProjection']=='sign_extend' and value&(1<<(bits-1)):
        value-=1<<bits
    value&=(1<<out)-1
    if call['outputSigned'] and value&(1<<(out-1)):value-=1<<out
    result=call['compilerSignature']['result'];width=result['widthBits']
    value&=(1<<width)-1
    if result['signed'] and value&(1<<(width-1)):value-=1<<width
    return value&((1<<64)-1)
