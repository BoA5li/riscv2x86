"""Compiler-owned atomic call roles, independent of GNU operand positions.

This register-argument domain has one unsigned integer object and 2--4
parameters. A type signature is not effect authority: callers must still prove
and replay the sole-region function scope and all output uses.
"""
from .compiler_memory_signature import type_fact, SCHEMA
from .l3_trace_support import identity, require_json_document, require_json_match


def bind(function, atom, sidecar):
    signature=function.get('compilerMemoryCallSignature')
    require_json_document(signature,'ATOMIC_CALL_SIGNATURE_JSON_INVALID')
    fields={'schemaVersion','functionIdentity','sourceDigest','targetABI','parameters','result','factsIdentity'}
    if (not isinstance(signature,dict) or set(signature)!=fields or signature['schemaVersion']!=SCHEMA
            or signature['targetABI']!='linux-lp64'
            or signature['functionIdentity']!=function['functionId']
            or signature['sourceDigest']!=function['sourceDigest']
            or signature['factsIdentity']!=identity({k:v for k,v in signature.items() if k!='factsIdentity'})):
        raise ValueError('ATOMIC_CALL_COMPILER_SIGNATURE_REQUIRED')
    params=signature['parameters'];decls=function['l2OperandBoundary']['parameterDeclarationIds']
    if (type(function.get('arity')) is not int or not 2<=function['arity']<=4
            or not isinstance(params,list) or len(params)!=function['arity']
            or len(function['parameterTypes'])!=len(params) or len(decls)!=len(params)
            or len(set(decls))!=len(decls) or any(not d for d in decls)):
        raise ValueError('ATOMIC_CALL_PARAMETER_DOMAIN_UNSUPPORTED')
    for p,d in zip(params,decls):
        if not isinstance(p,dict) or p.get('declarationIdentity')!=d:
            raise ValueError('ATOMIC_CALL_DECLARATION_MISMATCH')
        require_json_match(type_fact(p.get('cType','')),{k:v for k,v in p.items() if k!='declarationIdentity'},
                           'ATOMIC_CALL_PARAMETER_TYPE_MISMATCH')
    result=signature['result']
    if not isinstance(result,dict):raise ValueError('ATOMIC_CALL_RESULT_TYPE_REQUIRED')
    require_json_match(type_fact(result.get('cType','')),result,'ATOMIC_CALL_RESULT_TYPE_MISMATCH')
    operands={o.operand_index:o for o in sidecar.operands}
    address=operands[atom['address_operand_index']];value=operands[atom['value_operand_index']]
    projection=atom.get('address_projection')
    base=projection['baseDeclarationIdentity'] if projection else address.declaration_id
    if base not in decls or value.parameter_index is None:
        raise ValueError('ATOMIC_CALL_ROLE_BINDING_REQUIRED')
    pointer=decls.index(base);input_index=value.parameter_index
    if (type(input_index) is not int or not 0<=input_index<len(params) or input_index==pointer
            or decls[input_index]!=value.declaration_id
            or function.get('pointerParameters')!=[pointer]):
        raise ValueError('ATOMIC_CALL_ROLE_BINDING_REQUIRED')
    obj=params[pointer]
    if (obj['kind']!='pointer' or obj.get('pointeeQualifiers')
            or obj['pointee']['kind']!='integer' or obj['pointee']['signed'] is not False
            or obj['pointee']['widthBits']!=atom['width_bits']):
        raise ValueError('ATOMIC_CALL_OBJECT_TYPE_UNSUPPORTED')
    for i,p in enumerate(params):
        if i==pointer:continue
        if (p['kind']!='integer' or p['signed'] is not False or p['widthBits'] not in (32,64)):
            raise ValueError('ATOMIC_CALL_INTEGER_TYPE_UNSUPPORTED')
    if params[input_index]['widthBits']!=value.width_bits or value.signedness!='unsigned':
        raise ValueError('ATOMIC_CALL_INPUT_CARRIER_MISMATCH')
    # Compiler canonical spelling and original spelling must denote the same
    # supported scalar types; aliases are resolved by the original AST join.
    from .automatic_batch_cli import _integer_type
    for i,(spelling,p) in enumerate(zip(function['parameterTypes'],params)):
        if i==pointer:
            text=spelling.strip()
            if not text.endswith('*') or _integer_type(text[:-1].strip())!=(obj['pointee']['widthBits'],'unsigned'):
                raise ValueError('ATOMIC_CALL_SOURCE_TYPE_MISMATCH')
        elif _integer_type(spelling)!=(p['widthBits'],'unsigned'):
            raise ValueError('ATOMIC_CALL_SOURCE_TYPE_MISMATCH')
    ret=function['returnType']
    if result['kind']=='void':
        if ret!='void':raise ValueError('ATOMIC_CALL_RESULT_TYPE_MISMATCH')
    elif (result['kind']!='integer' or result['signed'] is not False
          or result['widthBits'] not in (32,64) or _integer_type(ret)!=(result['widthBits'],'unsigned')):
        raise ValueError('ATOMIC_CALL_RESULT_TYPE_MISMATCH')
    body={'schemaVersion':'riscv2x86.atomic-call-contract.v1','functionIdentity':function['functionId'],
          'sourceDigest':function['sourceDigest'],'compilerSignatureIdentity':signature['factsIdentity'],
          'abi':'linux-lp64-register-arguments','parameters':params,'result':result,
          'pointerParameter':pointer,'valueParameter':input_index}
    return dict(body,contractIdentity=identity(body))


def argument_values(contract, sample, value):
    """Declared finite boundary witnesses, not an exhaustive input proof."""
    seeds=(0,1,0xffffffffffffffff,0x7fffffff,0x80000000,0xffffffff,
           0x7fffffffffffffff,0x8000000000000000)
    result=[]
    for i,p in enumerate(contract['parameters']):
        if i==contract['pointerParameter']:result.append(None)
        else:
            v=value if i==contract['valueParameter'] else seeds[(sample+i+3)%len(seeds)]
            result.append(f'{v&((1<<p["widthBits"])-1):016x}')
    return result
