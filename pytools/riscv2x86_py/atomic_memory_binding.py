"""Compiler/decoder-owned association of GNU memory contents and address carrier."""
from collections.abc import Mapping
from hashlib import sha256
import json
import re

SCHEMA='riscv2x86.atomic-memory-access-binding.v1'
FIELDS={'schemaVersion','fragmentId','sourceDigest','compilerAuthorityIdentity',
    'memoryOperandIndex','addressOperandIndex','memoryExpressionIdentity',
    'evaluationBindingIdentity','addressValueNodeIdentity','memoryAddressValueNodeIdentity',
    'memoryObjectIdentity','offsetBytes','widthBits','access','relationKind',
    'authorityIdentity','readEffectIdentity','writeEffectIdentity','joinPayload','bindingIdentity'}


def identity(payload):
    return 'sha256:'+sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


class AtomicMemoryBindingError(ValueError):
    def __init__(self,code):
        self.reason_code=code
        super().__init__(code)


def validate_binding(binding):
    if not isinstance(binding,Mapping) or set(binding)!=FIELDS or binding.get('schemaVersion')!=SCHEMA:
        raise AtomicMemoryBindingError('L2_ATOMIC_MEMORY_BINDING_SCHEMA_INVALID')
    if binding['bindingIdentity']!=identity({k:v for k,v in binding.items() if k!='bindingIdentity'}):
        raise AtomicMemoryBindingError('L2_ATOMIC_MEMORY_BINDING_IDENTITY_MISMATCH')
    for k in ('memoryOperandIndex','addressOperandIndex'):
        if type(binding[k]) is not int or binding[k]<0:
            raise AtomicMemoryBindingError('L2_ATOMIC_MEMORY_BINDING_OPERAND_INVALID')
    if (type(binding['widthBits']) is not int or binding['widthBits'] not in {32,64}
            or type(binding['offsetBytes']) is not int or binding['offsetBytes']!=0
            or binding['access']!='read_write' or binding['relationKind']!='exact_dereference_of_carrier'):
        raise AtomicMemoryBindingError('L2_ATOMIC_MEMORY_BINDING_ACCESS_INVALID')
    for k in ('sourceDigest','compilerAuthorityIdentity','memoryExpressionIdentity',
              'evaluationBindingIdentity','addressValueNodeIdentity','memoryAddressValueNodeIdentity','authorityIdentity'):
        if not isinstance(binding[k],str) or re.fullmatch(r'sha256:[0-9a-f]{64}',binding[k]) is None:
            raise AtomicMemoryBindingError('L2_ATOMIC_MEMORY_BINDING_IDENTITY_INVALID')
    if (not isinstance(binding['fragmentId'],str) or not binding['fragmentId']
            or not isinstance(binding['memoryObjectIdentity'],str) or not binding['memoryObjectIdentity']
            or binding['readEffectIdentity']!=binding['authorityIdentity']+':read'
            or binding['writeEffectIdentity']!=binding['authorityIdentity']+':write'):
        raise AtomicMemoryBindingError('L2_ATOMIC_MEMORY_BINDING_EFFECT_INVALID')
    join=binding['joinPayload']
    bare={k:v for k,v in binding.items() if k not in
        {'authorityIdentity','readEffectIdentity','writeEffectIdentity','joinPayload','bindingIdentity'}}
    if (not isinstance(join,Mapping) or join.get('schemaVersion')!='riscv2x86.atomic-compiler-decoder-join.v2'
            or identity(join)!=binding['authorityIdentity']
            or bare not in join.get('expressionMemoryAccessBindings',[])):
        raise AtomicMemoryBindingError('L2_ATOMIC_MEMORY_BINDING_JOIN_MISMATCH')
    return binding


def model_binding_reason(item, operands, atom, fragment_id):
    """Validate the already-produced relation against every model participant."""
    address=getattr(item,'address',None)
    binding=getattr(address,'memory_access_binding',None)
    if binding is None and item.source_operand_index==getattr(atom,'address_operand_index',None):
        # Explicit legacy memory-only projection contract. Do not manufacture
        # a new association or relabel its old identity. Separate carriers
        # cannot use this compatibility path.
        projection=getattr(address,'address_projection',None)
        if (getattr(atom,'complete',False) and isinstance(projection,Mapping)
                and projection==getattr(atom,'address_projection',None)
                and projection.get('operandIndex')==item.source_operand_index
                and projection.get('projectionIdentity')==identity({k:v for k,v in projection.items() if k!='projectionIdentity'})
                and getattr(address,'atomic_authority_identity',None)
                and address.atomic_authority_identity==atom.authority_identity
                and address.memory_object_identity==atom.memory_object_identity
                and address.provenance_known):
            return ''
    try:validate_binding(binding)
    except AtomicMemoryBindingError as exc:return exc.reason_code
    if binding['fragmentId']!=fragment_id:return 'L2_ATOMIC_MEMORY_BINDING_FRAGMENT_MISMATCH'
    indices=[x.source_operand_index for x in operands]
    if len(set(indices))!=len(indices):return 'L2_ATOMIC_MEMORY_BINDING_OPERAND_AMBIGUOUS'
    carrier=next((x for x in operands if x.source_operand_index==binding['addressOperandIndex']),None)
    if (binding['memoryOperandIndex']!=item.source_operand_index or carrier is None
            or binding['addressOperandIndex']!=atom.address_operand_index):
        return 'L2_ATOMIC_MEMORY_ADDRESS_CARRIER_MISMATCH'
    if (getattr(item.access,'value','')!=binding['access']
            or item.width_bits!=binding['widthBits'] or atom.width_bits!=binding['widthBits']):
        return 'L2_ATOMIC_MEMORY_ACCESS_WIDTH_MISMATCH'
    target=getattr(carrier,'address',None)
    if target is None or not address.provenance_known or not target.provenance_known:
        return 'L2_ATOMIC_MEMORY_ADDRESS_AUTHORITY_MISSING'
    if not atom.complete:return 'L2_ATOMIC_MEMORY_OPERATION_INCOMPLETE'
    if any(x!=binding['memoryObjectIdentity'] for x in
            (address.memory_object_identity,target.memory_object_identity,atom.memory_object_identity)):
        return 'L2_ATOMIC_MEMORY_OBJECT_MISMATCH'
    if address.byte_offset!=binding['offsetBytes'] or target.byte_offset!=binding['offsetBytes']:
        return 'L2_ATOMIC_MEMORY_ACCESS_RANGE_MISMATCH'
    if any(x!=binding['authorityIdentity'] for x in
            (address.atomic_authority_identity,target.atomic_authority_identity,atom.authority_identity)):
        return 'L2_ATOMIC_MEMORY_AUTHORITY_MISMATCH'
    if (address.address_space_identity!=target.address_space_identity
            or address.address_space_identity!=atom.address_space_identity):
        return 'L2_ATOMIC_MEMORY_ADDRESS_SPACE_MISMATCH'
    if (address.atomic_read_effect_identity!=binding['readEffectIdentity']
            or address.atomic_write_effect_identity!=binding['writeEffectIdentity']
            or target.atomic_read_effect_identity!=binding['readEffectIdentity']
            or target.atomic_write_effect_identity!=binding['writeEffectIdentity']):
        return 'L2_ATOMIC_MEMORY_EFFECT_BINDING_MISMATCH'
    if carrier is item:
        projection=address.address_projection
        if (not isinstance(projection,Mapping) or projection!=atom.address_projection
                or projection.get('projectionIdentity')!=identity({k:v for k,v in projection.items() if k!='projectionIdentity'})
                or projection.get('operandIndex')!=item.source_operand_index):
            return 'L2_ATOMIC_MEMORY_ADDRESS_PROJECTION_MISMATCH'
    elif getattr(carrier.access,'value','')!='address' or getattr(carrier.kind,'value','')!='address':
        return 'L2_ATOMIC_MEMORY_ADDRESS_CARRIER_MISMATCH'
    return ''


def model_binding_diagnostics(fragment_id, model):
    operands=getattr(getattr(model,'operands',None),'operands',())
    atom=getattr(model,'atomic',None)
    if not getattr(atom,'present',False):return []
    return [{'operandIndex':x.source_operand_index,'reasonCode':reason}
        for x in operands if getattr(x.kind,'value','')=='memory'
        for reason in [model_binding_reason(x,operands,atom,fragment_id)] if reason]
