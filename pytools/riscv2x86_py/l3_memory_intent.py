"""Proof-consuming bounded ordinary-memory intent producer, not mnemonic classification."""
from .l3_trace_support import emit_json
import argparse
import json
from pathlib import Path
import sys

from .l3_intent_requirements import _hash, INTENT_SCHEMA, INTENT_SCHEMA_V2, parse_l3_intent_profile
from .l3_trace_support import identity
from .l3_cache_model import validate as cache_validate

CAPABILITY = 'qemu-compiler-region-memory-trace-v1'
LIMITATIONS = sorted(['compiler-loader-harness-and-outside-fragment-accesses-not-compared',
    'physical-cache-timing-prediction-and-speculation-not-claimed',
    'single-thread-private-valid-object-domain-only'])


def _range_covers(ranges, offset, width, size):
    """Validate effect ranges, then check one range covers this access.

    These are fragment access obligations, not page permissions or authority
    for the harness's outside-fragment initialization/post-state observations.
    """
    if not isinstance(ranges, list):
        raise ValueError('L3_MEMORY_OBJECT_DOMAIN_INCOMPLETE')
    pairs = []
    for item in ranges:
        if (not isinstance(item, list) or len(item) != 2
                or any(type(value) is not int for value in item)
                or not 0 <= item[0] < item[1] <= size):
            raise ValueError('L3_MEMORY_OBJECT_DOMAIN_INCOMPLETE')
        pairs.append(tuple(item))
    if pairs != sorted(set(pairs)):
        raise ValueError('L3_MEMORY_OBJECT_DOMAIN_INCOMPLETE')
    return any(start <= offset and offset + width <= end for start, end in pairs)


def memory_spec(finding, *, joint_region=False):
    approval = finding.get('approvalArtifact') or {}
    if (approval.get('proofStatus') != 'approved' or approval.get('architectureSemanticsPreserved') is not True or
            approval.get('shellSemanticsPreserved') is not True or finding.get('translationOutcome') not in ('emitted','strengthened')):
        raise ValueError('L3_MEMORY_ARCHITECTURAL_APPROVAL_REQUIRED')
    facts = approval.get('l2MemoryProofFacts') or {}
    authority = approval.get('l2AuthoritySidecar') or {}
    objects = authority.get('memoryObjects',[]); effects = authority.get('sourceEffects',[])
    relations = authority.get('approvedEffectRelations',[])
    fragment = finding.get('fragment') or {}; boundary = approval.get('l2FragmentOperandBoundary') or {}
    if facts.get('accessKind') not in {'load','store'}:
        raise ValueError('L3_MEMORY_ORDINARY_ACCESS_KIND_UNSUPPORTED')
    if not authority.get('complete') or not facts.get('complete') or not boundary.get('complete'):
        raise ValueError('L3_MEMORY_AUTHORITY_FACTS_INCOMPLETE')
    if any(x.get('fragmentId')!=fragment.get('id') for x in (facts,authority,boundary)):
        raise ValueError('L3_MEMORY_FRAGMENT_BINDING_MISMATCH')
    if facts.get('nonAtomic') is not True:
        raise ValueError('L3_MEMORY_NONATOMIC_DOMAIN_REQUIRED')
    if len(objects)!=1 or len(effects)!=1 or len(relations)!=1:
        raise ValueError('L3_MEMORY_SINGLE_OBJECT_EFFECT_RELATION_REQUIRED')
    if (effects[0].get('effectKind')!=('ReadMemory' if facts['accessKind']=='load' else 'WriteMemory')
            or effects[0].get('complete') is not True
            or relations[0].get('sourceEffectId')!=effects[0].get('effectId')
            or relations[0].get('relationKind')!='exact' or relations[0].get('complete') is not True):
        raise ValueError('L3_MEMORY_EXACT_EFFECT_RELATION_REQUIRED')
    if authority.get('runtimeContracts') or authority.get('ignoredState'):
        raise ValueError('L3_MEMORY_RUNTIME_OR_IGNORED_STATE_UNSUPPORTED')
    obj=objects[0]; width=facts.get('widthBytes'); offset=facts.get('byteOffset'); size=obj.get('sizeBytes'); alignment=obj.get('minimumAlignment')
    if (type(width) is not int or width not in (1,2,4,8) or type(offset) is not int or offset<0 or
            type(size) is not int or not offset+width<=size<=65536 or type(alignment) is not int or
            alignment<width or alignment>64 or alignment & (alignment-1) or offset%width or obj.get('complete') is not True or
            obj.get('originKind')!='function_argument' or obj.get('lifetimeScope')!='function_call'):
        raise ValueError('L3_MEMORY_OBJECT_DOMAIN_INCOMPLETE')
    readable = _range_covers(obj.get('readableRanges', []), offset, width, size)
    writable = _range_covers(obj.get('writableRanges', []), offset, width, size)
    # L2 deliberately emits no read range for a pure store. Preserve that
    # producer contract: only the actual access kind determines coverage.
    if (facts['accessKind']=='load' and (obj.get('writableRanges') or not readable)
            or facts['accessKind']=='store' and not writable):
        raise ValueError('L3_MEMORY_OBJECT_DOMAIN_INCOMPLETE')
    operands=authority.get('operands',[])
    address=[x for x in operands if x.get('operandIndex')==facts.get('addressOperandIndex')]
    if (len(address)!=1 or address[0].get('typeKind')!='pointer' or type(address[0].get('parameterIndex')) is not int or address[0]['parameterIndex']<0 or
            address[0].get('accessMode')!='address' or not boundary.get('programId')):
        raise ValueError('L3_MEMORY_POINTER_PARAMETER_BINDING_INCOMPLETE')
    if not joint_region and facts['accessKind']=='load' and address[0]['parameterIndex']!=0:
        raise ValueError('L3_MEMORY_POINTER_PARAMETER_BINDING_INCOMPLETE')
    if facts['accessKind']=='store':
        values=[x for x in operands if x.get('operandIndex')==facts.get('valueOperandIndex')]
        if (len(values)!=1 or values[0].get('typeKind')!='integer'
                or (not joint_region and (type(values[0].get('parameterIndex')) is not int or values[0]['parameterIndex']<0
                or values[0]['parameterIndex']==address[0]['parameterIndex'])) or values[0].get('accessMode')!='input'):
            raise ValueError('L3_MEMORY_POINTER_PARAMETER_BINDING_INCOMPLETE')
    return {'fragmentId':fragment['id'],'programId':boundary['programId'], 'objectId':obj['objectId'],
            'sourceEffectId':effects[0]['effectId'], 'offset':offset,'width':width,'size':size,
            'alignment':alignment,'access':'read' if facts['accessKind']=='load' else 'write','observationUnit':'compiler-asm-region',
            'authorityIdentity':authority['authorityIdentity']}


def produce(request, model=None):
    if request.get('schemaVersion')!='riscv2x86.l3-intent-producer-request.v1' or request.get('requestIdentity')!=_hash({k:v for k,v in request.items() if k!='requestIdentity'}):
        raise ValueError('L3_MEMORY_PRODUCER_REQUEST_INVALID')
    if model is not None: model=cache_validate(model)
    profiles=[]; dispositions=[]
    for item in request['candidates']:
        finding=item['finding']; artifact=item['translationArtifact']
        try:
            spec=memory_spec(finding)
        except ValueError as exc:
            # A bounded mechanism refusal is not a failed semantic comparison,
            # nor permission to infer that the source has no L3 obligations.
            code=str(exc)
            if code not in {'L3_MEMORY_ARCHITECTURAL_APPROVAL_REQUIRED',
                    'L3_MEMORY_ORDINARY_ACCESS_KIND_UNSUPPORTED',
                    'L3_MEMORY_AUTHORITY_FACTS_INCOMPLETE','L3_MEMORY_FRAGMENT_BINDING_MISMATCH',
                    'L3_MEMORY_NONATOMIC_DOMAIN_REQUIRED','L3_MEMORY_SINGLE_OBJECT_EFFECT_RELATION_REQUIRED',
                    'L3_MEMORY_EXACT_EFFECT_RELATION_REQUIRED','L3_MEMORY_RUNTIME_OR_IGNORED_STATE_UNSUPPORTED',
                    'L3_MEMORY_OBJECT_DOMAIN_INCOMPLETE',
                    'L3_MEMORY_POINTER_PARAMETER_BINDING_INCOMPLETE'}:
                raise
            fid=finding['fragment']['id']
            payload={'schemaVersion':INTENT_SCHEMA,'fragmentId':fid,'programId':'',
                'intentKind':'unknown','experimentClasses':[],
                'sourceIntent':'selected ordinary-memory mechanism cannot establish this intent',
                'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],
                'requiredProperties':[],'sourceCapabilities':[],'targetCapabilities':[],
                'observationBoundary':{'kind':'','identity':''},
                'notClaimedProperties':LIMITATIONS,
                'producer':{'kind':'translation-proof','producerIdentity':request['producerIdentity'],
                            'proofIdentity':artifact['proof_identity']},'complete':False}
            profile=dict(payload,profileIdentity=_hash(payload))
            profiles.append(parse_l3_intent_profile(profile).to_dict())
            decision={'schemaVersion':'riscv2x86.l3-intent-disposition.v1',
                'fragmentId':fid,'profileIdentity':profile['profileIdentity'],
                'status':'unsupported' if code in {'L3_MEMORY_ORDINARY_ACCESS_KIND_UNSUPPORTED','L3_MEMORY_NONATOMIC_DOMAIN_REQUIRED',
                    'L3_MEMORY_SINGLE_OBJECT_EFFECT_RELATION_REQUIRED','L3_MEMORY_RUNTIME_OR_IGNORED_STATE_UNSUPPORTED'} else 'prerequisites_missing',
                'reasonCodes':[code]}
            dispositions.append(dict(decision,dispositionIdentity=_hash(decision)))
            continue
        properties=[{'propertyId':'memory.fragment-access','dimension':'access_pattern','unit':'fragment'}]
        if model is not None: properties.insert(0,{'propertyId':'cache.fragment-stream-model','dimension':'cache_model','unit':'fragment'})
        limitations=LIMITATIONS + ([] if model is None else ['cache-model-is-object-relative-fragment-stream-only'])
        payload={'schemaVersion':INTENT_SCHEMA if model is None else INTENT_SCHEMA_V2,'fragmentId':spec['fragmentId'],'programId':spec['programId'],
            'intentKind':'memory_access' if model is None else 'composite',
            'experimentClasses':['memory_access'] if model is None else ['cache_model','memory_access'],
            'sourceIntent':'preserve the approved ordinary object access in the compiler asm region',
            'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],
            'requiredProperties':properties,'sourceCapabilities':[CAPABILITY],'targetCapabilities':[CAPABILITY],
            'observationBoundary':{'kind':'compiler-asm-region','identity':identity({'spec':spec,'model':model})},
            'notClaimedProperties':sorted(limitations),
            'producer':{'kind':'translation-proof','producerIdentity':request['producerIdentity'],'proofIdentity':artifact['proof_identity']},
            'complete':True}
        profile=parse_l3_intent_profile(dict(payload,profileIdentity=_hash(payload)))
        profiles.append(profile.to_dict())
    response={'schemaVersion':'riscv2x86.l3-intent-producer-response.v1','requestIdentity':request['requestIdentity'],'profiles':profiles}
    if dispositions:
        response.update(schemaVersion='riscv2x86.l3-intent-producer-response.v2',dispositions=dispositions)
    return response


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--implementation',required=True); parser.add_argument('--cache-model-file')
    parser.add_argument('--dependency',action='append',default=[])
    args=parser.parse_args()
    if Path(args.implementation).resolve()!=Path(__file__).resolve(): raise ValueError('L3_MEMORY_PRODUCER_IMPLEMENTATION_MISMATCH')
    from .l3_implementation_dependencies import implementation_paths
    required=set(implementation_paths())
    if set(map(lambda p:str(Path(p).resolve()),args.dependency))!=required: raise ValueError('L3_MEMORY_PRODUCER_DEPENDENCIES_UNPINNED')
    model=None if not args.cache_model_file else json.loads(Path(args.cache_model_file).read_text())
    emit_json(lambda: produce(json.load(sys.stdin),model))


if __name__=='__main__': main()
