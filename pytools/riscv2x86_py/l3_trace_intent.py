"""Registered obligation-first dispatcher for bounded compiler-region traces."""
import argparse
import json
from pathlib import Path
import sys

from .l3_intent_requirements import _hash, parse_l3_intent_profile
from .l3_memory_intent import CAPABILITY, LIMITATIONS, produce as memory_produce
from .l3_property_obligations import analyze, check_properties
from .l3_scalar_trace import scalar_spec
from .l3_trace_support import identity


def produce(request, model=None):
    if request.get('schemaVersion')!='riscv2x86.l3-intent-producer-request.v1' or request.get('requestIdentity')!=_hash({k:v for k,v in request.items() if k!='requestIdentity'}):
        raise ValueError('L3_TRACE_PRODUCER_REQUEST_INVALID')
    profiles=[]; decisions=[]
    for item in request['candidates']:
        f=item['finding']; artifact=item['translationArtifact']; obligation=None
        try:
            obligation=analyze(f,item.get('compilerFunctions'))
            if (obligation['proofIdentity']!=artifact['proof_identity'] or
                    obligation['approvedTargetRelationIdentity']!=artifact['effect_relation_set_identity']):
                raise ValueError('L3_OBLIGATION_ARTIFACT_MISMATCH')
            if any(p['dimension']!='access_pattern' for p in obligation['requiredProperties']):
                raise ValueError('L3_TRACE_REQUIRED_MECHANISM_UNAVAILABLE:'+','.join(
                    p['dimension'] for p in obligation['requiredProperties'] if p['dimension']!='access_pattern'))
            if f['l2SemanticProfile']['patternKind']=='scalar':
                spec=scalar_spec(f)
                if model is not None:raise ValueError('L3_SCALAR_OBJECT_RELATIVE_CACHE_MODEL_UNSUPPORTED')
                payload={'schemaVersion':'riscv2x86.l3-intent-profile.v1','fragmentId':spec['fragmentId'],
                    'programId':spec['programId'],'intentKind':'memory_access','experimentClasses':['memory_access'],
                    'sourceIntent':'observe successful data-access absence in an executed register-scalar compiler region',
                    'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],
                    'requiredProperties':obligation['requiredProperties'],'sourceCapabilities':[CAPABILITY],
                    'targetCapabilities':[CAPABILITY],'observationBoundary':{'kind':'compiler-asm-region',
                        'identity':identity({'spec':spec,'model':None,'obligations':obligation})},
                    'notClaimedProperties':LIMITATIONS,
                    'producer':{'kind':'translation-proof','producerIdentity':request['producerIdentity'],
                        'proofIdentity':artifact['proof_identity']},'complete':True}
                profiles.append(parse_l3_intent_profile(dict(payload,profileIdentity=_hash(payload))).to_dict())
            else:
                one=dict(request,candidates=[item]);one['requestIdentity']=_hash({k:v for k,v in one.items() if k!='requestIdentity'})
                result=memory_produce(one,model)
                profile=result['profiles'][0]
                check_properties(obligation,profile['requiredProperties'])
                if not profile['complete']:raise ValueError('L3_TRACE_REQUIRED_MECHANISM_UNAVAILABLE')
                profiles.append(profile)
        except (ValueError,KeyError,TypeError) as exc:
            # Keep known obligations even when no observer covers them.
            props=[] if obligation is None else obligation['requiredProperties']
            payload={'schemaVersion':'riscv2x86.l3-intent-profile.v1','fragmentId':f['fragment']['id'],
                'programId':'' if obligation is None else obligation['programId'],'intentKind':'unknown',
                'experimentClasses':sorted({{'access_pattern':'memory_access','control_flow':'control_flow','synchronization':'synchronization'}[p['dimension']] for p in props}),
                'sourceIntent':'bounded compiler-region policy; unresolved facts or mechanism coverage',
                'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],'requiredProperties':props,
                'sourceCapabilities':[],'targetCapabilities':[],'observationBoundary':{'kind':'','identity':''},
                'notClaimedProperties':LIMITATIONS,'producer':{'kind':'translation-proof',
                    'producerIdentity':request['producerIdentity'],'proofIdentity':artifact['proof_identity']},'complete':False}
            profile=dict(payload,profileIdentity=_hash(payload));profiles.append(parse_l3_intent_profile(profile).to_dict())
            d={'schemaVersion':'riscv2x86.l3-intent-disposition.v1','fragmentId':f['fragment']['id'],
               'profileIdentity':profile['profileIdentity'],'status':'prerequisites_missing' if obligation is None else 'unsupported',
               'reasonCodes':[str(exc)]}
            decisions.append(dict(d,dispositionIdentity=_hash(d)))
    return {'schemaVersion':'riscv2x86.l3-intent-producer-response.v2','requestIdentity':request['requestIdentity'],
            'profiles':profiles,'dispositions':decisions}


def main():
    p=argparse.ArgumentParser();p.add_argument('--implementation',required=True)
    p.add_argument('--dependency',action='append',default=[]);p.add_argument('--cache-model-file')
    a=p.parse_args()
    expected={str(Path(__file__).with_name(n).resolve()) for n in (
        'l3_trace_support.py','l3_cache_model.py','l3_intent_requirements.py','l3_memory_intent.py',
        'l3_property_obligations.py','l3_scalar_trace.py','l2_semantic_profile.py','l2_authority.py','l2_effect_proof.py',
        'l3_source_eligibility.py','l2_atomic_authority.py','l2_materialization.py','l2_fragment_execution.py',
        'compiler_provenance.py')}
    if Path(a.implementation).resolve()!=Path(__file__).resolve() or set(str(Path(x).resolve()) for x in a.dependency)!=expected:
        raise ValueError('L3_TRACE_PRODUCER_DEPENDENCIES_UNPINNED')
    model=None if a.cache_model_file is None else json.loads(Path(a.cache_model_file).read_text())
    print(json.dumps(produce(json.load(sys.stdin),model),sort_keys=True))


if __name__=='__main__':main()
