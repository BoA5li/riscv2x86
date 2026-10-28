"""Explicit control-backend intent ingress; no guessed branch observations."""
from .l3_trace_support import emit_json
import argparse
import json
from pathlib import Path
import sys
from .l3_trace_support import identity
from .l3_intent_requirements import parse_l3_intent_profile,_hash
from .l3_control_spec import spec,CAPABILITY,LIMITS

from .l3_implementation_dependencies import implementation_dependencies,implementation_paths
DEPENDENCIES=implementation_dependencies()


def produce(request):
    if request.get('schemaVersion')!='riscv2x86.l3-intent-producer-request.v1' or request.get('requestIdentity')!=_hash({k:v for k,v in request.items() if k!='requestIdentity'}):raise ValueError('L3_CONTROL_PRODUCER_REQUEST_INVALID')
    profiles=[];dispositions=[]
    for item in request['candidates']:
        f=item['finding'];artifact=item['translationArtifact'];control=None;ob=None;reason=None
        try:
            from .l3_property_obligations import analyze
            ob=analyze(f,item.get('compilerFunctions'))
            control=spec(f,item.get('compilerFunctions',[]))
            if control['obligations']['proofIdentity']!=artifact['proof_identity'] or control['obligations']['approvedTargetRelationIdentity']!=artifact['effect_relation_set_identity']:raise ValueError('L3_CONTROL_ARTIFACT_MISMATCH')
        except (KeyError,ValueError,TypeError) as exc:reason=str(exc)
        body={'schemaVersion':'riscv2x86.l3-intent-profile.v1','fragmentId':f['fragment']['id'],
          'programId':ob['programId'] if ob is not None else '',
          'intentKind':'composite' if reason is None else 'unknown',
          'experimentClasses':sorted({{'control_flow':'control_flow','access_pattern':'memory_access','synchronization':'synchronization'}[p['dimension']] for p in ob['requiredProperties']}) if ob is not None else [],
          'sourceIntent':'bounded executed control: logical continuation AND actual transfer shape',
          'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],
          'requiredProperties':ob['requiredProperties'] if ob is not None else [],
          'sourceCapabilities':[CAPABILITY] if reason is None else [],'targetCapabilities':[CAPABILITY] if reason is None else [],
          'observationBoundary':{'kind':'compiler-control-region','identity':control['specIdentity']} if reason is None else {'kind':'','identity':''},
          'notClaimedProperties':sorted(LIMITS),'producer':{'kind':'translation-proof','producerIdentity':request['producerIdentity'],'proofIdentity':artifact['proof_identity']},'complete':reason is None}
        profile=parse_l3_intent_profile(dict(body,profileIdentity=_hash(body))).to_dict();profiles.append(profile)
        if reason is not None:
            d={'schemaVersion':'riscv2x86.l3-intent-disposition.v1','fragmentId':f['fragment']['id'],
               'profileIdentity':profile['profileIdentity'],'status':'unsupported' if ob is not None else 'prerequisites_missing','reasonCodes':[reason]}
            dispositions.append(dict(d,dispositionIdentity=_hash(d)))
    return {'schemaVersion':'riscv2x86.l3-intent-producer-response.v2','requestIdentity':request['requestIdentity'],'profiles':profiles,'dispositions':dispositions}


def main():
    p=argparse.ArgumentParser();p.add_argument('--implementation',required=True);p.add_argument('--dependency',action='append',default=[]);a=p.parse_args()
    if Path(a.implementation).resolve()!=Path(__file__).resolve() or {str(Path(x).resolve()) for x in a.dependency}!=set(implementation_paths()):raise ValueError('L3_CONTROL_PRODUCER_DEPENDENCIES_UNPINNED')
    emit_json(lambda: produce(json.load(sys.stdin)))

if __name__=='__main__':main()
