"""Explicit atomic-backend intent ingress; no synthesized synchronization observations."""
import argparse
import json
from pathlib import Path
import sys
from .l3_trace_support import identity
from .l3_intent_requirements import parse_l3_intent_profile
from .l3_atomic_spec import spec,CAPABILITY,LIMITS

DEPENDENCIES=('l3_atomic_retry_observation.py','l3_atomic_semantics.py','l3_atomic_retry.py','l3_atomic_spec.py','l3_atomic_machine.py','l3_atomic_compare.py','l3_atomic_backend.py','l3_control_machine.py',
 'l3_property_obligations.py','l3_sync_obligations.py','l3_source_eligibility.py','l2_atomic_authority.py','atomic_builtin_shell.py',
 'l2_materialization.py','l2_fragment_execution.py','l2_control_flow.py','l2_asm_goto.py','automatic_l2_authority.py',
 'compiler_provenance.py','l2_authority.py','l2_effect_proof.py','l2_semantic_profile.py','l3_trace_support.py','l3_intent_requirements.py')


def produce(request):
    if request.get('schemaVersion')!='riscv2x86.l3-intent-producer-request.v1' or request.get('requestIdentity')!=identity({k:v for k,v in request.items() if k!='requestIdentity'}):raise ValueError('L3_ATOMIC_PRODUCER_REQUEST_INVALID')
    profiles=[];dispositions=[]
    for item in request['candidates']:
        f=item['finding'];artifact=item['translationArtifact'];atomic=None;ob=None;reason=None
        try:
            from .l3_property_obligations import analyze
            ob=analyze(f,item.get('compilerFunctions'))
            atomic=spec(f,item.get('compilerFunctions',[]))
            if atomic['obligations']['proofIdentity']!=artifact['proof_identity'] or atomic['obligations']['approvedTargetRelationIdentity']!=artifact['effect_relation_set_identity']:raise ValueError('L3_ATOMIC_ARTIFACT_MISMATCH')
        except (KeyError,ValueError,TypeError,IndexError) as exc:reason=str(exc)
        body={'schemaVersion':'riscv2x86.l3-intent-profile.v1','fragmentId':f['fragment']['id'],
          'programId':ob['programId'] if ob is not None else '',
          'intentKind':'composite' if reason is None else 'unknown',
          'experimentClasses':sorted({{'control_flow':'control_flow','access_pattern':'memory_access','synchronization':'synchronization'}[p['dimension']] for p in ob['requiredProperties']}) if ob is not None else [],
          'sourceIntent':'executed direct atomic RMW, actual outcomes AND approved ordering contract',
          'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],
          'requiredProperties':ob['requiredProperties'] if ob is not None else [],
          'sourceCapabilities':[CAPABILITY] if reason is None else [],'targetCapabilities':[CAPABILITY] if reason is None else [],
          'observationBoundary':{'kind':'compiler-atomic-region','identity':atomic['specIdentity']} if reason is None else {'kind':'','identity':''},
          'notClaimedProperties':sorted(LIMITS),'producer':{'kind':'translation-proof','producerIdentity':request['producerIdentity'],'proofIdentity':artifact['proof_identity']},'complete':reason is None}
        profile=parse_l3_intent_profile(dict(body,profileIdentity=identity(body))).to_dict();profiles.append(profile)
        if reason is not None:
            d={'schemaVersion':'riscv2x86.l3-intent-disposition.v1','fragmentId':f['fragment']['id'],
               'profileIdentity':profile['profileIdentity'],'status':'unsupported' if ob is not None else 'prerequisites_missing','reasonCodes':[reason]}
            dispositions.append(dict(d,dispositionIdentity=identity(d)))
    return {'schemaVersion':'riscv2x86.l3-intent-producer-response.v2','requestIdentity':request['requestIdentity'],'profiles':profiles,'dispositions':dispositions}


def main():
    p=argparse.ArgumentParser();p.add_argument('--implementation',required=True);p.add_argument('--dependency',action='append',default=[]);a=p.parse_args()
    if Path(a.implementation).resolve()!=Path(__file__).resolve() or {str(Path(x).resolve()) for x in a.dependency}!={str(Path(__file__).with_name(n).resolve()) for n in DEPENDENCIES}:raise ValueError('L3_ATOMIC_PRODUCER_DEPENDENCIES_UNPINNED')
    print(json.dumps(produce(json.load(sys.stdin)),sort_keys=True))

if __name__=='__main__':main()
