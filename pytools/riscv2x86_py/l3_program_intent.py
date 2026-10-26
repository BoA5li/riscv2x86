"""Whole-program membership is part of every scalar-region receipt."""
import argparse
import json
from pathlib import Path
import sys
from .l3_trace_support import identity
from .l3_program_spec import spec,CAPABILITY,LIMITS
from .l3_intent_requirements import parse_l3_intent_profile
from .l3_property_obligations import analyze

DEPENDENCIES=('l3_program_spec.py','l3_execution_plan.py','l3_scalar_trace.py','l3_control_spec.py',
 'l3_scalar_call.py','l3_property_obligations.py','l3_source_eligibility.py','l2_atomic_authority.py',
 'l2_materialization.py','l2_fragment_execution.py','automatic_l2_authority.py','compiler_provenance.py',
 'l2_authority.py','l2_effect_proof.py','l2_semantic_profile.py','l3_trace_support.py','l3_intent_requirements.py')


def produce(request):
    if request.get('schemaVersion')!='riscv2x86.l3-intent-producer-request.v1' or request.get('requestIdentity')!=identity({k:v for k,v in request.items() if k!='requestIdentity'}):raise ValueError('L3_PROGRAM_REQUEST_INVALID')
    candidates=request['candidates'];program=None;error=None
    try:
        functions=candidates[0]['compilerFunctions']
        if any(c['compilerFunctions']!=functions for c in candidates):raise ValueError('L3_PROGRAM_COMPILER_SNAPSHOT_CONFLICT')
        program=spec([c['finding'] for c in candidates],functions)
    except (KeyError,TypeError,ValueError,IndexError) as exc:error=str(exc)
    profiles=[];dispositions=[]
    for item in candidates:
        f=item['finding'];artifact=item['translationArtifact'];ob=None;reason=error
        try:
            ob=analyze(f,item['compilerFunctions'])
            if ob['proofIdentity']!=artifact['proof_identity'] or ob['approvedTargetRelationIdentity']!=artifact['effect_relation_set_identity']:raise ValueError('L3_PROGRAM_ARTIFACT_MISMATCH')
        except (KeyError,TypeError,ValueError) as exc:reason=str(exc)
        props=[] if ob is None else ob['requiredProperties']
        body={'schemaVersion':'riscv2x86.l3-intent-profile.v1','fragmentId':f['fragment']['id'],'programId':'' if ob is None else ob['programId'],
            'intentKind':'memory_access' if reason is None else 'unknown','experimentClasses':sorted({{'access_pattern':'memory_access','control_flow':'control_flow','synchronization':'synchronization'}[p['dimension']] for p in props}),
            'sourceIntent':'actual data-access absence per compiler region in one complete ordered scalar program',
            'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],'requiredProperties':props,
            'sourceCapabilities':[CAPABILITY] if reason is None else [],'targetCapabilities':[CAPABILITY] if reason is None else [],
            'observationBoundary':{'kind':'compiler-program-regions','identity':program['specIdentity']} if reason is None else {'kind':'','identity':''},
            'notClaimedProperties':sorted(LIMITS),'producer':{'kind':'translation-proof','producerIdentity':request['producerIdentity'],'proofIdentity':artifact['proof_identity']},'complete':reason is None}
        p=parse_l3_intent_profile(dict(body,profileIdentity=identity(body))).to_dict();profiles.append(p)
        if reason is not None:
            d={'schemaVersion':'riscv2x86.l3-intent-disposition.v1','fragmentId':f['fragment']['id'],'profileIdentity':p['profileIdentity'],
                'status':'unsupported' if ob is not None else 'prerequisites_missing','reasonCodes':[reason]}
            dispositions.append(dict(d,dispositionIdentity=identity(d)))
    return {'schemaVersion':'riscv2x86.l3-intent-producer-response.v2','requestIdentity':request['requestIdentity'],'profiles':profiles,'dispositions':dispositions}


def main():
    p=argparse.ArgumentParser();p.add_argument('--implementation',required=True);p.add_argument('--dependency',action='append',default=[]);a=p.parse_args()
    if Path(a.implementation).resolve()!=Path(__file__).resolve() or {str(Path(x).resolve()) for x in a.dependency}!={str(Path(__file__).with_name(n).resolve()) for n in DEPENDENCIES}:raise ValueError('L3_PROGRAM_DEPENDENCIES_UNPINNED')
    print(json.dumps(produce(json.load(sys.stdin)),sort_keys=True))
if __name__=='__main__':main()
