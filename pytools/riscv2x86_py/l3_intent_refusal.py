"""A route refusal retains proof-bound source obligations; no fallback approval."""
from .l3_intent_requirements import parse_l3_intent_profile,_hash
from .l3_property_obligations import analyze


class RouteUnavailable(ValueError):
    def __init__(self, code, *, disposition='unsupported', plan=None):
        if disposition not in {'unsupported','prerequisites_missing'}:
            raise ValueError('L3_ROUTE_DISPOSITION_INVALID')
        self.disposition=disposition
        self.plan=plan
        super().__init__(code)


def produce(request, reason):
    if (type(request) is not dict or request.get('schemaVersion')!='riscv2x86.l3-intent-producer-request.v1'
            or request.get('requestIdentity')!=_hash({k:v for k,v in request.items() if k!='requestIdentity'})
            or type(request.get('candidates')) is not list or not request['candidates']):
        raise ValueError('L3_MECHANISM_REQUEST_INVALID')
    profiles=[];dispositions=[];seen=set()
    for item in request['candidates']:
        finding=item['finding'];artifact=item['translationArtifact'];fid=finding['fragment']['id']
        if fid in seen:raise ValueError('L3_MECHANISM_DUPLICATE_FRAGMENT')
        seen.add(fid);ob=None;reasons=[str(reason)]
        try:
            ob=analyze(finding,item.get('compilerFunctions'))
            if (ob['proofIdentity']!=artifact['proof_identity'] or
                    ob['approvedTargetRelationIdentity']!=artifact['effect_relation_set_identity']):
                raise ValueError('L3_MECHANISM_ARTIFACT_MISMATCH')
        except (KeyError,ValueError,TypeError,IndexError) as exc:
            ob=None;reasons.append(str(exc))
        properties=ob['requiredProperties'] if ob is not None else []
        body={'schemaVersion':'riscv2x86.l3-intent-profile.v1','fragmentId':fid,
            'programId':ob['programId'] if ob is not None else '',
            'intentKind':'unknown','experimentClasses':sorted({
                {'access_pattern':'memory_access','control_flow':'control_flow','synchronization':'synchronization'}[p['dimension']]
                for p in properties}),
            'sourceIntent':'source obligations retained; selected execution route unavailable',
            'approvedTargetRelationIdentity':artifact['effect_relation_set_identity'],
            'requiredProperties':properties,'sourceCapabilities':[],'targetCapabilities':[],
            'observationBoundary':{'kind':'','identity':''},
            'notClaimedProperties':['execution-not-produced','physical-microarchitecture-not-claimed'],
            'producer':{'kind':'translation-proof','producerIdentity':request['producerIdentity'],
                'proofIdentity':artifact['proof_identity']},'complete':False}
        profile=parse_l3_intent_profile(dict(body,profileIdentity=_hash(body))).to_dict()
        profiles.append(profile)
        # A missing selection is a configuration precondition, not a permanent
        # unsupported source family. Unknown semantics remain unproved.
        status='prerequisites_missing' if ob is None else getattr(reason,'disposition','unsupported')
        decision={'schemaVersion':'riscv2x86.l3-intent-disposition.v1','fragmentId':fid,
            'profileIdentity':profile['profileIdentity'],'status':status,'reasonCodes':sorted(set(reasons))}
        dispositions.append(dict(decision,dispositionIdentity=_hash(decision)))
    return {'schemaVersion':'riscv2x86.l3-intent-producer-response.v2',
        'requestIdentity':request['requestIdentity'],'profiles':profiles,'dispositions':dispositions}
