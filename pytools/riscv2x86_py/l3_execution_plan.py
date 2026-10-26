"""Mechanism selection cannot erase source obligations or synthesize evidence."""
from .l3_trace_support import identity
from .l3_property_obligations import analyze


def build(findings,functions,capabilities):
    if not findings or len({f['fragment']['id'] for f in findings})!=len(findings):raise ValueError('L3_PLAN_MEMBER_SET_INVALID')
    members=[]
    for f in findings:
        obligations=analyze(f,functions);kind=f['l2SemanticProfile']['patternKind']
        dimensions={p['dimension'] for p in obligations['requiredProperties']}
        mechanism=('scalar-program' if len(findings)>1 and kind=='scalar' and dimensions=={'access_pattern'} else
                   'memory' if dimensions=={'access_pattern'} else
                   'control' if kind in {'branch','jump','asm_goto'} and dimensions=={'access_pattern','control_flow'} else 'unavailable')
        route_reasons=[]
        if kind=='fence' and len(findings)==1:
            try:
                from .l3_fence_spec import spec
                spec(f,functions)
                mechanism='fence'
            except (OSError,ValueError,KeyError,TypeError) as exc:
                route_reasons.append('L3_PLAN_FENCE_PREREQUISITE:'+str(exc))
        available=mechanism != 'unavailable' and mechanism in capabilities
        members.append({'fragmentId':f['fragment']['id'],'obligations':obligations,'mechanism':mechanism,
            'status':'ready' if available else 'unsupported','reasonCodes':[] if available else route_reasons+['L3_PLAN_CAPABILITY_MISSING:'+mechanism]})
    for member in members:
        sync=member['obligations'].get('synchronizationObligations')
        if sync is not None:
            member['requiredSynchronizationCapabilities']=[p['propertyId'] for p in sync['requiredSubproperties']]
            member['reasonCodes']=sorted(set(member['reasonCodes']+sync['reasonCodes']+([] if member['status']=='ready' else [
                'L3_PLAN_SYNC_CAPABILITY_MISSING:'+p for p in member['requiredSynchronizationCapabilities']])))
    programs={m['obligations']['programId'] for m in members}
    if len(programs)!=1:raise ValueError('L3_PLAN_PROGRAM_IDENTITY_CONFLICT')
    body={'schemaVersion':'riscv2x86.l3-mechanism-plan.v1','programId':programs.pop(),
          'members':members,'complete':all(m['status']=='ready' for m in members),
          'physicalMicroarchitectureClaimed':False}
    return dict(body,planIdentity=identity(body))
