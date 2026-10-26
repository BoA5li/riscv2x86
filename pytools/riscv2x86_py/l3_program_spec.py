"""Proof-replayed pure scalar regions, all members and compiler dataflow retained."""
from copy import deepcopy
from .l3_trace_support import identity
from .l3_scalar_trace import scalar_spec
from .l3_control_spec import signature
from .l3_execution_plan import build

CAPABILITY='qemu-ordered-compiler-program-regions.v1'
LIMITS=['listed-input-vectors-only','single-thread-pure-integer64-program-regions',
        'physical-cache-timing-prediction-and-speculation-not-claimed',
        'intermediate-values-covered-by-l2-not-observed-by-l3']


def spec(findings,functions):
    from .automatic_l2_authority import _scalar_authority
    from .l2_authority import l2_authority_sidecar_from_dict
    from .l2_fragment_execution import materialize_fragment_execution_authority
    if len(functions)!=1 or not 2<=len(findings)<=16:raise ValueError('L3_PROGRAM_MEMBER_DOMAIN_UNSUPPORTED')
    fn=functions[0];scope=fn.get('compilerProgramRegions')
    if (not scope or scope.get('schemaVersion')!='riscv2x86.compiler-program-regions.v1' or scope['scope']!='direct-acyclic-pure-shell'
            or scope['sourceDigest']!=fn['sourceDigest'] or scope['functionIdentity']!=fn['functionId']
            or scope['scopeIdentity']!=identity({k:v for k,v in scope.items() if k!='scopeIdentity'}) or len(scope['sites'])!=len(findings)):
        raise ValueError('L3_PROGRAM_COMPILER_REGION_SCOPE_REQUIRED')
    plan=build(findings,functions,{'scalar-program'})
    if not plan['complete']:raise ValueError('L3_PROGRAM_FULL_CAPABILITY_COVERAGE_REQUIRED')
    ordered=sorted(findings,key=lambda f:f['fragment']['compilerFragmentAuthority']['fragmentBindingKey']['beginOffset'])
    members=[]
    boundaries,graph,execution=materialize_fragment_execution_authority(ordered,fn,plan['programId'])
    if not graph.complete or not execution.complete:raise ValueError('L3_PROGRAM_DEPENDENCY_AUTHORITY_INCOMPLETE')
    for f,site in zip(ordered,scope['sites']):
        a=f['approvalArtifact'];fragment=f['fragment'];fid=fragment['id'];sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
        bound=_scalar_authority(deepcopy(f),functions,sidecar.producer.producer_binary_digest)
        if bound is None or bound.to_dict()!=sidecar.to_dict():raise ValueError('L3_PROGRAM_AUTHORITY_REPLAY_MISMATCH')
        if boundaries[fid].to_dict()!=a['l2FragmentOperandBoundary'] or graph.to_dict()!=a['l2FragmentDependencyGraph']:raise ValueError('L3_PROGRAM_DATAFLOW_REPLAY_MISMATCH')
        if fragment['compilerFragmentAuthority']['fragmentBindingKey']['beginOffset']!=site['begin']:raise ValueError('L3_PROGRAM_REGION_BINDING_MISMATCH')
        if f.get('sourceDigest')!=fn['sourceDigest']:raise ValueError('L3_PROGRAM_SOURCE_CHANGED')
        members.append({'fragmentId':fid,'spec':scalar_spec(f),'authorityIdentity':sidecar.authority_identity,
            'proofIdentity':a['proofIdentity'],'relationIdentity':sidecar.effect_relation_set_identity,'site':site})
    body={'schemaVersion':'riscv2x86.scalar-program-spec.v1','functionName':fn['name'],'functionIdentity':fn['functionId'],
        'sourceDigest':fn['sourceDigest'],'scope':scope,'callSignature':signature(fn),'members':members,
        'executionPlan':plan,'dependencyGraphIdentity':graph.graph_identity,'executionAuthorityIdentity':identity(execution.to_dict())}
    return dict(body,specIdentity=identity(body))
