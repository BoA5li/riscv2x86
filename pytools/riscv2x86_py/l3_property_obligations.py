"""Proof-bound source obligations, independent of observer availability.

The registered policy concerns successful data-access/control/synchronization
intent in a compiler asm region. It excludes physical timing and speculation.
No absence of *all* microarchitectural effects is inferred from a scalar result.
"""
from .l3_trace_support import identity

POLICY = {'schemaVersion':'riscv2x86.l3-evaluation-policy.v1',
    'policyId':'compiler-region-architectural-intent.v1',
    'scope':'successful-compiler-asm-region-events',
    'dimensions':['access_pattern','control_flow','synchronization'],
    'excluded':['instruction-fetch','outside-fragment-effects','physical-cache',
                'physical-timing','prediction','speculation']}


def analyze(finding, functions=None):
    from .l2_semantic_profile import profile_from_finding
    from .l2_authority import l2_authority_sidecar_from_dict
    from .l2_effect_proof import effect_proof_facts_from_dict
    a=finding.get('approvalArtifact') or {}; fid=finding['fragment']['id']
    if (a.get('proofStatus')!='approved' or a.get('architectureSemanticsPreserved') is not True
            or a.get('shellSemanticsPreserved') is not True
            or finding.get('translationOutcome') not in {'emitted','strengthened'}):
        raise ValueError('L3_OBLIGATION_APPROVAL_REQUIRED')
    profile=profile_from_finding(finding); sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    proof=effect_proof_facts_from_dict(a['l2EffectProofFacts'])
    boundary=a['l2FragmentOperandBoundary']
    atomic=profile.pattern_kind.value=='atomic'
    if atomic:
        from .l3_source_eligibility import atomic_boundary
        boundary=atomic_boundary(finding,functions,sidecar)
    if (not profile.complete or not sidecar.complete or not proof.complete or
            any(x!=fid for x in (profile.fragment_id,sidecar.fragment_id,proof.fragment_id,boundary.get('fragmentId')))
            or proof.proof_identity!=a['proofIdentity'] or (not atomic and not boundary.get('complete'))
            or not boundary.get('programId') or sidecar.effect_relation_set_identity==''):
        raise ValueError('L3_OBLIGATION_FACTS_INCOMPLETE')
    # All shapes are needed to make cross-family negative classifications;
    # L2 pattern-specific completeness alone does not establish these absences.
    shapes=(profile.memory_shape,profile.control_flow_shape,profile.ordering_shape,
            profile.privileged_shape,profile.internal_state_shape)
    if any(not x.complete for x in shapes) or not profile.ordering_shape.ordering_known:raise ValueError('L3_OBLIGATION_SHAPES_INCOMPLETE')
    if [x.to_dict() for x in proof.source_effects]!=[x.to_dict() for x in sidecar.source_effects]:
        raise ValueError('L3_OBLIGATION_SOURCE_EFFECT_MISMATCH')
    for relation in sidecar.approved_effect_relations:
        matches=[r for r in proof.relations if r.relation_id==relation.relation_id]
        if (len(matches)!=1 or matches[0].source_effect_id!=relation.source_effect_id
                or matches[0].target_effect_ids!=relation.target_effect_ids
                or matches[0].relation_kind!=relation.relation_kind):
            raise ValueError('L3_OBLIGATION_EFFECT_RELATION_MISMATCH')
    if len(proof.relations)!=len(sidecar.approved_effect_relations):
        raise ValueError('L3_OBLIGATION_EFFECT_RELATION_MISMATCH')
    raw=profile.to_dict(); control=raw['controlFlowShape']; order=raw['orderingShape']
    props=[{'propertyId':'memory.fragment-access','dimension':'access_pattern','unit':'fragment'}]
    if (control['continuationCount'] or any(control.get(k) for k in
            ('directJump','external','indirect','internalBranch','multipleExits'))):
        props.append({'propertyId':'control.fragment-events','dimension':'control_flow','unit':'fragment'})
    if (order['instructionVisibility'] or order['memoryBarrier'] or raw['memoryShape']['atomic']
            or raw['privilegedShape']['present']):
        props.append({'propertyId':'synchronization.fragment-events','dimension':'synchronization','unit':'fragment'})
    props.sort(key=lambda x:x['propertyId'])
    decisions=[{'dimension':d,'status':'required' if any(p['dimension']==d for p in props)
                else 'not_applicable_with_basis','basisIdentity':profile.profile_identity}
               for d in POLICY['dimensions']]
    body={'schemaVersion':'riscv2x86.l3-property-obligations.v1','fragmentId':fid,
        'programId':boundary['programId'],'policy':POLICY,'policyIdentity':identity(POLICY),
        'proofIdentity':a['proofIdentity'],'sourceProfileIdentity':profile.profile_identity,
        'authorityIdentity':sidecar.authority_identity,'effectProofIdentity':proof.to_dict()['factsIdentity'],
        'approvedTargetRelationIdentity':sidecar.effect_relation_set_identity,
        'requiredProperties':props,'decisions':decisions,'physicalMicroarchitectureClaimed':False}
    if any(p['dimension']=='synchronization' for p in props):
        from .l3_sync_obligations import build
        body['schemaVersion']='riscv2x86.l3-property-obligations.v2'
        body['synchronizationObligations']=build(finding,profile,proof,sidecar)
    return validate(dict(body,obligationIdentity=identity(body)))


def check_properties(obligations, properties):
    # Cache models add an explicit model property; they never discharge another
    # dimension or suppress source obligations.
    actual=[p for p in properties if p['dimension']!='cache_model']
    if actual!=obligations['requiredProperties']:
        raise ValueError('L3_OBLIGATION_PROPERTY_COVERAGE_MISMATCH')


def validate(value):
    """Content validation is necessary; proof replay remains mandatory at use."""
    fields={'schemaVersion','fragmentId','programId','policy','policyIdentity','proofIdentity',
        'sourceProfileIdentity','authorityIdentity','effectProofIdentity','approvedTargetRelationIdentity',
        'requiredProperties','decisions','physicalMicroarchitectureClaimed','obligationIdentity'}
    if isinstance(value,dict) and value.get('schemaVersion')=='riscv2x86.l3-property-obligations.v2':
        fields.add('synchronizationObligations')
        from .l3_sync_obligations import validate as validate_sync
        if 'synchronizationObligations' not in value:
            raise ValueError('L3_SYNC_OBLIGATION_REQUIRED')
        if not fields <= set(value):
            raise ValueError('L3_OBLIGATION_RECORD_INVALID')
        sync=validate_sync(value['synchronizationObligations'])
        for k in ('fragmentId','proofIdentity','authorityIdentity','sourceProfileIdentity'):
            if sync[k]!=value[k]:raise ValueError('L3_SYNC_OBLIGATION_BINDING_MISMATCH')
        if sync['effectRelationIdentity']!=value['approvedTargetRelationIdentity']:raise ValueError('L3_SYNC_OBLIGATION_BINDING_MISMATCH')
    if (not isinstance(value,dict) or set(value)!=fields
            or value['schemaVersion'] not in {'riscv2x86.l3-property-obligations.v1','riscv2x86.l3-property-obligations.v2'}
            or value['policy']!=POLICY or value['policyIdentity']!=identity(POLICY)
            or value['physicalMicroarchitectureClaimed'] is not False
            or value['obligationIdentity']!=identity({k:v for k,v in value.items() if k!='obligationIdentity'})):
        raise ValueError('L3_OBLIGATION_RECORD_INVALID')
    from .l3_intent_requirements import _sha
    for key in ('policyIdentity','proofIdentity','sourceProfileIdentity','authorityIdentity',
                'effectProofIdentity','approvedTargetRelationIdentity'):_sha(value[key],key)
    if any(not isinstance(value[k],str) or not value[k] for k in ('fragmentId','programId')):
        raise ValueError('L3_OBLIGATION_IDENTITY_MISSING')
    props=value['requiredProperties']
    allowed=[{'propertyId':p,'dimension':d,'unit':'fragment'} for p,d in (
        ('control.fragment-events','control_flow'),('memory.fragment-access','access_pattern'),
        ('synchronization.fragment-events','synchronization'))]
    if (not isinstance(props,list) or not props or props!=[p for p in allowed if p in props]
            or not any(p['dimension']=='access_pattern' for p in props)):
        raise ValueError('L3_OBLIGATION_PROPERTY_SET_INVALID')
    if ('synchronizationObligations' in value) != any(p['dimension']=='synchronization' for p in props):
        raise ValueError('L3_SYNC_OBLIGATION_REQUIRED')
    expected=[{'dimension':d,'status':'required' if any(p['dimension']==d for p in props)
                else 'not_applicable_with_basis','basisIdentity':value['sourceProfileIdentity']}
               for d in POLICY['dimensions']]
    if value['decisions']!=expected:raise ValueError('L3_OBLIGATION_DECISIONS_INVALID')
    return value
