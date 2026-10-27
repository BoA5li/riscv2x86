"""Typed synchronization sub-obligations; classification never grants execution.

Missing mechanism facts remain explicit required obligations. Dynamic records,
compiler/proof contracts and machine mechanism evidence are distinct requirements.
"""
from .l3_trace_support import identity

SCHEMA = 'riscv2x86.l3-synchronization-obligations.v1'
LIMITS = ['concurrent-linearizability-not-observed', 'physical-memory-order-not-observed',
          'prediction-speculation-and-timing-not-claimed']

REQUIREMENTS = {
    'sync.compiler-contract': ['approved-shell-contract'],
    'sync.fence-mechanism': ['actual-machine-region', 'complete-execution', 'instruction-attribution'],
    'sync.ordering-contract': ['approved-ordering-refinement'],
    'sync.atomic-mechanism': ['actual-machine-region', 'approved-atomic-contract', 'complete-execution'],
    'sync.atomic-outcome': ['actual-input-output', 'object-relative-memory'],
    'sync.instruction-visibility': ['approved-visibility-contract', 'actual-visibility-observation'],
    'sync.environment-operation': ['approved-environment-contract', 'actual-environment-observation'],
    'sync.unclassified-operation': ['complete-synchronization-semantics'],
}
FAMILY_REQUIRED = {
    'memory-fence': {'sync.compiler-contract','sync.fence-mechanism','sync.ordering-contract'},
    'atomic-rmw': {'sync.compiler-contract','sync.atomic-mechanism','sync.atomic-outcome','sync.ordering-contract'},
    'instruction-visibility': {'sync.compiler-contract','sync.instruction-visibility'},
    'controlled-environment': {'sync.compiler-contract','sync.environment-operation'},
    'unknown': {'sync.compiler-contract','sync.unclassified-operation'},
}


def build(finding, profile, proof, sidecar):
    a = finding['approvalArtifact']; fid = finding['fragment']['id']
    kind = profile.pattern_kind.value; reasons = []; basis = {}; roles = {}
    items = []
    def require(name, evidence):
        items.append({'propertyId': name, 'evidenceKinds': sorted(evidence), 'required': True})
    require('sync.compiler-contract', ['approved-shell-contract'])
    try:
        if kind == 'fence':
            from .l2_fence_ordering import fence_proof_facts_from_dict, validate_fence_effect_closure
            facts = fence_proof_facts_from_dict(a['l2FenceProofFacts'])
            validate_fence_effect_closure(facts, proof)
            if facts.fragment_id != fid: raise ValueError('L3_SYNC_FRAGMENT_MISMATCH')
            basis = {'fenceFactsIdentity': facts.facts_identity,
                     'sourceOrderingContract': facts.to_dict()['sourceOrderingContract'],
                     'targetOrderingContract': facts.to_dict()['targetOrderingContract'],
                     'relationKind': facts.relation_kind}
            roles = facts.to_dict()['effectRoles']
            if set(roles) != {e.effect_id for e in proof.source_effects}:
                raise ValueError('L3_SYNC_UNCLASSIFIED_SOURCE_EFFECT')
        elif kind == 'atomic':
            if a.get('l2LrscProofFacts') is not None:
                from .l2_lrsc_authority import validate as validate_lrsc
                atom, width, _ = validate_lrsc(finding)
                basis = {'lrscFactsIdentity': a['l2LrscProofFacts']['factsIdentity'],
                         'operation': atom, 'widthRoles': width, 'sourceMechanism': 'lrsc-sequence'}
            else:
                from .l2_atomic_authority import validate_atomic_proof_facts
                atom, width = validate_atomic_proof_facts(a['l2AtomicProofFacts'], a, fid)
                basis = {'atomicFactsIdentity': a['l2AtomicProofFacts']['factsIdentity'],
                         'operation': atom, 'widthRoles': width}
            roles = {e.effect_id: 'source-operation' for e in proof.source_effects}
    except (ValueError, KeyError, TypeError) as exc:
        reasons.append('L3_SYNC_BASIS_INCOMPLETE:' + str(exc))
    if kind == 'fence':
        require('sync.fence-mechanism', ['actual-machine-region', 'complete-execution', 'instruction-attribution'])
        require('sync.ordering-contract', ['approved-ordering-refinement'])
        mechanism = 'memory-fence'
        if not basis and not reasons: reasons.append('L3_SYNC_FENCE_FACTS_MISSING')
    elif kind == 'atomic':
        require('sync.atomic-mechanism', ['actual-machine-region', 'approved-atomic-contract', 'complete-execution'])
        require('sync.atomic-outcome', ['actual-input-output', 'object-relative-memory'])
        require('sync.ordering-contract', ['approved-ordering-refinement'])
        mechanism = 'atomic-rmw'
        if not basis and not reasons: reasons.append('L3_SYNC_ATOMIC_FACTS_MISSING')
    elif profile.ordering_shape.instruction_visibility:
        require('sync.instruction-visibility', ['approved-visibility-contract', 'actual-visibility-observation'])
        mechanism = 'instruction-visibility'
        reasons.append('L3_SYNC_VISIBILITY_ROUTE_REQUIRED')
    elif profile.privileged_shape.present:
        require('sync.environment-operation', ['approved-environment-contract', 'actual-environment-observation'])
        mechanism = 'controlled-environment'
        reasons.append('L3_SYNC_ENVIRONMENT_ROUTE_REQUIRED')
    else:
        require('sync.unclassified-operation', ['complete-synchronization-semantics'])
        mechanism = 'unknown'
        reasons.append('L3_SYNC_OPERATION_UNCLASSIFIED')
    # Compound profiles keep every independently present obligation.
    if profile.ordering_shape.instruction_visibility and mechanism != 'instruction-visibility':
        require('sync.instruction-visibility', ['approved-visibility-contract', 'actual-visibility-observation'])
        reasons.append('L3_SYNC_COMPOUND_VISIBILITY_UNSUPPORTED')
    if profile.privileged_shape.present and mechanism != 'controlled-environment':
        require('sync.environment-operation', ['approved-environment-contract', 'actual-environment-observation'])
        reasons.append('L3_SYNC_COMPOUND_ENVIRONMENT_UNSUPPORTED')
    if kind == 'atomic' and profile.ordering_shape.memory_barrier:
        require('sync.fence-mechanism', ['actual-machine-region', 'complete-execution', 'instruction-attribution'])
        reasons.append('L3_SYNC_COMPOUND_FENCE_UNSUPPORTED')
    body = {'schemaVersion': SCHEMA, 'fragmentId': fid, 'proofIdentity': a['proofIdentity'],
            'authorityIdentity': sidecar.authority_identity,
            'effectRelationIdentity': sidecar.effect_relation_set_identity,
            'sourceProfileIdentity': profile.profile_identity, 'mechanismFamily': mechanism,
            'basis': basis, 'basisComplete': not reasons, 'reasonCodes': sorted(set(reasons)),
            'effectRoles': roles, 'requiredSubproperties': sorted(items, key=lambda x: x['propertyId']),
            'declaredLimitations': LIMITS, 'physicalMicroarchitectureClaimed': False}
    return dict(body, obligationIdentity=identity(body))


def validate(value):
    fields = {'schemaVersion','fragmentId','proofIdentity','authorityIdentity','effectRelationIdentity',
              'sourceProfileIdentity','mechanismFamily','basis','basisComplete','reasonCodes',
              'effectRoles','requiredSubproperties','declaredLimitations','physicalMicroarchitectureClaimed','obligationIdentity'}
    if (not isinstance(value, dict) or set(value) != fields or value['schemaVersion'] != SCHEMA
            or value['obligationIdentity'] != identity({k:v for k,v in value.items() if k != 'obligationIdentity'})
            or value['physicalMicroarchitectureClaimed'] is not False or value['declaredLimitations'] != LIMITS
            or type(value['basisComplete']) is not bool or value['basisComplete'] != (value['reasonCodes'] == [])):
        raise ValueError('L3_SYNC_OBLIGATION_INVALID')
    from .l3_intent_requirements import _sha
    for k in ('proofIdentity','authorityIdentity','effectRelationIdentity','sourceProfileIdentity'):
        _sha(value[k], k)
    props = value['requiredSubproperties']
    if value['mechanismFamily'] not in FAMILY_REQUIRED:
        raise ValueError('L3_SYNC_MECHANISM_UNKNOWN')
    if not isinstance(props,list) or not props or props != sorted(props,key=lambda x:x['propertyId']) or len({p['propertyId'] for p in props}) != len(props):
        raise ValueError('L3_SYNC_PROPERTY_SET_INVALID')
    for p in props:
        if (set(p) != {'propertyId','evidenceKinds','required'} or p['required'] is not True
                or p['propertyId'] not in REQUIREMENTS
                or p['evidenceKinds'] != sorted(REQUIREMENTS[p['propertyId']])
                or p['evidenceKinds'] != sorted(set(p['evidenceKinds']))):
            raise ValueError('L3_SYNC_PROPERTY_INVALID')
    if value['basisComplete']:
        if value['mechanismFamily'] not in {'memory-fence','atomic-rmw'} or not value['basis']:
            raise ValueError('L3_SYNC_COMPLETE_BASIS_UNSUPPORTED')
        roles=value['effectRoles']
        if not isinstance(roles,dict) or not roles:
            raise ValueError('L3_SYNC_EFFECT_ROLES_MISSING')
        if value['mechanismFamily']=='memory-fence':
            if sorted(roles.values())!=['proof-context-anchor','proof-context-anchor','source-operation']:
                raise ValueError('L3_SYNC_FENCE_ROLE_MISMATCH')
        elif set(roles.values())!={'source-operation'}:
            raise ValueError('L3_SYNC_ATOMIC_ROLE_MISMATCH')
    if not FAMILY_REQUIRED[value['mechanismFamily']] <= {p['propertyId'] for p in props}:
        raise ValueError('L3_SYNC_PROPERTY_COVERAGE_INCOMPLETE')
    return value
