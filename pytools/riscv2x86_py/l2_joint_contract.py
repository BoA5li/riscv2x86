"""Production joint registrations; declared capability is never execution evidence."""
from copy import deepcopy

CAPABILITIES = ('composite_fragment_observation', 'joint_program_observation', 'logical_operand_observation',
                'object_relative_memory_observation', 'ordering_observation', 'shell_observation')
EXECUTION_PROFILE = 'rv64gc-user-to-x86_64-user'


def providers(config, execution_profiles=(EXECUTION_PROFILE,)):
    if config.get('mode') != 'joint-program-functions':
        raise ValueError('L2_JOINT_CONFIG_MODE_REQUIRED')
    result = []
    for name, patterns, dimensions in (
        ('scalar', ['composite','scalar'], ['logical_operands', 'shell_semantics']),
        ('memory', ['memory_load', 'memory_store'],
         ['logical_operands', 'memory_effects', 'shell_semantics']),
        ('fence', ['fence'], ['memory_effects','shell_semantics']),
    ):
        result.append({'providerId': 'automatic-l2-joint-' + name + '-v1',
            'supportedDimensions': dimensions, 'supportedPatterns': patterns,
            'requiredCapabilities': list(CAPABILITIES),
            'executionProfiles': sorted(set(execution_profiles)), 'bindingKind': 'automatic',
            'validatorType': 'automatic-l2-effect-differential',
            'configSchemaVersion': config['schemaVersion'], 'config': deepcopy(config),
            'fragmentIds': []})
    return result


def assess(findings, definitions, available, execution_profiles, *, execution_profile=EXECUTION_PROFILE):
    """Resolve the real contracts per fragment without constructing/running children."""
    from .l2_eligibility import classify_l2_requirements
    from .l2_semantic_profile import profile_from_finding
    from .l2_validator_resolution import (provider_from_dict, fragment_requirement_from_dict,
        L2RuntimeCapabilities, ExplicitL2Bindings, L2BindingKind, L2ValidatorResolver)
    parsed = tuple(provider_from_dict(p) for p in definitions)
    environment = L2RuntimeCapabilities(tuple(p for p in parsed if p.binding_kind is not L2BindingKind.EXPLICIT),
        tuple(sorted(set(available))), tuple(sorted(set(execution_profiles))))
    explicit = ExplicitL2Bindings(tuple(p for p in parsed if p.binding_kind is L2BindingKind.EXPLICIT))
    requirements = classify_l2_requirements({'findings': findings})['requirements']
    by_id = {p.provider_id: p for p in parsed}; plans = []
    for finding, raw in zip(findings, requirements):
        plan = L2ValidatorResolver().resolve(fragment_requirement_from_dict(raw), environment, explicit,
            execution_profile=execution_profile, profile=profile_from_finding(finding))
        if not plan.complete:
            raise ValueError('L2_JOINT_PROVIDER_PLAN_INCOMPLETE:' + str(plan.to_dict()))
        for pid in {b.provider_id for b in plan.bindings}:
            bound = sorted(b.dimension.value for b in plan.bindings if b.provider_id == pid)
            if bound != [d.value for d in by_id[pid].supported_dimensions]:
                raise ValueError('L2_JOINT_PROVIDER_DIMENSIONS_NOT_EXACT')
        plans.append(plan.to_dict())
    return plans


def operand_contract(finding, function, sidecar):
    """Proof-bound direct boundary observation contract, not observed values."""
    from .l3_trace_support import identity
    from .l2_fragment_execution import fragment_boundary_from_dict, fragment_dependency_graph_from_dict
    scope=function.get('compilerJointScope') or {};a=finding['approvalArtifact']
    from .versioned_program_contract import load as versioned_boundary
    program=versioned_boundary(finding)
    if program is not None:
        if (program.width_bits!=64
                or set(program.input_operand_indexes)!={o.operand_index for o in sidecar.operands if o.access_mode=='input'}
                or set(program.output_operand_indexes)!={o.operand_index for o in sidecar.operands if o.access_mode=='output'}
                or any(o.access_mode not in {'input','output'} for o in sidecar.operands)):
            raise ValueError('L2_JOINT_VERSIONED_OPERAND_CONTRACT_MISMATCH')
    from .compiler_joint_context import valid as valid_joint_scope
    if (not valid_joint_scope(function)
            or sidecar.producer.producer_id!='automatic-joint-fragment-authority'):
        raise ValueError('L2_JOINT_OPERAND_SCOPE_REQUIRED')
    boundary=fragment_boundary_from_dict(a['l2FragmentOperandBoundary'],expected_fragment_id=sidecar.fragment_id)
    graph=fragment_dependency_graph_from_dict(a['l2FragmentDependencyGraph'])
    if not boundary.complete or not graph.complete:raise ValueError('L2_JOINT_OPERAND_GRAPH_REQUIRED')
    points=[]
    for operand in sidecar.operands:
        if operand.type_kind!='integer' or operand.width_bits!=64 or operand.signedness!='unsigned':
            raise ValueError('L2_JOINT_OPERAND_DIRECT_UNSIGNED64_REQUIRED')
        edges=(['pre'] if operand.access_mode=='input' else ['post'] if operand.access_mode=='output'
               else ['pre','post'] if operand.access_mode=='read_write' else [])
        if not edges or not operand.declaration_id:raise ValueError('L2_JOINT_OPERAND_BINDING_REQUIRED')
        points.append({'operandIndex':operand.operand_index,'declarationIdentity':operand.declaration_id,'edges':edges})
    body={'schemaVersion':'riscv2x86.joint-operand-observation-contract.v1','fragmentId':sidecar.fragment_id,
        'scopeIdentity':scope['scopeIdentity'],'boundaryIdentity':boundary.boundary_identity,'graphIdentity':graph.graph_identity,
        'proofIdentity':a['proofIdentity'],'authorityIdentity':sidecar.authority_identity,'points':points,
        'observationMethod':'instrumented-direct-declaration-pre-post','executionObserved':False}
    return dict(body,contractIdentity=identity(body))
