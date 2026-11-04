"""Policy-specific L3 consumption. Labels and serialized audit summaries grant no authority.

Bounded SYSTEM evidence is intentionally not converted to architectural-intent
fragment/platform reports. Every consumer replays the original policy audit.
"""
from collections.abc import Mapping


def system_candidate(evaluation):
    from .l3_system_route import SCHEMA, POLICY, _json
    plan = evaluation.get('validationPlan') or {}
    if plan.get('experimentContractId') == POLICY['policyId']:
        return True
    for attempt in evaluation.get('attempts', []):
        for layer in (attempt.get('validation') or {}).get('layers', []):
            if layer.get('level') != 'L3':
                continue
            raw = layer.get('detail')
            try:
                body = _json(raw) if isinstance(raw, str) else raw
                if isinstance(body, Mapping) and isinstance(body.get('providerDetail'), str):
                    body = _json(body['providerDetail'])
            except (ValueError, TypeError):
                continue
            if isinstance(body, Mapping) and (body.get('schemaVersion') == SCHEMA
                    or 'systemL3' in body):
                return True
    return False


def consume_system(evaluation):
    """Return a checked, bounded summary, or None for another policy.

    Never accepts an externally persisted summary in place of original evidence.
    The audit replays proof/receipt, builds, machine attribution and observations.
    """
    if not system_candidate(evaluation):
        return None
    from .l3_system_route import audit_result, _json, POLICY
    from .l3_intent_requirements import parse_l3_requirement_manifest
    from .l3_trace_support import identity, require_json_match
    audited = audit_result(evaluation)
    attempt, = evaluation['attempts']
    detail = _json(attempt['validation']['layers'][-1]['detail'])
    manifest = parse_l3_requirement_manifest(evaluation['translationEvaluationLink']['l3Requirements'])
    if len(manifest.requirements) != 1:
        raise ValueError('SYSTEM_L3_CONSUMER_SINGLE_REQUIREMENT_REQUIRED')
    requirement, = manifest.requirements
    expected = [{'propertyId': p, 'dimension': 'synchronization', 'unit': 'fragment'}
                for p in sorted(POLICY['properties'])]
    require_json_match(requirement['requiredProperties'], expected,
                       'SYSTEM_L3_CONSUMER_PROPERTIES_INCOMPLETE')
    if (requirement['eligibilityStatus'] != 'eligible'
            or requirement['fragmentId'] != attempt['fragmentId']
            or audited['status'] != 'verified'
            or audited['programExecutionUnitCount'] != 1):
        raise ValueError('SYSTEM_L3_CONSUMER_REQUIREMENT_CLOSURE_INVALID')
    row = {key: requirement[key] for key in ('fragmentId', 'programId', 'requirementIdentity', 'profileIdentity')}
    row.update(status='verified', claimScope=detail['claimScope'],
               requiredProperties=expected, verifiedProperties=[p['propertyId'] for p in expected],
               evidenceIdentity=detail['evidenceIdentity'])
    body = {'schemaVersion': 'riscv2x86.bounded-system-consumption.v1',
            'status': 'verified', 'policyId': POLICY['policyId'],
            'claimScope': detail['claimScope'], 'programId': requirement['programId'],
            'policyIdentity': audited['policyIdentity'],
            'requirementManifestIdentity': audited['requirementManifestIdentity'],
            'fragments': [row], 'programExecutionUnitCount': 1,
            'physicalMicroarchitectureEquivalenceClaimed': False}
    return dict(body, summaryIdentity=identity(body))
