"""Complete current-report accounting, separate from layer approval.

Consumed only after original API/L2/applicability checkers. Every finding and
edited applicability instance stays visible, including unselected functions.
No counter here is an execution certificate or permission to discard a seed.
"""
from . import native_captured_deployment as d


def summarize(report, facts, l2):
    findings = report.get('findings', [])
    applications = facts.get('instances', [])
    by_instance = {r['instanceBindingIdentity']: r for r in applications}
    if len(by_instance) != len(applications):
        raise ValueError('COVERAGE_DUPLICATE_APPLICABILITY_INSTANCE')
    attempts = {r['findingId']: r for r in l2['instances'] if r.get('findingId')}
    if len(attempts) != sum(bool(r.get('findingId')) for r in l2['instances']):
        raise ValueError('COVERAGE_DUPLICATE_L2_FINDING')
    rows = []; represented = set(); used = set()
    for index, finding in enumerate(findings):
        fragment = finding.get('fragment') or {}; fragment_id = fragment.get('id', '')
        key = f'finding:{index}:{fragment_id}'
        physical = finding.get('physicalEditBinding') or {}
        instance = physical.get('instanceBindingIdentity')
        app = by_instance.get(instance); attempt = attempts.get(key)
        if instance in represented:
            raise ValueError('COVERAGE_DUPLICATE_FINDING_INSTANCE')
        if instance: represented.add(instance)
        if attempt is not None:
            used.add(key)
            if attempt.get('fragmentId') != fragment_id:
                raise ValueError('COVERAGE_L2_FRAGMENT_MISMATCH')
            disposition = attempt.get('instanceExecutionDisposition')
            if instance and (disposition is None or disposition['instanceBindingIdentities'] != [instance]):
                raise ValueError('COVERAGE_L2_INSTANCE_MISMATCH')
        excluded = app is not None and app['sourceGuardClassification'] == 'excluded-under-compiler-query-contracts'
        if attempt is not None and instance and bool(attempt.get('sourceConditionExcluded')) != excluded:
            raise ValueError('COVERAGE_SOURCE_DISPOSITION_MISMATCH')
        detail = (attempt or {}).get('detail') or {}
        erasure = detail.get('instanceErasureEvidence') or {}
        invariant = erasure.get('objectErasureInvariant') is True
        if invariant:
            subject = erasure['subject']; disposition = attempt['instanceExecutionDisposition']
            if (not excluded or subject['instanceBindingIdentity'] != instance
                    or subject['fragmentId'] != fragment_id
                    or subject['sourceDispositionIdentity'] != disposition['dispositionIdentity']
                    or subject['project'] != disposition['project']
                    or subject['functionBindingIdentity'] != disposition['functionBindingIdentity']):
                raise ValueError('COVERAGE_ERASURE_SUBJECT_MISMATCH')
        logical = (attempt or {}).get('logicalOperandEvidenceChecked') is True
        if logical and excluded:
            raise ValueError('COVERAGE_EXCLUDED_INSTANCE_CANNOT_BE_EXECUTED')
        if excluded:
            status = 'source-excluded-object-erasure-invariant' if invariant else 'source-excluded-object-influence-unresolved'
            action = 'retain-exclusion-and-select-another-recorded-configuration-or-instance'
        elif app is None:
            status = 'applicability-unavailable'; action = 'acquire-compiler-instance-and-applicability-binding'
        elif attempt is None:
            status = 'not-selected-for-L2'; action = 'plan-original-entry-contract-for-this-instance'
        elif logical:
            status = 'logical-operands-checked-canonical-coverage-unproved'; action = 'acquire-canonical-machine-region-and-events'
        else:
            status = 'original-L2-evidence-unresolved'; action = 'resolve-original-provider-reason'
        rows.append({'findingId': key, 'fragmentId': fragment_id, 'instanceBindingIdentity': instance,
            'sourceConditionExcluded': excluded, 'selectedForL2': attempt is not None,
            'logicalOperandEvidenceChecked': logical, 'objectErasureInvariant': invariant,
            'providerReasonCode': detail.get('reasonCode'), 'status': status, 'nextAction': action,
            'canonicalInstructionCoverageVerified': False})
    if set(attempts) != used:
        raise ValueError('COVERAGE_L2_FINDING_NOT_IN_REPORT')
    unrepresented = sorted(set(by_instance) - represented)
    counts = {'reportFindingCount': len(rows), 'editedInstanceCount': len(by_instance),
        'selectedFindingCount': sum(r['selectedForL2'] for r in rows),
        'sourceExcludedFindingCount': sum(r['sourceConditionExcluded'] for r in rows),
        'objectErasureInvariantFindingCount': sum(r['objectErasureInvariant'] for r in rows),
        'logicalOperandCheckedFindingCount': sum(r['logicalOperandEvidenceChecked'] for r in rows),
        'unselectedFindingCount': sum(not r['selectedForL2'] for r in rows)}
    body = {'schemaVersion': 'riscv2x86.current-report-evaluation-coverage.v1',
        'scope': 'all-current-report-findings-not-entire-corpus-or-layer-acceptance',
        'counts': counts, 'findings': rows, 'unrepresentedEditedInstances': unrepresented,
        'reportAccountingComplete': not unrepresented and bool(rows),
        'canonicalInstructionCoverageVerified': False, 'semanticApproval': False,
        'productionAcceptanceComplete': False}
    return d.seal(body, 'coverageIdentity')


def from_spec(spec, facts, l2):
    run = d.read(spec['run']['path']); d.verify_snapshot(run['translation'])
    translation = d.read(run['translation']['path']); reference = translation['report']
    d.verify_snapshot(reference); report = d.read(reference['path'])
    value = summarize(report, facts, l2)
    d.verify_snapshot(reference)
    return value
