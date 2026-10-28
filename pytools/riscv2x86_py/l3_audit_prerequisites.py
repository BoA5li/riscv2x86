"""Shared structural audit readiness; never grants semantic approval."""
import json


def check(evaluation, prefix, *, single_fragment=True):
    def refuse(reason):
        raise ValueError(prefix + '_AUDIT_' + reason)
    if type(evaluation) is not dict:
        refuse('EVALUATION_MAPPING_REQUIRED')
    for key in ('orchestrationFailure', 'requirementStagingFailure'):
        if evaluation.get(key):
            refuse('UPSTREAM_FAILURE:' + key + ':' + json.dumps(evaluation[key], sort_keys=True))
    for key in ('sourceProgramArtifact', 'targetProgramArtifact'):
        if type(evaluation.get(key)) is not dict:
            refuse('PROGRAM_ARTIFACT_REQUIRED:' + key)
    link = evaluation.get('translationEvaluationLink')
    if type(link) is not dict or type(link.get('l3Requirements')) is not dict:
        refuse('REQUIREMENTS_REQUIRED')
    attempts = evaluation.get('attempts')
    if (type(attempts) is not list or not attempts or
            single_fragment and len(attempts) != 1 or
            any(type(item) is not dict for item in attempts)):
        refuse('SINGLE_ATTEMPT_REQUIRED' if single_fragment else 'ATTEMPTS_REQUIRED')
    for attempt in attempts:
        validation = attempt.get('validation')
        layers = validation.get('layers') if type(validation) is dict else None
        if (type(attempt.get('translationArtifact')) is not dict or
                type(layers) is not list or len(layers) != 4 or
                any(type(layer) is not dict for layer in layers) or
                [layer.get('level') for layer in layers] != ['L0', 'L1', 'L2', 'L3'] or
                any(layer.get('status') != 'verified' for layer in layers[:3]) or
                layers[3].get('status') not in ('verified', 'failed') or
                not isinstance(layers[3].get('detail'), (str, dict))):
            refuse('COMPLETED_LAYERS_REQUIRED')


def batch(status, cases, reports, prefix, *, single_fragment=True):
    """Keep original failure evidence and do not audit an incomplete batch."""
    if not cases or len(cases) != len(reports):
        raise ValueError(prefix + '_AUDIT_BATCH_MEMBERS_REQUIRED')
    failures=[]
    first=None
    for case, report in zip(cases, reports):
        try:
            check(report, prefix, single_fragment=single_fragment)
        except ValueError as exc:
            if first is None:first=exc
            failures.append({'caseId':case['caseId'], 'auditReadinessReason':str(exc),
                **{key:report[key] for key in ('reasonCodes','detail','orchestrationFailure','requirementStagingFailure')
                   if isinstance(report,dict) and report.get(key)}})
    if first is not None:
        status.update(independentAuditDisposition={'status':'not_run','reasonCode':str(first)},
            upstreamFailures=failures,executionComplete=False,
            independentResultAuditComplete=False,productionAcceptanceComplete=False)
        raise first
