"""Original formal evaluation after a checked finite API task.

This is orchestration and attribution, not another translator or approval gate.
Finite API observations and official project test cases remain separate scopes.
A checked failed/inconclusive evaluation is terminal, never retried to get a pass.
"""
from pathlib import Path
from . import native_api_campaign as campaign
from . import native_original_evaluation as evaluation
from . import native_project_evaluation as project
from . import native_captured_deployment as d
from .native_external_providers import checked
from .native_original_corpus import lock
from .native_verifier_manifest import current, compare
from .project_acquisition import publish_checked
from .verification_session import measured

INPUT = 'riscv2x86.original-api-assessment-input.v1'
RESULT = 'riscv2x86.original-api-assessment.v1'


def context(preflight_path, campaign_path=None):
    preflight_ref = d.snapshot(preflight_path)
    preflight = campaign.check_preflight(preflight_path)
    spec_ref = preflight['project']; d.verify_snapshot(spec_ref)
    spec = d.read(spec_ref['path'])
    prefix = d.read(Path(preflight_path).resolve().parent / 'diagnostic/preparation/progress.json')
    applicability = prefix['checkpoints']['applicability']; d.verify_snapshot(applicability)
    runtime_ref = None; l2_ref = None
    if campaign_path is not None:
        runtime_ref = d.snapshot(campaign_path)
        value = campaign.check(campaign_path)
        if value['plan'] != preflight['plan'] or value['request'] != preflight['request']:
            raise ValueError('API_ASSESSMENT_RUNTIME_PREFLIGHT_MISMATCH')
        l2_ref = value['originalProjectL2']; d.verify_snapshot(l2_ref)
    elif preflight['selection']['runtimeAcquisitionRecommended']:
        raise ValueError('API_ASSESSMENT_ORIGINAL_RUNTIME_ATTEMPT_REQUIRED')
    if d.read(applicability['path'])['project'] != spec_ref:
        raise ValueError('API_ASSESSMENT_APPLICABILITY_PROJECT_MISMATCH')
    for ref in (preflight_ref, spec_ref, applicability, spec['run']):
        d.verify_snapshot(ref)
    return preflight, spec, d.seal({
        'schemaVersion': INPUT, 'verifier': current(), 'preflight': preflight_ref,
        'project': spec_ref, 'applicability': applicability, 'run': spec['run'],
        'apiCampaign': runtime_ref, 'apiL2': l2_ref,
    }, 'apiAssessmentInputIdentity')


def check_inputs(path):
    value = d.read(path); checked(value, 'apiAssessmentInputIdentity')
    compare(value['verifier'], current())
    for key in ('preflight', 'project', 'applicability', 'run', 'apiCampaign', 'apiL2'):
        if value[key] is not None: d.verify_snapshot(value[key])
    expected = context(value['preflight']['path'],
                       value['apiCampaign']['path'] if value['apiCampaign'] else None)[2]
    if value != expected:
        raise ValueError('API_ASSESSMENT_INPUT_REDERIVATION_MISMATCH')
    return value


def request_arguments(inputs):
    return {'api_l2_result': inputs['apiL2']['path'] if inputs['apiL2'] else None}


def layer_accounting(facts, required_levels):
    """Report unexecuted levels explicitly; never synthesize prior-layer passes."""
    rows = []
    for attempt in facts['attempts']:
        levels = [row['level'] for row in attempt['layers']]
        if len(set(levels)) != len(levels) or any(level not in required_levels for level in levels):
            raise ValueError('API_ASSESSMENT_LAYER_ACCOUNTING_INVALID')
        rows.append({'attemptArtifactId': attempt['attemptArtifactId'],
                     'fragmentId': attempt['fragmentId'], 'status': attempt['status'],
                     'reasonCodes': attempt['reasonCodes'], 'layers': attempt['layers'],
                     'unexecutedRequiredLevels': [level for level in required_levels if level not in levels],
                     'obligationAssessment': attempt.get('obligationAssessment')})
    return rows


@measured('native_api_assessment.derive')
def derive(root, reference):
    root = Path(root).resolve(); inputs = check_inputs(root / 'inputs.json')
    request_path = root / 'contracts/request.json'
    project.check_request(request_path, inputs['project']['path'], inputs['applicability']['path'],
                          **request_arguments(inputs))
    d.verify_snapshot(reference)
    folder = Path(reference['path']).parent
    if folder.parent != root / 'evaluations' or not folder.name.isdecimal():
        raise ValueError('API_ASSESSMENT_EVALUATION_LOCATION_INVALID')
    value = evaluation.check(reference['path'])
    if (value['inputs']['run'] != inputs['run']
            or value['inputs']['requestTemplate'] != d.snapshot(request_path)):
        raise ValueError('API_ASSESSMENT_EVALUATION_BINDING_MISMATCH')
    preflight = d.read(inputs['preflight']['path'])
    spec = d.read(inputs['project']['path'])
    required = value['readiness']['requiredLevels']; facts = value['facts']
    body = {
        'schemaVersion': RESULT, 'inputs': d.snapshot(root / 'inputs.json'),
        'request': d.snapshot(request_path), 'evaluation': reference,
        'originalEvaluationInvoked': value['originalEvaluationInvoked'],
        'evaluationStatus': facts['evaluationStatus'], 'reasonCodes': facts['reasonCodes'],
        'requiredLevels': required, 'attempts': layer_accounting(facts, required),
        'unexecutedRequiredLevelsWithoutAttempts': list(required) if not facts['attempts'] else [],
        'readiness': value['readiness'],
        'finiteApiScope': {
            'functionBindingIdentity': preflight['functionBindingIdentity'],
            'caseCount': preflight['caseCount'],
            'runtimeAttemptAvailable': inputs['apiCampaign'] is not None,
            'scope': 'finite-API-inputs-not-official-project-test-domain',
        },
        'projectTestScope': {'projectEvaluationIdentity': spec['projectEvaluationIdentity'],
                             'caseIds': [case['caseId'] for case in spec['cases']],
                             'scope': 'recorded-project-test-cases-not-finite-API-inputs'},
        'recordCheckComplete': True,
        'independentProgramAuditPerformed': value['independentProgramAuditPerformed'],
        'semanticApproval': False, 'productionAcceptanceComplete': False,
        'scope': 'original-evaluator-invocation-and-record-check-not-program-semantic-approval',
    }
    d.verify_snapshot(reference)
    d.verify_snapshot(inputs['project'])
    return d.seal(body, 'apiAssessmentIdentity')


def check(path):
    path = Path(path).resolve(); value = d.read(path); checked(value, 'apiAssessmentIdentity')
    if value != derive(path.parent, value['evaluation']):
        raise ValueError('API_ASSESSMENT_REDERIVATION_MISMATCH')
    return value


def acquire(preflight_path, output, *, campaign_path=None, resume=False):
    _, _, expected = context(preflight_path, campaign_path)
    requested = Path(output).absolute()
    if requested.is_symlink(): raise ValueError('API_ASSESSMENT_OUTPUT_LINK_UNSUPPORTED')
    root = requested.resolve()
    if not resume: root.mkdir(parents=True, exist_ok=False)
    if not root.is_dir(): raise ValueError('API_ASSESSMENT_OUTPUT_REQUIRED')
    with lock(root):
        if resume:
            if check_inputs(root / 'inputs.json') != expected:
                raise ValueError('API_ASSESSMENT_RESUME_CHANGED')
        else:
            publish_checked(root / 'inputs.json', expected, check_inputs)
        if (root / 'result.json').is_file(): return check(root / 'result.json')
        request_path = root / 'contracts/request.json'
        if request_path.exists():
            project.check_request(request_path, expected['project']['path'],
                                  expected['applicability']['path'], **request_arguments(expected))
        else:
            # Partial request publication is not reusable authority.
            if (root / 'contracts').exists():
                raise ValueError('API_ASSESSMENT_PARTIAL_REQUEST_REQUIRES_FRESH_ATTEMPT')
            project.request(expected['project']['path'], root / 'contracts',
                            expected['applicability']['path'], **request_arguments(expected))
        parent = root / 'evaluations'; parent.mkdir(exist_ok=True)
        folders = sorted(p for p in parent.iterdir() if p.is_dir() and p.name.isdecimal())
        for folder in folders:
            if (folder / 'result.json').is_file():
                reference = d.snapshot(folder / 'result.json')
                value = derive(root, reference)
                publish_checked(root / 'result.json', value, check)
                return value
        number = max((int(p.name) for p in folders), default=-1) + 1
        folder = parent / ('%06d' % number)
        evaluation.acquire(expected['run']['path'], request_path, folder)
        value = derive(root, d.snapshot(folder / 'result.json'))
        publish_checked(root / 'result.json', value, check)
        return value


def complete(preflight_path, output, *, resume=False):
    """Finish the SAME original API campaign if required, then evaluate."""
    preflight = campaign.check_preflight(preflight_path)
    runtime = None
    if preflight['selection']['runtimeAcquisitionRecommended']:
        root = Path(preflight_path).resolve().parent
        plan = campaign.check_plan(preflight['plan']['path'])
        campaign.execute(plan['configuration']['path'], plan['domain']['path'],
                         plan['functionAstPath'], [r['path'] for r in plan['assumptionSources']],
                         root, resume=True)
        runtime = root / 'result.json'
    return acquire(preflight_path, output, campaign_path=runtime, resume=resume)
