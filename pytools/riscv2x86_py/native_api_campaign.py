"""One-command, resumable finite API experiments using ORIGINAL producers.

No alternate translator or layer approval algorithm. Preparation is the existing
original campaign, comparison is original L1, L2 readiness is its original
consumer, and final program obligations remain separate from finite API claims.
"""
from pathlib import Path
from . import native_captured_deployment as d
from . import native_project_campaign as campaign
from . import native_project_diagnostic as diagnostic
from . import native_original_api as api
from . import native_api_evidence as evidence
from . import native_project_evaluation as project
from .native_external_providers import checked
from .native_original_corpus import lock
from .native_verifier_manifest import current, compare
from .project_acquisition import publish_checked
from .verification_session import measured

PLAN = 'riscv2x86.original-api-campaign-plan.v1'
RESULT = 'riscv2x86.original-api-campaign-result.v1'


def inputs(configuration, domain, function_path, sources):
    if (not isinstance(function_path, list) or not function_path
            or any(type(i) is not int or i < 0 for i in function_path)):
        raise ValueError('API_CAMPAIGN_FUNCTION_PATH_INVALID')
    if not sources: raise ValueError('API_CAMPAIGN_ASSUMPTION_SOURCES_REQUIRED')
    return d.seal({'schemaVersion': PLAN, 'configuration': d.snapshot(configuration),
                   'domain': d.snapshot(domain), 'functionAstPath': function_path,
                   'assumptionSources': [d.snapshot(p) for p in sources], 'verifier': current()}, 'apiCampaignPlanIdentity')


def check_plan(path):
    value = d.read(path); checked(value, 'apiCampaignPlanIdentity'); compare(value['verifier'], current())
    if set(value) != {'schemaVersion', 'configuration', 'domain', 'functionAstPath', 'assumptionSources',
                      'verifier', 'apiCampaignPlanIdentity'} or value['schemaVersion'] != PLAN:
        raise ValueError('API_CAMPAIGN_PLAN_INVALID')
    expected = inputs(value['configuration']['path'], value['domain']['path'], value['functionAstPath'],
                      [r['path'] for r in value['assumptionSources']])
    if value != expected: raise ValueError('API_CAMPAIGN_INPUT_CHANGED')
    return value


def request_matches(spec, request_path, plan):
    _, request, selected, _, _ = api.request_context(spec, request_path)
    _request_matches(request, selected, plan)


def _request_matches(request, selected, plan):
    if (selected['functionAstPath'] != plan['functionAstPath']
            or request['domain'] != d.read(plan['domain']['path'])
            or request['assumptionSources'] != plan['assumptionSources']):
        raise ValueError('API_CAMPAIGN_REQUEST_MISMATCH')


@measured('native_api_campaign.derive')
def derive(root, result_ref):
    root = Path(root).resolve(); plan = check_plan(root / 'plan.json')
    spec, _, applicability = api.from_progress(root / 'diagnostic/progress.json', with_applicability=True)
    d.verify_snapshot(result_ref)
    consumption, value = evidence.inspect_with_result(result_ref['path'])
    # The API checker just validated this request and selection against its
    # recorded input snapshots; compare policy without traversing that DAG again.
    _request_matches(d.read(root / 'request.json'), value['function'], plan)
    attempt = Path(result_ref['path']).parent
    if attempt.parent != root / 'attempts' or not attempt.name.isdecimal():
        raise ValueError('API_CAMPAIGN_RESULT_LOCATION_INVALID')
    recorded_inputs = d.read(attempt / 'inputs.json')
    if recorded_inputs['spec'] != d.snapshot(spec) or recorded_inputs['request'] != d.snapshot(root / 'request.json'):
        raise ValueError('API_CAMPAIGN_EXECUTION_BINDING_MISMATCH')
    from .program_validation_obligations import original_layer_readiness
    readiness = original_layer_readiness(d.read(spec))
    body = {'schemaVersion': RESULT, 'plan': d.snapshot(root / 'plan.json'), 'result': result_ref,
            'request': d.snapshot(root / 'request.json'),
            'completedStages': ['original-preparation-and-audit', 'input-contract', 'api-execution', 'independent-check'],
            'caseCount': value['caseCount'], 'processObservationStatus': value['processObservationStatus'],
            'bodyLinkAttributionComplete': value['bodyLinkAttributionComplete'],
            'linkAttributedObservationStatus': value['linkAttributedObservationStatus'],
            'instanceApplicability': applicability,
            'evidenceConsumption': consumption, 'originalLayerReadiness': readiness,
            'formalMatrixCellsExecuted': 0, 'formalValidationPerformed': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False,
            'scope': 'finite-api-campaign-not-complete-L0-L1-L2-L3'}
    check_plan(root / 'plan.json')
    d.verify_snapshot(result_ref)
    return d.seal(body, 'apiCampaignIdentity')


def replay(previous_result, output):
    """Use old campaign inputs as selectors, never as current evidence.

    A fresh output, current verifier, original preparation/translation/audit,
    link commands and execution are mandatory. Old success flags are ignored.
    """
    reference = d.snapshot(previous_result)
    previous = d.read(reference['path']); checked(previous, 'apiCampaignIdentity')
    if previous.get('schemaVersion') != RESULT:
        raise ValueError('API_REPLAY_PREVIOUS_CAMPAIGN_REQUIRED')
    d.verify_snapshot(previous['plan'])
    plan = d.read(previous['plan']['path']); checked(plan, 'apiCampaignPlanIdentity')
    if plan.get('schemaVersion') != PLAN:
        raise ValueError('API_REPLAY_PREVIOUS_PLAN_REQUIRED')
    # No old verifier authority is carried into the new campaign. Nevertheless
    # require the original selector files to remain exactly those recorded.
    for row in (plan['configuration'], plan['domain'], *plan['assumptionSources']):
        d.verify_snapshot(row)
    d.verify_snapshot(reference)
    return execute(plan['configuration']['path'], plan['domain']['path'], plan['functionAstPath'],
                   [r['path'] for r in plan['assumptionSources']], output)


def check(path):
    path = Path(path).resolve(); value = d.read(path); checked(value, 'apiCampaignIdentity')
    if value != derive(path.parent, value['result']):
        raise ValueError('API_CAMPAIGN_REDERIVATION_MISMATCH')
    return value


def execute(configuration, domain, function_path, sources, output, *, resume=False):
    plan = inputs(configuration, domain, function_path, sources)
    requested = Path(output).absolute()
    if requested.is_symlink(): raise ValueError('API_CAMPAIGN_OUTPUT_LINK_UNSUPPORTED')
    root = requested.resolve()
    if not resume: root.mkdir(parents=True, exist_ok=False)
    if not root.is_dir(): raise ValueError('API_CAMPAIGN_OUTPUT_REQUIRED')
    with lock(root):
        if resume:
            if check_plan(root / 'plan.json') != plan: raise ValueError('API_CAMPAIGN_RESUME_CHANGED')
        else:
            publish_checked(root / 'plan.json', plan, check_plan)
        if (root / 'result.json').is_file(): return check(root / 'result.json')
        if (root / 'diagnostic/progress.json').is_file():
            diagnostic.execute(d.read(root / 'diagnostic/diagnostic-plan.json'), root / 'diagnostic',
                               resume=True, stop_after='preparation')
        else:
            mode, base, _ = campaign.replan_configuration(configuration)
            if mode != 'diagnostic': base = diagnostic.make_plan(base)
            diagnostic.execute(base, root / 'diagnostic', stop_after='preparation')
        spec, builds = api.from_progress(root / 'diagnostic/progress.json')
        if not (root / 'request.json').exists():
            api.create_request(spec, domain, function_path, sources, root / 'request.json')
        request_matches(spec, root / 'request.json', plan)
        attempts = root / 'attempts'; attempts.mkdir(exist_ok=True)
        folders = sorted(p for p in attempts.iterdir() if p.is_dir())
        for folder in folders:
            if (folder / 'result.json').is_file():
                value = derive(root, d.snapshot(folder / 'result.json'))
                publish_checked(root / 'result.json', value, check)
                return value
        # Reuse only successfully completed, independently checked body builds
        # from failed API attempts; never overwrite failed command logs.
        for folder in folders:
            for side in api.SIDES:
                ref = folder / (side + '-baseline.project/result.json')
                if ref.is_file():
                    row = d.read(ref); artifact = row['program']
                    from .translation_validation import ProgramArtifact
                    project.build_record(ProgramArtifact(side, artifact['path'], 'executable', artifact['digest']),
                                         project.check(spec), side)
                    builds[side] = str(ref)
        target = attempts / ('%06d' % len(folders))
        api.acquire(spec, root / 'request.json', target, builds=builds)
        value = derive(root, d.snapshot(target / 'result.json'))
        publish_checked(root / 'result.json', value, check)
        return value
