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
from . import native_project_l2 as project_l2
from .native_external_providers import checked
from .native_original_corpus import lock
from .native_verifier_manifest import current, compare
from .project_acquisition import publish_checked
from .verification_session import measured

PLAN = 'riscv2x86.original-api-campaign-plan.v1'
RESULT = 'riscv2x86.original-api-campaign-result.v1'
PREFLIGHT = 'riscv2x86.original-api-preflight.v1'


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


def l2_attempt(root, api_reference, *, acquire=False):
    """Retain failed attempts; checking never executes or repairs a stage."""
    root = Path(root)
    prefix = d.read(root / 'diagnostic/preparation/progress.json')
    applicability = prefix['checkpoints']['applicability']
    d.verify_snapshot(applicability)
    folders = sorted((root / 'l2-attempts').glob('*'))
    for folder in reversed(folders):
        if not (folder / 'result.json').is_file(): continue
        inputs = d.read(folder / 'inputs.json')
        if inputs['apiResult'] != api_reference or inputs['applicability'] != applicability: continue
        return d.snapshot(folder / 'result.json'), project_l2.check(folder / 'result.json')
    if not acquire: raise ValueError('API_CAMPAIGN_ORIGINAL_L2_ATTEMPT_REQUIRED')
    parent = root / 'l2-attempts'; parent.mkdir(exist_ok=True)
    output = parent / ('%06d' % len(folders))
    value = project_l2.acquire(api_reference['path'], applicability['path'], output)
    return d.snapshot(output / 'result.json'), value


@measured('native_api_campaign.derive')
def derive(root, result_ref):
    root = Path(root).resolve(); plan = check_plan(root / 'plan.json')
    spec, _, applicability = api.from_progress(root / 'diagnostic/progress.json', with_applicability=True)
    d.verify_snapshot(result_ref)
    consumption, value = evidence.inspect_with_result(result_ref['path'])
    l2_reference, l2 = l2_attempt(root, result_ref)
    consumption['claims'].append({
        'kind': 'original-logical-operands-under-finite-typed-entry',
        'status': 'checked' if l2['originalLogicalOperandsVerified'] else 'inconclusive',
        'evidence': l2_reference,
        'scope': 'original-operand-dimension-not-all-applicable-effects-or-canonical-coverage'})
    for row in l2['instances']:
        compiler = row.get('detail', {}).get('compilerEliminationEvidence')
        if compiler is not None:
            consumption['claims'].append({
                'kind': 'compiler-final-RTL-inline-asm-absence',
                'status': 'observed' if compiler['compilerInlineAsmAbsenceObserved'] else 'inconclusive',
                'fragmentId': row['fragmentId'], 'evidence': compiler['receipt'],
                'scope': compiler['scope']})
        erasure = row.get('detail', {}).get('instanceErasureEvidence')
        if erasure is not None and erasure.get('receipt'):
            consumption['claims'].append({
                'kind': 'source-excluded-instance-object-erasure-invariance',
                'status': 'observed' if erasure['objectErasureInvariant'] else 'inconclusive',
                'fragmentId': row['fragmentId'], 'evidence': erasure['receipt'],
                'subject': erasure['subject'], 'scope': erasure['scope']})
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
    from .native_evaluation_coverage import from_spec
    coverage = from_spec(d.read(spec), applicability, l2)
    body = {'schemaVersion': RESULT, 'plan': d.snapshot(root / 'plan.json'), 'result': result_ref,
            'request': d.snapshot(root / 'request.json'),
            'completedStages': ['original-preparation-and-audit', 'input-contract', 'api-execution',
                                'original-L2-operand-attempt', 'independent-check'],
            'caseCount': value['caseCount'], 'processObservationStatus': value['processObservationStatus'],
            'bodyLinkAttributionComplete': value['bodyLinkAttributionComplete'],
            'linkAttributedObservationStatus': value['linkAttributedObservationStatus'],
            'instanceApplicability': applicability,
            'originalProjectL2': l2_reference,
            'originalLogicalOperandsVerified': l2['originalLogicalOperandsVerified'],
            'originalL2Instances': l2['instances'],
            'evidenceConsumption': consumption, 'originalLayerReadiness': readiness,
            'evaluationCoverage': coverage,
            'formalMatrixCellsExecuted': 0, 'formalValidationPerformed': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False,
            'scope': 'finite-api-campaign-not-complete-L0-L1-L2-L3'}
    check_plan(root / 'plan.json')
    d.verify_snapshot(result_ref)
    return d.seal(body, 'apiCampaignIdentity')


def replay(previous_result, output, *, stop_after=None):
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
                   [r['path'] for r in plan['assumptionSources']], output, stop_after=stop_after)


def check(path):
    path = Path(path).resolve(); value = d.read(path); checked(value, 'apiCampaignIdentity')
    if value != derive(path.parent, value['result']):
        raise ValueError('API_CAMPAIGN_REDERIVATION_MISMATCH')
    return value


def execute(configuration, domain, function_path, sources, output, *, resume=False, stop_after=None):
    if stop_after not in (None, 'preflight'):
        raise ValueError('API_CAMPAIGN_STOP_STAGE_INVALID')
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
        if stop_after == 'preflight' and (root / 'preflight.json').is_file():
            return check_preflight(root / 'preflight.json')
        if stop_after is None and (root / 'result.json').is_file(): return check(root / 'result.json')
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
        if stop_after == 'preflight':
            value = derive_preflight(root)
            publish_checked(root / 'preflight.json', value, check_preflight)
            return value
        # A preflight is a scheduler hint, never execution authority. A resumed
        # normal campaign still goes through the original API and L2 producers.
        attempts = root / 'attempts'; attempts.mkdir(exist_ok=True)
        folders = sorted(p for p in attempts.iterdir() if p.is_dir())
        for folder in folders:
            if (folder / 'result.json').is_file():
                reference = d.snapshot(folder / 'result.json')
                l2_attempt(root, reference, acquire=True)
                value = derive(root, reference)
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
        reference = d.snapshot(target / 'result.json')
        l2_attempt(root, reference, acquire=True)
        value = derive(root, reference)
        publish_checked(root / 'result.json', value, check)
        return value

def preflight_selection(selected, applicability):
    """Pure exact-instance join AFTER original request/applicability checking.

    An unknown or nonexcluded instance needs an execution attempt. Only a
    nonempty, complete, unambiguous set of checked source exclusions permits
    skipping runtime acquisition. This says nothing about machine elimination.
    """
    identities = selected['instanceBindingIdentities']
    if (not identities or any(not isinstance(i, str) or not i for i in identities)
            or len(set(identities)) != len(identities)):
        raise ValueError('API_PREFLIGHT_INSTANCE_SELECTION_INVALID')
    all_rows = applicability['instances']
    by_id = {r['instanceBindingIdentity']: r for r in all_rows}
    if len(by_id) != len(all_rows) or any(i not in by_id for i in identities):
        raise ValueError('API_PREFLIGHT_INSTANCE_JOIN_REQUIRED')
    rows = [by_id[i] for i in identities]
    excluded = [r['instanceBindingIdentity'] for r in rows
                if r['sourceGuardClassification'] == 'excluded-under-compiler-query-contracts'
                and r['unstructuredControlFlow'] is False]
    skip = len(excluded) == len(identities)
    return {
        'selectedInstanceIdentities': list(identities),
        'sourceExcludedInstanceIdentities': excluded,
        'unselectedInstanceIdentities': sorted(set(by_id) - set(identities)),
        'instances': rows,
        'disposition': ('all-selected-instances-source-excluded' if skip
                        else 'original-runtime-attempt-required'),
        'runtimeAcquisitionRecommended': not skip,
        'canonicalInstructionCoverageVerified': False,
        'machineEliminationVerified': False,
    }


@measured('native_api_campaign.preflight')
def derive_preflight(root):
    root = Path(root).resolve()
    plan = check_plan(root / 'plan.json')
    spec, _, facts = api.from_progress(root / 'diagnostic/progress.json', with_applicability=True)
    spec_ref = d.snapshot(spec); request_ref = d.snapshot(root / 'request.json')
    _, request, selected, _, _ = api.request_context(spec, request_ref['path'])
    _request_matches(request, selected, plan)
    selection = preflight_selection(selected, facts)
    from .native_evaluation_coverage import from_spec
    coverage = from_spec(d.read(spec), facts, {'instances': []})
    represented = [r['instanceBindingIdentity'] for r in coverage['findings']]
    for instance in selection['selectedInstanceIdentities']:
        if represented.count(instance) != 1:
            raise ValueError('API_PREFLIGHT_REPORT_INSTANCE_JOIN_REQUIRED')
    body = {'schemaVersion': PREFLIGHT, 'plan': d.snapshot(root / 'plan.json'),
            'project': spec_ref, 'request': request_ref,
            'functionBindingIdentity': selected['functionBindingIdentity'],
            'functionAstPath': selected['functionAstPath'],
            'selection': selection, 'reportCoverage': coverage,
            'caseCount': len(request['domain']['cases']),
            'runtimeAcquisitionPerformed': False,
            'formalValidationPerformed': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False,
            'scope': 'original-preparation-and-input-contract-not-execution-or-layer-acceptance'}
    check_plan(root / 'plan.json')
    d.verify_snapshot(spec_ref); d.verify_snapshot(request_ref)
    return d.seal(body, 'apiPreflightIdentity')


def check_preflight(path):
    path = Path(path).resolve()
    value = d.read(path); checked(value, 'apiPreflightIdentity')
    if value != derive_preflight(path.parent):
        raise ValueError('API_PREFLIGHT_REDERIVATION_MISMATCH')
    return value
