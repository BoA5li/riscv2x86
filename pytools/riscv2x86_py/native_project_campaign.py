"""Checked checkpoints for the ORIGINAL single-project workflow.

Only acquisition scheduling lives here. A checked incomplete/failed evaluation
is retained as a terminal result, never retried until it happens to pass.
"""
from copy import deepcopy
from pathlib import Path
import math
import time

from . import native_captured_deployment as d
from . import native_original_pipeline as route
from . import native_original_evaluation as evaluation
from . import native_project_evaluation as project
from . import native_original_applicability as applicability
from .native_original_corpus import lock
from .native_external_providers import checked
from .native_verifier_manifest import current, compare
from .ghidra_configuration import resolve_install_dir
from .project_acquisition import publish, publish_checked

PLAN = 'riscv2x86.original-project-campaign-plan.v2'
PROGRESS = 'riscv2x86.original-project-campaign-progress.v2'
STAGES = ('original', 'project', 'applicability', 'request', 'evaluation')


def make_plan(bundle, target_plan, records, *, qemu, runtime_prefix, cases,
              source_entry_action=None, ghidra_install_dir=None, timeout=600):
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError('PROJECT_CAMPAIGN_TIMEOUT_INVALID')
    if source_entry_action is not None and (not isinstance(source_entry_action, str) or not source_entry_action):
        raise ValueError('PROJECT_SOURCE_ENTRY_ACTION_INVALID')
    records = list(dict.fromkeys(str(Path(p).resolve(strict=True)) for p in records))
    if not records: raise ValueError('PROJECT_SOURCE_BUILD_RECORDS_REQUIRED')
    prefix = Path(runtime_prefix).resolve(strict=True)
    if not prefix.is_dir(): raise ValueError('PROJECT_RUNTIME_PREFIX_DIRECTORY_REQUIRED')
    install = resolve_install_dir(ghidra_install_dir)
    cli = Path(__file__).resolve().parents[2] / 'experiment/automate_native_project.py'
    return d.seal({'schemaVersion': PLAN, 'bundle': d.snapshot(bundle),
                   'targetPlan': d.snapshot(target_plan), 'sourceRecords': [d.snapshot(p) for p in records],
                   'qemu': d.snapshot(qemu), 'runtimePrefix': str(prefix),
                   'cases': deepcopy(project.validate_cases(cases)), 'timeoutSeconds': timeout,
                   'sourceEntryAction': source_entry_action, 'ghidraInstallDir': str(install),
                   'launcher': d.snapshot(install / 'support/pythonRun'), 'cli': d.snapshot(cli),
                   'verifier': current(), 'semanticApproval': False,
                   'productionAcceptanceComplete': False}, 'campaignPlanIdentity')


def validate_plan(plan):
    checked(plan, 'campaignPlanIdentity'); compare(plan['verifier'], current())
    if (set(plan) != {'schemaVersion', 'bundle', 'targetPlan', 'sourceRecords', 'qemu',
                     'runtimePrefix', 'cases', 'timeoutSeconds', 'sourceEntryAction',
                     'ghidraInstallDir', 'launcher', 'cli', 'verifier', 'semanticApproval',
                     'productionAcceptanceComplete', 'campaignPlanIdentity'}
            or plan['schemaVersion'] != PLAN or not plan['sourceRecords']
            or plan['semanticApproval'] is not False or plan['productionAcceptanceComplete'] is not False):
        raise ValueError('PROJECT_CAMPAIGN_PLAN_INVALID')
    for key in ('bundle', 'targetPlan', 'qemu', 'launcher', 'cli'): d.verify_snapshot(plan[key])
    for item in plan['sourceRecords']: d.verify_snapshot(item)
    project.validate_cases(plan['cases'])
    fresh = make_plan(plan['bundle']['path'], plan['targetPlan']['path'],
                      [r['path'] for r in plan['sourceRecords']], qemu=plan['qemu']['path'],
                      runtime_prefix=plan['runtimePrefix'], cases=plan['cases'],
                      source_entry_action=plan['sourceEntryAction'], ghidra_install_dir=plan['ghidraInstallDir'],
                      timeout=plan['timeoutSeconds'])
    if fresh != plan: raise ValueError('PROJECT_CAMPAIGN_PLAN_REDERIVATION_MISMATCH')
    return plan


def project_configuration(plan, run_path):
    return {'run_path': run_path, 'target_plan_path': plan['targetPlan']['resolvedPath'],
            'source_records': [r['path'] for r in plan['sourceRecords']], 'qemu': plan['qemu']['resolvedPath'],
            'runtime_prefix': plan['runtimePrefix'], 'cases': plan['cases'],
            'source_entry_action': plan['sourceEntryAction'], 'timeout': plan['timeoutSeconds']}


def check_progress(path):
    path = Path(path).resolve(strict=True); root = path.parent
    state = d.read(path); checked(state, 'stateIdentity')
    if (set(state) != {'schemaVersion', 'plan', 'checkpoints', 'attempts', 'status', 'currentStage',
                      'primaryFailure', 'evaluationStatus', 'semanticApproval',
                      'productionAcceptanceComplete', 'stateIdentity'}
            or state['schemaVersion'] != PROGRESS or state['status'] not in ('running', 'failed', 'paused', 'complete')
            or state['semanticApproval'] is not False or state['productionAcceptanceComplete'] is not False
            or not isinstance(state['checkpoints'], dict) or not isinstance(state['attempts'], list)):
        raise ValueError('PROJECT_CAMPAIGN_PROGRESS_INVALID')
    d.verify_snapshot(state['plan']); plan = validate_plan(d.read(state['plan']['path']))
    if state['plan']['path'] != str(root / 'campaign-plan.json'):
        raise ValueError('PROJECT_CAMPAIGN_PLAN_PATH_INVALID')
    cp = state['checkpoints']
    if set(cp) != set(STAGES[:len(cp)]): raise ValueError('PROJECT_CAMPAIGN_CHECKPOINT_ORDER_INVALID')
    for i, attempt in enumerate(state['attempts']):
        if (set(attempt) != {'index', 'stage', 'directory', 'status', 'failure', 'operationElapsedSeconds'}
                or attempt['index'] != i or attempt['stage'] not in STAGES
                or attempt['status'] not in ('running', 'complete', 'failed', 'interrupted')
                or attempt['directory'] != str(root / 'attempts' / ('%06d-%s' % (i, attempt['stage'])))):
            raise ValueError('PROJECT_CAMPAIGN_ATTEMPT_INVALID')
        elapsed = attempt['operationElapsedSeconds']
        if (elapsed is not None and (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0)
                or attempt['status'] in ('complete', 'failed') and elapsed is None):
            raise ValueError('PROJECT_CAMPAIGN_TIMING_INVALID')
        failure = attempt['failure']
        if attempt['status'] == 'failed':
            if (not isinstance(failure, dict) or set(failure) != {'stage', 'type', 'detail'}
                    or failure['stage'] != attempt['stage']
                    or not all(isinstance(failure[k], str) for k in ('type', 'detail'))):
                raise ValueError('PROJECT_CAMPAIGN_FAILURE_INVALID')
        elif failure is not None:
            raise ValueError('PROJECT_CAMPAIGN_UNEXPECTED_FAILURE')
    if state['status'] == 'failed':
        if (not state['attempts'] or state['attempts'][-1]['status'] != 'failed'
                or state['primaryFailure'] != state['attempts'][-1]['failure']):
            raise ValueError('PROJECT_CAMPAIGN_PRIMARY_FAILURE_MISMATCH')
    elif state['primaryFailure'] is not None:
        raise ValueError('PROJECT_CAMPAIGN_UNEXPECTED_PRIMARY_FAILURE')
    expected_stage = ('complete' if state['status'] == 'complete' else
                      state['attempts'][-1]['stage'] if state['attempts'] else 'initialization')
    if state['currentStage'] != expected_stage:
        raise ValueError('PROJECT_CAMPAIGN_CURRENT_STAGE_MISMATCH')
    stage_files = {'original': 'work/result.json', 'project': 'project.json',
                   'applicability': 'work/result.json', 'request': 'contracts/request.json', 'evaluation': 'work/result.json'}
    for attempt in state['attempts']:
        if attempt['status'] == 'complete':
            ref = cp.get(attempt['stage'])
            if ref is None or ref['path'] != str(Path(attempt['directory']) / stage_files[attempt['stage']]):
                raise ValueError('PROJECT_CAMPAIGN_ATTEMPT_CHECKPOINT_MISMATCH')
    for stage, ref in cp.items():
        owners = [a for a in state['attempts'] if a['stage'] == stage and a['status'] == 'complete'
                  and ref['path'] == str(Path(a['directory']) / stage_files[stage])]
        if len(owners) != 1: raise ValueError('PROJECT_CAMPAIGN_CHECKPOINT_OWNER_REQUIRED')
        if not Path(ref['path']).resolve().is_relative_to(root / 'attempts'):
            raise ValueError('PROJECT_CAMPAIGN_CHECKPOINT_PATH_INVALID')
        d.verify_snapshot(ref)
    if 'original' in cp:
        run = route.check_run(cp['original']['path'])
        if run['bundle'] != plan['bundle']: raise ValueError('PROJECT_CAMPAIGN_BUNDLE_MISMATCH')
    if 'project' in cp:
        spec = project.check(cp['project']['path'])
        if (spec['run'] != cp['original']
                or spec['configuration'] != project_configuration(plan, cp['original']['path'])):
            raise ValueError('PROJECT_CAMPAIGN_PROJECT_BINDING_MISMATCH')
    if 'applicability' in cp:
        app = applicability.check(cp['applicability']['path'])
        if app['project'] != cp['project']: raise ValueError('PROJECT_CAMPAIGN_APPLICABILITY_BINDING_MISMATCH')
    if 'request' in cp:
        project.check_request(cp['request']['path'], cp['project']['path'], cp['applicability']['path'])
    if 'evaluation' in cp:
        result = evaluation.check(cp['evaluation']['path'])
        if (result['inputs']['run'] != cp['original'] or result['inputs']['requestTemplate'] != cp['request']
                or state['evaluationStatus'] != result['facts']['evaluationStatus']):
            raise ValueError('PROJECT_CAMPAIGN_EVALUATION_BINDING_MISMATCH')
    elif state['evaluationStatus'] is not None:
        raise ValueError('PROJECT_CAMPAIGN_EVALUATION_RECEIPT_REQUIRED')
    if state['status'] == 'complete' and set(cp) != set(STAGES):
        raise ValueError('PROJECT_CAMPAIGN_COMPLETION_WITHOUT_RECEIPTS')
    return state


def execute(plan, output, *, resume=False, stop_after=None):
    if stop_after is not None and (resume or stop_after not in STAGES[:-1]):
        raise ValueError('PROJECT_STOP_AFTER_NEW_CAMPAIGN_STAGE_REQUIRED')
    validate_plan(plan)
    requested = Path(output).absolute()
    if requested.is_symlink(): raise ValueError('PROJECT_CAMPAIGN_OUTPUT_LINK_UNSUPPORTED')
    root = requested.resolve()
    if not resume: root.mkdir(parents=True, exist_ok=False)
    elif not root.is_dir(): raise ValueError('PROJECT_CAMPAIGN_RESUME_DIRECTORY_REQUIRED')
    with lock(root):
        progress = root / 'progress.json'
        if resume:
            state = check_progress(progress)
            if d.read(state['plan']['path']) != plan:
                raise ValueError('PROJECT_CAMPAIGN_RESUME_PLAN_CHANGED')
            state.pop('stateIdentity')
            # The only reuse authority is a previously committed, checked
            # checkpoint. A result file orphaned by interruption is not reused.
            for attempt in state['attempts']:
                if attempt['status'] == 'running': attempt['status'] = 'interrupted'
        else:
            publish_checked(root / 'campaign-plan.json', plan, lambda p: validate_plan(d.read(p)))
            (root / 'attempts').mkdir()
            state = {'schemaVersion': PROGRESS, 'plan': d.snapshot(root / 'campaign-plan.json'),
                     'checkpoints': {}, 'attempts': [], 'status': 'running', 'currentStage': 'initialization',
                     'primaryFailure': None, 'evaluationStatus': None,
                     'semanticApproval': False, 'productionAcceptanceComplete': False}
            publish(progress, state)
        if state['status'] == 'complete': return check_progress(progress)
        state.update(status='running', primaryFailure=None)
        for stage in STAGES:
            if stage in state['checkpoints']: continue
            index = len(state['attempts']); folder = root / 'attempts' / ('%06d-%s' % (index, stage))
            folder.mkdir()
            attempt = {'index': index, 'stage': stage, 'directory': str(folder), 'status': 'running', 'failure': None, 'operationElapsedSeconds': None}
            state['attempts'].append(attempt); state['currentStage'] = stage; publish(progress, state)
            cp = state['checkpoints']
            started = time.monotonic()
            try:
                validate_plan(plan)
                if stage == 'original':
                    route.run(plan['bundle']['path'], folder / 'work', ghidra_install_dir=plan['ghidraInstallDir'],
                              timeout=plan['timeoutSeconds'])
                    result = folder / 'work/result.json'
                    route.check_run(result)
                elif stage == 'project':
                    result = folder / 'project.json'
                    project.freeze(output=result, **project_configuration(plan, cp['original']['path']))
                elif stage == 'applicability':
                    applicability.acquire(cp['project']['path'], folder / 'work')
                    result = folder / 'work/result.json'
                elif stage == 'request':
                    result = project.request(cp['project']['path'], folder / 'contracts', cp['applicability']['path'])
                    project.check_request(result, cp['project']['path'], cp['applicability']['path'])
                else:
                    value = evaluation.acquire(cp['original']['path'], cp['request']['path'], folder / 'work')
                    result = folder / 'work/result.json'
                    state['evaluationStatus'] = value['facts']['evaluationStatus']
                validate_plan(plan)
                cp[stage] = d.snapshot(result); attempt['status'] = 'complete'
                attempt['operationElapsedSeconds'] = time.monotonic() - started
                publish(progress, state)
                check_progress(progress)
                if stage == stop_after:
                    state.update(status='paused'); publish(progress, state)
                    return check_progress(progress)
            except Exception as exc:
                # Failed acquisition cannot advance the checkpoint frontier.
                cp.pop(stage, None)
                if stage == 'evaluation': state['evaluationStatus'] = None
                failure = {'stage': stage, 'type': type(exc).__name__, 'detail': str(exc)}
                attempt.update(status='failed', failure=failure, operationElapsedSeconds=time.monotonic() - started)
                state.update(status='failed', primaryFailure=failure)
                publish(progress, state)
                raise
        state.update(status='complete', currentStage='complete')
        publish(progress, state); return check_progress(progress)


def resume_campaign(output):
    """Resume the pinned configuration; no hand reconstruction of CLI flags."""
    state = check_progress(Path(output).resolve() / 'progress.json')
    return execute(d.read(state['plan']['path']), output, resume=True)


def facts(state):
    original_facts = None
    if 'evaluation' in state['checkpoints']:
        ref = state['checkpoints']['evaluation']; d.verify_snapshot(ref)
        original_facts = d.read(ref['path'])['facts']
    return {'status': state['status'], 'completedStages': [s for s in STAGES if s in state['checkpoints']],
            'evaluationStatus': state['evaluationStatus'], 'primaryFailure': state['primaryFailure'],
            'resultPaths': {s: r['path'] for s, r in state['checkpoints'].items()},
            'originalEvaluation': original_facts,
            'operationTimings': [{k: a[k] for k in ('index', 'stage', 'status', 'operationElapsedSeconds')}
                                 for a in state['attempts']],
            'applicability': d.read(state['checkpoints']['applicability']['path'])['facts']
                             if 'applicability' in state['checkpoints'] else None,
            'attemptCount': len(state['attempts']), 'semanticApproval': False,
            'productionAcceptanceComplete': False}


def timing_report(path):
    """Read checked measurements. Overlapping scopes are not added together."""
    state = check_progress(path); result = {'operations': facts(state)['operationTimings'],
        'layers': [], 'commands': [],
        'scope': 'monotonic-wall-measurements-with-overlapping-scopes-not-sum-of-all-rows'}
    if 'evaluation' in state['checkpoints']:
        ref = state['checkpoints']['evaluation']; value = evaluation.check(ref['path'])
        for item in value['evaluationFiles']:
            name = Path(item['path']).name
            if name == 'phase-timings.json':
                measurement = d.read(item['path'])
                if measurement.get('schemaVersion') == 'riscv2x86.project-layer-timing.v1':
                    result['layers'].append({'path': item['path'], **measurement})
            elif name == 'execution.json':
                measurement = d.read(item['path'])
                if 'elapsedSeconds' in measurement:
                    project.validate_execution_record(measurement)
                    result['commands'].append({'path': item['path'], 'elapsedSeconds': measurement['elapsedSeconds'],
                        'returnCode': measurement['returnCode'], 'failureReason': measurement['failureReason']})
    return result
