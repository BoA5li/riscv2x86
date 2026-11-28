"""Bounded API corpus adapter using only ORIGINAL campaign producers.

The task list is an explicit experiment denominator, not a semantic certificate.
Source-excluded tasks remain visible; failed tasks do not prevent other tasks
from running. Unknown applicability never authorizes skipping a runtime attempt.
"""
from collections import Counter
from pathlib import Path

from . import native_captured_deployment as d
from . import native_api_campaign as campaign
from .native_external_providers import checked
from .native_original_corpus import lock
from .project_acquisition import publish, publish_checked

INPUT = 'riscv2x86.original-api-corpus-input.v1'
PLAN = 'riscv2x86.original-api-corpus-plan.v1'
PROGRESS = 'riscv2x86.original-api-corpus-progress.v1'
EVALUATION_PLAN = 'riscv2x86.original-api-corpus-plan.v2'
EVALUATION_PROGRESS = 'riscv2x86.original-api-corpus-progress.v2'


def make_plan(input_path, *, evaluate=False):
    reference = d.snapshot(input_path); raw = d.read(reference['path'])
    if (not isinstance(raw, dict) or set(raw) != {'schemaVersion', 'tasks'}
            or raw['schemaVersion'] != INPUT or not isinstance(raw['tasks'], list) or not raw['tasks']):
        raise ValueError('API_CORPUS_INPUT_INVALID')
    rows = []; names = set(); selectors = set()
    for task in raw['tasks']:
        if (not isinstance(task, dict) or set(task) != {
                'taskId', 'configuration', 'domain', 'functionAstPath', 'assumptionSources'}
                or not isinstance(task['taskId'], str) or not task['taskId']
                or task['taskId'] in names or not isinstance(task['assumptionSources'], list)):
            raise ValueError('API_CORPUS_TASK_INVALID')
        names.add(task['taskId'])
        paths = [task['configuration'], task['domain'], *task['assumptionSources']]
        if any(not isinstance(p, str) or not Path(p).is_absolute() for p in paths):
            raise ValueError('API_CORPUS_ABSOLUTE_SELECTOR_PATH_REQUIRED')
        plan = campaign.inputs(task['configuration'], task['domain'], task['functionAstPath'],
                               task['assumptionSources'])
        # Renaming the same task cannot inflate the experimental denominator.
        key = (plan['configuration']['digest'], plan['domain']['digest'],
               tuple(plan['functionAstPath']), tuple(r['digest'] for r in plan['assumptionSources']))
        if key in selectors:
            raise ValueError('API_CORPUS_DUPLICATE_SELECTORS')
        selectors.add(key)
        rows.append({'taskId': task['taskId'], 'campaignPlan': plan})
    d.verify_snapshot(reference)
    return d.seal({'schemaVersion': EVALUATION_PLAN if evaluate else PLAN,
                   'input': reference, 'tasks': rows}, 'apiCorpusPlanIdentity')


def check_plan(path):
    value = d.read(path); checked(value, 'apiCorpusPlanIdentity')
    d.verify_snapshot(value['input'])
    if value['schemaVersion'] not in (PLAN, EVALUATION_PLAN):
        raise ValueError('API_CORPUS_PLAN_SCHEMA_INVALID')
    if value != make_plan(value['input']['path'], evaluate=value['schemaVersion'] == EVALUATION_PLAN):
        raise ValueError('API_CORPUS_PLAN_CHANGED')
    return value


def attempt_root(root, index, number):
    if type(number) is not int or number < 0:
        raise ValueError('API_CORPUS_ATTEMPT_INVALID')
    return root / 'tasks' / ('%06d' % index) / ('%06d' % number)


def row_facts(root, index, task, row):
    if set(row) != {'taskId', 'attempt', 'preflight', 'result', 'failure'} or row['taskId'] != task['taskId']:
        raise ValueError('API_CORPUS_TASK_ACCOUNTING_CHANGED')
    if row['attempt'] is None:
        if any(row[k] is not None for k in ('preflight', 'result', 'failure')):
            raise ValueError('API_CORPUS_ATTEMPT_REQUIRED')
        return 'not_run'
    folder = attempt_root(root, index, row['attempt'])
    for key, name in (('preflight', 'preflight.json'), ('result', 'result.json'), ('failure', 'failure.json')):
        if row[key] is not None:
            d.verify_snapshot(row[key])
            if row[key] != d.snapshot(folder / name):
                raise ValueError('API_CORPUS_CHILD_LOCATION_CHANGED')
    preflight = None
    if row['preflight'] is not None:
        preflight = campaign.check_preflight(row['preflight']['path'])
        if d.read(preflight['plan']['path']) != task['campaignPlan']:
            raise ValueError('API_CORPUS_PREFLIGHT_TASK_MISMATCH')
    if row['result'] is not None:
        value = campaign.check(row['result']['path'])
        if preflight is None or d.read(value['plan']['path']) != task['campaignPlan']:
            raise ValueError('API_CORPUS_RESULT_TASK_MISMATCH')
        if preflight['request'] != value['request'] or row['failure'] is not None:
            raise ValueError('API_CORPUS_RESULT_BINDING_CHANGED')
        return 'runtime-observation-' + value['linkAttributedObservationStatus']
    if row['failure'] is not None:
        failure = d.read(row['failure']['path'])
        if (set(failure) != {'errorType', 'detail', 'scope'}
                or failure['scope'] != 'acquisition-diagnostic-not-validation-evidence'):
            raise ValueError('API_CORPUS_FAILURE_DIAGNOSTIC_INVALID')
        return 'blocked'
    if preflight is None:
        return 'pending'
    if preflight['selection']['runtimeAcquisitionRecommended'] is False:
        return 'source-excluded'
    return 'pending'


def assessed_row_facts(root, index, task, row):
    from . import native_api_assessment as assessment
    if set(row) != {'taskId', 'attempt', 'preflight', 'result', 'failure', 'assessment'}:
        raise ValueError('API_CORPUS_ASSESSED_RECORD_INVALID')
    base = {k: v for k, v in row.items() if k != 'assessment'}
    failure = base['failure']; base['failure'] = None
    status = row_facts(root, index, task, base)
    if failure is not None:
        if row['assessment'] is not None:
            raise ValueError('API_CORPUS_ASSESSMENT_FAILURE_CONFLICT')
        # Formal acquisition may fail after a valid finite API result.
        row_facts(root, index, task, dict(base, result=None, failure=failure))
        return 'blocked'
    if row['assessment'] is None:
        return 'not_run' if row['attempt'] is None else 'pending'
    if status in ('not_run', 'pending'):
        raise ValueError('API_CORPUS_ASSESSMENT_PREREQUISITES_REQUIRED')
    folder = attempt_root(root, index, row['attempt'])
    d.verify_snapshot(row['assessment'])
    if row['assessment'] != d.snapshot(folder / 'assessment/result.json'):
        raise ValueError('API_CORPUS_ASSESSMENT_LOCATION_CHANGED')
    value = assessment.check(row['assessment']['path'])
    inputs = d.read(value['inputs']['path'])
    if inputs['preflight'] != row['preflight'] or inputs['apiCampaign'] != row['result']:
        raise ValueError('API_CORPUS_ASSESSMENT_TASK_MISMATCH')
    prefix = 'source-excluded-evaluated-' if status == 'source-excluded' else 'evaluated-'
    return prefix + value['evaluationStatus']


def derive(root, records):
    root = Path(root).resolve(); plan = check_plan(root / 'plan.json')
    if not isinstance(records, list) or len(records) != len(plan['tasks']):
        raise ValueError('API_CORPUS_DENOMINATOR_CHANGED')
    evaluate = plan['schemaVersion'] == EVALUATION_PLAN
    checker = assessed_row_facts if evaluate else row_facts
    statuses = [checker(root, i, task, row)
                for i, (task, row) in enumerate(zip(plan['tasks'], records))]
    return summary(d.snapshot(root / 'plan.json'), records, statuses, evaluate=evaluate)


def summary(plan_reference, records, statuses, *, evaluate=False):
    """Checkpoint diagnostics only; check_progress always rechecks children."""
    return {'schemaVersion': EVALUATION_PROGRESS if evaluate else PROGRESS, 'plan': plan_reference,
            'records': records, 'taskStatuses': statuses,
            'plannedTaskCount': len(records), 'statusCounts': dict(sorted(Counter(statuses).items())),
            'allTasksAccounted': all(s not in ('not_run', 'pending') for s in statuses),
            'runtimeObservedTaskCount': (sum(r['result'] is not None for r in records) if evaluate
                                         else sum(s.startswith('runtime-observation-') for s in statuses)),
            'canonicalInstructionCoverageVerified': False,
            'formalValidationPerformed': bool(evaluate and any(r['assessment'] is not None for r in records)),
            'semanticApproval': False, 'productionAcceptanceComplete': False,
            'scope': 'explicit-original-api-task-list-not-complete-corpus-or-layer-acceptance'}


def check_progress(path):
    path = Path(path).resolve(); value = d.read(path); checked(value, 'stateIdentity')
    body = {k: v for k, v in value.items() if k != 'stateIdentity'}
    if body != derive(path.parent, value['records']):
        raise ValueError('API_CORPUS_PROGRESS_REDERIVATION_MISMATCH')
    return value


def execute(input_path, output, *, max_tasks=1, resume=False, retry_blocked=False, evaluate=False):
    if type(max_tasks) is not int or max_tasks < 1:
        raise ValueError('API_CORPUS_BUDGET_INVALID')
    expected = make_plan(input_path, evaluate=evaluate)
    requested = Path(output).absolute()
    if requested.is_symlink():
        raise ValueError('API_CORPUS_OUTPUT_LINK_UNSUPPORTED')
    root = requested.resolve()
    if not resume: root.mkdir(parents=True, exist_ok=False)
    if not root.is_dir(): raise ValueError('API_CORPUS_OUTPUT_REQUIRED')
    with lock(root):
        if resume:
            if check_plan(root / 'plan.json') != expected:
                raise ValueError('API_CORPUS_RESUME_PLAN_CHANGED')
            previous = check_progress(root / 'progress.json')
            records = previous['records']; statuses = previous['taskStatuses']
        else:
            publish_checked(root / 'plan.json', expected, check_plan)
            records = [{'taskId': t['taskId'], 'attempt': None,
                        'preflight': None, 'result': None, 'failure': None} for t in expected['tasks']]
            if evaluate:
                for row in records: row['assessment'] = None
            statuses = ['not_run'] * len(records)
        plan_reference = d.snapshot(root / 'plan.json')
        def save():
            # Producer-returned diagnostic state is checkpointed without
            # recursively checking ALL earlier tasks at every transition.
            # It never grants authority: final return and every independent
            # check reconstruct the whole list with fresh original checkers.
            publish(root / 'progress.json', summary(plan_reference, records, statuses, evaluate=evaluate))
        save(); budget = max_tasks
        # Decisions are freshly checked, not taken from a caller-supplied flag.
        for index, (task, row) in enumerate(zip(expected['tasks'], records)):
            if budget == 0: break
            status = statuses[index]
            if status not in ('not_run', 'pending') and not (retry_blocked and status == 'blocked'):
                continue
            budget -= 1
            if status != 'pending':
                parent = root / 'tasks' / ('%06d' % index); parent.mkdir(parents=True, exist_ok=True)
                numbers = [int(p.name) for p in parent.iterdir() if p.name.isdecimal()]
                row.update(attempt=max(numbers, default=-1) + 1, preflight=None, result=None, failure=None)
                if evaluate: row['assessment'] = None
            folder = attempt_root(root, index, row['attempt'])
            # Recover a diagnostic published just before an interruption. It
            # blocks the task; it cannot grant execution or semantic authority.
            if status == 'pending' and (folder / 'failure.json').is_file():
                row['failure'] = d.snapshot(folder / 'failure.json')
                statuses[index] = 'blocked'; save()
                continue
            statuses[index] = 'pending'; save()
            plan = task['campaignPlan']
            args = (plan['configuration']['path'], plan['domain']['path'], plan['functionAstPath'],
                    [r['path'] for r in plan['assumptionSources']], folder)
            try:
                preflight = campaign.execute(*args, resume=folder.exists(), stop_after='preflight')
                row['preflight'] = d.snapshot(folder / 'preflight.json')
                statuses[index] = ('pending' if evaluate or preflight['selection']['runtimeAcquisitionRecommended']
                                   else 'source-excluded')
                save()
                if preflight['selection']['runtimeAcquisitionRecommended']:
                    value = campaign.execute(*args, resume=True)
                    row['result'] = d.snapshot(folder / 'result.json')
                    statuses[index] = 'runtime-observation-' + value['linkAttributedObservationStatus']
                if evaluate:
                    from . import native_api_assessment as assessment
                    value = assessment.acquire(row['preflight']['path'], folder / 'assessment',
                        campaign_path=row['result']['path'] if row['result'] else None,
                        resume=(folder / 'assessment').exists())
                    row['assessment'] = d.snapshot(folder / 'assessment/result.json')
                    prefix = ('source-excluded-evaluated-' if
                              not preflight['selection']['runtimeAcquisitionRecommended'] else 'evaluated-')
                    statuses[index] = prefix + value['evaluationStatus']
            except Exception as exc:
                # Preserve the original child directory and continue independent
                # tasks. An exception is never interpreted as inapplicability.
                folder.mkdir(parents=True, exist_ok=True)
                failure = {'errorType': type(exc).__name__, 'detail': str(exc),
                           'scope': 'acquisition-diagnostic-not-validation-evidence'}
                path = folder / 'failure.json'
                if path.exists(): raise ValueError('API_CORPUS_FAILURE_ALREADY_RECORDED') from exc
                campaign.project.write(path, failure)
                row['failure'] = d.snapshot(path)
                statuses[index] = 'blocked'
            save()
        return check_progress(root / 'progress.json')
