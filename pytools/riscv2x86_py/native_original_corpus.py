"""Bounded, resumable corpus scheduling of the ORIGINAL pipeline/evaluator.

All planned seeds stay in the denominator. No source names, ISA instruction
strings, or historical native integer candidates select an alternate route.
"""
from collections import Counter
from contextlib import contextmanager
import fcntl
from pathlib import Path
import tempfile

from . import native_captured_deployment as d
from . import native_original_pipeline as route
from . import native_original_evaluation as evaluation
from .native_external_providers import checked
from .native_verifier_manifest import current, compare
from .project_acquisition import publish, publish_checked

INPUT = 'riscv2x86.native-original-corpus-input.v1'
PLAN = 'riscv2x86.native-original-corpus-plan.v1'
RESULT = 'riscv2x86.native-original-corpus-progress.v1'


def freeze(input_path, output):
    raw = d.read(input_path)
    if (not isinstance(raw, dict) or set(raw) != {'schemaVersion', 'seeds'}
            or raw['schemaVersion'] != INPUT or not isinstance(raw['seeds'], list) or not raw['seeds']):
        raise ValueError('ORIGINAL_CORPUS_INPUT_INVALID')
    rows = []; names = set()
    for seed in raw['seeds']:
        if (not isinstance(seed, dict) or set(seed) != {'seedId', 'bundlePath', 'requestPath'}
                or not isinstance(seed['seedId'], str) or not seed['seedId']
                or seed['seedId'] in names or not isinstance(seed['bundlePath'], str)
                or not seed['bundlePath']):
            raise ValueError('ORIGINAL_CORPUS_SEED_INVALID')
        names.add(seed['seedId'])
        # No seedId is used as a filesystem path.
        row = {'seedId': seed['seedId'], 'bundle': d.snapshot(seed['bundlePath']),
               'requestTemplate': None, 'requestContracts': {}}
        if seed['requestPath'] is not None:
            if not isinstance(seed['requestPath'], str) or not seed['requestPath']:
                raise ValueError('ORIGINAL_CORPUS_REQUEST_PATH_INVALID')
            row['requestTemplate'] = d.snapshot(seed['requestPath'])
            row['requestContracts'], _ = evaluation.contracts(seed['requestPath'])
        rows.append(row)
    body = {'schemaVersion': PLAN, 'verifier': current(), 'seeds': rows,
            'plannedSeedCount': len(rows), 'semanticApproval': False,
            'productionAcceptanceComplete': False}
    value = d.seal(body, 'originalCorpusPlanIdentity')
    publish_checked(output, value, check_plan)
    return value


def check_plan(path):
    value = d.read(path); checked(value, 'originalCorpusPlanIdentity')
    compare(value['verifier'], current())
    if (value['schemaVersion'] != PLAN or not value['seeds']
            or value['plannedSeedCount'] != len(value['seeds'])
            or len({s['seedId'] for s in value['seeds']}) != len(value['seeds'])
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('ORIGINAL_CORPUS_PLAN_INVALID')
    for seed in value['seeds']:
        d.verify_snapshot(seed['bundle'])
        if seed['requestTemplate'] is not None:
            d.verify_snapshot(seed['requestTemplate'])
            refs, _ = evaluation.contracts(seed['requestTemplate']['path'])
            if refs != seed['requestContracts']:
                raise ValueError('ORIGINAL_CORPUS_REQUEST_CONTRACT_CHANGED')
        elif seed['requestContracts']:
            raise ValueError('ORIGINAL_CORPUS_UNBOUND_REQUEST_CONTRACT')
    return value


def counts(rows):
    return dict(sorted(Counter(row['status'] for row in rows).items()))


def outcome_counts(rows):
    # Expanded attempts, not seeds or dependency compilation contexts.
    return dict(sorted(Counter(outcome for row in rows for outcome in row['translationOutcomes']).items()))


def record_translation(row, path):
    translated = route.check_translation(path)
    row.update(translation=d.snapshot(path), translationOutcomes=translated['attemptOutcomes'])


def check_progress(path):
    value = d.read(path); checked(value, 'stateIdentity')
    compare(value['verifier'], current()); d.verify_snapshot(value['plan'])
    plan = check_plan(value['plan']['path'])
    if (value['schemaVersion'] != RESULT or len(value['records']) != plan['plannedSeedCount']
            or value['statusCounts'] != counts(value['records'])
            or value['attemptOutcomeCounts'] != outcome_counts(value['records'])
            or value['allSeedsProcessed'] != all(r['status'] not in ('not_run', 'running') for r in value['records'])
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('ORIGINAL_CORPUS_PROGRESS_INVALID')
    for seed, row in zip(plan['seeds'], value['records']):
        if row['seedId'] != seed['seedId']:
            raise ValueError('ORIGINAL_CORPUS_DENOMINATOR_CHANGED')
        for snapshot in row['failureFiles']: d.verify_snapshot(snapshot)
        if row['translation'] is not None:
            d.verify_snapshot(row['translation'])
            translated = route.check_translation(row['translation']['path'])
            prepared = route.check_input(translated['input']['path'])
            if (prepared['bundle'] != seed['bundle']
                    or row['translationOutcomes'] != translated['attemptOutcomes']):
                raise ValueError('ORIGINAL_CORPUS_TRANSLATION_SEED_MISMATCH')
        elif row['translationOutcomes']:
            raise ValueError('ORIGINAL_CORPUS_TRANSLATION_RECEIPT_REQUIRED')
        run = None
        if row['run'] is not None:
            d.verify_snapshot(row['run']); run = route.check_run(row['run']['path'])
            if run['bundle'] != seed['bundle'] or row['translation'] != run['translation']:
                raise ValueError('ORIGINAL_CORPUS_RUN_SEED_MISMATCH')
        if row['evaluation'] is not None:
            d.verify_snapshot(row['evaluation']); ev = evaluation.check(row['evaluation']['path'])
            if (run is None or ev['inputs']['run'] != row['run']
                    or ev['inputs']['requestTemplate'] != seed['requestTemplate']
                    or row['status'] != 'evaluation_' + ev['facts']['evaluationStatus']):
                raise ValueError('ORIGINAL_CORPUS_EVALUATION_SEED_MISMATCH')
        elif row['status'].startswith('evaluation_'):
            raise ValueError('ORIGINAL_CORPUS_EVALUATION_RECEIPT_REQUIRED')
        elif row['status'] == 'translation_complete':
            if run is None or seed['requestTemplate'] is not None:
                raise ValueError('ORIGINAL_CORPUS_TRANSLATION_RESULT_INVALID')
        elif row['status'] not in ('not_run', 'running', 'blocked'):
            raise ValueError('ORIGINAL_CORPUS_STATUS_INVALID')
    return value


@contextmanager
def lock(root):
    with (root / 'scheduler.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('ORIGINAL_CORPUS_ALREADY_RUNNING') from exc
        try: yield
        finally: fcntl.flock(stream, fcntl.LOCK_UN)


def execute(plan_path, output, *, max_seeds=1, resume=False, retry_blocked=False,
            ghidra_install_dir=None, timeout=600):
    if type(max_seeds) is not int or max_seeds < 1:
        raise ValueError('ORIGINAL_CORPUS_BUDGET_INVALID')
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError('ORIGINAL_INPUT_TIMEOUT_INVALID')
    plan = check_plan(plan_path); plan_ref = d.snapshot(plan_path)
    root = Path(output).resolve()
    if not resume: root.mkdir(parents=True, exist_ok=False)
    elif not root.is_dir(): raise ValueError('ORIGINAL_CORPUS_RESUME_DIRECTORY_REQUIRED')
    with lock(root):
        progress = root / 'progress.json'
        if resume:
            state = check_progress(progress)
            if state['plan'] != plan_ref:
                raise ValueError('ORIGINAL_CORPUS_RESUME_PLAN_CHANGED')
            state.pop('stateIdentity')
        else:
            state = {'schemaVersion': RESULT, 'verifier': current(), 'plan': plan_ref,
                     'records': [{'seedId': seed['seedId'], 'status': 'not_run',
                                  'translation': None, 'translationOutcomes': [],
                                  'run': None, 'evaluation': None, 'error': None,
                                  'failureFiles': []} for seed in plan['seeds']],
                     'semanticApproval': False, 'productionAcceptanceComplete': False}
        def save():
            state['statusCounts'] = counts(state['records'])
            state['attemptOutcomeCounts'] = outcome_counts(state['records'])
            state['allSeedsProcessed'] = all(r['status'] not in ('not_run', 'running') for r in state['records'])
            publish(progress, state)
        # A process interruption never authorizes directory-based reuse.
        # Only fully checked child receipts already recorded above may be reused.
        for row in state['records']:
            if row['status'] == 'running':
                row.update(status='blocked', error={'type': 'InterruptedRun', 'detail': 'explicit retry required'})
        save(); budget = max_seeds
        for index, (seed, row) in enumerate(zip(plan['seeds'], state['records'])):
            if budget == 0: break
            if row['status'] != 'not_run' and not (retry_blocked and row['status'] == 'blocked'): continue
            budget -= 1
            # Keep all old attempts. A retry starts in a new exclusive directory.
            attempt = Path(tempfile.mkdtemp(prefix=f'seed-{index:06d}-', dir=root))
            row.update(status='running', error=None); save()
            try:
                if row['run'] is None:
                    route.run(seed['bundle']['path'], attempt / 'original-run',
                              ghidra_install_dir=ghidra_install_dir, timeout=timeout)
                    record_translation(row, attempt / 'original-run/translation/result.json')
                    row['run'] = d.snapshot(attempt / 'original-run/result.json'); save()
                if seed['requestTemplate'] is None:
                    row['status'] = 'translation_complete'
                else:
                    ev = evaluation.acquire(row['run']['path'], seed['requestTemplate']['path'], attempt / 'evaluation')
                    row.update(evaluation=d.snapshot(attempt / 'evaluation/result.json'),
                               status='evaluation_' + ev['facts']['evaluationStatus'])
            except Exception as exc:
                row.update(status='blocked', error={'type': type(exc).__name__, 'detail': str(exc)})
                partial = attempt / 'original-run/translation/result.json'
                if partial.is_file():
                    try: record_translation(row, partial)
                    except Exception as capture_error:
                        row['error']['translationCaptureError'] = str(capture_error)
                # Preserve diagnostics, including all partial acquisition results.
                row['failureFiles'].extend(evaluation.inventory(attempt))
            finally:
                save()
        return check_progress(progress)
