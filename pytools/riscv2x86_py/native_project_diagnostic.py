"""Resumable diagnostic scheduling over ORIGINAL translation/project producers.

No matrix subset is called L0 and no finite process agreement is called L1.
Independent acquisition branches continue after a failure, preserving every
planned obligation and every selected case. Formal evaluation remains original.
"""
from pathlib import Path
import math
import time

from . import native_captured_deployment as d
from . import native_project_campaign as campaign
from . import native_project_evaluation as project
from . import program_machine_inventory as machines
from .native_external_providers import checked
from .native_original_corpus import lock
from .project_acquisition import publish, publish_checked
from .translation_validation import ProgramArtifact

PLAN = 'riscv2x86.original-project-diagnostic-plan.v1'
PROGRESS = 'riscv2x86.original-project-diagnostic-progress.v1'
NODE = 'riscv2x86.original-project-diagnostic-node.v1'
PREFIX = ('original', 'project', 'applicability')


def make_plan(base, case_indices=None):
    campaign.validate_plan(base)
    indices = [0] if case_indices is None else case_indices
    if (not isinstance(indices, list) or not indices or indices != sorted(set(indices))
            or any(type(i) is not int or not 0 <= i < len(base['cases']) for i in indices)):
        raise ValueError('DIAGNOSTIC_EXPLICIT_CASE_SELECTION_INVALID')
    return d.seal({'schemaVersion': PLAN, 'basePlan': base, 'caseIndices': indices,
                   'scope': 'diagnostic-acquisition-not-formal-validation',
                   'semanticApproval': False, 'productionAcceptanceComplete': False}, 'diagnosticPlanIdentity')


def validate_plan(plan):
    checked(plan, 'diagnosticPlanIdentity')
    if plan != make_plan(plan['basePlan'], plan['caseIndices']): raise ValueError('DIAGNOSTIC_PLAN_CHANGED')
    return plan


def graph(plan):
    pair = ['source-build', 'target-build']
    return {'preparation': [], 'source-build': ['preparation'], 'target-build': ['preparation'],
            'machine-inventory': pair,
            **{'case-%06d' % i: pair for i in plan['caseIndices']}}


def files(root):
    return [d.snapshot(p) for p in sorted(Path(root).rglob('*')) if p.is_file()]


def program(row):
    ref = row['program']
    return ProgramArtifact(row['side'], ref['path'], 'executable', ref['digest'])


class Context:
    """A single check's verified upstream context; never a cross-run cache."""
    def __init__(self, root, plan, checkpoints):
        self.root = root; self.plan = plan; self.cp = checkpoints; self.prefix = None
        self.spec_path = None; self.spec = None; self.builds = {}
        if 'preparation' in checkpoints: self.load_prefix()

    def load_prefix(self):
        self.prefix = campaign.check_progress(self.root / 'preparation/progress.json')
        frozen = d.read(self.prefix['plan']['path'])
        if frozen != self.plan['basePlan']: raise ValueError('DIAGNOSTIC_PREFIX_PLAN_MISMATCH')
        if not all(s in self.prefix['checkpoints'] for s in PREFIX):
            raise ValueError('DIAGNOSTIC_ORIGINAL_PREFIX_REQUIRED')
        self.spec_path = self.prefix['checkpoints']['project']['path']
        self.spec = project.check(self.spec_path)


def node_facts(stage, folder, ctx):
    if stage == 'preparation':
        if ctx.prefix is None: raise ValueError('DIAGNOSTIC_PREFIX_REQUIRED')
        return {'prefixCheckpoints': {s: ctx.prefix['checkpoints'][s] for s in PREFIX}}
    if ctx.spec is None: raise ValueError('DIAGNOSTIC_PROJECT_REQUIRED')
    if stage in ('source-build', 'target-build'):
        side = stage.split('-')[0]; ref = d.snapshot(folder / 'program.project/result.json')
        build = d.read(ref['path']); actual = project.build_record(program(build), ctx.spec, side)
        if actual != build or actual['program']['path'] != str(folder / 'program'):
            raise ValueError('DIAGNOSTIC_BUILD_LOCATION_OR_BINDING_INVALID')
        ctx.builds[side] = actual
        return {'project': d.snapshot(ctx.spec_path), 'build': ref, 'files': files(folder / 'program.project')}
    if set(ctx.builds) != {'source', 'target'}: raise ValueError('DIAGNOSTIC_BOTH_BUILDS_REQUIRED')
    if stage == 'machine-inventory':
        ref = d.snapshot(folder / 'work/result.json'); value = machines.check(ref['path'])
        expected = {s: d.snapshot(Path(b['program']['path']).parent / 'program.project/result.json') for s, b in ctx.builds.items()}
        if value['project'] != d.snapshot(ctx.spec_path) or value['builds'] != expected:
            raise ValueError('DIAGNOSTIC_MACHINE_BUILD_BINDING_INVALID')
        return {'inventory': ref, 'files': files(folder / 'work')}
    index = int(stage.removeprefix('case-'))
    value = project.rederive_observations(ctx.spec, program(ctx.builds['source']), program(ctx.builds['target']),
                                         folder / 'work', [index])
    if d.read(folder / 'work/observations.json') != value: raise ValueError('DIAGNOSTIC_OBSERVATION_REDERIVATION_MISMATCH')
    return {'project': d.snapshot(ctx.spec_path),
            'builds': {s: d.snapshot(Path(b['program']['path']).parent / 'program.project/result.json') for s, b in ctx.builds.items()},
            'observation': value, 'files': files(folder / 'work')}


def node_value(stage, folder, ctx):
    return d.seal({'schemaVersion': NODE, 'stage': stage, 'diagnosticPlanIdentity': ctx.plan['diagnosticPlanIdentity'],
                   'facts': node_facts(stage, folder, ctx), 'formalValidationPerformed': False,
                   'semanticApproval': False, 'productionAcceptanceComplete': False}, 'diagnosticNodeIdentity')


def check_node(path, stage, ctx):
    value = d.read(path); checked(value, 'diagnosticNodeIdentity')
    if value != node_value(stage, Path(path).parent, ctx): raise ValueError('DIAGNOSTIC_NODE_REDERIVATION_MISMATCH')
    return value


def blocked(plan, cp):
    return {s: [d for d in deps if d not in cp] for s, deps in graph(plan).items()
            if s not in cp and any(d not in cp for d in deps)}


def _checked_progress(path):
    path = Path(path).resolve(strict=True); root = path.parent
    state = d.read(path); checked(state, 'stateIdentity')
    if (set(state) != {'schemaVersion', 'plan', 'checkpoints', 'attempts', 'status', 'blocked',
                       'formalValidationPerformed', 'semanticApproval', 'productionAcceptanceComplete', 'stateIdentity'}
            or state['schemaVersion'] != PROGRESS or state['status'] not in ('running', 'paused', 'failed', 'complete')
            or any(state[k] is not False for k in ('formalValidationPerformed', 'semanticApproval', 'productionAcceptanceComplete'))):
        raise ValueError('DIAGNOSTIC_PROGRESS_SCHEMA_INVALID')
    d.verify_snapshot(state['plan']); plan = validate_plan(d.read(state['plan']['path']))
    if state['plan']['path'] != str(root / 'diagnostic-plan.json'): raise ValueError('DIAGNOSTIC_PLAN_LOCATION_INVALID')
    cp = state['checkpoints']; stages = graph(plan)
    if not isinstance(cp, dict) or set(cp) - set(stages) or not isinstance(state['attempts'], list):
        raise ValueError('DIAGNOSTIC_CHECKPOINT_SET_INVALID')
    if state['blocked'] != blocked(plan, cp): raise ValueError('DIAGNOSTIC_BLOCKED_NODES_MISMATCH')
    completed = set()
    for i, attempt in enumerate(state['attempts']):
        if (set(attempt) != {'index', 'stage', 'directory', 'status', 'failure', 'elapsedSeconds'}
                or attempt['index'] != i or attempt['stage'] not in stages
                or attempt['directory'] != str(root / 'attempts' / ('%06d-%s' % (i, attempt['stage'])))
                or attempt['status'] not in ('running', 'interrupted', 'failed', 'complete')):
            raise ValueError('DIAGNOSTIC_ATTEMPT_INVALID')
        if attempt['stage'] in completed: raise ValueError('DIAGNOSTIC_HISTORY_AFTER_CHECKPOINT')
        if any(dep not in completed for dep in stages[attempt['stage']]):
            raise ValueError('DIAGNOSTIC_HISTORY_DEPENDENCY_MISSING')
        if attempt['status'] == 'complete': completed.add(attempt['stage'])
        elapsed = attempt['elapsedSeconds']
        if (elapsed is not None and (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0)
                or attempt['status'] in ('failed', 'complete') and elapsed is None):
            raise ValueError('DIAGNOSTIC_ATTEMPT_TIMING_INVALID')
        if attempt['status'] == 'failed':
            failure = attempt['failure']
            if not isinstance(failure, dict) or set(failure) != {'type', 'detail'} or any(not isinstance(v, str) for v in failure.values()):
                raise ValueError('DIAGNOSTIC_FAILURE_INVALID')
        elif attempt['failure'] is not None: raise ValueError('DIAGNOSTIC_UNEXPECTED_FAILURE')
        if attempt['status'] == 'complete' and cp.get(attempt['stage'], {}).get('path') != str(Path(attempt['directory']) / 'result.json'):
            raise ValueError('DIAGNOSTIC_UNBOUND_COMPLETE_ATTEMPT')
    if state['status'] == 'failed' and not any(a['status'] == 'failed' and a['stage'] not in cp for a in state['attempts']):
        raise ValueError('DIAGNOSTIC_FAILURE_WITHOUT_UNRESOLVED_ERROR')
    ctx = Context(root, plan, cp)
    for stage, deps in stages.items():
        if stage not in cp: continue
        if any(dep not in cp for dep in deps): raise ValueError('DIAGNOSTIC_CHECKPOINT_DEPENDENCY_MISSING')
        owners = [a for a in state['attempts'] if a['stage'] == stage and a['status'] == 'complete'
                  and cp[stage]['path'] == str(Path(a['directory']) / 'result.json')]
        if len(owners) != 1: raise ValueError('DIAGNOSTIC_CHECKPOINT_OWNER_REQUIRED')
        d.verify_snapshot(cp[stage])
        if Path(cp[stage]['path']).is_symlink() or not Path(cp[stage]['resolvedPath']).is_relative_to(root / 'attempts'):
            raise ValueError('DIAGNOSTIC_CHECKPOINT_PATH_INVALID')
        check_node(cp[stage]['path'], stage, ctx)
    if state['status'] == 'complete' and set(cp) != set(stages): raise ValueError('DIAGNOSTIC_COMPLETION_WITHOUT_ALL_NODES')
    if state['status'] == 'failed' and set(cp) == set(stages): raise ValueError('DIAGNOSTIC_FAILURE_WITH_ALL_NODES')
    return state, ctx


def check_progress(path):
    return _checked_progress(path)[0]


def acquire_node(stage, folder, ctx):
    if stage == 'preparation':
        child = ctx.root / 'preparation'
        if (child / 'progress.json').exists():
            campaign.execute(ctx.plan['basePlan'], child, resume=True, stop_after='applicability')
        else: campaign.execute(ctx.plan['basePlan'], child, stop_after='applicability')
        # Snapshot only immutable prefix receipts, permitting later ORIGINAL
        # formal continuation without invalidating diagnostic evidence.
        ctx.load_prefix()
    elif stage in ('source-build', 'target-build'):
        side = stage.split('-')[0]
        run = d.read(ctx.prefix['checkpoints']['original']['path'])
        if side == 'source': inp = d.read(run['input']['path'])['source']['path']
        else:
            translated = d.read(run['translation']['path'])
            # This layout is checked by the ORIGINAL materializer/replay, and
            # build_side additionally verifies the exact current input digest.
            inp = str(Path(translated['candidateManifest']['resolvedPath']).parent / 'candidate-staging/input.i')
        project.build_side(ctx.spec_path, side, inp, folder / 'program')
    elif stage == 'machine-inventory':
        (folder / 'work').mkdir(); machines.acquire(ctx.spec_path, ctx.builds, folder / 'work/result.json')
    else:
        for side, build in ctx.builds.items(): project.build_record(program(build), ctx.spec, side)
        (folder / 'work').mkdir()
        project.observe(ctx.spec, program(ctx.builds['source']), program(ctx.builds['target']), folder / 'work',
                        case_indices=[int(stage.removeprefix('case-'))])
        for side, build in ctx.builds.items(): project.build_record(program(build), ctx.spec, side)
    value = node_value(stage, folder, ctx)
    publish_checked(folder / 'result.json', value, lambda p: check_node(p, stage, ctx))


def execute(plan, output, *, resume=False, stop_after=None):
    validate_plan(plan); stages = graph(plan)
    if stop_after is not None and stop_after not in stages: raise ValueError('DIAGNOSTIC_STOP_STAGE_INVALID')
    requested = Path(output).absolute()
    if requested.is_symlink(): raise ValueError('DIAGNOSTIC_OUTPUT_LINK_UNSUPPORTED')
    root = requested.resolve()
    if not resume: root.mkdir(parents=True, exist_ok=False)
    with lock(root):
        progress = root / 'progress.json'
        if resume:
            state, ctx = _checked_progress(progress)
            if d.read(state['plan']['path']) != plan: raise ValueError('DIAGNOSTIC_RESUME_PLAN_CHANGED')
            if state['status'] == 'complete' or stop_after in state['checkpoints']: return state
            state.pop('stateIdentity')
            for row in state['attempts']:
                if row['status'] == 'running': row['status'] = 'interrupted'
        else:
            publish_checked(root / 'diagnostic-plan.json', plan, lambda p: validate_plan(d.read(p)))
            (root / 'attempts').mkdir()
            state = {'schemaVersion': PROGRESS, 'plan': d.snapshot(root / 'diagnostic-plan.json'), 'checkpoints': {},
                     'attempts': [], 'status': 'running', 'blocked': blocked(plan, {}),
                     'formalValidationPerformed': False, 'semanticApproval': False, 'productionAcceptanceComplete': False}
            publish(progress, state)
            ctx = Context(root, plan, state['checkpoints'])
        if state['status'] == 'complete' or stop_after in state['checkpoints']: return check_progress(progress)
        state['status'] = 'running'; cp = state['checkpoints']
        # Resume verified all prior receipts once above. New receipts are
        # individually checked before publication, then fully checked at exit.
        for stage, deps in stages.items():
            if stage in cp or any(dep not in cp for dep in deps): continue
            index = len(state['attempts']); folder = root / 'attempts' / ('%06d-%s' % (index, stage)); folder.mkdir()
            row = {'index': index, 'stage': stage, 'directory': str(folder), 'status': 'running', 'failure': None, 'elapsedSeconds': None}
            state['attempts'].append(row); state['blocked'] = blocked(plan, cp); publish(progress, state)
            start = time.monotonic()
            try:
                acquire_node(stage, folder, ctx); cp[stage] = d.snapshot(folder / 'result.json'); row['status'] = 'complete'
            except Exception as exc:
                row.update(status='failed', failure={'type': type(exc).__name__, 'detail': str(exc)})
            row['elapsedSeconds'] = time.monotonic() - start
            state['blocked'] = blocked(plan, cp); publish(progress, state)
            if stage == stop_after:
                state['status'] = 'paused' if row['status'] == 'complete' else 'failed'
                publish(progress, state); return check_progress(progress)
        state['status'] = 'complete' if set(cp) == set(stages) else 'failed'
        state['blocked'] = blocked(plan, cp); publish(progress, state); return check_progress(progress)


def resume_campaign(output):
    # The canonical plan is validated again and every receipt is checked under
    # the execute lock. Avoid a redundant full evidence walk before that lock.
    return execute(d.read(Path(output).resolve() / 'diagnostic-plan.json'), output, resume=True)


def facts(state):
    plan = d.read(state['plan']['path']); cp = state['checkpoints']
    selected = plan['caseIndices']; observations = []; inventory_gaps = []
    latest = {a['stage']: a for a in state['attempts']}
    if 'machine-inventory' in cp:
        ref = d.read(cp['machine-inventory']['path'])['facts']['inventory']
        inventory_gaps = [{'side': row['side'], 'functionAstPath': row['functionAstPath'], 'reasonCodes': row['reasonCodes']}
                          for row in d.read(ref['path'])['facts']['functions'] if row['reasonCodes']]
    for index in selected:
        stage = 'case-%06d' % index
        if stage in cp: observations.append(d.read(cp[stage]['path'])['facts']['observation'])
    pending = []; readiness = None; instance_applicability = None
    if 'preparation' in cp:
        prefix = d.read(cp['preparation']['path'])['facts']['prefixCheckpoints']
        pending = d.read(prefix['project']['path'])['gaps']
        app = d.read(prefix['applicability']['path']); readiness = app['layerReadiness']; instance_applicability = app['facts']
    return {'status': state['status'], 'diagnosticAcquisitionComplete': state['status'] == 'complete',
            'completedStages': list(cp), 'uncompletedStages': [s for s in graph(plan) if s not in cp],
            'blockedStages': state['blocked'],
            'acquisitionFailures': [{**a, 'resolved': a['stage'] in cp} for a in state['attempts'] if a['status'] == 'failed'],
            'currentAcquisitionFailures': [a for s, a in latest.items() if a['status'] == 'failed' and s not in cp],
            'originalProjectInputCount': 1, 'plannedCaseCount': len(plan['basePlan']['cases']), 'selectedCaseIndices': selected,
            'unselectedCaseIndices': [i for i in range(len(plan['basePlan']['cases'])) if i not in selected],
            'observedCaseCount': sum(len(o['cases']) for o in observations), 'observations': observations,
            'machineFactGaps': inventory_gaps, 'machineInventoryAcquired': 'machine-inventory' in cp,
            'instanceApplicability': instance_applicability, 'attemptCount': len(state['attempts']), 'unresolvedProgramObligations': pending, 'originalLayerReadiness': readiness,
            'operationTimings': [{k: a[k] for k in ('index', 'stage', 'status', 'elapsedSeconds')} for a in state['attempts']],
            'resultPaths': {s: r['path'] for s, r in cp.items()}, 'formalMatrixCellsExecuted': 0,
            'formalValidationPerformed': False, 'semanticApproval': False, 'productionAcceptanceComplete': False,
            'scope': 'selected-real-project-diagnostics-not-L0-L1-L2-L3-acceptance'}


def continue_formal(output):
    root = Path(output).resolve(strict=True)
    with lock(root):
        state = check_progress(root / 'progress.json')
        if 'preparation' not in state['checkpoints']: raise ValueError('DIAGNOSTIC_PREPARATION_REQUIRED_FOR_FORMAL')
        return campaign.resume_campaign(root / 'preparation')
