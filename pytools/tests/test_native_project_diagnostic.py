"""Diagnostic DAG protocol fixtures; actual producers covered separately below.

Mocks here are not cross-ISA, full matrix, or real GMP validation evidence.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest
from riscv2x86_py import native_project_diagnostic as q
from riscv2x86_py import native_project_campaign as c, native_project_evaluation as p
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.project_acquisition import publish
from .test_native_project_campaign import campaign


@pytest.fixture
def diagnostic(campaign, monkeypatch):
    root, base, calls, fail, _, _ = campaign
    original_run = c.route.run; original_freeze = c.project.freeze; original_app = c.applicability.acquire
    def run(bundle, output, **kwargs):
        original_run(bundle, output, **kwargs)
        src = output / 'input.i'; src.write_text('fixture-source')
        prepared = output / 'input.json'; p.write(prepared, {'source': d.snapshot(src)})
        staging = output / 'candidate-staging'; staging.mkdir(); (staging / 'input.i').write_text('fixture-target')
        manifest = output / 'manifest.json'; p.write(manifest, {'fixture': True})
        translated = output / 'translation.json'; p.write(translated, {'candidateManifest': d.snapshot(manifest)})
        value = d.read(output / 'result.json'); value.update(input=d.snapshot(prepared), translation=d.snapshot(translated))
        p.write(output / 'result.json', value)
    def freeze(*, output, **kwargs):
        original_freeze(output=output, **kwargs)
        value = d.read(output); value.update(gaps=['fixture-unresolved-ABI'], projectEvaluationIdentity='fixture-project')
        p.write(output, value)
    def app(spec, output):
        original_app(spec, output)
        value = d.read(output / 'result.json'); value['layerReadiness'] = {'fixture': 'no-fake-L2-authority'}
        p.write(output / 'result.json', value)
    def attempted(stage):
        calls.append(stage)
        if fail.get(stage, 0): fail[stage] -= 1; raise RuntimeError('fixture failure: ' + stage)
    def build(spec, side, inp, output):
        attempted(side + '-build'); root = output.parent / 'program.project'; root.mkdir()
        output.write_text('fixture-' + side)
        p.write(root / 'result.json', {'side': side, 'program': d.snapshot(output)})
    def record(artifact, spec, side):
        value = d.read(Path(artifact.artifact_path).parent / 'program.project/result.json')
        d.verify_snapshot(value['program']); assert value['side'] == side
        return value
    def machine(spec, builds, file):
        attempted('machine-inventory')
        p.write(file, {'project': d.snapshot(spec),
                       'builds': {s: d.snapshot(Path(b['program']['path']).parent / 'program.project/result.json') for s, b in builds.items()},
                       'facts': {'functions': []}})
    def observe(spec, source, target, root, *, case_indices=None):
        attempted('case-%06d' % case_indices[0])
        p.write(root / 'observations.json', {'cases': [{'index': i} for i in case_indices], 'mismatches': []})
    monkeypatch.setattr(c.route, 'run', run); monkeypatch.setattr(c.project, 'freeze', freeze)
    monkeypatch.setattr(c.applicability, 'acquire', app)
    monkeypatch.setattr(p, 'build_side', build); monkeypatch.setattr(p, 'build_record', record)
    monkeypatch.setattr(q.machines, 'acquire', machine); monkeypatch.setattr(q.machines, 'check', lambda file: d.read(file))
    monkeypatch.setattr(p, 'observe', observe)
    monkeypatch.setattr(p, 'rederive_observations', lambda spec, src, tgt, root, indices: d.read(root / 'observations.json'))
    plan = q.make_plan(base)
    return root, plan, calls, fail


def test_diagnostic_has_no_formal_matrix_or_approval_and_is_terminal(diagnostic):
    root, plan, calls, _ = diagnostic
    value = q.execute(plan, root / 'diag')
    assert value['status'] == 'complete'
    assert calls == ['original', 'project', 'applicability', 'source-build', 'target-build', 'machine-inventory', 'case-000000']
    summary = q.facts(value)
    assert summary['formalMatrixCellsExecuted'] == 0 and not summary['formalValidationPerformed']
    assert not summary['semanticApproval'] and not summary['productionAcceptanceComplete']
    assert summary['unresolvedProgramObligations'] == ['fixture-unresolved-ABI']
    assert q.resume_campaign(root / 'diag') == value
    assert len(calls) == 7


def test_machine_failure_does_not_hide_independent_runtime_diagnosis(diagnostic):
    root, plan, calls, fail = diagnostic; fail['machine-inventory'] = 1
    first = q.execute(plan, root / 'diag')
    assert first['status'] == 'failed' and 'case-000000' in first['checkpoints']
    assert q.facts(first)['currentAcquisitionFailures'][0]['stage'] == 'machine-inventory'
    final = q.resume_campaign(root / 'diag')
    assert final['status'] == 'complete' and calls.count('case-000000') == 1
    assert calls.count('source-build') == 1 and calls.count('machine-inventory') == 2
    assert q.facts(final)['acquisitionFailures'][0]['resolved']


def test_source_failure_still_builds_target_and_retains_blocked_nodes(diagnostic):
    root, plan, calls, fail = diagnostic; fail['source-build'] = 1
    first = q.execute(plan, root / 'diag')
    assert 'target-build' in first['checkpoints'] and 'source-build' not in first['checkpoints']
    assert first['blocked'] == {'machine-inventory': ['source-build'], 'case-000000': ['source-build']}
    final = q.resume_campaign(root / 'diag')
    assert final['status'] == 'complete' and calls.count('target-build') == 1


def test_prefix_retry_stops_at_applicability_and_never_runs_formal_evaluation(diagnostic):
    root, plan, calls, fail = diagnostic; fail['project'] = 1
    first = q.execute(plan, root / 'diag')
    assert first['status'] == 'failed' and not first['checkpoints']
    final = q.resume_campaign(root / 'diag')
    assert final['status'] == 'complete' and calls.count('original') == 1
    assert 'request' not in calls and 'evaluation' not in calls


def test_formal_continuation_reuses_original_prefix_but_keeps_full_original_dispatch(diagnostic):
    root, plan, calls, _ = diagnostic
    initial = q.execute(plan, root / 'diag')
    formal = q.continue_formal(root / 'diag')
    assert formal['status'] == 'complete' and formal['evaluationStatus'] == 'inconclusive'
    assert calls[-2:] == ['request', 'evaluation'] and calls.count('original') == 1
    assert q.check_progress(root / 'diag/progress.json') == initial


def test_pause_and_failure_status_are_distinct(diagnostic):
    root, plan, calls, fail = diagnostic
    paused = q.execute(plan, root / 'diag', stop_after='source-build')
    assert paused['status'] == 'paused' and 'target-build' not in calls
    final = q.resume_campaign(root / 'diag'); assert final['status'] == 'complete'
    fail['source-build'] = 1
    failed = q.execute(plan, root / 'other', stop_after='source-build')
    assert failed['status'] == 'failed'


def test_all_planned_cases_stay_visible_and_selected_cases_are_checkpointed(diagnostic):
    root, plan, calls, _ = diagnostic
    base = deepcopy(plan['basePlan']); base['cases'] = p.gmp_cases([42, 43], 10)
    base = d.seal({k: v for k, v in base.items() if k != 'campaignPlanIdentity'}, 'campaignPlanIdentity')
    selected = q.make_plan(base, [1]); result = q.execute(selected, root / 'diag')
    value = q.facts(result)
    assert value['plannedCaseCount'] == 2 and value['unselectedCaseIndices'] == [0]
    assert value['selectedCaseIndices'] == [1] and value['observedCaseCount'] == 1
    assert calls[-1] == 'case-000001' and 'case-000000' not in calls


@pytest.mark.parametrize('indices', [[], [True], [-1], [1], [0, 0]])
def test_invalid_selection_is_not_silently_repaired(diagnostic, indices):
    _, plan, _, _ = diagnostic
    with pytest.raises(ValueError): q.make_plan(plan['basePlan'], indices)


def test_resealed_progress_cannot_drop_nodes_or_grant_approval(diagnostic):
    root, plan, _, _ = diagnostic; state = q.execute(plan, root / 'diag')
    path = root / 'diag/progress.json'
    body = {k: v for k, v in state.items() if k != 'stateIdentity'}
    body['semanticApproval'] = True; publish(path, body)
    with pytest.raises(ValueError, match='SCHEMA_INVALID'): q.check_progress(path)
    body['semanticApproval'] = False; del body['checkpoints']['case-000000']; publish(path, body)
    with pytest.raises(ValueError): q.check_progress(path)


def test_orphan_receipt_is_not_reused_after_interruption(diagnostic, monkeypatch):
    root, plan, calls, _ = diagnostic; acquire = q.acquire_node
    def interrupt(stage, *args):
        acquire(stage, *args)
        if stage == 'source-build': raise KeyboardInterrupt('fixture interrupted before checkpoint')
    monkeypatch.setattr(q, 'acquire_node', interrupt)
    with pytest.raises(KeyboardInterrupt): q.execute(plan, root / 'diag')
    assert 'source-build' not in q.check_progress(root / 'diag/progress.json')['checkpoints']
    monkeypatch.setattr(q, 'acquire_node', acquire)
    result = q.resume_campaign(root / 'diag')
    assert result['status'] == 'complete' and calls.count('source-build') == 2
    assert result['attempts'][1]['status'] == 'interrupted'


def test_changed_input_or_checked_artifact_cannot_resume(diagnostic):
    root, plan, _, _ = diagnostic; result = q.execute(plan, root / 'diag')
    artifact = d.read(result['checkpoints']['source-build']['path'])['facts']['build']
    Path(artifact['path']).write_text('changed')
    with pytest.raises(ValueError): q.resume_campaign(root / 'diag')


def test_cli_exposes_diagnostic_scope_check_resume_and_formal(diagnostic, capsys):
    root, plan, _, _ = diagnostic; base = plan['basePlan']
    spec = importlib.util.spec_from_file_location('diagnostic_cli', Path(__file__).resolve().parents[2] / 'experiment/automate_native_project.py')
    cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
    args = ['run', '--mode', 'diagnostic', '--bundle', base['bundle']['path'], '--target-plan', base['targetPlan']['path'],
            '--source-records', base['sourceRecords'][0]['path'], '--qemu', base['qemu']['path'], '--runtime-prefix', base['runtimePrefix'],
            '--gmp-seeds', '42', '--ghidra-install-dir', base['ghidraInstallDir'], '--output', str(root / 'cli')]
    assert cli.main(args) == 1
    assert '"formalValidationPerformed": false' in capsys.readouterr().out
    assert cli.main(['check', '--input', str(root / 'cli/progress.json')]) == 0
    assert cli.main(['resume', '--output', str(root / 'cli')]) == 1
    assert cli.main(['formal', '--output', str(root / 'cli')]) == 1


from .test_program_machine_inventory import machine_project
from .test_native_project_evaluation import toy_project
from .test_native_captured_deployment import captured


def test_real_native_diagnostic_builds_machine_facts_and_replay_with_ingress_mocked(campaign, machine_project, monkeypatch):
    """Real native ELFs and process observations; no executable RV/GMP claim."""
    from riscv2x86_py import native_experiment_driver as driver
    root, base, _, _, _, _ = campaign
    machine_root, specfile, spec, _, _ = machine_project
    run = spec['run']; translated = d.read(d.read(run['path'])['translation']['path'])
    stage = Path(translated['candidateManifest']['resolvedPath']).parent / 'candidate-staging'; stage.mkdir()
    source = Path(d.read(d.read(run['path'])['input']['path'])['source']['path'])
    (stage / 'input.i').write_bytes(source.read_bytes())
    app = machine_root / 'fixture-app.json'
    p.write(app, {'facts': {'editedInstanceCount': 1}, 'layerReadiness': {'fixture': 'ingress'}})
    base = d.seal({**{k: v for k, v in base.items() if k != 'campaignPlanIdentity'}, 'cases': deepcopy(spec['cases'])}, 'campaignPlanIdentity')
    plan = q.make_plan(base)
    def preparation(frozen, output, **kwargs):
        assert kwargs['stop_after'] == 'applicability'
        output.mkdir(); p.write(output / 'campaign-plan.json', frozen)
        value = {'plan': d.snapshot(output / 'campaign-plan.json'), 'checkpoints': {
            'original': run, 'project': d.snapshot(specfile), 'applicability': d.snapshot(app)}}
        p.write(output / 'progress.json', value); return value
    monkeypatch.setattr(c, 'execute', preparation)
    monkeypatch.setattr(c, 'check_progress', lambda file: d.read(file))
    execute = driver.command
    def native(argv, *args):
        return execute(argv[3:] if argv[:2] == ['/usr/bin/env', '-L'] else argv, *args)
    monkeypatch.setattr(driver, 'command', native)
    value = q.execute(plan, root / 'real-diag')
    assert value['status'] == 'complete', q.facts(value)
    summary = q.facts(value)
    assert summary['observedCaseCount'] == 1 and summary['machineInventoryAcquired']
    assert not summary['observations'][0]['mismatches'] and not summary['semanticApproval']
    case_ref = value['checkpoints']['case-000000']; case = d.read(case_ref['path'])
    # A resealed incorrect summary cannot substitute for replayed process logs.
    case['facts']['observation']['cases'][0]['targetReturnCode'] = 99
    p.write(case_ref['path'], d.seal({k: v for k, v in case.items() if k != 'diagnosticNodeIdentity'}, 'diagnosticNodeIdentity'))
    body = {k: v for k, v in value.items() if k != 'stateIdentity'}
    body['checkpoints']['case-000000'] = d.snapshot(case_ref['path']); publish(root / 'real-diag/progress.json', body)
    with pytest.raises(ValueError, match='NODE_REDERIVATION_MISMATCH'):
        q.check_progress(root / 'real-diag/progress.json')


def test_completed_mismatch_is_retained_and_not_retried_until_pass(diagnostic, monkeypatch):
    root, plan, calls, _ = diagnostic; observe = p.observe
    def mismatching(*args, **kwargs):
        observe(*args, **kwargs)
        root = args[3]; value = d.read(root / 'observations.json'); value['mismatches'] = ['fixture-process-mismatch']
        p.write(root / 'observations.json', value)
    monkeypatch.setattr(p, 'observe', mismatching)
    first = q.execute(plan, root / 'diag')
    assert first['status'] == 'complete' and q.facts(first)['observations'][0]['mismatches']
    assert q.resume_campaign(root / 'diag') == first and calls.count('case-000000') == 1
    assert not q.facts(first)['semanticApproval']


def test_one_failed_case_does_not_hide_another_and_resume_keeps_other_case(diagnostic):
    root, plan, calls, fail = diagnostic
    base = d.seal({**{k: v for k, v in plan['basePlan'].items() if k != 'campaignPlanIdentity'},
                   'cases': p.gmp_cases([42, 43], 10)}, 'campaignPlanIdentity')
    plan = q.make_plan(base, [0, 1]); fail['case-000000'] = 1
    first = q.execute(plan, root / 'diag')
    assert first['status'] == 'failed' and 'case-000001' in first['checkpoints']
    last = q.resume_campaign(root / 'diag')
    assert last['status'] == 'complete' and calls.count('case-000001') == 1
    assert calls.count('case-000000') == 2


def test_resume_cannot_change_diagnostic_case_selection(diagnostic):
    root, plan, calls, _ = diagnostic
    base = d.seal({**{k: v for k, v in plan['basePlan'].items() if k != 'campaignPlanIdentity'},
                   'cases': p.gmp_cases([42, 43], 10)}, 'campaignPlanIdentity')
    q.execute(q.make_plan(base, [0]), root / 'diag'); before = list(calls)
    with pytest.raises(ValueError, match='RESUME_PLAN_CHANGED'):
        q.execute(q.make_plan(base, [1]), root / 'diag', resume=True)
    assert calls == before


def test_failed_progress_cannot_erase_its_only_failure(diagnostic):
    root, plan, _, fail = diagnostic; fail['case-000000'] = 1
    state = q.execute(plan, root / 'diag')
    body = {k: v for k, v in state.items() if k != 'stateIdentity'}
    body['attempts'].pop(); publish(root / 'diag/progress.json', body)
    with pytest.raises(ValueError, match='FAILURE_WITHOUT_UNRESOLVED_ERROR'):
        q.check_progress(root / 'diag/progress.json')


def test_attempt_history_requires_its_dependencies_before_execution(diagnostic):
    root, plan, _, _ = diagnostic; state = q.execute(plan, root / 'diag')
    body = {k: v for k, v in state.items() if k != 'stateIdentity'}
    body['attempts'][0]['stage'] = 'source-build'
    body['attempts'][0]['directory'] = str(root / 'diag/attempts/000000-source-build')
    publish(root / 'diag/progress.json', body)
    with pytest.raises(ValueError, match='HISTORY_DEPENDENCY_MISSING'):
        q.check_progress(root / 'diag/progress.json')


def test_attempt_history_cannot_retry_an_already_completed_stage(diagnostic):
    root, plan, _, _ = diagnostic; state = q.execute(plan, root / 'diag')
    body = {k: v for k, v in state.items() if k != 'stateIdentity'}
    i = len(body['attempts'])
    body['attempts'].append({'index': i, 'stage': 'preparation', 'directory': str(root / 'diag/attempts' / ('%06d-preparation' % i)),
                             'status': 'failed', 'failure': {'type': 'forged', 'detail': 'forged'}, 'elapsedSeconds': 0})
    publish(root / 'diag/progress.json', body)
    with pytest.raises(ValueError, match='HISTORY_AFTER_CHECKPOINT'):
        q.check_progress(root / 'diag/progress.json')
