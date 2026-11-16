"""Checkpoint protocol tests. Stage producers/checkers are explicit fixtures.

These verify scheduling and fail-closed reuse, not cross-ISA or GMP proofs.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys

import pytest
from riscv2x86_py import native_project_campaign as c
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.project_acquisition import publish


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    root = tmp_path
    bundle = root / 'bundle.json'; p.write(bundle, {'fixture': 'bundle'})
    target = root / 'target.json'; p.write(target, {'fixture': 'target'})
    records = root / 'records.json'; p.write(records, {'fixture': 'records'})
    ghidra = root / 'ghidra'; (ghidra / 'support').mkdir(parents=True)
    launcher = ghidra / 'support/pythonRun'; launcher.write_text('#!/bin/sh\nexit 0\n'); launcher.chmod(0o755)
    cases = p.gmp_cases([42], 10)
    options = dict(qemu=sys.executable, runtime_prefix=root, cases=cases, ghidra_install_dir=ghidra)
    plan = c.make_plan(bundle, target, [records], **options)
    calls = []; fail = {}; result_status = ['inconclusive']
    def attempt(stage):
        calls.append(stage)
        if fail.get(stage, 0):
            fail[stage] -= 1
            raise RuntimeError('fixture acquisition failed: ' + stage)
    def run(bundle, output, **kwargs):
        attempt('original'); output.mkdir()
        p.write(output / 'result.json', {'bundle': d.snapshot(bundle)})
    def freeze(*, output, **kwargs):
        attempt('project')
        p.write(output, {'run': d.snapshot(kwargs['run_path']), 'configuration': kwargs})
    def app(spec, output):
        attempt('applicability'); output.mkdir()
        p.write(output / 'result.json', {'project': d.snapshot(spec),
                                      'facts': {'editedInstanceCount': 1, 'canonicalInstructionCoverageVerified': False}})
    def request(spec, output, app_path=None):
        attempt('request'); output.mkdir()
        p.write(output / 'request.json', {'spec': d.snapshot(spec), 'app': d.snapshot(app_path)})
        return output / 'request.json'
    def check_request(path, spec, app_path=None):
        if d.read(path) != {'spec': d.snapshot(spec), 'app': d.snapshot(app_path)}: raise ValueError('fixture request binding changed')
    def evaluate(run, request, output):
        attempt('evaluation'); output.mkdir()
        value = {'inputs': {'run': d.snapshot(run), 'requestTemplate': d.snapshot(request)},
                 'facts': {'evaluationStatus': result_status[0]}}
        p.write(output / 'result.json', value); return value
    monkeypatch.setattr(c.route, 'run', run)
    monkeypatch.setattr(c.route, 'check_run', lambda path: d.read(path))
    monkeypatch.setattr(c.project, 'freeze', freeze)
    monkeypatch.setattr(c.project, 'check', lambda path: d.read(path))
    monkeypatch.setattr(c.applicability, 'acquire', app)
    monkeypatch.setattr(c.applicability, 'check', lambda path: d.read(path))
    monkeypatch.setattr(c.project, 'request', request)
    monkeypatch.setattr(c.project, 'check_request', check_request)
    monkeypatch.setattr(c.evaluation, 'acquire', evaluate)
    monkeypatch.setattr(c.evaluation, 'check', lambda path: d.read(path))
    return root, plan, calls, fail, options, result_status


def test_complete_inconclusive_campaign_is_a_terminal_observation_not_approval(campaign):
    root, plan, calls, _, _, _ = campaign
    value = c.execute(plan, root / 'campaign')
    assert calls == list(c.STAGES)
    assert value['status'] == 'complete' and value['evaluationStatus'] == 'inconclusive'
    assert not value['semanticApproval'] and not value['productionAcceptanceComplete']
    assert c.check_progress(root / 'campaign/progress.json') == value
    assert c.execute(plan, root / 'campaign', resume=True) == value
    assert calls == list(c.STAGES)


@pytest.mark.parametrize('stage', ['project', 'applicability', 'request', 'evaluation'])
def test_resume_reuses_only_committed_checked_prefix_and_preserves_failed_attempt(campaign, stage):
    root, plan, calls, fail, _, _ = campaign
    fail[stage] = 1
    with pytest.raises(RuntimeError): c.execute(plan, root / 'campaign')
    failed = c.check_progress(root / 'campaign/progress.json')
    assert failed['status'] == 'failed' and failed['primaryFailure']['stage'] == stage
    assert set(failed['checkpoints']) == set(c.STAGES[:c.STAGES.index(stage)])
    value = c.execute(plan, root / 'campaign', resume=True)
    assert value['status'] == 'complete' and value['evaluationStatus'] == 'inconclusive'
    assert calls.count('original') == 1 and calls.count(stage) == 2
    assert value['attempts'][c.STAGES.index(stage)]['status'] == 'failed'
    assert Path(value['attempts'][c.STAGES.index(stage)]['directory']).is_dir()


def test_changed_case_contract_cannot_resume_same_campaign(campaign):
    root, plan, calls, _, options, _ = campaign
    c.execute(plan, root / 'campaign')
    changed = deepcopy(options); changed['cases'][0]['arguments'] = ['11']
    newer = c.make_plan(plan['bundle']['path'], plan['targetPlan']['path'],
                        [r['path'] for r in plan['sourceRecords']], **changed)
    with pytest.raises(ValueError, match='RESUME_PLAN_CHANGED'):
        c.execute(newer, root / 'campaign', resume=True)
    assert calls == list(c.STAGES)


def test_changed_capture_or_tool_is_rejected_before_reuse(campaign):
    root, plan, calls, _, _, _ = campaign
    c.execute(plan, root / 'campaign')
    Path(plan['sourceRecords'][0]['path']).write_text('changed record')
    with pytest.raises(ValueError): c.execute(plan, root / 'campaign', resume=True)
    assert calls == list(c.STAGES)


def test_corrupt_cached_translation_is_not_silently_retranslated(campaign):
    root, plan, calls, _, _, _ = campaign
    value = c.execute(plan, root / 'campaign')
    Path(value['checkpoints']['original']['path']).write_text('changed')
    with pytest.raises(ValueError): c.execute(plan, root / 'campaign', resume=True)
    assert calls == list(c.STAGES)


def test_orphan_result_after_interruption_is_not_a_checkpoint(campaign, monkeypatch):
    root, plan, calls, _, _, _ = campaign
    original = c.route.run
    def interrupt(*args, **kwargs):
        original(*args, **kwargs)
        raise KeyboardInterrupt('fixture killed after writing result')
    monkeypatch.setattr(c.route, 'run', interrupt)
    with pytest.raises(KeyboardInterrupt): c.execute(plan, root / 'campaign')
    state = c.check_progress(root / 'campaign/progress.json')
    assert not state['checkpoints']
    orphan = root / 'campaign/attempts/000000-original/work/result.json'
    assert orphan.is_file()
    monkeypatch.setattr(c.route, 'run', original)
    value = c.execute(plan, root / 'campaign', resume=True)
    assert calls.count('original') == 2
    assert value['attempts'][0]['status'] == 'interrupted' and orphan.is_file()


def test_resealed_summary_cannot_complete_without_receipts(campaign):
    root, plan, _, fail, _, _ = campaign
    fail['project'] = 1
    with pytest.raises(RuntimeError): c.execute(plan, root / 'campaign')
    progress = root / 'campaign/progress.json'; state = d.read(progress); state.pop('stateIdentity')
    state['status'] = 'complete'; state['currentStage'] = 'complete'; state['primaryFailure'] = None; publish(progress, state)
    with pytest.raises(ValueError, match='COMPLETION_WITHOUT_RECEIPTS'): c.check_progress(progress)


def test_lock_rejects_concurrent_resume(campaign):
    root, plan, calls, _, _, _ = campaign
    c.execute(plan, root / 'campaign')
    with c.lock(root / 'campaign'):
        with pytest.raises(ValueError, match='ALREADY_RUNNING'):
            c.execute(plan, root / 'campaign', resume=True)
    assert calls == list(c.STAGES)


def test_existing_output_requires_explicit_resume(campaign):
    root, plan, _, _, _, _ = campaign
    c.execute(plan, root / 'campaign')
    with pytest.raises(FileExistsError): c.execute(plan, root / 'campaign')


def test_cli_drives_checkpoints_and_preserves_inconclusive_exit_code(campaign):
    root, plan, calls, _, _, _ = campaign
    file = Path(__file__).resolve().parents[2] / 'experiment/automate_native_project.py'
    spec = importlib.util.spec_from_file_location('checkpoint_cli', file)
    cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
    args = ['run', '--bundle', plan['bundle']['path'], '--target-plan', plan['targetPlan']['path'],
            '--source-records', plan['sourceRecords'][0]['path'], '--qemu', plan['qemu']['path'],
            '--runtime-prefix', plan['runtimePrefix'], '--gmp-seeds', '42', '--repetitions', '10',
            '--ghidra-install-dir', plan['ghidraInstallDir'], '--output', str(root / 'cli')]
    assert cli.main(args) == 1
    assert cli.main(args + ['--resume']) == 1
    assert cli.main(['resume', '--output', str(root / 'cli')]) == 1
    assert cli.main(['check', '--input', str(root / 'cli/progress.json')]) == 0
    assert calls == list(c.STAGES)


def test_alias_target_plan_has_canonical_project_configuration(campaign):
    root, plan, _, _, options, _ = campaign
    alias = root / 'target-alias.json'; alias.symlink_to(plan['targetPlan']['path'])
    new_plan = c.make_plan(plan['bundle']['path'], alias,
                           [r['path'] for r in plan['sourceRecords']], **options)
    state = c.execute(new_plan, root / 'alias-campaign')
    spec = d.read(state['checkpoints']['project']['path'])
    assert spec['configuration']['target_plan_path'] == plan['targetPlan']['resolvedPath']


def test_checkpoint_cannot_be_relabelled_as_another_attempt(campaign):
    root, plan, _, _, _, _ = campaign
    c.execute(plan, root / 'campaign')
    progress = root / 'campaign/progress.json'; state = d.read(progress); state.pop('stateIdentity')
    state['attempts'][0]['status'] = 'interrupted'; publish(progress, state)
    with pytest.raises(ValueError, match='CHECKPOINT_OWNER_REQUIRED'): c.check_progress(progress)


def test_resume_command_reuses_pinned_configuration_and_retains_failed_evaluation(campaign):
    root, plan, calls, _, _, status = campaign
    status[0] = 'failed'
    first = c.execute(plan, root / 'campaign')
    assert first['evaluationStatus'] == 'failed'
    assert c.resume_campaign(root / 'campaign') == first
    assert calls == list(c.STAGES)
    facts = c.facts(first)
    assert facts['originalEvaluation']['evaluationStatus'] == 'failed'
    assert facts['resultPaths']['evaluation'] == first['checkpoints']['evaluation']['path']


def test_changed_launcher_cannot_be_reused(campaign):
    root, plan, calls, _, _, _ = campaign
    c.execute(plan, root / 'campaign')
    Path(plan['launcher']['path']).write_text('#!/bin/sh\nexit 2\n')
    with pytest.raises(ValueError): c.resume_campaign(root / 'campaign')
    assert calls == list(c.STAGES)


def test_pause_after_applicability_does_not_run_matrix_or_evaluation(campaign):
    root, plan, calls, _, _, _ = campaign
    state = c.execute(plan, root / 'campaign', stop_after='applicability')
    assert state['status'] == 'paused' and state['evaluationStatus'] is None
    assert calls == ['original', 'project', 'applicability']
    final = c.resume_campaign(root / 'campaign')
    assert final['status'] == 'complete' and calls == list(c.STAGES)
    assert calls.count('original') == 1
    assert all(a['operationElapsedSeconds'] is not None for a in final['attempts'])


def test_resuming_preparation_can_stop_before_any_evaluation(campaign):
    root, plan, calls, fail, _, _ = campaign
    fail['project'] = 1
    with pytest.raises(RuntimeError): c.execute(plan, root / 'campaign', stop_after='applicability')
    value = c.resume_campaign(root / 'campaign', stop_after='applicability')
    assert value['status'] == 'paused' and calls.count('original') == 1
    assert calls == ['original', 'project', 'project', 'applicability']
    assert c.resume_campaign(root / 'campaign', stop_after='applicability') == value
    assert 'request' not in calls and 'evaluation' not in calls
