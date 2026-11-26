"""Preflight and corpus scheduling; upstream ingress stays fixture-owned."""
import copy
from pathlib import Path

import pytest

from riscv2x86_py import native_api_campaign as c
from riscv2x86_py import native_api_corpus as batch
from riscv2x86_py import native_evaluation_coverage as coverage
from .test_native_api_campaign import api_campaign
from .test_native_original_api import native_pair


def instance(identity, *, excluded=False, unstructured=False):
    return {'instanceBindingIdentity': identity, 'astPath': [1],
            'sourceGuardClassification': ('excluded-under-compiler-query-contracts'
                                          if excluded else 'unknown'),
            'unstructuredControlFlow': unstructured,
            'canonicalInstructionExecutionVerified': False}


def test_only_complete_nonempty_checked_exclusions_can_skip_runtime():
    selected = {'instanceBindingIdentities': ['a', 'b']}
    rows = [instance('a', excluded=True), instance('b')]
    value = c.preflight_selection(selected, {'instances': rows})
    assert value['runtimeAcquisitionRecommended'] is True
    rows[1] = instance('b', excluded=True)
    assert c.preflight_selection(selected, {'instances': rows})['runtimeAcquisitionRecommended'] is False
    rows[1]['unstructuredControlFlow'] = True
    assert c.preflight_selection(selected, {'instances': rows})['runtimeAcquisitionRecommended'] is True


@pytest.mark.parametrize('ids,rows', [
    ([], []), (['a', 'a'], [instance('a', excluded=True)]),
    (['a'], []), (['a'], [instance('a'), instance('a')]),
])
def test_missing_or_duplicate_binding_is_rejected(ids, rows):
    with pytest.raises(ValueError):
        c.preflight_selection({'instanceBindingIdentities': ids}, {'instances': rows})


def test_other_functions_are_retained_and_do_not_decide_selected_execution():
    rows = [instance('selected'), instance('other', excluded=True)]
    result = c.preflight_selection({'instanceBindingIdentities': ['selected']}, {'instances': rows})
    assert result['runtimeAcquisitionRecommended'] is True
    assert result['unselectedInstanceIdentities'] == ['other']
    assert result['canonicalInstructionCoverageVerified'] is False
    assert result['machineEliminationVerified'] is False


@pytest.fixture
def preflight_fixture(api_campaign, monkeypatch):
    config, dom, basis, root, calls = api_campaign
    spec, builds = c.api.from_progress('fixture-owned-ingress')
    # Own the compiler/applicability join at this boundary only. The real
    # producers have separate integrity tests; no execution proof is mocked.
    selected = c.api.context(spec)[1][0]
    rows = [instance(i, excluded=True) for i in selected['instanceBindingIdentities']]
    facts = {'instances': rows}
    monkeypatch.setattr(c.api, 'from_progress', lambda path, **kw:
                        (spec, dict(builds), copy.deepcopy(facts)) if kw.get('with_applicability')
                        else (spec, dict(builds)))
    report = {'findings': [{'fragment': {'id': 'fixture:' + r['instanceBindingIdentity']},
                            'physicalEditBinding': {'instanceBindingIdentity': r['instanceBindingIdentity']}}
                           for r in rows]}
    monkeypatch.setattr(coverage, 'from_spec', lambda spec, app, l2: coverage.summarize(report, app, l2))
    return config, dom, basis, root, calls, facts


def test_preflight_skips_acquisition_and_is_independently_rederived(preflight_fixture, monkeypatch):
    config, dom, basis, root, calls, _ = preflight_fixture
    monkeypatch.setattr(c.api, 'acquire', lambda *a, **kw: pytest.fail('preflight launched API'))
    monkeypatch.setattr(c, 'l2_attempt', lambda *a, **kw: pytest.fail('preflight launched L2'))
    out = root / 'preflight'
    value = c.execute(config, dom, [0], [basis], out, stop_after='preflight')
    assert value == c.check_preflight(out / 'preflight.json')
    assert value['selection']['disposition'] == 'all-selected-instances-source-excluded'
    assert not value['runtimeAcquisitionPerformed'] and not value['semanticApproval']
    assert not (out / 'attempts').exists() and not (out / 'result.json').exists()
    assert c.execute(config, dom, [0], [basis], out, resume=True, stop_after='preflight') == value
    assert len(calls) == 1
    changed = copy.deepcopy(value); changed['selection']['canonicalInstructionCoverageVerified'] = True
    c.project.write(out / 'preflight.json', c.d.seal(
        {k: v for k, v in changed.items() if k != 'apiPreflightIdentity'}, 'apiPreflightIdentity'))
    with pytest.raises(ValueError, match='REDERIVATION'):
        c.check_preflight(out / 'preflight.json')


def test_missing_report_binding_cannot_skip_a_seed(preflight_fixture, monkeypatch):
    config, dom, basis, root, _, _ = preflight_fixture
    monkeypatch.setattr(coverage, 'from_spec', lambda *args: {'findings': []})
    with pytest.raises(ValueError, match='REPORT_INSTANCE_JOIN_REQUIRED'):
        c.execute(config, dom, [0], [basis], root / 'missing', stop_after='preflight')
    assert not (root / 'missing/preflight.json').exists()


def task(config, dom, basis, name):
    return {'taskId': name, 'configuration': str(config), 'domain': str(dom),
            'functionAstPath': [0], 'assumptionSources': [str(basis)]}


def manifest(root, tasks):
    path = root / 'tasks.json'
    c.project.write(path, {'schemaVersion': batch.INPUT, 'tasks': tasks})
    return path


def test_batch_retains_excluded_tasks_and_never_repeats_runtime(preflight_fixture, monkeypatch):
    config, dom, basis, root, calls, _ = preflight_fixture
    monkeypatch.setattr(c.api, 'acquire', lambda *a, **kw: pytest.fail('excluded task launched API'))
    source = manifest(root, [task(config, dom, basis, '../only-a-label')])
    out = root / 'batch'
    value = batch.execute(source, out)
    assert value['taskStatuses'] == ['source-excluded']
    assert value['allTasksAccounted'] and value['plannedTaskCount'] == 1
    assert value['runtimeObservedTaskCount'] == 0 and not value['semanticApproval']
    assert batch.check_progress(out / 'progress.json') == value
    assert batch.execute(source, out, resume=True) == value
    assert len(calls) == 1
    # Child validity is not memoized as an approval token.
    changed = c.d.read(dom); changed['cases'][0]['arguments'][1]['integer'] = 7
    c.project.write(dom, changed)
    with pytest.raises(ValueError):
        batch.check_progress(out / 'progress.json')


def test_task_ids_do_not_allow_duplicate_selectors(preflight_fixture):
    config, dom, basis, root, _, _ = preflight_fixture
    path = manifest(root, [task(config, dom, basis, 'a'), task(config, dom, basis, 'b')])
    with pytest.raises(ValueError, match='DUPLICATE_SELECTORS'): batch.make_plan(path)


def test_unknown_applicability_runs_original_campaign(preflight_fixture):
    config, dom, basis, root, _, facts = preflight_fixture
    for row in facts['instances']: row['sourceGuardClassification'] = 'unknown'
    path = manifest(root, [task(config, dom, basis, 'unknown')]); out = root / 'batch'
    value = batch.execute(path, out)
    assert value['taskStatuses'] == ['runtime-observation-observed-agreement']
    assert not value['canonicalInstructionCoverageVerified']
    assert not value['semanticApproval']
    assert c.d.read(value['records'][0]['result']['path'])['originalLogicalOperandsVerified'] is False


def test_failure_is_retained_and_retry_creates_new_attempt(preflight_fixture, monkeypatch):
    config, dom, basis, root, calls, _ = preflight_fixture
    path = manifest(root, [task(config, dom, basis, 'blocked')]); out = root / 'batch'
    original = c.execute
    def fail(*args, **kwargs):
        raise ValueError('fixture preflight failure')
    monkeypatch.setattr(c, 'execute', fail)
    first = batch.execute(path, out)
    assert first['taskStatuses'] == ['blocked']
    assert not first['semanticApproval']
    assert batch.execute(path, out, resume=True) == first
    monkeypatch.setattr(c, 'execute', original)
    second = batch.execute(path, out, resume=True, retry_blocked=True)
    assert second['taskStatuses'] == ['source-excluded']
    assert second['records'][0]['attempt'] == 1
    assert (out / 'tasks/000000/000000/failure.json').is_file()
    assert len(calls) == 1


def test_budget_preserves_all_tasks_and_continues_after_failure(preflight_fixture, monkeypatch):
    config, dom, basis, root, _, _ = preflight_fixture
    alternate = root / 'alternate.json'
    data = c.d.read(dom); data['cases'][0]['arguments'][1]['integer'] = 7
    c.project.write(alternate, data)
    path = manifest(root, [task(config, dom, basis, 'first'), task(config, alternate, basis, 'second')])
    original = c.execute
    def fail_first(*args, **kwargs):
        if Path(args[4]).parent.name == '000000':
            raise ValueError('fixture first-task failure')
        return original(*args, **kwargs)
    monkeypatch.setattr(c, 'execute', fail_first)
    out = root / 'batch'
    first = batch.execute(path, out, max_tasks=1)
    assert first['taskStatuses'] == ['blocked', 'not_run']
    assert not first['allTasksAccounted'] and first['plannedTaskCount'] == 2
    second = batch.execute(path, out, max_tasks=1, resume=True)
    assert second['taskStatuses'] == ['blocked', 'source-excluded']
    assert second['allTasksAccounted'] and not second['semanticApproval']
    forged = copy.deepcopy(second); forged['taskStatuses'][0] = 'source-excluded'
    c.project.write(out / 'progress.json', c.d.seal(
        {k: v for k, v in forged.items() if k != 'stateIdentity'}, 'stateIdentity'))
    with pytest.raises(ValueError, match='REDERIVATION'):
        batch.check_progress(out / 'progress.json')


def test_checkpoints_do_not_recursively_recheck_prior_tasks(preflight_fixture, monkeypatch):
    config, dom, basis, root, _, _ = preflight_fixture
    alternate = root / 'alternate.json'
    data = c.d.read(dom); data['cases'][0]['arguments'][1]['integer'] = 7
    c.project.write(alternate, data)
    path = manifest(root, [task(config, dom, basis, 'first'), task(config, alternate, basis, 'second')])
    calls = []; original = batch.row_facts
    def record(root, index, task, row):
        calls.append(index)
        return original(root, index, task, row)
    monkeypatch.setattr(batch, 'row_facts', record)
    value = batch.execute(path, root / 'batch', max_tasks=2)
    # Every final child is checked; intermediate checkpoint writes do not
    # multiply deep checks by the number of state transitions.
    assert calls == [0, 1]
    assert value['taskStatuses'] == ['source-excluded', 'source-excluded']


def test_cached_and_uncached_preflight_checks_agree(preflight_fixture):
    from riscv2x86_py.verification_session import session
    config, dom, basis, root, _, _ = preflight_fixture
    out = root / 'preflight'
    c.execute(config, dom, [0], [basis], out, stop_after='preflight')
    with session(256 * 1024 * 1024):
        cached = c.check_preflight(out / 'preflight.json')
    with session(0):
        uncached = c.check_preflight(out / 'preflight.json')
    assert cached == uncached


def test_cli_reports_preflight_as_non_acceptance(tmp_path, monkeypatch):
    import runpy
    main = runpy.run_path(str(Path(__file__).resolve().parents[2] /
                            'experiment/automate_native_project.py'))['main']
    calls = []
    def replay(previous, output, **kwargs):
        calls.append(kwargs)
        return {'schemaVersion': c.PREFLIGHT, 'semanticApproval': False}
    monkeypatch.setattr(c, 'replay', replay)
    assert main(['api-replay', '--previous-result', 'fixture.json',
                 '--output', str(tmp_path / 'out'), '--stop-after', 'preflight']) == 1
    assert calls == [{'stop_after': 'preflight'}]
