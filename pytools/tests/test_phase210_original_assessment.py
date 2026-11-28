"""Original evaluator invocation with explicit fixture-owned ingress boundaries.

The real evaluator/materializer/result checker execute. Copy-built fixtures and
missing L0 validators are NOT cross-ISA, ABI, GMP, or program semantic proofs.
"""
import copy
import json
from pathlib import Path
import pytest

from riscv2x86_py import native_api_assessment as assess
from riscv2x86_py import native_api_campaign as c
from riscv2x86_py import native_api_corpus as batch
from riscv2x86_py import native_project_inventory as inventory
from riscv2x86_py import native_project_l2 as l2
from .test_native_original_api import native_pair
from .test_native_api_campaign import api_campaign
from .test_phase209_api_preflight import preflight_fixture, manifest, task
from .test_evaluation_runner import _setup


def finding(identity, name='same', fragment='fragment'):
    return {'fragment': {'id': fragment, 'enclosingFunction': name},
            'physicalEditBinding': {'instanceBindingIdentity': identity}}


def test_compiler_instance_join_does_not_select_same_name_or_reject_renaming():
    report = {'findings': [finding('foreign', fragment='foreign'), finding('chosen', name='renamed')]}
    rows = l2.selected_findings(report, {'instanceBindingIdentities': ['chosen']})
    assert rows == [(1, report['findings'][1])]


@pytest.mark.parametrize('rows,ids', [
    ([finding('chosen')], []),
    ([finding('chosen')], ['chosen', 'chosen']),
    ([finding('foreign')], ['chosen']),
    ([finding('chosen'), finding('chosen', fragment='other')], ['chosen']),
    ([finding('chosen'), finding('foreign')], ['chosen']),
])
def test_missing_duplicate_or_ambiguous_subject_rejected(rows, ids):
    with pytest.raises(ValueError):
        l2.selected_findings({'findings': rows}, {'instanceBindingIdentities': ids})


@pytest.fixture
def formal_fixture(preflight_fixture, native_pair, monkeypatch):
    config, dom, basis, root, calls, facts = preflight_fixture
    specpath, _, _, _, spec = native_pair
    request, _, _ = _setup(root / 'formal-template')
    # Keep the real original evaluator. Only upstream run/declaration ingress
    # and project-specific request generation are fixture-owned.
    raw = {
        'schemaVersion': request.schema_version, 'sourceRoot': request.source_root,
        'sourceRelativePath': request.source_relative_path, 'targetRelativePath': request.target_relative_path,
        'translatedReport': request.translated_report, 'attemptArchive': request.attempt_archive,
        'validationPlan': request.validation_plan, 'targetEnvironment': request.target_environment,
        'runtimeRegistryTemplate': request.runtime_registry_template,
        'translationArtifacts': request.translation_artifacts, 'translationCommand': [],
        'comparisonPolicy': request.comparison_policy, 'validationUnit': 'program',
        'validationGroupId': '', 'selectedAttemptIds': [],
    }
    for side in ('source', 'target'):
        build = getattr(request, side + '_build')
        raw[side + 'Build'] = {'artifactId': build.artifact_id, 'artifactKind': build.artifact_kind,
            'outputRelativePath': build.output_relative_path, 'command': list(build.command)}
    report = root / 'inventory-report.json'
    c.project.write(report, {'findings': [
        finding('instance-1', fragment='one'), finding('unselected-instance', fragment='two')]})
    translation = root / 'translation.json'
    c.project.write(translation, {'report': c.d.snapshot(report)})
    runpath = root / 'run.json'; run = {'translation': c.d.snapshot(translation), 'originalRunIdentity': 'fixture-original-run'}
    c.project.write(runpath, run)
    spec['run'] = c.d.snapshot(runpath)
    spec['cases'] = [{'caseId': 'official-project-case-not-api', 'arguments': []}]
    c.project.write(specpath, spec)
    app = root / 'app.json'; c.project.write(app, {'project': c.d.snapshot(specpath)})
    prepare = c.diagnostic.execute
    def preparation(plan, output, **kwargs):
        prepare(plan, output, **kwargs)
        prefix = Path(output) / 'preparation'; prefix.mkdir(exist_ok=True)
        c.project.write(prefix / 'progress.json', {'checkpoints': {'applicability': c.d.snapshot(app)}})
    monkeypatch.setattr(c.diagnostic, 'execute', preparation)
    monkeypatch.setattr(assess.evaluation.route, 'check_run', lambda path: copy.deepcopy(run))
    monkeypatch.setattr(assess.evaluation.route, 'bound_evaluation_request',
                        lambda translation, template: c.d.read(template))
    from riscv2x86_py import native_original_pipeline as route
    def bind(translation, template, output):
        c.project.write(Path(output), c.d.read(template))
        return c.d.read(template)
    monkeypatch.setattr(route, 'evaluation_request', bind)
    def create(specpath, output, app, **kwargs):
        output = Path(output); output.mkdir()
        c.project.write(output / 'request.json', raw)
        return output / 'request.json'
    def check_request(path, *args, **kwargs):
        if c.d.read(path) != raw:
            raise ValueError('FIXTURE_REQUEST_CHANGED')
        return [c.d.snapshot(path)]
    monkeypatch.setattr(assess.project, 'request', create)
    monkeypatch.setattr(assess.project, 'check_request', check_request)
    return config, dom, basis, root, calls, facts


def test_real_original_evaluator_invoked_and_inconclusive_is_terminal(formal_fixture, monkeypatch):
    config, dom, basis, root, _, _ = formal_fixture
    pre = root / 'preflight'
    c.execute(config, dom, [0], [basis], pre, stop_after='preflight')
    out = root / 'assessment'
    value = assess.acquire(pre / 'preflight.json', out)
    assert value['originalEvaluationInvoked'] is True
    assert value['evaluationStatus'] == 'inconclusive'
    assert value['attempts'][0]['unexecutedRequiredLevels'] == ['L1', 'L2']
    assert value['finiteApiScope']['runtimeAttemptAvailable'] is False
    assert value['finiteApiScope']['caseCount'] == 1
    assert value['projectTestScope']['caseIds'] == ['official-project-case-not-api']
    assert not value['semanticApproval'] and not value['independentProgramAuditPerformed']
    assert assess.check(out / 'result.json') == value
    monkeypatch.setattr(assess.evaluation, 'acquire', lambda *a, **kw: pytest.fail('reran terminal result'))
    assert assess.acquire(pre / 'preflight.json', out, resume=True) == value


def test_live_preflight_requires_original_runtime_attempt(formal_fixture):
    config, dom, basis, root, _, facts = formal_fixture
    for row in facts['instances']: row['sourceGuardClassification'] = 'unknown'
    pre = root / 'preflight'
    c.execute(config, dom, [0], [basis], pre, stop_after='preflight')
    with pytest.raises(ValueError, match='RUNTIME_ATTEMPT_REQUIRED'):
        assess.acquire(pre / 'preflight.json', root / 'must-not-exist')
    assert not (root / 'must-not-exist').exists()


def test_finite_api_success_does_not_upgrade_original_formal_result(formal_fixture):
    config, dom, basis, root, _, facts = formal_fixture
    for row in facts['instances']: row['sourceGuardClassification'] = 'unknown'
    folder = root / 'api'
    c.execute(config, dom, [0], [basis], folder, stop_after='preflight')
    runtime = c.execute(config, dom, [0], [basis], folder, resume=True)
    assert runtime['linkAttributedObservationStatus'] == 'observed-agreement'
    value = assess.acquire(folder / 'preflight.json', root / 'assess',
                           campaign_path=folder / 'result.json')
    assert value['evaluationStatus'] == 'inconclusive'
    assert value['finiteApiScope']['runtimeAttemptAvailable']
    assert not value['semanticApproval']


def test_resealed_formal_approval_is_rejected(formal_fixture):
    config, dom, basis, root, _, _ = formal_fixture
    pre = root / 'preflight'; out = root / 'assess'
    c.execute(config, dom, [0], [basis], pre, stop_after='preflight')
    value = assess.acquire(pre / 'preflight.json', out)
    value['semanticApproval'] = True
    c.project.write(out / 'result.json', c.d.seal(
        {k: v for k, v in value.items() if k != 'apiAssessmentIdentity'}, 'apiAssessmentIdentity'))
    with pytest.raises(ValueError, match='REDERIVATION'):
        assess.check(out / 'result.json')


def test_batch_evaluation_runs_even_for_source_exclusion(formal_fixture):
    config, dom, basis, root, _, _ = formal_fixture
    source = manifest(root, [task(config, dom, basis, 'excluded')])
    value = batch.execute(source, root / 'batch', evaluate=True)
    assert value['taskStatuses'] == ['source-excluded-evaluated-inconclusive']
    assert value['records'][0]['result'] is None
    assert value['records'][0]['assessment'] is not None
    assert value['formalValidationPerformed'] is True
    assert value['allTasksAccounted'] and not value['semanticApproval']
    assert batch.check_progress(root / 'batch/progress.json') == value
    with pytest.raises(ValueError):
        batch.execute(source, root / 'batch', resume=True, evaluate=False)


def test_formal_acquisition_failure_retains_runtime_and_blocks(formal_fixture, monkeypatch):
    config, dom, basis, root, _, facts = formal_fixture
    for row in facts['instances']: row['sourceGuardClassification'] = 'unknown'
    source = manifest(root, [task(config, dom, basis, 'live')])
    def broken(*args, **kwargs): raise ValueError('fixture formal acquisition failed')
    monkeypatch.setattr(assess, 'acquire', broken)
    value = batch.execute(source, root / 'batch', evaluate=True)
    assert value['taskStatuses'] == ['blocked']
    assert value['records'][0]['result'] is not None
    assert value['records'][0]['failure'] is not None
    assert value['records'][0]['assessment'] is None
    assert not value['formalValidationPerformed']


def test_inventory_retains_unselected_findings_without_inventing_contracts(formal_fixture):
    config, dom, basis, root, _, _ = formal_fixture
    pre = root / 'preflight'
    c.execute(config, dom, [0], [basis], pre, stop_after='preflight')
    value = inventory.acquire([pre / 'preflight.json'], root / 'inventory.json')
    assert value['reportFindingCount'] == 2
    rows = value['contexts'][0]['findings']
    assert rows[0]['entryContractAvailable']
    assert rows[1]['entryContractAvailable'] is False
    assert rows[1]['entryStatus'] == 'compiler-entry-unavailable'
    assert inventory.check(root / 'inventory.json') == value
    with pytest.raises(ValueError, match='DUPLICATE'):
        inventory.acquire([pre / 'preflight.json', pre / 'preflight.json'], root / 'bad.json')


def test_complete_continues_same_original_api_task(formal_fixture):
    config, dom, basis, root, _, facts = formal_fixture
    for row in facts['instances']: row['sourceGuardClassification'] = 'unknown'
    pre = root / 'preflight'
    c.execute(config, dom, [0], [basis], pre, stop_after='preflight')
    value = assess.complete(pre / 'preflight.json', root / 'assess')
    assert value['evaluationStatus'] == 'inconclusive'
    assert value['finiteApiScope']['runtimeAttemptAvailable']
    assert (pre / 'result.json').is_file()
    assert (root / 'assess/result.json').is_file()
