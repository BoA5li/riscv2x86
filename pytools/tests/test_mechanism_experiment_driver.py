"""Driver protocol tests; subprocess output is explicitly simulated here."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py.semantic_content import semantic_identity


def driver():
    path=Path(__file__).resolve().parents[2]/'experiment/run_mechanism_routes.py'
    spec=importlib.util.spec_from_file_location('mechanism_driver_under_test',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def architecture(tmp_path):
    p={'schemaVersion':'riscv2x86.csr-architecture-template.v1',
       'privilegeSpecVersion':'riscv-privileged-1.12','xlenBits':64,'extensions':['zicsr']}
    p['templateIdentity']=semantic_identity(p)
    path=tmp_path/'architecture.json';path.write_text(json.dumps(p));return path


def test_architecture_checkpoint_runs_without_backend_and_does_not_claim_acceptance(tmp_path,monkeypatch):
    from tests.test_mechanism_route_closure import write_fixture
    fixture=tmp_path/'fixture';fixture.mkdir()
    source,report,*_=write_fixture(fixture)
    module=driver();out=tmp_path/'run'
    def execute(command,**kwargs):
        result=Path(command[command.index('--output-directory')+1])
        work=result/'cases'/'arbitrary'/'work'/'translation-work';work.mkdir(parents=True)
        for name in ('translated_report.json','compiler-candidates.json','csr-architecture.materialized.json'):
            shutil.copyfile(fixture/name,work/name)
        return SimpleNamespace(returncode=1) # expected withheld translation
    monkeypatch.setattr(module.subprocess,'run',execute)
    monkeypatch.setattr(sys,'argv',['driver','--frontend','unexecuted-protocol-fixture',
        '--output',str(out),'--architecture-template',str(architecture(tmp_path)),
        '--time-source',str(source),'--stop-after','architecture'])
    assert module.main()==0
    status=json.loads((out/'run-status.json').read_text())
    assert status['preparedRoutes']==['time'] and status['completedRoutes']==[]
    assert status['productionAcceptanceComplete'] is False
    assert status['currentStage']=='checkpoint_complete' and not status['blockers']


@pytest.mark.parametrize('extra,reason',[
    (['--time-mode','native'],'TIME_NATIVE_STRICT_BACKEND_UNAVAILABLE'),
    ([], 'TIME_EXPLICIT_INPUTS_REQUIRED'),
    (['--stop-after','architecture','--suite','unused'],'SUITE_REQUIRES_COMPLETE_PRODUCTION_RUN'),
])
def test_driver_rejects_wrong_goal_or_missing_input_before_execution(tmp_path,monkeypatch,extra,reason):
    module=driver();out=tmp_path/'run'
    def forbidden(*args,**kwargs):pytest.fail('must not execute before prerequisite rejection')
    monkeypatch.setattr(module.subprocess,'run',forbidden)
    monkeypatch.setattr(sys,'argv',['driver','--frontend','missing','--output',str(out),
        '--architecture-template',str(architecture(tmp_path)),'--time-source','arbitrary.c',*extra])
    assert module.main()==2
    status=json.loads((out/'run-status.json').read_text())
    assert status['blockers']==[reason] and not status['productionAcceptanceComplete']
    assert status['currentStage']=='input_validation'


@pytest.mark.parametrize('mutation',[None,'source','regression','selected'])
def test_suite_acceptance_uses_same_inventory_and_actual_selected_case(tmp_path,mutation):
    from riscv2x86_py.mechanism_route_checks import require_suite_preserved
    from riscv2x86_py.time_trace_harness import digest
    source=tmp_path/'renamed source.c';source.write_text('source')
    before=tmp_path/'before';after=tmp_path/'after'
    programs=[{'sourceRelativePath':source.name,'caseId':'inventory-owned-id','sourceDigest':digest(source)},
        {'sourceRelativePath':'other.c','caseId':'previous','sourceDigest':'sha256:'+'a'*64}]
    for directory in (before,after):
        directory.mkdir();inventory=Path(str(directory)+'-inventory');inventory.mkdir()
        (inventory/'automatic-inventory.json').write_text(json.dumps({'sourceRoot':str(tmp_path),'programs':programs}))
        cases=[{'caseId':'inventory-owned-id','status':'needs_route' if directory==before else 'verified'},
               {'caseId':'previous','status':'verified'}]
        if mutation=='regression' and directory==after:cases[1]['status']='failed'
        if mutation=='selected' and directory==after:cases[0]['status']='needs_route'
        (directory/'batch-evaluation.json').write_text(json.dumps({'cases':cases}))
    if mutation=='source':source.write_text('changed after inventory')
    if mutation:
        with pytest.raises(ValueError):require_suite_preserved(before,after,[source])
    else:
        result=require_suite_preserved(before,after,[source])
        assert result['selectedCases']==['inventory-owned-id']
        assert result['sameSourceInventory']


@pytest.mark.parametrize('mutation,reason', [
    ('missing', 'TIME_BACKEND_FILE_MISSING'),
    ('manifest', 'TIME_SOURCE_BACKEND_INVALID'),
    ('runner', 'TIME_RUNNER_COMMAND_INVALID'),
    ('binary', 'TIME_SOURCE_BINARY_MISMATCH'),
])
def test_time_prerequisites_are_checked_before_any_bootstrap(tmp_path, monkeypatch, mutation, reason):
    from tests.test_controlled_time import backend
    module = driver()
    source = tmp_path/'renamed.c'; source.write_text('unsigned long renamed(void);')
    review = tmp_path/'review.json'; review.write_text('{}')
    manifest = tmp_path/'backend.json'
    value = {} if mutation == 'manifest' else backend()
    if mutation != 'missing': manifest.write_text(json.dumps(value))
    command = {} if mutation == 'runner' else [sys.executable]
    def forbidden(*args, **kwargs): pytest.fail('prerequisites must precede subprocess execution')
    monkeypatch.setattr(module.subprocess, 'run', forbidden)
    out = tmp_path/'run'
    monkeypatch.setattr(sys, 'argv', ['driver', '--frontend', 'unexecuted',
        '--output', str(out), '--architecture-template', str(architecture(tmp_path)),
        '--time-source', str(source), '--time-mode', 'controlled',
        '--time-review', str(review), '--time-backend', str(manifest),
        '--time-runner-json', json.dumps(command)])
    assert module.main() == 2
    status = json.loads((out/'run-status.json').read_text())
    assert status['blockers'][0].startswith(reason)
    assert status['steps'] == [] and not status['productionAcceptanceComplete']


@pytest.mark.parametrize('layout', ['nested', 'same', 'ancestor', 'symlink', 'suite'])
def test_output_overlap_is_rejected_before_preparation(tmp_path, monkeypatch, layout):
    module = driver()
    inputs = tmp_path/'inputs'; inputs.mkdir()
    source = inputs/'renamed.c'; source.write_text('void renamed(void);')
    out = inputs/'production'
    suite = None
    if layout == 'same': out = inputs
    if layout == 'ancestor': out = tmp_path
    if layout == 'symlink':
        alias = tmp_path/'alias'; alias.symlink_to(inputs, target_is_directory=True)
        out = alias/'production'
    if layout == 'suite':
        suite = tmp_path
        out = tmp_path/'production'
    with pytest.raises(module.MechanismRunError, match='MECHANISM_INPUT_OUTPUT_OVERLAP'):
        module.require_disjoint_output(out, [source], suite)
    # A normal invocation fails before environment preparation or commands.
    if layout == 'nested':
        def forbidden(*args, **kwargs): pytest.fail('overlap must be rejected before preparation')
        monkeypatch.setattr(module, 'prepare_environment', forbidden)
        monkeypatch.setattr(module.subprocess, 'run', forbidden)
        monkeypatch.setattr(sys, 'argv', ['driver', '--frontend', 'unused', '--output', str(out),
            '--architecture-template', str(architecture(tmp_path)), '--time-source', str(source),
            '--stop-after', 'architecture'])
        assert module.main() == 2
        status = json.loads((out/'run-status.json').read_text())
        assert status['steps'] == [] and not status['productionAcceptanceComplete']
        assert status['failureDiagnostics']['sourceRoot'] == str(inputs)


def test_sibling_input_and_output_keep_evaluator_isolation(tmp_path):
    from riscv2x86_py.evaluation import run_evaluation
    module = driver()
    inputs = tmp_path/'inputs'; inputs.mkdir()
    source = inputs/'renamed.c'; source.write_text('void renamed(void);')
    module.require_disjoint_output(tmp_path/'production', [source])
    work = inputs/'production'/'cases'/'renamed'/'work'
    with pytest.raises(ValueError, match='must not overlap'):
        run_evaluation(SimpleNamespace(source_root=str(inputs)), work_directory=work)
    assert not work.exists()


@pytest.mark.parametrize('escaped', [False, True])
def test_report_lookup_preserves_batch_failure_and_confines_paths(tmp_path, escaped):
    module = driver()
    result = tmp_path/'bootstrap'; result.mkdir()
    evaluation = tmp_path/'outside.json' if escaped else result/'cases'/'renamed'/'evaluation-result.json'
    evaluation.parent.mkdir(parents=True, exist_ok=True)
    failure = {'failureStage': 'evaluation_orchestration', 'exceptionType': 'ValueError',
               'detail': 'evaluation work directory and source root must not overlap'}
    evaluation.write_text(json.dumps({'detail': 'ValueError: '+failure['detail'],
        'orchestrationFailure': failure, 'reasonCodes': ['batch.evaluation-orchestration-error']}))
    (result/'batch-evaluation.json').write_text(json.dumps({'cases': [{
        'caseId': 'renamed', 'status': 'inconclusive',
        'resultPath': '../outside.json' if escaped else 'cases/renamed/evaluation-result.json'}]}))
    with pytest.raises(module.MechanismRunError, match='BOOTSTRAP_TRANSLATION_REPORT_MISSING') as exc:
        module.report_in(result)
    case = exc.value.diagnostic['cases'][0]
    if escaped:
        assert case['diagnosticError'] == 'RESULT_PATH_OUTSIDE_BATCH'
        assert 'orchestrationFailure' not in case
    else:
        assert case['orchestrationFailure'] == failure
        assert case['reasonCodes'] == ['batch.evaluation-orchestration-error']


def test_report_lookup_returns_unique_report_and_rejects_ambiguity(tmp_path):
    module = driver()
    reports = []
    for name in ('first', 'second'):
        path = tmp_path/'cases'/name/'work'/'translation-work'/'translated_report.json'
        path.parent.mkdir(parents=True); path.write_text('{}'); reports.append(path)
        if name == 'first': assert module.report_in(tmp_path) == path
    with pytest.raises(module.MechanismRunError, match='BOOTSTRAP_TRANSLATION_REPORT_AMBIGUOUS') as exc:
        module.report_in(tmp_path)
    assert exc.value.diagnostic['reportCount'] == 2
