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
