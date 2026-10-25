import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def runner():
    path = Path(__file__).resolve().parents[2]/'experiment'/'verify_route_contracts.py'
    spec = importlib.util.spec_from_file_location('route_contract_runner',path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_outer_regression_budget_is_explicit_without_changing_test_options(tmp_path,monkeypatch):
    module=runner();output=tmp_path/'out';seen=[]
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend','frontend','--clang10','clang',
        '--output',str(output),'--regression-timeout-seconds','7200'])
    monkeypatch.setattr(module.shutil,'which',lambda name,**kw:'/tools/'+name)
    def run(command,**kw):
        stage=Path(kw['stdout'].name).stem
        if stage=='clang-version':kw['stdout'].write('clang version 10.0.0\n')
        if stage=='regression':
            seen.append(kw['timeout'])
            assert '--require-no-regression-skips' not in command
            assert '--junitxml='+str(output/'regression.xml') in command
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess,'run',run)
    assert module.main()==0 and seen==[7200]
    assert json.loads((output/'run-status.json').read_text())['regressionTimeoutSeconds']==7200


@pytest.mark.parametrize('failed', ['clang-version','frontend-build','regression',None])
def test_runner_preserves_nonzero_results_and_never_runs_suite_after_failed_prerequisite(tmp_path, monkeypatch, failed):
    module = runner(); output=tmp_path/'out'; calls=[]
    monkeypatch.setattr(module.shutil,'which',lambda name,**kwargs:'/tools/'+name)
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend',str(tmp_path/'frontend'),
        '--clang10',str(tmp_path/'clang'),'--suite',str(tmp_path/'suite'),'--output',str(output)])
    def run(argv, **kwargs):
        stage=Path(kwargs['stdout'].name).stem
        calls.append(stage)
        kwargs['stdout'].write('clang version 10.0.0\n' if stage=='clang-version' else '')
        code=1 if stage==failed or stage=='generated-suite' else 0
        if stage=='generated-suite':
            batch=output/'generated-suite-strict'/'batch-evaluation.json'
            batch.parent.mkdir()
            batch.write_text(json.dumps({'batchIdentity':'test-batch','caseCount':1,'statusCounts':{'unsupported':1}}))
        return SimpleNamespace(returncode=code)
    monkeypatch.setattr(module.subprocess,'run',run)
    code=module.main()
    status=json.loads((output/'run-status.json').read_text())
    if failed:
        assert code==2
        assert failed in status['blockers']
        assert not status['generatedSuiteExecuted']
        assert 'generated-suite' not in calls
    else:
        assert code==1
        assert status['generatedSuiteExitCode']==1
        assert status['generatedSuiteExecuted']
        assert 'provider-audit' in calls
        assert json.loads((output/'summary.json').read_text())['statusCounts']=={'unsupported':1}


def test_runner_does_not_overwrite_existing_result_directory(tmp_path, monkeypatch):
    module=runner(); output=tmp_path/'out'; output.mkdir(); marker=output/'existing'; marker.write_text('preserve')
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend','frontend','--clang10','clang','--output',str(output)])
    assert module.main()==2
    assert marker.read_text()=='preserve'


@pytest.mark.parametrize('position',['first','later','absent'])
def test_runner_keeps_selected_build_search_environment(tmp_path,monkeypatch,position):
    module=runner();output=tmp_path/'out'
    directory=str(tmp_path/'toolchain')
    initial={'first':directory+':/usr/bin:/bin',
             'later':'/usr/bin:'+directory+':/bin','absent':'/usr/bin:/bin'}[position]
    monkeypatch.setenv('PATH',initial)
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend','frontend',
        '--clang10',directory+'/clang','--output',str(output)])
    monkeypatch.setattr(module.shutil,'which',lambda name,**kw:'/tools/'+name)
    expected=initial if position=='first' else directory+':'+initial
    calls=[]
    def run(command,**kw):
        calls.append(command)
        assert kw['env']['PATH']==expected
        stage=Path(kw['stdout'].name).stem
        if stage=='clang-version':kw['stdout'].write('clang version 10.0.0\n')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess,'run',run)
    assert module.main()==0
    assert any('pytest' in c for c in calls)


def test_runner_forwards_runtime_environment_and_provider_directories(tmp_path, monkeypatch):
    module = runner(); output = tmp_path/'out'; commands = []
    names = ('privileged-config-directory','l2-provider-directory','l3-provider-directory',
             'harness-directory','atomic-authority-directory','csr-architecture-directory',
             'csr-authority-directory','csr-environment-contract-directory','instruction-stream-sync-directory')
    argv = ['runner','--frontend','frontend','--clang10','clang','--suite','suite','--output',str(output)]
    for name in names: argv += ['--'+name, str(tmp_path/name)]
    monkeypatch.setattr(module.sys, 'argv', argv)
    monkeypatch.setattr(module.shutil, 'which', lambda name, **kw: '/tools/'+name)
    def run(command, **kw):
        commands.append(command)
        if Path(kw['stdout'].name).stem == 'clang-version': kw['stdout'].write('clang version 10.0.0\n')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess, 'run', run)
    # No batch is produced by this mock; forwarding is what is under test.
    assert module.main() == 2
    batch_command = next(c for c in commands if 'riscv2x86_py.automatic_batch_cli' in c)
    for name in names:
        assert batch_command[batch_command.index('--'+name)+1] == str(tmp_path/name)


@pytest.mark.parametrize('rejected',[False,True])
def test_environment_checked_before_build_and_forwarded(tmp_path,monkeypatch,rejected):
    module=runner();output=tmp_path/'out';commands=[]
    manifest=tmp_path/'environment.json'
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend','frontend','--clang10','clang',
        '--suite','suite','--output',str(output),'--experiment-environment',str(manifest)])
    monkeypatch.setattr(module.shutil,'which',lambda name,**kw:'/tools/'+name)
    def run(command,**kw):
        commands.append(command);stage=Path(kw['stdout'].name).stem
        if stage=='clang-version':kw['stdout'].write('clang version 10.0.0\n')
        return SimpleNamespace(returncode=2 if stage=='experiment-environment' and rejected else 0)
    monkeypatch.setattr(module.subprocess,'run',run)
    assert module.main()==2 # mock intentionally does not produce a batch
    status=json.loads((output/'run-status.json').read_text())
    if rejected:
        assert 'experiment-environment' in status['blockers']
        assert not any(c[0]=='cmake' for c in commands)
    else:
        command=next(c for c in commands if 'riscv2x86_py.automatic_batch_cli' in c)
        assert command[command.index('--experiment-environment')+1]==str(manifest)


def test_explicit_goal_failure_is_recorded_even_when_suite_command_succeeds(tmp_path,monkeypatch):
    module=runner();output=tmp_path/'out'
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend','frontend','--clang10','clang',
        '--suite','suite','--output',str(output),'--require-verified-case','renamable'])
    monkeypatch.setattr(module.shutil,'which',lambda name,**kw:'/tools/'+name)
    def run(command,**kw):
        stage=Path(kw['stdout'].name).stem
        if stage=='clang-version':kw['stdout'].write('clang version 10.0.0\n')
        if stage=='generated-suite':
            path=output/'generated-suite-strict/batch-evaluation.json';path.parent.mkdir()
            path.write_text(json.dumps({'caseCount':1,'statusCounts':{'needs_route':1}}))
        if stage=='route-goals':return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess,'run',run)
    assert module.main()==1
    status=json.loads((output/'run-status.json').read_text())
    assert status['routeGoalsSatisfied'] is False and not status['blockers']
    assert status['generatedSuiteExecuted'] and status['generatedSuiteExitCode']==0


def test_no_skip_mode_blocks_suite_and_records_coverage(tmp_path,monkeypatch):
    module=runner();output=tmp_path/'out';calls=[]
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend','frontend','--clang10','clang',
        '--suite','suite','--output',str(output),'--require-no-regression-skips'])
    monkeypatch.setattr(module.shutil,'which',lambda name,**kw:'/tools/'+name)
    def run(command,**kw):
        stage=Path(kw['stdout'].name).stem;calls.append(stage)
        if stage=='clang-version':kw['stdout'].write('clang version 10.0.0\n')
        if stage=='regression':
            assert '--junitxml='+str(output/'regression.xml') in command
            (output/'regression.xml').write_text('<testsuites><testsuite tests="4" failures="0" errors="0" skipped="1"/></testsuites>')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess,'run',run)
    assert module.main()==2
    status=json.loads((output/'run-status.json').read_text())
    assert status['regressionCoverage']=={'tests':4,'failures':0,'errors':0,'skipped':1}
    assert 'regression-skipped' in status['blockers'] and 'generated-suite' not in calls


def test_matrix_failure_is_distinct_from_provider_audit(tmp_path,monkeypatch):
    module=runner();output=tmp_path/'out';calls=[]
    monkeypatch.setattr(module.sys,'argv',['runner','--frontend','frontend','--clang10','clang',
        '--suite','suite','--output',str(output),'--acceptance-matrix',str(tmp_path/'goals.json')])
    monkeypatch.setattr(module.shutil,'which',lambda name,**kw:'/tools/'+name)
    def run(command,**kw):
        stage=Path(kw['stdout'].name).stem;calls.append(stage)
        if stage=='clang-version':kw['stdout'].write('clang version 10.0.0\n')
        if stage=='generated-suite':
            batch=output/'generated-suite-strict/batch-evaluation.json';batch.parent.mkdir()
            batch.write_text('{"statusCounts":{"verified":1}}')
        return SimpleNamespace(returncode=1 if stage=='acceptance-matrix' else 0)
    monkeypatch.setattr(module.subprocess,'run',run)
    assert module.main()==1
    status=json.loads((output/'run-status.json').read_text())
    assert status['acceptanceMatrixSatisfied'] is False
    assert 'provider-audit' in calls
