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
