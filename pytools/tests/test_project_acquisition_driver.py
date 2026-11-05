"""Dependency gates and actual subprocess stage failures, no cross compiler required."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

from riscv2x86_py import project_acquisition as a

DRIVER = Path(__file__).resolve().parents[2] / 'experiment/acquire_real_project_builds.sh'


def fixture(tmp_path, monkeypatch, *, source_code=0, configure_code=0, prepare_code=0):
    tooling=tmp_path/'tooling'; scripts=tooling/'experiment'; scripts.mkdir(parents=True)
    (scripts/'check_project_acquisition.py').write_text('print("available")\n')
    (scripts/'prepare_real_project_experiment.py').write_text('''import sys,json
from pathlib import Path
operation=sys.argv[1]
if operation=='verify-source':
 print('source-check')
 if SOURCE_CODE: sys.exit(SOURCE_CODE)
Path(sys.argv[sys.argv.index('--output')+1]).write_text('{}')
'''.replace('SOURCE_CODE',str(source_code)))
    (scripts/'capture_project_build.py').write_text('''import sys,json,os
from pathlib import Path
args=sys.argv[1:]
if args[0]=='create':
 p=Path(args[args.index('--output')+1]);p.mkdir();(p/'capture.json').write_text('{}')
else:
 stage=args[args.index('--stage')+1]
 Path(__file__).with_name(stage+'-argv.json').write_text(json.dumps(args))
 code={'configure':CONFIGURE_CODE,'prepare':PREPARE_CODE}.get(stage,0)
 print('actual-'+stage+'-return-'+str(code))
 if code: sys.exit(code)
 b=Path(args[args.index('--cwd')+1])
 if stage=='configure':
  (b/'.config').write_text('CONFIG_64BIT=y\\n')
  for name in ('config.h','gmp.h','gmp-mparam.h','Makefile','config.status','libtool'):(b/name).touch()
'''.replace('CONFIGURE_CODE',str(configure_code)).replace('PREPARE_CODE',str(prepare_code)))
    prep=tmp_path/'prep'; (prep/'upstream/gmp-6.3.0').mkdir(parents=True)
    guess=prep/'upstream/gmp-6.3.0/config.guess'
    guess.write_text('#!/bin/sh\necho x86_64-pc-linux-gnu\n');guess.chmod(0o755)
    archives=tmp_path/'archives';archives.mkdir()
    monkeypatch.setattr(a,'preflight',lambda project:{'prerequisitesAvailable':True,'missing':[],
        'tools':[{'role':k,'path':sys.executable} for k in a.TOOLS]})
    return tooling,prep,archives,tmp_path/'new-result'


def test_source_failure_stops_before_capture_and_build(tmp_path,monkeypatch,capsys):
    args=fixture(tmp_path,monkeypatch,source_code=9)
    assert a.acquire(*args,'gmp')==9
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert state['primaryFailure']['stage']=='source'
    assert state['primaryFailure']['returnCode']==9
    assert not (args[-1]/'capture').exists() and not (args[-1]/'build').exists()
    assert 'source.log' in capsys.readouterr().err
    before=(args[-1]/'run-status.json').read_bytes()
    assert a.main([*map(str,args),'gmp'])==2
    assert (args[-1]/'run-status.json').read_bytes()==before


@pytest.mark.parametrize('project,stage,code',[('gmp','configure',1),('linux','prepare',2)])
def test_native_failure_preserves_status_and_exports_diagnostic(tmp_path,monkeypatch,capsys,project,stage,code):
    args=fixture(tmp_path,monkeypatch,configure_code=code if stage=='configure' else 0,
                 prepare_code=code if stage=='prepare' else 0)
    assert a.acquire(*args,project)==code
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert state['primaryFailure']['stage']==stage and state['primaryFailure']['returnCode']==code
    assert state['status']=='failed' and not state['acquisitionComplete']
    assert not state['semanticApproval'] and not state['productionAcceptanceComplete']
    assert (args[-1]/'failure-records.json').exists()
    assert stage+'.log' in capsys.readouterr().err
    assert not (args[-1]/'build.log').exists() and not (args[-1]/'diagnostic-build.log').exists()
    assert not (args[-1]/'records.json').exists()


def test_gmp_recipe_does_not_inherit_wrong_abi_selector(tmp_path,monkeypatch):
    args=fixture(tmp_path,monkeypatch)
    monkeypatch.setenv('ABI','64')
    assert a.acquire(*args,'gmp')==0
    argv=json.loads((args[0]/'experiment/configure-argv.json').read_text())
    tail=argv[argv.index('--')+1:]
    assert tail[1:3]==['-u','ABI']
    assert 'ABI=64' not in tail
    assert 'CFLAGS=-O2 -march=rv64gc -mabi=lp64d' in tail
    # Also execute the actual env command; recipe inspection alone is insufficient.
    r=subprocess.run([tail[0],'-u','ABI',sys.executable,'-c','import os;assert "ABI" not in os.environ'],check=False)
    assert r.returncode==0


def test_missing_dependency_stops_before_source_and_capture(tmp_path,monkeypatch,capsys):
    args=fixture(tmp_path,monkeypatch)
    monkeypatch.setattr(a,'preflight',lambda project:{'prerequisitesAvailable':False,
        'tools':[],'missing':[{'role':'bc','reason':'not found'}]})
    assert a.acquire(*args,'linux')==2
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert state['primaryFailure']['stage']=='prerequisites'
    assert 'bc' in state['primaryFailure']['detail']
    assert not (args[-1]/'source.log').exists()
    assert 'bc' in capsys.readouterr().err


def test_real_stage_child_failure_is_visible_without_bash_err_trap(tmp_path,capsys):
    runner=a.Runner(tmp_path/'out','gmp')
    with pytest.raises(a.StageFailure):
        runner.step('configure',[sys.executable,'-c','import sys;print("native-error");sys.exit(3)'])
    assert 'native-error' in (runner.output/'configure.log').read_text()
    assert 'configure.log' in capsys.readouterr().err
    state=json.loads((runner.output/'run-status.json').read_text())
    assert state['primaryFailure']['returnCode']==3


def test_dependency_preflight_records_bc_missing_without_hiding_other_tools(monkeypatch):
    original=a.resolve_executable
    def resolve(name):
        if name=='bc':raise FileNotFoundError('missing-bc')
        return original(sys.executable)
    monkeypatch.setattr(a,'resolve_executable',resolve)
    result=a.preflight('linux')
    assert result['missing']==[{'role':'bc','requested':'bc','reason':'missing-bc'}]
    assert result['tools'] and not result['prerequisitesAvailable']
    assert not result['allBuildDependenciesVerified']


def test_shell_wrapper_rejects_existing_output_without_erasing_it(tmp_path):
    output=tmp_path/'old';output.mkdir(); marker=output/'keep';marker.write_text('evidence')
    run=subprocess.run(['bash',str(DRIVER),str(tmp_path),str(tmp_path),str(tmp_path),str(output),'gmp'],capture_output=True,text=True)
    assert run.returncode==2 and 'OUTPUT_EXISTS' in run.stderr
    assert marker.read_text()=='evidence'


def test_diagnostic_export_failure_never_masks_original_failure(tmp_path,monkeypatch):
    args=fixture(tmp_path,monkeypatch,configure_code=5)
    path=args[0]/'experiment/prepare_real_project_experiment.py'
    path.write_text(path.read_text().replace("operation=sys.argv[1]", "operation=sys.argv[1]\nif operation=='import-capture':sys.exit(12)"))
    assert a.acquire(*args,'gmp')==5
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert state['primaryFailure']['returnCode']==5
    assert state['diagnostics'][0]['returnCode']==12


def test_real_child_signal_is_preserved_in_stage_evidence(tmp_path):
    runner=a.Runner(tmp_path/'out','linux')
    with pytest.raises(a.StageFailure) as error:
        runner.step('prepare',[sys.executable,'-c','import os,signal;os.kill(os.getpid(),signal.SIGTERM)'])
    assert error.value.code==-15
    state=json.loads((runner.output/'run-status.json').read_text())
    assert state['primaryFailure']['returnCode']==-15
    assert not state['acquisitionComplete']
