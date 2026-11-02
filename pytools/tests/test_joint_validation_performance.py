"""Lifecycle/cost regressions with explicit adapters, not real ISA acceptance."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from riscv2x86_py.l3_backend_validation import checked
from riscv2x86_py.l3_trace_support import digest
from riscv2x86_py.validation_timing import timed


def setup_operation(tmp_path,monkeypatch,mutation=None):
    from riscv2x86_py import l3_joint_route as route,l3_joint_backend as backend
    path=tmp_path/'backend.json';path.write_text(json.dumps({'version':1}))
    dependency=tmp_path/'dependency';dependency.write_text('original')
    calls=[];executed=[]
    def validate(value):
        calls.append(1)
        assert dependency.read_text()=='original','dependency changed'
        return json.loads(Path(value).read_text()) if isinstance(value,(str,Path)) else value
    monkeypatch.setattr(route,'backend_validate',validate)
    monkeypatch.setattr(backend,'validate',validate)
    def prepare(*args):
        return {'spec':{},'samplePlan':{'inputs':[0]},'sides':{
            s:{'executionArtifact':{'artifactPath':'fixture-'+s},'regions':[]} for s in ('source','target')}}
    monkeypatch.setattr(route,'prepare',prepare)
    def capture(b,side,binary,regions,directory,calls,timeout,**kw):
        # Exercise the exact operation/path binding, but no emulator is claimed.
        session=kw['_context'];current=checked(session,validate,kw['_backend_path'])
        assert current==b
        executed.append(side)
        return [],'',{'token':'fixture-only'}
    monkeypatch.setattr(route,'capture',capture)
    monkeypatch.setattr(route,'parse_samples',lambda *args: [])
    monkeypatch.setattr(route,'platform',lambda *args: {})
    def replay(group,source,target,*,_context=None):
        checked(_context,validate,group['backendPath'])
        if mutation=='dependency':dependency.write_text('changed')
        if mutation=='backend':path.write_text(json.dumps({'version':2}))
        return group
    monkeypatch.setattr(route,'replay_group',replay)
    config={'backendPath':str(path),'backendDigest':digest(path),'sourcePath':'fixture-source',
            'targetPath':'fixture-target','clang':'fixture-clang','sampleCount':1,'timeoutSeconds':1}
    return route,config,calls,executed


def test_one_capture_reuses_checks_but_has_uncached_closing_validation(tmp_path,monkeypatch):
    route,config,calls,executed=setup_operation(tmp_path,monkeypatch)
    value=route.new_capture(config,'report',None,None,[],tmp_path/'work')
    assert len(calls)==2 and executed==['source','target']
    assert value['backendPath']==config['backendPath']
    # A second operation receives a new session; no cross-run trust.
    route.new_capture(config,'report',None,None,[],tmp_path/'second')
    assert len(calls)==4


@pytest.mark.parametrize('mutation',['backend','dependency'])
def test_changed_dependencies_cannot_return_capture_group(tmp_path,monkeypatch,mutation):
    route,config,calls,executed=setup_operation(tmp_path,monkeypatch,mutation)
    with pytest.raises((AssertionError,ValueError)):
        route.new_capture(config,'report',None,None,[],tmp_path/'work')
    assert len(calls)==2 and executed==['source','target']
    assert not (tmp_path/'work/capture-group.json').exists()


def test_capture_keeps_default_checks_and_context_rejects_backend_substitution(tmp_path,monkeypatch):
    from riscv2x86_py import l3_joint_backend as backend
    from riscv2x86_py.l3_backend_validation import BackendValidationSession
    path=tmp_path/'backend';path.write_text('{}');calls=[]
    def validate(value,**kwargs):calls.append(1);return {}
    monkeypatch.setattr(backend,'validate',validate)
    # Reject a mismatched in-memory backend before attempting any execution.
    with pytest.raises(ValueError,match='CAPTURE_BACKEND_CHANGED'):
        with BackendValidationSession() as session:
            backend.capture({'changed':True},'source','unused',[],tmp_path,1,1,_context=session,_backend_path=path)
    assert len(calls)==1
    with pytest.raises(ValueError,match='CONTEXT_INVALID'):
        with BackendValidationSession() as session:
            backend.capture({},'source','unused',[],tmp_path,1,1,calibration=True,_context=session,_backend_path=path)


def test_real_capture_function_has_two_default_checks_and_session_closure(tmp_path,monkeypatch):
    from riscv2x86_py import l3_joint_backend as backend
    from riscv2x86_py.l3_backend_validation import BackendValidationSession
    binary=tmp_path/'binary';binary.write_bytes(b'fixture, not an executable')
    path=tmp_path/'backend';path.write_text('{}');checks=[];runs=[]
    def validate(value,**kw):checks.append(1);return {}
    monkeypatch.setattr(backend,'validate',validate)
    monkeypatch.setattr(backend,'command',lambda b,s,binary,regions,path,token:[str(path),token])
    def run(args,directory,phase,timeout):
        runs.append(1);trace=Path(args[0]);trace.write_text('H 3 '+args[1]+' riscv64\nF 0 0 0 0\n')
        (Path(directory)/'execute.command.json').write_text('{}')
        return SimpleNamespace(stderr='',stdout='')
    monkeypatch.setattr(backend,'run',run)
    backend.capture({},'source',binary,[],tmp_path/'default',0,1)
    assert len(checks)==2
    checks.clear()
    with BackendValidationSession() as session:
        checked(session,validate,path)
        for side in ('one','two'):
            backend.capture({},'source',binary,[],tmp_path/side,0,1,_context=session,_backend_path=path)
        assert len(checks)==1
    assert len(checks)==2 and len(runs)==3


def test_timing_nesting_exceptions_and_opt_out(tmp_path,monkeypatch):
    destination=tmp_path/'timing.jsonl';monkeypatch.setenv('RV2X86_VALIDATION_TIMING',str(destination))
    @timed('inner')
    def inner():return 7
    @timed('outer')
    def outer():return inner()
    assert outer()==7
    @timed('raising')
    def raising():raise ValueError('original failure')
    with pytest.raises(ValueError,match='original failure'):raising()
    rows=[json.loads(x) for x in destination.read_text().splitlines()]
    assert len(rows)==3 and rows[0]['parent']==rows[1]['span']
    assert rows[2]['returned'] is False
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_validation_timing.py'
    spec=importlib.util.spec_from_file_location('inspect_validation_timing',script)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    summary=module.summarize(destination)
    assert summary['spanCount']==3 and not summary['incompleteParentSpans']
    assert summary['stages']['outer']['exclusiveSeconds']<=summary['stages']['outer']['inclusiveSeconds']
    monkeypatch.delenv('RV2X86_VALIDATION_TIMING');assert outer()==7
    assert len(destination.read_text().splitlines())==3


def test_failed_timing_write_does_not_hide_validation_exception(tmp_path,monkeypatch,capsys):
    monkeypatch.setenv('RV2X86_VALIDATION_TIMING',str(tmp_path/'missing'/'timing'))
    @timed('failing')
    def operation():raise ValueError('original validation error')
    with pytest.raises(ValueError,match='original validation error'):operation()
    assert 'TIMING_WRITE_FAILED' in capsys.readouterr().err
