"""Operation-local reuse invariants. Native adapters are NOT dual-ISA approval."""
from copy import deepcopy
import json
from pathlib import Path
import threading
import pytest
from riscv2x86_py.atomic_validation_operation import AtomicValidationOperation,checked,current,watch_files,operation
from riscv2x86_py.l3_trace_support import digest


@pytest.fixture(autouse=True)
def default_reuse_mode(monkeypatch):
    monkeypatch.setenv('RV2X86_ATOMIC_PERFORMANCE','1')


def test_reuse_is_success_only_isolated_typed_and_closed(monkeypatch):
    monkeypatch.setenv('RV2X86_ATOMIC_PERFORMANCE','1');calls=[]
    def compute(v):calls.append(deepcopy(v));return {'value':v}
    with AtomicValidationOperation('production') as scope:
        first=checked(compute,{'n':1});first['value']['n']=99
        assert checked(compute,{'n':1})=={'value':{'n':1}}
        checked(compute,{'n':True})
        assert len(calls)==2
    assert len(calls)==4 and current() is None and not scope.entries
    with pytest.raises(ValueError):scope.check(compute,{})
    with AtomicValidationOperation('again'):checked(compute,{'n':1})
    assert len(calls)==6


@pytest.mark.parametrize('mode,expected',[('0',4),('1',2)])
def test_same_code_control_and_closing_work(monkeypatch,mode,expected):
    monkeypatch.setenv('RV2X86_ATOMIC_PERFORMANCE',mode);calls=[]
    def compute(v):calls.append(1);return v
    with AtomicValidationOperation('test'):
        assert [checked(compute,{'a':2}) for _ in range(4)]==[{'a':2}]*4
    assert len(calls)==expected


def test_failures_are_not_cached_and_changed_closing_result_is_rejected():
    calls=[]
    def fail(v):calls.append(1);raise ValueError('failure')
    with AtomicValidationOperation('failure'):
        for _ in range(2):
            with pytest.raises(ValueError,match='failure'):checked(fail,{})
    assert len(calls)==2
    calls=[]
    def changing(v):calls.append(1);return {'value':1 if len(calls)==1 else True}
    with pytest.raises(ValueError,match='CLOSING_REPLAY_CHANGED'):
        with AtomicValidationOperation('type-sensitive'):checked(changing,{})
    assert current() is None


def test_nested_audit_and_threads_do_not_inherit_production_trust():
    calls=[]
    def compute(v):calls.append(1);return v
    with AtomicValidationOperation('production') as parent:
        checked(compute,{})
        with AtomicValidationOperation('independent-audit'):checked(compute,{})
        assert len(calls)==3 and current() is parent
        seen=[];thread=threading.Thread(target=lambda:seen.append(current()))
        thread.start();thread.join();assert seen==[None]
        checked(compute,{})
    assert len(calls)==4


@pytest.mark.parametrize('closing',[False,True])
def test_file_changes_cannot_be_hidden_by_hits(tmp_path,closing):
    path=tmp_path/'input';path.write_text('initial');files={str(path):digest(path)}
    with pytest.raises(ValueError,match='FILE_CHANGED'):
        with AtomicValidationOperation('files'):
            watch_files(files);path.write_text('changed')
            if not closing:watch_files(files)
    assert current() is None


def test_decorated_entry_cannot_return_success_after_closing_failure():
    calls=[]
    def compute(v):calls.append(1);return len(calls)
    @operation('entry')
    def entry():checked(compute,{});return {'status':'verified'}
    with pytest.raises(ValueError,match='CLOSING_REPLAY_CHANGED'):entry()



@pytest.mark.parametrize('mode,expected',[('0',5),('1',2)])
def test_calibration_reuse_hashes_every_input_and_closes_fresh(tmp_path,monkeypatch,mode,expected):
    from riscv2x86_py.atomic_validation_operation import calibration
    monkeypatch.setenv('RV2X86_ATOMIC_PERFORMANCE',mode)
    paths=[tmp_path/x for x in ('probe','probe.S','trace','execute.command.json','build.command.json')]
    for p in paths:p.write_text('intact')
    record={'binary':str(paths[0]),'assembly':str(paths[1]),'evidence':{'rawTracePath':str(paths[2])}}
    calls=[]
    @calibration
    def check(value,record):
        assert value['plugin']=='p';calls.append(1)
        assert Path(record['binary']).read_text()=='intact'
    with AtomicValidationOperation('calibrations'):
        for _ in range(5):check({'plugin':'p','calibration':[1,2]},record)
    assert len(calls)==expected


@pytest.mark.parametrize('name',['probe','probe.S','trace','execute.command.json','build.command.json'])
@pytest.mark.parametrize('closing',[False,True])
def test_calibration_changed_file_rejected_on_hit_or_close(tmp_path,monkeypatch,name,closing):
    from riscv2x86_py.atomic_validation_operation import calibration
    for n in ('probe','probe.S','trace','execute.command.json','build.command.json'):(tmp_path/n).write_text('intact')
    record={'binary':str(tmp_path/'probe'),'assembly':str(tmp_path/'probe.S'),'evidence':{'rawTracePath':str(tmp_path/'trace')}}
    @calibration
    def check(value,record):
        if any(p.read_text()!='intact' for p in tmp_path.iterdir()):raise ValueError('calibration invalid')
    with pytest.raises(ValueError):
        with AtomicValidationOperation('calibrations'):
            check({'plugin':'p'},record);(tmp_path/name).write_text('changed')
            if not closing:check({'plugin':'p'},record)
    assert current() is None


def test_base_validation_reuse_and_closing_provenance(tmp_path,monkeypatch):
    from riscv2x86_py.atomic_validation_operation import validate_base
    from riscv2x86_py import l3_base_validation
    tool=tmp_path/'tool';tool.write_text('original');manifest=tmp_path/'backend.json'
    manifest.write_text(json.dumps({'files':{str(tool):digest(tool)}}));calls=[]
    def full(path):calls.append(1);return json.loads(Path(path).read_text())
    monkeypatch.setattr(l3_base_validation,'validate_optimized',full)
    with AtomicValidationOperation('base'):
        for _ in range(5):validate_base(manifest)
        assert len(calls)==1
    assert len(calls)==2
    with pytest.raises(ValueError,match='FILE_CHANGED'):
        with AtomicValidationOperation('changed'):
            validate_base(manifest);tool.write_text('changed');validate_base(manifest)


@pytest.mark.parametrize('kind',['atomic','lrsc'])
@pytest.mark.parametrize('side',['source','target'])
@pytest.mark.parametrize('changed',['trace','command'])
def test_raw_damage_rejected_before_backend_or_deployment(tmp_path,monkeypatch,kind,side,changed):
    from importlib import import_module
    from riscv2x86_py.l3_trace_support import save,identity
    route=import_module('riscv2x86_py.l3_'+kind+'_route')
    manifest=tmp_path/'backend.json';manifest.write_text('{}')
    body={'schemaVersion':route.CONTRACT,'backendPath':str(manifest),'backendDigest':digest(manifest),
          'atomicPolicy':'executed-rmw-outcomes-and-approved-contract.v2' if kind=='atomic' else 'executed-lrsc-cas-outcomes-and-approved-contract.v1',
          'limitations':sorted(route.LIMITS)}
    contract=tmp_path/'contract.json';save(contract,dict(body,contractIdentity=identity(body)))
    detail={'contractPath':str(contract),'contractDigest':digest(contract),'platformReports':{}}
    for s in ('source','target'):
        directory=tmp_path/s;directory.mkdir();trace=directory/'trace';trace.write_text('raw')
        command=directory/'execute.command.json';command.write_text('{}')
        detail['platformReports'][s]={'evidence':{'rawTracePath':str(trace),'rawTraceDigest':digest(trace),'commandRecordDigest':digest(command)}}
    destination=tmp_path/side/('trace' if changed=='trace' else 'execute.command.json');destination.write_text('tamper')
    def forbidden(*args):raise AssertionError('expensive rebuild reached')
    monkeypatch.setattr(route,'backend_validate',forbidden);monkeypatch.setattr(route,'replay_deployment',forbidden)
    with pytest.raises(ValueError,match='RAW_CAPTURE_CHANGED'):route.replay(detail,None,None,None)

# Real calibration parsers/decoders over fixture tool artifacts; not ISA approval.
from tests.test_l3_atomic_trace import calibration_tools


@pytest.mark.parametrize('mode',['0','1'])
def test_all_138_atomic_calibrations_are_replayed_in_both_epochs(calibration_tools,monkeypatch,mode):
    monkeypatch.setenv('RV2X86_ATOMIC_PERFORMANCE',mode)
    backend,path,out=calibration_tools;value=backend.prepare(path,out)
    calls=[];original=backend.instruction
    def counted(*args):calls.append(args[-1]['case'] if 'case' in args[-1] else args[-1]);return original(*args)
    monkeypatch.setattr(backend,'instruction',counted)
    with AtomicValidationOperation('all-138'):
        for _ in range(4):assert backend.validate(value)==value
        assert len(calls)==(1 if mode=='1' else 4)*len(backend.CASES)
    assert len(calls)==(2 if mode=='1' else 4)*len(backend.CASES)


def test_closing_leaf_cannot_inherit_initial_or_nested_audit_trust():
    from riscv2x86_py.atomic_validation_operation import leaf_checked
    calls=[]
    def compute(value):calls.append(1);return value
    with AtomicValidationOperation('production'):
        for _ in range(3):leaf_checked(compute,{'x':True})
        with AtomicValidationOperation('independent'):
            leaf_checked(compute,{'x':True})
        assert len(calls)==3
    assert len(calls)==4


@pytest.mark.parametrize('closing_failure',[False,True])
def test_complete_operation_timing_covers_closing_and_records_its_failure(tmp_path,monkeypatch,closing_failure):
    import importlib.util
    destination=tmp_path/'timing.jsonl'
    monkeypatch.setenv('RV2X86_VALIDATION_TIMING',str(destination))
    calls=[]
    def calculate(value):
        calls.append(1)
        if closing_failure and len(calls)==2:raise ValueError('closing rejected')
        return value
    @operation('timing-fixture')
    def execute():
        checked(calculate,{'input':1})
        return {'status':'verified'}
    if closing_failure:
        with pytest.raises(ValueError,match='closing rejected'):execute()
    else:assert execute()['status']=='verified'
    assert len(calls)==2 and current() is None
    rows=[json.loads(line) for line in destination.read_text().splitlines()]
    outer,=[r for r in rows if r['stage']=='atomic.operation-complete.timing-fixture']
    close,=[r for r in rows if r['stage']=='atomic.operation-closing-replay']
    assert close['parent']==outer['span']
    assert outer['startNs']<=close['startNs']<=close['endNs']<=outer['endNs']
    assert outer['returned'] is (not closing_failure)
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_validation_timing.py'
    spec=importlib.util.spec_from_file_location('atomic_timing_summary',script)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    summary=module.summarize(destination)
    item,=summary['atomicOperations']
    assert item['closingReplayCalls']==1 and item['returned'] is (not closing_failure)
    assert item['inclusiveSeconds']>=summary['stages']['atomic.operation-closing-replay']['inclusiveSeconds']
    assert summary['semanticApproval'] is False
