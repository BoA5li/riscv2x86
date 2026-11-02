"""Operation-local reuse invariants. Native adapters are NOT dual-ISA approval."""
from copy import deepcopy
import json
from pathlib import Path
import threading
import pytest
from riscv2x86_py.joint_validation_operation import JointValidationOperation,checked,current,watch_files,operation
from riscv2x86_py.l3_trace_support import digest


@pytest.fixture(autouse=True)
def default_reuse_mode(monkeypatch):
    monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE','1')


def test_reuse_is_success_only_isolated_typed_and_closed(monkeypatch):
    monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE','1');calls=[]
    def compute(v):calls.append(deepcopy(v));return {'value':v}
    with JointValidationOperation('production') as scope:
        first=checked(compute,{'n':1});first['value']['n']=99
        assert checked(compute,{'n':1})=={'value':{'n':1}}
        checked(compute,{'n':True})
        assert len(calls)==2
    assert len(calls)==4 and current() is None and not scope.entries
    with pytest.raises(ValueError):scope.check(compute,{})
    with JointValidationOperation('again'):checked(compute,{'n':1})
    assert len(calls)==6


@pytest.mark.parametrize('mode,expected',[('0',4),('1',2)])
def test_same_code_control_and_closing_work(monkeypatch,mode,expected):
    monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE',mode);calls=[]
    def compute(v):calls.append(1);return v
    with JointValidationOperation('test'):
        assert [checked(compute,{'a':2}) for _ in range(4)]==[{'a':2}]*4
    assert len(calls)==expected


def test_failures_are_not_cached_and_changed_closing_result_is_rejected():
    calls=[]
    def fail(v):calls.append(1);raise ValueError('failure')
    with JointValidationOperation('failure'):
        for _ in range(2):
            with pytest.raises(ValueError,match='failure'):checked(fail,{})
    assert len(calls)==2
    calls=[]
    def changing(v):calls.append(1);return {'value':1 if len(calls)==1 else True}
    with pytest.raises(ValueError,match='CLOSING_REPLAY_CHANGED'):
        with JointValidationOperation('type-sensitive'):checked(changing,{})
    assert current() is None


def test_nested_audit_and_threads_do_not_inherit_production_trust():
    calls=[]
    def compute(v):calls.append(1);return v
    with JointValidationOperation('production') as parent:
        checked(compute,{})
        with JointValidationOperation('independent-audit'):checked(compute,{})
        assert len(calls)==3 and current() is parent
        seen=[];thread=threading.Thread(target=lambda:seen.append(current()))
        thread.start();thread.join();assert seen==[None]
        checked(compute,{})
    assert len(calls)==4


@pytest.mark.parametrize('closing',[False,True])
def test_file_changes_cannot_be_hidden_by_hits(tmp_path,closing):
    path=tmp_path/'input';path.write_text('initial');files={str(path):digest(path)}
    with pytest.raises(ValueError,match='FILE_CHANGED'):
        with JointValidationOperation('files'):
            watch_files(files);path.write_text('changed')
            if not closing:watch_files(files)
    assert current() is None


def test_decorated_entry_cannot_return_success_after_closing_failure():
    calls=[]
    def compute(v):calls.append(1);return len(calls)
    @operation('entry')
    def entry():checked(compute,{});return {'status':'verified'}
    with pytest.raises(ValueError,match='CLOSING_REPLAY_CHANGED'):entry()


def test_backend_api_hits_still_have_fresh_closing_validation(tmp_path,monkeypatch):
    from riscv2x86_py import l3_joint_backend as subject
    path=tmp_path/'backend';path.write_text('{}');dependency=tmp_path/'tool';dependency.write_text('good');calls=[]
    def full(value,**kw):
        calls.append(1)
        if dependency.read_text()!='good':raise ValueError('dependency changed')
        return {'version':1}
    monkeypatch.setattr(subject,'_validate_full',full)
    with JointValidationOperation('backend'):
        for _ in range(8):assert subject.validate(path)=={'version':1}
        assert len(calls)==1
    assert len(calls)==2
    with pytest.raises(ValueError,match='dependency changed'):
        with JointValidationOperation('changed'):
            subject.validate(path);dependency.write_text('bad');subject.validate(path)
    assert len(calls)==4


@pytest.mark.parametrize('mode,expected',[('0',3),('1',2)])
def test_native_l2_common_rebuild_reuse_retains_member_replay(tmp_path,monkeypatch,mode,expected):
    from tests.test_l2_joint_registry import setup,registry,artifact
    from riscv2x86_py import l2_joint_replay as replay
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    findings,fn,c=setup(tmp_path,monkeypatch);monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE',mode)
    # Produce a real persisted native observation through the central provider.
    layer=registry(tmp_path,findings,c,findings[0]).validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2,translation_artifact=artifact(findings[0]),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is ValidationStatus.VERIFIED,layer.detail
    value=json.loads((Path(c['replayDirectory'])/'joint-observation.json').read_text())
    calls=[];original=replay._rebuild_program
    def rebuild(v):calls.append(1);return original(v)
    monkeypatch.setattr(replay,'_rebuild_program',rebuild)
    with JointValidationOperation('native'):
        for _ in range(3):assert replay.replay(deepcopy(value))==value
    assert len(calls)==expected
    # Even after a hit, the invocation's own normalized output is rechecked.
    with JointValidationOperation('member-tamper'):
        replay.replay(deepcopy(value));bad=deepcopy(value);bad['source']['boundaries'][1]['values'][0]='bad'
        with pytest.raises(ValueError,match='OBSERVATION_REPLAY_MISMATCH'):replay.replay(bad)


def test_invalid_mode_and_non_json_results_are_not_silent(monkeypatch):
    monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE','yes')
    with pytest.raises(ValueError,match='MODE_INVALID'):
        with JointValidationOperation('invalid'):pass
    monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE','1')
    with JointValidationOperation('json'):
        with pytest.raises(ValueError,match='NOT_JSON'):checked(lambda v:(1,2),{})


# Reuse the existing real subprocess protocol fixture; compiler joins remain stubs.
from tests.test_l3_production_ingress import ingress


@pytest.mark.parametrize('mode,expected',[('0',4),('1',2)])
def test_receipts_batch_whole_program_but_keep_individual_bindings(ingress,monkeypatch,mode,expected):
    from riscv2x86_py import l3_intent_ingress as subject
    source,report,manifest,tool,artifact,seal=ingress
    tool.write_text(tool.read_text().replace("'proof-region'","'compiler-joint-regions'"));seal()
    finding=subject.produce_intents(source,report,manifest)['findings'][0]
    report.with_name('compiler-candidates.json').write_text('{}')
    Path(str(report)+'.attempts.json').write_text('{}')
    calls=[];original=subject.produce_intents
    def producer(*a,**kw):calls.append(1);return original(*a,**kw)
    monkeypatch.setattr(subject,'produce_intents',producer);monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE',mode)
    with JointValidationOperation('receipts'):
        for _ in range(4):subject.validate_receipt(finding,artifact,source,report)
        bad=deepcopy(finding);bad['l3IntentDisposition']={'unexpected':True}
        with pytest.raises(ValueError,match='producer-replay-mismatch'):subject.validate_receipt(bad,artifact,source,report)
    # The bad member also runs the producer in full-work mode.
    assert len(calls)==(expected+1 if mode=='0' else expected)
    monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE','1')
    with pytest.raises(ValueError):
        with JointValidationOperation('receipt-tool-change'):
            subject.validate_receipt(finding,artifact,source,report);tool.write_text('changed tool')


def test_three_distinct_members_share_only_common_native_rebuild(tmp_path,monkeypatch):
    from tests.test_l2_joint_registry import setup,registry,artifact
    from riscv2x86_py import l2_joint_replay as replay
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    findings,fn,c=setup(tmp_path,monkeypatch);calls=[];original=replay._rebuild_program
    def rebuild(v):calls.append(1);return original(v)
    monkeypatch.setattr(replay,'_rebuild_program',rebuild)
    snapshots=[]
    with JointValidationOperation('three-members'):
        for index,finding in enumerate(findings):
            member=dict(c,workDirectory=str(tmp_path/('work-'+str(index))),replayDirectory=str(tmp_path/('replay-'+str(index))))
            layer=registry(tmp_path,findings,member,finding).validator_for(ValidationLevel.L2)(
                level=ValidationLevel.L2,translation_artifact=artifact(finding),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
            assert layer.status is ValidationStatus.VERIFIED,layer.detail
            snapshots.append(json.loads((Path(member['replayDirectory'])/'joint-observation.json').read_text()))
        assert len(calls)==1
        bad=deepcopy(snapshots[-1]);bad['approvedRelationAuthority']['unexpected']=1
        with pytest.raises(ValueError,match='RELATION_REPLAY_MISMATCH'):replay.replay(bad)
    assert len(calls)==2


def test_selection_gate_is_joint_only_and_rechecks_transitive_inputs(tmp_path,monkeypatch):
    from riscv2x86_py import l3_mechanism_selection as subject
    selection=tmp_path/'selection.json';tool=tmp_path/'tool';tool.write_text('valid');calls=[]
    def load(path,**kw):
        calls.append(1)
        if tool.read_text()!='valid':raise ValueError('tool changed')
        return {'joint':{'backendIdentity':'fixture'}}
    monkeypatch.setattr(subject,'_load',load)
    selection.write_text(json.dumps({'backends':{'joint':'fixture'}}))
    with JointValidationOperation('selection'):
        for _ in range(4):subject.load(selection)
    assert len(calls)==2
    with pytest.raises(ValueError,match='tool changed'):
        with JointValidationOperation('changed-selection-tool'):
            subject.load(selection);tool.write_text('bad');subject.load(selection)
    tool.write_text('valid');calls.clear();selection.write_text(json.dumps({'backends':{'memory':'fixture'}}))
    with JointValidationOperation('non-joint'):
        for _ in range(4):subject.load(selection)
    assert len(calls)==4


def test_evaluation_entry_defers_return_until_closing_replay(tmp_path):
    from tests.test_evaluation_runner import _setup
    from riscv2x86_py.evaluation import run_evaluation,_execute
    request,source,attempt=_setup(tmp_path);calls=[]
    def changing(v):calls.append(1);return len(calls)
    def execute(*args):
        assert current() is not None
        checked(changing,{})
        return _execute(*args)
    with pytest.raises(ValueError,match='CLOSING_REPLAY_CHANGED'):
        run_evaluation(request,work_directory=tmp_path/'evaluation',command_executor=execute)
    assert len(calls)==2 and current() is None
