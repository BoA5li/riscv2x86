"""Real Git parity, integrity and epoch tests; not real QEMU/ISA approval."""
import ast
from copy import deepcopy
import inspect
import json
from pathlib import Path
import pytest
from tests.test_l3_qemu_dependencies import repositories,configured_binding,prepare,git,commit
from riscv2x86_py import l3_qemu_dependencies as old,l3_dependency_validation as fast
from riscv2x86_py.joint_validation_operation import JointValidationOperation,leaf_checked


@pytest.fixture(autouse=True)
def modes(monkeypatch):
    monkeypatch.setenv('RV2X86_JOINT_PERFORMANCE_V2','1')
    monkeypatch.setenv('RV2X86_JOINT_OPERATION_REUSE','1')


def test_complete_backend_gates_are_ast_identical():
    from riscv2x86_py import l3_base_validation as new,l3_qemu_backend as legacy
    for a,b in ((new.validate_optimized,legacy.validate_backend),(new._validate_source_preparation,legacy._validate_source_preparation)):
        left=ast.parse(inspect.getsource(a));right=ast.parse(inspect.getsource(b))
        left.body[0].name=right.body[0].name
        for node in ast.walk(left):
            if isinstance(node,ast.ImportFrom) and node.module=='l3_dependency_validation':node.module='l3_qemu_dependencies'
        assert ast.dump(left,include_attributes=False)==ast.dump(right,include_attributes=False)


def test_real_git_snapshot_parity_and_fewer_processes(repositories,monkeypatch):
    record=prepare(repositories);calls=[];run=old._git
    def counted(*args):calls.append(args[1:]);return run(*args)
    monkeypatch.setattr(old,'_git',counted);monkeypatch.setattr(fast,'_git',counted)
    assert old.verify_prepared_dependencies(record,expected_commit=repositories[1])==record
    baseline=len(calls);calls.clear()
    assert fast.verify_prepared_dependencies(record,expected_commit=repositories[1])==record
    assert len(calls)<baseline
    assert sum(args[0]=='fsck' for args in calls)==6
    for item in record['dependencies']:
        assert fast.inspect_checkout(item['preparedPath'],item['commit'],independent=True)==item['preparedSnapshot']


@pytest.mark.parametrize('mutation',['hidden-dirty','untracked','mode','escape','parent-link','missing-blob','alternates','wrong-head','snapshot','source-file'])
def test_optimized_provenance_keeps_legacy_rejection(repositories,mutation):
    source,sha,target,logs=repositories;record=prepare(repositories);module=target/old.PATHS[0]
    if mutation=='hidden-dirty':
        git(module,'update-index','--assume-unchanged','input.txt');(module/'input.txt').write_text('hidden')
    if mutation=='untracked':(module/'new.c').write_text('unexpected')
    if mutation=='mode':(module/'executable.sh').chmod(0o644)
    if mutation=='escape':(module/'link').unlink();(module/'link').symlink_to(source/'configure')
    if mutation=='parent-link':
        parent=module/'test cases';outside=module.parent/'outside';parent.rename(outside);parent.symlink_to(outside)
    if mutation=='missing-blob':
        blob=git(module,'rev-parse','HEAD:input.txt');(module/'.git/objects'/blob[:2]/blob[2:]).unlink()
    if mutation=='alternates':(module/'.git/objects/info/alternates').write_text(str(source/old.PATHS[0]/'.git/objects'))
    if mutation=='wrong-head':
        git(module,'config','user.name','Fixture');git(module,'config','user.email','f@example.invalid')
        (module/'input.txt').write_text('new');commit(module)
    if mutation=='snapshot':(target/'.git-submodule-status').write_text('fake')
    if mutation=='source-file':(target/'configure').write_text('changed')
    for verifier in (old.verify_prepared_dependencies,fast.verify_prepared_dependencies):
        with pytest.raises((ValueError,OSError)):verifier(record,expected_commit=sha)


def test_base_configuration_and_record_parity(configured_binding):
    from riscv2x86_py.l3_base_validation import _validate_source_preparation
    backend,record,build=configured_binding
    assert _validate_source_preparation(backend)==record
    backend['files'].pop(str(build/'config.status'))
    with pytest.raises(ValueError):_validate_source_preparation(backend)


def test_two_epochs_share_dependencies_but_never_initial_trust():
    calls=[];observed=[]
    def leaf(v):calls.append(1);return {'value':v}
    def root(v):return leaf_checked(leaf,v)
    from riscv2x86_py.joint_validation_operation import checked
    with JointValidationOperation('dag'):
        for name in ('one','two','three'):
            # Three DIFFERENT roots request the same validated dependency.
            def node(v,name=name):observed.append(name);return root(v)
            checked(node,{'input':1})
        assert len(calls)==1
    assert len(calls)==2 and len(observed)==6
    with JointValidationOperation('audit'):leaf_checked(leaf,{'input':1})
    assert len(calls)==4


def test_closing_checks_even_orphaned_leaf_and_rejects_change():
    calls=[]
    def leaf(v):calls.append(1);return {'n':len(calls)}
    with pytest.raises(ValueError,match='LEAF_REPLAY_CHANGED'):
        with JointValidationOperation('orphan'):leaf_checked(leaf,{})
    assert len(calls)==2


def test_damaged_raw_capture_rejected_before_expensive_replay(tmp_path,monkeypatch):
    from riscv2x86_py import l3_joint_route as route
    from riscv2x86_py.l3_trace_support import identity,digest
    backend=tmp_path/'backend';backend.write_text('{}')
    trace=tmp_path/'trace';trace.write_text('initial');command=tmp_path/'execute.command.json';command.write_text('{}')
    body={'schemaVersion':'riscv2x86.joint-region-capture.v1','backendPath':str(backend),'backendDigest':digest(backend),
        'reports':{s:{'evidence':{'rawTracePath':str(trace),'rawTraceDigest':digest(trace),'commandRecordDigest':digest(command)}} for s in ('source','target')}}
    group=dict(body,groupIdentity=identity(body));trace.write_text('corrupted');calls=[]
    monkeypatch.setattr(route,'backend_validate',lambda *a,**kw:calls.append(1))
    with pytest.raises(ValueError,match='RAW_EXECUTION_CHANGED'):route.replay_group(group,None,None)
    assert not calls


def test_nested_backend_sessions_delegate_to_fresh_outer_epochs(tmp_path,monkeypatch):
    from riscv2x86_py import l3_joint_backend as backend,l3_base_validation as base,l3_mechanism_selection as selection
    from riscv2x86_py.l3_backend_validation import BackendValidationSession,checked
    b=tmp_path/'joint.json';b.write_text('{}');q=tmp_path/'base.json';q.write_text('{}')
    config=tmp_path/'selection.json';config.write_text(json.dumps({'schemaVersion':selection.SCHEMA,'backends':{'joint':str(b)}}))
    calls={'root':0,'base':0};tool=tmp_path/'tool';tool.write_text('valid')
    def full_base(value):
        calls['base']+=1
        if tool.read_text()!='valid':raise ValueError('base tool changed')
        return {'backendIdentity':'base-fixture'}
    def full_joint(value,**kw):
        calls['root']+=1;base.validate(q);return {'backendIdentity':'joint-fixture'}
    monkeypatch.setattr(base,'validate_optimized',full_base);monkeypatch.setattr(backend,'_validate_full',full_joint)
    with JointValidationOperation('whole-program'):
        selection.load(config)
        with BackendValidationSession() as inner:
            checked(inner,backend.validate,b);backend.validate(b)
        assert calls=={'root':1,'base':1}
    assert calls=={'root':2,'base':2}
    with pytest.raises(ValueError,match='base tool changed'):
        with JointValidationOperation('mutation'):
            selection.load(config);backend.validate(b);tool.write_text('bad')


from tests.test_l3_production_ingress import ingress


def test_joint_producer_batches_only_complete_compiler_bound_members(ingress,monkeypatch):
    from types import SimpleNamespace
    from riscv2x86_py import mechanism_route_checks as checks,translation_artifact_binding as binding
    from riscv2x86_py import l3_intent_ingress as subject
    from riscv2x86_py.l3_trace_support import identity,digest,require_json_match
    from tests.test_l3_provider_resolution import _facts
    source,report,manifest,tool,artifact,seal=ingress
    findings=[{'fragment':{'id':'fragment:'+str(i)},'translationOutcome':'emitted'} for i in range(3)]
    report.write_text(json.dumps({'findings':findings}))
    scope={'schemaVersion':'riscv2x86.compiler-joint-scope.v3','scope':'direct-typed-private-object-views',
        'sourceDigest':digest(source),'functionIdentity':'fixture-function'}
    scope['scopeIdentity']=identity(scope)
    snapshot={'functions':[{'functionId':'fixture-function','sourceDigest':digest(source),'compilerJointScope':scope}]}
    report.with_name('compiler-candidates.json').write_text(json.dumps(snapshot))
    artifacts={}
    for i,finding in enumerate(findings):
        fields=dict(vars(artifact),fragment_id=finding['fragment']['id'])
        artifacts['finding:'+str(i)+':'+finding['fragment']['id']]=SimpleNamespace(**fields)
    monkeypatch.setattr(binding,'artifacts_from_report',lambda *a:artifacts)
    calls={'single':0,'batch':0}
    def single(s,r,fid):
        calls['single']+=1;return next(f for f in json.loads(report.read_text())['findings'] if f['fragment']['id']==fid),snapshot
    def batch(*a):calls['batch']+=1;return json.loads(report.read_text())['findings'],snapshot
    monkeypatch.setattr(checks,'compiler_bound_finding',single);monkeypatch.setattr(checks,'compiler_bound_findings',batch)
    profile,_=_facts()
    tool.write_text('import json,sys,copy\nfrom riscv2x86_py.l3_intent_requirements import _hash\nr=json.load(sys.stdin);profiles=[]\n'
        'for item in r["candidates"]:\n p=copy.deepcopy('+repr(profile)+');p["fragmentId"]=item["finding"]["fragment"]["id"];p["producer"]["producerIdentity"]=r["producerIdentity"];p["profileIdentity"]=_hash({k:v for k,v in p.items() if k!="profileIdentity"});profiles.append(p)\n'
        'print(json.dumps({"schemaVersion":"riscv2x86.l3-intent-producer-response.v1","requestIdentity":r["requestIdentity"],"profiles":profiles}))\n')
    seal();outputs=[]
    for mode in ('0','1'):
        calls.update(single=0,batch=0);monkeypatch.setenv('RV2X86_JOINT_PERFORMANCE_V2',mode)
        outputs.append(subject.produce_intents(source,report,manifest,replay=True))
        assert calls==({'single':6,'batch':0} if mode=='0' else {'single':0,'batch':2})
    require_json_match(outputs[0],outputs[1],'PRODUCER_BATCH_CHANGED')
