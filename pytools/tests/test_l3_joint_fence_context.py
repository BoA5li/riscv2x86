"""Joint fence plumbing and adverse evidence; native fixtures are not ISA approval."""
from copy import deepcopy
import subprocess
import shutil
import pytest
from tests.test_l3_joint_program import fixture
from riscv2x86_py.l3_joint_spec import spec,sample_plan
from riscv2x86_py.l3_joint_observation import harness,instrument,parse_l2,parse_samples
from riscv2x86_py.l3_joint_route import project,comparison
from riscv2x86_py.l3_trace_support import identity


def test_joint_fence_compiler_scope_proofs_and_native_boundaries(tmp_path):
    source,findings,fn=fixture(tmp_path,include_fence=True)
    p=spec(findings,[fn]);plan=sample_plan(p)
    assert p['members'][1]['fenceBasis']['obligations']['synchronizationObligations']['basisComplete']
    c=tmp_path/'variant.c';c.write_bytes(instrument(source,p['scope']['sites'],p))
    h=tmp_path/'h.c';h.write_text(harness(p,plan));exe=tmp_path/'native'
    run=subprocess.run([shutil.which('gcc'),'-O0','-Wall','-Wextra','-Werror',str(c),str(h),'-o',str(exe)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    run=subprocess.run([str(exe),'a'*64],capture_output=True,text=True)
    observed=parse_l2(run.stdout,'a'*64,p,plan)
    assert len(observed['boundaries'])==64
    from riscv2x86_py.l3_mechanism_selection import plan as select
    assert select(findings,[fn],{'joint':{}})[1]=='joint'


@pytest.mark.parametrize('mutation',['none','missing','nop','partial','reordered','duplicate','sample'])
def test_same_invocation_fence_comparison_rejects_adverse_evidence(tmp_path,mutation):
    source,findings,fn=fixture(tmp_path,include_fence=True);p=spec(findings,[fn]);plan=sample_plan(p)
    c=tmp_path/'c.c';c.write_bytes(source);h=tmp_path/'h.c';h.write_text(harness(p,plan));exe=tmp_path/'native'
    run=subprocess.run([shutil.which('gcc'),'-O0',str(c),str(h),'-o',str(exe)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    run=subprocess.run([str(exe),'a'*64],capture_output=True,text=True);rows=parse_samples(run.stdout,'a'*64,p,plan)
    events=[]
    for i,row in enumerate(rows):
        events.extend([{'sample':i,'region':0,'pc':100,'address':int(row['objectBase'],16)+8,'size':8,'access':'read'},
            {'sample':i,'region':1,'pc':120,'access':'fence','completed':True,'machineMechanism':{'kind':'ordinary-rw-fence'},'rawBeginLine':2,'rawEndLine':3},
            {'sample':i,'region':3,'pc':150,'address':int(row['objectBase'],16)+16,'size':8,'access':'write'}])
    group={'groupIdentity':identity('group'),'deployment':{'spec':p},'reports':{s:{'events':deepcopy(events),'samples':deepcopy(rows),'environment':{}} for s in ('source','target')}}
    target=group['reports']['target']['events']
    if mutation=='missing':target.pop(1)
    if mutation in {'nop','partial'}:target[1]['machineMechanism']['kind']=mutation
    if mutation=='reordered':target[0],target[1]=target[1],target[0]
    if mutation=='duplicate':target.insert(1,deepcopy(target[1]))
    if mutation=='sample':target[1]['sample']=99
    result=comparison(project(group,1))
    assert result['status']==('verified' if mutation=='none' else 'failed')
    assert result['synchronization']['physicalMemoryOrderMeasured'] is False


def test_fence_joint_provider_resolves_executes_and_replays(tmp_path,monkeypatch):
    from tests.test_l2_joint_registry import setup,registry,artifact
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    findings,fn,c=setup(tmp_path,monkeypatch,include_fence=True)
    f=findings[1];r=registry(tmp_path,findings,c,f)
    layer=r.validator_for(ValidationLevel.L2)(level=ValidationLevel.L2,translation_artifact=artifact(f),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is ValidationStatus.VERIFIED,layer.detail


def test_joint_fence_intent_retains_sync_obligations(tmp_path):
    from riscv2x86_py.l3_joint_intent import produce
    from tests.test_l3_scalar_trace import request
    from riscv2x86_py.l3_intent_requirements import _hash
    _,findings,fn=fixture(tmp_path,include_fence=True)
    value=request(findings[0]);value['candidates']=[request(f)['candidates'][0] for f in findings]
    for c in value['candidates']:c['compilerFunctions']=[fn]
    value['requestIdentity']=_hash({k:v for k,v in value.items() if k!='requestIdentity'})
    result=produce(value)
    assert all(p['complete'] for p in result['profiles'])
    assert {p['dimension'] for p in result['profiles'][1]['requiredProperties']}=={'access_pattern','synchronization'}


def test_fence_capture_requires_actual_entry_and_completion():
    from riscv2x86_py.l3_joint_backend import parse_capture
    token='a'*64
    regions=[{'start':16,'end':19,'fenceMechanism':{'kind':'ordinary-rw-fence'}}]
    raw='H 3 '+token+' x86_64\nB 0 0 10\nE 0 0 13\nF 1 0 0 0'
    events=parse_capture(raw,token,'target',regions,1)
    assert events[0]['rawBeginLine']==1 and events[0]['rawEndLine']==2
    for bad in (raw.replace('B 0 0 10\n',''),raw.replace('E 0 0 13\n',''),raw.replace('E 0 0 13','E 0 0 14')):
        with pytest.raises(ValueError):parse_capture(bad,token,'target',regions,1)
