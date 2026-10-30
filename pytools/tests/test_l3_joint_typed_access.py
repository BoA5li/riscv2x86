"""Proof-driven narrow accesses share actual object state across regions."""
import subprocess
import shutil
import pytest
from tests.test_l3_joint_program import fixture
from riscv2x86_py.l3_joint_spec import spec,sample_plan
from riscv2x86_py.l3_joint_observation import harness,instrument,parse_l2


@pytest.mark.parametrize('width',[1,2,4])
@pytest.mark.parametrize('signed',[False,True])
@pytest.mark.parametrize('fence',[False,True])
def test_typed_narrow_access_actual_native_boundaries(tmp_path,width,signed,fence):
    source,findings,fn=fixture(tmp_path,width=width,sign_extend=signed,signed_object=signed,include_fence=fence)
    p=spec(findings,[fn]);plan=sample_plan(p)
    assert p['scope']['schemaVersion'].endswith('.v2')
    c=tmp_path/'c.c';c.write_bytes(instrument(source,p['scope']['sites'],p));h=tmp_path/'h.c';h.write_text(harness(p,plan));exe=tmp_path/'native'
    run=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(c),str(h),'-o',str(exe)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    run=subprocess.run([str(exe),'a'*64],capture_output=True,text=True)
    observed=parse_l2(run.stdout,'a'*64,p,plan)
    assert len(observed['samples'])==8
    # A wrong measured output must not be rescued by source/target agreement.
    lines=run.stdout.splitlines()
    post=next(i for i,v in enumerate(lines) if v.startswith('J 0 0 post'))
    parts=lines[post].split();parts[5]='ffffffffffffffff';lines[post]=' '.join(parts)
    with pytest.raises(ValueError,match='LOAD_VALUE_MISMATCH'):
        parse_l2('\n'.join(lines),'a'*64,p,plan)


def test_object_graph_keeps_partial_overlap_and_rejects_unproved_alias_layout(tmp_path):
    from copy import deepcopy
    from riscv2x86_py.joint_object_access_graph import build
    _,findings,fn=fixture(tmp_path)
    p=spec(findings,[fn]);members=deepcopy(p['members'])
    # Consumer contract test: a proved second read after a write must retain
    # the overlapping state dependency rather than treat it as a fresh object.
    later=deepcopy(members[0]);later['fragmentId']='later-read';later['spec'].update(offset=18,width=2)
    members.append(later)
    graph=build(members)
    assert graph['dependencies']==[{'beforeRegion':2,'afterRegion':3,'objectId':later['spec']['objectId'],'overlap':[18,20],'relation':'write-before-read'}]
    members[-1]['spec']['objectId']='unproved-distinct-view'
    with pytest.raises(ValueError,match='ALIAS_LAYOUT_REQUIRED'):build(members)


@pytest.mark.parametrize('width',[1,2,4])
@pytest.mark.parametrize('index',[0,1,3])
def test_typed_signed_object_central_provider_execution_and_replay(tmp_path,monkeypatch,width,index):
    from tests.test_l2_joint_registry import setup,registry,artifact
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    findings,fn,c=setup(tmp_path,monkeypatch,width=width,sign_extend=True,signed_object=True,include_fence=True)
    f=findings[index];r=registry(tmp_path,findings,c,f)
    layer=r.validator_for(ValidationLevel.L2)(level=ValidationLevel.L2,translation_artifact=artifact(f),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is ValidationStatus.VERIFIED,layer.detail
