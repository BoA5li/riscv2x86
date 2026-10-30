"""Real native execution and synthetic compiler/proof fixtures, not dual-ISA approval."""
from copy import deepcopy
import shutil
import subprocess
import pytest
from tests.test_l3_joint_program import fixture
from riscv2x86_py.l3_joint_spec import spec,sample_plan
from riscv2x86_py.l3_joint_observation import harness,instrument,parse_samples,parse_l2


@pytest.mark.parametrize('fence',[False,True])
@pytest.mark.parametrize('width',[1,2,4,8])
def test_actual_typed_alias_layouts_and_boundary_semantics(tmp_path,fence,width):
    source,findings,fn=fixture(tmp_path,multi_object=True,include_fence=fence,width=width)
    program=spec(findings,[fn]);plan=sample_plan(program)
    assert len(program['objectLayout']['layouts'])==3
    c=tmp_path/'variant.c';c.write_bytes(instrument(source,program['scope']['sites'],program))
    h=tmp_path/'h.c';h.write_text(harness(program,plan));exe=tmp_path/'native'
    run=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(h),str(c),'-o',str(exe)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr+'\n'+h.read_text()
    run=subprocess.run([str(exe),'a'*64],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    rows=parse_l2(run.stdout,'a'*64,program,plan)
    assert len(rows['samples'])==8
    # Distinct compiler IDs really share physical storage in alias invocations.
    text='\n'.join(l for l in run.stdout.splitlines() if not l.startswith('J '))
    observations=parse_samples(text,'a'*64,program,plan)
    assert observations[1]['objects'][0]['base']==observations[1]['objects'][1]['base']
    assert int(observations[2]['objects'][1]['base'],16)-int(observations[2]['objects'][0]['base'],16)==8
    from riscv2x86_py.automatic_validation import _memory_object_wrapper,_memory_object_observations
    l1=tmp_path/'l1.c';l1.write_text(_memory_object_wrapper([fn]));plain=tmp_path/'plain.c';plain.write_bytes(source)
    result=subprocess.run([shutil.which('gcc'),'-O0','-Wall','-Wextra','-Werror',str(l1),str(plain),'-o',str(exe)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    result=subprocess.run([str(exe)],capture_output=True,text=True)
    assert len(_memory_object_observations(result.stdout,multi_object=True))==16


@pytest.mark.parametrize('index',[0,1,3])
def test_central_provider_and_independent_alias_replay(tmp_path,monkeypatch,index):
    from tests.test_l2_joint_registry import setup,registry,artifact
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    findings,fn,c=setup(tmp_path,monkeypatch,multi_object=True,include_fence=True)
    f=findings[index];r=registry(tmp_path,findings,c,f)
    layer=r.validator_for(ValidationLevel.L2)(level=ValidationLevel.L2,translation_artifact=artifact(f),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is ValidationStatus.VERIFIED,layer.detail


def test_store_then_alias_reload_uses_updated_state(tmp_path):
    source,findings,fn=fixture(tmp_path,multi_object=True,reload_after_store=True,store_offset=8)
    program=spec(findings,[fn]);plan=sample_plan(program)
    c=tmp_path/'c.c';c.write_bytes(instrument(source,program['scope']['sites'],program));h=tmp_path/'h.c';h.write_text(harness(program,plan));exe=tmp_path/'native'
    run=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(h),str(c),'-o',str(exe)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    run=subprocess.run([str(exe),'a'*64],capture_output=True,text=True)
    rows=parse_l2(run.stdout,'a'*64,program,plan)
    graph=program['objectAccessGraph']
    assert any(e['relation']=='write-before-read' for c in graph['layoutCases'] for e in c['dependencies'])
    assert len(rows['samples'])==8
    lines=run.stdout.splitlines();i=next(i for i,s in enumerate(lines) if s.startswith('J 1 3 post'))
    values=lines[i].split();values[5]='0000000000000000';lines[i]=' '.join(values)
    with pytest.raises(ValueError,match='LOAD_VALUE'):parse_l2('\n'.join(lines),'a'*64,program,plan)


@pytest.mark.parametrize('change',['address','size','direction','missing','extra','sample','return','guard'])
@pytest.mark.parametrize('fence',[False,True])
def test_actual_call_comparison_rejects_wrong_evidence(tmp_path,change,fence):
    import json
    from riscv2x86_py.l3_joint_route import project,comparison
    from riscv2x86_py.l3_trace_support import identity
    source,findings,fn=fixture(tmp_path,multi_object=True,include_fence=fence)
    program=spec(findings,[fn]);plan=sample_plan(program)
    c=tmp_path/'c.c';c.write_bytes(source);h=tmp_path/'h.c';h.write_text(harness(program,plan));exe=tmp_path/'native'
    run=subprocess.run([shutil.which('gcc'),'-O0',str(h),str(c),'-o',str(exe)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    rows=parse_samples(subprocess.run([str(exe),'a'*64],capture_output=True,text=True).stdout,'a'*64,program,plan)
    events=[]
    for sample,row in enumerate(rows):
        for index,member in enumerate(program['members']):
            s=member['spec']
            if member.get('fenceBasis') is not None:
                events.append({'sample':sample,'region':index,'access':'fence','completed':True,'machineMechanism':{'kind':'ordinary-rw-fence'}})
                continue
            if s['access']=='none':continue
            obj=next(o for o in row['objects'] if o['objectId']==s['objectId'])
            events.append({'sample':sample,'region':index,'address':int(obj['base'],16)+s['offset'],'size':s['width'],'access':s['access']})
    group={'groupIdentity':identity('group'),'deployment':{'spec':program},'reports':{side:{'events':deepcopy(events),'samples':deepcopy(rows),'environment':{}} for side in ('source','target')}}
    assert all(comparison(project(group,i))['status']=='verified' for i in range(len(program['members'])))
    target=group['reports']['target'];e=target['events'][0]
    if change=='address':e['address']+=8
    if change=='size':e['size']=4
    if change=='direction':e['access']='write'
    if change=='missing':target['events'].pop(0)
    if change=='extra':target['events'].append(deepcopy(e))
    if change=='sample':e['sample']=99
    if change=='return':target['samples'][0]['value']='ffffffffffffffff'
    if change=='guard':target['samples'][0]['objects'][0]['hex']='ff'+target['samples'][0]['objects'][0]['hex'][2:]
    assert comparison(project(group,0))['status']=='failed'


@pytest.mark.parametrize('change',['alias','disjoint','missing','size','duplicate-key','bool'])
def test_parser_checks_actual_alias_layout_and_complete_views(tmp_path,change):
    import json
    source,findings,fn=fixture(tmp_path,multi_object=True);program=spec(findings,[fn]);plan=sample_plan(program)
    c=tmp_path/'c.c';c.write_bytes(source);h=tmp_path/'h.c';h.write_text(harness(program,plan));exe=tmp_path/'native'
    subprocess.run([shutil.which('gcc'),'-O0',str(h),str(c),'-o',str(exe)],check=True,capture_output=True)
    rows=parse_samples(subprocess.run([str(exe),'a'*64],capture_output=True,text=True).stdout,'a'*64,program,plan)
    if change=='alias':rows[1]['objects'][1]['base']=format(int(rows[1]['objects'][1]['base'],16)+8,'x')
    if change=='disjoint':rows[0]['objects'][1]['base']=rows[0]['objects'][0]['base']
    if change=='missing':rows[0]['objects'].pop()
    if change=='size':rows[0]['objects'][0]['size']=16
    if change=='bool':rows[0]['sample']=False
    text='\n'.join(json.dumps(r) for r in rows)
    if change=='duplicate-key':text=text.replace('"sample": 0','"sample": 0,"sample": 0',1)
    with pytest.raises(ValueError):parse_samples(text,'a'*64,program,plan)


def test_multi_object_receipt_and_capability_closure(tmp_path):
    from riscv2x86_py.l3_joint_intent import produce
    from riscv2x86_py.l3_capability_assessment import assess
    from tests.test_l3_scalar_trace import request
    from riscv2x86_py.l3_intent_requirements import _hash
    _,findings,fn=fixture(tmp_path,multi_object=True,include_fence=True)
    value=request(findings[0]);value['candidates']=[request(f)['candidates'][0] for f in findings]
    for c in value['candidates']:c['compilerFunctions']=[fn]
    value['requestIdentity']=_hash({k:v for k,v in value.items() if k!='requestIdentity'})
    response=produce(value)
    assert len(response['profiles'])==4 and all(p['complete'] for p in response['profiles'])
    assert len({p['observationBoundary']['identity'] for p in response['profiles']})==1
    result=assess(findings,[fn],{'joint'})
    assert result['staticPrerequisitesComplete'] and not result['productionAcceptanceComplete']


def test_legacy_l1_stdout_braces_are_not_reinterpreted_as_layout_protocol():
    from riscv2x86_py.automatic_validation import _memory_object_observations
    assert _memory_object_observations('callee debug {not a protocol document}\n')==[]


@pytest.mark.parametrize('name',['allocation0','returned','argc'])
def test_harness_c_local_names_cannot_shadow_user_entry(tmp_path,name):
    source,findings,fn=fixture(tmp_path,multi_object=True);program=spec(findings,[fn])
    # Harness-only name collision test, not semantic approval for a changed source.
    source=source.replace(b'unrelated',name.encode());program['functionName']=name
    plan=sample_plan(program);c=tmp_path/'c.c';c.write_bytes(source);h=tmp_path/'h.c';h.write_text(harness(program,plan));exe=tmp_path/'native'
    run=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(h),str(c),'-o',str(exe)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    run=subprocess.run([str(exe),'a'*64],capture_output=True,text=True)
    assert len(parse_samples(run.stdout,'a'*64,program,plan))==8
