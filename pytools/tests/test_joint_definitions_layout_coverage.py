"""Real native state/alias tests; compiler/proof fixtures are explicitly synthetic."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from tests.test_l3_joint_program import fixture
from riscv2x86_py.l3_joint_spec import spec,sample_plan
from riscv2x86_py.l3_joint_observation import instrument,harness,parse_l2
from riscv2x86_py.l3_trace_support import identity
from riscv2x86_py.object_layout_contract import build,materialize,allocation_bytes


@pytest.mark.parametrize('multi',[False,True])
@pytest.mark.parametrize('width',[1,2,4,8])
def test_redefinition_kills_old_return_without_losing_prior_consumer(tmp_path,multi,width):
    source,findings,fn=fixture(tmp_path,multi_object=multi,width=width,
        reload_after_store=True,reuse_output=True,store_offset=8,include_fence=True)
    program=spec(findings,[fn]);plan=sample_plan(program)
    first=findings[0]['approvalArtifact']['l2FragmentOperandBoundary']
    last=findings[-1]['approvalArtifact']['l2FragmentOperandBoundary']
    assert all(s['sinkKind']!='function_return' for s in first['observationSinks'])
    assert any(s['sinkKind']=='function_return' for s in last['observationSinks'])
    c=tmp_path/'c.c';c.write_bytes(instrument(source,program['scope']['sites'],program))
    h=tmp_path/'h.c';h.write_text(harness(program,plan));binary=tmp_path/'program'
    result=subprocess.run([shutil.which('gcc'),'-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(c),str(h),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    executed=subprocess.run([str(binary),'a'*64],capture_output=True,text=True,check=True)
    observation=parse_l2(executed.stdout,'a'*64,program,plan)
    assert len(observation['samples'])==len(plan['inputs'])
    # A wrong last value cannot be hidden by the earlier correct definition.
    lines=executed.stdout.splitlines()
    i=next(i for i,s in enumerate(lines) if s.startswith('J 0 4 post'))
    parts=lines[i].split();parts[5]='ffffffffffffffff';lines[i]=' '.join(parts)
    with pytest.raises(ValueError):parse_l2('\n'.join(lines),'a'*64,program,plan)


def test_three_views_schedule_and_execute_every_declared_layout(tmp_path):
    source,findings,fn=fixture(tmp_path,multi_object=True,extra_pointer=True,
        reload_after_store=True,reuse_output=True,store_offset=8)
    program=spec(findings,[fn]);plan=sample_plan(program)
    assert len(program['objectLayout']['layouts'])>8
    assert len(plan['inputs'])==len(program['objectLayout']['layouts'])
    assert plan['allDeclaredLayoutsScheduled'] and all(x['samples'] for x in plan['layoutCoverage'])
    # Rebuilding from the persisted actual sample count is lossless.
    assert sample_plan(program,len(plan['inputs']))==plan
    assert any(len(c['allocations'])==1 for c in program['objectLayout']['layouts'])
    c=tmp_path/'c.c';c.write_bytes(instrument(source,program['scope']['sites'],program))
    h=tmp_path/'h.c';h.write_text(harness(program,plan));binary=tmp_path/'program'
    result=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(c),str(h),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    executed=subprocess.run([str(binary),'a'*64],capture_output=True,text=True,check=True)
    observation=parse_l2(executed.stdout,'a'*64,program,plan)
    assert len(observation['samples'])==len(plan['inputs'])


def test_all_compatible_set_partitions_and_actual_byte_cover(tmp_path):
    _,_,fn=fixture(tmp_path,multi_object=True,extra_pointer=True)
    contract=build(fn);partitions=set()
    for case in contract['layouts']:
        allocations,views=materialize(case,contract['views'])
        partitions.add(tuple(v['allocationId'] for v in case['views']))
        from riscv2x86_py.object_layout_contract import initial_objects
        allocation_bytes(case,contract['views'],initial_objects(case,contract['views'],0))
    assert len(partitions)==5  # Bell(3), derived independently of address offsets.


def test_incompatible_effective_types_never_share_generated_allocation(tmp_path):
    _,_,fn=fixture(tmp_path,multi_object=True,extra_pointer=True)
    fn=deepcopy(fn);p=fn['compilerMemoryCallSignature']['parameters'][2]
    from riscv2x86_py.compiler_memory_signature import type_fact
    fn['compilerMemoryCallSignature']['parameters'][2]={**type_fact('unsigned int *'),'declarationIdentity':p['declarationIdentity']}
    call=fn['compilerMemoryCallSignature'];call['factsIdentity']=identity({k:v for k,v in call.items() if k!='factsIdentity'})
    contract=build(fn)
    for case in contract['layouts']:
        _,views=materialize(case,contract['views'])
        different=views[contract['views'][2]['objectId']]['allocationId']
        assert all(views[v['objectId']]['allocationId']!=different for v in contract['views'][:2])


@pytest.mark.parametrize('mutation',['missing-site','uninitialized','missing-use','wrong-partition'])
def test_reaching_definition_incomplete_inputs_remain_blocked(tmp_path,mutation):
    from riscv2x86_py.joint_reaching_definitions import derive,uses_for
    from riscv2x86_py.l2_fragment_execution import resolve_compiler_fragment_candidate
    _,findings,fn=fixture(tmp_path,multi_object=True,reload_after_store=True,reuse_output=True,store_offset=8)
    resolved={}
    for f in findings:
        c,r=resolve_compiler_fragment_candidate(f['fragment'],fn['l2OperandBoundary']['fragmentCandidates'],fn)
        resolved[f['fragment']['id']]=(deepcopy(c),r,deepcopy(f['fragment']))
    first=findings[0]['fragment']['id']
    if mutation=='missing-site':resolved.pop(first)
    if mutation=='uninitialized':fn['l2OperandBoundary']['parameterDeclarationIds']=[]
    if mutation=='wrong-partition':
        c,r,f=resolved[first];f['outputs'].append(f['inputs'].pop())
    if mutation=='missing-use':resolved[first][0]['downstreamUses']=[]
    with pytest.raises(ValueError):
        flow=derive(fn,resolved)
        uses_for(flow,first,resolved[first][0])


def four_pointer_function(tmp_path):
    _,_,fn=fixture(tmp_path,multi_object=True,extra_pointer=True)
    # Layout/harness-only compiler fixture. No translated program approval.
    fn=deepcopy(fn);call=fn['compilerMemoryCallSignature'];decl=call['parameters'][3]['declarationIdentity']
    from riscv2x86_py.compiler_memory_signature import type_fact
    call['parameters'][3]={**type_fact('unsigned long *'),'declarationIdentity':decl}
    call['factsIdentity']=identity({k:v for k,v in call.items() if k!='factsIdentity'})
    old=fn['l2OperandBoundary']['memoryObjectBindings'][call['parameters'][0]['declarationIdentity']]
    binding={**old,'objectIdentity':'parameter-object:'+decl,'baseDeclarationIdentity':decl,'aliasDomainIdentity':'parameter-alias-domain:'+decl}
    binding['bindingIdentity']=identity({k:v for k,v in binding.items() if k!='bindingIdentity'})
    fn['l2OperandBoundary']['memoryObjectBindings'][decl]=binding
    return fn


def test_four_views_cover_all_partitions_and_more_than_32_calls(tmp_path):
    fn=four_pointer_function(tmp_path);contract=build(fn)
    partitions={tuple(v['allocationId'] for v in case['views']) for case in contract['layouts']}
    assert len(partitions)==15  # Bell(4).
    program={'functionName':'native_four','specIdentity':identity('layout-harness-only'),
        'callSignature':fn['compilerMemoryCallSignature'],'objectLayout':contract,'pointerParameters':[0,1,2,3]}
    from riscv2x86_py.l3_multi_object_observation import sample_plan as plan_for,parse_samples
    plan=plan_for(program,8);assert len(plan['inputs'])==93
    c=tmp_path/'four.c';c.write_text('unsigned long native_four(unsigned long*a,unsigned long*b,unsigned long*c,unsigned long*d){return *a^*b^*c^*d;}')
    h=tmp_path/'h.c';h.write_text(harness(program,plan));binary=tmp_path/'four'
    result=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(c),str(h),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    executed=subprocess.run([str(binary),'a'*64],check=True,capture_output=True,text=True)
    assert len(parse_samples(executed.stdout,'a'*64,program,plan))==93


@pytest.mark.parametrize('budget',[True,3,257,-1])
def test_incomplete_or_unbounded_sample_budgets_are_not_silently_truncated(tmp_path,budget):
    _,findings,fn=fixture(tmp_path,multi_object=True)
    program=spec(findings,[fn])
    with pytest.raises(ValueError):sample_plan(program,budget)


def test_duplicate_layout_identity_cannot_count_as_coverage(tmp_path):
    _,findings,fn=fixture(tmp_path,multi_object=True)
    program=spec(findings,[fn]);program['objectLayout']['layouts'].append(program['objectLayout']['layouts'][0])
    with pytest.raises(ValueError,match='LAYOUT_MEMBERSHIP'):sample_plan(program)


def test_one_definition_reaches_two_distinct_input_slots(tmp_path):
    source,findings,fn=fixture(tmp_path,duplicate_input=True)
    program=spec(findings,[fn]);flow=program['valueFlowContract']
    uses=[u for u in flow['uses'] if u['producer']['fragmentId']==findings[0]['fragment']['id']]
    assert len(uses)==2 and {u['consumerOperandIndex'] for u in uses}=={1,2}
    graph=findings[0]['approvalArtifact']['l2FragmentDependencyGraph']
    assert len([e for e in graph['edges'] if e['producerFragmentId']==findings[0]['fragment']['id']])==2
    plan=sample_plan(program);c=tmp_path/'c.c';c.write_bytes(instrument(source,program['scope']['sites'],program))
    h=tmp_path/'h.c';h.write_text(harness(program,plan));binary=tmp_path/'native'
    result=subprocess.run([shutil.which('gcc'),'-O2','-Wall','-Wextra','-Werror',str(c),str(h),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    executed=subprocess.run([str(binary),'a'*64],check=True,capture_output=True,text=True)
    assert len(parse_l2(executed.stdout,'a'*64,program,plan)['samples'])==8


@pytest.mark.parametrize('calls',[33,93,256,257])
def test_actual_plugin_invocation_capacity_is_bounded(tmp_path,calls):
    from tests.test_l3_control_backend import HEADER
    from riscv2x86_py.l3_joint_backend import parse_capture
    header=tmp_path/'include/qemu/qemu-plugin.h';header.parent.mkdir(parents=True);header.write_text(HEADER)
    plugin=Path(__file__).resolve().parents[2]/'runtime/l3_qemu_program_trace.c'
    source=tmp_path/'callbacks.c';trace=tmp_path/'trace';binary=tmp_path/'callbacks';token='a'*64
    source.write_text('#include "'+str(plugin)+'"\nint main(void){qemu_info_t i={false,"riscv64"};'
        'char *args[]={"regions=0x1000:0x1004;0x1010:0x1014","output='+str(trace)+'","token='+token+'"};'
        'if(qemu_plugin_install(1,&i,3,args))return 2;for(unsigned n=0;n<'+str(calls)+';n++){'
        'instruction(0,(void*)0x1000);memory(0,3,0x2000,(void*)0x1000);instruction(0,(void*)0x1004);'
        'instruction(0,(void*)0x1010);instruction(0,(void*)0x1014);}finish(1,NULL);return 0;}')
    result=subprocess.run([shutil.which('gcc'),'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(header.parents[1]),str(source),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    subprocess.run([str(binary)],check=True)
    args=(trace.read_text(),token,'source',[{'start':0x1000,'end':0x1004},{'start':0x1010,'end':0x1014}],calls)
    if calls>256:
        with pytest.raises(ValueError):parse_capture(*args)
    else:assert len(parse_capture(*args))==calls
