"""Real native harness equivalence; fixtures are not dual-ISA acceptance."""
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py.l3_trace_support import identity,require_json_match


def compile_run(tmp_path,code,wrapper,name):
    c=tmp_path/(name+'.c');c.write_bytes(code)
    h=tmp_path/(name+'-h.c');h.write_text(wrapper);binary=tmp_path/name
    built=subprocess.run([shutil.which('gcc'),'-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(c),str(h),'-o',str(binary)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    return subprocess.run([str(binary),'a'*64],check=True,capture_output=True,text=True).stdout


@pytest.mark.parametrize('width,signed,fence',[(1,False,False),(1,True,True),(2,True,False),(4,False,True),(4,True,False),(8,False,True)])
def test_typed_tables_preserve_all_native_l2_values_and_layouts(tmp_path,monkeypatch,width,signed,fence):
    from tests.test_l3_joint_program import fixture
    from riscv2x86_py.l3_joint_spec import spec,sample_plan
    from riscv2x86_py.l3_multi_object_observation import harness,instrument,parse_l2
    source,findings,fn=fixture(tmp_path,width=width,sign_extend=signed,signed_object=signed,
        multi_object=True,reload_after_store=True,reuse_output=True,include_fence=fence)
    program=spec(findings,[fn]);plan=sample_plan(program);code=instrument(source,program['scope']['sites'],program)
    results=[]
    for mode in ('0','1'):
        monkeypatch.setenv('RV2X86_JOINT_PERFORMANCE_V2',mode)
        output=compile_run(tmp_path,code,harness(program,plan),'mode'+mode)
        results.append(parse_l2(output,'a'*64,program,plan))
    require_json_match(results[0],results[1],'HARNESS_SEMANTICS_CHANGED')


def test_93_typed_layouts_keep_outputs_with_smaller_generated_code(tmp_path,monkeypatch):
    from tests.test_joint_definitions_layout_coverage import four_pointer_function
    from riscv2x86_py.object_layout_contract import build
    from riscv2x86_py.l3_multi_object_observation import sample_plan,harness,parse_samples,normalized
    fn=four_pointer_function(tmp_path)
    program={'functionName':'native_four','specIdentity':identity('harness-comparison'),
        'callSignature':fn['compilerMemoryCallSignature'],'objectLayout':build(fn),'pointerParameters':[0,1,2,3]}
    plan=sample_plan(program,8);assert len(plan['inputs'])==93
    code=b'unsigned long native_four(unsigned long*a,unsigned long*b,unsigned long*c,unsigned long*d){*b=*a+1;*d=*c;return *c;}'
    wrappers=[];results=[]
    for mode in ('0','1'):
        monkeypatch.setenv('RV2X86_JOINT_PERFORMANCE_V2',mode);wrapper=harness(program,plan);wrappers.append(wrapper)
        output=compile_run(tmp_path,code,wrapper,'large'+mode)
        results.append([normalized(row) for row in parse_samples(output,'a'*64,program,plan)])
    require_json_match(results[0],results[1],'HARNESS_93_LAYOUT_RESULTS_CHANGED')
    assert len(wrappers[1])<len(wrappers[0])/2
    assert 'counts[sample]' in wrappers[1]  # Exact allocation sizes, not a larger backing object.


@pytest.mark.parametrize('generation,audit',[('0','1'),('1','0')])
def test_persisted_l2_generator_is_independent_of_audit_flags(tmp_path,monkeypatch,generation,audit):
    from tests.test_l2_joint_registry import setup,registry,artifact
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    from riscv2x86_py.l2_joint_replay import replay
    findings,fn,c=setup(tmp_path,monkeypatch,multi_object=True)
    monkeypatch.setenv('RV2X86_JOINT_PERFORMANCE_V2',generation)
    layer=registry(tmp_path,findings,c,findings[0]).validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2,translation_artifact=artifact(findings[0]),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is ValidationStatus.VERIFIED,layer.detail
    value=json.loads((Path(c['replayDirectory'])/'joint-observation.json').read_text())
    assert value['schemaVersion'].endswith('.v2')
    monkeypatch.setenv('RV2X86_JOINT_PERFORMANCE_V2',audit)
    assert replay(value)==value
    value['harnessGenerator']='unapproved-generator'
    with pytest.raises(ValueError,match='GENERATOR_UNSUPPORTED'):replay(value)
