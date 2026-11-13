"""Keep archive selection order and the original mandatory L0 matrix contract."""
import os
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py import native_l0_materialization as native
from riscv2x86_py import native_toolchain_environment as environment
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.native_elf_runtime import parse
from riscv2x86_py.l0_build_matrix import render_link_template,validate_link_template


def test_template_retains_candidate_before_archive_instead_of_prepending_all_flags(tmp_path):
    gcc=shutil.which('gcc');ar=shutil.which('ar')
    if not gcc or not ar:pytest.skip('native GCC/ar required')
    (tmp_path/'candidate.c').write_text('extern int helper(void);int selected(void){return helper();}\n')
    (tmp_path/'helper.c').write_text('int helper(void){return 7;}\n')
    for name in ('candidate','helper'):
        subprocess.run([gcc,'-fPIC','-c',str(tmp_path/(name+'.c')),'-o',str(tmp_path/(name+'.o'))],check=True,capture_output=True)
    archive=tmp_path/'providers.a';subprocess.run([ar,'cq',str(archive),str(tmp_path/'helper.o')],check=True,capture_output=True)
    args=[gcc,'-shared','candidate.o','providers.a','-o','original.so']
    plan={'originalObject':{'argumentIndex':2},'library':{'outputIndex':5,'action':{'arguments':args},
        'inputs':[{'argumentIndex':i,**d.snapshot(tmp_path/name)} for i,name in [(2,'candidate.o'),(3,'providers.a')]]}}
    recipe=native.link_flags(plan)
    assert recipe==['-shared','{object}',str(archive),'-o','{output}']
    result=tmp_path/'correct.so'
    subprocess.run([gcc,*render_link_template(recipe,tmp_path/'candidate.o',result)],check=True,capture_output=True)
    correct=parse(result.read_bytes())
    assert any(s['name']=='helper' and s['defined'] for s in correct['dynamicSymbols'])
    wrong=tmp_path/'wrong.so'
    subprocess.run([gcc,'-shared',str(archive),str(tmp_path/'candidate.o'),'-o',str(wrong)],check=True,capture_output=True)
    assert not any(s['name']=='helper' and s['defined'] for s in parse(wrong.read_bytes())['dynamicSymbols'])


@pytest.mark.parametrize('value',[[],['{object}'],['{output}'],['{object}','{object}','{output}'],['{object}','{output}','']])
def test_template_does_not_guess_missing_or_duplicate_slots(value):
    with pytest.raises(ValueError):validate_link_template(value)


def test_environment_is_operation_local_and_preserves_legacy_defaults():
    assert environment.kwargs(['cc'])=={}
    default={'PATH':os.environ['PATH'],'MODEL':'target'};source={'PATH':os.environ['PATH'],'MODEL':'source'}
    with environment.operation(default,{'rv-cc':source}):
        assert environment.kwargs(['rv-cc'])['env']['MODEL']=='source'
        assert environment.kwargs(['gcc'])['env']['MODEL']=='target'
        with environment.operation(source,{}):assert environment.kwargs(['gcc'])['env']['MODEL']=='source'
        assert environment.kwargs(['gcc'])['env']['MODEL']=='target'
    assert environment.kwargs(['gcc'])=={}


@pytest.fixture
def real_matrix(real_api,monkeypatch):
    """All real compilers/ELFs; upstream candidate binding remains a fixture."""
    from copy import deepcopy
    from riscv2x86_py import native_api_experiment as experiment
    from riscv2x86_py.project_build_records import identity
    from riscv2x86_py.translation_validation import translation_artifact_from_dict,program_artifact_from_dict
    from riscv2x86_py.native_framework_admission import artifacts,isolate_programs
    if not shutil.which('clang'):pytest.skip('real Clang required for mandatory 18-cell matrix')
    root,_=real_api
    report,deployed,plan,candidate,receipt,source=experiment.context(root/'contracts.json')
    # Probe SDK availability before the real matrix; never suppress a matrix
    # error or accept a partial set of sanitizer cells as a complete matrix.
    probe=root/'sdk.c';probe.write_text('int main(void){return 0;}\n')
    for compiler in ('gcc','clang'):
        for sanitizer in ('address','undefined'):
            result=subprocess.run([compiler,'-fsanitize='+sanitizer,str(probe),'-o',str(root/'sdk')],capture_output=True)
            if result.returncode:
                pytest.skip('required sanitizer SDK unavailable: '+compiler+'/'+sanitizer)
    candidate=deepcopy(candidate);plan=deepcopy(plan);receipt=deepcopy(receipt)
    proof=d.seal({'instanceBindingIdentity':'fixture-instance','sourceInstruction':{'operation':'unsigned-high-multiply','bits':64},
        'localIntegerStatementEquivalenceVerified':True,
        'claimScope':'architectural-integer-values-under-compiler-and-context-contracts'},'proofIdentity')
    candidate.update({'sourceAstIdentity':identity({'fixture':'native AST boundary'}),
      'localProofs':[proof],'edits':[{'instanceBindingIdentity':'fixture-instance',
        'constraintRelationIdentity':identity({'output':['=r'],'inputs':['r','r']}),
        'proofScope':'local-statement-under-unchanged-C-context'}],
      'compilerOperandTypeWitnessesComplete':True,'tools':{candidate['targetCompiler']:d.digest(candidate['targetCompiler'])}})
    candidate=d.seal(candidate,'candidateIdentity')
    candidatefile=root/'matrix-candidate.json';candidatefile.write_text(__import__('json').dumps(candidate))
    obj=root/'target-input.o'
    subprocess.run([candidate['targetCompiler'],'-fPIC','-x','cpp-output','-c',candidate['candidatePath'],'-o',str(obj)],check=True,capture_output=True)
    plan['candidatePath']=str(candidatefile)
    plan['library']={'action':{'arguments':[candidate['targetCompiler'],'-shared',str(obj),'-o',str(root/'baseline.so')]},
        'outputIndex':4,'inputs':[{'argumentIndex':2,**d.snapshot(obj)}]}
    plan['originalObject']={'argumentIndex':2}
    receipt['context']['environment']=dict(plan['environment'])
    monkeypatch.setattr(experiment,'context',lambda path:(report,deployed,plan,candidate,receipt,source))
    value=native.acquire(root/'contracts.json','fixture-instance',root/'l0-reference',timeout=60)
    out=root/'framework';out.mkdir()
    src,tgt=isolate_programs(program_artifact_from_dict(value['sourceProgram']),program_artifact_from_dict(value['targetProgram']),deployed,out,create=True)
    return root,value,translation_artifact_from_dict(artifacts(candidate)[0]['translationArtifact']),src,tgt


# Reuse actual RV64/QEMU API fixture; absence is an explicit skip, not emulation.
from .test_native_api_experiment import real_api


def test_real_native_candidate_uses_full_original_matrix_and_can_be_reverified(real_matrix):
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    root,value,translation,source,target=real_matrix
    config={'schemaVersion':'riscv2x86.native-l0-runner.v1','nativeBuild':d.snapshot(root/'l0-reference/result.json'),
            'workDirectory':str(root/'framework/matrix')}
    validator=native.factory(config)
    result=validator(level=ValidationLevel.L0,translation_artifact=translation,source_program_artifact=source,
        target_program_artifact=target,target_environment={'sourceIsa':'rv64gc','sourceAbi':'lp64d','targetIsa':'x86_64','targetAbi':'sysv_amd64'})
    assert result.status is ValidationStatus.VERIFIED,result.detail
    assert native.check(root/'l0-reference/result.json')==value
