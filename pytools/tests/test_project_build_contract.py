from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import pytest

from riscv2x86_py.project_build_records import record,identity
from riscv2x86_py.project_compile_context import derive
from riscv2x86_py.project_build_contract import make,validate,profile,normalize_paths
from riscv2x86_py.project_validation_operation import active,operation,flags,require_compiler


def contract(tmp_path):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native GCC required')
    (tmp_path/'inc').mkdir(exist_ok=True);(tmp_path/'inc/config.h').write_text('#define VALUE 7\n')
    source=tmp_path/'original.c';source.write_text('#include "config.h"\nint entry(void) { return VALUE; }\n')
    a=record([gcc,'-std=c99','-O2','-I','inc','-DORIGINAL=1','-c','original.c','-o','original.o'],tmp_path,{'kind':'test'})
    return make(derive(a),clang=sys.executable,target_compiler=gcc,
        target_arguments=['-std=c99','-O2','-Iinc','-fPIC'],target_directory=tmp_path,
        source_driver_arguments=['-std=gnu11'],target_driver_arguments=['-std=gnu11'])


def test_profiles_preserve_order_and_separate_harness_from_body(tmp_path):
    c=contract(tmp_path);validate(c)
    cc,body=profile(c,'source');_,driver=profile(c,'source',driver=True)
    assert '-O2' in body and '-DORIGINAL=1' in body and str(tmp_path/'inc') in body
    assert '-DORIGINAL=1' not in driver and '-std=gnu11' in driver
    assert normalize_paths(['-DMESSAGE=relative/path','-Iinc'],tmp_path)==['-DMESSAGE=relative/path','-I'+str(tmp_path/'inc')]
    assert not c['semanticApproval'] and not c['compilerCompatibilityVerified']


def test_profile_identity_detects_rehashed_argument_changes(tmp_path):
    c=contract(tmp_path);c['targetProfile']['arguments'].append('-DCHANGED=1')
    c['contractIdentity']=identity({k:v for k,v in c.items() if k!='contractIdentity'})
    with pytest.raises(ValueError,match='DERIVATION'):validate(c)


def test_source_and_inspector_bytes_are_bound(tmp_path):
    c=contract(tmp_path)
    (tmp_path/'original.c').write_text('int different;\n')
    with pytest.raises(ValueError,match='CONTENT_CHANGED'):validate(c)


def test_target_profile_does_not_silently_accept_riscv_flags(tmp_path):
    c=contract(tmp_path)
    with pytest.raises(ValueError,match='ISA_ARGUMENT'):
        make(c['sourceContext'],clang=sys.executable,target_compiler=c['targetProfile']['compiler'],
            target_arguments=['-march=rv64gc'],target_directory=tmp_path,
            source_driver_arguments=[],target_driver_arguments=[])


def test_operation_context_is_explicit_nested_and_always_reset(tmp_path):
    c=contract(tmp_path);assert active() is None
    with pytest.raises(RuntimeError):
        with operation(c):
            assert active()==c and '-O2' in flags('source',['-O0'])
            require_compiler('target',c['targetProfile']['compiler'])
            with operation(c):assert active()==c
            raise RuntimeError('reject')
    assert active() is None and flags('source',['-O0'])==['-O0']


def test_native_project_artifact_and_separate_driver_replay(tmp_path):
    from riscv2x86_py.project_artifact_build import build,build_driver
    c=contract(tmp_path);src=Path(c['sourceContext']['sourcePath']);out=tmp_path/'object/native.o'
    result=build(c,'source',src,out,'object')
    assert out.is_file() and result['contractIdentity']==c['contractIdentity']
    with pytest.raises(FileExistsError):build(c,'source',src,out,'object')
    driver=tmp_path/'driver.c';driver.write_text('int entry(void); int main(void) { return entry()!=7; }\n')
    binary=tmp_path/'driver/program'
    assert build_driver(c,'source',[driver,src],binary).returncode==0
    import subprocess
    assert subprocess.run([str(binary)]).returncode==0
    logs=list(binary.parent.glob('*.command.json'));assert len(logs)==3
    commands=[json.loads(p.read_text())['command'] for p in logs]
    assert any('-DORIGINAL=1' in command for command in commands)
    assert any('-std=gnu11' in command and '-DORIGINAL=1' not in command for command in commands)


def test_project_validator_does_not_escalate_child_result(tmp_path):
    from riscv2x86_py.validation_runtime_registry import validation_runtime_registry_from_dict
    from riscv2x86_py.translation_validation import ValidationLayerResult,ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    c=contract(tmp_path)
    def factory(config):
        def run(**kwargs):
            assert active()['contractIdentity']==c['contractIdentity']
            return ValidationLayerResult(ValidationLevel.L1,ValidationStatus.INCONCLUSIVE,detail='missing proof')
        return run
    registry=validation_runtime_registry_from_dict({'schemaVersion':'riscv2x86.validation-runtime-registry.v2',
        'version':'test','validators':{'L1':{'type':'project-context-validator','config':{
            'schemaVersion':'riscv2x86.project-validator.v1','projectBuildContract':c,
            'validator':{'type':'test-child','config':{}}}}}},validator_factories={'test-child':factory})
    assert registry.layer_validators[ValidationLevel.L1](level=ValidationLevel.L1).status is ValidationStatus.INCONCLUSIVE
    assert active() is None


def test_compiler_mismatch_rejects_without_default_fallback(tmp_path):
    c=contract(tmp_path)
    with operation(c):
        with pytest.raises(ValueError,match='COMPILER_MISMATCH'):require_compiler('source',sys.executable)


def test_preprocessing_token_comparison_preserves_boundaries_and_literals():
    from riscv2x86_py.project_compiler_compatibility import tokens
    assert tokens('a << b')!=tokens('a < < b')
    assert tokens('1e+3')!=tokens('1e + 3')
    assert tokens('"a b"')!=tokens('"ab"')
    assert tokens('a + b')==tokens('a+ b')
    assert tokens('x >>= 1;')==['x','>>=','1',';']
    with pytest.raises(ValueError,match='TOKEN_UNSUPPORTED'):tokens('\\u00AB')


def test_project_report_cannot_silently_lose_context(tmp_path):
    from riscv2x86_py.project_validation_operation import report_operation
    c=contract(tmp_path);report=tmp_path/'report.json';report.write_text('{}')
    @report_operation
    def entry(report):return True
    with operation(c):
        with pytest.raises(ValueError,match='CONTRACT_MISSING'):entry(report)


def test_source_inspection_uses_project_flags_and_dependency_identity(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from riscv2x86_py.automatic_batch_cli import inspect_entry_points
    c=contract(tmp_path);source=Path(c['sourceContext']['sourcePath'])
    ast={'kind':'TranslationUnitDecl','inner':[{'kind':'FunctionDecl','id':'entry','name':'entry',
         'type':{'qualType':'unsigned long ()'},'loc':{'file':str(source)},
         'range':{'begin':{'offset':0},'end':{'offset':20,'tokLen':1}},
         'inner':[{'kind':'CompoundStmt','inner':[]}]}]}
    commands=[]
    def run(command,**kwargs):
        commands.append((command,kwargs))
        return SimpleNamespace(returncode=0,stderr='',stdout=(
            'rv2x86_call_inventory: '+str(source)+'\n' if '-M' in command else json.dumps(ast)))
    monkeypatch.setattr('riscv2x86_py.compiler_call_dependencies.subprocess.run',run)
    _,functions=inspect_entry_points(source,project_contract=c)
    assert functions[0]['projectBuildContractIdentity']==c['contractIdentity']
    assert functions[0]['compilerDependencyIdentity'].startswith('sha256:')
    assert all('-std=c99' in cmd and '-DORIGINAL=1' in cmd and kw['cwd']==tmp_path for cmd,kw in commands)


def test_compatibility_distinguishes_macro_branch_difference(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from riscv2x86_py.project_compiler_compatibility import acquire,require
    c=contract(tmp_path);source=c['sourceContext']['sourcePath']
    def run(command,**kwargs):
        if '-dM' in command:
            text='\n'.join('#define '+k+' '+v for k,v in {'__CHAR_BIT__':'8','__SIZEOF_SHORT__':'2','__SIZEOF_INT__':'4','__SIZEOF_LONG__':'8','__SIZEOF_LONG_LONG__':'8','__SIZEOF_POINTER__':'8','__BYTE_ORDER__':'1234','__WCHAR_TYPE__':'int','__SIZEOF_WCHAR_T__':'4','__STDC_VERSION__':'199901L'}.items())
        elif '-M' in command:text='rv2x86_call_inventory: '+source+'\n'
        else:text='int x = 1;' if command[0]==c['sourceContext']['nativeCompiler'] else 'int x = 2;'
        return SimpleNamespace(returncode=0,stderr='',stdout=text)
    monkeypatch.setattr('riscv2x86_py.project_compiler_compatibility.subprocess.run',run)
    receipt=acquire(c)
    assert receipt['sourcePreprocessingMatched'] is False and receipt['firstDifference']
    with pytest.raises(ValueError,match='PREPROCESSING_MISMATCH'):require(c,receipt)


def test_project_audit_rejects_absent_binding_before_old_acceptance():
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    with pytest.raises(ValueError,match='BUILD_BINDING_REQUIRED'):
        audit_evaluation({'status':'verified','commands':[{'command':['python','--project-build-contract','missing']} ]})


def test_whole_plan_keeps_missing_contract_variants_in_denominator(tmp_path):
    from riscv2x86_py.project_corpus_evaluation import execute
    variants=[{'variantId':name,'projectBuildContract':str(tmp_path/(name+'.json')),
               'frontend':sys.executable,'mechanismSelections':None,'harnessDirectory':None} for name in ['first','second']]
    plan={'schemaVersion':'riscv2x86.project-corpus-plan.v1','variants':variants};plan['planIdentity']=identity(plan)
    result=execute(plan,tmp_path/'run')
    assert result['plannedVariantCount']==2 and result['statusCounts']=={'blocked':2}
    assert not result['productionAcceptanceComplete']
    assert all(r['error']['type']=='FileNotFoundError' for r in result['records'])


def test_empty_or_duplicate_project_plan_cannot_claim_completion(tmp_path):
    from riscv2x86_py.project_corpus_evaluation import execute
    plan={'schemaVersion':'riscv2x86.project-corpus-plan.v1','variants':[]};plan['planIdentity']=identity(plan)
    with pytest.raises(ValueError,match='PLAN_INVALID'):execute(plan,tmp_path/'run')


def test_project_frontend_failure_is_bound_to_actual_flags_and_cwd(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from riscv2x86_py import automatic_translation_command as command
    from riscv2x86_py import project_compiler_compatibility,compiler_call_dependencies
    c=contract(tmp_path);source=c['sourceContext']['sourcePath'];path=tmp_path/'contract.json';path.write_text(json.dumps(c))
    monkeypatch.setattr(project_compiler_compatibility,'acquire',lambda *a,**kw:{'sourcePreprocessingMatched':True,'integerDataModelMatched':True})
    monkeypatch.setattr(compiler_call_dependencies,'acquire',lambda *a,**kw:{'dependencyManifest':{}})
    monkeypatch.setattr(compiler_call_dependencies,'validate',lambda value:value)
    observed=[]
    def run(argv,**kwargs):
        observed.append((argv,kwargs));return SimpleNamespace(args=argv,returncode=9,stdout='',stderr='front failure')
    monkeypatch.setattr(command.subprocess,'run',run)
    monkeypatch.setattr(sys,'argv',['translator','--frontend',sys.executable,'--source',source,
        '--source-root',str(tmp_path),'--report',str(tmp_path/'work/report.json'),'--project-build-contract',str(path)])
    assert command.main()==9
    assert len(observed)==1 and '-print-sysroot' not in observed[0][0]
    assert observed[0][1]['cwd']==str(tmp_path)
    assert '-std=c99' in observed[0][0] and '-DORIGINAL=1' in observed[0][0]
    payload=json.loads((tmp_path/'work/report.json.preflight.json').read_text())
    assert payload['backendExecuted'] is False


def test_matching_cpp_tokens_do_not_hide_target_integer_abi_mismatch(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from riscv2x86_py.project_compiler_compatibility import acquire,require
    c=contract(tmp_path);source=c['sourceContext']['sourcePath']
    def run(command,**kwargs):
        if '-dM' in command:
            facts={'__CHAR_BIT__':'8','__SIZEOF_SHORT__':'2','__SIZEOF_INT__':'4','__SIZEOF_LONG__':'8',
                '__SIZEOF_LONG_LONG__':'8','__SIZEOF_POINTER__':'8','__BYTE_ORDER__':'1234','__WCHAR_TYPE__':'int',
                '__SIZEOF_WCHAR_T__':'4','__STDC_VERSION__':'199901L'}
            if '-fPIC' in command:facts['__CHAR_UNSIGNED__']='1'
            text='\n'.join('#define '+k+' '+v for k,v in facts.items())
        elif '-M' in command:text='rv2x86_call_inventory: '+source+'\n'
        else:text='int entry(void) { return 7; }'
        return SimpleNamespace(returncode=0,stderr='',stdout=text)
    monkeypatch.setattr('riscv2x86_py.project_compiler_compatibility.subprocess.run',run)
    receipt=acquire(c)
    assert receipt['sourcePreprocessingMatched'] and not receipt['integerDataModelMatched']
    with pytest.raises(ValueError,match='INTEGER_DATA_MODEL_MISMATCH'):require(c,receipt)


def test_target_cpp_branch_difference_is_blocking_before_artifact_compile(tmp_path,monkeypatch):
    from riscv2x86_py.project_artifact_build import build
    c=contract(tmp_path);target=tmp_path/'target.c';target.write_text('int entry(void) { return 8; }\n')
    monkeypatch.setattr('riscv2x86_py.project_compiler_compatibility.target_acquire',
        lambda *a,**kw:{'targetPreprocessingMatched':False,'semanticApproval':False})
    output=tmp_path/'result/target.o'
    with pytest.raises(ValueError,match='TARGET_PREPROCESSING_MISMATCH'):build(c,'target',target,output,'object')
    assert not output.exists()
    assert output.with_name(output.name+'.target-cpp.json').is_file()


def test_driver_macros_cannot_change_generated_observer_semantics(tmp_path):
    c=contract(tmp_path)
    with pytest.raises(ValueError,match='DRIVER_PREPROCESSOR_ADAPTER_REQUIRED'):
        make(c['sourceContext'],clang=c['inspectionCompiler'],target_compiler=c['targetProfile']['compiler'],
            target_arguments=c['targetProfile']['arguments'],target_directory=tmp_path,
            source_driver_arguments=['-Dprintf=fake'],target_driver_arguments=[])


def test_program_semantic_options_cannot_silently_change_on_migration(tmp_path):
    c=contract(tmp_path)
    with pytest.raises(ValueError,match='PROGRAM_SEMANTIC_ARGUMENTS_MISMATCH'):
        make(c['sourceContext'],clang=c['inspectionCompiler'],target_compiler=c['targetProfile']['compiler'],
            target_arguments=[*c['targetProfile']['arguments'],'-fwrapv'],target_directory=tmp_path,
            source_driver_arguments=c['sourceDriverProfile']['arguments'],target_driver_arguments=c['targetDriverProfile']['arguments'])


@pytest.mark.parametrize('native,inspection', [
    ('int x = a++ + b;','int x = a + + +b;'),
    ('#pragma pack(1)\nstruct S {int x;};','#pragma pack(1) struct S {int x;};'),
])
def test_cpp_compatibility_cannot_merge_operators_or_pragma_lines(tmp_path,monkeypatch,native,inspection):
    from types import SimpleNamespace
    from riscv2x86_py.project_compiler_compatibility import acquire,require
    c=contract(tmp_path);source=c['sourceContext']['sourcePath']
    def run(command,**kwargs):
        if '-dM' in command:
            facts={'__CHAR_BIT__':'8','__SIZEOF_SHORT__':'2','__SIZEOF_INT__':'4','__SIZEOF_LONG__':'8',
                '__SIZEOF_LONG_LONG__':'8','__SIZEOF_POINTER__':'8','__BYTE_ORDER__':'1234',
                '__WCHAR_TYPE__':'int','__SIZEOF_WCHAR_T__':'4','__STDC_VERSION__':'199901L'}
            text='\n'.join('#define '+k+' '+v for k,v in facts.items())
        elif '-M' in command:text='rv2x86_call_inventory: '+source+'\n'
        else:text=native if command[0]==c['sourceContext']['nativeCompiler'] else inspection
        return SimpleNamespace(returncode=0,stderr='',stdout=text)
    monkeypatch.setattr('riscv2x86_py.project_compiler_compatibility.subprocess.run',run)
    receipt=acquire(c)
    assert receipt['schemaVersion']=='riscv2x86.project-preprocessing-compatibility.v2'
    assert receipt['tokenizationVersion']=='riscv2x86.c11-gnu-pp-token-spellings.v1'
    assert not receipt['sourcePreprocessingMatched']
    with pytest.raises(ValueError,match='PREPROCESSING_MISMATCH'):require(c,receipt)
    old=deepcopy(receipt);old['schemaVersion']='riscv2x86.project-preprocessing-compatibility.v1'
    old['compatibilityIdentity']=identity({k:v for k,v in old.items() if k!='compatibilityIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):require(c,old)
