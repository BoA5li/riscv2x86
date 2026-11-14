"""Exercise the ORIGINAL orchestrator; callbacks below are protocol fixtures."""
from riscv2x86_py import native_framework_admission as adapter
from riscv2x86_py.translation_validation import (TranslationArtifact,ProgramArtifact,TargetEnvironment,
    ValidationPlan,ValidationProfile,ValidationLevel,ValidationRuntimeRegistry,ValidationLayerResult)
from riscv2x86_py.validation_status import PreservationMode,ValidationStatus


def args():
    artifact=TranslationArtifact('f','model','plan','constraint','proof',PreservationMode.ARCHITECTURE_EQUIVALENT,
        'shell','riscv2x86.runtime.none','','recipe',(),'integer','pure-c')
    report={'stages':{n:{'status':'inconclusive'} for n in
        ('runtime-binding','entry-abi','legal-objects-inputs','output-termination')}}
    environment=TargetEnvironment('env','rv64gc','lp64d','x86_64','sysv_amd64',('qemu',),('native',),('none',),'runtime','loader')
    return report,artifact,ProgramArtifact('s','/fixture/source','object','sha256:source'),ProgramArtifact('t','/fixture/target','executable','sha256:target'),environment


def test_real_orchestrator_stops_at_native_prerequisites_without_invoking_l1():
    report,artifact,source,target,env=args();calls=[]
    def fixture(**kwargs):
        calls.append(kwargs['level'])
        return ValidationLayerResult(kwargs['level'],ValidationStatus.VERIFIED,'fixture-receipt')
    registry=ValidationRuntimeRegistry('test-registry',{l:fixture for l in (ValidationLevel.L0,ValidationLevel.L1)})
    plan=ValidationPlan('p',ValidationProfile.FUNCTIONAL,'qemu','native',0,10,'test-registry')
    result=adapter.invoke(report,artifact,source,target,plan,env,registry)
    assert calls==[ValidationLevel.L0]
    assert result.status is ValidationStatus.INCONCLUSIVE and result.completed_levels==(ValidationLevel.L0,)
    assert 'native.stage-required:entry-abi' in result.reason_codes


def test_failed_native_contract_is_not_downgraded_to_inconclusive():
    report,artifact,source,target,env=args();report['stages']['legal-objects-inputs']['status']='failed'
    runner=lambda **kw:ValidationLayerResult(kw['level'],ValidationStatus.VERIFIED,'fixture-receipt')
    registry=ValidationRuntimeRegistry('r',{ValidationLevel.L0:runner,ValidationLevel.L1:runner})
    result=adapter.invoke(report,artifact,source,target,ValidationPlan('p',ValidationProfile.FUNCTIONAL,'qemu','native',0,10,'r'),env,registry)
    assert result.status is ValidationStatus.FAILED


def test_missing_original_runner_remains_inconclusive_no_synthetic_l0():
    report,artifact,source,target,env=args()
    result=adapter.invoke(report,artifact,source,target,ValidationPlan('p',ValidationProfile.ARCHITECTURAL,'qemu','native',0,10,'r'),env,ValidationRuntimeRegistry('r',{}))
    assert result.reason_codes==('validation.layer-runner-missing:L0',)
    assert not result.completed_levels


def test_original_runner_output_directories_cannot_overwrite_audited_locations(tmp_path):
    import pytest
    with pytest.raises(ValueError,match='MUST_BE_ISOLATED'):
        adapter.validate_output_directories({'validators':{'L0':{'config':{'workDirectory':'/old/audited/build'}}}},tmp_path)
    adapter.validate_output_directories({'validators':{'L0':{'config':{'workDirectory':str(tmp_path/'new-matrix')}}}},tmp_path)


def test_original_inputs_are_copied_before_any_rebuild(tmp_path):
    from riscv2x86_py import native_captured_deployment as d
    source_file=tmp_path/'original.o';source_file.write_bytes(b'pinned-source')
    target_file=tmp_path/'original-program';target_file.write_bytes(b'pinned-target')
    source=ProgramArtifact('s',str(source_file),'object',d.digest(source_file),'build-s')
    target=ProgramArtifact('t',str(target_file),'executable',d.digest(target_file),'build-t')
    out=tmp_path/'new';out.mkdir()
    s,t=adapter.isolate_programs(source,target,{'artifacts':[]},out,create=True)
    from pathlib import Path
    Path(s.artifact_path).write_bytes(b'rebuilt-source');Path(t.artifact_path).write_bytes(b'rebuilt-target')
    assert source_file.read_bytes()==b'pinned-source' and target_file.read_bytes()==b'pinned-target'
    assert s.artifact_digest==source.artifact_digest and t.artifact_digest==target.artifact_digest


def test_native_artifact_export_binds_actual_proof_and_rejects_rehashed_bad_scope():
    from copy import deepcopy
    import pytest
    from riscv2x86_py import native_captured_deployment as d
    from riscv2x86_py.project_build_records import identity
    proof=d.seal({'instanceBindingIdentity':'instance','sourceInstruction':{'operation':'unsigned-high-multiply'},
       'localIntegerStatementEquivalenceVerified':True,
       'claimScope':'architectural-integer-values-under-compiler-and-context-contracts'},'proofIdentity')
    edit={'instanceBindingIdentity':'instance','constraintRelationIdentity':identity({'outputs':['=r'],'inputs':['r','r']}),
          'proofScope':'local-statement-under-unchanged-C-context'}
    candidate=d.seal({'localProofs':[proof],'edits':[edit],'sourceAstIdentity':identity({'ast':'fixture'}),
         'compilerOperandTypeWitnessesComplete':True,'tools':{},'sourceFlags':[],'targetFlags':[]},'candidateIdentity')
    result=adapter.artifacts(candidate)[0]
    from riscv2x86_py.translation_validation import translation_artifact_from_dict
    import json
    direct=translation_artifact_from_dict(result['translationArtifact'])
    assert direct==translation_artifact_from_dict(json.loads(json.dumps(result['translationArtifact'])))
    assert direct.identity==result['translationArtifactIdentity']
    assert result['translationArtifact']['proof_identity']==proof['proofIdentity']
    assert result['translationArtifact']['fragment_id']=='instance'
    assert result['translationArtifact']['l2_authority_complete'] is False
    bad=deepcopy(candidate);bad['localProofs'][0]['claimScope']='whole-program-approved'
    bad['localProofs'][0]=d.seal({k:v for k,v in bad['localProofs'][0].items() if k!='proofIdentity'},'proofIdentity')
    bad=d.seal({k:v for k,v in bad.items() if k!='candidateIdentity'},'candidateIdentity')
    with pytest.raises(ValueError,match='LOCAL_PROOF_BINDING'):adapter.artifacts(bad)


def test_verified_l0_cannot_leave_different_program_bytes(tmp_path):
    import pytest
    from types import SimpleNamespace
    from riscv2x86_py import native_captured_deployment as d
    source_path=tmp_path/'source';source_path.write_bytes(b'source')
    target_path=tmp_path/'target';target_path.write_bytes(b'target')
    source=ProgramArtifact('s',str(source_path),'object',d.digest(source_path))
    target=ProgramArtifact('t',str(target_path),'executable',d.digest(target_path))
    target_path.write_bytes(b'changed')
    with pytest.raises(ValueError,match='VERIFIED_PROGRAM_BYTES_CHANGED'):
        adapter.verify_completed_build(SimpleNamespace(completed_levels=(ValidationLevel.L0,)),source,target)
    adapter.verify_completed_build(SimpleNamespace(completed_levels=()),source,target)
