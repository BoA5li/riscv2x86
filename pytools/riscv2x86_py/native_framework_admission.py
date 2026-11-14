"""Native candidate adapter to the ORIGINAL translation validation orchestrator.

Exports real local-proof-bound TranslationArtifacts, never dummy identities.
Existing registry factories remain responsible for L0--L3. Native prerequisites
are an additional gate, not substitutes for any registered validator. Layer
failures/inconclusive states and partial results are preserved verbatim.
"""
from dataclasses import asdict,replace
import json
from pathlib import Path

from . import native_captured_deployment as d
from . import native_api_experiment as api_experiment
from .native_external_providers import checked
from .project_build_records import identity
from .translation_validation import (TranslationArtifact,ProgramArtifact,ValidationLevel,ValidationLayerResult,
    ValidationRuntimeRegistry,run_translation_validation,validation_plan_from_dict,target_environment_from_dict)
from .validation_status import PreservationMode,ValidationStatus
from .validation_runtime_registry import validation_runtime_registry_from_dict

SCHEMA='riscv2x86.native-framework-execution.v1'


def artifacts(candidate):
    checked(candidate,'candidateIdentity')
    proofs=candidate['localProofs'];edits=candidate['edits']
    if not 1<=len(edits)<=1024 or len(proofs)!=len(edits):raise ValueError('FRAMEWORK_NATIVE_PROOF_SET_REQUIRED')
    rows=[];seen=set()
    for edit,proof in zip(edits,proofs):
        checked(proof,'proofIdentity');instance=edit['instanceBindingIdentity']
        if (instance in seen or proof['instanceBindingIdentity']!=instance
                or proof['localIntegerStatementEquivalenceVerified'] is not True
                or proof['claimScope']!='architectural-integer-values-under-compiler-and-context-contracts'
                or edit['proofScope']!='local-statement-under-unchanged-C-context'):
            raise ValueError('FRAMEWORK_NATIVE_LOCAL_PROOF_BINDING_INVALID')
        seen.add(instance)
        source_model={'sourceAstIdentity':candidate['sourceAstIdentity'],'instanceBindingIdentity':instance,
                      'sourceInstruction':proof['sourceInstruction']}
        shell={'constraintRelationIdentity':edit['constraintRelationIdentity'],
               'compilerOperandTypeWitnessesComplete':candidate['compilerOperandTypeWitnessesComplete'],
               'scope':edit['proofScope']}
        if not shell['compilerOperandTypeWitnessesComplete']:raise ValueError('FRAMEWORK_NATIVE_OPERAND_TYPES_REQUIRED')
        artifact=TranslationArtifact(instance,identity(source_model),identity(edit),edit['constraintRelationIdentity'],
            proof['proofIdentity'],PreservationMode.ARCHITECTURE_EQUIVALENT,identity(shell),
            'riscv2x86.runtime.none','',identity({'tools':candidate['tools'],
                'sourceFlags':candidate['sourceFlags'],'targetFlags':candidate['targetFlags']}),(),
            'integer','pure-c')
        body=asdict(artifact);body['preservation_mode']=artifact.preservation_mode.value
        # Public parser consumes JSON arrays, including on direct in-memory
        # calls. dataclasses.asdict preserves tuples and is not a JSON codec.
        body['ignored_source_state']=list(artifact.ignored_source_state)
        rows.append({'instanceBindingIdentity':instance,'sourceModel':source_model,'shellFacts':shell,
                     'translationArtifact':body,'translationArtifactIdentity':artifact.identity,
                     'claimScope':proof['claimScope']})
    return rows


def prerequisite_reasons(report,level):
    """Only completed checked stages admit program semantics; no API shortcut."""
    if level is ValidationLevel.L0:return ()
    required=['runtime-binding','entry-abi','legal-objects-inputs','output-termination']
    reasons=['native.stage-required:'+name for name in required if report['stages'][name]['status']!='verified']
    if level in (ValidationLevel.L2,ValidationLevel.L3):
        # Source/target instance mapping and applicable L2 provider evidence are
        # still checked by the original registered L2 validator itself.
        coverage=(report.get('candidateStatementEvidence') or {})
        if not coverage.get('canonicalInstructionCoverageVerified',False):reasons.append('native.canonical-instance-execution-required')
    return tuple(reasons)


def invoke(report,artifact,source,target,plan,environment,registry,*,l3_requirement_manifest=None,l3_intent_profile=None,executed_levels=None):
    validators={}
    for level,validator in registry.layer_validators.items():
        def guarded(*,level=level,_validator=validator,**kwargs):
            reasons=prerequisite_reasons(report,level)
            failed=any(v['status']=='failed' for k,v in report['stages'].items() if k in ('runtime-binding','entry-abi','legal-objects-inputs','output-termination'))
            if reasons:return ValidationLayerResult(level,ValidationStatus.FAILED if failed else ValidationStatus.INCONCLUSIVE,
                detail=json.dumps({'reasonCodes':list(reasons),'scope':'native-admission-not-layer-execution'}))
            if executed_levels is not None:executed_levels.append(level.value)
            return _validator(level=level,**kwargs)
        validators[level]=guarded
    # No local replacement for ordering, profile checking, layer status or
    # result aggregation. Missing original runners remain inconclusive.
    return run_translation_validation(artifact,source,target,plan,environment,
        ValidationRuntimeRegistry(registry.version,validators),
        l3_requirement_manifest=l3_requirement_manifest,l3_intent_profile=l3_intent_profile)


def export(contracts_path,output):
    from .native_deployment_prerequisites import output_path
    report,deployed,plan,candidate,_,_=api_experiment.context(contracts_path)
    value=d.seal({'schemaVersion':'riscv2x86.native-framework-artifacts.v1',
        'contracts':d.snapshot(contracts_path),'contractEvidenceIdentity':report['contractEvidenceIdentity'],
        'candidateIdentity':candidate['candidateIdentity'],'deploymentIdentity':deployed['deploymentIdentity'],
        'artifacts':artifacts(candidate),
        'sourceProgram':asdict(ProgramArtifact(candidate['candidateIdentity']+':source-object',
            str(Path(candidate['candidatePath']).parent/'source.o'),'object',candidate['sourceObjectDigest'],candidate['candidateIdentity'])),
        'targetPrograms':[asdict(ProgramArtifact(deployed['deploymentIdentity']+':'+a['stage'],a['path'],
            'shared_library' if a['stage']=='derived-library' else 'executable',a['digest'],deployed['deploymentIdentity']))
            for a in deployed['artifacts'] if a['stage'] in ('derived-entry','derived-library')],
        'scope':'local-proofs-only-not-program-eligibility',
        'semanticApproval':False,'productionAcceptanceComplete':False},'frameworkArtifactsIdentity')
    path=output_path(output)
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
    return value


def acquire(contracts_path,request_path,output):
    from .native_deployment_prerequisites import output_path
    report,deployed,deployment_plan,candidate,_,_=api_experiment.context(contracts_path)
    request=d.read(request_path)
    expected={'schemaVersion','instanceBindingIdentity','sourceProgram','targetProgram','plan','environment','registry',
              'l3RequirementManifest','l3IntentProfile'}
    if set(request) not in (expected,expected|{'nativeBuild','sourceRunnerTool'}) or request['schemaVersion']!='riscv2x86.native-framework-request.v1':
        raise ValueError('FRAMEWORK_NATIVE_REQUEST_INVALID')
    rows=artifacts(candidate);matches=[r for r in rows if r['instanceBindingIdentity']==request['instanceBindingIdentity']]
    if len(matches)!=1:raise ValueError('FRAMEWORK_NATIVE_INSTANCE_REQUIRED')
    from .translation_validation import translation_artifact_from_dict,program_artifact_from_dict
    artifact=translation_artifact_from_dict(matches[0]['translationArtifact'])
    source,target=programs(request,candidate,deployed)
    validation_plan=validation_plan_from_dict(request['plan']);environment=target_environment_from_dict(request['environment'])
    root=output_path(output)
    validate_output_directories(request['registry'],root)
    registry=validation_runtime_registry_from_dict(request['registry'])
    root.mkdir()
    source,target=isolate_programs(source,target,deployed,root,create=True)
    inputs=d.seal({'schemaVersion':'riscv2x86.native-framework-inputs.v1',
        'contracts':d.snapshot(contracts_path),'request':d.snapshot(request_path),'outputDirectory':str(root)},'frameworkInputsIdentity')
    (root/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    executed=[]
    outcome=invoke(report,artifact,source,target,validation_plan,environment,registry,
                   l3_requirement_manifest=request['l3RequirementManifest'],l3_intent_profile=request['l3IntentProfile'],executed_levels=executed)
    # Original runners rebuild only isolated copies; audited inputs stay pinned.
    api_experiment.context(contracts_path);d.verify_snapshot(inputs['request'])
    verify_completed_build(outcome,source,target)
    post=[d.snapshot(p) for p in sorted((root/'artifacts').rglob('*')) if p.is_file()]
    (root/'post-artifacts.json').write_text(json.dumps(post,indent=2)+'\n')
    value=d.seal({'schemaVersion':SCHEMA,'contractEvidenceIdentity':report['contractEvidenceIdentity'],
        'candidateIdentity':candidate['candidateIdentity'],'translationArtifactIdentity':artifact.identity,
        'sourceProgramDigest':source.artifact_digest,'targetProgramDigest':target.artifact_digest,
        'frameworkResult':outcome.to_dict(),'originalFrameworkInvoked':True,
        'executedOriginalValidatorLevels':executed,
        'nativeFrameworkInputsIdentity':inputs['frameworkInputsIdentity'],
        'postArtifactsIdentity':identity(post),
        'scope':'requested-profile-with-native-admission-prerequisites',
        'semanticApproval':False,'productionAcceptanceComplete':False},'nativeFrameworkIdentity')
    (root/'result.json').write_text(json.dumps(value,indent=2)+'\n');check(root/'result.json');return value


def check(path):
    from .translation_validation import (translation_artifact_from_dict,program_artifact_from_dict,
        translation_validation_result_from_dict)
    path=Path(path).resolve(strict=True);value=d.read(path);checked(value,'nativeFrameworkIdentity')
    inputs=d.read(path.parent/'inputs.json');checked(inputs,'frameworkInputsIdentity')
    if (set(inputs)!={'schemaVersion','contracts','request','outputDirectory','frameworkInputsIdentity'}
            or inputs['schemaVersion']!='riscv2x86.native-framework-inputs.v1' or inputs['outputDirectory']!=str(path.parent)):
        raise ValueError('FRAMEWORK_NATIVE_INPUT_SCHEMA_INVALID')
    d.verify_snapshot(inputs['contracts']);d.verify_snapshot(inputs['request'])
    report,deployed,plan,candidate,_,_=api_experiment.context(inputs['contracts']['path'])
    request=d.read(inputs['request']['path'])
    if (set(request) not in ({'schemaVersion','instanceBindingIdentity','sourceProgram','targetProgram','plan','environment','registry',
                       'l3RequirementManifest','l3IntentProfile'}, {'schemaVersion','instanceBindingIdentity','sourceProgram','targetProgram','plan','environment','registry',
                       'l3RequirementManifest','l3IntentProfile','nativeBuild','sourceRunnerTool'}) or request['schemaVersion']!='riscv2x86.native-framework-request.v1'):
        raise ValueError('FRAMEWORK_NATIVE_REQUEST_INVALID')
    matches=[r for r in artifacts(candidate) if r['instanceBindingIdentity']==request['instanceBindingIdentity']]
    if len(matches)!=1:raise ValueError('FRAMEWORK_NATIVE_INSTANCE_REQUIRED')
    artifact=translation_artifact_from_dict(matches[0]['translationArtifact'])
    source,target=programs(request,candidate,deployed)
    validate_output_directories(request['registry'],path.parent)
    source,target=isolate_programs(source,target,deployed,path.parent,create=False)
    post=d.read(path.parent/'post-artifacts.json')
    current=[d.snapshot(p) for p in sorted((path.parent/'artifacts').rglob('*')) if p.is_file()]
    if current!=post:raise ValueError('FRAMEWORK_NATIVE_ISOLATED_ARTIFACTS_CHANGED')
    previous=translation_validation_result_from_dict(value['frameworkResult'])
    verify_completed_build(previous,source,target)
    validation_plan=validation_plan_from_dict(request['plan']);environment=target_environment_from_dict(request['environment'])
    registry=validation_runtime_registry_from_dict(request['registry'])
    recorded={r.level:r for r in previous.layer_results}
    # Replay ORIGINAL aggregation and all native guards. Recorded layer outcomes
    # are captured runner receipts, not independent proof of their internals.
    callbacks={level:(lambda _level=level,**kwargs:recorded.get(_level,
        ValidationLayerResult(_level,ValidationStatus.INCONCLUSIVE,detail='not executed')))
        for level in registry.layer_validators}
    executed=[]
    fresh=invoke(report,artifact,source,target,validation_plan,environment,
        ValidationRuntimeRegistry(registry.version,callbacks),l3_requirement_manifest=request['l3RequirementManifest'],
        l3_intent_profile=request['l3IntentProfile'],executed_levels=executed)
    expected=d.seal({'schemaVersion':SCHEMA,'contractEvidenceIdentity':report['contractEvidenceIdentity'],
        'candidateIdentity':candidate['candidateIdentity'],'translationArtifactIdentity':artifact.identity,
        'sourceProgramDigest':source.artifact_digest,'targetProgramDigest':target.artifact_digest,
        'frameworkResult':fresh.to_dict(),'originalFrameworkInvoked':True,
        'executedOriginalValidatorLevels':executed,
        'nativeFrameworkInputsIdentity':inputs['frameworkInputsIdentity'],
        'postArtifactsIdentity':identity(post),
        'scope':'requested-profile-with-native-admission-prerequisites',
        'semanticApproval':False,'productionAcceptanceComplete':False},'nativeFrameworkIdentity')
    if expected!=value:raise ValueError('FRAMEWORK_NATIVE_REDERIVATION_MISMATCH')
    return value


def programs(request,candidate,deployed):
    from .translation_validation import program_artifact_from_dict
    source=program_artifact_from_dict(request['sourceProgram']);target=program_artifact_from_dict(request['targetProgram'])
    if request.get('nativeBuild') is not None:
        from .native_l0_materialization import check as check_native_build
        d.verify_snapshot(request['nativeBuild']);d.verify_snapshot(request['sourceRunnerTool'])
        build=check_native_build(request['nativeBuild']['path'])
        matches=[r for r in artifacts(candidate) if r['instanceBindingIdentity']==request['instanceBindingIdentity']]
        if (build['candidateIdentity']!=candidate['candidateIdentity'] or build['deploymentIdentity']!=deployed['deploymentIdentity']
                or len(matches)!=1 or matches[0]['translationArtifactIdentity']!=build['translationArtifactIdentity']
                or request['sourceProgram']!=build['sourceProgram'] or request['targetProgram']!=build['targetProgram']):
            raise ValueError('FRAMEWORK_NATIVE_MATRIX_PROGRAM_BINDING_INVALID')
        return source,target
    # Public ProgramArtifact values cannot designate unrelated same-ISA files.
    source_obj=Path(candidate['candidatePath']).parent/'source.o'
    target_options=[a for a in deployed['artifacts'] if a['stage'] in ('derived-entry','derived-library')]
    if (Path(source.artifact_path).resolve()!=source_obj.resolve() or source.artifact_digest!=candidate['sourceObjectDigest']
            or source.artifact_kind!='object' or source.build_identity!=candidate['candidateIdentity']
            or source.artifact_id!=candidate['candidateIdentity']+':source-object' or d.digest(source_obj)!=source.artifact_digest):
        raise ValueError('FRAMEWORK_NATIVE_SOURCE_PROGRAM_BINDING_INVALID')
    options=[a for a in target_options if Path(a['path']).resolve()==Path(target.artifact_path).resolve()
             and a['digest']==target.artifact_digest]
    if (len(options)!=1 or target.build_identity!=deployed['deploymentIdentity']
            or target.artifact_id!=deployed['deploymentIdentity']+':'+options[0]['stage']
            or target.artifact_kind!=('shared_library' if options[0]['stage']=='derived-library' else 'executable')):
        raise ValueError('FRAMEWORK_NATIVE_TARGET_PROGRAM_BINDING_INVALID')
    from .native_elf_runtime import parse
    if parse(source_obj.read_bytes())['machine']!=243 or parse(Path(target.artifact_path).read_bytes())['machine']!=62:
        raise ValueError('FRAMEWORK_NATIVE_PROGRAM_ARCHITECTURE_INVALID')
    return source,target



def validate_output_directories(registry,root):
    """Known original-runner output directories must be new experiment space."""
    root=Path(root).resolve();pending=[registry]
    keys={'workDirectory','work_directory','replayDirectory','replay_directory',
          'outputDirectory','output_directory','cacheDirectory','cache_directory'}
    while pending:
        row=pending.pop()
        if isinstance(row,list):pending.extend(row)
        elif isinstance(row,dict):
            for key,value in row.items():
                if key in keys:
                    if not isinstance(value,str) or not value:raise ValueError('FRAMEWORK_OUTPUT_DIRECTORY_INVALID')
                    dest=Path(value).resolve()
                    if not dest.is_relative_to(root) or dest==root or dest.is_relative_to(root/'artifacts'):
                        raise ValueError('FRAMEWORK_OUTPUT_DIRECTORY_MUST_BE_ISOLATED:'+key)
                elif isinstance(value,(dict,list)):pending.append(value)


def isolate_programs(source,target,deployed,root,*,create):
    import shutil
    root=Path(root).resolve();folder=root/'artifacts'
    source_path=folder/'source.o';target_path=folder/('program.so' if target.artifact_kind=='shared_library' else 'program')
    if create:
        folder.mkdir();(folder/'lib').mkdir()
        shutil.copyfile(source.artifact_path,source_path);shutil.copy2(target.artifact_path,target_path)
        # Preserve the audited executable's $ORIGIN/lib layout in this copy.
        from .native_elf_runtime import parse
        for library in [a for a in deployed['artifacts'] if a['stage']=='derived-library']:
            dest=folder/'lib'/Path(library['path']).name;shutil.copyfile(library['path'],dest)
            soname=parse(dest.read_bytes())['soname']
            if soname:
                if Path(soname).name!=soname:raise ValueError('FRAMEWORK_LIBRARY_SONAME_INVALID')
                alias=dest.parent/soname
                if alias!=dest:alias.symlink_to(dest.name)
        if d.digest(source_path)!=source.artifact_digest or d.digest(target_path)!=target.artifact_digest:
            raise ValueError('FRAMEWORK_COPY_BYTES_CHANGED')
    # Failed rebuilds may leave changed outputs. Record them separately; never
    # rewrite the original expected input digest to accept a failed build.
    return replace(source,artifact_path=str(source_path)),replace(target,artifact_path=str(target_path))



def verify_completed_build(result,source,target):
    if ValidationLevel.L0 in result.completed_levels:
        if d.digest(source.artifact_path)!=source.artifact_digest or d.digest(target.artifact_path)!=target.artifact_digest:
            raise ValueError('FRAMEWORK_VERIFIED_PROGRAM_BYTES_CHANGED')
