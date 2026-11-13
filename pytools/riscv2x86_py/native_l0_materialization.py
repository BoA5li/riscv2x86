"""Original 18-cell L0 matrix over the actual native candidate translation unit.

The captured library link is reused with its selected original object removed:
L0 compiles and supplies the candidate object separately in EACH matrix cell.
No old O2 library digest is relabeled as the canonical GCC-O0-none artifact.
"""
from dataclasses import asdict,replace
import json
from pathlib import Path
import shutil
from . import native_captured_deployment as d
from . import native_api_experiment as api
from .native_external_providers import checked
from .native_framework_admission import artifacts as translation_artifacts
from .native_toolchain_environment import operation
from .translation_validation import translation_artifact_from_dict,program_artifact_from_dict,ValidationLevel,ValidationLayerResult
from .l0_manifest_builder import build_l0_reference_manifest
from .l0_build_matrix import L0_BUILD_MATRIX_SCHEMA,load_l0_build_matrix,build_l0_validator
from .project_build_records import identity

SCHEMA='riscv2x86.native-l0-materialization.v1'


def link_flags(plan):
    link=plan['library'];index=plan['originalObject']['argumentIndex'];out=link['outputIndex']
    args=link['action']['arguments'];inputs={r['argumentIndex']:r for r in link['inputs']}
    if index not in inputs or args[out-1]!='-o' or out==index or not args[0]:raise ValueError('NATIVE_L0_CAPTURED_RECIPE_INVALID')
    # Link grammar was already admitted by deployment.validate/check_result.
    # Absolute input paths preserve meaning under a new matrix work directory.
    flags=[('{object}' if i==index else '{output}' if i==out else inputs[i]['path'] if i in inputs else a)
           for i,a in enumerate(args) if i!=0]
    if any(a.startswith('@') for a in flags):raise ValueError('NATIVE_L0_LINK_RESPONSE_CONTRACT_REQUIRED')
    return flags


def matrix_dict(matrix):
    return {'schemaVersion':L0_BUILD_MATRIX_SCHEMA,'sourcePath':matrix.source_path,'sourceCompiler':matrix.source_compiler,
        'sourceFlags':list(matrix.source_flags),'targetPath':matrix.target_path,'targetCompilers':list(matrix.target_compilers),
        'targetFlags':list(matrix.target_flags),'optimizations':list(matrix.optimizations),'sanitizers':list(matrix.sanitizers),
        'workDirectory':matrix.work_directory,'translationManifestPath':matrix.translation_manifest_path,
        'translationManifestDigest':matrix.translation_manifest_digest,'runtimeHeaders':list(matrix.runtime_headers),
        'includeDirectories':list(matrix.include_directories),'libraryDirectories':list(matrix.library_directories),
        'libraries':list(matrix.libraries),'linkKind':matrix.link_kind,'warningPolicy':{'warningsAsErrors':matrix.warnings_as_errors},
        'runtimeTimeoutSeconds':matrix.runtime_timeout_seconds,'targetLinkFlags':list(matrix.target_link_flags),'targetLinkArguments':list(matrix.target_link_arguments)}


def environments(plan,receipt):
    target=dict(plan['environment'])
    source={k:v for k,v in receipt['context']['environment'].items() if v is not None}
    # PATH is required, not inherited from an unrelated current shell.
    if 'PATH' not in source:raise ValueError('NATIVE_L0_CAPTURED_SOURCE_PATH_REQUIRED')
    return target,{receipt['context']['nativeCompiler']:source}


def acquire(contracts_path,instance,output,*,timeout=300):
    from .native_deployment_prerequisites import output_path
    report,deployed,plan,candidate,receipt,source=api.context(contracts_path)
    rows=[r for r in translation_artifacts(candidate) if r['instanceBindingIdentity']==instance]
    if len(rows)!=1:raise ValueError('NATIVE_L0_INSTANCE_REQUIRED')
    translation=translation_artifact_from_dict(rows[0]['translationArtifact'])
    env,overrides=environments(plan,receipt)
    tools=[]
    for name in ('gcc','clang'):
        found=shutil.which(name,path=env['PATH'])
        if found is None:raise ValueError('NATIVE_L0_MATRIX_COMPILER_REQUIRED:'+name)
        tools.append(d.snapshot(found))
    tools.append(d.snapshot(receipt['context']['nativeCompiler']))
    root=output_path(output);root.mkdir()
    (root/'source.i').write_bytes(source['inputBytes'])
    (root/'candidate.i').write_bytes(Path(candidate['candidatePath']).read_bytes())
    inputs=d.seal({'schemaVersion':'riscv2x86.native-l0-inputs.v1','contracts':d.snapshot(contracts_path),
        'instanceBindingIdentity':instance,'timeoutSeconds':timeout,'tools':tools},'nativeL0InputsIdentity')
    (root/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    with operation(env,overrides):
        matrix,src,tgt=build_l0_reference_manifest(source_path=root/'source.i',target_path=root/'candidate.i',
            output_directory=root/'reference',translation=translation,link_kind='shared_library',timeout=timeout,
            source_compiler=receipt['context']['nativeCompiler'],source_flags_override=candidate['sourceFlags'],
            target_flags_override=candidate['targetFlags'],target_link_arguments=link_flags(plan))
    build=identity({'manifestDigest':matrix.translation_manifest_digest,'candidateIdentity':candidate['candidateIdentity'],
                    'contractEvidenceIdentity':report['contractEvidenceIdentity']})
    src=replace(src,build_identity=build);tgt=replace(tgt,build_identity=build)
    # Manifest binds every one of the 18 cells. Freeze all reference outputs,
    # including object files, rather than checking only the chosen target DSO.
    outputs=[d.snapshot(p) for p in sorted((root/'reference').rglob('*')) if p.is_file()]
    body={'schemaVersion':SCHEMA,'nativeL0InputsIdentity':inputs['nativeL0InputsIdentity'],
        'contractEvidenceIdentity':report['contractEvidenceIdentity'],'candidateIdentity':candidate['candidateIdentity'],
        'deploymentIdentity':deployed['deploymentIdentity'],'translationArtifactIdentity':translation.identity,
        'matrix':matrix_dict(matrix),'sourceProgram':asdict(src),'targetProgram':asdict(tgt),'referenceOutputs':outputs,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    value=d.seal(body,'nativeL0MaterializationIdentity')
    (root/'result.json').write_text(json.dumps(value,indent=2)+'\n');check(root/'result.json');return value


def check(path):
    from .native_elf_runtime import parse
    path=Path(path).resolve(strict=True);root=path.parent;value=d.read(path);checked(value,'nativeL0MaterializationIdentity')
    inputs=d.read(root/'inputs.json');checked(inputs,'nativeL0InputsIdentity')
    if set(inputs)!={'schemaVersion','contracts','instanceBindingIdentity','timeoutSeconds','tools','nativeL0InputsIdentity'} or inputs['schemaVersion']!='riscv2x86.native-l0-inputs.v1':
        raise ValueError('NATIVE_L0_INPUT_SCHEMA_INVALID')
    if type(inputs['timeoutSeconds']) is not int or not 1<=inputs['timeoutSeconds']<=86400:raise ValueError('NATIVE_L0_TIMEOUT_INVALID')
    d.verify_snapshot(inputs['contracts'])
    report,deployed,plan,candidate,receipt,source=api.context(inputs['contracts']['path'])
    rows=[r for r in translation_artifacts(candidate) if r['instanceBindingIdentity']==inputs['instanceBindingIdentity']]
    if len(rows)!=1:raise ValueError('NATIVE_L0_INSTANCE_REQUIRED')
    translation=translation_artifact_from_dict(rows[0]['translationArtifact'])
    env,overrides=environments(plan,receipt)
    expected_tools=[]
    for name in ('gcc','clang'):
        found=shutil.which(name,path=env['PATH'])
        if found is None:raise ValueError('NATIVE_L0_MATRIX_COMPILER_REQUIRED:'+name)
        expected_tools.append(d.snapshot(found))
    expected_tools.append(d.snapshot(receipt['context']['nativeCompiler']))
    if inputs['tools']!=expected_tools:raise ValueError('NATIVE_L0_COMPILER_SELECTION_CHANGED')
    for snap in expected_tools:d.verify_snapshot(snap)
    if (root/'source.i').read_bytes()!=source['inputBytes'] or (root/'candidate.i').read_bytes()!=Path(candidate['candidatePath']).read_bytes():
        raise ValueError('NATIVE_L0_SOURCE_OR_CANDIDATE_CHANGED')
    matrix=load_l0_build_matrix(value['matrix'])
    if (matrix.source_path!=str(root/'source.i') or matrix.target_path!=str(root/'candidate.i')
            or matrix.source_compiler!=receipt['context']['nativeCompiler']
            or list(matrix.source_flags)!=candidate['sourceFlags'] or list(matrix.target_flags)!=candidate['targetFlags']
            or list(matrix.target_link_arguments)!=link_flags(plan) or matrix.target_link_flags or matrix.link_kind!='shared_library'
            or not matrix.warnings_as_errors or matrix.runtime_timeout_seconds!=inputs['timeoutSeconds']
            or matrix.translation_manifest_path!=str(root/'reference/l0-artifact-manifest.json')
            or matrix.translation_manifest_digest!=d.digest(matrix.translation_manifest_path)
            or matrix.work_directory!=str(root/'reference/verify')
            or any((matrix.runtime_headers,matrix.include_directories,matrix.library_directories,matrix.libraries))):
        raise ValueError('NATIVE_L0_MATRIX_RECIPE_CHANGED')
    actual=[d.snapshot(p) for p in sorted((root/'reference').rglob('*')) if p.is_file()]
    if actual!=value['referenceOutputs']:raise ValueError('NATIVE_L0_REFERENCE_OUTPUTS_CHANGED')
    # Reuse the strict original manifest parser and its complete cell contract.
    from .l0_artifact_manifest import load_l0_artifact_manifest
    manifest=load_l0_artifact_manifest(matrix.translation_manifest_path,matrix.translation_manifest_digest)
    src=program_artifact_from_dict(value['sourceProgram']);tgt=program_artifact_from_dict(value['targetProgram'])
    from .l0_build_matrix import _check_manifest_binding
    if _check_manifest_binding(manifest,matrix,translation,src,tgt):raise ValueError('NATIVE_L0_ORIGINAL_MANIFEST_BINDING_INVALID')
    if (src.artifact_path!=str(root/'reference/source.rv64.o') or tgt.artifact_path!=str(root/'reference/target.so')
            or src.artifact_kind!='object' or tgt.artifact_kind!='shared_library'
            or src.artifact_digest!=d.digest(src.artifact_path) or tgt.artifact_digest!=d.digest(tgt.artifact_path)
            or parse(Path(src.artifact_path).read_bytes())['machine']!=243
            or parse(Path(tgt.artifact_path).read_bytes())['machine']!=62):
        raise ValueError('NATIVE_L0_PROGRAM_BINDING_INVALID')
    build=identity({'manifestDigest':matrix.translation_manifest_digest,'candidateIdentity':candidate['candidateIdentity'],
                    'contractEvidenceIdentity':report['contractEvidenceIdentity']})
    if (src.build_identity!=build or tgt.build_identity!=build or value['candidateIdentity']!=candidate['candidateIdentity']
            or value['contractEvidenceIdentity']!=report['contractEvidenceIdentity']
            or value['deploymentIdentity']!=deployed['deploymentIdentity'] or value['translationArtifactIdentity']!=translation.identity
            or value['nativeL0InputsIdentity']!=inputs['nativeL0InputsIdentity']
            or value['schemaVersion']!=SCHEMA or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('NATIVE_L0_PARENT_BINDING_INVALID')
    return value


def factory(config):
    if set(config)!={'schemaVersion','nativeBuild','workDirectory'} or config['schemaVersion']!='riscv2x86.native-l0-runner.v1':
        raise ValueError('NATIVE_L0_RUNNER_CONFIG_INVALID')
    d.verify_snapshot(config['nativeBuild']);value=check(config['nativeBuild']['path'])
    matrix=replace(load_l0_build_matrix(value['matrix']),work_directory=config['workDirectory'])
    validator=build_l0_validator(matrix)
    def run(**kwargs):
        if kwargs['level'] is not ValidationLevel.L0:raise ValueError('NATIVE_L0_WRONG_LEVEL')
        current=check(config['nativeBuild']['path']);d.verify_snapshot(config['nativeBuild'])
        if kwargs['translation_artifact'].identity!=current['translationArtifactIdentity']:raise ValueError('NATIVE_L0_TRANSLATION_BINDING_INVALID')
        for key,program in [('sourceProgram',kwargs['source_program_artifact']),('targetProgram',kwargs['target_program_artifact'])]:
            expected=program_artifact_from_dict(current[key])
            if (program.artifact_digest!=expected.artifact_digest or program.artifact_kind!=expected.artifact_kind
                    or program.build_identity!=expected.build_identity or program.artifact_id!=expected.artifact_id):
                raise ValueError('NATIVE_L0_EXECUTION_ARTIFACT_MISMATCH')
        parent=d.read(Path(config['nativeBuild']['path']).parent/'inputs.json')
        _,_,plan,_,receipt,_=api.context(parent['contracts']['path']);env,overrides=environments(plan,receipt)
        with operation(env,overrides):result=validator(**kwargs)
        check(config['nativeBuild']['path']);return result
    return run


def prepare_request(build_path,output,framework_output,qemu,*,source_isa):
    """Create a genuine BUILD request with the real native L0 producer/runner."""
    import subprocess
    from .translation_validation import TargetEnvironment,ValidationPlan,ValidationProfile
    from .validation_runtime_registry import VALIDATION_RUNTIME_REGISTRY_SCHEMA
    from .native_deployment_prerequisites import output_path
    value=check(build_path);parent=d.read(Path(build_path).resolve().parent/'inputs.json')
    report,deployed,plan,candidate,receipt,_=api.context(parent['contracts']['path'])
    root=output_path(framework_output)
    qemu=d.snapshot(qemu)
    version=subprocess.run([qemu['path'],'--version'],capture_output=True,text=True,timeout=30,check=False)
    if version.returncode or 'qemu-riscv64' not in version.stdout:raise ValueError('NATIVE_L0_EXPLICIT_RV64_QEMU_REQUIRED')
    from .native_deployment_observation import check_observation
    base_inputs=d.read(Path(parent['contracts']['path']).parent/'inputs.json')
    observation=check_observation(base_inputs['observation']['path'])
    source_abi=api.source_abi(candidate).removeprefix('riscv_')
    config={'schemaVersion':'riscv2x86.native-l0-runner.v1','nativeBuild':d.snapshot(build_path),'workDirectory':str(root/'matrix')}
    registry={'schemaVersion':VALIDATION_RUNTIME_REGISTRY_SCHEMA,'version':identity(config),
              'validators':{'L0':{'type':'native-l0-build-matrix','config':config}}}
    env=TargetEnvironment(value['nativeL0MaterializationIdentity'],source_isa,source_abi,'x86_64','sysv_amd64',
         ('qemu',),('native',),('none',),value['nativeL0MaterializationIdentity'],observation['loader']['digest'])
    # Runner capabilities are configured/probed; BUILD executes no source program.
    selected_plan=ValidationPlan(value['nativeL0MaterializationIdentity']+':build',ValidationProfile.BUILD,
         'qemu','native',0,load_l0_build_matrix(value['matrix']).runtime_timeout_seconds,registry['version'])
    request={'schemaVersion':'riscv2x86.native-framework-request.v1',
        'instanceBindingIdentity':parent['instanceBindingIdentity'],'sourceProgram':value['sourceProgram'],
        'targetProgram':value['targetProgram'],'nativeBuild':d.snapshot(build_path),'sourceRunnerTool':qemu,
        'plan':{'schemaVersion':selected_plan.schema_version,'planId':selected_plan.plan_id,
            'profile':selected_plan.profile.value,'sourceRunner':selected_plan.source_runner,'targetRunner':selected_plan.target_runner,
            'seed':selected_plan.seed,'timeoutSeconds':selected_plan.timeout_seconds,
            'runtimeRegistryVersion':selected_plan.runtime_registry_version,'experimentContractId':''},
        'environment':env.to_dict(),'registry':registry,'l3RequirementManifest':None,'l3IntentProfile':None}
    # Use the original parsers before writing, so the request is concretely runnable.
    from .translation_validation import validation_plan_from_dict
    validation_plan_from_dict(request['plan'])
    with output_path(output).open('x') as stream:json.dump(request,stream,indent=2);stream.write('\n')
    return {'nativeL0MaterializationIdentity':value['nativeL0MaterializationIdentity'],
            'profile':'build','semanticApproval':False,'productionAcceptanceComplete':False}
