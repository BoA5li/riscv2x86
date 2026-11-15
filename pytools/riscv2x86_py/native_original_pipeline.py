"""Physical CPP input adapter to the ORIGINAL frontend/backend/materializer.

There are no instruction rules, replacement expressions or semantic approvals
in this module. Terminal outcomes and publication decisions belong to the
original pipeline. A CPP artifact never authorizes rewriting original macros.
"""
import json
from pathlib import Path
import subprocess
import sys

from . import native_captured_deployment as d
from . import project_native_binding as binding
from . import project_native_input as native
from .native_context_bridge import validated_input
from .native_external_providers import checked
from .project_acquisition import Runner, StageFailure, publish_checked
from .project_compile_context import digest
from .project_build_records import identity
from .candidate_materialization import (materialize_candidate_tree,
    load_candidate_artifact_manifest, verify_candidate_artifact_manifest)
from .translation_attempt import load_translation_attempt_archive
from .native_verifier_manifest import current as verifier, compare as compare_verifier
from .ghidra_configuration import resolve_install_dir
from .ghidra_preflight import runtime_environment

PREPARED='riscv2x86.native-original-input.v1'
TRANSLATED='riscv2x86.native-original-translation.v1'


def environment(context):
    return native.execution_environment(context)


def execute(runner, stage, command, cwd, env, timeout):
    runner.state['currentStage']=stage;runner.save()
    result=subprocess.run(command,cwd=cwd,env=env,capture_output=True,timeout=timeout,check=False)
    stdout=runner.output/(stage+'.stdout');stderr=runner.output/(stage+'.stderr')
    stdout.write_bytes(result.stdout);stderr.write_bytes(result.stderr)
    row={'stage':stage,'command':command,'directory':str(cwd),'environment':env,
         'returnCode':result.returncode,'stdout':d.snapshot(stdout),'stderr':d.snapshot(stderr)}
    runner.state.setdefault('commands',[]).append(row);runner.save()
    return row


def prepare(bundle_path, output, *, timeout=300):
    """Re-export from an isolated, byte-identical CPP file; never edit AST facts."""
    if type(timeout) is not int or not 1<=timeout<=86400:raise ValueError('ORIGINAL_INPUT_TIMEOUT_INVALID')
    bundle=d.read(bundle_path);binding.validate_artifacts(bundle)
    if digest(bundle['frontend'])!=bundle['frontendDigest']:raise ValueError('ORIGINAL_INPUT_FRONTEND_CHANGED')
    receipt=d.read(bundle['nativeInputReceiptPath']);artifacts=validated_input(receipt)
    if receipt['target']!='riscv64':raise ValueError('ORIGINAL_INPUT_RISCV64_REQUIRED')
    runner=Runner(output,'original-pipeline-input-adaptation')
    try:
        source=runner.output/'source';source.mkdir()
        file=source/'input.i';file.write_bytes(artifacts['inputBytes'])
        raw_report=runner.output/'frontend-export.json'
        report=runner.output/'frontend-report.json'
        command=binding.export_command(receipt,bundle['frontend'],file,raw_report,runner.output)
        row=execute(runner,'original-frontend',command,receipt['context']['workingDirectory'],
                    environment(receipt['context']),timeout)
        if row['returnCode']:
            raise StageFailure('original-frontend',row['returnCode'])
        bindings=binding.derive(artifacts['canonicalAst'],d.read(raw_report),file.read_bytes(),receipt['analysisInputIdentity'])
        if bindings['occurrenceCount']<1:raise ValueError('ORIGINAL_INPUT_INLINE_ASM_INSTANCE_REQUIRED')
        inventory=runner.output/'instance-bindings.json';inventory.write_text(json.dumps(bindings,indent=2)+'\n')
        from .physical_edit_binding import project
        report.write_text(json.dumps(project(d.read(raw_report),bindings,file,runner.output/'result.json'),indent=2)+'\n')
        value=d.seal({'schemaVersion':PREPARED,'bundle':d.snapshot(bundle_path),
            'adapterVerifier':verifier(), 'python':d.snapshot(sys.executable),
            'frontend':d.snapshot(bundle['frontend']),'source':d.snapshot(file),
            'rawFrontendReport':d.snapshot(raw_report),'frontendReport':d.snapshot(report),'bindings':d.snapshot(inventory),
            'command':row,'timeoutSeconds':timeout,
            'sourceLocationCount':None,'expandedInstanceCount':bindings['occurrenceCount'],
            'dependencyCompileContextCount':None,
            'artifactDomain':'frozen-preprocessed-translation-unit',
            'originalSourceEditAuthorized':False,'semanticApproval':False,
            'productionAcceptanceComplete':False},'originalInputIdentity')
        publish_checked(runner.output/'result.json',value,check_input)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save()
        return value
    except Exception as exc:
        runner.failure(runner.state['currentStage'],exc);raise


def check_command(row):
    for key in ('stdout','stderr'):d.verify_snapshot(row[key])
    if type(row['returnCode']) is not int:raise ValueError('ORIGINAL_PIPELINE_COMMAND_STATUS_INVALID')


def check_input(path):
    value=d.read(path);checked(value,'originalInputIdentity')
    if value['schemaVersion']!=PREPARED:raise ValueError('ORIGINAL_INPUT_SCHEMA_INVALID')
    compare_verifier(value['adapterVerifier'],verifier());d.verify_snapshot(value['python'])
    for key in ('bundle','frontend','source','rawFrontendReport','frontendReport','bindings'):d.verify_snapshot(value[key])
    bundle=d.read(value['bundle']['path']);binding.validate_artifacts(bundle)
    if digest(bundle['frontend'])!=bundle['frontendDigest']:raise ValueError('ORIGINAL_INPUT_FRONTEND_CHANGED')
    receipt=d.read(bundle['nativeInputReceiptPath']);artifacts=validated_input(receipt)
    source=Path(value['source']['path']);root=Path(path).resolve().parent
    if source!=root/'source/input.i' or source.read_bytes()!=artifacts['inputBytes']:
        raise ValueError('ORIGINAL_INPUT_BYTES_OR_DOMAIN_MISMATCH')
    if receipt['target']!='riscv64' or value['frontend']!=d.snapshot(bundle['frontend']):
        raise ValueError('ORIGINAL_INPUT_FRONTEND_OR_TARGET_MISMATCH')
    row=value['command'];check_command(row)
    expected=binding.export_command(receipt,bundle['frontend'],source,
                                    Path(value['rawFrontendReport']['path']),root)
    if (row['command']!=expected or row['returnCode']!=0
            or row['directory']!=receipt['context']['workingDirectory']
            or row['environment']!=environment(receipt['context'])):
        raise ValueError('ORIGINAL_INPUT_EXPORT_RECIPE_MISMATCH')
    bindings=binding.derive(artifacts['canonicalAst'],d.read(value['rawFrontendReport']['path']),
                            source.read_bytes(),receipt['analysisInputIdentity'])
    if (d.read(value['bindings']['path'])!=bindings or type(value['expandedInstanceCount']) is not int
            or value['expandedInstanceCount']<1 or value['expandedInstanceCount']!=bindings['occurrenceCount']):
        raise ValueError('ORIGINAL_INPUT_BINDING_REDERIVATION_MISMATCH')
    from .physical_edit_binding import project
    if d.read(value['frontendReport']['path'])!=project(d.read(value['rawFrontendReport']['path']),bindings,source,root/'result.json'):
        raise ValueError('ORIGINAL_INPUT_PHYSICAL_PROJECTION_MISMATCH')
    if (value['artifactDomain']!='frozen-preprocessed-translation-unit'
            or value['sourceLocationCount'] is not None or value['dependencyCompileContextCount'] is not None
            or any(value[k] is not False for k in ('originalSourceEditAuthorized','semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('ORIGINAL_INPUT_CLAIM_ESCALATION')
    return value


def backend_command(prepared, report, *, ghidra_install_dir=None, ghidra_language_id=None):
    install=str(resolve_install_dir(ghidra_install_dir))
    command=[sys.executable,'-m','riscv2x86_py.cli','--in',prepared['frontendReport']['path'],
             '--out',str(report),'--xlen','64','--skip-verify','--ghidra-install-dir',install]
    for option,value in (('--ghidra-language-id',ghidra_language_id),):
        if value is not None:command.extend((option,str(value)))
    return command


def backend_environment(receipt,ghidra_install_dir,*,runtime_env=None):
    env=environment(receipt['context']);env['PYTHONPATH']=str(Path(__file__).resolve().parents[1])
    env.update(runtime_environment(runtime_env))
    # Both the register query and p-code lifter must select the same explicit
    # installation. The public CLI argument configures the former; the latter
    # uses the existing GHIDRA_INSTALL_DIR runtime interface.
    env['GHIDRA_INSTALL_DIR']=str(resolve_install_dir(ghidra_install_dir))
    return env


def translate(input_path,output,*,ghidra_install_dir=None,ghidra_language_id=None,timeout=600,runtime_env=None):
    """Invoke the public CLI, then the original candidate materializer.

    --skip-verify requests candidates withheld pending external validation. It
    does not skip the semantic proof gate and never grants program acceptance.
    """
    if type(timeout) is not int or not 1<=timeout<=86400:raise ValueError('ORIGINAL_INPUT_TIMEOUT_INVALID')
    # Resolve in the caller's working directory, BEFORE entering a new output
    # directory. Empty/missing/non-executable launchers create no partial run.
    ghidra_install_dir=str(resolve_install_dir(ghidra_install_dir))
    runtime_env=runtime_environment(runtime_env)
    prepared=check_input(input_path);runner=Runner(output,'original-pipeline-translation')
    try:
        bundle=d.read(prepared['bundle']['path']);receipt=d.read(bundle['nativeInputReceiptPath'])
        env=backend_environment(receipt,ghidra_install_dir,runtime_env=runtime_env)
        report=runner.output/'translated.json'
        command=backend_command(prepared,report,ghidra_install_dir=ghidra_install_dir,
                                ghidra_language_id=ghidra_language_id)
        row=execute(runner,'original-backend',command,runner.output,env,timeout)
        archive=Path(str(report)+'.attempts.json')
        if not report.is_file() or not archive.is_file():
            raise StageFailure('original-backend',row['returnCode'] or 2)
        from .physical_edit_binding import validate_report
        validate_report(prepared,report)
        attempts=load_translation_attempt_archive(archive)
        manifest=materialize_candidate_tree(source_root=Path(prepared['source']['path']).parent,
            staging_root=runner.output/'candidate-staging',translated_report=report,
            attempt_archive=archive,manifest_output=runner.output/'candidate-manifest.json')
        value=d.seal({'schemaVersion':TRANSLATED,'input':d.snapshot(input_path),
            'adapterVerifier':verifier(),'python':d.snapshot(sys.executable),
            'report':d.snapshot(report),'attemptArchive':d.snapshot(archive),
            'candidateManifest':d.snapshot(runner.output/'candidate-manifest.json'),
            'candidateManifestIdentity':manifest.manifest_id,'command':row,
            'ghidraInstallDir':ghidra_install_dir,'ghidraLanguageId':ghidra_language_id,
            'backendRuntimeEnvironment':runtime_env,
            'timeoutSeconds':timeout,'attemptOutcomes':[a.translation_outcome.value for a in attempts.attempts],
            'translationImplementation':'riscv2x86_py.cli/pipeline.run',
            'materializationImplementation':'candidate_materialization.materialize_candidate_tree',
            'originalSourceEditAuthorized':False,'semanticApproval':False,
            'productionAcceptanceComplete':False},'originalTranslationIdentity')
        publish_checked(runner.output/'result.json',value,check_translation)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save()
        return value
    except Exception as exc:
        runner.failure(runner.state['currentStage'],exc);raise


def check_translation(path):
    value=d.read(path);checked(value,'originalTranslationIdentity')
    if value['schemaVersion']!=TRANSLATED:raise ValueError('ORIGINAL_TRANSLATION_SCHEMA_INVALID')
    compare_verifier(value['adapterVerifier'],verifier());d.verify_snapshot(value['python'])
    if str(resolve_install_dir(value['ghidraInstallDir']))!=value['ghidraInstallDir']:
        raise ValueError('ORIGINAL_TRANSLATION_NONCANONICAL_GHIDRA_CONFIGURATION')
    for key in ('input','report','attemptArchive','candidateManifest'):d.verify_snapshot(value[key])
    prepared=check_input(value['input']['path']);check_command(value['command'])
    root=Path(path).resolve().parent
    command=backend_command(prepared,root/'translated.json',ghidra_install_dir=value['ghidraInstallDir'],
                            ghidra_language_id=value['ghidraLanguageId'])
    bundle=d.read(prepared['bundle']['path']);receipt=d.read(bundle['nativeInputReceiptPath'])
    env=backend_environment(receipt,value['ghidraInstallDir'],runtime_env=value['backendRuntimeEnvironment'])
    if (value['command']['command']!=command or value['command']['directory']!=str(root)
            or value['command']['environment']!=env):raise ValueError('ORIGINAL_TRANSLATION_RECIPE_MISMATCH')
    from .physical_edit_binding import validate_report
    validate_report(prepared,value['report']['path'])
    manifest=load_candidate_artifact_manifest(value['candidateManifest']['path'])
    verify_candidate_artifact_manifest(manifest,source_root=Path(prepared['source']['path']).parent,
        staging_root=root/'candidate-staging',translated_report=value['report']['path'],
        attempt_archive=value['attemptArchive']['path'])
    outcomes=[a.translation_outcome.value for a in load_translation_attempt_archive(value['attemptArchive']['path']).attempts]
    if (value['attemptOutcomes']!=outcomes or value['candidateManifestIdentity']!=manifest.manifest_id
            or value['translationImplementation']!='riscv2x86_py.cli/pipeline.run'
            or value['materializationImplementation']!='candidate_materialization.materialize_candidate_tree'
            or any(value[k] is not False for k in ('originalSourceEditAuthorized','semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('ORIGINAL_TRANSLATION_REDERIVATION_OR_CLAIM_MISMATCH')
    return value


def audit(translation_path,output):
    """Re-run the ORIGINAL backend and materializer, not the legacy generator."""
    old=check_translation(translation_path)
    root=Path(output).resolve();root.mkdir(parents=True,exist_ok=False)
    prepared=check_input(old['input']['path'])
    bundle=d.read(prepared['bundle']['path']);receipt=d.read(bundle['nativeInputReceiptPath'])
    frontend=Runner(root/'frontend-audit','original-frontend-independent-reexport')
    report=frontend.output/'frontend-report.json'
    command=binding.export_command(receipt,bundle['frontend'],Path(prepared['source']['path']),report,frontend.output)
    row=execute(frontend,'original-frontend',command,receipt['context']['workingDirectory'],
                environment(receipt['context']),old['timeoutSeconds'])
    if row['returnCode']!=0 or d.read(report)!=d.read(prepared['rawFrontendReport']['path']):
        raise ValueError('ORIGINAL_FRONTEND_INDEPENDENT_REEXPORT_MISMATCH')
    frontend.state.update(status='complete',currentStage='complete',acquisitionComplete=True);frontend.save()
    fresh=translate(old['input']['path'],root/'rebuild',
        ghidra_install_dir=old['ghidraInstallDir'],ghidra_language_id=old['ghidraLanguageId'],
        timeout=old['timeoutSeconds'],runtime_env=old['backendRuntimeEnvironment'])
    old_manifest=load_candidate_artifact_manifest(old['candidateManifest']['path'])
    new_manifest=load_candidate_artifact_manifest(fresh['candidateManifest']['path'])
    old_attempts=load_translation_attempt_archive(old['attemptArchive']['path'])
    new_attempts=load_translation_attempt_archive(fresh['attemptArchive']['path'])
    if (old['command']['returnCode']!=fresh['command']['returnCode']
            or old['attemptOutcomes']!=fresh['attemptOutcomes']
            or old_attempts!=new_attempts
            or old_manifest.target_tree_digest!=new_manifest.target_tree_digest):
        raise ValueError('ORIGINAL_BACKEND_INDEPENDENT_REPLAY_MISMATCH')
    value=d.seal({'schemaVersion':'riscv2x86.native-original-replay.v1',
        'original':d.snapshot(translation_path),'fresh':d.snapshot(root/'rebuild/result.json'),
        'freshFrontendReport':d.snapshot(report),'freshFrontendCommand':row,
        'originalBackendReplayComplete':True,'semanticApproval':False,
        'productionAcceptanceComplete':False},'originalReplayIdentity')
    publish_checked(root/'result.json',value,check_replay);return value


def check_replay(path):
    value=d.read(path);checked(value,'originalReplayIdentity')
    if value['schemaVersion']!='riscv2x86.native-original-replay.v1':raise ValueError('ORIGINAL_REPLAY_SCHEMA_INVALID')
    for key in ('original','fresh','freshFrontendReport'):d.verify_snapshot(value[key])
    old=check_translation(value['original']['path']);fresh=check_translation(value['fresh']['path'])
    prepared=check_input(old['input']['path']);bundle=d.read(prepared['bundle']['path'])
    receipt=d.read(bundle['nativeInputReceiptPath']);row=value['freshFrontendCommand'];check_command(row)
    report=Path(value['freshFrontendReport']['path'])
    expected=binding.export_command(receipt,bundle['frontend'],Path(prepared['source']['path']),report,report.parent)
    a=load_candidate_artifact_manifest(old['candidateManifest']['path'])
    b=load_candidate_artifact_manifest(fresh['candidateManifest']['path'])
    if (row['command']!=expected or row['returnCode']!=0
            or row['environment']!=environment(receipt['context'])
            or row['directory']!=receipt['context']['workingDirectory']
            or d.read(report)!=d.read(prepared['rawFrontendReport']['path'])
            or old['input']!=fresh['input'] or old['attemptOutcomes']!=fresh['attemptOutcomes']
            or any(old[key]!=fresh[key] for key in ('ghidraInstallDir','ghidraLanguageId','backendRuntimeEnvironment'))
            or old['command']['returnCode']!=fresh['command']['returnCode']
            or a.target_tree_digest!=b.target_tree_digest
            or load_translation_attempt_archive(old['attemptArchive']['path'])!=load_translation_attempt_archive(fresh['attemptArchive']['path'])
            or value['originalBackendReplayComplete'] is not True
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('ORIGINAL_REPLAY_REDERIVATION_MISMATCH')
    return value


def evaluation_request(translation_path,request_path,output):
    """Bind an explicit ORIGINAL evaluation request; never invent an input domain.

    Build commands, registry, comparison policy and layers must come from the
    experiment owner/original request producer. Their correctness is decided
    by the original evaluator, not by this input adapter.
    """
    from .evaluation import evaluation_request_from_dict, artifacts_from_report
    from .translation_validation import translation_artifact_from_dict
    value=check_translation(translation_path);prepared=check_input(value['input']['path'])
    request=d.read(request_path)
    # An explicit artifact map is authority, not a path template. It may only
    # describe artifacts derived by the ORIGINAL factory from this exact run.
    # An empty map uses the original evaluator's normal report derivation.
    supplied=request.get('translationArtifacts',{})
    if supplied:
        derived=artifacts_from_report(Path(value['report']['path']),
            load_translation_attempt_archive(value['attemptArchive']['path']),finding_ids=set(supplied))
        if set(supplied)!=set(derived) or any(
                translation_artifact_from_dict(supplied[key])!=derived[key] for key in supplied):
            raise ValueError('ORIGINAL_EVALUATION_STALE_OR_FOREIGN_TRANSLATION_ARTIFACT')
    request.update(sourceRoot=str(Path(prepared['source']['path']).parent),
        sourceRelativePath='input.i',targetRelativePath='input.i',
        translatedReport=value['report']['path'],attemptArchive=value['attemptArchive']['path'],
        translationCommand=[])
    evaluation_request_from_dict(request)
    with Path(output).open('x') as stream:json.dump(request,stream,indent=2);stream.write('\n')
    return request


def run(bundle_path,output,*,ghidra_install_dir=None,ghidra_language_id=None,timeout=600):
    """Gate original stages in order; never audit a missing/unsupported result."""
    from . import ghidra_preflight
    if type(timeout) is not int or not 1<=timeout<=86400:raise ValueError('ORIGINAL_INPUT_TIMEOUT_INVALID')
    install=str(resolve_install_dir(ghidra_install_dir))
    if ghidra_language_id not in (None,'RISCV:LE:64:default'):
        raise ValueError('ORIGINAL_RV64_LANGUAGE_UNSUPPORTED')
    bundle=d.read(bundle_path);binding.validate_artifacts(bundle)
    receipt=d.read(bundle['nativeInputReceiptPath']);validated_input(receipt)
    env=runtime_environment();runner=Runner(output,'original-pipeline-composed-run')
    try:
        runner.state['currentStage']='backend-preflight';runner.save()
        ghidra_preflight.acquire(runner.output/'preflight',ghidra_install_dir=install,
            environment=backend_environment(receipt,install,runtime_env=env),timeout=timeout)
        runner.state['currentStage']='original-input';runner.save()
        prepare(bundle_path,runner.output/'input',timeout=timeout)
        runner.state['currentStage']='original-translation';runner.save()
        value=translate(runner.output/'input/result.json',runner.output/'translation',
            ghidra_install_dir=install,ghidra_language_id=ghidra_language_id,timeout=timeout,runtime_env=env)
        if not translation_complete(value):
            runner.state['currentStage']='original-translation-outcome';runner.save()
            raise StageFailure('original-translation-outcome',value['command']['returnCode'] or 2)
        runner.state['currentStage']='original-audit';runner.save()
        audit(runner.output/'translation/result.json',runner.output/'audit')
        value=d.seal({'schemaVersion':'riscv2x86.native-original-run.v1',
            'bundle':d.snapshot(bundle_path),'verifier':verifier(),
            'preflight':d.snapshot(runner.output/'preflight/result.json'),
            'input':d.snapshot(runner.output/'input/result.json'),
            'translation':d.snapshot(runner.output/'translation/result.json'),
            'audit':d.snapshot(runner.output/'audit/result.json'),
            'originalCandidateRouteComplete':True,'programValidationPerformed':False,
            'semanticApproval':False,'productionAcceptanceComplete':False},'originalRunIdentity')
        publish_checked(runner.output/'result.json',value,check_run)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save();return value
    except Exception as exc:
        runner.failure(runner.state['currentStage'],exc);raise


def translation_complete(value):
    return (value['command']['returnCode']==0 and bool(value['attemptOutcomes'])
            and all(x in ('emitted','keep') for x in value['attemptOutcomes']))


def check_run(path):
    from . import ghidra_preflight
    value=d.read(path);checked(value,'originalRunIdentity');compare_verifier(value['verifier'],verifier())
    if value['schemaVersion']!='riscv2x86.native-original-run.v1':raise ValueError('ORIGINAL_RUN_SCHEMA_INVALID')
    for key in ('bundle','preflight','input','translation','audit'):d.verify_snapshot(value[key])
    preflight=ghidra_preflight.check(value['preflight']['path']);inp=check_input(value['input']['path'])
    translated=check_translation(value['translation']['path']);replayed=check_replay(value['audit']['path'])
    if (inp['bundle']!=value['bundle'] or translated['input']!=value['input']
            or replayed['original']!=value['translation'] or not translation_complete(translated)
            or preflight['installationDirectory']!=translated['ghidraInstallDir']
            or preflight['environment']!=translated['command']['environment']
            or value['originalCandidateRouteComplete'] is not True
            or any(value[k] is not False for k in ('programValidationPerformed','semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('ORIGINAL_RUN_REDERIVATION_MISMATCH')
    return value
