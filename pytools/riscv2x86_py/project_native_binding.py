"""Compiler API export and exact physical-domain binding for native CPP input.

This is prerequisite acquisition. It cannot translate, patch original macros,
approve a helper or bypass existing project/L0--L3 production gates.
"""
import json
from pathlib import Path
import subprocess

from .compiler_native_instance_binding import derive, call_contexts
from .project_acquisition import Runner, StageFailure
from .project_build_records import identity
from .project_compile_context import digest, validate as validate_context
from .project_tool_resolution import resolve_executable
from . import project_native_input as native_input

SCHEMA = 'riscv2x86.native-instance-binding-bundle.v1'


def read(path):
    return json.loads(Path(path).read_text())


def export_command(receipt, binary, input_path, report_path, output):
    return [binary, '--analysis-only', '--no-builtin-rules',
        '--src-root', str(input_path.parent), '-o', str(output/'no-rewrite'),
        '--report-json', str(report_path), str(input_path), '--',
        '--target=' + receipt['target'] + '-linux-gnu', '-std=gnu11',
        *receipt['analysisInput']['inspectionArguments'],
        '-Werror', '-Werror=unknown-attributes', '-Werror=ignored-attributes',
        '-Werror=unknown-warning-option', '-x', 'cpp-output']


def acquire(receipt_path, frontend, output, *, timeout=300):
    if type(timeout) is not int or timeout < 1:
        raise ValueError('NATIVE_BINDING_TIMEOUT_INVALID')
    if Path(output).absolute().parent == Path('/'):
        raise ValueError('NATIVE_BINDING_RESULT_PARENT_REQUIRED')
    runner = Runner(output, 'native-instance-binding')
    try:
        path = Path(receipt_path).resolve(strict=True); expected = digest(path)
        receipt = read(path)
        runner.state['currentStage'] = 'native-input-independent-replay'; runner.save()
        replayed = native_input.replay(receipt, runner.output/'native-input-replay', timeout=timeout)
        artifacts = native_input.validate_artifacts(receipt)
        raw = artifacts['inputBytes']; ast = artifacts['canonicalAst']
        context = receipt['context']; cwd = Path(context['workingDirectory'])
        binary = str(resolve_executable(frontend, cwd)); tool_digest = digest(binary)
        input_path = Path(artifacts['stages']['native-expanded']['stdoutPath']).resolve(strict=True)
        frontend_report = runner.output/'frontend-report.json'
        command = export_command(receipt, binary, input_path, frontend_report, runner.output)
        runner.state['currentStage'] = 'compiler-api-export'; runner.save()
        result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=timeout, check=False)
        stdout = runner.output/'frontend.stdout'; stdout.write_bytes(result.stdout)
        stderr = runner.output/'frontend.stderr'; stderr.write_bytes(result.stderr)
        command_record = {'command': command, 'directory': str(cwd),
            'returnCode': result.returncode, 'stdoutPath': str(stdout), 'stdoutDigest': digest(stdout),
            'stderrPath': str(stderr), 'stderrDigest': digest(stderr)}
        runner.state['commands'] = [command_record]; runner.save()
        if result.returncode:
            runner.state.update(status='failed', primaryFailure={'stage': 'compiler-api-export',
                'returnCode': result.returncode, 'stderrPath': str(stderr)})
            runner.save(); raise StageFailure('compiler-api-export', result.returncode)
        report = read(frontend_report)
        runner.state['currentStage'] = 'physical-instance-binding'; runner.save()
        bindings = derive(ast, report, raw, receipt['analysisInputIdentity'])
        contexts = call_contexts(ast, bindings, receipt['analysisInputIdentity'])
        binding_path = runner.output/'instance-bindings.json'
        context_path = runner.output/'call-contexts.json'
        binding_path.write_text(json.dumps(bindings, indent=2))
        context_path.write_text(json.dumps(contexts, indent=2))
        runner.state['currentStage'] = 'input-consistency'; runner.save()
        validate_context(context)
        if (digest(path) != expected or digest(binary) != tool_digest
                or input_path.read_bytes() != raw):
            raise ValueError('NATIVE_BINDING_INPUT_CHANGED')
        native_input.validate_artifacts(receipt)
        body = {'schemaVersion': SCHEMA, 'nativeInputReceiptPath': str(path),
            'nativeInputReceiptDigest': expected, 'nativeInputIdentity': receipt['nativeInputIdentity'],
            'analysisInputIdentity': receipt['analysisInputIdentity'], 'frontend': binary,
            'frontendDigest': tool_digest, 'nativeInputReplay': replayed,
            'freshNativeInputReceiptPath': str(runner.output/'native-input-replay/native-input.json'),
            'freshNativeInputReceiptDigest': digest(runner.output/'native-input-replay/native-input.json'),
            'command': command_record, 'frontendReportPath': str(frontend_report),
            'frontendReportDigest': digest(frontend_report), 'frontendReportIdentity': identity(report),
            'bindingsPath': str(binding_path), 'bindingsDigest': digest(binding_path),
            'bindingInventoryIdentity': bindings['bindingInventoryIdentity'],
            'contextsPath': str(context_path), 'contextsDigest': digest(context_path),
            'contextInventoryIdentity': contexts['contextInventoryIdentity'],
            'occurrenceCount': bindings['occurrenceCount'],
            'allEmittedAstAsmOccurrencesBound': True,
            'derivedInputInstanceBindingComplete': True,
            'originalSourceInstanceBindingComplete': False,
            'macroArgumentGraphComplete': False, 'editAuthorizationComplete': False,
            'endToEndEligibilityAssessed': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False}
        bundle = dict(body, bindingBundleIdentity=identity(body))
        bundle_path = runner.output/'binding-bundle.json'
        bundle_path.write_text(json.dumps(bundle, indent=2))
        runner.state.update(currentStage='complete', status='complete', acquisitionComplete=True,
            occurrenceCount=bindings['occurrenceCount'],
            derivedInputInstanceBindingComplete=True,
            bundlePath=str(bundle_path), bundleDigest=digest(bundle_path))
        runner.save(); return bundle
    except StageFailure as exc:
        if runner.state['status'] != 'failed':
            runner.state.update(status='failed', primaryFailure={'stage': exc.stage, 'returnCode': exc.code})
            runner.save()
        raise
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
        runner.failure(runner.state['currentStage'], exc); raise


def validate_artifacts(bundle):
    if (not isinstance(bundle, dict) or bundle.get('schemaVersion') != SCHEMA
            or bundle.get('bindingBundleIdentity') != identity({
                k: v for k, v in bundle.items() if k != 'bindingBundleIdentity'})):
        raise ValueError('NATIVE_BINDING_BUNDLE_INVALID')
    for key in ('nativeInputReceipt', 'freshNativeInputReceipt', 'frontendReport', 'bindings', 'contexts'):
        if digest(bundle[key+'Path']) != bundle[key+'Digest']:
            raise ValueError('NATIVE_BINDING_ARTIFACT_CHANGED:' + key)
    for key in ('stdout', 'stderr'):
        if digest(bundle['command'][key+'Path']) != bundle['command'][key+'Digest']:
            raise ValueError('NATIVE_BINDING_ARTIFACT_CHANGED:' + key)
    receipt = read(bundle['nativeInputReceiptPath'])
    artifacts = native_input.validate_artifacts(receipt)
    report_path = Path(bundle['frontendReportPath'])
    input_path = Path(artifacts['stages']['native-expanded']['stdoutPath']).resolve(strict=True)
    expected_command = export_command(receipt, bundle['frontend'], input_path, report_path, report_path.parent)
    if (bundle['command']['command'] != expected_command
            or bundle['command']['directory'] != receipt['context']['workingDirectory']
            or type(bundle['command']['returnCode']) is not int or bundle['command']['returnCode'] != 0):
        raise ValueError('NATIVE_BINDING_EXPORT_COMMAND_MISMATCH')
    fresh_receipt = read(bundle['freshNativeInputReceiptPath'])
    native_input.validate_artifacts(fresh_receipt)
    if identity(native_input.replay_projection(receipt)) != identity(native_input.replay_projection(fresh_receipt)):
        raise ValueError('NATIVE_BINDING_STORED_INPUT_REPLAY_MISMATCH')
    replay_body = {'schemaVersion': 'riscv2x86.native-analysis-input-replay.v1',
        'originalNativeInputIdentity': receipt['nativeInputIdentity'],
        'freshNativeInputIdentity': fresh_receipt['nativeInputIdentity'],
        'analysisInputIdentity': receipt['analysisInputIdentity'],
        'nativeInputReplayComplete': True, 'compilerEquivalenceVerified': False,
        'sourceInstanceBindingComplete': False, 'semanticApproval': False,
        'productionAcceptanceComplete': False}
    expected_replay = dict(replay_body, replayIdentity=identity(replay_body))
    if identity(bundle['nativeInputReplay']) != identity(expected_replay):
        raise ValueError('NATIVE_BINDING_INPUT_REPLAY_RECEIPT_INVALID')
    report = read(bundle['frontendReportPath'])
    bindings = derive(artifacts['canonicalAst'], report, artifacts['inputBytes'], receipt['analysisInputIdentity'])
    contexts = call_contexts(artifacts['canonicalAst'], bindings, receipt['analysisInputIdentity'])
    if (bundle['nativeInputIdentity'] != receipt['nativeInputIdentity']
            or bundle['analysisInputIdentity'] != receipt['analysisInputIdentity']
            or bundle['frontendReportIdentity'] != identity(report)
            or bundle['bindingInventoryIdentity'] != bindings['bindingInventoryIdentity']
            or bundle['contextInventoryIdentity'] != contexts['contextInventoryIdentity']
            or identity(read(bundle['bindingsPath'])) != identity(bindings)
            or identity(read(bundle['contextsPath'])) != identity(contexts)
            or type(bundle['occurrenceCount']) is not int or bundle['occurrenceCount'] != bindings['occurrenceCount']
            or bundle['allEmittedAstAsmOccurrencesBound'] is not True
            or bundle['derivedInputInstanceBindingComplete'] is not True
            or any(bundle.get(k) is not False for k in (
                'originalSourceInstanceBindingComplete', 'macroArgumentGraphComplete',
                'editAuthorizationComplete', 'endToEndEligibilityAssessed',
                'semanticApproval', 'productionAcceptanceComplete'))):
        raise ValueError('NATIVE_BINDING_DERIVATION_MISMATCH')
    return bindings, contexts


def replay(bundle, output, *, timeout=300):
    validate_artifacts(bundle)
    if digest(bundle['frontend']) != bundle['frontendDigest']:
        raise ValueError('NATIVE_BINDING_FRONTEND_CHANGED')
    fresh = acquire(bundle['nativeInputReceiptPath'], bundle['frontend'], output, timeout=timeout)
    def meaning(value):
        return {k: value[k] for k in ('schemaVersion', 'nativeInputReceiptDigest',
            'nativeInputIdentity', 'analysisInputIdentity', 'frontend', 'frontendDigest',
            'frontendReportIdentity', 'bindingInventoryIdentity', 'contextInventoryIdentity',
            'occurrenceCount', 'derivedInputInstanceBindingComplete',
            'originalSourceInstanceBindingComplete', 'macroArgumentGraphComplete',
            'editAuthorizationComplete', 'endToEndEligibilityAssessed',
            'semanticApproval', 'productionAcceptanceComplete')}
    if identity(meaning(bundle)) != identity(meaning(fresh)):
        raise ValueError('NATIVE_BINDING_INDEPENDENT_REPLAY_MISMATCH')
    body = {'schemaVersion': 'riscv2x86.native-binding-replay.v1',
        'originalBindingBundleIdentity': bundle['bindingBundleIdentity'],
        'freshBindingBundleIdentity': fresh['bindingBundleIdentity'],
        'analysisInputIdentity': fresh['analysisInputIdentity'],
        'bindingInventoryIdentity': fresh['bindingInventoryIdentity'],
        'nativeBindingReplayComplete': True, 'occurrenceCount': fresh['occurrenceCount'],
        'originalSourceInstanceBindingComplete': False, 'editAuthorizationComplete': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, replayIdentity=identity(body))


def build_basis(bundle, records_path):
    """Inspect captured actions, without inferring executable entries or ABIs."""
    from collections import Counter
    from .project_build_records import classify
    validate_artifacts(bundle)
    path = Path(records_path).resolve(strict=True); expected = digest(path); records = read(path)
    if (records.get('schemaVersion') != 'riscv2x86.project-build-records.v1'
            or records.get('inventoryIdentity') != identity({
                k: v for k, v in records.items() if k != 'inventoryIdentity'})):
        raise ValueError('NATIVE_BINDING_BUILD_RECORDS_INVALID')
    actions = records.get('actions')
    if not isinstance(actions, list) or not isinstance(records.get('unresolved'), list):
        raise ValueError('NATIVE_BINDING_BUILD_ACTIONS_REQUIRED')
    counts = Counter(); links = []; observed_success = 0
    for action in actions:
        if (not isinstance(action, dict) or not isinstance(action.get('arguments'), list)
                or not action['arguments'] or any(not isinstance(a, str) or not a for a in action['arguments'])
                or type(action.get('exitStatusObserved')) is not bool):
            raise ValueError('NATIVE_BINDING_BUILD_ACTION_INVALID')
        if action.get('actionIdentity') != identity({k: v for k, v in action.items() if k != 'actionIdentity'}):
            raise ValueError('NATIVE_BINDING_BUILD_ACTION_IDENTITY_INVALID')
        kind = classify(action['arguments'])
        if kind != action['kind']:
            raise ValueError('NATIVE_BINDING_BUILD_ACTION_KIND_MISMATCH')
        counts[kind] += 1
        if action.get('exitStatusObserved') is True:
            if type(action.get('observedReturnCode')) is not int:
                raise ValueError('NATIVE_BINDING_BUILD_EXIT_STATUS_INVALID')
            observed_success += action['observedReturnCode'] == 0
        if kind in {'link', 'archive'}:
            links.append(deepcopy_action(action))
    if dict(counts) != records.get('actionCounts'):
        raise ValueError('NATIVE_BINDING_BUILD_COUNTS_MISMATCH')
    context = read(bundle['nativeInputReceiptPath'])['context']
    selected = [a for a in actions if a['actionIdentity'] == context['actionIdentity']]
    if len(selected) > 1:
        raise ValueError('NATIVE_BINDING_BUILD_CONTEXT_AMBIGUOUS')
    if selected and identity(selected[0]) != identity(context['originalAction']):
        raise ValueError('NATIVE_BINDING_BUILD_CONTEXT_MISMATCH')
    if digest(path) != expected:
        raise ValueError('NATIVE_BINDING_BUILD_RECORDS_CHANGED')
    body = {'schemaVersion': 'riscv2x86.native-build-entry-basis.v1',
        'bindingBundleIdentity': bundle['bindingBundleIdentity'], 'recordsPath': str(path),
        'recordsDigest': expected, 'recordsInventoryIdentity': records['inventoryIdentity'],
        'actionCounts': dict(counts), 'observedSuccessfulActions': observed_success,
        'selectedNativeCompileActionPresent': bool(selected),
        'unresolvedBuildRecords': records.get('unresolved'), 'linkAndArchiveActions': links,
        'formalEvaluationEntrySelected': False, 'legalInputObjectDomainProvided': False,
        'targetBuildAdaptationApproved': False, 'buildLinkClosureVerified': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, basisIdentity=identity(body))


def deepcopy_action(value):
    # Build records are persisted JSON; preserve every recorded field.
    return json.loads(json.dumps(value))
