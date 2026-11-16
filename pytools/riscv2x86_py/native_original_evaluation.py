"""Execute ORIGINAL evaluation of an independently checked original candidate.

This adapter owns no translation rules, validators, or approval algorithm.
Its summaries are attributed observations of original results, not ABI/object
proofs. Record checking does not rerun external tools or certify their semantics.
"""
import json
from pathlib import Path

from . import native_captured_deployment as d
from . import native_original_pipeline as route
from . import evaluation as original
from .native_external_providers import checked
from .native_verifier_manifest import current, compare
from .project_acquisition import Runner, publish_checked
from .translation_validation import (load_validation_plan, load_target_environment,
                                    translation_validation_result_from_dict)
from .validation_status import ValidationStatus

SCHEMA = 'riscv2x86.native-original-evaluation.v1'


def contracts(request_path):
    """Freeze explicit top-level contracts. Nested runtime evidence is checked
    by its original provider, not guessed from names of strings in a template.
    Require absolute paths so running/resuming in another cwd is unambiguous.
    """
    if not request_path or not Path(request_path).is_file():
        raise ValueError('ORIGINAL_EVALUATION_REQUEST_REGULAR_FILE_REQUIRED')
    request = original.load_evaluation_request(request_path)
    refs = {}
    for key, path in (('validationPlan', request.validation_plan),
                      ('targetEnvironment', request.target_environment)):
        if not Path(path).is_absolute():
            raise ValueError('ORIGINAL_EVALUATION_ABSOLUTE_CONTRACT_PATH_REQUIRED:' + key)
        refs[key] = d.snapshot(path)
    plan = load_validation_plan(request.validation_plan)
    load_target_environment(request.target_environment)
    # This provider's project specification lives outside the evaluation work
    # tree. Pin it as an input too: hashing retained logs alone cannot detect a
    # later change to its case list, environments or captured build recipes.
    checked_specs = {}; checked_apps = {}
    for level, descriptor in request.runtime_registry_template.get('validators', {}).items():
        if isinstance(descriptor, dict) and descriptor.get('type') == 'original-captured-project':
            from . import native_project_evaluation as project
            path = descriptor['config']['specPath']
            if not Path(path).is_absolute():
                raise ValueError('ORIGINAL_PROJECT_ABSOLUTE_SPEC_PATH_REQUIRED')
            if path not in checked_specs:
                project.check(path); checked_specs[path] = d.snapshot(path)
            d.verify_snapshot(checked_specs[path])
            refs['projectSpec:' + level] = checked_specs[path]
            app_path = descriptor['config'].get('applicabilityPath')
            if app_path is not None:
                from .native_original_applicability import check as check_applicability
                if not Path(app_path).is_absolute(): raise ValueError('ORIGINAL_APPLICABILITY_ABSOLUTE_PATH_REQUIRED')
                if app_path not in checked_apps:
                    checked_apps[app_path] = (check_applicability(app_path), d.snapshot(app_path))
                app, app_snapshot = checked_apps[app_path]
                d.verify_snapshot(app_snapshot)
                if app['project'] != d.snapshot(path): raise ValueError('ORIGINAL_APPLICABILITY_PROJECT_MISMATCH')
                refs['applicability:' + level] = app_snapshot
    return refs, plan


def inspect(run_path, request_path=None):
    """Report acquisition gaps without pretending they are a semantic check."""
    run = route.check_run(run_path)
    report = {'originalRunIdentity': run['originalRunIdentity'],
              'originalCandidateRouteComplete': True,
              'evaluationImplementation': 'riscv2x86_py.evaluation.run_evaluation',
              'requestContractAvailable': False, 'requiredLevels': [], 'gaps': [],
              'semanticApproval': False, 'productionAcceptanceComplete': False}
    if request_path is None:
        report['gaps'].append('EXPLICIT_ORIGINAL_EVALUATION_REQUEST_REQUIRED')
    else:
        refs, plan = contracts(request_path)
        bound = route.bound_evaluation_request(run['translation']['path'], request_path)
        if bound.get('validationUnit', 'program') != 'program':
            raise ValueError('ORIGINAL_PROGRAM_EVALUATION_UNIT_REQUIRED')
        validators = bound['runtimeRegistryTemplate'].get('validators', {})
        report.update(requestContractAvailable=True, contractReferences=refs,
                      requiredLevels=[level.value for level in plan.required_levels])
        report['gaps'].extend('ORIGINAL_LAYER_RUNNER_NOT_DECLARED:' + level.value
                              for level in plan.required_levels if level.value not in validators)
    report['scope'] = 'request-availability-not-semantic-readiness'
    return report


def summary(result):
    """Keep profile, attempt, and level distinctions; never synthesize passes."""
    rows = []
    for attempt in result['attempts']:
        validation = attempt.get('validation')
        layers = [] if validation is None else validation['layers']
        if validation is not None:
            translation_validation_result_from_dict(validation)
        assessment = None; machine_inventory = None
        for layer in layers:
            if layer['level'] == 'L1':
                try:
                    detail = json.loads(layer['detail'])
                    assessment = detail.get('obligationAssessment'); machine_inventory = detail.get('machineInventory')
                except (ValueError, TypeError, AttributeError): pass
        rows.append({'machineInventory': machine_inventory, 'obligationAssessment': assessment, 'attemptArtifactId': attempt['attemptArtifactId'],
                     'fragmentId': attempt['fragmentId'],
                     'translationOutcome': attempt['translationOutcome'],
                     'status': attempt['status'], 'reasonCodes': attempt['reasonCodes'],
                     'requestedProfile': attempt.get('requestedValidationProfile', ''),
                     'effectiveProfile': attempt.get('effectiveValidationProfile', ''),
                     'layers': [{'level': row['level'], 'status': row['status'],
                                 'evidenceIdentity': row['evidenceIdentity']} for row in layers]})
    return {'evaluationStatus': result['status'], 'reasonCodes': result['reasonCodes'],
            'attempts': rows,
            'sourceBuildReported': any(c['phase'] == 'source-build' for c in result['commands']),
            'targetBuildReported': any(c['phase'] == 'target-build' for c in result['commands']),
            'runtimeLayerReported': any(l['level'] == 'L1' for r in rows for l in r['layers']),
            'scope': 'original-evaluator-results-under-explicit-request',
            'semanticApproval': False, 'productionAcceptanceComplete': False}


def inventory(work):
    """Capture all retained evaluation files, including staged source, resolved
    registries, layer logs, and compiler artifacts. External contracts retain
    their original provider's checks; this is not a provenance proof for them.
    """
    root = Path(work)
    return [d.snapshot(path) for path in sorted(root.rglob('*')) if path.is_file()]


def check_original_result(result, request, work):
    if result.get('schemaVersion') != original.EVALUATION_RESULT_SCHEMA:
        raise ValueError('ORIGINAL_EVALUATION_RESULT_SCHEMA_INVALID')
    body = {k: v for k, v in result.items() if k not in ('evaluationIdentity', 'replayArtifact')}
    if (result['evaluationIdentity'] != original._digest_bytes(original._canonical(body))
            or result['requestIdentity'] != original._request_identity(request)):
        raise ValueError('ORIGINAL_EVALUATION_RESULT_IDENTITY_MISMATCH')
    ValidationStatus(result['status'])
    replay = Path(work) / result['replayArtifact']
    # Never follow an arbitrary result path outside the captured evaluation.
    if not replay.resolve().is_relative_to(Path(work).resolve()):
        raise ValueError('ORIGINAL_EVALUATION_REPLAY_PATH_INVALID')
    record = d.read(replay)
    for key in ('requestIdentity', 'evaluationIdentity', 'commands', 'attempts', 'candidateManifestId'):
        if record[key] != result[key]:
            raise ValueError('ORIGINAL_EVALUATION_REPLAY_MISMATCH:' + key)
    for side in ('source', 'target'):
        artifact = result[side + 'ProgramArtifact']
        if artifact is not None and d.digest(artifact['artifact_path']) != artifact['artifact_digest']:
            raise ValueError('ORIGINAL_EVALUATION_PROGRAM_CHANGED:' + side)
    summary(result)
    check_project_machine_inventory(result, request, work)


def check_project_machine_inventory(result, request, work):
    """Re-derive machine receipts bound to this request and both current builds."""
    descriptor = request.runtime_registry_template.get('validators', {}).get('L1', {})
    if descriptor.get('type') == 'original-captured-project' and descriptor.get('config', {}).get('applicabilityPath'):
        from .program_machine_inventory import check as check_machine_inventory
        for attempt in result['attempts']:
            for layer in (attempt.get('validation') or {}).get('layers', []):
                if layer['level'] != 'L1': continue
                detail = json.loads(layer['detail']); ref = detail.get('machineInventory')
                if not isinstance(ref, dict): raise ValueError('ORIGINAL_MACHINE_INVENTORY_REQUIRED')
                d.verify_snapshot(ref)
                if not Path(ref['path']).resolve().is_relative_to(Path(work).resolve()):
                    raise ValueError('ORIGINAL_MACHINE_INVENTORY_PATH_INVALID')
                evidence = check_machine_inventory(ref['path'])
                if evidence['project'] != d.snapshot(descriptor['config']['specPath']):
                    raise ValueError('ORIGINAL_MACHINE_INVENTORY_PROJECT_MISMATCH')
                for side in ('source', 'target'):
                    build = d.read(evidence['builds'][side]['path'])
                    program = result[side + 'ProgramArtifact']
                    if (build['program']['path'] != program['artifact_path']
                            or build['program']['digest'] != program['artifact_digest']):
                        raise ValueError('ORIGINAL_MACHINE_INVENTORY_PROGRAM_MISMATCH')


def acquire(run_path, request_path, output):
    readiness = inspect(run_path, request_path)
    run = route.check_run(run_path)
    refs, _ = contracts(request_path)
    # Bind before execution and verify again afterwards. Mutation during a run
    # leaves diagnostic files and a failed status, never a checked result.
    inputs = {'run': d.snapshot(run_path), 'requestTemplate': d.snapshot(request_path),
              **refs}
    runner = Runner(output, 'original-candidate-program-evaluation')
    try:
        runner.state['currentStage'] = 'original-evaluation-request'; runner.save()
        request_path_bound = runner.output / 'request.json'
        route.evaluation_request(run['translation']['path'], request_path, request_path_bound)
        request = original.load_evaluation_request(request_path_bound)
        runner.state['currentStage'] = 'original-program-evaluation'; runner.save()
        work = runner.output / 'evaluation'
        result = original.run_evaluation(request, work_directory=work)
        result_path = runner.output / 'evaluation-result.json'
        original.persist_evaluation_result(result, result_path)
        check_original_result(result, request, work)
        for ref in inputs.values(): d.verify_snapshot(ref)
        value = d.seal({'schemaVersion': SCHEMA, 'verifier': current(),
                       'inputs': inputs, 'readiness': readiness,
                       'boundRequest': d.snapshot(request_path_bound),
                       'evaluationResult': d.snapshot(result_path),
                       'evaluationFiles': inventory(work), 'facts': summary(result),
                       'originalEvaluationInvoked': True,
                       'independentProgramAuditPerformed': False,
                       'semanticApproval': False, 'productionAcceptanceComplete': False},
                      'originalEvaluationIdentity')
        publish_checked(runner.output / 'result.json', value, check)
        runner.state.update(status='complete', currentStage='complete', acquisitionComplete=True)
        runner.save()
        return value
    except Exception as exc:
        runner.failure(runner.state['currentStage'], exc)
        raise


def check(path):
    """Check record consistency and artifacts, NOT independent program proof."""
    value = d.read(path); checked(value, 'originalEvaluationIdentity')
    compare(value['verifier'], current())
    if value['schemaVersion'] != SCHEMA:
        raise ValueError('ORIGINAL_EVALUATION_SCHEMA_INVALID')
    for ref in value['inputs'].values(): d.verify_snapshot(ref)
    for key in ('boundRequest', 'evaluationResult'): d.verify_snapshot(value[key])
    run = route.check_run(value['inputs']['run']['path'])
    template = value['inputs']['requestTemplate']['path']
    refs, _ = contracts(template)
    if value['inputs'] != {'run': d.snapshot(value['inputs']['run']['path']),
                           'requestTemplate': d.snapshot(template), **refs}:
        raise ValueError('ORIGINAL_EVALUATION_INPUTS_MISMATCH')
    if d.read(value['boundRequest']['path']) != route.bound_evaluation_request(run['translation']['path'], template):
        raise ValueError('ORIGINAL_EVALUATION_REQUEST_MISMATCH')
    work = Path(path).resolve().parent / 'evaluation'
    if value['evaluationFiles'] != inventory(work):
        raise ValueError('ORIGINAL_EVALUATION_FILES_CHANGED')
    result = d.read(value['evaluationResult']['path'])
    check_original_result(result, original.load_evaluation_request(value['boundRequest']['path']), work)
    if (value['facts'] != summary(result) or value['readiness'] != inspect(value['inputs']['run']['path'], template)
            or value['originalEvaluationInvoked'] is not True
            or value['independentProgramAuditPerformed'] is not False
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('ORIGINAL_EVALUATION_REDERIVATION_MISMATCH')
    return value
