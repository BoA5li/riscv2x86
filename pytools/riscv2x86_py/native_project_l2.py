"""Run and read back the ORIGINAL operand provider on a finite project entry.

The result is one original L2 dimension attempt, not a substitute for the full
requirement-driven aggregator, L0/L1 prerequisites, canonical events or L3.
"""
from pathlib import Path
import json
from . import native_captured_deployment as d
from . import native_original_api as api
from . import native_project_evaluation as project
from .native_external_providers import checked
from .native_verifier_manifest import current, compare
from .project_acquisition import publish_checked
from .translation_validation import ValidationLevel
from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .validation_status import ValidationStatus
from .verification_session import measured

SCHEMA = 'riscv2x86.original-project-finite-L2-operands.v1'
PROVIDER = 'original-project-finite-typed-operands-v1'


def configuration(api_result, output):
    """API checker is mandatory; paths alone never admit a new function."""
    value = api.check(api_result)
    inputs = d.read(Path(api_result).resolve().parent / 'inputs.json')
    spec = d.read(inputs['spec']['path'])
    run = d.read(spec['run']['path']); translation = d.read(run['translation']['path'])
    report = d.read(translation['report']['path'])
    builds = {s: d.read(inputs['builds'][s]['path']) for s in api.SIDES}
    config = {'schemaVersion': 'riscv2x86.auto-l2-operand-runner.v1',
        'translatedReport': translation['report']['path'], 'functions': report['functions'],
        'workDirectory': str(Path(output) / 'work'), 'replayDirectory': str(Path(output) / 'replay'),
        'timeoutSeconds': spec['timeoutSeconds'], 'seed': 0, 'qemuBinary': spec['qemu']['path'],
        'typedProjectEntry': {'specPath': inputs['spec']['path'], 'requestPath': inputs['request']['path'],
            **{s + 'Build': inputs['builds'][s]['path'] for s in api.SIDES}}}
    for s in api.SIDES:
        config[s + 'Path'] = builds[s]['input']['path']; config[s + 'Digest'] = builds[s]['input']['digest']
    return value, inputs, spec, translation, report, config


def registry_descriptor(config, fragment_ids, manifest, report, resolved):
    """An ordinary ORIGINAL requirement-driven descriptor, with no new gate."""
    return {'type': 'requirement-driven', 'config': {
        'schemaVersion': 'riscv2x86.l2-requirement-driven-registry.v3',
        'requirementManifestPath': str(manifest), 'semanticProfilePath': str(report),
        'fragmentId': '${FRAGMENT_ID}', 'semanticProfileSource': 'translated-report',
        'providerSelectionUnit': 'fragment', 'executionProfile': 'rv64gc-user-to-x86_64-user',
        'environmentCapabilities': ['logical_operand_observation'],
        'environmentExecutionProfiles': ['rv64gc-user-to-x86_64-user'],
        'resolvedPlanPath': str(resolved), 'providers': [{
            'providerId': PROVIDER, 'supportedDimensions': ['logical_operands'],
            'supportedPatterns': ['branch', 'composite', 'jump', 'scalar'],
            'requiredCapabilities': ['logical_operand_observation'],
            'executionProfiles': ['rv64gc-user-to-x86_64-user'], 'bindingKind': 'automatic',
            'validatorType': 'automatic-l2-operand-differential',
            'configSchemaVersion': config['schemaVersion'], 'config': config, 'fragmentIds': sorted(fragment_ids)}]}}


@measured('native_project_l2.derive')
def derive(root, *, readback, checking_path=None):
    from .automatic_l2_operand import build_auto_l2_operand_validator, _authority, _emit
    from .native_original_applicability import check as check_applicability
    from .translation_attempt import load_translation_attempt_archive
    from .translation_artifact_binding import artifacts_from_report
    from .l2_evidence_closure import validated_provider_evidence
    from .l2_typed_entry import bind
    from .l2_eligibility import classify_l2_requirements
    root = Path(root).resolve(); inputs = d.read(root / 'inputs.json')
    checked(inputs, 'l2InputsIdentity'); compare(inputs['verifier'], current())
    for k in ('apiResult', 'applicability'): d.verify_snapshot(inputs[k])
    value, api_inputs, spec, translation, report, config = configuration(inputs['apiResult']['path'], root)
    app = check_applicability(inputs['applicability']['path'])
    if app['project'] != api_inputs['spec']:
        raise ValueError('L2_TYPED_APPLICABILITY_PROJECT_MISMATCH')
    selected = value['function']
    functions = [f for f in report['functions'] if f.get('nativeCompilerDeclarationId') == selected['compilerDeclarationIdentity']]
    if len(functions) != 1: raise ValueError('L2_TYPED_SELECTED_DECLARATION_NOT_UNIQUE')
    function = functions[0]
    entry = bind(function, selected, d.read(api_inputs['request']['path'])['domain'])
    archive = load_translation_attempt_archive(translation['attemptArchive']['path'])
    artifacts = artifacts_from_report(translation['report']['path'], archive)
    rows = []; ids = []
    # All original findings remain in the manifest. This attempt supplies only
    # the selected compiler declaration and only the logical operand dimension.
    for i, finding in enumerate(report['findings']):
        fragment = finding.get('fragment') or {}
        if fragment.get('enclosingFunction') != function['name']: continue
        fragment_id = fragment.get('id', ''); key = f'finding:{i}:{fragment_id}'
        artifact = artifacts.get(key)
        ids.append(fragment_id)
        if artifact is None:
            rows.append({'findingId': key, 'fragmentId': fragment_id,
                'typedEntryIdentity': entry['entryIdentity'], 'status': 'inconclusive',
                'detail': {'reasonCode': 'L2_TYPED_TRANSLATION_ARTIFACT_UNAVAILABLE'},
                'logicalOperandEvidenceChecked': False, 'canonicalInstructionCoverageVerified': False})
            continue
        cfg = {**config, 'workDirectory': str(root / ('finding-%06d' % i) / 'work'),
               'replayDirectory': str(root / ('finding-%06d' % i) / 'replay')}
        applicable = [r for r in app['facts']['instances']
                      if r['instanceBindingIdentity'] in selected['instanceBindingIdentities']
                      and r.get('astPath') == (finding.get('physicalEditBinding') or {}).get('astPath')]
        # If the report does not carry an AST path, an exclusion may be used
        # only when EVERY compiler-bound instance in this selection is excluded.
        if not applicable:
            applicable = [r for r in app['facts']['instances'] if r['instanceBindingIdentity'] in selected['instanceBindingIdentities']]
        excluded = bool(applicable) and all(r['sourceGuardClassification'] == 'excluded-under-compiler-query-contracts' for r in applicable)
        authority, reason = _authority(finding, report['functions'], artifact, typed_entry=entry)
        validator = build_auto_l2_operand_validator(cfg, readback=readback)
        layer = validator(level=ValidationLevel.L2, comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
                          translation_artifact=artifact, l2_provider_id=PROVIDER,
                          source_instance_excluded=excluded)
        detail = json.loads(layer.detail)
        closure, closure_reasons = (validated_provider_evidence(detail, artifact,
            dimension='logical_operands', provider_id=PROVIDER) if layer.status is ValidationStatus.VERIFIED else (None, ()))
        if layer.status is ValidationStatus.VERIFIED and (closure is None or closure_reasons):
            raise ValueError('L2_TYPED_ORIGINAL_EVIDENCE_CLOSURE_REJECTED:' + ','.join(closure_reasons))
        rows.append({'findingId': key, 'fragmentId': fragment_id, 'translationArtifactIdentity': artifact.identity,
            'typedEntryIdentity': entry['entryIdentity'], 'operandAuthorityReady': authority is not None,
            'authorityReasonCode': reason, 'sourceConditionExcluded': excluded,
            'authorityDiagnostic': (finding.get('approvalArtifact') or {}).get('l2ScalarAuthorityFailure'),
            'status': layer.status.value, 'evidenceIdentity': layer.evidence_identity, 'detail': detail,
            'logicalOperandEvidenceChecked': closure is not None,
            'canonicalInstructionCoverageVerified': False})
    if not rows: raise ValueError('L2_TYPED_SELECTED_TRANSLATION_ARTIFACT_REQUIRED')
    manifest = classify_l2_requirements(report)
    _emit(root / 'requirements.json', json.dumps(manifest, indent=2)+'\n', readback)
    template_config = {**config, 'workDirectory': '${WORK_DIR}/project-typed-L2/${ATTEMPT_ID}',
                       'replayDirectory': '${REPLAY_DIR}/${ATTEMPT_ID}-project-typed-L2'}
    descriptor = registry_descriptor(template_config, ids, root / 'requirements.json',
        translation['report']['path'], '${REPLAY_DIR}/${ATTEMPT_ID}-project-L2-plan.json')
    _emit(root / 'registry-descriptor.json', json.dumps(descriptor, indent=2)+'\n', readback)
    excluded_files = {root / 'result.json'}
    if checking_path is not None: excluded_files.add(Path(checking_path).resolve())
    inventory = [d.snapshot(p) for p in sorted(root.rglob('*')) if p.is_file() and p not in excluded_files]
    for k in ('apiResult', 'applicability'): d.verify_snapshot(inputs[k])
    return d.seal({'schemaVersion': SCHEMA, 'inputs': d.snapshot(root / 'inputs.json'),
        'entryContract': entry, 'caseCount': value['caseCount'], 'instances': rows, 'inventory': inventory,
        'registryDescriptor': d.snapshot(root / 'registry-descriptor.json'),
        'originalLogicalOperandsVerified': all(r['logicalOperandEvidenceChecked'] for r in rows),
        'formalValidationPerformed': False, 'semanticApproval': False, 'productionAcceptanceComplete': False,
        'scope': 'original-logical-operand-provider-under-finite-entry-not-complete-L2-or-program-acceptance'}, 'projectL2Identity')


def check(path):
    value = d.read(path); checked(value, 'projectL2Identity')
    if value != derive(Path(path).resolve().parent, readback=True, checking_path=path):
        raise ValueError('L2_TYPED_RESULT_REDERIVATION_MISMATCH')
    return value


def acquire(api_result, applicability, output):
    root = Path(output).resolve(); root.mkdir(parents=True, exist_ok=False)
    inputs = d.seal({'apiResult': d.snapshot(api_result), 'applicability': d.snapshot(applicability),
                     'verifier': current()}, 'l2InputsIdentity')
    project.write(root / 'inputs.json', inputs)
    value = derive(root, readback=False)
    publish_checked(root / 'result.json', value, check)
    return value
