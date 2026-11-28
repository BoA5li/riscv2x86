"""Freeze declared program scope and generate evidence-production obligations.

This is a work plan for ORIGINAL validators. It cannot manufacture runtime
coverage, approve a trusted provider, or replace layer status aggregation.
"""
import json
from pathlib import Path
from . import native_captured_deployment as d
from .native_original_pipeline import check_translation,translation_complete
from .native_verifier_manifest import current,compare
from .project_acquisition import Runner,publish_checked

SCHEMA='riscv2x86.program-validation-obligations.v1'
SCOPE='riscv2x86.declared-program-scope.v1'


def derive(translation_path,scope):
    from .schema import load_report
    value=check_translation(translation_path)
    if not translation_complete(value):raise ValueError('PROGRAM_PLAN_COMPLETE_ORIGINAL_TRANSLATION_REQUIRED')
    if (not isinstance(scope,dict) or set(scope)!={'schemaVersion','entryContract','inputDomainContract',
            'observationContract','trustBoundaryContract','requiredLevels','buildCells'} or scope['schemaVersion']!=SCOPE):
        raise ValueError('PROGRAM_DECLARED_SCOPE_SCHEMA_INVALID')
    refs={}
    for key in ('entryContract','inputDomainContract','observationContract','trustBoundaryContract'):
        if not isinstance(scope[key],str) or not scope[key]:raise ValueError('PROGRAM_EXPLICIT_CONTRACT_REQUIRED:'+key)
        refs[key]=d.snapshot(scope[key])
    levels=scope['requiredLevels'];order=['L0','L1','L2','L3']
    if not isinstance(levels,list) or not levels or levels!=order[:len(levels)] or len(levels)>4:
        raise ValueError('PROGRAM_ORIGINAL_LEVEL_ORDER_REQUIRED')
    cells=scope['buildCells']
    if (not isinstance(cells,list) or not cells or len(cells)>128 or any(not isinstance(c,dict)
            or set(c)!={'cellId','buildContract'} or not isinstance(c['cellId'],str) or not c['cellId']
            or not isinstance(c['buildContract'],str) or not c['buildContract'] for c in cells)
            or len({c['cellId'] for c in cells})!=len(cells)):
        raise ValueError('PROGRAM_BUILD_CELL_IDENTITY_REQUIRED')
    builds=[{'cellId':c['cellId'],'contract':d.snapshot(c['buildContract'])} for c in cells]
    findings=load_report(value['report']['path'])
    instances=[{'findingIndex':i,'fragmentId':f.fragment.id if f.fragment else '',
                'physicalBinding':f.physicalEditBinding,
                'translationOutcome':f.translationOutcome} for i,f in enumerate(findings)]
    rows=[]
    def obligation(kind,phase,consumer,bindings):
        body={'kind':kind,'phase':phase,'consumer':consumer,'bindings':bindings,
              'status':'evidence-production-required'}
        rows.append(dict(body,obligationIdentity=d.identity(body)))
    for cell in builds:
        obligation('source-target-materialization-and-link','before-L0','l0_build_matrix',cell)
        if 'L1' in levels:
            for kind in ('legal-inputs-and-entry-interface','runtime-selected-artifacts','declared-comparison-policy'):
                obligation(kind,'before-L1','original-runtime-registry',cell)
            obligation('actual-output-error-and-termination-relation','after-L1','l1_differential',cell)
        if 'L2' in levels:
            for instance in instances:
                for kind in ('instance-survival-or-elimination','compiler-instance-to-canonical-region',
                             'canonical-region-runtime-events','operand-shell-and-applicable-effects'):
                    obligation(kind,'before-or-during-L2','original-L2-providers',{'cell':cell,'instance':instance})
        if 'L3' in levels:
            obligation('declared-intent-applicability-environment-and-observations','before-or-during-L3',
                       'original-L3-providers',cell)
    obligation('applicable-ABI-object-and-external-call-contracts','scoped-program-prerequisites',
               'checked-contract-consumers',{'contracts':refs})
    obligation('independent-program-evidence-audit','after-required-levels',
               'original-validation-and-audit',{'requiredLevels':levels})
    return {'translationIdentity':value['originalTranslationIdentity'],'contractReferences':refs,'buildCells':builds,
        'instances':instances,'obligations':rows,'requiredLevels':levels,
        'executionPreconditionsSeparatedFromPostconditions':True,
        'programScopeFrozen':True,'programPrerequisitesVerified':False,
        'canonicalInstructionCoverageVerified':False,'programValidationPerformed':False,
        'scope':'evidence-production-plan-not-evaluation-or-proof'}


def acquire(translation_path,scope_path,output):
    scope=d.read(scope_path);facts=derive(translation_path,scope);runner=Runner(output,'program-validation-plan')
    try:
        value=d.seal({'schemaVersion':SCHEMA,'verifier':current(),'translation':d.snapshot(translation_path),
            'declaredScope':d.snapshot(scope_path),'facts':facts,
            'semanticApproval':False,'productionAcceptanceComplete':False},'programObligationsIdentity')
        publish_checked(runner.output/'result.json',value,check)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save();return value
    except Exception as exc:runner.failure('program-obligations',exc);raise


def check(path):
    from .native_external_providers import checked
    value=d.read(path);checked(value,'programObligationsIdentity');compare(value['verifier'],current())
    for key in ('translation','declaredScope'):d.verify_snapshot(value[key])
    if (value['schemaVersion']!=SCHEMA
            or value['facts']!=derive(value['translation']['path'],d.read(value['declaredScope']['path']))
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('PROGRAM_OBLIGATIONS_REDERIVATION_MISMATCH')
    return value


# Obligations for the existing captured-project adapter. These identify the
# consumer phase; they do not remove final program requirements or grant facts.
_PROJECT_PHASES = {
    'THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED': 'before-L1',
    'ACTUAL_MACHINE_ABI_REQUIRED': 'before-L1',
    'INTERNAL_OBJECT_ACCESS_PROOF_REQUIRED': 'before-L1',
    'DEPENDENCY_CALL_AND_EFFECT_CLOSURE_REQUIRED': 'before-L1',
    'SOURCE_TARGET_TEST_INPUT_RELATION_REQUIRED': 'before-L1',
    'NATURAL_RUN_IMAGE_IDENTITY_REQUIRED': 'before-L1',
    'OUTPUT_AND_TERMINATION_RELATION_REQUIRED': 'after-L1',
    'CANONICAL_INSTANCE_INSTRUCTION_COVERAGE_REQUIRED': 'before-or-during-L2',
    'PROGRAM_L2_AUTHORITY_REQUIRED': 'before-or-during-L2',
    'INDEPENDENT_PROGRAM_AUDIT_REQUIRED': 'after-required-levels',
}


def project_assessment(spec, observation=None, applicability=None, *, project_evidence=None):
    """Classify actual obligations; process agreement is a bounded subgoal.

    Full preconditions do not currently have connected proof producers. Nothing
    accepts a caller-supplied Boolean as a discharge certificate.
    """
    if (not isinstance(spec.get('gaps'), list) or len(spec['gaps']) != len(_PROJECT_PHASES)
            or set(spec['gaps']) != set(_PROJECT_PHASES)):
        raise ValueError('PROGRAM_FULL_OBLIGATION_POLICY_REQUIRED')
    from .program_claim_consumption import consume
    consumption = consume(spec['projectEvaluationIdentity'], {
        'observations': [observation] if observation is not None else [],
        'selectedCaseIndices': observation.get('caseIndices', []) if observation is not None else [],
        'plannedCaseCount': len(spec.get('cases', []))}, project_evidence=project_evidence)
    derived = {r['reasonCode']: r for r in consumption['obligations']}
    rows = []
    for reason in spec['gaps']:
        if reason not in _PROJECT_PHASES: raise ValueError('PROGRAM_OBLIGATION_PHASE_UNREGISTERED:' + reason)
        body = {'reasonCode': reason, 'phase': _PROJECT_PHASES[reason],
                'status': derived[reason]['status'],
                'missingProofFacts': derived[reason]['missingProofFacts'],
                'checkedSubclaims': derived[reason]['checkedSubclaims'],
                'projectEvaluationIdentity': spec['projectEvaluationIdentity']}
        rows.append(dict(body, obligationIdentity=d.identity(body)))
    observable = 'not-observed'
    if observation is not None:
        if observation['executionBudgetFailed'] or observation['loaderListFailed']:
            observable = 'execution-unavailable'
        elif observation['exitOutsideDeclaredDomain']:
            observable = 'outside-declared-exit-domain'
        elif observation['mismatches']:
            observable = 'observed-mismatch'
        else:
            observable = 'observed-match'
    l1_pending = [r['reasonCode'] for r in rows if r['phase'] in ('before-L1', 'after-L1')
                  and r['status'] != 'verified']
    from .validation_status import ValidationStatus
    # Real checked producers must discharge these before bounded observation
    # can support a complete L1 result. L2/audit obligations are kept separately.
    status = (ValidationStatus.INCONCLUSIVE if l1_pending or observable in
              ('not-observed', 'execution-unavailable', 'outside-declared-exit-domain') else
              ValidationStatus.FAILED if observable == 'observed-mismatch' else ValidationStatus.VERIFIED)
    return {'schemaVersion': 'riscv2x86.project-obligation-assessment.v1',
            'obligations': rows, 'l1Status': status.value, 'l1ReasonCodes': l1_pending,
            'boundedProcessObservableStatus': observable, 'claimConsumption': consumption,
            'applicability': applicability['facts'] if applicability else None,
            'programRequirementsComplete': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False}


def l2_function_binding_diagnostic(finding, functions):
    """Explain the original name join without manufacturing compiler facts.

    Counts identify an acquisition/propagation gap; names alone never authorize
    an L2 function boundary or establish a declaration/instance/value-flow join.
    """
    fragment = finding.get('fragment') or {}
    name = fragment.get('enclosingFunction')
    if not isinstance(functions, list):
        raise ValueError('PROGRAM_L2_FUNCTION_TABLE_INVALID')
    matches = [row for row in functions if isinstance(row, dict) and row.get('name') == name]
    if not isinstance(name, str) or not name:
        disposition = 'enclosing-function-name-missing'
    elif not matches:
        disposition = 'function-record-not-found'
    elif len(matches) > 1:
        disposition = 'multiple-function-records'
    else:
        disposition = 'one-name-match-not-a-proof'
    approval = finding.get('approvalArtifact')
    approval = approval if isinstance(approval, dict) else {}
    return {
        'enclosingFunction': name,
        'functionRecordCount': len(functions),
        'nameMatchCount': len(matches),
        'disposition': disposition,
        'matches': [{
            'recordIndex': i,
            'recordedIdentities': {key: row[key] for key in (
                'id', 'declarationIdentity', 'functionIdentity', 'mangledName',
                'qualifiedName', 'functionId', 'nativeCompilerDeclarationId') if key in row},
            'arity': row.get('arity'),
            'compilerHarnessSignatureSupported': row.get('compilerHarnessSignatureSupported'),
            'operandBoundaryPresent': isinstance(row.get('l2OperandBoundary'), dict),
        } for i, row in enumerate(functions) if isinstance(row, dict) and row.get('name') == name],
        'fragmentBoundaryPresent': isinstance(approval.get('l2FragmentOperandBoundary'), dict),
        'scalarAuthorityDecisionPresent': isinstance(approval.get('l2ScalarAuthorityDecision'), dict),
        'scope': 'original-name-join-diagnosis-not-compiler-declaration-authority',
    }


def original_layer_readiness(spec):
    """Ask original L2 authority consumer about original artifacts; no stubs."""
    from . import native_original_pipeline as route
    from .translation_attempt import load_translation_attempt_archive
    from .translation_artifact_binding import artifacts_from_report
    from .automatic_l2_operand import _authority
    run = route.check_run(spec['run']['path']); translation = d.read(run['translation']['path'])
    report = d.read(translation['report']['path']); findings = report['findings']
    archive = load_translation_attempt_archive(translation['attemptArchive']['path'])
    artifacts = artifacts_from_report(Path(translation['report']['path']), archive)
    rows = []
    attempts = {a.finding_id: a for a in archive.attempts}
    for index, finding in enumerate(findings):
        fragment = finding.get('fragment') or {}; fragment_id = fragment.get('id', '')
        finding_id = f'finding:{index}:{fragment_id}'
        artifact = artifacts.get(finding_id)
        if artifact is None: continue
        attempt = attempts.get(finding_id)
        if attempt is None or attempt.fragment_id != fragment_id:
            raise ValueError('PROGRAM_L2_ATTEMPT_BINDING_REQUIRED')
        binding_diagnostic = l2_function_binding_diagnostic(finding, report.get('functions', []))
        binding_diagnostic['reportFunctionTablePresent'] = 'functions' in report
        authority, reason = _authority(finding, report.get('functions', []), artifact)
        matches = [fn for fn in report.get('functions', [])
                   if fn.get('name') == fragment.get('enclosingFunction')]
        from .l2_execution_requirements import plan as execution_plan
        execution_requirements = execution_plan(matches[0], fragment_id) if len(matches) == 1 else None
        from .operand_permutation_proof import consume as consume_permutations, FIELD
        approval = finding.get('approvalArtifact') or {}
        permutation = {'status': 'not-supplied', 'scope': 'registered-local-proof-not-program-authority'}
        if FIELD in approval:
            try:
                permutation.update(status='verified-within-registered-contract',
                    binding=consume_permutations(approval[FIELD], fragment, approval))
            except (KeyError, TypeError, ValueError) as exc:
                permutation.update(status='invalid', detail=str(exc))
        rows.append({'fragmentId': fragment_id, 'translationArtifactIdentity': artifact.identity,
                     'entryAdmissionScope': 'legacy-scalar-entry-not-finite-typed-project-entry',
                     'authorityDiagnostic': approval.get('l2ScalarAuthorityFailure'),
                     'originalProvider': 'automatic-l2-operand-differential',
                     'authorityConsumerReady': authority is not None,
                     'authorityComplete': artifact.l2_authority_complete,
                     'reasonCode': reason, 'functionBindingDiagnostic': binding_diagnostic,
                     'executionRequirements': execution_requirements,
                     'permutationProofConsumption': permutation,
                     'scalarAuthorityReasonCodes': ((finding.get('approvalArtifact') or {})
                         .get('l2ScalarAuthorityDecision') or {}).get('reasonCodes', []),
                     'fragmentBoundaryReasonCodes': ((finding.get('approvalArtifact') or {})
                         .get('l2FragmentOperandBoundary') or {}).get('reasonCodes', []),
                     'canonicalExecutionCoverageVerified': False,
                     'l3IntentReceiptPresent': bool(finding.get('l3IntentReceipt')),
                     'l3Applicability': 'requires-original-intent-validation'})
    return {'scope': 'original-authority-consumer-readiness-not-L2-or-L3-validation', 'instances': rows}
