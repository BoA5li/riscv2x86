"""Checked, scoped evidence coverage over the ORIGINAL diagnostic campaign.

This is an evidence-consumption inventory, never a new approval algorithm.
Only the existing progress checker admits inputs. Present producers establish
bounded subgoals; none is registered as a full ABI/object/coverage certificate.
"""
from pathlib import Path
from . import native_captured_deployment as d
from . import native_project_diagnostic as diagnostic
from .program_validation_obligations import _PROJECT_PHASES
from .verification_session import measured

# Stable obligations, not corpus names, source strings or function heuristics.
_PRODUCERS = {
    'THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED': 'checked-source-candidate-producer-context-relation',
    'ACTUAL_MACHINE_ABI_REQUIRED': 'machine-calling-convention-and-applicable-exit-checker',
    'INTERNAL_OBJECT_ACCESS_PROOF_REQUIRED': 'scoped-object-lifetime-alias-and-access-checker',
    'DEPENDENCY_CALL_AND_EFFECT_CLOSURE_REQUIRED': 'actual-link-call-target-and-effects-checker',
    'SOURCE_TARGET_TEST_INPUT_RELATION_REQUIRED': 'declared-input-domain-and-cross-ISA-value-relation',
    'NATURAL_RUN_IMAGE_IDENTITY_REQUIRED': 'natural-execution-image-and-loader-event-checker',
    'OUTPUT_AND_TERMINATION_RELATION_REQUIRED': 'original-comparator-under-closed-input-and-effect-contracts',
    'CANONICAL_INSTANCE_INSTRUCTION_COVERAGE_REQUIRED': 'canonical-instance-region-and-runtime-event-checker',
    'PROGRAM_L2_AUTHORITY_REQUIRED': 'original-L2-provider-and-authority-consumer',
    'INDEPENDENT_PROGRAM_AUDIT_REQUIRED': 'independent-original-program-audit',
}

_STAGE_OBLIGATIONS = {
    'runtime-binding': ('DEPENDENCY_CALL_AND_EFFECT_CLOSURE_REQUIRED', 'NATURAL_RUN_IMAGE_IDENTITY_REQUIRED'),
    'entry-abi': ('THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED', 'ACTUAL_MACHINE_ABI_REQUIRED'),
    'legal-objects-inputs': ('INTERNAL_OBJECT_ACCESS_PROOF_REQUIRED', 'SOURCE_TARGET_TEST_INPUT_RELATION_REQUIRED'),
    'output-termination': ('OUTPUT_AND_TERMINATION_RELATION_REQUIRED',),
    'program-validation': tuple(_PROJECT_PHASES),
}


def _derive(state, facts):
    """Consume only a progress state already rederived by diagnostic.check."""
    cp = state['checkpoints']
    references = {key: value for key, value in cp.items()}
    project_identity = None
    if 'preparation' in cp:
        prefix = d.read(cp['preparation']['path'])['facts']['prefixCheckpoints']
        references.update({'preparation/' + key: value for key, value in prefix.items()})
        spec = d.read(prefix['project']['path'])
        project_identity = spec['projectEvaluationIdentity']
        if len(spec['gaps']) != len(_PROJECT_PHASES) or set(spec['gaps']) != set(_PROJECT_PHASES):
            raise ValueError('LEDGER_FULL_PROJECT_OBLIGATION_POLICY_REQUIRED')
    observations = facts['observations']
    subgoals = []
    def subgoal(kind, evidence, scope):
        subgoals.append({'kind': kind, 'evidenceStages': evidence, 'scope': scope})
    if 'preparation' in cp:
        subgoal('original-candidate-and-source-guard-acquisition', ['preparation'],
                'original-translation-and-typed-source-guards-not-machine-survival')
    builds = [side + '-build' for side in ('source', 'target') if side + '-build' in cp]
    if builds:
        subgoal('checked-project-materialization', builds,
                'recorded-builds-not-the-formal-18-cell-L0-matrix')
    if 'machine-inventory' in cp:
        subgoal('bounded-machine-inventory', ['machine-inventory'],
                'symbol-and-linear-decode-facts-not-complete-ABI-object-or-CFG-proof')
    if observations:
        subgoal('bounded-process-observations', [s for s in cp if s.startswith('case-')],
                'exact-selected-process-output-and-exit-not-full-L1-or-input-relation')
    rows = []
    for reason, phase in _PROJECT_PHASES.items():
        relevant = []
        if reason in ('THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED', 'DEPENDENCY_CALL_AND_EFFECT_CLOSURE_REQUIRED'):
            relevant = builds
        elif reason in ('ACTUAL_MACHINE_ABI_REQUIRED', 'INTERNAL_OBJECT_ACCESS_PROOF_REQUIRED'):
            relevant = ['machine-inventory'] if 'machine-inventory' in cp else []
        elif reason == 'OUTPUT_AND_TERMINATION_RELATION_REQUIRED':
            relevant = [s for s in cp if s.startswith('case-')]
        elif reason in ('PROGRAM_L2_AUTHORITY_REQUIRED', 'CANONICAL_INSTANCE_INSTRUCTION_COVERAGE_REQUIRED'):
            relevant = ['preparation'] if 'preparation' in cp else []
        rows.append({
            'reasonCode': reason, 'phase': phase,
            'projectEvaluationIdentity': project_identity,
            'status': 'partial-evidence' if relevant else 'producer-required',
            'relatedEvidenceStages': relevant,
            'requiredConsumer': _PRODUCERS[reason],
            'fullObligationDischarged': False,
        })
    excluded = (facts.get('instanceApplicability') or {}).get('sourceExcludedInstanceCount', 0)
    actions = ['produce-and-check-scoped-contracts-before-formal-program-approval']
    if excluded:
        actions.insert(0, 'retain-source-excluded-results-and-find-a-supported-executable-configuration-or-instance')
    if facts['machineFactGaps']:
        actions.append('resolve-reported-machine-inventory-gaps-without-upgrading-linear-decode-to-ABI-proof')
    readiness = facts.get('originalLayerReadiness')
    if readiness and any(not row['authorityConsumerReady'] for row in readiness.get('instances', [])):
        actions.append('repair-original-L2-compiler-instance-and-value-flow-binding-from-diagnostics')
    from .program_claim_consumption import consume
    consumption = consume(project_identity, {**facts, 'completedStages': list(cp)})
    by_reason = {r['reasonCode']: r for r in consumption['obligations']}
    for row in rows:
        derived = by_reason[row['reasonCode']]
        row.update(status=derived['status'], fullObligationDischarged=derived['fullObligationDischarged'],
                   checkedSubclaims=derived['checkedSubclaims'], missingProofFacts=derived['missingProofFacts'])
    return {
        'schemaVersion': 'riscv2x86.checked-project-evidence-ledger.v1',
        'projectEvaluationIdentity': project_identity,
        'evidenceReferences': references, 'checkedSubgoals': subgoals, 'claimConsumption': consumption,
        'obligations': rows,
        'stageCoverage': {stage: {
            'status': 'inconclusive' if any(not by_reason[r]['fullObligationDischarged'] for r in required) else 'verified',
            'unresolvedObligations': [r for r in required if not by_reason[r]['fullObligationDischarged']],
        } for stage, required in _STAGE_OBLIGATIONS.items()},
        'plannedCaseCount': facts['plannedCaseCount'],
        'selectedCaseIndices': facts['selectedCaseIndices'],
        'unselectedCaseIndices': facts['unselectedCaseIndices'],
        'observedCaseCount': facts['observedCaseCount'],
        'boundedObservations': observations,
        'instanceApplicability': facts.get('instanceApplicability'),
        'originalLayerReadiness': readiness,
        'nextActions': actions, 'fullProofConsumersConnected': [],
        'formalValidationPerformed': False, 'semanticApproval': False,
        'productionAcceptanceComplete': False,
        'scope': 'checked-diagnostic-evidence-coverage-not-L0-L1-L2-L3-acceptance',
    }


@measured('project-evidence-ledger.inspect')
def inspect(path):
    ref = d.snapshot(path)
    from . import native_original_api
    from . import native_api_campaign
    if d.read(path).get('schemaVersion') == native_api_campaign.RESULT:
        value = native_api_campaign.check(path)
        d.verify_snapshot(ref)
        return dict(value['evidenceConsumption'], checkedCampaign=ref,
                    originalProjectL2=value['originalProjectL2'],
                    originalL2Instances=value['originalL2Instances'])
    if d.read(path).get('schemaVersion') == native_original_api.SCHEMA:
        from .native_api_evidence import inspect as inspect_api
        return inspect_api(path)
    state = diagnostic.check_progress(path)
    result = _derive(state, diagnostic.facts(state))
    d.verify_snapshot(ref)
    for snapshot in result['evidenceReferences'].values():
        d.verify_snapshot(snapshot)
    return dict(result, checkedProgress=ref)
