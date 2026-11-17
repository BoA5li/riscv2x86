"""Closed evidence rules over ORIGINAL checked diagnostic subgoals.

Callers first rederive progress/observations with the original checkers. These
rules never trust approval booleans or turn process agreement into L1. Missing
proof producers remain named prerequisites; only actual checked subclaims enter
this graph. Adding a full-proof producer requires code and adversarial tests.
"""
from .project_build_records import identity

RULES = {
    'THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED': ('recorded-project-builds', 'three-context-semantic-refinement'),
    'ACTUAL_MACHINE_ABI_REQUIRED': ('bounded-machine-inventory', 'complete-machine-call-and-exit-contract'),
    'INTERNAL_OBJECT_ACCESS_PROOF_REQUIRED': ('code-bound-object-lifetime-alias-and-access-proof',),
    'DEPENDENCY_CALL_AND_EFFECT_CLOSURE_REQUIRED': ('recorded-project-builds', 'actual-call-selection-and-effects'),
    'SOURCE_TARGET_TEST_INPUT_RELATION_REQUIRED': ('cross-ISA-input-domain-relation',),
    'NATURAL_RUN_IMAGE_IDENTITY_REQUIRED': ('natural-run-image-events-bound-to-artifacts',),
    'OUTPUT_AND_TERMINATION_RELATION_REQUIRED': ('selected-process-output-and-exit-agreement',
        'cross-ISA-input-domain-relation', 'output-effects-and-termination-domain'),
    'CANONICAL_INSTANCE_INSTRUCTION_COVERAGE_REQUIRED': ('canonical-instance-region-and-execution-events',),
    'PROGRAM_L2_AUTHORITY_REQUIRED': ('original-L2-authority-and-applicable-effects',),
    'INDEPENDENT_PROGRAM_AUDIT_REQUIRED': ('independent-original-program-semantic-audit',),
}


def consume(project_identity, facts):
    """Consume already checked finite diagnostic facts; keep full scope explicit."""
    scope = {'projectEvaluationIdentity': project_identity,
             'selectedCaseIndices': list(facts.get('selectedCaseIndices', [])),
             'plannedCaseCount': facts.get('plannedCaseCount'),
             'scope': 'checked-diagnostic-subclaims-not-program-acceptance'}
    scope_id = identity(scope)
    claims = []
    def claim(kind):
        body = {'kind': kind, 'scopeIdentity': scope_id,
                'status': 'verified-within-diagnostic-scope'}
        claims.append(dict(body, claimIdentity=identity(body)))
    completed = set(facts.get('completedStages', []))
    if {'source-build', 'target-build'} <= completed:
        claim('recorded-project-builds')
    if 'machine-inventory' in completed:
        claim('bounded-machine-inventory')
    observations = facts.get('observations', [])
    if observations and all(
        isinstance(o, dict) and o.get('cases')
        and o.get('mismatches') == []
        and o.get('executionBudgetFailed') is False
        and o.get('exitOutsideDeclaredDomain') is False
        and o.get('loaderListFailed') is False
        and all(c.get('mismatches') == [] for c in o['cases'])
        for o in observations
    ):
        claim('selected-process-output-and-exit-agreement')
    verified = {c['kind'] for c in claims}
    obligations = []
    for reason, required in RULES.items():
        missing = [kind for kind in required if kind not in verified]
        # At least one full-proof prerequisite is intentionally not produced by
        # the currently registered diagnostic checkers for every global rule.
        obligations.append({'reasonCode': reason,
            'status': 'verified' if not missing else 'partial-evidence' if verified.intersection(required) else 'producer-required',
            'checkedSubclaims': [kind for kind in required if kind in verified],
            'missingProofFacts': missing, 'fullObligationDischarged': not missing})
    return {'schemaVersion': 'riscv2x86.program-claim-consumption.v1',
            'scope': scope, 'scopeIdentity': scope_id, 'claims': claims,
            'obligations': obligations, 'semanticApproval': False,
            'productionAcceptanceComplete': False}
