"""Consume checked API evidence within its exact finite function/domain scope.

Uses the original checker and comparator result. Never transfers an API test's
input relation to an official test executable, other inputs, or build cells.
"""
from pathlib import Path
from . import native_captured_deployment as d
from . import native_original_api as api
from .program_claim_consumption import RULES
from .verification_session import measured


def inspect(path):
    return inspect_with_result(path)[0]


@measured('native_api_evidence.checked_consumption')
def inspect_with_result(path):
    """Check once and return both views; never accepts caller-asserted validity.

    No checked-result cache survives this call. Independent CLI checks start
    again with live inputs, tool identities and dependency verification.
    """
    reference = d.snapshot(path)
    inputs_ref = d.snapshot(Path(path).resolve().parent / 'inputs.json')
    result = api.check(path)
    inputs = d.read(inputs_ref['path'])
    request = d.read(inputs['request']['path'])
    scope = {'project': inputs['spec']['digest'], 'function': result['function']['functionBindingIdentity'],
             'domain': d.identity(request['domain']), 'apiInputIdentity': result['apiInputIdentity'],
             'caseCount': result['caseCount'], 'artifacts': result['artifacts'],
             'scope': 'finite-api-under-declared-preconditions-not-official-test-or-program-scope'}
    observations = result['processObservationStatus']
    claims = [
        {'kind': 'finite-typed-input-and-alias-relation', 'status': 'checked-under-declared-preconditions'},
        {'kind': 'entry-object-construction', 'status': 'checked-under-declared-preconditions'},
        {'kind': 'compiler-declaration-witnesses', 'status': 'checked'},
        {'kind': 'declared-region-output-and-termination', 'status': observations},
        {'kind': 'link-time-function-definition-ownership',
         'status': 'checked' if result['bodyLinkAttributionComplete'] else 'inconclusive'},
        {'kind': 'link-attributed-finite-process-observation', 'status': result['linkAttributedObservationStatus']},
    ]
    d.verify_snapshot(reference)
    d.verify_snapshot(inputs_ref)
    d.verify_snapshot(inputs['spec']); d.verify_snapshot(inputs['request'])
    consumption = {'schemaVersion': 'riscv2x86.finite-api-evidence-consumption.v1',
            'evidence': reference, 'scope': scope, 'scopeIdentity': d.identity(scope), 'claims': claims,
            'programObligations': [{'reasonCode': reason, 'requiredFacts': list(required),
                                    'fullObligationDischarged': False} for reason, required in RULES.items()],
            'formalValidationPerformed': False, 'semanticApproval': False, 'productionAcceptanceComplete': False}
    return consumption, result
