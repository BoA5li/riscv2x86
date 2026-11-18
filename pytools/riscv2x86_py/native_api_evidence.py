"""Consume checked API evidence within its exact finite function/domain scope.

Uses the original checker and comparator result. Never transfers an API test's
input relation to an official test executable, other inputs, or build cells.
"""
from pathlib import Path
from . import native_captured_deployment as d
from . import native_original_api as api
from .program_claim_consumption import RULES


def inspect(path):
    reference = d.snapshot(path); result = api.check(path)
    inputs = d.read(Path(path).resolve().parent / 'inputs.json')
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
    ]
    d.verify_snapshot(reference)
    return {'schemaVersion': 'riscv2x86.finite-api-evidence-consumption.v1',
            'evidence': reference, 'scope': scope, 'scopeIdentity': d.identity(scope), 'claims': claims,
            'programObligations': [{'reasonCode': reason, 'requiredFacts': list(required),
                                    'fullObligationDischarged': False} for reason, required in RULES.items()],
            'formalValidationPerformed': False, 'semanticApproval': False, 'productionAcceptanceComplete': False}
