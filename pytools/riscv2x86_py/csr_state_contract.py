"""Explicit logical scratch-state assumptions, independent of counter clocks."""
import re
from .route_authority import content_identity

SCHEMA='riscv2x86.csr-logical-state-contract.v1'
CONTEXT_EXPRESSION='rv2x86_csr_bound_context_v1()'
ABI='riscv2x86.logical-scratch.checked.v1'
_SHA=re.compile(r'sha256:[0-9a-f]{64}')
FIELDS={'schemaVersion','targetStateObjectId','stateLifetimeId','initialStateIdentity',
    'sourceExecutionIdentity','targetEnvironmentIdentity','ownership','concurrency',
    'contextAbi','contextExpression','contractIdentity'}


def validate_state_contract(value,*,state_object=None,lifetime=None,source_execution=None,target_environment=None):
    if (not isinstance(value,dict) or set(value)!=FIELDS or value['schemaVersion']!=SCHEMA
            or value['contractIdentity']!=content_identity({k:v for k,v in value.items() if k!='contractIdentity'})):
        raise ValueError('CSR_STATE_CONTRACT_SCHEMA_OR_IDENTITY_INVALID')
    for field in ('initialStateIdentity','sourceExecutionIdentity','targetEnvironmentIdentity'):
        if not isinstance(value[field],str) or _SHA.fullmatch(value[field]) is None:
            raise ValueError('CSR_STATE_CONTRACT_EVIDENCE_IDENTITY_INVALID')
    if any(not isinstance(value[k],str) or not value[k] for k in ('targetStateObjectId','stateLifetimeId')):
        raise ValueError('CSR_STATE_CONTRACT_OBJECT_OR_LIFETIME_INVALID')
    if (value['ownership']!='one-logical-hart-per-bound-thread'
            or value['concurrency']!='single-owner-no-concurrent-access'
            or value['contextAbi']!=ABI or value['contextExpression']!=CONTEXT_EXPRESSION):
        raise ValueError('CSR_STATE_CONTRACT_DOMAIN_UNSUPPORTED')
    for actual,expected in ((value['targetStateObjectId'],state_object),(value['stateLifetimeId'],lifetime),
            (value['sourceExecutionIdentity'],source_execution),(value['targetEnvironmentIdentity'],target_environment)):
        if expected is not None and actual!=expected:raise ValueError('CSR_STATE_CONTRACT_BINDING_MISMATCH')
    return value
