"""Explicit execution-domain assumptions for the shipped local SMC protocol.

These are externally supplied environment facts, not automatically discovered
platform guarantees. Their applicability must also be checked by the runner.
"""
from .semantic_content import semantic_identity
import re
from collections.abc import Mapping
from types import MappingProxyType

def freeze_domain(value):
    return MappingProxyType({k: freeze_domain(v) if isinstance(v, Mapping) else v for k,v in value.items()})


SCHEMA = 'riscv2x86.instruction-stream-domain.v1'
FIELDS = {'schemaVersion','sourceDigest','fragmentId','targetEnvironmentId','targetCpuProfileId',
          'sourceExecution','targetExecution','memoryDomain','coverage','domainIdentity'}
SHA = re.compile(r'sha256:[0-9a-f]{64}')


def validate_domain(value, *, fragment_id, environment_id, cpu_profile, source_digest=None):
    if not isinstance(value, Mapping) or set(value)!=FIELDS or value['schemaVersion']!=SCHEMA:
        raise ValueError('ISS_DOMAIN_SCHEMA_INVALID')
    if value['domainIdentity']!=semantic_identity({k:v for k,v in value.items() if k!='domainIdentity'}):
        raise ValueError('ISS_DOMAIN_IDENTITY_MISMATCH')
    if (value['fragmentId']!=fragment_id or value['targetEnvironmentId']!=environment_id
            or value['targetCpuProfileId']!=cpu_profile):
        raise ValueError('ISS_DOMAIN_BINDING_MISMATCH')
    if not isinstance(value['sourceDigest'],str) or SHA.fullmatch(value['sourceDigest']) is None:
        raise ValueError('ISS_DOMAIN_SOURCE_INVALID')
    if source_digest is not None and source_digest!=value['sourceDigest']:
        raise ValueError('ISS_DOMAIN_SOURCE_MISMATCH')
    if value['coverage']!='all_prior_visible_instruction_stores_on_bound_hart':
        raise ValueError('ISS_DOMAIN_COVERAGE_UNSUPPORTED')
    for side in ('sourceExecution','targetExecution'):
        execution=value[side]
        if (not isinstance(execution,Mapping) or set(execution)!={'runnerIdentity','logicalHartIdentity','pinnedCpu','threadCount'}
                or not isinstance(execution['runnerIdentity'],str) or SHA.fullmatch(execution['runnerIdentity']) is None
                or not isinstance(execution['logicalHartIdentity'],str) or not execution['logicalHartIdentity']
                or type(execution['pinnedCpu']) is not int or execution['pinnedCpu']<0
                or type(execution['threadCount']) is not int or execution['threadCount']!=1):
            raise ValueError('ISS_DOMAIN_EXECUTION_UNSUPPORTED')
    if value['sourceExecution']['logicalHartIdentity']!=value['targetExecution']['logicalHartIdentity']:
        raise ValueError('ISS_DOMAIN_HART_RELATION_MISMATCH')
    memory=value['memoryDomain']
    expected={'kind':'ordinary_cacheable_coherent_memory',
              'targetProtocol':'x86-local-serializing-smc-v1',
              'buildContract':'automatic-gcc-separate-tu-no-lto-v1'}
    if memory!=expected:
        raise ValueError('ISS_DOMAIN_MEMORY_MODEL_UNSUPPORTED')
    return value
