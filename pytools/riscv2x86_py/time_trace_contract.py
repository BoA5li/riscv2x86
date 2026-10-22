"""Strict TIME equivalence under an explicit common external event trajectory.

This is not a claim about the unmodified QEMU/TSC time domain. The environment
owner chooses the trajectory. Runners must consume every read and check the
actual read site, result and event count; independent clock samples cannot
satisfy this contract. Hashes bind reviewed evidence, not its truth.
"""
import re
from collections.abc import Mapping
from .semantic_content import semantic_identity, semantic_payload
from .instruction_stream_domain import freeze_domain

SCHEMA = 'riscv2x86.controlled-time-contract.v1'
MECHANISM = 'qemu-linux-user-controlled-time-v1'
TARGET = 'rv2x86.controlled-time.checked.v1'
QEMU_BASE = 'b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56'
# Exact upstream target/riscv/csr.c at QEMU_BASE after the registered patch.
# This checks the implementation, independently of a rehashed manifest.
PATCHED_CSR_DIGEST = 'sha256:7f33be50f03c6bf8bbdab779e027bf95fb2f5e03a2f8de037181a92e363b5d81'
FIELDS = {'schemaVersion', 'sourceDigest', 'fragmentId', 'sourceExecutionIdentity',
          'targetEnvironmentIdentity', 'sourceBackend', 'targetMechanism', 'unit',
          'readRelation', 'concurrency', 'transportIsolation', 'ordering', 'failurePolicy', 'review', 'contractIdentity'}
SHA = re.compile(r'sha256:[0-9a-f]{64}')


def digest_ok(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def validate_backend(value):
    fields = {'schemaVersion', 'mechanism', 'baseCommit', 'sourceDigest',
              'traceHeaderDigest', 'binaryDigest', 'buildIdentity', 'backendIdentity'}
    if (not isinstance(value, Mapping) or set(value) != fields
            or value['schemaVersion'] != 'riscv2x86.controlled-time-backend.v1'
            or value['mechanism'] != MECHANISM or value['baseCommit'] != QEMU_BASE
            or any(not digest_ok(value[k]) for k in
                   ('sourceDigest', 'traceHeaderDigest', 'binaryDigest', 'buildIdentity'))
            or value['backendIdentity'] != semantic_identity({k:v for k,v in value.items() if k != 'backendIdentity'})):
        raise ValueError('TIME_SOURCE_BACKEND_INVALID')
    if value['sourceDigest'] != PATCHED_CSR_DIGEST:
        raise ValueError('TIME_SOURCE_IMPLEMENTATION_MISMATCH')
    # A stale or foreign trace implementation must not acquire this protocol.
    from pathlib import Path
    from hashlib import sha256
    header = Path(__file__).resolve().parents[2] / 'runtime/include/riscv2x86_time_trace.h'
    if value['traceHeaderDigest'] != 'sha256:' + sha256(header.read_bytes()).hexdigest():
        raise ValueError('TIME_SOURCE_TRACE_IMPLEMENTATION_MISMATCH')
    return value


def validate_time_contract(value, *, source_digest=None, fragment_id=None,
                           source_execution=None, target_environment=None):
    if (not isinstance(value, Mapping) or set(value) != FIELDS or value['schemaVersion'] != SCHEMA
            or value['contractIdentity'] != semantic_identity({k:v for k,v in value.items() if k != 'contractIdentity'})):
        raise ValueError('TIME_CONTRACT_SCHEMA_OR_IDENTITY_INVALID')
    for name in ('sourceDigest', 'sourceExecutionIdentity', 'targetEnvironmentIdentity'):
        if not digest_ok(value[name]): raise ValueError('TIME_CONTRACT_BINDING_INVALID')
    if not isinstance(value['fragmentId'], str) or not value['fragmentId']:
        raise ValueError('TIME_CONTRACT_FRAGMENT_REQUIRED')
    for name, expected in (('sourceDigest', source_digest), ('fragmentId', fragment_id),
            ('sourceExecutionIdentity', source_execution), ('targetEnvironmentIdentity', target_environment)):
        if expected is not None and value[name] != expected:
            raise ValueError('TIME_CONTRACT_BINDING_MISMATCH:' + name)
    validate_backend(value['sourceBackend'])
    expected = {'targetMechanism': TARGET, 'unit': 'opaque-64-bit-time-ticks',
        'readRelation': 'same-index-same-external-value-modulo-2^64',
        'concurrency': 'single-thread-no-asynchronous-readers',
        'transportIsolation':'reserved-trace-files-no-program-alias-no-resource-observation',
        'ordering': 'logical-read-events-only-no-wall-time-or-memory-order-claim',
        'failurePolicy': 'execution-failure-not-counter-value'}
    if any(value[k] != v for k,v in expected.items()):
        raise ValueError('TIME_CONTRACT_DOMAIN_UNSUPPORTED')
    review = value['review']
    if (not isinstance(review, Mapping) or set(review) != {'owner', 'basis', 'evidenceIdentity'}
            or not isinstance(review['owner'], str) or not review['owner'].strip()
            or review['basis'] != 'explicit-controlled-environment-selection'
            or not digest_ok(review['evidenceIdentity'])):
        raise ValueError('TIME_CONTRACT_EXPLICIT_SELECTION_REQUIRED')
    return freeze_domain(semantic_payload(value))


def validate_counter_payload(counter):
    trace = counter.get('trace_relation')
    validate_time_contract(trace)
    expected = {'relation_kind':'architectural-equivalence', 'frequency_hz':None,
        'scale_numerator':1, 'scale_denominator':1, 'monotonicity':'external-trajectory-modulo-2^64',
        'wraparound_bits':64, 'scope':'one-bound-logical-read-stream',
        'migration_behavior':'no-physical-time-dependence',
        'serialization':'logical-read-events-only',
        'target_observation_mechanism':TARGET, 'error_bound_ticks':0,
        'availability_policy':'explicit-controlled-backend-required',
        'trap_policy':'execution-failure-not-counter-value', 'complete':True}
    if any(counter.get(k) != v for k,v in expected.items()):
        raise ValueError('TIME_COUNTER_MODEL_MISMATCH')
    if counter.get('source_epoch') != trace['contractIdentity'] or counter.get('target_epoch') != trace['contractIdentity']:
        raise ValueError('TIME_COUNTER_EPOCH_MISMATCH')
    return trace


def controlled_execution_facts(*, fragment_id, backend, privilege_spec, extensions):
    """Complete only for the isolated user TIME reader, never a system model."""
    validate_backend(backend)
    from .privileged_execution_sidecar import (PrivilegedExecutionFacts,
        CsrAccessPolicyFacts, SourceExecutionProfile, TargetExecutionMode,
        SourcePrivilegeMode, UnknownCsrAccessDisposition, USER_COUNTER_EXECUTION_SCHEMA)
    return PrivilegedExecutionFacts(fragment_id=fragment_id,
        source_execution_profile=SourceExecutionProfile.RISCV_USER_PROCESS,
        target_execution_mode=TargetExecutionMode.X86_USER_PROCESS,
        source_privilege_spec_version=privilege_spec.removeprefix("riscv-privileged-"), source_isa_extensions=tuple(sorted(set(extensions))),
        initial_privilege_mode=SourcePrivilegeMode.U,
        csr_access_policy=CsrAccessPolicyFacts('controlled-time-read-access:'+backend['backendIdentity'],
            ('riscv.csr.time',),(),UnknownCsrAccessDisposition.TRAP,True),
        target_runtime_contract_set_id=TARGET,complete=True,missing_fact_codes=(),
        provenance='explicit-controlled-time-backend:'+backend['backendIdentity'],
        schema_version=USER_COUNTER_EXECUTION_SCHEMA,
        user_counter_backend_identity=backend['backendIdentity'])
