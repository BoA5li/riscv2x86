"""Case/layer environment identity for the restricted controlled read stream.

The identity binds the complete runner command, approved contract and observer.
It deliberately cannot be reported as the native QEMU/TSC environment. Neither
this profile nor an arbitrary finite trajectory supplies a legal physical clock
model (frequency, elapsed time, inter-hart synchronization).
"""
from .semantic_content import semantic_identity
from .time_trace_contract import validate_time_contract

CLAIMS = {
    'profile': 'controlled-time-read-trace.v1',
    'architecture': 'isolated-time-read-result-in-controlled-model',
    'compilerShell': 'approved-bounded-no-argument-return-function',
    'environmentRelation': 'same-index-same-external-value-modulo-2^64',
    'fullArchitecturalTimeClock': 'not_verified',
    'nativeTime': 'not_verified',
    'microarchitecture': 'not_verified',
}


def environment_binding(config, trace):
    validate_time_contract(trace)
    payload = {'schemaVersion': 'riscv2x86.controlled-time-environment.v1',
        'timeContractIdentity': trace['contractIdentity'],
        'sourceDigest': trace['sourceDigest'], 'fragmentId': trace['fragmentId'],
        'sourceBackendIdentity': trace['sourceBackend']['backendIdentity'],
        'sourceBinaryDigest': trace['sourceBackend']['binaryDigest'],
        'sourceRunner': list(config['sourceRunner']),
        'targetMechanism': trace['targetMechanism'],
        'observerIdentity': config['observerDigest'], 'claims': dict(CLAIMS)}
    return {**payload, 'environmentProfileIdentity': semantic_identity(payload)}


def environment_id(binding):
    return 'controlled-time-read-trace:' + binding['environmentProfileIdentity']


def provider_environment(provider):
    """Replay the existing approval, not just a provider's environment label."""
    import json
    from pathlib import Path
    from types import SimpleNamespace
    from .time_trace_runner import load_config, load_finding
    from .time_trace_harness import digest
    import shutil
    config = load_config(provider['config'])
    ids = provider['fragmentIds']
    report = json.loads(Path(config['approvalPath']).read_text())
    matches = [f for f in report['findings'] if (f['fragment'].get('id') or f['fragment'].get('fragmentId')) in ids]
    if len(ids) != 1 or len(matches) != 1:
        raise ValueError('TIME_ENVIRONMENT_FRAGMENT_AMBIGUOUS')
    _, _, trace = load_finding(config['approvalPath'], SimpleNamespace(
        fragment_id=ids[0], proof_identity=matches[0]['approvalArtifact']['proofIdentity']))
    if digest(shutil.which(config['sourceRunner'][0]) or config['sourceRunner'][0]) != trace['sourceBackend']['binaryDigest']:
        raise ValueError('TIME_SOURCE_BINARY_MISMATCH')
    return environment_binding(config, trace)


def audit_case_environment(case, records=()):
    """Cross-check retained per-layer execution against its outer case report."""
    import json
    from .local_sync_environment import audit_case_environment as audit_local_sync
    audit_local_sync(case,records)
    from .time_trace_runner import RESULT, validate_persisted_result
    outer = (case.get('targetEnvironment') or {}).get('environmentId')
    for attempt in case.get('attempts', []):
        for layer in (attempt.get('validation') or {}).get('layers', []):
            if layer.get('level') != 'L1':
                continue
            try:
                detail = json.loads(layer.get('detail', ''))
            except (ValueError, TypeError):
                continue
            if isinstance(detail, dict) and detail.get('schemaVersion') == RESULT:
                validate_persisted_result(detail)
                if outer != detail['environmentId'] or layer['evidenceIdentity'] != detail['evidenceIdentity']:
                    raise ValueError('TIME_CASE_LAYER_ENVIRONMENT_MISMATCH')
    for entry in records:
        envelope = entry.get('envelope', entry)
        if envelope['providerDefinition']['validatorType'] != 'controlled-time-validation':
            continue
        detail = json.loads(envelope['normalizedResult']['detail'])
        if detail.get('schemaVersion') != RESULT:  # partial evidence grants no verification
            if envelope['normalizedResult']['status'] == 'verified':
                raise ValueError('TIME_CASE_EXECUTION_EVIDENCE_MISSING')
            continue
        validate_persisted_result(detail)
        expected = environment_binding(envelope['providerDefinition']['config'], detail['timeContract'])
        if outer != environment_id(expected) or detail['executionEnvironment'] != expected:
            raise ValueError('TIME_CASE_PROVIDER_ENVIRONMENT_MISMATCH')
