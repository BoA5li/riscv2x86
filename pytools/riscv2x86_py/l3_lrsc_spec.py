"""Sequence-only capability; never grants direct-AMO observation authority."""
from .l3_atomic_spec import samples,harness,parse_samples
CAPABILITY='qemu-attributed-lrsc-sequence-v1'
LIMITS=['source-target-raw-access-and-retry-count-equality-not-claimed','completion-state-abstraction-from-approved-sequence-proof','bounded-completed-lrsc-and-cas-paths','failed-attempt-register-values-not-observed',
        'concurrent-linearizability-and-physical-memory-order-not-measured',
        'no-individual-termination-or-progress-proof','boundary-value-samples-not-exhaustive-input-proof',
        'compiler-proven-dead-next-status-only','ordinary-aligned-memory-only',
        'outside-fragment-effects-not-compared','physical-cache-timing-prediction-speculation-not-claimed']

def spec(finding,functions):
    if not (finding.get('approvalArtifact') or {}).get('l2LrscProofFacts'):
        raise ValueError('L3_LRSC_APPROVED_SEQUENCE_REQUIRED')
    from .l3_atomic_spec import spec as common
    from .l3_trace_support import require_json_document
    return require_json_document(common(finding,functions,_sequence=True),
                                 'L3_LRSC_SPEC_JSON_INVALID')
