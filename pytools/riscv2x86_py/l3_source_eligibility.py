"""Family-specific boundary replay; persisted materializability is not authority."""
from .l3_trace_support import identity


def atomic_boundary(finding, functions, sidecar):
    from .l2_atomic_authority import validate_atomic_proof_facts, materialize_atomic_authority
    from .l2_materialization import assess_fragment_l2_materializability
    from .l2_fragment_execution import materialize_fragment_execution_authority
    from .compiler_provenance import bind_compiler_provenance
    approval = finding['approvalArtifact']
    fragment = finding['fragment']
    sequence=approval.get('l2LrscProofFacts') is not None
    if sequence:
        from .l2_lrsc_authority import validate,materialize as sequence_materialize
        validate(finding)
    else:
        validate_atomic_proof_facts(approval.get('l2AtomicProofFacts'), approval, fragment['id'])
    if not isinstance(functions, list):
        raise ValueError('L3_ATOMIC_COMPILER_SNAPSHOT_REQUIRED')
    compiler = fragment['compilerFragmentAuthority']
    matches = [f for f in functions if f.get('functionId') == compiler['functionIdentity']]
    if len(matches) != 1:
        raise ValueError('L3_ATOMIC_COMPILER_FUNCTION_AMBIGUOUS')
    function = matches[0]
    if (function.get('sourceDigest') != compiler['sourceDigest']
            or finding.get('sourceDigest') != compiler['sourceDigest']):
        raise ValueError('L3_ATOMIC_COMPILER_SOURCE_MISMATCH')
    rebuilt = (sequence_materialize if sequence else materialize_atomic_authority)(finding, functions, sidecar.producer.producer_binary_digest)
    if rebuilt is None or rebuilt.to_dict() != sidecar.to_dict():
        raise ValueError('L3_ATOMIC_AUTHORITY_REPLAY_MISMATCH')
    bind_compiler_provenance(fragment, rebuilt)
    decision = assess_fragment_l2_materializability(finding, sidecar=rebuilt)
    if not decision.executable:
        raise ValueError('L3_ATOMIC_MATERIALIZATION_INCOMPLETE:'+','.join(decision.reason_codes))
    # Reproduce even the incomplete generic boundary, for its program/function
    # identity. Its scalar candidate verdict cannot overrule dedicated atomic
    # expression authority; its identities cannot be accepted without replay.
    program_id = str(function.get('programId') or identity({
        'schemaVersion': 'riscv2x86.automatic-program.v1',
        'producerDigest': sidecar.producer.producer_binary_digest}))
    boundaries, _, _ = materialize_fragment_execution_authority([finding], function, program_id)
    boundary = boundaries.get(fragment['id'])
    if boundary is None or boundary.to_dict() != approval.get('l2FragmentOperandBoundary'):
        raise ValueError('L3_ATOMIC_PROGRAM_BOUNDARY_REPLAY_MISMATCH')
    return boundary.to_dict()
