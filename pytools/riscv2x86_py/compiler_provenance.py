"""Validate compiler closure against the canonical operands actually emitted."""
from .compiler_fragment_closure import validate_closed_compiler_fragment_candidate
from .l2_evidence_reader import _identity
from .compiler_operand_type import compiler_operand_type_from_dict


def bind_compiler_provenance(fragment, sidecar):
    authority = fragment.get('compilerFragmentAuthority')
    if not authority:
        return None  # Legacy/manual entry points have no production compiler envelope.
    unsigned = {k: v for k, v in authority.items() if k != 'authorityIdentity'}
    if authority.get('authorityIdentity') != _identity(unsigned):
        raise ValueError('COMPILER_AUTHORITY_IDENTITY_MISMATCH')
    candidate = authority['candidate']
    validate_closed_compiler_fragment_candidate(candidate)
    key = candidate['fragmentBindingKey']
    if (authority.get('schemaVersion') not in {'riscv2x86.compiler-fragment-authority.v1',
            'riscv2x86.compiler-fragment-authority.v2'} or
            authority.get('targetTriple') != 'riscv64-linux-gnu' or
            authority['fragmentBindingKey'] != key or
            key['sourceDigest'] != authority['sourceDigest'] or
            key['functionIdentity'] != authority['functionIdentity']):
        raise ValueError('COMPILER_AUTHORITY_SOURCE_BINDING_MISMATCH')
    expected_candidate = _identity({
        'schemaVersion': 'riscv2x86.compiler-fragment-binding-key.v2', **key})
    if candidate.get('candidateIdentity') != expected_candidate:
        raise ValueError('COMPILER_AUTHORITY_CANDIDATE_IDENTITY_INVALID')
    binding = fragment.get('compilerFragmentBinding')
    if binding and binding.get('candidateIdentity') != candidate['candidateIdentity']:
        raise ValueError('COMPILER_AUTHORITY_CANDIDATE_MISMATCH')
    fragment_id = fragment.get('fragmentId') or fragment.get('id')
    if authority['fragmentId'] != fragment_id or sidecar.fragment_id != fragment_id:
        raise ValueError('COMPILER_AUTHORITY_FRAGMENT_MISMATCH')
    bindings = candidate['operandBindings']
    indexes = [b['operandIndex'] for b in bindings]
    if len(indexes) != len(set(indexes)) or len(bindings) != len(sidecar.operands):
        raise ValueError('COMPILER_AUTHORITY_OPERAND_ARITY_MISMATCH')
    by_index = {b['operandIndex']: b for b in bindings}
    if authority['schemaVersion'] == 'riscv2x86.compiler-fragment-authority.v2':
        types = authority.get('compilerTypeBindings')
        if not isinstance(types, dict) or not types:
            raise ValueError('COMPILER_AUTHORITY_TYPES_MISSING')
        for key, record in types.items():
            if (not isinstance(record, dict) or set(record) != {'operandIndex', 'valueNodeIdentity', 'compilerType'}
                    or type(record['operandIndex']) is not int
                    or str(record['operandIndex']) != key
                    or record['operandIndex'] not in by_index):
                raise ValueError('COMPILER_AUTHORITY_TYPE_BINDING_INVALID')
            binding = by_index[record['operandIndex']]
            parsed = compiler_operand_type_from_dict(record['compilerType'])
            carrier = next((x for x in candidate['operandCarriers']
                            if x['operandIndex'] == record['operandIndex']), None)
            if (record['valueNodeIdentity'] != binding['valueNodeIdentity']
                    or parsed.width_bits != binding['widthBits']
                    or carrier is None
                    or carrier['carrierKind'] != ('pointer' if parsed.is_pointer else 'integer')):
                raise ValueError('COMPILER_AUTHORITY_TYPE_VALUE_MISMATCH')
    for operand in sidecar.operands:
        binding = by_index.get(operand.operand_index)
        expected = {'declarationIdentity': operand.declaration_id,
                    'valueNodeIdentity': operand.value_node_identity,
                    'access': operand.access_mode, 'widthBits': operand.width_bits,
                    'signedness': operand.signedness}
        if binding is None or any(binding.get(k) != v for k, v in expected.items()):
            raise ValueError('COMPILER_AUTHORITY_CANONICAL_OPERAND_MISMATCH')
    result = {
        'schemaVersion': 'riscv2x86.compiler-authority-consumption.v1',
        'fragmentId': fragment_id, 'sourceDigest': authority['sourceDigest'],
        'functionIdentity': authority['functionIdentity'],
        'compilerCandidateIdentity': candidate['closureProvenance']['compilerCandidateIdentity'],
        'closureIdentity': candidate['closureIdentity'],
        'compilerAuthorityIdentity': authority['authorityIdentity'],
        'canonicalAuthorityIdentity': sidecar.authority_identity,
    }
    result['consumptionIdentity'] = _identity(result)
    return result


def validate_compiler_snapshot(snapshot):
    expected = {'schemaVersion', 'sourceDigest', 'frontendReportIdentity', 'functions', 'manifestIdentity'}
    if (set(snapshot) != expected or snapshot['schemaVersion'] != 'riscv2x86.compiler-candidates.v1'
            or snapshot['manifestIdentity'] != _identity({k:v for k,v in snapshot.items() if k != 'manifestIdentity'})):
        raise ValueError('COMPILER_SNAPSHOT_IDENTITY_INVALID')
    candidates = {}
    for function in snapshot['functions']:
        if function['sourceDigest'] != snapshot['sourceDigest']:
            raise ValueError('COMPILER_SNAPSHOT_SOURCE_MISMATCH')
        for candidate in function.get('l2OperandBoundary', {}).get('fragmentCandidates', []):
            key = candidate['fragmentBindingKey']
            expected_id = _identity({'schemaVersion':'riscv2x86.compiler-fragment-binding-key.v2', **key})
            if (key['sourceDigest'] != snapshot['sourceDigest'] or
                    key['functionIdentity'] != function['functionId'] or
                    candidate['candidateIdentity'] != expected_id or expected_id in candidates):
                raise ValueError('COMPILER_SNAPSHOT_CANDIDATE_INVALID')
            candidates[expected_id] = candidate
    return candidates
