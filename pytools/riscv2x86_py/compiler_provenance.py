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
            'riscv2x86.compiler-fragment-authority.v2',
            'riscv2x86.compiler-fragment-authority.v3'} or
            authority.get('targetTriple') != 'riscv64-linux-gnu' or
            authority['fragmentBindingKey'] != key or
            key['sourceDigest'] != authority['sourceDigest'] or
            key['functionIdentity'] != authority['functionIdentity']):
        raise ValueError('COMPILER_AUTHORITY_SOURCE_BINDING_MISMATCH')
    if authority.get('schemaVersion') == 'riscv2x86.compiler-fragment-authority.v3':
        from .fragment_source_range import validate_fragment_source_range
        if set(authority) != {'schemaVersion', 'sourceDigest', 'fragmentId', 'targetTriple',
                'functionIdentity', 'fragmentBindingKey', 'candidate', 'memoryObjectBindings',
                'compilerTypeBindings', 'sourceRangeBinding', 'authorityIdentity'}:
            raise ValueError('COMPILER_AUTHORITY_FIELDS_INVALID')
        validate_fragment_source_range(authority.get('sourceRangeBinding'), key,
            fragment_id=fragment.get('fragmentId') or fragment.get('id'),
            source_digest=authority['sourceDigest'], begin_offset=fragment.get('beginOffset'),
            end_offset=fragment.get('endOffset'), frontend_fragment=fragment)
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
    if authority['schemaVersion'] in {'riscv2x86.compiler-fragment-authority.v2', 'riscv2x86.compiler-fragment-authority.v3'}:
        types = authority.get('compilerTypeBindings')
        if not isinstance(types, dict) or (not types and (bindings or authority['schemaVersion'] == 'riscv2x86.compiler-fragment-authority.v2')):
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
            expected_kind = 'pointer' if parsed.is_pointer else 'integer'
            if carrier is not None and carrier.get('schemaVersion') == 'riscv2x86.compiler-expression-carrier.v1':
                # validate_closed_compiler_fragment_candidate above independently
                # replays this expression carrier from its original AST/GNU shell.
                evaluation = candidate.get('expressionEvaluation', {})
                matches = [x for x in evaluation.get('bindings', [])
                           if x.get('operandIndex') == record['operandIndex']]
                if len(matches) != 1:
                    raise ValueError('COMPILER_AUTHORITY_EXPRESSION_BINDING_MISSING')
                evaluated = matches[0]
                joined = evaluation['expressionJoin']['operands'][record['operandIndex']]
                if joined['compilerType'] != record['compilerType']:
                    raise ValueError('COMPILER_AUTHORITY_EXPRESSION_TYPE_MISMATCH')
                if evaluated['role'] == 'memory_lvalue':
                    expected_kind = 'memory_lvalue'
                if (carrier.get('evaluationBindingIdentity') != evaluated['bindingIdentity']
                        or carrier.get('expressionIdentity') != evaluated['expressionIdentity']):
                    raise ValueError('COMPILER_AUTHORITY_EXPRESSION_BINDING_MISMATCH')
            if (record['valueNodeIdentity'] != binding['valueNodeIdentity']
                    or parsed.width_bits != binding['widthBits']
                    or carrier is None or carrier['carrierKind'] != expected_kind):
                raise ValueError('COMPILER_AUTHORITY_TYPE_VALUE_MISMATCH')
    for operand in sidecar.operands:
        binding = by_index.get(operand.operand_index)
        expected = {'declarationIdentity': operand.declaration_id,
                    'valueNodeIdentity': operand.value_node_identity,
                    'access': operand.access_mode, 'widthBits': operand.width_bits,
                    'signedness': operand.signedness}
        static = getattr(operand,'static_operand',None)
        if static is not None:
            from .compiler_static_operand import validate_static_operand
            validate_static_operand(static,index=operand.operand_index,node=operand.value_node_identity,
                width=operand.width_bits,signedness=operand.signedness,access=operand.access_mode,declaration=operand.declaration_id)
            carriers=[c for c in candidate['operandCarriers'] if c['operandIndex']==operand.operand_index]
            if (len(carriers)!=1 or carriers[0].get('constantValue')!=static['value']
                    or carriers[0].get('expressionIdentity')!=static['expressionIdentity']
                    or carriers[0].get('evaluationBindingIdentity')!=static['evaluationBindingIdentity']):
                raise ValueError('COMPILER_AUTHORITY_STATIC_VALUE_MISMATCH')
        if getattr(operand, 'operand_role', 'value') == 'memory_lvalue':
            # Storage authority has no scalar signed interpretation. Require
            # the exact replayed memory role and evaluation/address identities.
            records = (candidate.get('expressionEvaluation') or {}).get('bindings', [])
            matches = [x for x in records if x.get('operandIndex') == operand.operand_index]
            if (len(matches) != 1 or matches[0]['role'] != 'memory_lvalue'
                    or getattr(operand, 'type_kind', '') != 'aggregate'
                    or operand.signedness != 'not_applicable'
                    or operand.declaration_id
                    or operand.expression_identity != matches[0]['expressionIdentity']
                    or operand.evaluation_binding_identity != matches[0]['bindingIdentity']):
                raise ValueError('COMPILER_AUTHORITY_MEMORY_ROLE_MISMATCH')
            expected.pop('signedness')
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
