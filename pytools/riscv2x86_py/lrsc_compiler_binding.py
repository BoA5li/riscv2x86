"""Compiler/object binding for byte-owned LR/SC sequences, without approval.

This contract preserves every GNU slot and machine output. It supplies no
RMW effect, ordering refinement, output projection or progress proof.
"""
from .atomic_authority import (validated_compiler_fragment_authority,
                               validated_compiler_memory_object)
from .compiler_operand_type import compiler_operand_type_from_dict
from .memory_address_projection import project_memory_address
from .runtime_facts import canonicalize_riscv_register_name
from .route_authority import content_identity
from .lrsc_sequence import replay, SequenceError


def _require(condition, code):
    if not condition:
        raise SequenceError(code)


def bind(sequence, authority, *, fragment_id, source_digest, begin_offset,
         end_offset, runtime_facts, frontend_fragment):
    """Join independently replayed compiler closure and assembler register map.

    The finite domain requires explicit pointer and value inputs, three XLEN
    early-clobber outputs and one exact read/write memory expression. Slots may
    be permuted. No fixed register allocation or source identifier is used.
    """
    seq = replay(sequence)
    _require(seq['inputRegister'] != 0, 'LRSC_CONSTANT_INPUT_REQUIRES_CONSTANT_SLOT_CONTRACT')
    candidate, objects = validated_compiler_fragment_authority(
        authority, fragment_id=fragment_id, source_digest=source_digest,
        begin_offset=begin_offset, end_offset=end_offset,
        frontend_fragment=frontend_fragment)
    raw = candidate.get('expressionClosureInputs', {}).get('fragment', {})
    def partition(fragment, name):
        return [{k: op.get(k, {} if k != 'constraint' else None)
                 for k in ('constraint', 'compilerType', 'compilerAddressType')}
                for op in fragment.get(name, [])]
    _require(all(partition(raw, name) == partition(frontend_fragment, name)
                 for name in ('outputs', 'inputs')), 'LRSC_FRONTEND_PARTITION_MISMATCH')
    slots = raw['outputs'] + raw['inputs']
    bindings = {x['operandIndex']: x for x in candidate['operandBindings']}
    carriers = {x['operandIndex']: x for x in candidate['operandCarriers']}
    expected = set(range(len(slots)))
    _require(set(bindings) == set(carriers) == expected
             and len(bindings) == len(candidate['operandBindings'])
             and len(carriers) == len(candidate['operandCarriers']),
             'LRSC_COMPILER_OPERAND_SET_MISMATCH')
    widths = dict(getattr(runtime_facts, 'operand_width_bits', {}))
    _require(set(widths) == expected and all(type(i) is int for i in widths),
             'LRSC_ASSEMBLER_OPERAND_SET_MISMATCH')
    for i in expected:
        _require(type(widths[i]) is int and widths[i] == bindings[i]['widthBits']
                 == carriers[i]['widthBits'], 'LRSC_OPERAND_WIDTH_MISMATCH')
    register_map = {}
    for name, index in getattr(runtime_facts, 'rv_to_operand_index', {}).items():
        canonical = canonicalize_riscv_register_name(name)
        _require(bool(canonical) and type(index) is int and index in expected,
                 'LRSC_REGISTER_BINDING_INVALID')
        _require(canonical not in register_map or register_map[canonical] == index,
                 'LRSC_REGISTER_BINDING_AMBIGUOUS')
        register_map[canonical] = index
    role_indexes = {}
    for role in ('old', 'next', 'status', 'address', 'input'):
        register = canonicalize_riscv_register_name('x' + str(seq[role + 'Register']))
        index = register_map.get(register)
        _require(index is not None, 'LRSC_MACHINE_ROLE_UNBOUND')
        _require(list(register_map.values()).count(index) == 1,
                 'LRSC_OPERAND_REGISTER_AMBIGUOUS')
        item, carrier = bindings[index], carriers[index]
        output = role in ('old', 'next', 'status')
        _require(item['access'] == ('output' if output else 'input')
                 and carrier['carrierKind'] == ('pointer' if role == 'address' else 'integer')
                 and widths[index] == 64, 'LRSC_ROLE_CARRIER_MISMATCH')
        if output:
            _require(slots[index]['constraint'].startswith('=&'),
                     'LRSC_EARLY_CLOBBER_REQUIRED')
        role_indexes[role] = index
    _require(len(set(role_indexes.values())) == 5, 'LRSC_ROLE_SLOT_ALIAS')
    memory_indexes = [i for i in expected if carriers[i]['carrierKind'] == 'memory_lvalue']
    _require(len(memory_indexes) == 1 and expected == set(role_indexes.values()) | set(memory_indexes),
             'LRSC_UNACCOUNTED_OPERANDS')
    memory_index = memory_indexes[0]
    _require(bindings[memory_index]['access'] == 'read_write'
             and widths[memory_index] == seq['memoryWidthBits'],
             'LRSC_MEMORY_SLOT_MISMATCH')
    projection = project_memory_address(candidate, memory_index)
    address_index = role_indexes['address']
    declaration = carriers[address_index]['declarationIdentity']
    _require(projection['baseDeclarationIdentity'] == declaration,
             'LRSC_MEMORY_ADDRESS_MISMATCH')
    type_binding = authority.get('compilerTypeBindings', {}).get(str(address_index), {})
    _require(type_binding.get('operandIndex') == address_index
             and type_binding.get('valueNodeIdentity') == bindings[address_index]['valueNodeIdentity'],
             'LRSC_POINTER_TYPE_BINDING_MISMATCH')
    pointer = compiler_operand_type_from_dict(type_binding.get('compilerType'))
    projected = compiler_operand_type_from_dict(projection['compilerPointerType'])
    _require(pointer.type_identity == projected.type_identity
             and pointer.pointee_type_identity == projected.pointee_type_identity
             and pointer.is_pointer and pointer.side_effect_free and pointer.expression_repeatable
             and not pointer.qualifiers and not pointer.pointee_qualifiers
             and pointer.width_bits == 64
             and pointer.pointee_width_bits == seq['memoryWidthBits'],
             'LRSC_POINTER_TYPE_MISMATCH')
    obj = validated_compiler_memory_object(objects, declaration=declaration,
        source_digest=source_digest, width_bits=seq['memoryWidthBits'])
    _require(obj['volatile'] is False, 'LRSC_VOLATILE_OBJECT_CONTRACT_REQUIRED')
    payload = {
        'schemaVersion': 'riscv2x86.lrsc-compiler-binding.v1',
        'fragmentId': fragment_id, 'sourceDigest': source_digest,
        'sequenceIdentity': seq['sequenceIdentity'],
        'compilerAuthorityIdentity': authority['authorityIdentity'],
        'compilerClosureIdentity': candidate['closureIdentity'],
        'fragmentBindingKey': dict(authority['fragmentBindingKey']),
        'roleOperandIndexes': role_indexes, 'memoryOperandIndex': memory_index,
        'operandBindings': candidate['operandBindings'],
        'assemblerRegisterBindings': register_map, 'operandWidths': widths,
        'memoryAddressProjection': projection, 'memoryObjectBinding': dict(obj),
        'compilerBindingComplete': True, 'semanticApproval': False,
        'remainingObligations': ['sequence-state-and-output-proof',
            'source-target-ordering-refinement', 'target-rendering-and-l2-authority',
            'actual-lr-sc-outcomes-and-independent-l3-audit',
            'termination-and-concurrent-progress'],
    }
    return dict(payload, bindingIdentity=content_identity(payload))


def replay_binding(value, sequence, authority, **context):
    """Recompute evidence joins; a rehashed assertion alone cannot close a join."""
    expected = bind(sequence, authority, **context)
    _require(value == expected, 'LRSC_COMPILER_BINDING_REPLAY_MISMATCH')
    return expected
