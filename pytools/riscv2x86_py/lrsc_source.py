"""Replayed LR/SC runtime ingress and immutable source sequence semantics.

Object/operand closure is independent of target approval. Reference transitions
below are specification calculations, never observations or progress proofs.
"""
from dataclasses import asdict, dataclass, is_dataclass
import json
from types import SimpleNamespace

from .lrsc_compiler_binding import bind
from .lrsc_sequence import candidate, replay, SequenceError
from .route_authority import content_identity


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _require(value, code):
    if not value:
        raise SequenceError(code)


def _raw(fragment):
    return asdict(fragment) if is_dataclass(fragment) else dict(fragment)


def _frontend(fragment):
    raw = _raw(fragment)
    _require(not (raw.get('id') and raw.get('fragmentId')
                  and raw['id'] != raw['fragmentId']), 'LRSC_FRAGMENT_ID_ALIAS_CONFLICT')
    # Only independently owned compiler/frontend fields enter this contract.
    names = ('beginOffset', 'endOffset', 'astBeginOffset',
             'astEndOffset', 'outputs', 'inputs', 'isVolatile', 'clobbers',
             'hasAsmGoto', 'hasExternalControlFlow', 'hasMultipleExits',
             'hasNonLocalControlDependency', 'gotoLabels', 'controlFlow')
    return {'fragmentId': raw.get('fragmentId') or raw.get('id'),
            **{k: raw[k] for k in names if k in raw}}


def _runtime(data):
    widths = data['operandWidths']
    _require(isinstance(widths, dict) and all(isinstance(k, str)
        and k.isdecimal() and str(int(k)) == k for k in widths),
        'LRSC_RUNTIME_WIDTH_KEYS_INVALID')
    return SimpleNamespace(rv_to_operand_index=data['registerBindings'],
                           operand_width_bits={int(k): v for k, v in widths.items()})


def _replay_ingress(data):
    fields = {'schemaVersion', 'sequence', 'compilerAuthority', 'frontend',
              'registerBindings', 'operandWidths', 'binding', 'evidenceIdentity'}
    _require(isinstance(data, dict) and set(data) == fields
        and data['schemaVersion'] == 'riscv2x86.lrsc-runtime-evidence.v1',
        'LRSC_RUNTIME_EVIDENCE_FIELDS_INVALID')
    _require(data['evidenceIdentity'] == content_identity({k: v for k, v in data.items()
        if k != 'evidenceIdentity'}), 'LRSC_RUNTIME_EVIDENCE_IDENTITY_MISMATCH')
    sequence = replay(data['sequence'])
    authority, fragment = data['compilerAuthority'], data['frontend']
    binding = bind(sequence, authority,
        fragment_id=fragment.get('fragmentId') or fragment.get('id'),
        source_digest=authority['sourceDigest'], begin_offset=fragment.get('beginOffset'),
        end_offset=fragment.get('endOffset'), runtime_facts=_runtime(data),
        frontend_fragment=fragment)
    _require(_json(binding) == _json(data['binding']), 'LRSC_RUNTIME_BINDING_REPLAY_MISMATCH')
    return sequence, binding


@dataclass(frozen=True)
class LrScRuntimeEvidence:
    """An immutable snapshot. Every consumer replays its independent inputs."""
    evidence_json: str

    def __post_init__(self):
        _replay_ingress(json.loads(self.evidence_json))

    def to_dict(self):
        return json.loads(self.evidence_json)

    @classmethod
    def from_dict(cls, value):
        return cls(_json(value))

    @classmethod
    def produce(cls, fragment, machine_bytes, *, base_address, xlen_bits,
                runtime_facts, source_digest):
        raw = _raw(fragment)
        authority = raw.get('compilerFragmentAuthority') or {}
        sequence = candidate(machine_bytes, base_address=base_address, xlen_bits=xlen_bits)
        frontend = _frontend(fragment)
        binding = bind(sequence, authority,
            fragment_id=raw.get('fragmentId') or raw.get('id'), source_digest=source_digest,
            begin_offset=raw.get('beginOffset'), end_offset=raw.get('endOffset'),
            runtime_facts=runtime_facts, frontend_fragment=frontend)
        data = {'schemaVersion': 'riscv2x86.lrsc-runtime-evidence.v1',
            'sequence': sequence, 'compilerAuthority': authority, 'frontend': frontend,
            'registerBindings': binding['assemblerRegisterBindings'],
            'operandWidths': {str(k): v for k, v in runtime_facts.operand_width_bits.items()},
            'binding': binding}
        data['evidenceIdentity'] = content_identity(data)
        return cls.from_dict(data)

    def validate_current(self, fragment, runtime_facts, *, xlen_bits):
        data = self.to_dict()
        sequence, binding = _replay_ingress(data)
        raw = _raw(fragment)
        _require(_json(_frontend(fragment)) == _json(data['frontend'])
            and _json(raw.get('compilerFragmentAuthority')) == _json(data['compilerAuthority']),
            'LRSC_CURRENT_FRAGMENT_MISMATCH')
        _require(type(xlen_bits) is int and xlen_bits == sequence['xlenBits'],
                 'LRSC_CURRENT_XLEN_MISMATCH')
        current = bind(sequence, data['compilerAuthority'],
            fragment_id=raw.get('fragmentId') or raw.get('id'),
            source_digest=data['compilerAuthority']['sourceDigest'],
            begin_offset=raw.get('beginOffset'), end_offset=raw.get('endOffset'),
            runtime_facts=runtime_facts, frontend_fragment=_frontend(fragment))
        _require(_json(current) == _json(binding), 'LRSC_CURRENT_RUNTIME_FACTS_MISMATCH')
        return sequence, binding


@dataclass(frozen=True)
class SourceLrScSequenceModel:
    fragment_id: str
    source_digest: str
    sequence_identity: str
    compiler_binding_identity: str
    runtime_evidence_identity: str
    memory_object_identity: str
    object_binding_identity: str
    role_operand_indexes: tuple[tuple[str, int], ...]
    register_roles: tuple[tuple[str, int], ...]
    memory_operand_index: int
    memory_width_bits: int
    arithmetic_width_bits: int
    operation: str
    lr_ordering_bits: tuple[bool, bool]
    sc_ordering_bits: tuple[bool, bool]
    retry_target: int
    success_exit: int
    source_xlen: int = 64

    def __post_init__(self):
        _require(type(self.source_xlen) is int and self.source_xlen == 64, 'LRSC_SOURCE_XLEN_UNSUPPORTED')
        _require(type(self.memory_width_bits) is int and self.memory_width_bits in (32, 64)
            and type(self.arithmetic_width_bits) is int and self.arithmetic_width_bits in (32, 64)
            and self.operation in {'fetch_add', 'fetch_and', 'fetch_or', 'fetch_xor'}
            and (self.arithmetic_width_bits == 64 or
                 (self.memory_width_bits == 32 and self.operation == 'fetch_add')),
            'LRSC_SOURCE_WIDTH_OR_OPERATION_INVALID')
        _require(len(self.lr_ordering_bits) == len(self.sc_ordering_bits) == 2
            and all(type(v) is bool for v in self.lr_ordering_bits + self.sc_ordering_bits),
            'LRSC_SOURCE_ORDERING_BITS_INVALID')
        _require(type(self.retry_target) is int and self.retry_target >= 0
            and type(self.success_exit) is int
            and self.success_exit - self.retry_target in (14, 16),
            'LRSC_SOURCE_REGION_INVALID')
        registers = dict(self.register_roles)
        _require(len(self.register_roles) == 5 and set(registers) == {
            'old', 'next', 'status', 'address', 'input'} and
            all(type(r) is int and 0 < r < 32 for r in registers.values())
            and len(set(registers.values())) == 5, 'LRSC_SOURCE_REGISTER_ROLES_INVALID')
        roles = dict(self.role_operand_indexes)
        _require(len(self.role_operand_indexes) == 5 and set(roles) == {
            'old', 'next', 'status', 'address', 'input'} and
            all(type(i) is int and i >= 0 for i in (*roles.values(), self.memory_operand_index))
            and len(set(roles.values()) | {self.memory_operand_index}) == 6,
            'LRSC_SOURCE_ROLE_SET_INVALID')

    @property
    def complete(self):
        # Local source-state description, not a target proof or termination claim.
        return True

    def to_dict(self):
        body = {'schemaVersion': 'riscv2x86.source-lrsc-sequence.v1',
            **asdict(self),
            'role_operand_indexes': dict(self.role_operand_indexes),
            'register_roles': dict(self.register_roles),
            # The immutable model uses tuples; the public wire DTO uses JSON
            # arrays so a saved/reloaded contract is structurally identical.
            'lr_ordering_bits': list(self.lr_ordering_bits),
            'sc_ordering_bits': list(self.sc_ordering_bits),
            'sourceStateModelComplete': True, 'semanticApproval': False,
            'states': ['load_reserved', 'compute_next', 'store_conditional',
                       'retry_or_exit'],
            'failureStatusDomain': 'nonzero-xlen-bit-pattern',
            'failureStoreEffect': 'no-successful-store',
            'successStatus': 0, 'oldExtension': 'sign_extend_to_xlen' if self.memory_width_bits < 64 else 'identity',
            'storeProjection': 'low-memory-width-bits',
            'allRegisterOutputsModeled': True,
            'reservationValidity': 'independent-environment-outcome-not-value-equality',
            'successfulSCRequiresValidReservation': True,
            'validReservationDoesNotForceSuccess': True,
            'scClearsReservationRegardlessOfOutcome': True,
            'terminationProved': False, 'concurrentAtomicityMeasured': False,
            'physicalMemoryOrderMeasured': False,
            'orderingRefinementProved': False,
            'remainingObligations': ['target-sequence-proof', 'l2-sequence-authority',
                'actual-execution-and-independent-l3-audit', 'environment-and-progress-contract']}
        return dict(body, modelIdentity=content_identity(body))


def build_source_sequence(fragment, runtime_facts, *, xlen_bits, machine_code=None):
    ingress = getattr(runtime_facts, 'lrsc_sequence_evidence', None)
    if ingress is None:
        return None
    _require(isinstance(ingress, LrScRuntimeEvidence), 'LRSC_TYPED_RUNTIME_EVIDENCE_REQUIRED')
    sequence, binding = ingress.validate_current(fragment, runtime_facts, xlen_bits=xlen_bits)
    _require(type(machine_code) is bytes and machine_code.hex() == sequence['machineBytes'],
             'LRSC_CURRENT_MACHINE_BYTES_MISMATCH')
    raw = _raw(fragment)
    _require(not any(raw.get(k) for k in ('hasAsmGoto', 'hasExternalControlFlow',
        'hasMultipleExits', 'hasNonLocalControlDependency', 'gotoLabels')),
        'LRSC_SOURCE_EXTERNAL_CONTROL_UNSUPPORTED')
    surface = raw.get('controlFlow') or {}
    _require(not any(surface.get(k) for k in ('hasAsmGoto', 'hasMultipleExits',
        'hasIndirectBranch', 'hasCallLike', 'hasReturnLike', 'hasNonLocalControl')),
        'LRSC_SOURCE_EXTERNAL_CONTROL_UNSUPPORTED')
    obj = binding['memoryObjectBinding']
    return SourceLrScSequenceModel(
        binding['fragmentId'], binding['sourceDigest'], sequence['sequenceIdentity'],
        binding['bindingIdentity'], ingress.to_dict()['evidenceIdentity'],
        obj['objectIdentity'], obj['bindingIdentity'],
        tuple(sorted(binding['roleOperandIndexes'].items())),
        tuple((role, sequence[role + 'Register']) for role in ('old', 'next', 'status', 'address', 'input')),
        binding['memoryOperandIndex'],
        sequence['memoryWidthBits'], sequence['arithmeticWidthBits'], sequence['operation'],
        tuple(sequence['lrOrderingBits'][k] for k in ('aq', 'rl')),
        tuple(sequence['scOrderingBits'][k] for k in ('aq', 'rl')),
        sequence['retryTarget'], sequence['successExit'])


def source_operands(model, shell, runtime_facts):
    """Materialize only object/type/slot semantics; no atomic approval fabricated."""
    from .source_model import (SourceOperandBinding, SourceOperandModel, SourceOperandKind,
        SourceOperandAccess, SourceSignedness, SourceExpressionBinding,
        SourceLvalueBinding, SourceAddressBinding)
    from .compiler_operand_type import compiler_operand_type_from_dict
    data = runtime_facts.lrsc_sequence_evidence.to_dict()
    binding = data['binding'];obj = binding['memoryObjectBinding']
    projection = binding['memoryAddressProjection'];roles = dict(model.role_operand_indexes)
    records = {x['operandIndex']: x for x in binding['operandBindings']}
    result = []
    for index, operand in enumerate(shell.all_operands):
        record = records[index]
        memory = index == model.memory_operand_index
        address = index == roles['address']
        typ = operand.compiler_type
        _require(typ is not None, 'LRSC_COMPILER_SLOT_TYPE_REQUIRED')
        access = SourceOperandAccess.READ_WRITE if memory else SourceOperandAccess.ADDRESS if address else (
            SourceOperandAccess.OUTPUT if record['access'] == 'output' else SourceOperandAccess.INPUT)
        reads = access != SourceOperandAccess.OUTPUT
        writes = access in {SourceOperandAccess.OUTPUT, SourceOperandAccess.READ_WRITE}
        _require(typ.side_effect_free and (not writes or typ.modifiable_lvalue),
                 'LRSC_SLOT_EVALUATION_CONTRACT_REQUIRED')
        expression = SourceExpressionBinding(record['valueNodeIdentity'], typ.type_identity,
            typ.side_effect_free, typ.expression_repeatable) if reads else None
        if memory:
            expression = SourceExpressionBinding(projection['addressValueNodeIdentity'],
                compiler_operand_type_from_dict(projection['compilerPointerType']).type_identity, True, True)
        lvalue = SourceLvalueBinding(projection['expressionIdentity'] if memory else record['valueNodeIdentity'],
            typ.type_identity, typ.modifiable_lvalue) if writes else None
        location = SourceAddressBinding(
            address_id=projection['addressValueNodeIdentity'],
            pointee_type_id=compiler_operand_type_from_dict(projection['compilerPointerType']).pointee_type_identity,
            alignment_bytes=obj['provenAlignmentBytes'], provenance_known=True,
            memory_object_identity=obj['objectIdentity'], address_space_identity=obj['addressSpaceIdentity'],
            address_projection=projection) if memory or address else None
        result.append(SourceOperandBinding(index,
            SourceOperandKind.MEMORY if memory else SourceOperandKind.ADDRESS if address else SourceOperandKind.REGISTER,
            access, record['widthBits'], SourceSignedness.SIGNED if typ.is_signed else SourceSignedness.UNSIGNED,
            reads, writes, memory, None, operand.is_early_clobber, None,
            expression, lvalue, location))
    _require(len(result) == 6, 'LRSC_SOURCE_OPERAND_COVERAGE_INVALID')
    return SourceOperandModel(tuple(result), True)


def reference_attempt(model, *, loaded_value, input_value, sc_status, reservation_valid=True):
    """One specification attempt. SC status is supplied, never guessed from values."""
    mask = (1 << 64) - 1
    _require(all(type(v) is int for v in (loaded_value, input_value, sc_status))
        and 0 <= loaded_value < (1 << model.memory_width_bits)
        and 0 <= input_value <= mask and 0 <= sc_status <= mask,
        'LRSC_REFERENCE_VALUE_DOMAIN_INVALID')
    _require(type(reservation_valid) is bool and (sc_status != 0 or reservation_valid),
             'LRSC_REFERENCE_RESERVATION_INVALID')
    old = loaded_value
    if old & (1 << (model.memory_width_bits - 1)):
        old -= 1 << model.memory_width_bits
    old &= mask
    value = {'fetch_add': lambda: old + input_value,
             'fetch_and': lambda: old & input_value,
             'fetch_or': lambda: old | input_value,
             'fetch_xor': lambda: old ^ input_value}[model.operation]()
    value &= (1 << model.arithmetic_width_bits) - 1
    if model.arithmetic_width_bits == 32 and value & (1 << 31):
        value -= 1 << 32
    value &= mask
    return {'old': old, 'next': value,
        'status': sc_status, 'successful': sc_status == 0,
        'reservationValidAtSc': reservation_valid, 'reservationAfterSc': False,
        'storeValue': value & ((1 << model.memory_width_bits) - 1) if sc_status == 0 else None,
        'nextState': 'exit' if sc_status == 0 else 'load_reserved',
        'evidenceKind': 'reference-calculation-not-observation'}


def reference_prefix(model, attempts, *, input_value):
    """Finite attempt prefix; no assumption that retries see the initial memory."""
    _require(isinstance(attempts, (list, tuple)), 'LRSC_REFERENCE_ATTEMPTS_REQUIRED')
    rows = []
    for attempt in attempts:
        _require(not rows or not rows[-1]['successful'], 'LRSC_REFERENCE_AFTER_EXIT')
        _require(isinstance(attempt, dict) and set(attempt) in (
            {'loadedValue', 'scStatus'}, {'loadedValue', 'scStatus', 'reservationValid'}),
                 'LRSC_REFERENCE_ATTEMPT_FIELDS_INVALID')
        rows.append(reference_attempt(model, loaded_value=attempt['loadedValue'],
            input_value=input_value, sc_status=attempt['scStatus'],
            reservation_valid=attempt.get('reservationValid', True)))
    complete = bool(rows and rows[-1]['successful'])
    return {'attempts': rows, 'executionComplete': complete,
        'successfulStoreCount': int(complete),
        'outputs': {k: rows[-1][k] for k in ('old', 'next', 'status')} if complete else None,
        'terminationProved': False, 'evidenceKind': 'reference-calculation-not-observation'}
