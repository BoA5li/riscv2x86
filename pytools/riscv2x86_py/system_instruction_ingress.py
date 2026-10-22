"""Decoder-owned SYSTEM facts and separately supplied environment bindings.

Instruction bits identify an operation, never a service number, trap handler,
permission, wait policy, or approval. The first bound domain is RV64 M-mode;
other domains remain incomplete until an independently reviewed model exists.
"""
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
import re
from .semantic_content import semantic_identity

SCHEMA = 'riscv2x86.system-instruction-authority.v1'
PROFILE = 'rv64-m-mode-system-1.12.v1'
WORDS = {0x00000073: 'ecall', 0x10500073: 'wfi'}
_DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')


def digest(data):
    return 'sha256:' + sha256(data).hexdigest()


def decode_system_instruction(machine_bytes):
    if not isinstance(machine_bytes, (bytes, bytearray)) or len(machine_bytes) != 4:
        return None
    return WORDS.get(int.from_bytes(machine_bytes, 'little'))


def intrinsic_operations(machine_bytes):
    from .pcode_ir import CanonicalPrivilegedOperation as Op, CanonicalPrivilegedOperationKind as Kind
    name = decode_system_instruction(machine_bytes)
    if name == 'ecall':
        return (Op(Kind.TRAP, trap_kind='environment_call', state_complete=False),)
    if name == 'wfi':
        return (Op(Kind.INTERRUPT_STATE, interrupt_kind='wait', state_complete=False),)
    return ()


def _fields(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('SYSTEM_AUTHORITY_FIELDS_INVALID:' + label)


def _text(value, label):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError('SYSTEM_AUTHORITY_TEXT_INVALID:' + label)
    return value


@dataclass(frozen=True)
class SystemBinding:
    instruction_offset: int
    operation: str
    transition: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class SystemInstructionAuthority:
    source_digest: str
    fragment_id: str
    machine_code_digest: str
    execution_identity: str
    mechanism_identity: str
    bindings: tuple[SystemBinding, ...]
    authority_identity: str

    @classmethod
    def from_dict(cls, value):
        _fields(value, ('schemaVersion', 'profile', 'sourceDigest', 'fragmentId',
            'machineCodeDigest', 'executionIdentity', 'mechanismIdentity',
            'bindings', 'authorityIdentity'), 'envelope')
        if value['schemaVersion'] != SCHEMA or value['profile'] != PROFILE:
            raise ValueError('SYSTEM_AUTHORITY_PROFILE_UNSUPPORTED')
        for key in ('sourceDigest', 'machineCodeDigest', 'executionIdentity',
                    'mechanismIdentity', 'authorityIdentity'):
            if not isinstance(value[key], str) or not _DIGEST.fullmatch(value[key]):
                raise ValueError('SYSTEM_AUTHORITY_DIGEST_INVALID:' + key)
        _text(value['fragmentId'], 'fragmentId')
        payload = {key: item for key, item in value.items() if key != 'authorityIdentity'}
        if semantic_identity(payload) != value['authorityIdentity']:
            raise ValueError('SYSTEM_AUTHORITY_IDENTITY_MISMATCH')
        if not isinstance(value['bindings'], list) or not value['bindings']:
            raise ValueError('SYSTEM_AUTHORITY_BINDINGS_REQUIRED')
        bindings = []
        for item in value['bindings']:
            _fields(item, ('instructionOffset', 'operation', 'transition'), 'binding')
            offset, name, transition = item['instructionOffset'], item['operation'], item['transition']
            if type(offset) is not int or offset < 0 or offset % 2 or name not in ('ecall', 'wfi'):
                raise ValueError('SYSTEM_AUTHORITY_INSTRUCTION_INVALID')
            keys = ('handlerBindingId', 'continuationIdentity', 'registerEffects') if name == 'ecall' else (
                'interruptEnableState', 'interruptPendingState', 'eventSourceId',
                'waitWakeupRelationId', 'spuriousWakeupPolicy', 'registerEffects')
            _fields(transition, keys, 'transition')
            for key in keys: _text(transition[key], key)
            if transition['registerEffects'] != 'all-gprs-preserved':
                raise ValueError('SYSTEM_AUTHORITY_REGISTER_TRANSPORT_UNSUPPORTED')
            if name == 'wfi' and transition['spuriousWakeupPolicy'] != 'permitted':
                raise ValueError('SYSTEM_AUTHORITY_WFI_POLICY_UNSUPPORTED')
            bindings.append(SystemBinding(offset, name, tuple(sorted(transition.items()))))
        offsets = [item.instruction_offset for item in bindings]
        if offsets != sorted(set(offsets)):
            raise ValueError('SYSTEM_AUTHORITY_OFFSETS_NOT_CANONICAL')
        return cls(value['sourceDigest'], value['fragmentId'], value['machineCodeDigest'],
            value['executionIdentity'], value['mechanismIdentity'], tuple(bindings), value['authorityIdentity'])


def load_system_instruction_authority(path):
    return SystemInstructionAuthority.from_dict(json.loads(Path(path).read_text()))


def bind_system_instructions(lifted, *, machine_code, base_addr, source_digest,
                             fragment_id, facts, authority):
    """Join exact decoded sites to environment evidence before canonical IR.

    This supplies Phase-4 facts. Phase 6D and runtime registration still decide
    approval; neither a content hash nor this join proves an implementation.
    """
    if (authority.fragment_id != fragment_id or authority.source_digest != source_digest
            or authority.machine_code_digest != digest(machine_code)
            or authority.execution_identity != semantic_identity(facts)):
        raise ValueError('SYSTEM_AUTHORITY_BINDING_MISMATCH')
    if (facts is None or not facts.complete or facts.initial_privilege_mode.value != 'm'
            or facts.source_execution_profile.value != 'riscv_machine_firmware'
            or facts.source_privilege_spec_version not in ('1.12', 'riscv-privileged-1.12')
            or 'i' not in facts.source_isa_extensions
            or not set(facts.source_isa_extensions).issubset({'i', 'zicsr'})
            or facts.virtual_memory_model is None
            or facts.virtual_memory_model.address_translation_enabled is not False
            or facts.virtual_memory_model.translation_mode != 'bare'
            or facts.virtual_memory_model.vmid_width_bits is not None
            or facts.delegation_model is None
            or not facts.delegation_model.exception_delegation_complete
            or not facts.delegation_model.interrupt_delegation_complete):
        raise ValueError('SYSTEM_AUTHORITY_EXECUTION_DOMAIN_UNSUPPORTED')
    observed = []
    for ins in lifted.insns:
        offset = ins.addr - base_addr
        name = decode_system_instruction(machine_code[offset:offset + ins.length])
        if name is not None: observed.append((offset, name, ins))
    expected = [(item.instruction_offset, item.operation) for item in authority.bindings]
    if [(offset, name) for offset, name, _ in observed] != expected:
        raise ValueError('SYSTEM_AUTHORITY_SITE_COVERAGE_MISMATCH')
    if len(lifted.insns) != 1 or len(machine_code) != 4 or len(expected) != 1:
        raise ValueError('SYSTEM_AUTHORITY_SCOPE_UNSUPPORTED')
    for (_, name, ins), binding in zip(observed, authority.bindings):
        original = intrinsic_operations(machine_code[binding.instruction_offset:binding.instruction_offset + 4])
        if ins.privileged_operations != original:
            raise ValueError('SYSTEM_AUTHORITY_INTRINSIC_MISMATCH')
        transition = dict(binding.transition)
        prefix = 'system:' + authority.authority_identity + ':' + str(binding.instruction_offset)
        if name == 'ecall':
            handler = facts.trap_handler_binding
            if (handler is None or not handler.complete
                    or transition['handlerBindingId'] != handler.binding_id
                    or transition['continuationIdentity'] != handler.continuation_model_id):
                raise ValueError('SYSTEM_AUTHORITY_HANDLER_MISMATCH')
            operation = replace(original[0], trap_cause='environment-call-from-m',
                tval_node_id=prefix + ':mtval', trap_target_privilege_mode='m',
                handler_binding_id=handler.binding_id, saved_pc_node_id=prefix + ':mepc',
                saved_status_effect_ids=('mstatus.mie', 'mstatus.mpie', 'mstatus.mpp'),
                delegation_path=('m',), continuation_identity=handler.continuation_model_id,
                externally_observable=True, state_complete=True)
        else:
            interrupt = facts.interrupt_model
            if interrupt is None or not interrupt.complete or not interrupt.priority_model_id:
                raise ValueError('SYSTEM_AUTHORITY_INTERRUPT_MODEL_INCOMPLETE')
            # State references are tied to the actual interrupt model, never
            # copied from a differently scoped declaration.
            if (transition['interruptEnableState'] != interrupt.model_id + ':enable'
                    or transition['interruptPendingState'] != interrupt.model_id + ':pending'):
                raise ValueError('SYSTEM_AUTHORITY_INTERRUPT_MODEL_MISMATCH')
            operation = replace(original[0], interrupt_enable_state=transition['interruptEnableState'],
                interrupt_pending_state=transition['interruptPendingState'],
                interrupt_delegation_path=('m',), interruptibility=interrupt.externally_interruptible,
                event_source_id=prefix + ':' + transition['eventSourceId'],
                wait_wakeup_relation_id=prefix + ':' + transition['waitWakeupRelationId'], state_complete=True)
        ins.privileged_operations = (operation,)
    return {'reasonCode': 'SYSTEM_INSTRUCTION_BINDING_COMPLETE', 'accepted': True,
            'fragmentId': fragment_id, 'authorityIdentity': authority.authority_identity,
            'mechanismIdentity': authority.mechanism_identity,
            'instructionCount': len(observed), 'semanticApproval': False}
