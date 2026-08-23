"""Phase-5 V2 privileged effect analysis over canonical semantics.

The analyzer joins typed decoder/lifter metadata with Phase-4 execution facts.
It never reads assembly text, mnemonics, rendered p-code, symbols, or source
names.  Missing V2 metadata remains unknown and makes the affected effect and
therefore the complete privileged model fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence

from .cfg import CFGResult
from .pcode_ir import (
    Block,
    CanonicalCsrFieldEffect,
    CanonicalCsrOperationKind,
    CanonicalPrivilegedOperationKind,
    VarKind,
)
from .privileged_execution_sidecar import (
    PrivilegedExecutionFacts,
    SourceExecutionProfile,
    SourcePrivilegeMode,
    TargetExecutionMode,
    UnknownCsrAccessDisposition,
    default_user_process_execution_facts,
)


class PrivilegedStateReasonCode(str, Enum):
    EXECUTION_FACTS_INCOMPLETE = "privileged-state.execution-facts-incomplete"
    CFG_INCOMPLETE = "privileged-state.cfg-incomplete"
    CANONICAL_METADATA_INCOMPLETE = "privileged-state.canonical-privileged-metadata-incomplete"
    CSR_IDENTITY_UNKNOWN = "privileged-state.csr-identity-unknown"
    CSR_CLASS_UNKNOWN = "privileged-state.csr-class-unknown"
    CSR_OPERATION_UNKNOWN = "privileged-state.csr-operation-unknown"
    CSR_VALUE_FLOW_INCOMPLETE = "privileged-state.csr-value-flow-incomplete"
    CSR_IMMEDIATE_MASK_INCOMPLETE = "privileged-state.csr-immediate-mask-incomplete"
    CSR_FIELD_EFFECT_INCOMPLETE = "privileged-state.csr-field-effect-incomplete"
    CSR_WARL_WLRL_POLICY_INCOMPLETE = "privileged-state.csr-warl-wlrl-policy-incomplete"
    CSR_SIDE_EFFECT_INCOMPLETE = "privileged-state.csr-side-effect-incomplete"
    CSR_XLEN_UNKNOWN = "privileged-state.csr-xlen-unknown"
    CSR_EXTENSION_UNPROVEN = "privileged-state.csr-extension-unproven"
    CSR_ACCESS_GATE_INCOMPLETE = "privileged-state.csr-access-gate-incomplete"
    CSR_ACCESS_POLICY_INCOMPLETE = "privileged-state.csr-access-policy-incomplete"
    CSR_REQUIRED_PRIVILEGE_UNKNOWN = "privileged-state.csr-required-privilege-unknown"
    CSR_ACCESS_TRAP_UNMODELLED = "privileged-state.csr-access-trap-unmodelled"
    TRAP_EFFECT_INCOMPLETE = "privileged-state.trap-effect-incomplete"
    TRAP_BINDING_INCOMPLETE = "privileged-state.trap-binding-incomplete"
    TRAP_DELEGATION_INCOMPLETE = "privileged-state.trap-delegation-incomplete"
    RETURN_EFFECT_INCOMPLETE = "privileged-state.return-effect-incomplete"
    RETURN_KIND_UNCLASSIFIED = "privileged-state.return-kind-unclassified"
    INTERRUPT_EFFECT_INCOMPLETE = "privileged-state.interrupt-effect-incomplete"
    MMU_EFFECT_INCOMPLETE = "privileged-state.mmu-effect-incomplete"
    MMU_SCOPE_INCOMPLETE = "privileged-state.mmu-scope-incomplete"
    VIRTUALIZATION_EFFECT_INCOMPLETE = "privileged-state.virtualization-effect-incomplete"
    DEBUG_EFFECT_INCOMPLETE = "privileged-state.debug-effect-incomplete"


class CsrSemanticClass(str, Enum):
    USER_COUNTER_OBSERVATION = "user_counter_observation"
    FPU_STATE = "fpu_state"
    PRIVILEGED_STATUS = "privileged_status"
    COUNTER_CONTROL = "counter_control"
    STATE_ENABLE = "state_enable"
    ADDRESS_TRANSLATION = "address_translation"
    INTERRUPT_STATE = "interrupt_state"
    PMP_STATE = "pmp_state"
    DEBUG_STATE = "debug_state"
    VIRTUALIZATION_STATE = "virtualization_state"
    OTHER = "other"
    UNKNOWN = "unknown"


class CsrEffectOperation(str, Enum):
    READ = "read"; WRITE = "write"; READ_WRITE = "read_write"
    SET_BITS = "set_bits"; CLEAR_BITS = "clear_bits"; UNKNOWN = "unknown"


class TrapEffectKind(str, Enum):
    ENVIRONMENT_CALL = "environment_call"; BREAKPOINT = "breakpoint"
    ACCESS_FAULT = "access_fault"; ILLEGAL_INSTRUCTION = "illegal_instruction"
    OTHER = "other"; UNKNOWN = "unknown"


class PrivilegeReturnKind(str, Enum):
    MRET = "mret"; SRET = "sret"; URET = "uret"; DRET = "dret"
    UNKNOWN = "unknown"


class InterruptEffectKind(str, Enum):
    WAIT = "wait"; ENABLE_CHANGE = "enable_change"
    PENDING_CHANGE = "pending_change"; DELEGATION_CHANGE = "delegation_change"
    OTHER = "other"; UNKNOWN = "unknown"


class AddressTranslationEffectKind(str, Enum):
    ROOT_CHANGE = "root_change"; TLB_INVALIDATION = "tlb_invalidation"
    ADDRESS_SPACE_CHANGE = "address_space_change"; OTHER = "other"
    UNKNOWN = "unknown"


class VirtualizationEffectKind(str, Enum):
    GUEST_STATE = "guest_state"; STAGE2_TRANSLATION = "stage2_translation"
    VIRTUAL_INTERRUPT = "virtual_interrupt"; OTHER = "other"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CsrFieldEffect:
    field_id: str
    old_value_binding: str | None
    new_value_binding: str | None
    writable_mask: int | None
    warl_or_wlrl_policy_id: str | None
    side_effect_ids: tuple[str, ...]
    complete: bool
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class CsrEffect:
    # Legacy positional prefix is retained for API compatibility.
    block_address: int
    operation_index: int
    csr_id: str
    operation: CsrEffectOperation
    required_privilege_mode: SourcePrivilegeMode | None
    access_allowed: bool | None
    may_trap: bool | None
    complete: bool
    csr_class: CsrSemanticClass = CsrSemanticClass.UNKNOWN
    read_value_node_id: str | None = None
    write_value_node_id: str | None = None
    immediate_mask: int | None = None
    read_modify_write: bool = False
    affected_fields: tuple[CsrFieldEffect, ...] = ()
    xlen_bits: int | None = None
    required_extension_id: str | None = None
    access_gate_ids: tuple[str, ...] = ()
    access_policy_complete: bool = False
    trap_binding_id: str | None = None
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrapEffect:
    block_address: int
    operation_index: int
    kind: TrapEffectKind
    complete: bool
    cause: str | None = None
    tval_binding: str | None = None
    source_privilege: SourcePrivilegeMode | None = None
    target_privilege: SourcePrivilegeMode | None = None
    handler_binding_id: str | None = None
    saved_pc_binding: str | None = None
    saved_status_effects: tuple[str, ...] = ()
    delegation_path: tuple[str, ...] = ()
    continuation: str | None = None
    externally_observable: bool | None = None
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PrivilegeReturnEffect:
    block_address: int
    operation_index: int
    kind: PrivilegeReturnKind
    complete: bool
    restored_privilege_mode: SourcePrivilegeMode | None = None
    restored_interrupt_state: str | None = None
    return_pc_binding: str | None = None
    status_field_effects: tuple[str, ...] = ()
    continuation_identity: str | None = None
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class InterruptEffect:
    block_address: int
    operation_index: int
    kind: InterruptEffectKind
    complete: bool
    enable_state: str | None = None
    pending_state: str | None = None
    delegation_path: tuple[str, ...] = ()
    priority: int | None = None
    interruptibility: bool | None = None
    event_source: str | None = None
    wait_wakeup_relation: str | None = None
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class AddressTranslationEffect:
    block_address: int
    operation_index: int
    kind: AddressTranslationEffectKind
    complete: bool
    root_binding: str | None = None
    mode: str | None = None
    asid: int | None = None
    vmid: int | None = None
    virtual_address_scope: str | None = None
    address_space_identity: str | None = None
    synchronization_scope: str | None = None
    shootdown_required: bool | None = None
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class VirtualizationEffect:
    block_address: int
    operation_index: int
    kind: VirtualizationEffectKind
    complete: bool
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class DebugStateEffect:
    block_address: int
    operation_index: int
    kind: str
    complete: bool
    missing_fact_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourcePrivilegedStateModel:
    execution_profile: SourceExecutionProfile
    target_execution_mode: TargetExecutionMode
    initial_privilege_mode: SourcePrivilegeMode
    source_privilege_spec_version: str | None
    source_isa_extensions: tuple[str, ...]
    csr_effects: tuple[CsrEffect, ...]
    trap_effects: tuple[TrapEffect, ...]
    return_effects: tuple[PrivilegeReturnEffect, ...]
    interrupt_effects: tuple[InterruptEffect, ...]
    address_translation_effects: tuple[AddressTranslationEffect, ...]
    virtualization_effects: tuple[VirtualizationEffect, ...]
    debug_effects: tuple[DebugStateEffect, ...]
    access_permissions_complete: bool
    control_transfer_complete: bool
    present: bool
    complete: bool
    missing_fact_codes: tuple[str, ...]
    effect_model_version: str = "privileged-effect-model.v2"
    delegation_model_id: str | None = None
    interrupt_model_id: str | None = None
    virtual_memory_model_id: str | None = None
    trap_handler_binding_id: str | None = None
    address_space_identity: str | None = None
    target_runtime_contract_set_id: str | None = None
    execution_environment_complete: bool = False

    def __post_init__(self) -> None:
        for values in (
            self.csr_effects, self.trap_effects, self.return_effects,
            self.interrupt_effects, self.address_translation_effects,
            self.virtualization_effects, self.debug_effects,
        ):
            if tuple(sorted(values, key=_site_key)) != values:
                raise ValueError("privileged effects must use stable sorting")
        if tuple(sorted(set(self.missing_fact_codes))) != self.missing_fact_codes:
            raise ValueError("privileged model reasons must be unique and sorted")
        if self.complete and self.missing_fact_codes:
            raise ValueError("complete privileged state cannot have reasons")
        if not self.complete and not self.missing_fact_codes:
            raise ValueError("incomplete privileged state requires reasons")
        if self.present and self.complete and not self.execution_environment_complete:
            raise ValueError("complete privileged model needs complete environment")
        if self.complete and any(
            not item.complete
            for values in (
                self.csr_effects, self.trap_effects, self.return_effects,
                self.interrupt_effects, self.address_translation_effects,
                self.virtualization_effects, self.debug_effects,
            )
            for item in values
        ):
            raise ValueError("complete model contains incomplete effect")


def _site_key(value: object) -> tuple[int, int, str]:
    return (
        int(getattr(value, "block_address")),
        int(getattr(value, "operation_index")),
        str(getattr(value, "csr_id", getattr(value, "kind", ""))),
    )


def _ordered(values: Iterable[str | PrivilegedStateReasonCode]) -> tuple[str, ...]:
    return tuple(sorted(set(
        item.value if isinstance(item, PrivilegedStateReasonCode) else item
        for item in values if item
    )))


def _enum_or_unknown(enum_type, value):
    if value is None:
        return enum_type.UNKNOWN
    try:
        return enum_type(value.strip().lower())
    except (ValueError, AttributeError):
        return enum_type.UNKNOWN


def _privilege_mode(value: object) -> SourcePrivilegeMode | None:
    if value is None:
        return None
    try:
        return SourcePrivilegeMode(str(value).strip().lower())
    except ValueError:
        return None


def _csr_operation(value: object) -> CsrEffectOperation:
    if value is None:
        return CsrEffectOperation.UNKNOWN
    try:
        return CsrEffectOperation(value.value)
    except (ValueError, AttributeError):
        return CsrEffectOperation.UNKNOWN


def _mode_satisfies(
    current: SourcePrivilegeMode, required: SourcePrivilegeMode | None
) -> bool | None:
    if required is None:
        return None
    if current is required:
        return True
    rank = {
        SourcePrivilegeMode.U: 0, SourcePrivilegeMode.S: 1,
        SourcePrivilegeMode.HS: 1, SourcePrivilegeMode.M: 2,
    }
    if current in rank and required in rank:
        return rank[current] >= rank[required]
    if current is SourcePrivilegeMode.VS and required in {
        SourcePrivilegeMode.VS, SourcePrivilegeMode.VU,
    }:
        return True
    if current is SourcePrivilegeMode.VU and required is SourcePrivilegeMode.VU:
        return True
    return None


def _csr_access(facts, csr_id, operation, required=None):
    policy = facts.csr_access_policy
    if not policy.complete:
        return None, False
    reads = operation in {
        CsrEffectOperation.READ, CsrEffectOperation.READ_WRITE,
        CsrEffectOperation.SET_BITS, CsrEffectOperation.CLEAR_BITS,
    }
    writes = operation in {
        CsrEffectOperation.WRITE, CsrEffectOperation.READ_WRITE,
        CsrEffectOperation.SET_BITS, CsrEffectOperation.CLEAR_BITS,
    }
    listed = (
        (not reads or csr_id in policy.readable_csr_ids)
        and (not writes or csr_id in policy.writable_csr_ids)
    )
    mode_allowed = _mode_satisfies(facts.initial_privilege_mode, required)
    if listed and mode_allowed is True:
        return True, True
    if mode_allowed is False:
        return False, True
    if not listed and policy.unknown_access in {
        UnknownCsrAccessDisposition.DENY,
        UnknownCsrAccessDisposition.TRAP,
    }:
        return False, True
    return None, False


def _canonical_csr_id(name, facts):
    value = (name or "").strip().lower()
    if not value:
        return None
    policy_ids = (
        facts.csr_access_policy.readable_csr_ids
        + facts.csr_access_policy.writable_csr_ids
    )
    aliases = {item: item for item in policy_ids}
    aliases.update({item.rsplit(".", 1)[-1]: item for item in policy_ids})
    return value if value.startswith("riscv.csr.") else aliases.get(value)


def _field_effect(
    item: CanonicalCsrFieldEffect,
    *,
    write_required: bool,
) -> CsrFieldEffect:
    reasons: list[str | PrivilegedStateReasonCode] = []
    if not item.field_id:
        reasons.append(PrivilegedStateReasonCode.CSR_FIELD_EFFECT_INCOMPLETE)
    if write_required and item.new_value_node_id is None:
        reasons.append(PrivilegedStateReasonCode.CSR_VALUE_FLOW_INCOMPLETE)
    if write_required and item.writable_mask is None:
        reasons.append(PrivilegedStateReasonCode.CSR_FIELD_EFFECT_INCOMPLETE)
    if write_required and not item.warl_or_wlrl_policy_id:
        reasons.append(PrivilegedStateReasonCode.CSR_WARL_WLRL_POLICY_INCOMPLETE)
    if not item.complete:
        reasons.append(PrivilegedStateReasonCode.CSR_FIELD_EFFECT_INCOMPLETE)
    missing = _ordered(reasons)
    return CsrFieldEffect(
        field_id=item.field_id,
        old_value_binding=item.old_value_node_id,
        new_value_binding=item.new_value_node_id,
        writable_mask=item.writable_mask,
        warl_or_wlrl_policy_id=item.warl_or_wlrl_policy_id,
        side_effect_ids=tuple(sorted(set(item.side_effect_ids))),
        complete=not missing,
        missing_fact_codes=missing,
    )


def _typed_csr_effect(block_address, operation_index, meta, facts) -> CsrEffect:
    reasons: list[str | PrivilegedStateReasonCode] = []
    csr_id = (meta.csr_id or "").strip().lower()
    csr_class = _enum_or_unknown(CsrSemanticClass, meta.csr_semantic_class)
    operation = _csr_operation(meta.csr_operation)
    required = _privilege_mode(meta.required_privilege_mode)
    reads = operation in {
        CsrEffectOperation.READ, CsrEffectOperation.READ_WRITE,
        CsrEffectOperation.SET_BITS, CsrEffectOperation.CLEAR_BITS,
    }
    writes = operation in {
        CsrEffectOperation.WRITE, CsrEffectOperation.READ_WRITE,
        CsrEffectOperation.SET_BITS, CsrEffectOperation.CLEAR_BITS,
    }
    if not csr_id.startswith("riscv.csr."):
        reasons.append(PrivilegedStateReasonCode.CSR_IDENTITY_UNKNOWN)
    if csr_class is CsrSemanticClass.UNKNOWN:
        reasons.append(PrivilegedStateReasonCode.CSR_CLASS_UNKNOWN)
    if operation is CsrEffectOperation.UNKNOWN:
        reasons.append(PrivilegedStateReasonCode.CSR_OPERATION_UNKNOWN)
    if reads and not meta.read_value_node_id:
        reasons.append(PrivilegedStateReasonCode.CSR_VALUE_FLOW_INCOMPLETE)
    if writes and not meta.write_value_node_id and meta.immediate_mask is None:
        reasons.append(PrivilegedStateReasonCode.CSR_VALUE_FLOW_INCOMPLETE)
    if operation in {CsrEffectOperation.SET_BITS, CsrEffectOperation.CLEAR_BITS}:
        if meta.immediate_mask is None and not meta.write_value_node_id:
            reasons.append(PrivilegedStateReasonCode.CSR_IMMEDIATE_MASK_INCOMPLETE)
    expected_rmw = operation in {
        CsrEffectOperation.READ_WRITE,
        CsrEffectOperation.SET_BITS,
        CsrEffectOperation.CLEAR_BITS,
    }
    if meta.read_modify_write is None or meta.read_modify_write != expected_rmw:
        reasons.append(PrivilegedStateReasonCode.CSR_OPERATION_UNKNOWN)
    if meta.xlen_bits not in {32, 64}:
        reasons.append(PrivilegedStateReasonCode.CSR_XLEN_UNKNOWN)
    extension = (meta.required_extension_id or "").strip().lower() or None
    if extension is None or extension not in facts.source_isa_extensions:
        reasons.append(PrivilegedStateReasonCode.CSR_EXTENSION_UNPROVEN)
    if required is None:
        reasons.append(PrivilegedStateReasonCode.CSR_REQUIRED_PRIVILEGE_UNKNOWN)

    allowed, permission_complete = _csr_access(
        facts, csr_id, operation, required
    )
    if not permission_complete:
        reasons.append(PrivilegedStateReasonCode.CSR_ACCESS_POLICY_INCOMPLETE)
    if not meta.access_gate_evaluation_complete:
        reasons.append(PrivilegedStateReasonCode.CSR_ACCESS_GATE_INCOMPLETE)

    fields = tuple(
        _field_effect(item, write_required=writes)
        for item in meta.affected_csr_fields
    )
    if writes and not fields:
        reasons.append(PrivilegedStateReasonCode.CSR_FIELD_EFFECT_INCOMPLETE)
    for field in fields:
        reasons.extend(field.missing_fact_codes)

    may_trap = meta.may_trap
    if may_trap is None and allowed is not None:
        may_trap = not allowed
    if may_trap is None:
        reasons.append(PrivilegedStateReasonCode.TRAP_EFFECT_INCOMPLETE)
    trap_binding = (
        meta.handler_binding_id
        or facts.trap_handler_binding_id
        if may_trap else None
    )
    if may_trap and not trap_binding:
        reasons.append(PrivilegedStateReasonCode.TRAP_BINDING_INCOMPLETE)
    if not meta.state_complete:
        reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)

    missing = _ordered(reasons)
    return CsrEffect(
        block_address=block_address,
        operation_index=operation_index,
        csr_id=csr_id,
        operation=operation,
        required_privilege_mode=required,
        access_allowed=allowed,
        may_trap=may_trap,
        complete=not missing,
        csr_class=csr_class,
        read_value_node_id=meta.read_value_node_id,
        write_value_node_id=meta.write_value_node_id,
        immediate_mask=meta.immediate_mask,
        read_modify_write=bool(meta.read_modify_write),
        affected_fields=fields,
        xlen_bits=meta.xlen_bits,
        required_extension_id=extension,
        access_gate_ids=tuple(sorted(set(meta.access_gate_ids))),
        access_policy_complete=permission_complete,
        trap_binding_id=trap_binding,
        missing_fact_codes=missing,
    )


def _derived_csr_effects(blocks, facts, typed_sites):
    """Inventory untyped canonical CSR data flow, always incomplete in V2."""
    grouped = {}
    for block in blocks:
        for index, op in enumerate(block.ops):
            output_id = (
                _canonical_csr_id(op.output.name, facts)
                if op.output is not None and op.output.kind is VarKind.REG
                else None
            )
            input_ids = {
                csr_id for item in op.inputs if item.kind is VarKind.REG
                for csr_id in (_canonical_csr_id(item.name, facts),)
                if csr_id is not None
            }
            for csr_id in input_ids | ({output_id} if output_id else set()):
                key = (block.addr, op.addr, csr_id)
                entry = grouped.setdefault(
                    key, {"index": index, "read": False, "write": False}
                )
                entry["index"] = min(entry["index"], index)
                entry["read"] = bool(entry["read"] or csr_id in input_ids)
                entry["write"] = bool(entry["write"] or csr_id == output_id)
    result = []
    for (block_address, _addr, csr_id), item in grouped.items():
        site = (block_address, item["index"], csr_id)
        if site in typed_sites:
            continue
        operation = (
            CsrEffectOperation.READ_WRITE
            if item["read"] and item["write"]
            else CsrEffectOperation.READ
            if item["read"] else CsrEffectOperation.WRITE
        )
        allowed, permission_complete = _csr_access(
            facts, csr_id, operation, None
        )
        missing = _ordered((
            PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE,
            PrivilegedStateReasonCode.CSR_CLASS_UNKNOWN,
            PrivilegedStateReasonCode.CSR_VALUE_FLOW_INCOMPLETE,
            PrivilegedStateReasonCode.CSR_XLEN_UNKNOWN,
            PrivilegedStateReasonCode.CSR_EXTENSION_UNPROVEN,
            PrivilegedStateReasonCode.CSR_REQUIRED_PRIVILEGE_UNKNOWN,
        ))
        result.append(CsrEffect(
            block_address, item["index"], csr_id, operation, None,
            allowed, None, False,
            access_policy_complete=permission_complete,
            missing_fact_codes=missing,
        ))
    return tuple(sorted(result, key=_site_key))


def _trap_effect(block_address, operation_index, meta, facts):
    reasons: list[str | PrivilegedStateReasonCode] = []
    kind = _enum_or_unknown(TrapEffectKind, meta.trap_kind)
    cause = (meta.trap_cause or "").strip() or None
    target = _privilege_mode(meta.trap_target_privilege_mode)
    handler = meta.handler_binding_id or facts.trap_handler_binding_id
    delegation = tuple(meta.delegation_path)
    if kind is TrapEffectKind.UNKNOWN or cause is None:
        reasons.append(PrivilegedStateReasonCode.TRAP_EFFECT_INCOMPLETE)
    if target is None or not handler or not meta.saved_pc_node_id:
        reasons.append(PrivilegedStateReasonCode.TRAP_BINDING_INCOMPLETE)
    if not meta.tval_node_id or not meta.saved_status_effect_ids:
        reasons.append(PrivilegedStateReasonCode.TRAP_EFFECT_INCOMPLETE)
    if not delegation or facts.delegation_model is None:
        reasons.append(PrivilegedStateReasonCode.TRAP_DELEGATION_INCOMPLETE)
    if not meta.continuation_identity or meta.externally_observable is None:
        reasons.append(PrivilegedStateReasonCode.TRAP_EFFECT_INCOMPLETE)
    if not meta.state_complete:
        reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)
    missing = _ordered(reasons)
    return TrapEffect(
        block_address, operation_index, kind, not missing,
        cause, meta.tval_node_id, facts.initial_privilege_mode, target,
        handler, meta.saved_pc_node_id,
        tuple(sorted(set(meta.saved_status_effect_ids))), delegation,
        meta.continuation_identity, meta.externally_observable, missing,
    )


def _return_effect(block_address, operation_index, meta):
    reasons: list[str | PrivilegedStateReasonCode] = []
    kind = _enum_or_unknown(PrivilegeReturnKind, meta.return_kind)
    restored = _privilege_mode(meta.restored_privilege_mode)
    if kind is PrivilegeReturnKind.UNKNOWN:
        reasons.append(PrivilegedStateReasonCode.RETURN_EFFECT_INCOMPLETE)
    if (
        restored is None or not meta.restored_interrupt_state
        or not meta.return_pc_node_id or not meta.status_field_effect_ids
        or not meta.continuation_identity
    ):
        reasons.append(PrivilegedStateReasonCode.RETURN_EFFECT_INCOMPLETE)
    if not meta.state_complete:
        reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)
    missing = _ordered(reasons)
    return PrivilegeReturnEffect(
        block_address, operation_index, kind, not missing, restored,
        meta.restored_interrupt_state, meta.return_pc_node_id,
        tuple(sorted(set(meta.status_field_effect_ids))),
        meta.continuation_identity, missing,
    )


def _interrupt_effect(block_address, operation_index, meta, facts):
    reasons: list[str | PrivilegedStateReasonCode] = []
    kind = _enum_or_unknown(InterruptEffectKind, meta.interrupt_kind)
    if kind is InterruptEffectKind.UNKNOWN:
        reasons.append(PrivilegedStateReasonCode.INTERRUPT_EFFECT_INCOMPLETE)
    required = (
        meta.interrupt_enable_state,
        meta.interrupt_pending_state,
        meta.interruptibility,
        meta.event_source_id,
    )
    if any(value is None for value in required):
        reasons.append(PrivilegedStateReasonCode.INTERRUPT_EFFECT_INCOMPLETE)
    if kind is InterruptEffectKind.WAIT and not meta.wait_wakeup_relation_id:
        reasons.append(PrivilegedStateReasonCode.INTERRUPT_EFFECT_INCOMPLETE)
    if (
        not meta.interrupt_delegation_path
        or facts.interrupt_model is None
        or facts.delegation_model is None
    ):
        reasons.append(PrivilegedStateReasonCode.INTERRUPT_EFFECT_INCOMPLETE)
    if not meta.state_complete:
        reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)
    missing = _ordered(reasons)
    return InterruptEffect(
        block_address, operation_index, kind, not missing,
        meta.interrupt_enable_state, meta.interrupt_pending_state,
        tuple(meta.interrupt_delegation_path), meta.interrupt_priority,
        meta.interruptibility, meta.event_source_id,
        meta.wait_wakeup_relation_id, missing,
    )


def _mmu_effect(block_address, operation_index, meta, facts):
    reasons: list[str | PrivilegedStateReasonCode] = []
    kind = _enum_or_unknown(
        AddressTranslationEffectKind, meta.address_translation_kind
    )
    address_identity = (
        meta.address_space_identity or facts.address_space_identity
    )
    if kind is AddressTranslationEffectKind.UNKNOWN:
        reasons.append(PrivilegedStateReasonCode.MMU_EFFECT_INCOMPLETE)
    if (
        not meta.translation_mode or not meta.virtual_address_scope
        or not address_identity or not meta.synchronization_scope
        or meta.shootdown_required is None
    ):
        reasons.append(PrivilegedStateReasonCode.MMU_SCOPE_INCOMPLETE)
    if facts.virtual_memory_model is None:
        reasons.append(PrivilegedStateReasonCode.MMU_EFFECT_INCOMPLETE)
    if kind is AddressTranslationEffectKind.ROOT_CHANGE and not meta.translation_root_node_id:
        reasons.append(PrivilegedStateReasonCode.MMU_EFFECT_INCOMPLETE)
    # A TLB invalidation must state both ASID and VMID scope.  A wildcard is
    # represented by an explicit negative-free sentinel in canonical metadata,
    # never by None.
    if kind is AddressTranslationEffectKind.TLB_INVALIDATION and (
        meta.asid is None or meta.vmid is None
    ):
        reasons.append(PrivilegedStateReasonCode.MMU_SCOPE_INCOMPLETE)
    if not meta.state_complete:
        reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)
    missing = _ordered(reasons)
    return AddressTranslationEffect(
        block_address, operation_index, kind, not missing,
        meta.translation_root_node_id, meta.translation_mode,
        meta.asid, meta.vmid, meta.virtual_address_scope,
        address_identity, meta.synchronization_scope,
        meta.shootdown_required, missing,
    )


def analyze_privileged_state(
    *, fragment_id: str, blocks: Sequence[Block],
    cfg: CFGResult | None,
    execution_facts: PrivilegedExecutionFacts | None,
) -> SourcePrivilegedStateModel:
    facts = execution_facts or default_user_process_execution_facts(fragment_id)
    if facts.fragment_id != fragment_id:
        raise ValueError("privileged execution facts belong to another fragment")

    reasons: list[str | PrivilegedStateReasonCode] = []
    csr = []; traps = []; returns = []; interrupts = []; mmu = []; virt = []; debug = []
    typed_sites = set(); typed_instruction_sites = set(); callother_sites = set()

    for block in sorted(blocks, key=lambda item: item.addr):
        index_by_address = {}
        for index, op in enumerate(block.ops):
            index_by_address.setdefault(op.addr, index)
            if op.opcode.upper() == "CALLOTHER":
                callother_sites.add((block.addr, op.addr))
        for instruction_index, instruction in enumerate(block.instructions):
            operation_index = index_by_address.get(
                instruction.addr, instruction_index
            )
            if instruction.privileged_metadata_invalid:
                typed_instruction_sites.add((block.addr, instruction.addr))
                reasons.append(
                    PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE
                )
            for meta in instruction.privileged_operations:
                typed_instruction_sites.add((block.addr, instruction.addr))
                if meta.kind is CanonicalPrivilegedOperationKind.CSR_ACCESS:
                    effect = _typed_csr_effect(
                        block.addr, operation_index, meta, facts
                    )
                    csr.append(effect)
                    typed_sites.add((block.addr, operation_index, effect.csr_id))
                elif meta.kind is CanonicalPrivilegedOperationKind.TRAP:
                    traps.append(_trap_effect(
                        block.addr, operation_index, meta, facts
                    ))
                elif meta.kind is CanonicalPrivilegedOperationKind.PRIVILEGE_RETURN:
                    returns.append(_return_effect(
                        block.addr, operation_index, meta
                    ))
                elif meta.kind is CanonicalPrivilegedOperationKind.INTERRUPT_STATE:
                    interrupts.append(_interrupt_effect(
                        block.addr, operation_index, meta, facts
                    ))
                elif meta.kind is CanonicalPrivilegedOperationKind.ADDRESS_TRANSLATION:
                    mmu.append(_mmu_effect(
                        block.addr, operation_index, meta, facts
                    ))
                elif meta.kind is CanonicalPrivilegedOperationKind.VIRTUALIZATION_STATE:
                    kind = _enum_or_unknown(
                        VirtualizationEffectKind, meta.virtualization_kind
                    )
                    missing = _ordered((
                        PrivilegedStateReasonCode.VIRTUALIZATION_EFFECT_INCOMPLETE
                        if (
                            kind is VirtualizationEffectKind.UNKNOWN
                            or facts.virtual_memory_model is None
                            or not meta.state_complete
                        ) else "",
                    ))
                    virt.append(VirtualizationEffect(
                        block.addr, operation_index, kind, not missing, missing
                    ))
                elif meta.kind is CanonicalPrivilegedOperationKind.DEBUG_STATE:
                    kind = (meta.debug_kind or "").strip().lower()
                    missing = _ordered((
                        PrivilegedStateReasonCode.DEBUG_EFFECT_INCOMPLETE
                        if not kind or not meta.state_complete else "",
                    ))
                    debug.append(DebugStateEffect(
                        block.addr, operation_index, kind or "unknown",
                        not missing, missing,
                    ))

    csr.extend(_derived_csr_effects(blocks, facts, typed_sites))
    for values in (csr, traps, returns, interrupts, mmu, virt, debug):
        for effect in values:
            reasons.extend(effect.missing_fact_codes)

    unclassified = callother_sites - typed_instruction_sites
    present = bool(
        csr or traps or returns or interrupts or mmu or virt or debug
        or unclassified or reasons
    )
    if unclassified:
        reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)
    if (
        facts.source_execution_profile is not SourceExecutionProfile.RISCV_USER_PROCESS
        and any(block.terminator_kind.lower() == "return" for block in blocks)
        and not returns
    ):
        present = True
        reasons.append(PrivilegedStateReasonCode.RETURN_KIND_UNCLASSIFIED)
    if present and not facts.complete:
        reasons.append(PrivilegedStateReasonCode.EXECUTION_FACTS_INCOMPLETE)
        reasons.extend(facts.missing_fact_codes)

    cfg_complete = (
        cfg is not None and cfg.ok
        and all(block.addr in cfg.nodes for block in blocks)
    )
    if present and not cfg_complete:
        reasons.append(PrivilegedStateReasonCode.CFG_INCOMPLETE)

    trap_sites = {
        (item.block_address, item.operation_index) for item in traps
    }
    for item in csr:
        if (
            item.access_allowed is False
            and (item.block_address, item.operation_index) not in trap_sites
        ):
            reasons.append(
                PrivilegedStateReasonCode.CSR_ACCESS_TRAP_UNMODELLED
            )

    access_complete = all(
        item.complete and item.access_policy_complete
        and item.access_allowed is not None
        for item in csr
    )
    control_complete = all(
        item.complete for item in (*traps, *returns)
    )
    reason_codes = _ordered(reasons)
    complete = not present or not reason_codes
    return SourcePrivilegedStateModel(
        execution_profile=facts.source_execution_profile,
        target_execution_mode=facts.target_execution_mode,
        initial_privilege_mode=facts.initial_privilege_mode,
        source_privilege_spec_version=facts.source_privilege_spec_version,
        source_isa_extensions=facts.source_isa_extensions,
        csr_effects=tuple(sorted(csr, key=_site_key)),
        trap_effects=tuple(sorted(traps, key=_site_key)),
        return_effects=tuple(sorted(returns, key=_site_key)),
        interrupt_effects=tuple(sorted(interrupts, key=_site_key)),
        address_translation_effects=tuple(sorted(mmu, key=_site_key)),
        virtualization_effects=tuple(sorted(virt, key=_site_key)),
        debug_effects=tuple(sorted(debug, key=_site_key)),
        access_permissions_complete=access_complete,
        control_transfer_complete=control_complete,
        present=present,
        complete=complete,
        missing_fact_codes=reason_codes,
        delegation_model_id=facts.delegation_model_id,
        interrupt_model_id=facts.interrupt_model_id,
        virtual_memory_model_id=facts.virtual_memory_model_id,
        trap_handler_binding_id=facts.trap_handler_binding_id,
        address_space_identity=facts.address_space_identity,
        target_runtime_contract_set_id=facts.target_runtime_contract_set_id,
        execution_environment_complete=facts.complete,
    )
