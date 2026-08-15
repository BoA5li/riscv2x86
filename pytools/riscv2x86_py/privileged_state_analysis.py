"""Phase-5 privileged-state analysis over canonical machine semantics.

Only canonical ops, typed decoder metadata, CFG facts, and the Phase-4
execution sidecar are consumed. Raw assembly and mnemonic text are never an
authority for classification.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence

from .cfg import CFGResult
from .pcode_ir import (
    Block, CanonicalCsrOperationKind, CanonicalPrivilegedOperationKind,
    VarKind,
)
from .privileged_execution_sidecar import (
    PrivilegedExecutionFacts, SourceExecutionProfile, SourcePrivilegeMode,
    UnknownCsrAccessDisposition, default_user_process_execution_facts,
)


class PrivilegedStateReasonCode(str, Enum):
    EXECUTION_FACTS_INCOMPLETE = "privileged-state.execution-facts-incomplete"
    CFG_INCOMPLETE = "privileged-state.cfg-incomplete"
    CANONICAL_METADATA_INCOMPLETE = "privileged-state.canonical-privileged-metadata-incomplete"
    CSR_IDENTITY_UNKNOWN = "privileged-state.csr-identity-unknown"
    CSR_OPERATION_UNKNOWN = "privileged-state.csr-operation-unknown"
    CSR_ACCESS_POLICY_INCOMPLETE = "privileged-state.csr-access-policy-incomplete"
    CSR_REQUIRED_PRIVILEGE_UNKNOWN = "privileged-state.csr-required-privilege-unknown"
    CSR_ACCESS_TRAP_UNMODELLED = "privileged-state.csr-access-trap-unmodelled"
    TRAP_EFFECT_INCOMPLETE = "privileged-state.trap-effect-incomplete"
    RETURN_EFFECT_INCOMPLETE = "privileged-state.return-effect-incomplete"
    RETURN_KIND_UNCLASSIFIED = "privileged-state.return-kind-unclassified"
    INTERRUPT_EFFECT_INCOMPLETE = "privileged-state.interrupt-effect-incomplete"
    MMU_EFFECT_INCOMPLETE = "privileged-state.mmu-effect-incomplete"
    VIRTUALIZATION_EFFECT_INCOMPLETE = "privileged-state.virtualization-effect-incomplete"
    DEBUG_EFFECT_INCOMPLETE = "privileged-state.debug-effect-incomplete"


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
class CsrEffect:
    block_address:int; operation_index:int; csr_id:str
    operation:CsrEffectOperation; required_privilege_mode:SourcePrivilegeMode|None
    access_allowed:bool|None; may_trap:bool|None; complete:bool


@dataclass(frozen=True)
class TrapEffect:
    block_address:int; operation_index:int; kind:TrapEffectKind; complete:bool


@dataclass(frozen=True)
class PrivilegeReturnEffect:
    block_address:int; operation_index:int; kind:PrivilegeReturnKind; complete:bool


@dataclass(frozen=True)
class InterruptEffect:
    block_address:int; operation_index:int; kind:InterruptEffectKind; complete:bool


@dataclass(frozen=True)
class AddressTranslationEffect:
    block_address:int; operation_index:int; kind:AddressTranslationEffectKind; complete:bool


@dataclass(frozen=True)
class VirtualizationEffect:
    block_address:int; operation_index:int; kind:VirtualizationEffectKind; complete:bool


@dataclass(frozen=True)
class DebugStateEffect:
    block_address:int; operation_index:int; kind:str; complete:bool


@dataclass(frozen=True)
class SourcePrivilegedStateModel:
    execution_profile:SourceExecutionProfile
    initial_privilege_mode:SourcePrivilegeMode
    source_privilege_spec_version:str|None
    source_isa_extensions:tuple[str,...]
    csr_effects:tuple[CsrEffect,...]
    trap_effects:tuple[TrapEffect,...]
    return_effects:tuple[PrivilegeReturnEffect,...]
    interrupt_effects:tuple[InterruptEffect,...]
    address_translation_effects:tuple[AddressTranslationEffect,...]
    virtualization_effects:tuple[VirtualizationEffect,...]
    debug_effects:tuple[DebugStateEffect,...]
    access_permissions_complete:bool
    control_transfer_complete:bool
    present:bool
    complete:bool
    missing_fact_codes:tuple[str,...]

    def __post_init__(self):
        for values in (self.csr_effects,self.trap_effects,self.return_effects,
                       self.interrupt_effects,self.address_translation_effects,
                       self.virtualization_effects,self.debug_effects):
            if tuple(sorted(values,key=_site_key)) != values:
                raise ValueError("privileged effects must use stable sorting")
        if self.complete and self.missing_fact_codes:
            raise ValueError("complete privileged state cannot have reasons")
        if not self.complete and not self.missing_fact_codes:
            raise ValueError("incomplete privileged state requires reasons")


def _site_key(value):
    return (value.block_address,value.operation_index,
            str(getattr(value,"csr_id",getattr(value,"kind",""))))


def _ordered_reasons(values:Iterable[str|PrivilegedStateReasonCode]):
    return tuple(sorted(set(value.value if isinstance(value,PrivilegedStateReasonCode)
                            else value for value in values if value)))


def _enum_or_unknown(enum_type,value):
    if value is None:return enum_type.UNKNOWN
    try:return enum_type(value.strip().lower())
    except (ValueError,AttributeError):return enum_type.UNKNOWN


def _privilege_mode(value):
    if value is None:return None
    try:return SourcePrivilegeMode(value.strip().lower())
    except (ValueError,AttributeError):return None


def _csr_operation(value):
    return CsrEffectOperation.UNKNOWN if value is None else CsrEffectOperation(value.value)


def _mode_satisfies(
    current: SourcePrivilegeMode,
    required: SourcePrivilegeMode | None,
) -> bool | None:
    """Conservative privilege-order check, including virtualized modes."""
    if required is None:
        return None
    if current is required:
        return True
    ordinary_rank = {
        SourcePrivilegeMode.U: 0,
        SourcePrivilegeMode.S: 1,
        SourcePrivilegeMode.HS: 1,
        SourcePrivilegeMode.M: 2,
    }
    if current in ordinary_rank and required in ordinary_rank:
        return ordinary_rank[current] >= ordinary_rank[required]
    if current is SourcePrivilegeMode.VS and required in {
        SourcePrivilegeMode.VS,
        SourcePrivilegeMode.VU,
    }:
        return True
    if current is SourcePrivilegeMode.VU and required is SourcePrivilegeMode.VU:
        return True
    # Crossing host/guest privilege domains requires virtualization state
    # that is deliberately not guessed in this Phase-5 model.
    return None


def _csr_access(facts, csr_id, operation, required=None):
    policy=facts.csr_access_policy
    if not policy.complete:
        return None, False
    reads=operation in {CsrEffectOperation.READ,CsrEffectOperation.READ_WRITE,
                        CsrEffectOperation.SET_BITS,CsrEffectOperation.CLEAR_BITS}
    writes=operation in {CsrEffectOperation.WRITE,CsrEffectOperation.READ_WRITE,
                         CsrEffectOperation.SET_BITS,CsrEffectOperation.CLEAR_BITS}
    listed=((not reads or csr_id in policy.readable_csr_ids) and
            (not writes or csr_id in policy.writable_csr_ids))
    mode_allowed = _mode_satisfies(facts.initial_privilege_mode, required)
    if listed and mode_allowed is not False:
        return (True, True) if mode_allowed is True else (None, False)
    if mode_allowed is False:
        return False, True
    if policy.unknown_access in {UnknownCsrAccessDisposition.DENY,
                                 UnknownCsrAccessDisposition.TRAP}:
        return False, True
    return None, False


def _canonical_csr_id(name,facts):
    value=(name or "").strip().lower()
    if not value:return None
    policy_ids=(facts.csr_access_policy.readable_csr_ids+
                facts.csr_access_policy.writable_csr_ids)
    aliases={item:item for item in policy_ids}
    aliases.update({item.rsplit(".",1)[-1]:item for item in policy_ids})
    return value if value.startswith("riscv.csr.") else aliases.get(value)


def _derived_csr_effects(blocks,facts,typed_sites):
    grouped={}
    for block in blocks:
        for index,op in enumerate(block.ops):
            output_id=(_canonical_csr_id(op.output.name,facts)
                       if op.output is not None and op.output.kind is VarKind.REG else None)
            input_ids={csr_id for item in op.inputs if item.kind is VarKind.REG
                       for csr_id in (_canonical_csr_id(item.name,facts),)
                       if csr_id is not None}
            for csr_id in input_ids|({output_id} if output_id else set()):
                key=(block.addr,op.addr,csr_id)
                item=grouped.setdefault(key,{"index":index,"read":False,
                                             "write":False,"opcodes":set()})
                item["index"]=min(item["index"],index)
                item["read"]=bool(item["read"] or csr_id in input_ids)
                item["write"]=bool(item["write"] or csr_id==output_id)
                item["opcodes"].add(op.opcode.upper())
    result=[]
    for (block_address,_addr,csr_id),item in grouped.items():
        site=(block_address,item["index"],csr_id)
        if site in typed_sites:continue
        if item["read"] and item["write"] and "INT_OR" in item["opcodes"]:
            operation=CsrEffectOperation.SET_BITS
        elif item["read"] and item["write"]:operation=CsrEffectOperation.READ_WRITE
        elif item["read"]:operation=CsrEffectOperation.READ
        else:operation=CsrEffectOperation.WRITE
        allowed,permission_complete=_csr_access(facts,csr_id,operation)
        result.append(CsrEffect(block_address,item["index"],csr_id,operation,None,
                                allowed,False if allowed is True else True,
                                permission_complete))
    return tuple(sorted(result,key=_site_key))


def analyze_privileged_state(*,fragment_id:str,blocks:Sequence[Block],
                             cfg:CFGResult|None,
                             execution_facts:PrivilegedExecutionFacts|None):
    facts=execution_facts or default_user_process_execution_facts(fragment_id)
    if facts.fragment_id!=fragment_id:
        raise ValueError("privileged execution facts belong to another fragment")
    reasons=[]; csr=[]; traps=[]; returns=[]; interrupts=[]; mmu=[]; virt=[]; debug=[]
    typed_sites=set()
    typed_instruction_sites=set()
    callother_sites=set()
    for block in sorted(blocks,key=lambda item:item.addr):
        index_by_address={}
        for index,op in enumerate(block.ops):
            index_by_address.setdefault(op.addr,index)
            if op.opcode.upper() == "CALLOTHER":
                callother_sites.add((block.addr, op.addr))
        for instruction_index,instruction in enumerate(block.instructions):
            operation_index=index_by_address.get(instruction.addr,instruction_index)
            if instruction.privileged_metadata_invalid:
                typed_instruction_sites.add((block.addr, instruction.addr))
                reasons.append(
                    PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE
                )
            for meta in instruction.privileged_operations:
                typed_instruction_sites.add((block.addr, instruction.addr))
                complete=meta.state_complete
                if not complete:reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)
                if meta.kind is CanonicalPrivilegedOperationKind.CSR_ACCESS:
                    csr_id=(meta.csr_id or "").strip().lower(); operation=_csr_operation(meta.csr_operation)
                    required=_privilege_mode(meta.required_privilege_mode)
                    if not csr_id.startswith("riscv.csr."):
                        reasons.append(PrivilegedStateReasonCode.CSR_IDENTITY_UNKNOWN); complete=False
                    if operation is CsrEffectOperation.UNKNOWN:
                        reasons.append(PrivilegedStateReasonCode.CSR_OPERATION_UNKNOWN); complete=False
                    if required is None:
                        reasons.append(
                            PrivilegedStateReasonCode.CSR_REQUIRED_PRIVILEGE_UNKNOWN
                        )
                        complete = False
                    allowed,permission_complete=_csr_access(
                        facts, csr_id, operation, required
                    )
                    if not permission_complete:
                        reasons.append(PrivilegedStateReasonCode.CSR_ACCESS_POLICY_INCOMPLETE); complete=False
                    may_trap = meta.may_trap
                    if may_trap is None and allowed is not None:
                        may_trap = not allowed
                    csr.append(CsrEffect(block.addr,operation_index,csr_id,operation,
                                         required,allowed,may_trap,
                                         complete and permission_complete))
                    typed_sites.add((block.addr,operation_index,csr_id))
                elif meta.kind is CanonicalPrivilegedOperationKind.TRAP:
                    kind=_enum_or_unknown(TrapEffectKind,meta.trap_kind)
                    if kind is TrapEffectKind.UNKNOWN:
                        reasons.append(PrivilegedStateReasonCode.TRAP_EFFECT_INCOMPLETE); complete=False
                    traps.append(TrapEffect(block.addr,operation_index,kind,complete))
                elif meta.kind is CanonicalPrivilegedOperationKind.PRIVILEGE_RETURN:
                    kind=_enum_or_unknown(PrivilegeReturnKind,meta.return_kind)
                    if kind is PrivilegeReturnKind.UNKNOWN:
                        reasons.append(PrivilegedStateReasonCode.RETURN_EFFECT_INCOMPLETE); complete=False
                    returns.append(PrivilegeReturnEffect(block.addr,operation_index,kind,complete))
                elif meta.kind is CanonicalPrivilegedOperationKind.INTERRUPT_STATE:
                    kind=_enum_or_unknown(InterruptEffectKind,meta.interrupt_kind)
                    if kind is InterruptEffectKind.UNKNOWN:
                        reasons.append(PrivilegedStateReasonCode.INTERRUPT_EFFECT_INCOMPLETE); complete=False
                    interrupts.append(InterruptEffect(block.addr,operation_index,kind,complete))
                elif meta.kind is CanonicalPrivilegedOperationKind.ADDRESS_TRANSLATION:
                    kind=_enum_or_unknown(AddressTranslationEffectKind,meta.address_translation_kind)
                    if kind is AddressTranslationEffectKind.UNKNOWN:
                        reasons.append(PrivilegedStateReasonCode.MMU_EFFECT_INCOMPLETE); complete=False
                    mmu.append(AddressTranslationEffect(block.addr,operation_index,kind,complete))
                elif meta.kind is CanonicalPrivilegedOperationKind.VIRTUALIZATION_STATE:
                    kind=_enum_or_unknown(VirtualizationEffectKind,meta.virtualization_kind)
                    if kind is VirtualizationEffectKind.UNKNOWN:
                        reasons.append(PrivilegedStateReasonCode.VIRTUALIZATION_EFFECT_INCOMPLETE); complete=False
                    virt.append(VirtualizationEffect(block.addr,operation_index,kind,complete))
                elif meta.kind is CanonicalPrivilegedOperationKind.DEBUG_STATE:
                    kind=(meta.debug_kind or "").strip().lower()
                    if not kind:
                        reasons.append(PrivilegedStateReasonCode.DEBUG_EFFECT_INCOMPLETE); complete=False
                    debug.append(DebugStateEffect(block.addr,operation_index,kind or "unknown",complete))
    csr.extend(_derived_csr_effects(blocks,facts,typed_sites))
    for effect in csr:
        if effect.required_privilege_mode is None:
            reasons.append(
                PrivilegedStateReasonCode.CSR_REQUIRED_PRIVILEGE_UNKNOWN
            )
        if not effect.complete or effect.access_allowed is None:
            reasons.append(
                PrivilegedStateReasonCode.CSR_ACCESS_POLICY_INCOMPLETE
            )
    unclassified_callother_sites = callother_sites - typed_instruction_sites
    present=bool(csr or traps or returns or interrupts or mmu or virt or debug
                 or unclassified_callother_sites or reasons)
    if unclassified_callother_sites:
        reasons.append(PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE)
    if (facts.source_execution_profile is not SourceExecutionProfile.RISCV_USER_PROCESS
            and any(block.terminator_kind.lower()=="return" for block in blocks)
            and not returns):
        present=True; reasons.append(PrivilegedStateReasonCode.RETURN_KIND_UNCLASSIFIED)
    if present and not facts.complete:
        reasons.append(PrivilegedStateReasonCode.EXECUTION_FACTS_INCOMPLETE)
        reasons.extend(facts.missing_fact_codes)
    cfg_complete = (
        cfg is not None
        and cfg.ok
        and all(block.addr in cfg.nodes for block in blocks)
    )
    if present and not cfg_complete:
        reasons.append(PrivilegedStateReasonCode.CFG_INCOMPLETE)
    trap_sites={(item.block_address,item.operation_index) for item in traps}
    for item in csr:
        if item.access_allowed is False and (item.block_address,item.operation_index) not in trap_sites:
            reasons.append(PrivilegedStateReasonCode.CSR_ACCESS_TRAP_UNMODELLED)
    access_complete=all(item.complete and item.access_allowed is not None for item in csr)
    control_complete=all(item.complete for item in (*traps,*returns))
    reason_codes=_ordered_reasons(reasons)
    complete=not present or not reason_codes
    return SourcePrivilegedStateModel(
        facts.source_execution_profile,facts.initial_privilege_mode,
        facts.source_privilege_spec_version,facts.source_isa_extensions,
        tuple(sorted(csr,key=_site_key)),tuple(sorted(traps,key=_site_key)),
        tuple(sorted(returns,key=_site_key)),tuple(sorted(interrupts,key=_site_key)),
        tuple(sorted(mmu,key=_site_key)),tuple(sorted(virt,key=_site_key)),
        tuple(sorted(debug,key=_site_key)),access_complete,control_complete,
        present,complete,reason_codes)
