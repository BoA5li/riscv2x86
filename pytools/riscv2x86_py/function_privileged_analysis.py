"""Phase-4 declarations and Phase-5 whole-function privileged dataflow.

The analysis is deliberately function scoped.  Privilege returns and trap
continuations can never be approved as a replacement for one inline-asm
statement.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256

from .privileged_execution_sidecar import SourcePrivilegeMode
from .whole_function import FunctionExitKind, SourceFunctionControlFlowModel


@dataclass(frozen=True)
class FunctionPrivilegeExitMode:
    exit_id: str
    privilege_mode: SourcePrivilegeMode
    complete: bool


@dataclass(frozen=True)
class FunctionTrapHandlerBinding:
    binding_id: str
    entry_node_id: str
    entry_privilege_mode: SourcePrivilegeMode
    complete: bool


@dataclass(frozen=True)
class FunctionInterruptibilityRegion:
    region_id: str
    entry_node_id: str
    exit_node_id: str
    entry_interrupt_state: str
    exit_interrupt_state: str
    complete: bool


@dataclass(frozen=True)
class FunctionPrivilegedExecutionFacts:
    function_id: str
    entry_privilege_mode: SourcePrivilegeMode
    normal_exit_privilege_modes: tuple[FunctionPrivilegeExitMode, ...]
    exceptional_exit_modes: tuple[FunctionPrivilegeExitMode, ...]
    trap_handler_bindings: tuple[FunctionTrapHandlerBinding, ...]
    interruptibility_regions: tuple[FunctionInterruptibilityRegion, ...]
    address_space_identity: str | None
    member_fragment_ids: tuple[str, ...]
    complete: bool
    provenance: str
    missing_fact_codes: tuple[str, ...]
    has_nonlocal_transfer: bool | None = None
    has_unwind: bool | None = None
    has_signal_sensitive_state: bool | None = None
    has_setjmp_longjmp: bool | None = None

    def __post_init__(self) -> None:
        if not self.function_id or not self.provenance:
            raise ValueError("function privileged facts require identity and provenance")
        for values, key in (
            (self.normal_exit_privilege_modes, lambda x: x.exit_id),
            (self.exceptional_exit_modes, lambda x: x.exit_id),
            (self.trap_handler_bindings, lambda x: x.binding_id),
            (self.interruptibility_regions, lambda x: x.region_id),
        ):
            keys = tuple(key(item) for item in values)
            if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
                raise ValueError("function privileged facts require stable unique identities")
        if self.member_fragment_ids != tuple(sorted(set(self.member_fragment_ids))):
            raise ValueError("privileged member fragment IDs must be unique and sorted")
        if self.missing_fact_codes != tuple(sorted(set(self.missing_fact_codes))):
            raise ValueError("missing fact codes must be unique and sorted")
        if self.complete and self.missing_fact_codes:
            raise ValueError("complete privileged facts cannot have missing facts")
        if not self.complete and not self.missing_fact_codes:
            raise ValueError("incomplete privileged facts require reason codes")


@dataclass(frozen=True)
class FunctionPrivilegedMachineState:
    privilege_mode: SourcePrivilegeMode | None
    interrupt_state: str | None
    delegation_state: str | None
    address_space_state: str | None
    trap_continuation_state: str | None
    saved_status_state: str | None

    @property
    def complete(self) -> bool:
        return all(value is not None for value in (
            self.privilege_mode, self.interrupt_state, self.delegation_state,
            self.address_space_state, self.trap_continuation_state,
            self.saved_status_state,
        ))


class FunctionPrivilegedTransferKind(str, Enum):
    IDENTITY = "identity"
    TRAP_ENTRY = "trap_entry"
    PRIVILEGE_RETURN = "privilege_return"
    STATE_UPDATE = "state_update"
    NONLOCAL_TRANSFER = "nonlocal_transfer"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FunctionPrivilegedBlockTransfer:
    node_id: str
    kind: FunctionPrivilegedTransferKind
    output_state: FunctionPrivilegedMachineState
    handler_binding_id: str | None = None
    continuation_identity: str | None = None
    privilege_return_kind: str | None = None
    complete: bool = False


@dataclass(frozen=True)
class FunctionPrivilegedNodeState:
    node_id: str
    state: FunctionPrivilegedMachineState


@dataclass(frozen=True)
class FunctionPrivilegedExitState:
    exit_id: str
    state: FunctionPrivilegedMachineState
    complete: bool


@dataclass(frozen=True)
class FunctionPrivilegedMachineAnalysis:
    function_id: str
    entry_state: FunctionPrivilegedMachineState
    node_entry_states: tuple[FunctionPrivilegedNodeState, ...]
    normal_exit_states: tuple[FunctionPrivilegedExitState, ...]
    exceptional_exit_states: tuple[FunctionPrivilegedExitState, ...]
    trap_handler_entry_states: tuple[FunctionPrivilegedNodeState, ...]
    privilege_returns_present: bool
    all_return_continuations_complete: bool
    all_normal_exits_restore_privilege: bool
    all_normal_exits_restore_interrupt_state: bool
    address_space_identity_preserved: bool
    complete: bool
    missing_fact_codes: tuple[str, ...]
    analysis_identity: str


def _merge(states: tuple[FunctionPrivilegedMachineState, ...]):
    if not states:
        return None
    fields = []
    for name in (
        "privilege_mode", "interrupt_state", "delegation_state",
        "address_space_state", "trap_continuation_state", "saved_status_state",
    ):
        values = tuple(getattr(state, name) for state in states)
        fields.append(values[0] if all(value == values[0] for value in values) else None)
    return FunctionPrivilegedMachineState(*fields)


def analyze_function_privileged_state(
    *,
    cfg: SourceFunctionControlFlowModel,
    facts: FunctionPrivilegedExecutionFacts,
    transfers: tuple[FunctionPrivilegedBlockTransfer, ...],
    initial_interrupt_state: str,
    initial_delegation_state: str,
    initial_trap_continuation_state: str,
    initial_saved_status_state: str,
) -> FunctionPrivilegedMachineAnalysis:
    reasons = set(cfg.missing_fact_codes) | set(facts.missing_fact_codes)
    if not cfg.complete:
        reasons.add("whole-function.privileged-cfg-incomplete")
    if not facts.complete:
        reasons.add("whole-function.privileged-execution-facts-incomplete")
    if set(facts.member_fragment_ids) == set() and facts.complete:
        reasons.add("whole-function.privileged-fragment-membership-incomplete")
    for name in ("has_nonlocal_transfer", "has_unwind", "has_signal_sensitive_state", "has_setjmp_longjmp"):
        value = getattr(facts, name)
        if value is None:
            reasons.add("whole-function.privileged-nonlocal-effects-unknown")
        elif value:
            reasons.add("whole-function.privileged-nonlocal-route-required")

    entry = FunctionPrivilegedMachineState(
        facts.entry_privilege_mode, initial_interrupt_state,
        initial_delegation_state, facts.address_space_identity,
        initial_trap_continuation_state, initial_saved_status_state,
    )
    by_transfer = {item.node_id: item for item in transfers}
    if len(by_transfer) != len(transfers):
        reasons.add("whole-function.privileged-transfer-duplicate")
    predecessors = {node.node_id: [] for node in cfg.nodes}
    successors = {node.node_id: [] for node in cfg.nodes}
    for edge in cfg.edges:
        predecessors.setdefault(edge.target_node_id, []).append(edge.source_node_id)
        successors.setdefault(edge.source_node_id, []).append(edge.target_node_id)
    inputs = {cfg.entry_node_id: entry}
    outputs = {}
    for _ in range(max(1, len(cfg.nodes) * 4)):
        changed = False
        for node_id in sorted(predecessors):
            if node_id != cfg.entry_node_id:
                incoming = tuple(outputs[pred] for pred in predecessors[node_id] if pred in outputs)
                if len(incoming) != len(predecessors[node_id]):
                    continue
                merged = _merge(incoming)
                if merged is None or not merged.complete:
                    reasons.add("whole-function.privileged-state-merge-unknown")
                if inputs.get(node_id) != merged:
                    inputs[node_id] = merged
                    changed = True
            if node_id not in inputs:
                continue
            transfer = by_transfer.get(node_id)
            if transfer is None or not transfer.complete or transfer.kind is FunctionPrivilegedTransferKind.UNKNOWN:
                reasons.add("whole-function.privileged-transfer-incomplete")
                continue
            if transfer.kind is FunctionPrivilegedTransferKind.PRIVILEGE_RETURN and (
                inputs[node_id].trap_continuation_state is None
                or inputs[node_id].saved_status_state is None
                or not transfer.continuation_identity
                or transfer.privilege_return_kind not in {"mret", "sret", "dret"}
            ):
                reasons.add("whole-function.privileged-return-continuation-unproven")
            if transfer.kind is FunctionPrivilegedTransferKind.TRAP_ENTRY and not transfer.handler_binding_id:
                reasons.add("whole-function.privileged-trap-handler-unbound")
            if transfer.kind is FunctionPrivilegedTransferKind.NONLOCAL_TRANSFER:
                reasons.add("whole-function.privileged-nonlocal-route-required")
            if not transfer.output_state.complete:
                reasons.add("whole-function.privileged-output-state-incomplete")
            if outputs.get(node_id) != transfer.output_state:
                outputs[node_id] = transfer.output_state
                changed = True
        if not changed:
            break
    else:
        reasons.add("whole-function.privileged-dataflow-nonconvergent")

    declared_normal = {item.exit_id: item for item in facts.normal_exit_privilege_modes}
    declared_exceptional = {item.exit_id: item for item in facts.exceptional_exit_modes}
    normal = []
    exceptional = []
    for exit_binding in cfg.exits:
        state = outputs.get(exit_binding.node_id) or inputs.get(exit_binding.node_id)
        if state is None:
            state = FunctionPrivilegedMachineState(None, None, None, None, None, None)
        declarations = declared_normal if exit_binding.kind is FunctionExitKind.NORMAL_RETURN else declared_exceptional
        declaration = declarations.get(exit_binding.exit_id)
        complete = bool(declaration and declaration.complete and state.complete and
                        declaration.privilege_mode == state.privilege_mode)
        if not complete:
            reasons.add("whole-function.privileged-exit-state-unproven")
        item = FunctionPrivilegedExitState(exit_binding.exit_id, state, complete)
        (normal if exit_binding.kind is FunctionExitKind.NORMAL_RETURN else exceptional).append(item)

    handler_states = []
    for binding in facts.trap_handler_bindings:
        state = inputs.get(binding.entry_node_id)
        bound_transfer = any(item.kind is FunctionPrivilegedTransferKind.TRAP_ENTRY
                             and item.handler_binding_id == binding.binding_id
                             for item in transfers)
        if state is None or not state.complete or state.privilege_mode is not binding.entry_privilege_mode or not bound_transfer:
            reasons.add("whole-function.privileged-trap-handler-entry-unproven")
            state = state or FunctionPrivilegedMachineState(None, None, None, None, None, None)
        handler_states.append(FunctionPrivilegedNodeState(binding.entry_node_id, state))

    for region in facts.interruptibility_regions:
        entry_state = inputs.get(region.entry_node_id)
        exit_state = outputs.get(region.exit_node_id) or inputs.get(region.exit_node_id)
        if (not region.complete or entry_state is None or exit_state is None
                or entry_state.interrupt_state != region.entry_interrupt_state
                or exit_state.interrupt_state != region.exit_interrupt_state):
            reasons.add("whole-function.interruptibility-region-unproven")

    returns_present = any(item.kind is FunctionPrivilegedTransferKind.PRIVILEGE_RETURN for item in transfers)
    return_ok = not returns_present or not any(
        reason == "whole-function.privileged-return-continuation-unproven" for reason in reasons
    )
    privilege_ok = bool(normal) and all(
        item.complete and item.state.privilege_mode is facts.entry_privilege_mode for item in normal
    )
    interrupt_ok = bool(normal) and all(
        item.state.interrupt_state == entry.interrupt_state for item in normal
    )
    address_ok = bool(normal) and facts.address_space_identity is not None and all(
        item.state.address_space_state == facts.address_space_identity for item in normal
    )
    if not privilege_ok: reasons.add("whole-function.privileged-mode-restoration-unproven")
    if not interrupt_ok: reasons.add("whole-function.interrupt-state-restoration-unproven")
    if not address_ok: reasons.add("whole-function.address-space-identity-unproven")
    ordered_reasons = tuple(sorted(reasons))
    payload = (facts, cfg, transfers, tuple(sorted(inputs.items())), tuple(sorted(outputs.items())), ordered_reasons)
    return FunctionPrivilegedMachineAnalysis(
        facts.function_id, entry,
        tuple(FunctionPrivilegedNodeState(key, value) for key, value in sorted(inputs.items())),
        tuple(sorted(normal, key=lambda item: item.exit_id)),
        tuple(sorted(exceptional, key=lambda item: item.exit_id)),
        tuple(sorted(handler_states, key=lambda item: item.node_id)),
        returns_present, return_ok, privilege_ok, interrupt_ok, address_ok,
        not ordered_reasons, ordered_reasons,
        "sha256:" + sha256(repr(payload).encode("utf-8")).hexdigest(),
    )
