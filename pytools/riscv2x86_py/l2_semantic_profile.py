"""Strict, per-fragment L2 semantic profiles.

Profiles are derived at the translation boundary from the normalized Phase-6A
source model.  The report-side consumer only parses the resulting profile; it
never examines source paths, function names, assembly text, or mnemonics.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Mapping


L2_FRAGMENT_SEMANTIC_PROFILE_SCHEMA = "riscv2x86.l2-fragment-semantic-profile.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class L2PatternKind(str, Enum):
    SCALAR = "scalar"
    BRANCH = "branch"
    JUMP = "jump"
    MEMORY_LOAD = "memory_load"
    MEMORY_STORE = "memory_store"
    FENCE = "fence"
    INSTRUCTION_VISIBILITY_FENCE = "instruction_visibility_fence"
    PRIVILEGED_READ = "privileged_read"
    PRIVILEGED_WRITE = "privileged_write"
    COMPOSITE = "composite"
    ATOMIC = "atomic"
    UNKNOWN = "unknown"


_CAPABILITIES = {
    L2PatternKind.SCALAR: ("logical_operand_observation", "shell_observation"),
    L2PatternKind.BRANCH: ("control_flow_observation", "logical_operand_observation",
                           "shell_observation"),
    L2PatternKind.JUMP: ("control_flow_observation", "logical_operand_observation",
                         "shell_observation"),
    L2PatternKind.MEMORY_LOAD: ("logical_operand_observation",
                                "object_relative_memory_observation", "shell_observation"),
    L2PatternKind.MEMORY_STORE: ("logical_operand_observation",
                                 "object_relative_memory_observation", "shell_observation"),
    L2PatternKind.FENCE: ("ordering_observation", "shell_observation"),
    L2PatternKind.INSTRUCTION_VISIBILITY_FENCE: (
        "instruction_visibility", "shell_observation"),
    L2PatternKind.PRIVILEGED_READ: ("privileged_state_observation", "shell_observation"),
    L2PatternKind.PRIVILEGED_WRITE: ("privileged_state_observation", "shell_observation"),
    L2PatternKind.COMPOSITE: ("composite_fragment_observation", "shell_observation"),
    L2PatternKind.ATOMIC: ("atomic_outcome_observation",
                           "object_relative_memory_observation", "shell_observation"),
    L2PatternKind.UNKNOWN: (),
}


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _strict_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(label + " must be boolean")
    return value


@dataclass(frozen=True)
class L2OperandShape:
    input_count: int
    output_count: int
    read_write_count: int
    complete: bool

    def __post_init__(self) -> None:
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 0
               for item in (self.input_count, self.output_count, self.read_write_count)):
            raise ValueError("L2 operand shape counts must be non-negative integers")

    def to_dict(self) -> dict[str, object]:
        return {"inputCount": self.input_count, "outputCount": self.output_count,
                "readWriteCount": self.read_write_count, "complete": self.complete}


@dataclass(frozen=True)
class L2ControlFlowShape:
    internal_branch: bool
    direct_jump: bool
    indirect: bool
    external: bool
    multiple_exits: bool
    continuation_count: int
    complete: bool

    def __post_init__(self) -> None:
        if (isinstance(self.continuation_count, bool)
                or not isinstance(self.continuation_count, int)
                or self.continuation_count < 0):
            raise ValueError("L2 continuation count must be a non-negative integer")

    def to_dict(self) -> dict[str, object]:
        return {"internalBranch": self.internal_branch, "directJump": self.direct_jump,
                "indirect": self.indirect, "external": self.external,
                "multipleExits": self.multiple_exits,
                "continuationCount": self.continuation_count, "complete": self.complete}


@dataclass(frozen=True)
class L2MemoryShape:
    reads: bool
    writes: bool
    atomic: bool
    object_relative: bool
    complete: bool

    def to_dict(self) -> dict[str, object]:
        return {"reads": self.reads, "writes": self.writes, "atomic": self.atomic,
                "objectRelative": self.object_relative, "complete": self.complete}


@dataclass(frozen=True)
class L2OrderingShape:
    memory_barrier: bool
    instruction_visibility: bool
    ordering_known: bool
    complete: bool

    def to_dict(self) -> dict[str, object]:
        return {"memoryBarrier": self.memory_barrier,
                "instructionVisibility": self.instruction_visibility,
                "orderingKnown": self.ordering_known, "complete": self.complete}


@dataclass(frozen=True)
class L2PrivilegedShape:
    present: bool
    reads_state: bool
    writes_state: bool
    complete: bool

    def to_dict(self) -> dict[str, object]:
        return {"present": self.present, "readsState": self.reads_state,
                "writesState": self.writes_state, "complete": self.complete}


@dataclass(frozen=True)
class L2InternalStateShape:
    has_internal_values: bool
    has_multiple_operations: bool
    escape_complete: bool
    complete: bool

    def to_dict(self) -> dict[str, object]:
        return {"hasInternalValues": self.has_internal_values,
                "hasMultipleOperations": self.has_multiple_operations,
                "escapeComplete": self.escape_complete, "complete": self.complete}


@dataclass(frozen=True)
class L2FragmentSemanticProfile:
    fragment_id: str
    pattern_kind: L2PatternKind
    operand_shape: L2OperandShape
    control_flow_shape: L2ControlFlowShape
    memory_shape: L2MemoryShape
    ordering_shape: L2OrderingShape
    privileged_shape: L2PrivilegedShape
    internal_state_shape: L2InternalStateShape
    execution_profile: str
    required_capabilities: tuple[str, ...]
    profile_identity: str = ""
    schema_version: str = L2_FRAGMENT_SEMANTIC_PROFILE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_FRAGMENT_SEMANTIC_PROFILE_SCHEMA:
            raise ValueError("unsupported L2 fragment semantic profile schema")
        if not self.fragment_id or not self.execution_profile:
            raise ValueError("L2 fragment semantic profile identity/profile is missing")
        if self.required_capabilities != tuple(sorted(set(self.required_capabilities))):
            raise ValueError("L2 required capabilities must be unique and sorted")
        if self.required_capabilities != tuple(sorted(_CAPABILITIES[self.pattern_kind])):
            raise ValueError("L2 required capabilities do not match pattern kind")
        expected = _identity(self._payload(False))
        if self.profile_identity and self.profile_identity != expected:
            raise ValueError("L2 semantic profile identity does not match content")
        object.__setattr__(self, "profile_identity", expected)

    @property
    def complete(self) -> bool:
        return (self.pattern_kind is not L2PatternKind.UNKNOWN
                and self.operand_shape.complete and self.control_flow_shape.complete
                and self.memory_shape.complete and self.ordering_shape.complete
                and self.privileged_shape.complete and self.internal_state_shape.complete)

    def _payload(self, include_identity: bool) -> dict[str, object]:
        value = {"schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
                 "patternKind": self.pattern_kind.value,
                 "operandShape": self.operand_shape.to_dict(),
                 "controlFlowShape": self.control_flow_shape.to_dict(),
                 "memoryShape": self.memory_shape.to_dict(),
                 "orderingShape": self.ordering_shape.to_dict(),
                 "privilegedShape": self.privileged_shape.to_dict(),
                 "internalStateShape": self.internal_state_shape.to_dict(),
                 "executionProfile": self.execution_profile,
                 "requiredCapabilities": list(self.required_capabilities)}
        if include_identity:
            value["profileIdentity"] = self.profile_identity
        return value

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


def profile_from_source_model(
    fragment_id: str, source_model: object, *,
    execution_profile: str = "rv64gc-user-to-x86_64-user",
) -> L2FragmentSemanticProfile:
    """Derive a profile solely from normalized Phase-6A semantic fields."""
    operands = getattr(getattr(source_model, "operands", None), "operands", ())
    accesses = [str(getattr(getattr(item, "access", None), "value", "")) for item in operands]
    operand_shape = L2OperandShape(
        sum(item in {"input", "read_write", "address", "control_target"}
            for item in accesses),
        sum(item in {"output", "read_write"} for item in accesses),
        sum(item == "read_write" for item in accesses),
        bool(getattr(getattr(source_model, "operands", None), "complete", False)),
    )
    control = getattr(source_model, "control_flow", None)
    shell = getattr(source_model, "shell", None)
    branch = getattr(source_model, "local_branch_select", None)
    jump = getattr(source_model, "local_unconditional_jump", None)
    successors = tuple(getattr(control, "successors", ()) or ())
    control_shape = L2ControlFlowShape(
        bool(branch) or bool(getattr(control, "has_internal_branch", False)), bool(jump),
        bool(getattr(control, "has_indirect_control_flow", False)),
        bool(getattr(control, "has_external_control_flow", False)),
        bool(getattr(control, "has_multiple_exits", False)),
        2 if branch else 1 if jump else len(successors),
        bool(getattr(control, "cfg_ok", False))
        and not bool(getattr(control, "has_unknown_target", True)),
    )
    memory = getattr(source_model, "memory", None)
    atomic_model = getattr(source_model, "atomic", None)
    atomic = bool(getattr(atomic_model, "present",
                          getattr(memory, "has_atomic", False)))
    reads, writes = bool(getattr(memory, "reads_memory", False)), bool(
        getattr(memory, "writes_memory", False))
    address_bindings = [getattr(item, "address", None) for item in operands
                        if str(getattr(getattr(item, "access", None), "value", ""))
                        == "address"]
    object_relative = bool(address_bindings) and all(
        bool(getattr(item, "address_id", ""))
        and bool(getattr(item, "provenance_known", False))
        for item in address_bindings
    )
    memory_shape = L2MemoryShape(
        reads, writes, atomic,
        object_relative if (reads or writes) else False,
        not bool(getattr(memory, "has_unknown_barrier", True))
        and (not (reads or writes) or object_relative),
    )
    barrier = getattr(source_model, "barrier", None)
    instruction_visibility = bool(getattr(
        barrier, "instruction_serializing",
        getattr(memory, "has_instruction_barrier", False),
    ))
    memory_barrier = bool(getattr(
        barrier, "hardware_memory_barrier",
        getattr(memory, "has_memory_barrier", False),
    ))
    ordering_shape = L2OrderingShape(
        memory_barrier, instruction_visibility,
        not bool(getattr(memory, "has_unknown_barrier", True)),
        not bool(getattr(memory, "has_unknown_barrier", True)),
    )
    privileged = getattr(source_model, "privileged_state", None)
    privileged_present = bool(privileged and getattr(privileged, "state", None)
                              and getattr(privileged.state, "present", False))
    csr_effects = tuple(getattr(getattr(privileged, "state", None),
                                "csr_effects", ()) or ())
    csr_operations = {
        str(getattr(getattr(effect, "operation", None), "value", ""))
        for effect in csr_effects
    }
    privileged_read = bool(getattr(privileged, "read_only_counter", None)) or bool(
        csr_operations & {"read", "read_write", "set_bits", "clear_bits"}
    )
    privileged_write = bool(
        csr_operations & {"write", "read_write", "set_bits", "clear_bits"}
    ) or bool(
        privileged_present and getattr(privileged, "state", None)
        and any(tuple(getattr(privileged.state, name, ()) or ()) for name in (
            "trap_effects", "return_effects", "interrupt_effects",
            "address_translation_effects", "virtualization_effects", "debug_effects",
        ))
    )
    privileged_shape = L2PrivilegedShape(
        privileged_present, privileged_read,
        privileged_write,
        not privileged_present or bool(getattr(privileged, "complete", False)),
    )
    value_program = getattr(source_model, "value_program", None)
    operations = tuple(getattr(value_program, "instructions", ()) or ())
    internal_shape = L2InternalStateShape(
        len(operations) > 1, len(operations) > 1,
        bool(getattr(getattr(source_model, "operands", None), "complete", False)),
        bool(getattr(getattr(source_model, "completeness", None), "cfg_ok", False)),
    )
    if privileged_present and privileged_read and not privileged_write:
        kind = L2PatternKind.PRIVILEGED_READ
    elif privileged_present and privileged_write:
        kind = L2PatternKind.PRIVILEGED_WRITE
    elif privileged_present:
        kind = L2PatternKind.UNKNOWN
    elif atomic:
        kind = L2PatternKind.ATOMIC
    elif instruction_visibility:
        kind = L2PatternKind.INSTRUCTION_VISIBILITY_FENCE
    elif memory_barrier:
        kind = L2PatternKind.FENCE
    elif bool(getattr(shell, "has_asm_goto", False)):
        # Host-C continuations require a versioned explicit harness.  Treating
        # asm-goto as an automatic local branch would overclaim observability.
        kind = L2PatternKind.UNKNOWN
    elif branch:
        kind = L2PatternKind.BRANCH
    elif jump:
        kind = L2PatternKind.JUMP
    elif reads and not writes:
        kind = L2PatternKind.MEMORY_LOAD
    elif writes and not reads:
        kind = L2PatternKind.MEMORY_STORE
    elif reads or writes or len(operations) > 1:
        kind = L2PatternKind.COMPOSITE
    elif operand_shape.complete and control_shape.complete:
        kind = L2PatternKind.SCALAR
    else:
        kind = L2PatternKind.UNKNOWN
    return L2FragmentSemanticProfile(
        fragment_id, kind, operand_shape, control_shape, memory_shape, ordering_shape,
        privileged_shape, internal_shape, execution_profile,
        tuple(sorted(_CAPABILITIES[kind])),
    )


def l2_fragment_semantic_profile_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
) -> L2FragmentSemanticProfile:
    fields = {"schemaVersion", "fragmentId", "patternKind", "operandShape",
              "controlFlowShape", "memoryShape", "orderingShape", "privilegedShape",
              "internalStateShape", "executionProfile", "requiredCapabilities",
              "profileIdentity"}
    if set(value) != fields:
        raise ValueError("L2 fragment semantic profile fields are incomplete or unknown")
    fragment_id = value.get("fragmentId")
    if not isinstance(fragment_id, str) or not fragment_id:
        raise ValueError("L2 semantic profile fragment ID is invalid")
    if expected_fragment_id and fragment_id != expected_fragment_id:
        raise ValueError("L2 semantic profile fragment identity mismatch")
    def shape(name: str, expected: set[str]) -> Mapping[str, object]:
        raw = value.get(name)
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise ValueError("L2 semantic profile " + name + " is invalid")
        return raw
    operand = shape("operandShape", {"inputCount", "outputCount", "readWriteCount", "complete"})
    control = shape("controlFlowShape", {"internalBranch", "directJump", "indirect",
                    "external", "multipleExits", "continuationCount", "complete"})
    memory = shape("memoryShape", {"reads", "writes", "atomic", "objectRelative", "complete"})
    ordering = shape("orderingShape", {"memoryBarrier", "instructionVisibility",
                      "orderingKnown", "complete"})
    privileged = shape("privilegedShape", {"present", "readsState", "writesState", "complete"})
    internal = shape("internalStateShape", {"hasInternalValues", "hasMultipleOperations",
                    "escapeComplete", "complete"})
    capabilities = value.get("requiredCapabilities")
    if not isinstance(capabilities, list) or not all(isinstance(item, str) and item
                                                     for item in capabilities):
        raise ValueError("L2 semantic profile required capabilities are invalid")
    identity = value.get("profileIdentity")
    execution = value.get("executionProfile")
    if (not isinstance(identity, str) or _SHA256.fullmatch(identity) is None
            or not isinstance(execution, str) or not execution):
        raise ValueError("L2 semantic profile identities are invalid")
    return L2FragmentSemanticProfile(
        fragment_id, L2PatternKind(str(value.get("patternKind"))),
        L2OperandShape(operand["inputCount"], operand["outputCount"],
                       operand["readWriteCount"], _strict_bool(operand["complete"], "operand complete")),
        L2ControlFlowShape(*(_strict_bool(control[name], "control " + name) for name in
            ("internalBranch", "directJump", "indirect", "external", "multipleExits")),
            control["continuationCount"], _strict_bool(control["complete"], "control complete")),
        L2MemoryShape(*(_strict_bool(memory[name], "memory " + name) for name in
            ("reads", "writes", "atomic", "objectRelative", "complete"))),
        L2OrderingShape(*(_strict_bool(ordering[name], "ordering " + name) for name in
            ("memoryBarrier", "instructionVisibility", "orderingKnown", "complete"))),
        L2PrivilegedShape(*(_strict_bool(privileged[name], "privileged " + name) for name in
            ("present", "readsState", "writesState", "complete"))),
        L2InternalStateShape(*(_strict_bool(internal[name], "internal " + name) for name in
            ("hasInternalValues", "hasMultipleOperations", "escapeComplete", "complete"))),
        execution, tuple(capabilities), identity, str(value.get("schemaVersion")),
    )


def profile_from_finding(finding: Mapping[str, object]) -> L2FragmentSemanticProfile:
    raw = finding.get("l2SemanticProfile")
    fragment = finding.get("fragment")
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "") \
        if isinstance(fragment, Mapping) else ""
    if not isinstance(raw, Mapping):
        raise ValueError("L2 semantic profile is missing from translated finding")
    return l2_fragment_semantic_profile_from_dict(raw, expected_fragment_id=fragment_id)
