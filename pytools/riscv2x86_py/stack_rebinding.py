"""Authoritative Phase-4/5 evidence for logical stack-address rebinding.

Nothing in this module identifies a C object by guessing the host stack
layout.  Producers (a compiler sidecar or a verified corpus annotation) must
provide the binding explicitly; Phase 6 merely validates and consumes it.
"""
from __future__ import annotations
from dataclasses import dataclass

from .pcode_ir import StackAccessKind


@dataclass(frozen=True)
class SourceStackObjectBinding:
    binding_id: str
    source_block_address: int
    source_operation_index: int
    c_object_id: str
    c_base_operand_index: int | None
    c_lvalue_binding_id: str
    source_offset_bytes: int
    object_offset_bytes: int
    object_size_bytes: int | None
    guaranteed_alignment_bytes: int | None
    # The value operand is intentionally explicit.  StackMemoryAccess alone
    # says nothing about which C operand receives/provides the value.
    value_operand_index: int
    access: StackAccessKind
    binding_complete: bool
    source_compiler_provenance: str
    lifetime_proven: bool = False
    effective_type_proven: bool = False

    def __post_init__(self) -> None:
        if not self.binding_id or not self.c_object_id or not self.c_lvalue_binding_id:
            raise ValueError("stack rebinding identifiers must be non-empty")
        if self.value_operand_index < 0:
            raise ValueError("value_operand_index must be non-negative")
        if not isinstance(self.access, StackAccessKind):
            raise TypeError("access must be StackAccessKind")
        if not self.source_compiler_provenance:
            raise ValueError("stack rebinding requires provenance")


@dataclass(frozen=True)
class StackAddressRebindingFacts:
    bindings: tuple[SourceStackObjectBinding, ...] = ()
    complete: bool = False
    missing_fact_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        ids = tuple(x.binding_id for x in self.bindings)
        if len(ids) != len(set(ids)):
            raise ValueError("stack rebinding binding_id values must be unique")
        if not self.complete and not self.missing_fact_codes:
            raise ValueError("incomplete stack rebinding facts need reason codes")


@dataclass(frozen=True)
class SourceStackRebindingAccess:
    source_block_address: int
    source_operation_index: int
    c_object_id: str
    c_lvalue_binding_id: str
    c_base_operand_index: int | None
    source_offset_bytes: int
    target_object_offset_bytes: int
    object_size_bytes: int | None
    required_alignment_bytes: int | None
    guaranteed_alignment_bytes: int | None
    width_bits: int
    access: StackAccessKind
    signed_load: bool | None
    value_operand_index: int
    aliases_external_memory: bool
    provenance: str
    complete: bool


@dataclass(frozen=True)
class TargetStackRebindingAccess:
    source_block_address: int
    source_operation_index: int
    c_lvalue_binding_id: str
    byte_offset: int
    width_bits: int
    access: StackAccessKind
    value_operand_index: int


@dataclass(frozen=True)
class TargetStackRebindingConstraint:
    accesses: tuple[TargetStackRebindingAccess, ...]
    forbids_host_stack_pointer_mutation: bool = True
    requires_object_bounds_proof: bool = True
    requires_no_escape_proof: bool = True
    requires_layout_preservation: bool = True
