"""Structured target contract for a compiler-managed private frame."""
from __future__ import annotations
from dataclasses import dataclass
from .pcode_ir import StackAccessKind

@dataclass(frozen=True)
class TargetVirtualPrivateFrameAccess:
    source_block_address:int; source_operation_index:int
    byte_offset:int; width_bits:int; access:StackAccessKind
    value_operand_index:int; signed_load:bool|None

@dataclass(frozen=True)
class TargetVirtualPrivateFrameConstraint:
    frame_size_bytes:int; required_alignment_bytes:int
    accesses:tuple[TargetVirtualPrivateFrameAccess,...]
    uses_compiler_managed_storage:bool=True
    forbids_explicit_host_stack_pointer_mutation:bool=True
    forbids_frame_address_builtin:bool=True
    requires_layout_proof:bool=True
    requires_bounds_proof:bool=True
    requires_initialization_proof:bool=True
    requires_no_escape_proof:bool=True
