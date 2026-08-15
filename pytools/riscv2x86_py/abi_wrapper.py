"""Phase-6C exact ABI-wrapper constraints and versioned registry."""
from __future__ import annotations
from dataclasses import dataclass
from .abi_effects import TargetAbiWrapperContract, TargetAbiWrapperRegistry

@dataclass(frozen=True)
class TargetAbiWrapperArgument:
    source_operand_index:int; target_wrapper_argument_index:int
    source_width_bits:int; target_type_id:str; signedness:str|None

@dataclass(frozen=True)
class TargetAbiWrapperReturn:
    source_operand_index:int; target_wrapper_return_index:int
    source_width_bits:int; target_type_id:str; signedness:str|None

@dataclass(frozen=True)
class TargetAbiWrapperConstraint:
    wrapper_contract:TargetAbiWrapperContract
    arguments:tuple[TargetAbiWrapperArgument,...]
    returns:tuple[TargetAbiWrapperReturn,...]
    target_call_stack_alignment_bytes:int
    registry_version:str=""
    forbids_unwind:bool=True
    forbids_implicit_shell_barrier:bool=True

# Registries are supplied explicitly by TranslationContext / Phase 6C.  A
# mutable module-global registry would make proof artifacts process-dependent.
