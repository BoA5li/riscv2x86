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
    forbids_unwind:bool=True
    forbids_implicit_shell_barrier:bool=True

# Empty by default: a project/corpus must explicitly register exact contracts.
DEFAULT_ABI_WRAPPER_REGISTRY=TargetAbiWrapperRegistry()

def install_abi_wrapper_registry(registry: TargetAbiWrapperRegistry) -> None:
    """Install corpus-owned contracts before translation; no implicit lookup exists."""
    if not isinstance(registry, TargetAbiWrapperRegistry):
        raise TypeError("registry must be TargetAbiWrapperRegistry")
    global DEFAULT_ABI_WRAPPER_REGISTRY
    DEFAULT_ABI_WRAPPER_REGISTRY = registry
