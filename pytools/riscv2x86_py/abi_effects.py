"""Typed Phase-4/5 ABI-call facts; never inferred from assembly spelling."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

class SourceAbiProfile(str,Enum): RV64_LP64="rv64-lp64"; RV64_LP64D="rv64-lp64d"; UNKNOWN="unknown"
class AbiValueLocationKind(str,Enum): GPR="gpr"; FPR="fpr"; STACK="stack"; MEMORY_INDIRECT="memory_indirect"; UNKNOWN="unknown"

@dataclass(frozen=True)
class SourceAbiValueLocation:
    kind:AbiValueLocationKind; register:str|None; stack_offset_bytes:int|None
    width_bits:int|None; signedness:str|None; value_kind:str; complete:bool

@dataclass(frozen=True)
class SourceDirectCallTarget:
    target_id:str; source_symbol:str|None; semantic_contract_id:str|None; semantic_version:str|None
    is_direct:bool; pic_plt_mode:str|None; tls_model:str|None; complete:bool

@dataclass(frozen=True)
class SourceAbiCallBinding:
    fragment_id:str; block_address:int; operation_index:int; source_abi_profile:SourceAbiProfile
    direct_target_id:str; source_semantic_contract_id:str; source_semantic_version:str
    argument_operand_indexes:tuple[int,...]; return_operand_indexes:tuple[int,...]
    argument_types:tuple[str,...]; return_types:tuple[str,...]
    source_argument_locations:tuple[SourceAbiValueLocation,...]; source_return_locations:tuple[SourceAbiValueLocation,...]
    stack_alignment_bytes:int|None; pic_plt_mode:str|None; tls_model:str|None
    may_return:bool|None; may_unwind:bool|None; memory_effect:str
    binding_complete:bool; provenance:str

@dataclass(frozen=True)
class SourceCallEffect:
    block_address:int; operation_index:int; target:SourceDirectCallTarget
    arguments:tuple[SourceAbiValueLocation,...]; returns:tuple[SourceAbiValueLocation,...]
    caller_saved_clobbers:tuple[str,...]; callee_saved_preserved:tuple[str,...]
    stack_alignment_bytes:int|None; source_call_frame_size_bytes:int|None
    may_return:bool|None; may_unwind:bool|None; may_trap:bool|None
    reads_ra:bool; writes_ra:bool; return_continuation_internal:bool
    memory_effect:str; complete:bool

@dataclass(frozen=True)
class SourceAbiEffectModel:
    source_abi_profile:SourceAbiProfile; calls:tuple[SourceCallEffect,...]
    reads_ra:bool; writes_ra:bool; returns_from_containing_function:bool
    caller_saved_effects_complete:bool; callee_saved_effects_complete:bool
    pic_plt_tls_effects_complete:bool; unwind_effects_complete:bool
    variadic_or_aggregate_abi:bool; complete:bool; missing_fact_codes:tuple[str,...]=()

def build_abi_effects(*, has_call:bool, bindings:tuple[SourceAbiCallBinding,...]) -> SourceAbiEffectModel|None:
    if not has_call and not bindings:return None
    reasons=[]; ordered=tuple(sorted(bindings,key=lambda x:(x.block_address,x.operation_index)))
    if len(ordered)!=1: reasons.append("abi-call-exactly-one-required")
    if has_call != bool(ordered): reasons.append("abi-call-control-flow-mismatch")
    calls=[]
    for b in ordered:
        aggregate=any(x.value_kind in {"aggregate","variadic","sret"} for x in b.source_argument_locations+b.source_return_locations)
        complete=(b.binding_complete and b.source_abi_profile is not SourceAbiProfile.UNKNOWN and b.direct_target_id != "" and b.source_semantic_contract_id != "" and b.source_semantic_version != "" and b.may_return is True and b.may_unwind is False and b.stack_alignment_bytes is not None and b.pic_plt_mode is not None and b.tls_model is not None and not aggregate and len(b.argument_operand_indexes)==len(b.source_argument_locations)==len(b.argument_types) and len(b.return_operand_indexes)==len(b.source_return_locations)==len(b.return_types) and all(x.complete and x.kind is AbiValueLocationKind.GPR and x.width_bits in {32,64} for x in b.source_argument_locations+b.source_return_locations))
        if not complete: reasons.append("abi-call-binding-incomplete")
        target=SourceDirectCallTarget(b.direct_target_id,None,b.source_semantic_contract_id,b.source_semantic_version,True,b.pic_plt_mode,b.tls_model,complete)
        calls.append(SourceCallEffect(b.block_address,b.operation_index,target,b.source_argument_locations,b.source_return_locations,(),(),b.stack_alignment_bytes,None,b.may_return,b.may_unwind,False,False,False,True,b.memory_effect,complete))
    complete=not reasons and all(x.complete for x in calls)
    profile=ordered[0].source_abi_profile if len(ordered)==1 else SourceAbiProfile.UNKNOWN
    return SourceAbiEffectModel(profile,tuple(calls),False,False,False,True,True,True,True,False,complete,tuple(sorted(set(reasons))))

@dataclass(frozen=True)
class TargetAbiWrapperContract:
    contract_id:str; semantic_version:str; source_abi_profile:SourceAbiProfile; target_abi:str
    source_target_id:str; target_wrapper_symbol:str; argument_types:tuple[str,...]; return_types:tuple[str,...]
    argument_operand_indexes:tuple[int,...]; return_operand_indexes:tuple[int,...]
    memory_effect:str; may_return:bool; may_unwind:bool
    required_headers:tuple[str,...]; required_library:str|None; pic_plt_compatible:bool; tls_compatible:bool
    exact_semantic_contract_id:str

@dataclass(frozen=True)
class TargetAbiWrapperRegistry:
    contracts:tuple[TargetAbiWrapperContract,...]=()
    def resolve(self,effects:SourceAbiEffectModel,target_abi:str)->TargetAbiWrapperContract|None:
        if not effects.complete or len(effects.calls)!=1:return None
        call=effects.calls[0]
        matches=[x for x in self.contracts if x.source_abi_profile is effects.source_abi_profile and x.target_abi==target_abi and x.source_target_id==call.target.target_id and x.exact_semantic_contract_id==call.target.semantic_contract_id and x.semantic_version==call.target.semantic_version]
        return matches[0] if len(matches)==1 else None
