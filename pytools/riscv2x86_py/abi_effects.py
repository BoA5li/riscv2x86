"""Typed Phase-4/5 ABI-call join; never inferred from assembly spelling."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

class SourceAbiProfile(str,Enum): RV64_LP64="rv64-lp64"; RV64_LP64D="rv64-lp64d"; UNKNOWN="unknown"
class AbiValueLocationKind(str,Enum): GPR="gpr"; FPR="fpr"; STACK="stack"; MEMORY_INDIRECT="memory_indirect"; UNKNOWN="unknown"

@dataclass(frozen=True)
class SourceAbiValueLocation:
    kind:AbiValueLocationKind; register:str|None; stack_offset_bytes:int|None; width_bits:int|None; signedness:str|None; value_kind:str; complete:bool

@dataclass(frozen=True)
class SourceDirectCallTarget:
    target_id:str; source_symbol:str|None; semantic_contract_id:str|None; semantic_version:str|None; is_direct:bool; pic_plt_mode:str|None; tls_model:str|None; complete:bool

@dataclass(frozen=True)
class SourceAbiCallBinding:
    fragment_id:str; block_address:int; operation_index:int; source_abi_profile:SourceAbiProfile
    direct_target_id:str; source_semantic_contract_id:str; source_semantic_version:str
    argument_operand_indexes:tuple[int,...]; return_operand_indexes:tuple[int,...]
    argument_types:tuple[str,...]; return_types:tuple[str,...]
    source_argument_locations:tuple[SourceAbiValueLocation,...]; source_return_locations:tuple[SourceAbiValueLocation,...]
    stack_alignment_bytes:int|None; pic_plt_mode:str|None; tls_model:str|None
    may_return:bool|None; may_unwind:bool|None; memory_effect:str; binding_complete:bool; provenance:str
    source_symbol_id:str|None=None; caller_saved_clobbers:tuple[str,...]=(); callee_saved_preserved:tuple[str,...]=()
    source_call_frame_size_bytes:int|None=None; may_trap:bool|None=None; canonical_target_identity:str|None=None

@dataclass(frozen=True)
class AbiCallBindingFacts:
    fragment_id:str; bindings:tuple[SourceAbiCallBinding,...]=(); complete:bool=False; missing_fact_codes:tuple[str,...]=(); provenance:str=""
    def __post_init__(self):
        keys=[(x.block_address,x.operation_index) for x in self.bindings]
        if len(keys)!=len(set(keys)): raise ValueError("ABI call bindings must have unique call-site identities")
        if not self.complete and not self.missing_fact_codes: raise ValueError("incomplete ABI call facts need reason codes")
        if self.complete and not self.provenance: raise ValueError("complete ABI call facts need provenance")

@dataclass(frozen=True)
class CanonicalCallSite:
    block_address:int; operation_index:int; is_direct:bool; direct_target_identity:str|None
    argument_registers:tuple[str,...]; result_registers:tuple[str,...]
    reads_ra:bool; writes_ra:bool; continuation_internal:bool; complete:bool

@dataclass(frozen=True)
class SourceCallEffect:
    block_address:int; operation_index:int; target:SourceDirectCallTarget
    arguments:tuple[SourceAbiValueLocation,...]; returns:tuple[SourceAbiValueLocation,...]
    caller_saved_clobbers:tuple[str,...]; callee_saved_preserved:tuple[str,...]
    stack_alignment_bytes:int|None; source_call_frame_size_bytes:int|None
    may_return:bool|None; may_unwind:bool|None; may_trap:bool|None
    reads_ra:bool; writes_ra:bool; return_continuation_internal:bool; memory_effect:str; complete:bool

@dataclass(frozen=True)
class SourceAbiEffectModel:
    source_abi_profile:SourceAbiProfile; calls:tuple[SourceCallEffect,...]; reads_ra:bool; writes_ra:bool; returns_from_containing_function:bool
    caller_saved_effects_complete:bool; callee_saved_effects_complete:bool; pic_plt_tls_effects_complete:bool; unwind_effects_complete:bool
    variadic_or_aggregate_abi:bool; complete:bool; missing_fact_codes:tuple[str,...]=()

def collect_canonical_call_sites(*, blocks, cfg) -> tuple[CanonicalCallSite,...]:
    """Inventory canonical CALL/CALLIND ops with stable block/op identities."""
    sites=[]; nodes={} if cfg is None else getattr(cfg,"nodes",{})
    for block in blocks:
        node=nodes.get(block.addr); target=getattr(block,"call_targets",[]) or []
        for index,op in enumerate(block.ops):
            code=op.opcode.upper()
            if code not in {"CALL","CALLIND"}: continue
            direct=code=="CALL" and len(target)==1
            regs=tuple((v.name or "").lower() for v in op.inputs if getattr(getattr(v,"kind",None),"value",None)=="reg" and (v.name or ""))
            output=() if op.output is None or not (op.output.name or "") else ((op.output.name or "").lower(),)
            sites.append(CanonicalCallSite(block.addr,index,direct,str(target[0]) if direct else None,regs,output,"ra" in regs or "x1" in regs,True,not bool(getattr(node,"has_unknown_target",False)),True))
    return tuple(sorted(sites,key=lambda x:(x.block_address,x.operation_index)))

def build_abi_effects(*, has_call:bool, bindings:tuple[SourceAbiCallBinding,...], call_sites:tuple[CanonicalCallSite,...]=(), returns_from_containing_function:bool=False) -> SourceAbiEffectModel|None:
    if not has_call and not bindings and not call_sites:return None
    reasons=[]; ordered=tuple(sorted(bindings,key=lambda x:(x.block_address,x.operation_index))); sites=tuple(sorted(call_sites,key=lambda x:(x.block_address,x.operation_index)))
    if not sites and has_call: reasons.append("abi-call.canonical-call-site-missing")
    if sites and not has_call: reasons.append("abi-call.control-flow-mismatch")
    by_key={(x.block_address,x.operation_index):x for x in ordered}
    if len(by_key)!=len(ordered): reasons.append("abi-call.binding-ambiguous")
    if { (x.block_address,x.operation_index) for x in sites } != set(by_key): reasons.append("abi-call.call-site-mismatch")
    calls=[]
    for site in sites:
        binding=by_key.get((site.block_address,site.operation_index))
        if binding is None: continue
        aggregate=any(x.value_kind in {"aggregate","variadic","sret"} for x in binding.source_argument_locations+binding.source_return_locations)
        args_ok=len(binding.argument_operand_indexes)==len(binding.argument_types)==len(binding.source_argument_locations)
        ret_ok=len(binding.return_operand_indexes)==len(binding.return_types)==len(binding.source_return_locations)
        locations_ok=all(x.complete and x.kind is AbiValueLocationKind.GPR and x.width_bits in {32,64} for x in binding.source_argument_locations+binding.source_return_locations)
        target_ok=site.is_direct and (binding.canonical_target_identity is None or binding.canonical_target_identity==site.direct_target_identity)
        if not target_ok: reasons.append("abi-call.direct-target-mismatch" if site.is_direct else "abi-call.indirect-target")
        if not args_ok: reasons.append("abi-call.argument-location-mismatch")
        if not ret_ok: reasons.append("abi-call.return-location-mismatch")
        if aggregate: reasons.append("abi-call.variadic-or-aggregate-unsupported")
        complete=all((binding.binding_complete,binding.source_abi_profile is not SourceAbiProfile.UNKNOWN,bool(binding.direct_target_id),bool(binding.source_semantic_contract_id),bool(binding.source_semantic_version),binding.may_return is True,binding.may_unwind is False,binding.may_trap is False,binding.stack_alignment_bytes is not None,binding.pic_plt_mode=="direct",binding.tls_model=="none",args_ok,ret_ok,locations_ok,target_ok,not aggregate,site.complete,site.continuation_internal))
        if not complete: reasons.append("abi-call.binding-incomplete")
        target=SourceDirectCallTarget(binding.direct_target_id,binding.source_symbol_id,binding.source_semantic_contract_id,binding.source_semantic_version,site.is_direct,binding.pic_plt_mode,binding.tls_model,complete)
        calls.append(SourceCallEffect(site.block_address,site.operation_index,target,binding.source_argument_locations,binding.source_return_locations,tuple(sorted(binding.caller_saved_clobbers)),tuple(sorted(binding.callee_saved_preserved)),binding.stack_alignment_bytes,binding.source_call_frame_size_bytes,binding.may_return,binding.may_unwind,binding.may_trap,site.reads_ra,site.writes_ra,site.continuation_internal,binding.memory_effect,complete))
    complete=not reasons and len(calls)==1 and all(x.complete for x in calls)
    profile=ordered[0].source_abi_profile if len(ordered)==1 else SourceAbiProfile.UNKNOWN
    return SourceAbiEffectModel(profile,tuple(calls),any(x.reads_ra for x in calls),any(x.writes_ra for x in calls),returns_from_containing_function,all(x.complete for x in calls),all(x.complete for x in calls),all(x.complete and x.target.pic_plt_mode=="direct" and x.target.tls_model=="none" for x in calls),all(x.complete and x.may_unwind is False for x in calls),any(x.value_kind in {"aggregate","variadic","sret"} for b in ordered for x in b.source_argument_locations+b.source_return_locations),complete,tuple(sorted(set(reasons))))

@dataclass(frozen=True)
class TargetAbiWrapperContract:
    contract_id:str; semantic_version:str; source_abi_profile:SourceAbiProfile; target_abi:str; source_target_id:str; target_wrapper_symbol:str; argument_types:tuple[str,...]; return_types:tuple[str,...]; argument_operand_indexes:tuple[int,...]; return_operand_indexes:tuple[int,...]; memory_effect:str; may_return:bool; may_unwind:bool; required_headers:tuple[str,...]; required_library:str|None; pic_plt_compatible:bool; tls_compatible:bool; exact_semantic_contract_id:str

@dataclass(frozen=True)
class TargetAbiWrapperRegistry:
    contracts:tuple[TargetAbiWrapperContract,...]=(); version:str=""
    def resolve(self,effects:SourceAbiEffectModel,target_abi:str)->TargetAbiWrapperContract|None:
        if not effects.complete or len(effects.calls)!=1:return None
        call=effects.calls[0]; matches=[x for x in self.contracts if x.source_abi_profile is effects.source_abi_profile and x.target_abi==target_abi and x.source_target_id==call.target.target_id and x.exact_semantic_contract_id==call.target.semantic_contract_id and x.semantic_version==call.target.semantic_version]
        return matches[0] if len(matches)==1 else None
