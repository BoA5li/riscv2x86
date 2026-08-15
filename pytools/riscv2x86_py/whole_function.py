"""Fail-closed whole-function lowering for ABI-visible inline assembly.

This is an independent D-class route.  It replaces a bound C *function
definition*, never a single asm statement; all source facts are frontend
sidecar / Phase-5 products and every incomplete input is rejected.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Iterable


class WholeFunctionClassification(str, Enum):
    NOT_REQUIRED="not_required"; ELIGIBLE_STATIC="eligible_static"
    REQUIRES_UNWIND_ROUTE="requires_unwind_route"; UNSUPPORTED="unsupported"; UNKNOWN="unknown"
class WholeFunctionLoweringKind(str, Enum):
    STRUCTURED_C_FUNCTION="structured_c_function"; RUNTIME_STATE_MACHINE_FUNCTION="runtime_state_machine_function"
    NEEDS_UNWIND_ROUTE="needs_unwind_route"; UNSUPPORTED="unsupported"
class FunctionExitKind(str, Enum):
    NORMAL_RETURN="normal_return"; NORETURN="noreturn"; EXCEPTIONAL="exceptional"; NONLOCAL="nonlocal"; UNKNOWN="unknown"

@dataclass(frozen=True)
class SourceTextRange:
    start:int; end:int
    def __post_init__(self):
        if self.start < 0 or self.end < self.start: raise ValueError("source range must be non-negative and half-open")

@dataclass(frozen=True)
class FunctionAstBinding:
    function_id:str; c_ast_function_binding_id:str; definition_range:SourceTextRange
    parameter_binding_ids:tuple[str,...]=(); return_binding_id:str|None=None
    has_vla_or_cleanup_sensitive_scope:bool=False; complete:bool=False; provenance:str=""
    # The range is file-relative.  This path is part of the authoritative
    # frontend binding, never inferred from a member asm fragment.
    source_file:str=""

@dataclass(frozen=True)
class FunctionCfgNode:
    node_id:str; kind:str; source_binding_id:str|None; complete:bool
@dataclass(frozen=True)
class FunctionCfgEdge:
    source_node_id:str; target_node_id:str; kind:str; complete:bool
@dataclass(frozen=True)
class FunctionExitBinding:
    exit_id:str; node_id:str; kind:FunctionExitKind; complete:bool
@dataclass(frozen=True)
class SourceFunctionControlFlowModel:
    entry_node_id:str; nodes:tuple[FunctionCfgNode,...]; edges:tuple[FunctionCfgEdge,...]
    exits:tuple[FunctionExitBinding,...]; complete:bool; missing_fact_codes:tuple[str,...]=()
    def __post_init__(self):
        if len({x.node_id for x in self.nodes}) != len(self.nodes): raise ValueError("function CFG node ids must be unique")
        if self.complete and (not self.entry_node_id or not self.exits): raise ValueError("complete function CFG needs entry and exits")
    @property
    def normal_exits(self): return tuple(x for x in self.exits if x.kind is FunctionExitKind.NORMAL_RETURN)
    @property
    def has_exceptional_exit(self): return any(x.kind in {FunctionExitKind.EXCEPTIONAL,FunctionExitKind.NONLOCAL,FunctionExitKind.UNKNOWN} for x in self.exits)

@dataclass(frozen=True)
class FunctionFramePathSummary:
    exit_id:str; final_sp_offset_bytes:int|None; stack_alignment_bytes:int|None; complete:bool
@dataclass(frozen=True)
class SourceFunctionStackModel:
    # Original five fields remain first for source compatibility.
    frame_kind:str; net_stack_delta_bytes:int|None; dynamic_adjustment_present:bool; real_stack_identity_required:bool; complete:bool
    frame_size_bytes:int|None=None; required_alignment_bytes:int|None=None
    exit_summaries:tuple[FunctionFramePathSummary,...]=()
    all_normal_exits_restore_entry_sp:bool=False; all_call_sites_aligned:bool=False

@dataclass(frozen=True)
class CalleeSavedRegisterEffect:
    register:str; save_site_ids:tuple[str,...]; restore_site_ids:tuple[str,...]; modified_site_ids:tuple[str,...]
    restored_on_all_normal_exits:bool; complete:bool
@dataclass(frozen=True)
class FunctionAbiFacts:
    source_abi_profile:str; entry_complete:bool; exits_complete:bool; calls_complete:bool; pic_plt_tls_complete:bool
    may_unwind:bool|None; may_trap:bool|None; complete:bool
@dataclass(frozen=True)
class WholeFunctionRendererContract:
    """Versioned structured-C recipe. It is never inferred from asm text."""
    contract_id:str; version:str; function_id:str; replacement_text:str
    required_headers:tuple[str,...]=(); required_libraries:tuple[str,...]=()
    compiler_managed_stack_only:bool=True; complete:bool=False

@dataclass(frozen=True)
class FunctionTranslationUnit:
    function_id:str; c_ast_function_binding_id:str|None; source_abi_profile:str; complete:bool
    missing_fact_codes:tuple[str,...]=()
@dataclass(frozen=True)
class WholeFunctionTranslationFacts:
    unit:FunctionTranslationUnit; ast_binding:FunctionAstBinding|None; control_flow:SourceFunctionControlFlowModel|None
    stack:SourceFunctionStackModel|None; abi:FunctionAbiFacts|None
    callee_saved_effects:tuple[CalleeSavedRegisterEffect,...]=(); fragment_ids:tuple[str,...]=()
    renderer_contract:WholeFunctionRendererContract|None=None; complete:bool=False; missing_fact_codes:tuple[str,...]=()
    def __post_init__(self):
        if len(set(self.fragment_ids)) != len(self.fragment_ids): raise ValueError("whole-function fragment ids must be unique")
        if self.complete and self.ast_binding is None: raise ValueError("complete whole-function facts need AST binding")

@dataclass(frozen=True)
class WholeFunctionRouteDecision:
    classification:WholeFunctionClassification; route_id:str|None; required:bool; complete:bool; reason_codes:tuple[str,...]=()
@dataclass(frozen=True)
class WholeFunctionSemanticModel:
    # Keep historical fields first for compatibility with earlier route tests.
    unit:FunctionTranslationUnit; stack:SourceFunctionStackModel
    reads_ra:bool; writes_ra:bool; has_call:bool; has_return:bool|None; has_tail_call:bool|None
    callee_saved_registers:tuple[str,...]; has_unwind_or_exception_edge:bool|None; complete:bool; missing_fact_codes:tuple[str,...]=()
    ast_binding:FunctionAstBinding|None=None; control_flow:SourceFunctionControlFlowModel|None=None
    abi:FunctionAbiFacts|None=None; callee_saved_effects:tuple[CalleeSavedRegisterEffect,...]=()
    renderer_contract:WholeFunctionRendererContract|None=None
@dataclass(frozen=True)
class WholeFunctionLoweringPlan:
    plan_id:str; kind:WholeFunctionLoweringKind; route_id:str; requirements:frozenset[str]; reason_codes:tuple[str,...]=()
@dataclass(frozen=True)
class WholeFunctionProofResult:
    approved:bool; plan_id:str; reason_codes:tuple[str,...]; proof_identity:str|None=None
@dataclass(frozen=True)
class FunctionReplacementArtifact:
    function_id:str; ast_binding_id:str; source_definition_range:SourceTextRange; replacement_text:str
    proof_identity:str; renderer_contract_id:str; renderer_contract_version:str
    required_headers:tuple[str,...]; required_libraries:tuple[str,...]

def _ordered(values:Iterable[str])->tuple[str,...]: return tuple(sorted(set(x for x in values if x)))

def classify_whole_function_route(*, reads_registers:frozenset[str], writes_registers:frozenset[str],
                                  has_call:bool, has_return:bool|None, has_tail_call:bool|None,
                                  stack_kind:str|None, dynamic_adjustment:bool, stack_complete:bool,
                                  has_unwind_or_exception_edge:bool|None)->WholeFunctionRouteDecision:
    regs=reads_registers|writes_registers; ra_observable="ra" in regs or "x1" in regs
    callee=tuple(sorted(r for r in regs if r in {"s0","fp","x8","s1","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11"}))
    required=ra_observable or has_return is True or has_tail_call is True or stack_kind in {"call_frame","whole_function"} or bool(callee) or dynamic_adjustment
    if not required:return WholeFunctionRouteDecision(WholeFunctionClassification.NOT_REQUIRED,None,False,True)
    if has_unwind_or_exception_edge is True:return WholeFunctionRouteDecision(WholeFunctionClassification.REQUIRES_UNWIND_ROUTE,"whole-function-abi-lowering.v1",True,True,("whole-function.unwind-route-required",))
    if has_return is None or has_tail_call is None or not stack_complete or has_unwind_or_exception_edge is None:return WholeFunctionRouteDecision(WholeFunctionClassification.UNKNOWN,"whole-function-abi-lowering.v1",True,False,("whole-function.facts-incomplete",))
    if dynamic_adjustment or has_tail_call:return WholeFunctionRouteDecision(WholeFunctionClassification.UNSUPPORTED,"whole-function-abi-lowering.v1",True,True,("whole-function.dynamic-frame-or-tail-call",))
    reasons=[]
    if ra_observable:reasons.append("whole-function.ra-or-return-observable")
    if has_return is True:reasons.append("whole-function.return-continuation")
    if callee:reasons.append("whole-function.callee-saved-state")
    if has_call:reasons.append("whole-function.call-frame")
    return WholeFunctionRouteDecision(WholeFunctionClassification.ELIGIBLE_STATIC,"whole-function-abi-lowering.v1",True,True,tuple(reasons))

def build_whole_function_semantic_model(*, unit:FunctionTranslationUnit, route:WholeFunctionRouteDecision, source_model=None, facts:WholeFunctionTranslationFacts|None=None)->WholeFunctionSemanticModel:
    """Phase-6A adapter. A lone fragment source model can route, never render."""
    if facts is not None:
        if facts.unit.function_id != unit.function_id: raise ValueError("whole-function facts belong to another function")
        stack=facts.stack or SourceFunctionStackModel("unknown",None,True,True,False)
        cfg=facts.control_flow; abi=facts.abi; effects=tuple(sorted(facts.callee_saved_effects,key=lambda x:x.register))
        exits_ok=cfg is not None and bool(cfg.normal_exits) and not cfg.has_exceptional_exit
        callee_ok=all(x.complete and x.restored_on_all_normal_exits for x in effects)
        complete=bool(facts.complete and facts.ast_binding and facts.ast_binding.complete and cfg and cfg.complete and exits_ok and stack.complete and abi and abi.complete and callee_ok and route.complete)
        missing=list(unit.missing_fact_codes)+list(facts.missing_fact_codes)+([] if route.complete else list(route.reason_codes))
        if not exits_ok:missing.append("whole-function.exit-facts-incomplete")
        if not callee_ok:missing.append("whole-function.callee-saved-facts-incomplete")
        return WholeFunctionSemanticModel(unit,stack,False,False,bool(cfg and any(x.kind=="call" for x in cfg.nodes)),bool(cfg and cfg.normal_exits),False,tuple(x.register for x in effects),bool(cfg and cfg.has_exceptional_exit),complete,_ordered(missing),facts.ast_binding,cfg,abi,effects,facts.renderer_contract)
    stack0=getattr(source_model,"stack_frame",None); control=getattr(source_model,"control_flow",None); registers=getattr(source_model,"registers",None)
    if control is None or registers is None: raise TypeError("source_model must expose structured Phase-6A facts")
    stack=SourceFunctionStackModel("none" if stack0 is None else stack0.kind.value,0 if stack0 is None else stack0.net_stack_delta_bytes,False if stack0 is None else stack0.has_dynamic_adjustment,False if stack0 is None else stack0.requires_real_stack_identity,True if stack0 is None else stack0.complete)
    regs=registers.reads_registers|registers.writes_registers
    callee=tuple(sorted(x for x in regs if x in {"s0","fp","x8","s1","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11"}))
    return WholeFunctionSemanticModel(unit,stack,"ra" in registers.reads_registers or "x1" in registers.reads_registers,"ra" in registers.writes_registers or "x1" in registers.writes_registers,control.has_call,control.has_return,control.has_tail_call,callee,None,False,_ordered((*unit.missing_fact_codes,"whole-function.frontend-facts-required")))

_STATIC_REQUIREMENTS=frozenset({"prove_function_ast_binding","prove_function_cfg_completeness","prove_function_entry_abi","prove_function_exit_abi","prove_all_exit_stack_restoration","prove_static_function_frame","prove_function_frame_layout","prove_callee_saved_state","prove_function_call_effects","prove_return_continuation","prove_no_real_stack_identity","prove_no_unwind_or_nonlocal_transfer","prove_function_shell_integration","prove_function_writeback_binding"})
def generate_whole_function_candidate_plans(model:WholeFunctionSemanticModel,route:WholeFunctionRouteDecision)->tuple[WholeFunctionLoweringPlan,...]:
    if not route.required:return ()
    if route.classification is WholeFunctionClassification.ELIGIBLE_STATIC and model.complete:return (WholeFunctionLoweringPlan("whole-function.structured-c.static.v1",WholeFunctionLoweringKind.STRUCTURED_C_FUNCTION,route.route_id or "whole-function-abi-lowering.v1",_STATIC_REQUIREMENTS,route.reason_codes),)
    kind=WholeFunctionLoweringKind.NEEDS_UNWIND_ROUTE if route.classification is WholeFunctionClassification.REQUIRES_UNWIND_ROUTE else WholeFunctionLoweringKind.UNSUPPORTED
    return (WholeFunctionLoweringPlan("whole-function.route-required.v1",kind,route.route_id or "whole-function-abi-lowering.v1",frozenset(),route.reason_codes),)
def _proof_id(model,plan):
    c=model.renderer_contract
    return "sha256:"+sha256(repr((model.unit,model.ast_binding,model.control_flow,model.stack,model.abi,model.callee_saved_effects,plan.plan_id,None if c is None else (c.contract_id,c.version))).encode()).hexdigest()
def prove_whole_function_plan(*,model:WholeFunctionSemanticModel,plan:WholeFunctionLoweringPlan)->WholeFunctionProofResult:
    if plan.kind is not WholeFunctionLoweringKind.STRUCTURED_C_FUNCTION:return WholeFunctionProofResult(False,plan.plan_id,plan.reason_codes or ("whole-function.route-not-implemented",))
    reasons=[]; ast,cfg,abi,contract=model.ast_binding,model.control_flow,model.abi,model.renderer_contract
    if not model.complete:reasons.append("phase6d.whole_function.facts-incomplete")
    if ast is None or not ast.complete or ast.c_ast_function_binding_id!=model.unit.c_ast_function_binding_id:reasons.append("phase6d.whole_function.ast_binding_missing")
    if cfg is None or not cfg.complete or not cfg.normal_exits:reasons.append("phase6d.whole_function.cfg_incomplete")
    elif cfg.has_exceptional_exit:reasons.append("phase6d.whole_function.unwind_or_nonlocal_transfer")
    if model.stack.dynamic_adjustment_present or model.stack.net_stack_delta_bytes not in {0,None}:reasons.append("phase6d.whole_function.frame_unbalanced")
    if not model.stack.complete or not model.stack.all_normal_exits_restore_entry_sp:reasons.append("phase6d.whole_function.frame_layout_unproven")
    if model.stack.real_stack_identity_required:reasons.append("phase6d.whole_function.real_stack_identity_required")
    if abi is None or not abi.complete or not (abi.entry_complete and abi.exits_complete and abi.calls_complete and abi.pic_plt_tls_complete):reasons.append("phase6d.whole_function.entry_or_exit_abi_unproven")
    if abi is not None and (abi.may_unwind is not False or abi.may_trap is not False):reasons.append("phase6d.whole_function.unwind_or_trap_unproven")
    if any(not x.complete or not x.restored_on_all_normal_exits for x in model.callee_saved_effects):reasons.append("phase6d.whole_function.callee_saved_unproven")
    if contract is None or not contract.complete or contract.function_id!=model.unit.function_id:reasons.append("phase6d.whole_function.renderer_contract_missing")
    elif not contract.compiler_managed_stack_only or any(x in contract.replacement_text for x in ("%rsp","%rbp","__builtin_frame_address")):reasons.append("phase6d.whole_function.host_stack_mutation")
    if ast is not None and ast.has_vla_or_cleanup_sensitive_scope:reasons.append("phase6d.whole_function.scope_sensitive_ast")
    return WholeFunctionProofResult(not reasons,plan.plan_id,_ordered(reasons),_proof_id(model,plan) if not reasons else None)
def render_whole_function_replacement(*,model:WholeFunctionSemanticModel,plan:WholeFunctionLoweringPlan,proof:WholeFunctionProofResult)->FunctionReplacementArtifact|None:
    if not proof.approved or plan.kind is not WholeFunctionLoweringKind.STRUCTURED_C_FUNCTION:return None
    ast,contract=model.ast_binding,model.renderer_contract
    if ast is None or contract is None or not contract.replacement_text.strip() or proof.proof_identity is None:return None
    return FunctionReplacementArtifact(model.unit.function_id,ast.c_ast_function_binding_id,ast.definition_range,contract.replacement_text,proof.proof_identity,contract.contract_id,contract.version,tuple(sorted(contract.required_headers)),tuple(sorted(contract.required_libraries)))
def translate_whole_function(*,facts:WholeFunctionTranslationFacts,route:WholeFunctionRouteDecision)->tuple[FunctionReplacementArtifact|None,WholeFunctionProofResult|None]:
    model=build_whole_function_semantic_model(unit=facts.unit,route=route,facts=facts); plans=generate_whole_function_candidate_plans(model,route)
    if not plans:return None,None
    proof=prove_whole_function_plan(model=model,plan=plans[0])
    return render_whole_function_replacement(model=model,plan=plans[0],proof=proof),proof
