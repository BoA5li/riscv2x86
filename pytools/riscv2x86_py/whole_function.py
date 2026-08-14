"""Function-scope routing facts for ABI-visible RISC-V inline assembly.

This module is intentionally a route boundary, not a local-asm lowerer.  It
contains no target text and never authorizes a fragment replacement.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

class WholeFunctionClassification(str, Enum):
    NOT_REQUIRED="not_required"; ELIGIBLE_STATIC="eligible_static"
    REQUIRES_UNWIND_ROUTE="requires_unwind_route"; UNSUPPORTED="unsupported"; UNKNOWN="unknown"

class WholeFunctionLoweringKind(str, Enum):
    STRUCTURED_C_FUNCTION="structured_c_function"
    NEEDS_UNWIND_ROUTE="needs_unwind_route"
    UNSUPPORTED="unsupported"

@dataclass(frozen=True)
class FunctionTranslationUnit:
    function_id:str
    c_ast_function_binding_id:str | None
    source_abi_profile:str
    complete:bool
    missing_fact_codes:tuple[str,...]=()

@dataclass(frozen=True)
class SourceFunctionStackModel:
    frame_kind:str; net_stack_delta_bytes:int|None
    dynamic_adjustment_present:bool; real_stack_identity_required:bool
    complete:bool

@dataclass(frozen=True)
class WholeFunctionRouteDecision:
    classification:WholeFunctionClassification
    route_id:str|None
    required:bool
    complete:bool
    reason_codes:tuple[str,...]=()

@dataclass(frozen=True)
class WholeFunctionSemanticModel:
    unit:FunctionTranslationUnit
    stack:SourceFunctionStackModel
    reads_ra:bool; writes_ra:bool
    has_call:bool; has_return:bool|None; has_tail_call:bool|None
    callee_saved_registers:tuple[str,...]
    has_unwind_or_exception_edge:bool|None
    complete:bool
    missing_fact_codes:tuple[str,...]=()

@dataclass(frozen=True)
class WholeFunctionLoweringPlan:
    plan_id:str; kind:WholeFunctionLoweringKind; route_id:str
    requirements:frozenset[str]; reason_codes:tuple[str,...]=()

@dataclass(frozen=True)
class WholeFunctionProofResult:
    approved:bool; plan_id:str; reason_codes:tuple[str,...]=()

def generate_whole_function_candidate_plans(model:WholeFunctionSemanticModel, route:WholeFunctionRouteDecision) -> tuple[WholeFunctionLoweringPlan,...]:
    """Independent Phase 6B entry point; never returns a fragment plan."""
    if not route.required:
        return ()
    if route.classification is WholeFunctionClassification.ELIGIBLE_STATIC and model.complete:
        return (WholeFunctionLoweringPlan("whole-function.structured-c.static.v1",WholeFunctionLoweringKind.STRUCTURED_C_FUNCTION,route.route_id or "whole-function-abi-lowering.v1",frozenset({"prove_function_entry_abi","prove_function_exit_abi","prove_all_exit_stack_restoration","prove_callee_saved_state","prove_return_continuation","prove_function_cfg_completeness","prove_function_call_effects","prove_function_shell_integration"}),route.reason_codes),)
    kind=WholeFunctionLoweringKind.NEEDS_UNWIND_ROUTE if route.classification is WholeFunctionClassification.REQUIRES_UNWIND_ROUTE else WholeFunctionLoweringKind.UNSUPPORTED
    return (WholeFunctionLoweringPlan("whole-function.route-required.v1",kind,route.route_id or "whole-function-abi-lowering.v1",frozenset(),route.reason_codes),)

def prove_whole_function_plan(*, model:WholeFunctionSemanticModel, plan:WholeFunctionLoweringPlan) -> WholeFunctionProofResult:
    """First D gate: approval is deliberately withheld until a renderer exists."""
    if plan.kind is not WholeFunctionLoweringKind.STRUCTURED_C_FUNCTION:
        return WholeFunctionProofResult(False,plan.plan_id,plan.reason_codes or ("whole-function.route-not-implemented",))
    # The current branch only establishes scope, facts, and routing.  It must
    # not claim a function rewrite exists before entry/exit ABI and renderer
    # contracts are implemented.
    return WholeFunctionProofResult(False,plan.plan_id,("whole-function.structured-c-renderer-not-implemented",))

def build_whole_function_semantic_model(*, unit:FunctionTranslationUnit, route:WholeFunctionRouteDecision,
                                        source_model) -> WholeFunctionSemanticModel:
    """Adapt Phase-6A facts into a function-scope model without raw rescans."""
    if not isinstance(unit, FunctionTranslationUnit):
        raise TypeError("unit must be FunctionTranslationUnit")
    stack=getattr(source_model,"stack_frame",None); control=getattr(source_model,"control_flow",None)
    registers=getattr(source_model,"registers",None)
    if control is None or registers is None:
        raise TypeError("source_model must expose structured Phase-6A facts")
    frame=SourceFunctionStackModel(
        "none" if stack is None else stack.kind.value,
        0 if stack is None else stack.net_stack_delta_bytes,
        False if stack is None else stack.has_dynamic_adjustment,
        False if stack is None else stack.requires_real_stack_identity,
        True if stack is None else stack.complete,
    )
    regs=registers.reads_registers|registers.writes_registers
    callee=tuple(sorted(x for x in regs if x in {"s0","fp","x8","s1","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11"}))
    missing=tuple(sorted(set(unit.missing_fact_codes + (() if route.complete else route.reason_codes))))
    return WholeFunctionSemanticModel(unit,frame,"ra" in registers.reads_registers or "x1" in registers.reads_registers,"ra" in registers.writes_registers or "x1" in registers.writes_registers,control.has_call,control.has_return,control.has_tail_call,callee,None,unit.complete and route.complete and frame.complete,missing)

def classify_whole_function_route(*, reads_registers:frozenset[str], writes_registers:frozenset[str],
                                  has_call:bool, has_return:bool|None, has_tail_call:bool|None,
                                  stack_kind:str|None, dynamic_adjustment:bool, stack_complete:bool,
                                  has_unwind_or_exception_edge:bool|None) -> WholeFunctionRouteDecision:
    """Fail closed classification based solely on Phase-6A structured facts."""
    regs=reads_registers|writes_registers; reasons=[]
    ra_observable="ra" in regs or "x1" in regs
    callee=tuple(sorted(r for r in regs if r in {"s0","fp","x8","s1","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11"}))
    required=ra_observable or has_return is True or has_tail_call is True or stack_kind in {"call_frame","whole_function"} or bool(callee) or dynamic_adjustment
    if not required:
        return WholeFunctionRouteDecision(WholeFunctionClassification.NOT_REQUIRED,None,False,True)
    if has_unwind_or_exception_edge is True:
        return WholeFunctionRouteDecision(WholeFunctionClassification.REQUIRES_UNWIND_ROUTE,"whole-function-abi-lowering.v1",True,True,("whole-function.unwind-route-required",))
    if has_return is None or has_tail_call is None or not stack_complete or has_unwind_or_exception_edge is None:
        return WholeFunctionRouteDecision(WholeFunctionClassification.UNKNOWN,"whole-function-abi-lowering.v1",True,False,("whole-function.facts-incomplete",))
    if dynamic_adjustment or has_tail_call:
        return WholeFunctionRouteDecision(WholeFunctionClassification.UNSUPPORTED,"whole-function-abi-lowering.v1",True,True,("whole-function.dynamic-frame-or-tail-call",))
    if ra_observable: reasons.append("whole-function.ra-or-return-observable")
    if has_return is True: reasons.append("whole-function.return-continuation")
    if callee: reasons.append("whole-function.callee-saved-state")
    if has_call: reasons.append("whole-function.call-frame")
    return WholeFunctionRouteDecision(WholeFunctionClassification.ELIGIBLE_STATIC,"whole-function-abi-lowering.v1",True,True,tuple(reasons))
