"""Phase-6A read-only adapter for validated whole-function facts."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from .whole_function import *
from .function_abi_sidecar import FunctionAbiDeclarationFacts
from .function_abi_machine_join import FunctionAbiMachineJoin
from .function_frame_analysis import FunctionFrameAnalysis

@dataclass(frozen=True)
class FrontendFunctionFacts:
    function_id:str; ast_binding:FunctionAstBinding; fragment_ids:tuple[str,...]
    complete:bool; missing_fact_codes:tuple[str,...]=()

def build_whole_function_translation_facts(*,frontend:FrontendFunctionFacts|None,mixed_cfg:SourceFunctionControlFlowModel|None,frame:FunctionFrameAnalysis|None,declaration:FunctionAbiDeclarationFacts|None,abi_join:FunctionAbiMachineJoin|None,renderer_contract:WholeFunctionRendererContract|None)->WholeFunctionTranslationFacts:
    reasons=[]
    if frontend is None: reasons.append("whole-function.frontend-facts-missing")
    if mixed_cfg is None or not mixed_cfg.complete: reasons.append("whole-function.mixed-cfg-incomplete")
    if frame is None or not frame.complete: reasons.append("whole-function.frame-analysis-incomplete")
    if declaration is None or not declaration.complete: reasons.append("whole-function.abi-declaration-incomplete")
    if abi_join is None or not abi_join.complete: reasons.append("whole-function.abi-machine-join-incomplete")
    if renderer_contract is None or not renderer_contract.complete: reasons.append("whole-function.renderer-contract-incomplete")
    if frontend:
        reasons.extend(frontend.missing_fact_codes)
        if not frontend.complete or not frontend.ast_binding.complete: reasons.append("whole-function.frontend-facts-incomplete")
        if declaration and frontend.function_id!=declaration.function_id: reasons.append("whole-function.frontend-abi-function-mismatch")
        if renderer_contract and renderer_contract.function_id!=frontend.function_id: reasons.append("whole-function.renderer-function-mismatch")
    complete=not reasons
    unit=FunctionTranslationUnit("" if frontend is None else frontend.function_id,None if frontend is None else frontend.ast_binding.c_ast_function_binding_id,"unknown" if declaration is None else declaration.source_abi_profile,complete,tuple(sorted(set(reasons))))
    evidence=None if reasons else WholeFunctionPhase5Evidence(
        "sha256:"+sha256(repr(mixed_cfg).encode()).hexdigest(),
        "sha256:"+sha256(repr(frame).encode()).hexdigest(),
        "sha256:"+sha256(repr(declaration).encode()).hexdigest(),
        "sha256:"+sha256(repr(abi_join).encode()).hexdigest(),
    )
    return WholeFunctionTranslationFacts(unit,None if frontend is None else frontend.ast_binding,mixed_cfg,None if frame is None else frame.stack,None if abi_join is None else abi_join.abi,() if frame is None else frame.callee_saved_effects,() if frontend is None else frontend.fragment_ids,renderer_contract,complete,tuple(sorted(set(reasons))),evidence)
