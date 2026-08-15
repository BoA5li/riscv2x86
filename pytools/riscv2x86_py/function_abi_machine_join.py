"""Phase-5 exact join of compiler ABI declarations and machine facts."""
from __future__ import annotations
from dataclasses import dataclass
from .function_abi_sidecar import FunctionAbiDeclarationFacts
from .function_frame_analysis import FunctionFrameAnalysis
from .whole_function import SourceFunctionControlFlowModel, FunctionAbiFacts

@dataclass(frozen=True)
class FunctionMachineAbiFacts:
    function_id:str; source_abi_profile:str|None; pic_plt_mode:str|None; tls_model:str|None
    may_unwind:bool|None; may_trap:bool|None; direct_calls_complete:bool
    callee_saved_preserved:bool; stack_alignment_bytes:int|None; complete:bool

@dataclass(frozen=True)
class FunctionAbiMachineJoin:
    abi:FunctionAbiFacts; complete:bool; missing_fact_codes:tuple[str,...]

def join_function_abi_machine(*,declaration:FunctionAbiDeclarationFacts|None,machine:FunctionMachineAbiFacts|None,cfg:SourceFunctionControlFlowModel|None,frame:FunctionFrameAnalysis|None)->FunctionAbiMachineJoin:
    r=[]
    if declaration is None:r.append("whole-function.abi-declaration-missing")
    if machine is None:r.append("whole-function.machine-abi-facts-missing")
    if cfg is None or not cfg.complete:r.append("whole-function.cfg-incomplete")
    if frame is None or not frame.complete:r.append("whole-function.frame-analysis-incomplete")
    if declaration and machine:
        if not declaration.complete:r.append("whole-function.abi-declaration-incomplete")
        if not machine.complete:r.append("whole-function.machine-abi-facts-incomplete")
        if declaration.function_id!=machine.function_id:r.append("whole-function.abi-function-identity-mismatch")
        if declaration.source_abi_profile!=machine.source_abi_profile:r.append("whole-function.abi-profile-mismatch")
        if declaration.pic_plt_mode!=machine.pic_plt_mode:r.append("whole-function.pic-plt-mismatch")
        if declaration.tls_model!=machine.tls_model:r.append("whole-function.tls-mismatch")
        if declaration.unwind_enabled is None or declaration.unwind_enabled!=machine.may_unwind:r.append("whole-function.unwind-mismatch-or-unproven")
        if not machine.direct_calls_complete:r.append("whole-function.direct-call-identity-unproven")
        if not machine.callee_saved_preserved:r.append("whole-function.callee-saved-unproven")
        if frame and machine.stack_alignment_bytes!=frame.stack.required_alignment_bytes:r.append("whole-function.call-alignment-unproven")
    if declaration and cfg and declaration.unwind_enabled is False and cfg.has_exceptional_exit:r.append("whole-function.unwind-cfg-mismatch")
    complete=not r
    abi=FunctionAbiFacts("unknown" if declaration is None else declaration.source_abi_profile,complete,complete,False if machine is None else machine.direct_calls_complete,complete,None if machine is None else machine.may_unwind,None if machine is None else machine.may_trap,complete)
    return FunctionAbiMachineJoin(abi,complete,tuple(sorted(set(r))))
