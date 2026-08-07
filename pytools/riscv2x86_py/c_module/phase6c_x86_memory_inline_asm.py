"""Phase 6C-5 x86 memory-inline-asm contracts; compiler barriers only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING
from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import SourceOperandKind, SourceSemanticModel
if TYPE_CHECKING: from ..phase6c_constraints import TargetConstraintDerivationResult, TargetEnvironment

@dataclass(frozen=True)
class X86MemoryOperandContract:
    source_operand_index: int
    access: str
    alignment_bytes: int | None
    alias_precision: str

@dataclass(frozen=True)
class X86MemoryInlineAsmContract:
    operands: tuple[X86MemoryOperandContract, ...]
    memory_clobber: bool
    compiler_barrier: bool
    volatile: bool
    hardware_fence: bool = False

def _fail(plan, code, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id,reason_codes=(getattr(TargetConstraintReasonCode,code),),details={} if details is None else details)

def derive_x86_memory_inline_asm_constraints(source_model: SourceSemanticModel,candidate_plan: TargetLoweringPlan,target_environment:"TargetEnvironment")->"TargetConstraintDerivationResult":
    from ..phase6c_constraints import TargetConstraintDerivationResult,TargetConstraintModel,TargetMemoryConstraint,TargetControlFlowConstraint
    if candidate_plan.kind is not TargetLoweringKind.X86_GNU_INLINE_ASM:return _fail(candidate_plan,"X86_MEMORY_ASM_PLAN_KIND_MISMATCH")
    if "x86:gpr_inline_asm" not in target_environment.available_features:return _fail(candidate_plan,"X86_MEMORY_ASM_FEATURE_UNAVAILABLE")
    if not source_model.operands.complete or not source_model.operation.complete:return _fail(candidate_plan,"X86_MEMORY_ASM_SOURCE_INCOMPLETE")
    if source_model.atomic.present or source_model.barrier.present or source_model.memory.has_memory_barrier or source_model.memory.has_instruction_barrier or source_model.memory.has_unknown_barrier:return _fail(candidate_plan,"X86_MEMORY_ASM_HARDWARE_SEMANTICS_UNSUPPORTED")
    if source_model.operation.has_control_flow or source_model.operation.has_call or source_model.operation.has_return is not False or source_model.operation.may_trap is not False:return _fail(candidate_plan,"X86_MEMORY_ASM_CONTROL_FLOW_UNSUPPORTED")
    ops=[]
    for op in source_model.operands.operands:
        if op.kind not in {SourceOperandKind.MEMORY,SourceOperandKind.ADDRESS}:continue
        if op.address is None:return _fail(candidate_plan,"X86_MEMORY_ASM_ADDRESS_BINDING_MISSING",{"source_operand_index":op.source_operand_index})
        if not op.address.provenance_known:
            precision="unknown"
        else: precision="precise"
        ops.append(X86MemoryOperandContract(op.source_operand_index,op.access.value,op.address.alignment_bytes,precision))
    reads=source_model.operation.reads_memory or source_model.memory.reads_memory; writes=source_model.operation.writes_memory or source_model.memory.writes_memory
    if (reads or writes) and not ops:return _fail(candidate_plan,"X86_MEMORY_ASM_ADDRESS_BINDING_MISSING")
    conservative=source_model.shell.has_memory_clobber or any(o.alias_precision=="unknown" for o in ops)
    if any(o.alias_precision=="unknown" for o in ops) and not conservative:return _fail(candidate_plan,"X86_MEMORY_ASM_ALIAS_UNKNOWN")
    contract=X86MemoryInlineAsmContract(tuple(ops),conservative,conservative,source_model.shell.is_volatile,False)
    mem=TargetMemoryConstraint(requires_memory_clobber=conservative,requires_compiler_barrier=conservative,required_alignment_bytes=next((o.alignment_bytes for o in ops if o.alignment_bytes),None))
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,environment=target_environment,x86_memory_inline_asm_contract=contract,memory_constraint=mem,control_flow_constraint=TargetControlFlowConstraint(),preserve_volatile=source_model.shell.is_volatile))
