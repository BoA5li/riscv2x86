"""Phase 6C-4 register-only x86 GNU inline-asm contracts."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING
from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import SourceOperandAccess, SourceOperandKind, SourceSemanticModel

if TYPE_CHECKING:
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetEnvironment

class X86OperandRole(str, Enum):
    INPUT="input"; OUTPUT="output"; READ_WRITE="read_write"

@dataclass(frozen=True)
class X86GprOperandContract:
    source_operand_index: int
    role: X86OperandRole
    width_bits: int
    signedness: str
    host_c_type_id: str | None
    upper_bits_policy: str
    fixed_register_name: str | None = None
    tied_to_source_operand_index: int | None = None
    early_clobber: bool = False
    immediate: bool = False

@dataclass(frozen=True)
class X86GnuInlineAsmContract:
    operands: tuple[X86GprOperandContract, ...]
    volatile: bool
    cc_clobber: bool
    required_target_feature: str

def _fail(plan, code, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id, reason_codes=(getattr(TargetConstraintReasonCode, code),), details={} if details is None else details)

def derive_x86_gnu_inline_asm_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint
    if candidate_plan.kind is not TargetLoweringKind.X86_GNU_INLINE_ASM: return _fail(candidate_plan,"X86_INLINE_ASM_PLAN_KIND_MISMATCH")
    feature="x86:gpr_inline_asm"
    if feature not in target_environment.available_features: return _fail(candidate_plan,"X86_INLINE_ASM_FEATURE_UNAVAILABLE",{"feature":feature})
    if not source_model.operands.complete or not source_model.operation.complete or not source_model.implicit_state.complete: return _fail(candidate_plan,"X86_INLINE_ASM_SOURCE_INCOMPLETE")
    if source_model.operation.kind.value != "register_only" or source_model.operation.reads_memory or source_model.operation.writes_memory or source_model.memory.reads_memory or source_model.memory.writes_memory or source_model.atomic.present or source_model.barrier.present: return _fail(candidate_plan,"X86_INLINE_ASM_NON_REGISTER_SEMANTICS")
    cf=source_model.control_flow
    if source_model.operation.has_control_flow or source_model.operation.has_call or source_model.operation.has_return is not False or source_model.operation.may_trap is not False or cf.has_internal_branch or cf.has_call or cf.has_return is not False or cf.has_asm_goto or cf.has_multiple_exits or cf.has_indirect_control_flow is not False: return _fail(candidate_plan,"X86_INLINE_ASM_CONTROL_FLOW_UNSUPPORTED")
    st=source_model.implicit_state
    if source_model.registers.reads_or_writes_stack_pointer or source_model.registers.reads_or_writes_frame_pointer or st.reads_stack_pointer or st.writes_stack_pointer or st.reads_frame_pointer or st.writes_frame_pointer or st.reads_implicit_machine_state or st.writes_implicit_machine_state: return _fail(candidate_plan,"X86_INLINE_ASM_IMPLICIT_STATE_UNSUPPORTED")
    shell=source_model.shell
    if shell.has_memory_clobber or shell.has_asm_goto or shell.has_external_control_flow: return _fail(candidate_plan,"X86_INLINE_ASM_SHELL_UNSUPPORTED")
    operands=[]
    for op in source_model.operands.operands:
        if op.kind not in {SourceOperandKind.REGISTER,SourceOperandKind.IMMEDIATE,SourceOperandKind.FIXED_REGISTER} or op.width_bits not in {8,16,32,64} or op.signedness.value == "unknown": return _fail(candidate_plan,"X86_INLINE_ASM_OPERAND_UNSUPPORTED",{"source_operand_index":op.source_operand_index})
        if op.access is SourceOperandAccess.INPUT: role=X86OperandRole.INPUT
        elif op.access is SourceOperandAccess.OUTPUT: role=X86OperandRole.OUTPUT
        elif op.access is SourceOperandAccess.READ_WRITE: role=X86OperandRole.READ_WRITE
        else: return _fail(candidate_plan,"X86_INLINE_ASM_OPERAND_UNSUPPORTED",{"source_operand_index":op.source_operand_index})
        if role is not X86OperandRole.OUTPUT and (op.expression is None or not op.expression.c_type_id): return _fail(candidate_plan,"X86_INLINE_ASM_BINDING_INCOMPLETE",{"source_operand_index":op.source_operand_index})
        if role is not X86OperandRole.INPUT and (op.lvalue is None or not op.lvalue.c_type_id or not op.lvalue.is_modifiable): return _fail(candidate_plan,"X86_INLINE_ASM_BINDING_INCOMPLETE",{"source_operand_index":op.source_operand_index})
        host=(op.lvalue.c_type_id if role is not X86OperandRole.INPUT else op.expression.c_type_id)
        operands.append(X86GprOperandContract(op.source_operand_index,role,op.width_bits,op.signedness.value,host,"zero_extend" if op.width_bits==32 else "preserve",op.fixed_register_name,op.tied_to_source_operand_index,op.early_clobber,op.kind is SourceOperandKind.IMMEDIATE))
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,environment=target_environment,x86_gnu_inline_asm_contract=X86GnuInlineAsmContract(tuple(operands),shell.is_volatile,shell.has_cc_clobber,feature),memory_constraint=TargetMemoryConstraint(),control_flow_constraint=TargetControlFlowConstraint(),preserve_volatile=shell.is_volatile,preserve_cc_clobber=shell.has_cc_clobber))
