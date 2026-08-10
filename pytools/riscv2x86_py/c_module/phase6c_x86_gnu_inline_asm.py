"""Phase 6C-4 register-only x86 GNU inline-asm contracts."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING
from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import SourceOperandAccess, SourceOperandKind, SourceSemanticModel, SourceValueOperationKind

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
    value_operation_kind: SourceValueOperationKind

def _fail(plan, code, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id, reason_codes=(getattr(TargetConstraintReasonCode, code),), details={} if details is None else details)


_SUPPORTED_RENDERER_CONTRACTS = frozenset({
    "x86.gnu-att.gpr.rw-gpr-binary.v1",
    "x86.gnu-att.gpr.rw-immediate-binary.v1",
    "x86.gnu-att.gpr.rw-early-clobber-binary.v1",
})


def _validate_renderer_operand_contract(candidate_plan, operands, target_operands):
    """Validate the concrete contract selected by Phase 6B.

    This is a derivation-time compatibility check, not renderer inference:
    unknown variants and operand shapes without a registered proof-compatible
    recipe are rejected before they can reach Phase 6D/6E.
    """
    semantic_id = candidate_plan.metadata.get("renderer_semantic_contract_id")
    if semantic_id not in _SUPPORTED_RENDERER_CONTRACTS:
        return _fail(candidate_plan, "X86_INLINE_ASM_SEMANTIC_CONTRACT_UNSUPPORTED", {
            "renderer_semantic_contract_id": str(semantic_id),
        })

    outputs = [op for op in target_operands if op.role.name == "READ_WRITE"]
    inputs = [op for op in target_operands if op.role.name == "INPUT"]
    if len(outputs) != 1 or len(inputs) != 1:
        return _fail(candidate_plan, "X86_INLINE_ASM_OPERAND_CONTRACT_MISMATCH", {
            "renderer_semantic_contract_id": semantic_id,
            "expected": "one_read_write_output_and_one_input",
        })

    output, input_ = outputs[0], inputs[0]
    if output.required_width_bits not in {32, 64} or input_.required_width_bits != output.required_width_bits:
        return _fail(candidate_plan, "X86_INLINE_ASM_OPERAND_CONTRACT_MISMATCH", {
            "renderer_semantic_contract_id": semantic_id,
            "expected": "matching_32_or_64_bit_operands",
        })
    if output.tied_to_source_operand_index is not None or input_.tied_to_source_operand_index is not None:
        return _fail(candidate_plan, "X86_INLINE_ASM_OPERAND_CONTRACT_MISMATCH", {
            "renderer_semantic_contract_id": semantic_id,
            "expected": "no_tied_operand",
        })
    if output.requires_fixed_register or input_.requires_fixed_register:
        return _fail(candidate_plan, "X86_INLINE_ASM_OPERAND_CONTRACT_MISMATCH", {
            "renderer_semantic_contract_id": semantic_id,
            "expected": "no_fixed_register",
        })
    if TargetOperandClass.GENERAL_REGISTER not in output.allowed_classes:
        return _fail(candidate_plan, "X86_INLINE_ASM_OPERAND_CONTRACT_MISMATCH", {
            "renderer_semantic_contract_id": semantic_id,
            "expected": "gpr_read_write_output",
        })

    if semantic_id == "x86.gnu-att.gpr.rw-gpr-binary.v1":
        ok = (TargetOperandClass.GENERAL_REGISTER in input_.allowed_classes and
              not output.early_clobber and not input_.early_clobber)
    elif semantic_id == "x86.gnu-att.gpr.rw-immediate-binary.v1":
        ok = (TargetOperandClass.IMMEDIATE in input_.allowed_classes and
              not output.early_clobber and not input_.early_clobber)
    else:
        ok = (TargetOperandClass.GENERAL_REGISTER in input_.allowed_classes and
              output.early_clobber and not input_.early_clobber)
    if not ok:
        return _fail(candidate_plan, "X86_INLINE_ASM_OPERAND_CONTRACT_MISMATCH", {
            "renderer_semantic_contract_id": semantic_id,
            "expected": "registered_operand_variant",
        })
    return None

def derive_x86_gnu_inline_asm_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintModel, TargetMemoryConstraint, TargetControlFlowConstraint, TargetOperandConstraint, TargetOperandRole, TargetOperandClass
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
    if source_model.value_operation is None or not source_model.value_operation.complete:
        return _fail(candidate_plan,"X86_INLINE_ASM_SOURCE_INCOMPLETE")
    operands=[]; target_operands=[]
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
        allowed = frozenset({TargetOperandClass.IMMEDIATE}) if op.kind is SourceOperandKind.IMMEDIATE else frozenset({TargetOperandClass.GENERAL_REGISTER})
        target_operands.append(TargetOperandConstraint(op.source_operand_index, {X86OperandRole.INPUT:TargetOperandRole.INPUT,X86OperandRole.OUTPUT:TargetOperandRole.OUTPUT,X86OperandRole.READ_WRITE:TargetOperandRole.READ_WRITE}[role], allowed, op.tied_to_source_operand_index, op.early_clobber, op.width_bits, op.signedness, op.kind is SourceOperandKind.FIXED_REGISTER, op.fixed_register_name))
    contract_failure = _validate_renderer_operand_contract(
        candidate_plan, operands, target_operands,
    )
    if contract_failure is not None:
        return contract_failure
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,environment=target_environment,operand_constraints=tuple(target_operands),x86_gnu_inline_asm_contract=X86GnuInlineAsmContract(tuple(operands),shell.is_volatile,shell.has_cc_clobber,feature,source_model.value_operation.kind),memory_constraint=TargetMemoryConstraint(),control_flow_constraint=TargetControlFlowConstraint(),preserve_volatile=shell.is_volatile,preserve_cc_clobber=shell.has_cc_clobber))
