"""Phase 6C contracts for registered direct x86 scalar memory asm routes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import (
    SourceOperandAccess, SourceOperandKind, SourceOperationKind,
    SourceSemanticModel,
)

if TYPE_CHECKING:
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetEnvironment


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
    semantic_contract_id: str = ""
    operation_kind: str = ""
    address_operand_index: int | None = None
    value_operand_index: int | None = None
    value_width_bits: int | None = None


_LOAD_IDS = {
    "x86.gnu-att.memory.load.gpr-address.u32.v1": 32,
    "x86.gnu-att.memory.load.gpr-address.u64.v1": 64,
}
_STORE_IDS = {
    "x86.gnu-att.memory.store.gpr-address.u32.v1": 32,
    "x86.gnu-att.memory.store.gpr-address.u64.v1": 64,
}


def _fail(plan, code, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(
        plan_id=plan.plan_id,
        reason_codes=(getattr(TargetConstraintReasonCode, code),),
        details={} if details is None else details,
    )


def derive_x86_memory_inline_asm_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    from ..phase6c_constraints import (
        TargetConstraintDerivationResult, TargetConstraintModel,
        TargetMemoryConstraint, TargetControlFlowConstraint,
        TargetOperandConstraint, TargetOperandRole, TargetOperandClass,
    )
    if candidate_plan.kind is not TargetLoweringKind.X86_GNU_INLINE_ASM:
        return _fail(candidate_plan, "X86_MEMORY_ASM_PLAN_KIND_MISMATCH")
    if "x86:gpr_inline_asm" not in target_environment.available_features:
        return _fail(candidate_plan, "X86_MEMORY_ASM_FEATURE_UNAVAILABLE")
    if not source_model.operands.complete or not source_model.operation.complete:
        return _fail(candidate_plan, "X86_MEMORY_ASM_SOURCE_INCOMPLETE")
    if (source_model.atomic.present or source_model.memory.has_memory_barrier or source_model.memory.has_instruction_barrier or
            source_model.memory.has_unknown_barrier):
        return _fail(candidate_plan, "X86_MEMORY_ASM_HARDWARE_SEMANTICS_UNSUPPORTED")
    if (source_model.operation.has_control_flow or source_model.operation.has_call or
            source_model.operation.has_return is not False or source_model.operation.may_trap is not False):
        return _fail(candidate_plan, "X86_MEMORY_ASM_CONTROL_FLOW_UNSUPPORTED")

    semantic_id = candidate_plan.metadata.get("renderer_semantic_contract_id")
    if semantic_id in _LOAD_IDS:
        expected_kind, width = SourceOperationKind.LOAD, _LOAD_IDS[semantic_id]
    elif semantic_id in _STORE_IDS:
        expected_kind, width = SourceOperationKind.STORE, _STORE_IDS[semantic_id]
    else:
        return _fail(candidate_plan, "X86_MEMORY_ASM_SOURCE_INCOMPLETE", {"renderer_semantic_contract_id": str(semantic_id)})
    if source_model.operation.kind is not expected_kind:
        return _fail(candidate_plan, "X86_MEMORY_ASM_SOURCE_INCOMPLETE", {"expected_operation": expected_kind.value})

    address = [item for item in source_model.operands.operands if item.kind is SourceOperandKind.ADDRESS]
    if len(address) != 1 or address[0].address is None or not address[0].address.provenance_known:
        return _fail(candidate_plan, "X86_MEMORY_ASM_ADDRESS_BINDING_MISSING")
    address = address[0]
    if address.early_clobber or address.tied_to_source_operand_index is not None:
        return _fail(candidate_plan, "X86_MEMORY_ASM_ADDRESS_BINDING_MISSING")
    if expected_kind is SourceOperationKind.LOAD:
        values = [item for item in source_model.operands.operands if item.access is SourceOperandAccess.OUTPUT]
    else:
        values = [item for item in source_model.operands.operands if item.access is SourceOperandAccess.INPUT]
    if len(source_model.operands.operands) != 2 or len(values) != 1:
        return _fail(candidate_plan, "X86_MEMORY_ASM_ADDRESS_BINDING_MISSING")
    value = values[0]
    if (value.kind is not SourceOperandKind.REGISTER or value.width_bits != width or
            value.early_clobber or value.tied_to_source_operand_index is not None):
        return _fail(candidate_plan, "X86_MEMORY_ASM_ADDRESS_BINDING_MISSING")

    target_operands = [
        TargetOperandConstraint(
            source_operand_index=address.source_operand_index,
            role=TargetOperandRole.INPUT,
            allowed_classes=frozenset({TargetOperandClass.GENERAL_REGISTER}),
            required_width_bits=address.width_bits,
            required_signedness=address.signedness,
        ),
        TargetOperandConstraint(
            source_operand_index=value.source_operand_index,
            role=(TargetOperandRole.OUTPUT if expected_kind is SourceOperationKind.LOAD else TargetOperandRole.INPUT),
            allowed_classes=frozenset({TargetOperandClass.GENERAL_REGISTER}),
            required_width_bits=width,
            required_signedness=value.signedness,
        ),
    ]
    contract = X86MemoryInlineAsmContract(
        operands=(X86MemoryOperandContract(address.source_operand_index, "address", address.address.alignment_bytes, "precise"),),
        memory_clobber=True, compiler_barrier=True,
        volatile=source_model.shell.is_volatile,
        semantic_contract_id=semantic_id,
        operation_kind=expected_kind.value,
        address_operand_index=address.source_operand_index,
        value_operand_index=value.source_operand_index,
        value_width_bits=width,
    )
    memory = TargetMemoryConstraint(
        requires_memory_clobber=True,
        requires_compiler_barrier=True,
        required_alignment_bytes=address.address.alignment_bytes,
    )
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(
        plan_id=candidate_plan.plan_id, environment=target_environment,
        operand_constraints=tuple(target_operands),
        x86_memory_inline_asm_contract=contract,
        memory_constraint=memory,
        control_flow_constraint=TargetControlFlowConstraint(),
        preserve_volatile=source_model.shell.is_volatile,
        preserve_cc_clobber=source_model.shell.has_cc_clobber,
    ))
