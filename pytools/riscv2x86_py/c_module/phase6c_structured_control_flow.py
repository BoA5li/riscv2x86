"""Phase 6C-7 structured CFG and asm-goto contracts; derived fail-closed."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..plan_types import TargetLoweringKind, TargetLoweringPlan
from ..source_model import SourceSemanticModel

if TYPE_CHECKING:
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetEnvironment


@dataclass(frozen=True)
class TargetSuccessorContinuation:
    source_block_address: int
    source_successor_address: int
    edge_kind: str
    target_continuation_id: str


@dataclass(frozen=True)
class AsmGotoLabelContract:
    label: str
    source_successor_address: int
    target_continuation_id: str


@dataclass(frozen=True)
class StructuredControlFlowContract:
    """Renderer-independent target CFG contract, never raw asm-goto text."""
    continuations: tuple[TargetSuccessorContinuation, ...]
    fallthrough_continuations: tuple[str, ...]
    asm_goto_labels: tuple[AsmGotoLabelContract, ...]
    uses_asm_goto: bool
    has_multiple_exits: bool
    preserves_return: bool
    preserves_noreturn: bool
    # These fields are source-model/plan facts, not renderer deductions.  A
    # contract that needs an actual branch expression must provide a stable
    # binding id before a recipe registry may render it.
    semantic_contract_id: str = ""
    branch_condition_binding_id: str | None = None
    state_merge_requirements: tuple[str, ...] = ()
    has_exception_or_trap_edge: bool = False


def _failure(plan, name, details=None):
    from ..phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintReasonCode
    return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id,
        reason_codes=(getattr(TargetConstraintReasonCode, name),), details={} if details is None else details)


def derive_structured_control_flow_constraints(source_model: SourceSemanticModel, candidate_plan: TargetLoweringPlan, target_environment: "TargetEnvironment") -> "TargetConstraintDerivationResult":
    """Use only SourceSemanticModel's normalized control-flow contract."""
    from ..phase6c_constraints import (
        TargetConstraintDerivationResult, TargetConstraintModel,
        TargetMemoryConstraint, TargetControlFlowConstraint,
        TargetOperandConstraint, TargetOperandRole, TargetOperandClass,
    )
    from ..source_model import SourceOperandAccess, SourceOperandKind
    if candidate_plan.kind is not TargetLoweringKind.STRUCTURED_CONTROL_FLOW:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_PLAN_KIND_MISMATCH")
    cf = source_model.control_flow
    if not source_model.operation.complete or not cf.cfg_ok:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_SOURCE_INCOMPLETE")
    # A renderer may not turn a possibly trapping operation into an ordinary
    # branch.  Exception/trap edges need their own registered route.
    if source_model.operation.may_trap is not False:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_SOURCE_INCOMPLETE")
    if cf.has_unknown_target:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_UNKNOWN_TARGET")
    if cf.has_indirect_control_flow is not False:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_INDIRECT_UNSUPPORTED")
    if cf.has_call or cf.has_tail_call is True or cf.has_return is True:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_CALL_OR_RETURN_UNSUPPORTED")
    if not cf.successors_complete:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_SUCCESSORS_INCOMPLETE")
    if cf.has_asm_goto and not target_environment.supports_gnu_asm_goto:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_ASM_GOTO_UNAVAILABLE")
    if cf.has_asm_goto and not cf.asm_goto_label_bindings_complete:
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_LABEL_BINDINGS_INCOMPLETE")
    # This is intentionally a narrow contract family.  A condition is never
    # reconstructed from template text here: Phase 4 recorded a normalized
    # fact and Phase 6A exposed it through SourceSemanticModel.
    branch_operand = None
    if cf.has_asm_goto:
        if (cf.asm_goto_condition_kind not in {"zero", "nonzero"} or
                cf.asm_goto_condition_operand_index is None):
            return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_BRANCH_CONDITION_UNSUPPORTED")
        expected_binding = (
            f"asm-goto:{cf.asm_goto_condition_kind}:operand:"
            f"{cf.asm_goto_condition_operand_index}"
        )
        if candidate_plan.metadata.get("cfg_branch_condition_binding_id") != expected_binding:
            return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_BRANCH_CONDITION_UNSUPPORTED")
        matching = [item for item in source_model.operands.operands
                    if item.source_operand_index == cf.asm_goto_condition_operand_index]
        if len(matching) != 1:
            return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_BRANCH_OPERAND_UNSAFE")
        branch_operand = matching[0]
        if (branch_operand.kind is not SourceOperandKind.REGISTER or
                branch_operand.access is not SourceOperandAccess.INPUT or
                not branch_operand.reads or branch_operand.writes or
                branch_operand.width_bits not in {32, 64} or
                branch_operand.early_clobber or
                branch_operand.tied_to_source_operand_index is not None or
                branch_operand.fixed_register_name is not None or
                source_model.memory.reads_memory or source_model.memory.writes_memory or
                source_model.atomic.present or source_model.barrier.present or
                source_model.shell.has_memory_clobber):
            return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_BRANCH_OPERAND_UNSAFE")
    continuations = tuple(TargetSuccessorContinuation(edge.source_block_address,
        edge.successor_address, edge.edge_kind,
        f"continuation:{edge.source_block_address:x}:{edge.successor_address:x}") for edge in cf.successors)
    by_successor = {item.source_successor_address: item.target_continuation_id for item in continuations}
    labels = []
    for binding in cf.asm_goto_label_bindings:
        target = by_successor.get(binding.successor_address)
        if target is None:
            return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_LABEL_BINDINGS_INCOMPLETE")
        labels.append(AsmGotoLabelContract(binding.label, binding.successor_address, target))
    if cf.has_asm_goto and {item.label for item in labels} != set(source_model.shell.goto_labels):
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_LABEL_BINDINGS_INCOMPLETE")
    fallthrough = tuple(item.target_continuation_id for item in continuations if item.edge_kind == "fallthrough")
    # Phase 6C does not invent condition ASTs.  Phase 6B must carry an
    # authoritative condition binding into the plan metadata; if it is absent
    # the derived constraints remain usable for proof/selection, but no
    # registered renderer recipe can consume it.
    branch_condition_binding_id = candidate_plan.metadata.get("cfg_branch_condition_binding_id")
    if branch_condition_binding_id is not None and not isinstance(branch_condition_binding_id, str):
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_SOURCE_INCOMPLETE")
    merge_requirements = candidate_plan.metadata.get("cfg_state_merge_requirements", ())
    if (not isinstance(merge_requirements, tuple) or
            not all(isinstance(item, str) and item for item in merge_requirements)):
        return _failure(candidate_plan, "STRUCTURED_CONTROL_FLOW_SOURCE_INCOMPLETE")
    semantic_contract_id = (
        f"x86.gnu-att.asm-goto.b{cf.asm_goto_condition_kind}.u32-u64.v1"
        if cf.has_asm_goto else "x86.structured-cfg.explicit.v1"
    )
    contract = StructuredControlFlowContract(continuations, fallthrough, tuple(labels),
        cf.has_asm_goto, cf.has_multiple_exits, False, False,
        semantic_contract_id, branch_condition_binding_id, merge_requirements,
        False)
    flow = TargetControlFlowConstraint(preserve_control_flow=True,
        preserve_asm_goto=cf.has_asm_goto)
    operands = () if branch_operand is None else (
        TargetOperandConstraint(
            source_operand_index=branch_operand.source_operand_index,
            role=TargetOperandRole.INPUT,
            allowed_classes=frozenset({TargetOperandClass.GENERAL_REGISTER}),
            required_width_bits=branch_operand.width_bits,
            required_signedness=branch_operand.signedness,
        ),
    )
    return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(plan_id=candidate_plan.plan_id,
        environment=target_environment, structured_control_flow_contract=contract,
        operand_constraints=operands, memory_constraint=TargetMemoryConstraint(),
        control_flow_constraint=flow,
        preserve_volatile=source_model.shell.is_volatile,
        # x86 TEST changes EFLAGS; this explicit target-shell fact is required
        # by both proof and renderer and is never inferred by Phase 6F.
        preserve_cc_clobber=cf.has_asm_goto))
