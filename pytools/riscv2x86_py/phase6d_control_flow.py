from .phase6c_constraints import TargetOperandClass, TargetOperandRole
from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s,cc=r.constraints,r.source_model,r.compiler_capabilities
    contract = c.structured_control_flow_contract
    if contract is None or not c.control_flow_constraint.preserve_control_flow:return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if (contract.has_exception_or_trap_edge or s.operation.may_trap is not False or
            s.control_flow.has_unknown_target or
            s.control_flow.has_indirect_control_flow is not False):
        return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if not s.control_flow.has_asm_goto:
        successors = {item.source_successor_address for item in contract.continuations}
        if (not successors or
                any(item not in {x.target_continuation_id for x in contract.continuations}
                    for item in contract.fallthrough_continuations)):
            return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if s.control_flow.has_asm_goto and (not cc.supports_asm_goto or not c.control_flow_constraint.preserve_asm_goto):return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if s.control_flow.has_asm_goto and {item.label for item in contract.asm_goto_labels} != set(s.shell.goto_labels):
        return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if s.control_flow.has_asm_goto:
        # Prove the concrete, registered zero/nonzero branch family.  All
        # facts below originated in SourceSemanticModel/6C constraints; this
        # gate deliberately does not read asm, CFG text, or renderer text.
        semantic_ids = {
            "zero": "x86.gnu-att.asm-goto.bzero.u32-u64.v1",
            "nonzero": "x86.gnu-att.asm-goto.bnonzero.u32-u64.v1",
        }
        kind = s.control_flow.asm_goto_condition_kind
        index = s.control_flow.asm_goto_condition_operand_index
        expected_binding = None if index is None else f"asm-goto:{kind}:operand:{index}"
        if (kind not in semantic_ids or index is None or
                s.control_flow.has_multiple_exits or
                s.control_flow.has_non_local_control_dependency or
                contract.state_merge_requirements or
                contract.semantic_contract_id != semantic_ids[kind] or
                r.candidate_plan.metadata.get("renderer_semantic_contract_id") != semantic_ids[kind] or
                contract.branch_condition_binding_id != expected_binding or
                len(contract.asm_goto_labels) != 1 or
                len(contract.fallthrough_continuations) != 1 or
                contract.asm_goto_fallthrough_continuation_id != contract.fallthrough_continuations[0] or
                set(contract.asm_goto_successor_continuation_ids) !=
                    ({contract.fallthrough_continuations[0]} |
                     {item.target_continuation_id for item in contract.asm_goto_labels}) or
                set(s.control_flow.asm_goto_successor_continuation_ids) !=
                    set(contract.asm_goto_successor_continuation_ids) or
                s.control_flow.asm_goto_fallthrough_continuation_id !=
                    contract.asm_goto_fallthrough_continuation_id or
                any(item.source_continuation_id != item.target_continuation_id
                    for item in contract.asm_goto_labels) or
                not c.preserve_cc_clobber or
                c.preserve_volatile != s.shell.is_volatile):
            return reject(r, SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
        source_operands = {item.source_operand_index: item for item in s.operands.operands}
        target_operands = tuple(c.operand_constraints)
        source = source_operands.get(index)
        if (source is None or len(target_operands) != 1 or
                target_operands[0].source_operand_index != index or
                target_operands[0].role is not TargetOperandRole.INPUT or
                target_operands[0].allowed_classes != frozenset({TargetOperandClass.GENERAL_REGISTER}) or
                target_operands[0].required_width_bits not in {32, 64} or
                target_operands[0].required_width_bits != source.width_bits or
                s.memory.reads_memory or s.memory.writes_memory or
                s.atomic.present or s.barrier.present):
            return reject(r, SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
