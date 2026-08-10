from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s,cc=r.constraints,r.source_model,r.compiler_capabilities
    contract = c.structured_control_flow_contract
    if contract is None or not c.control_flow_constraint.preserve_control_flow:return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if (contract.has_exception_or_trap_edge or s.operation.may_trap is not False or
            s.control_flow.has_unknown_target or
            s.control_flow.has_indirect_control_flow is not False):
        return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    successors = {item.source_successor_address for item in contract.continuations}
    if (not successors or
            any(item.source_successor_address not in successors for item in contract.asm_goto_labels) or
            any(item not in {x.target_continuation_id for x in contract.continuations}
                for item in contract.fallthrough_continuations)):
        return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if s.control_flow.has_asm_goto and (not cc.supports_asm_goto or not c.control_flow_constraint.preserve_asm_goto):return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if s.control_flow.has_asm_goto and {item.label for item in contract.asm_goto_labels} != set(s.shell.goto_labels):
        return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
