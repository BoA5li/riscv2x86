from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s,cc=r.constraints,r.source_model,r.compiler_capabilities
    if c.structured_control_flow_contract is None or not c.control_flow_constraint.preserve_control_flow:return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if s.control_flow.has_asm_goto and (not cc.supports_asm_goto or not c.control_flow_constraint.preserve_asm_goto):return reject(r,SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
