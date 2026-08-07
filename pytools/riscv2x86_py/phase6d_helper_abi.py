from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s,registry=r.constraints,r.source_model,r.helper_contract_registry
    if c.helper_abi_contract is None or not c.control_flow_constraint.requires_helper_abi_contract:return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    if registry is None or c.helper_abi_contract.runtime_contract_id not in registry.allowed_contract_ids:return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    if s.registers.reads_or_writes_stack_pointer and not c.control_flow_constraint.preserve_stack_pointer:return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    if s.registers.reads_or_writes_frame_pointer and not c.control_flow_constraint.preserve_frame_pointer:return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
