from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c=r.constraints
    if c.c_expression_constraint is None:return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if not c.memory_constraint.is_no_memory_effect() or not c.control_flow_constraint.is_simple_fallthrough():return reject(r,SemanticProofReasonCode.MEMORY_UNPRESERVED)
    if r.source_model.shell.requires_shell_aware_lowering or r.source_model.atomic.present or r.source_model.barrier.present:return reject(r,SemanticProofReasonCode.SHELL_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,))
