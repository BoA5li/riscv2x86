from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s=r.constraints,r.source_model
    if c.c_builtin_constraint is None:return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if s.atomic.present and not c.memory_constraint.requires_atomic_ordering:return reject(r,SemanticProofReasonCode.ATOMIC_UNPRESERVED)
    if s.barrier.present and not (c.memory_constraint.requires_compiler_barrier or c.memory_constraint.requires_hardware_barrier):return reject(r,SemanticProofReasonCode.BARRIER_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
