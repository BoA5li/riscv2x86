from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove_atomic(r):
    c,s=r.constraints,r.source_model
    if c.x86_atomic_contract is None or not c.memory_constraint.requires_atomic_ordering:return reject(r,SemanticProofReasonCode.ATOMIC_UNPRESERVED)
    if c.memory_constraint.atomic_success_ordering != s.atomic.success_ordering or c.memory_constraint.atomic_failure_ordering != s.atomic.failure_ordering:return reject(r,SemanticProofReasonCode.ATOMIC_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
def prove_barrier(r):
    c,s=r.constraints,r.source_model
    if c.x86_barrier_contract is None:return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if s.barrier.compiler_barrier and not c.memory_constraint.requires_compiler_barrier:return reject(r,SemanticProofReasonCode.BARRIER_UNPRESERVED)
    if s.barrier.hardware_memory_barrier and not c.memory_constraint.requires_hardware_barrier:return reject(r,SemanticProofReasonCode.BARRIER_UNPRESERVED)
    if c.x86_barrier_contract.ordering != s.barrier.ordering or c.x86_barrier_contract.scope != s.barrier.scope:return reject(r,SemanticProofReasonCode.BARRIER_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
