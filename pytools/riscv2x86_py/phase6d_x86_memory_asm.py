"""Proof path for x86 memory inline asm, distinct from register-only asm."""
from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s,cc=r.constraints,r.source_model,r.compiler_capabilities
    if not cc.supports_gnu_inline_asm:return reject(r,SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    if c.x86_memory_inline_asm_contract is None:return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if s.atomic.present or s.barrier.present or s.operation.has_control_flow:return reject(r,SemanticProofReasonCode.UNSUPPORTED_PLAN_KIND)
    if (s.shell.has_memory_clobber and not c.memory_constraint.requires_memory_clobber):return reject(r,SemanticProofReasonCode.MEMORY_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
