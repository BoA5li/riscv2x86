from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s,cc=r.constraints,r.source_model,r.compiler_capabilities
    if c.x86_memory_inline_asm_contract is not None:
        from .phase6d_x86_memory_asm import prove
        return prove(r)
    if not cc.supports_gnu_inline_asm:return reject(r,SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    if c.x86_gnu_inline_asm_contract is None and c.x86_memory_inline_asm_contract is None:return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if s.atomic.present or s.barrier.present or s.operation.has_control_flow:return reject(r,SemanticProofReasonCode.UNSUPPORTED_PLAN_KIND)
    if (s.shell.has_cc_clobber and not c.preserve_cc_clobber) or (s.shell.is_volatile and not c.preserve_volatile):return reject(r,SemanticProofReasonCode.SHELL_UNPRESERVED)
    if s.shell.has_memory_clobber and not c.memory_constraint.requires_memory_clobber:return reject(r,SemanticProofReasonCode.MEMORY_UNPRESERVED)
    contract = c.x86_gnu_inline_asm_contract
    semantic_id = r.candidate_plan.metadata.get("renderer_semantic_contract_id")
    if semantic_id == "x86.gnu-att.gpr.out-gpr-immediate-binary.v1":
        source_value = s.value_operation
        if (
            source_value is None
            or source_value.immediate_value is None
            or contract is None
            or contract.immediate_value != source_value.immediate_value
            or r.candidate_plan.metadata.get("source_immediate_value") != source_value.immediate_value
            or not -(1 << 31) <= contract.immediate_value <= (1 << 31) - 1
        ):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if (contract is not None and
            contract.value_operation_kind.value in {"unsigned_add", "unsigned_sub", "bit_and", "bit_or", "bit_xor"} and
            not c.preserve_cc_clobber):
        return reject(r, SemanticProofReasonCode.SHELL_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
