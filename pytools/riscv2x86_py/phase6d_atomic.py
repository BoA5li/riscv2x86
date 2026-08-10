from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject


def prove_atomic(r):
    """Proof gate for the concrete x86 lock-atomic contract."""
    c, s = r.constraints, r.source_model
    contract = c.x86_atomic_contract
    semantic_id = r.candidate_plan.metadata.get("renderer_semantic_contract_id")
    if contract is None or not isinstance(semantic_id, str):
        return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if (contract.semantic_contract_id != semantic_id or
            semantic_id not in r.target_semantic_catalog.semantic_contract_ids or
            contract.kind != s.atomic.kind or
            contract.rmw_operation != s.atomic.rmw_operation or
            contract.object_operand_index != s.atomic.address_operand_index or
            contract.value_operand_index != s.atomic.value_operand_index or
            contract.result_operand_index != s.atomic.result_operand_index or
            contract.width_bits != s.atomic.width_bits or
            contract.alignment_bytes != s.atomic.alignment_bytes):
        return reject(r, SemanticProofReasonCode.BINDING_UNSAFE)
    memory = c.memory_constraint
    if (not contract.requires_lock_semantics or
            not contract.requires_compiler_barrier or
            not contract.requires_hardware_ordering or
            not c.preserve_volatile or not c.preserve_cc_clobber or
            not memory.requires_memory_clobber or
            not memory.requires_compiler_barrier or
            not memory.requires_hardware_barrier or
            not memory.requires_atomic_ordering or
            memory.atomic_success_ordering != s.atomic.success_ordering or
            memory.atomic_failure_ordering != s.atomic.failure_ordering or
            memory.required_atomic_width_bits != s.atomic.width_bits or
            memory.required_alignment_bytes != s.atomic.alignment_bytes):
        return reject(r, SemanticProofReasonCode.ATOMIC_UNPRESERVED)
    if not r.compiler_capabilities.supports_gnu_inline_asm:
        return reject(r, SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    return finalize(r, (
        PreservationConclusion.ARCHITECTURE_EQUIVALENT,
        PreservationConclusion.SHELL_PRESERVED,
    ))
def prove_barrier(r):
    c, s = r.constraints, r.source_model
    contract = c.x86_barrier_contract
    semantic_id = r.candidate_plan.metadata.get("renderer_semantic_contract_id")
    if contract is None or not isinstance(semantic_id, str):
        return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if (contract.semantic_contract_id != semantic_id or
            semantic_id not in r.target_semantic_catalog.semantic_contract_ids or
            contract.ordering != s.barrier.ordering or
            contract.scope != s.barrier.scope or
            not c.preserve_volatile or
            not c.memory_constraint.requires_compiler_barrier or
            not c.memory_constraint.requires_memory_clobber):
        return reject(r, SemanticProofReasonCode.BARRIER_UNPRESERVED)
    if contract.route == "full_hardware_fence":
        if (not s.barrier.hardware_memory_barrier or
                not c.memory_constraint.requires_hardware_barrier or
                contract.ordering.value != "seq_cst" or
                contract.scope.value != "system"):
            return reject(r, SemanticProofReasonCode.BARRIER_UNPRESERVED)
    elif contract.route == "instruction_serialization":
        if (not s.barrier.instruction_serializing or
                not c.memory_constraint.requires_instruction_serialization or
                c.memory_constraint.requires_hardware_barrier):
            return reject(r, SemanticProofReasonCode.BARRIER_UNPRESERVED)
    else:
        return reject(r, SemanticProofReasonCode.UNSUPPORTED_PLAN_KIND)
    if not r.compiler_capabilities.supports_gnu_inline_asm:
        return reject(r, SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
