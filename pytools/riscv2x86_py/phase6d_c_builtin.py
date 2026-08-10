from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject


def prove(r):
    """Proof for a registered public-builtin contract, never a builtin string."""
    c, s = r.constraints, r.source_model
    contract = c.c_builtin_constraint
    if contract is None:
        return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    semantic_id = r.candidate_plan.metadata.get("renderer_semantic_contract_id")
    if (not isinstance(semantic_id, str) or
            contract.semantic_contract_id != semantic_id or
            semantic_id not in r.target_semantic_catalog.semantic_contract_ids):
        return reject(r, SemanticProofReasonCode.TARGET_SEMANTICS_MISSING)
    if contract.capability not in r.compiler_capabilities.builtin_capabilities:
        return reject(r, SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)

    if s.atomic.present:
        atom = s.atomic
        if (not c.memory_constraint.requires_atomic_ordering or
                not c.memory_constraint.requires_compiler_barrier or
                c.memory_constraint.atomic_success_ordering != atom.success_ordering or
                c.memory_constraint.required_atomic_width_bits != atom.width_bits or
                c.memory_constraint.required_alignment_bytes != atom.alignment_bytes):
            return reject(r, SemanticProofReasonCode.ATOMIC_UNPRESERVED)
        if (contract.object_operand_index != atom.address_operand_index or
                contract.result_operand_index != atom.result_operand_index or
                contract.value_operand_index != atom.value_operand_index or
                contract.width_bits != atom.width_bits or
                contract.alignment_bytes != atom.alignment_bytes or
                contract.success_ordering != atom.success_ordering.value):
            return reject(r, SemanticProofReasonCode.BINDING_UNSAFE)
    elif s.barrier.present:
        if (not c.memory_constraint.requires_compiler_barrier or
                c.memory_constraint.requires_hardware_barrier or
                contract.kind.value != "compiler_barrier"):
            return reject(r, SemanticProofReasonCode.BARRIER_UNPRESERVED)
    else:
        return reject(r, SemanticProofReasonCode.UNSUPPORTED_PLAN_KIND)
    return finalize(r, (
        PreservationConclusion.ARCHITECTURE_EQUIVALENT,
        PreservationConclusion.SHELL_PRESERVED,
    ))
