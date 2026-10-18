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
        if ('c_builtin:compiler_barrier' not in r.compiler_capabilities.builtin_capabilities
                or not s.shell.has_memory_clobber or not c.preserve_volatile or not c.preserve_cc_clobber):
            return reject(r,SemanticProofReasonCode.ATOMIC_UNPRESERVED)
        if (not c.memory_constraint.requires_atomic_ordering or
                not c.memory_constraint.requires_compiler_barrier or
                c.memory_constraint.atomic_success_ordering != atom.success_ordering or
                c.memory_constraint.required_atomic_width_bits != atom.width_bits or
                c.memory_constraint.required_alignment_bytes != atom.alignment_bytes):
            return reject(r, SemanticProofReasonCode.ATOMIC_UNPRESERVED)
        if atom.register_width_bits and atom.register_width_bits!=s.xlen:
            return reject(r,SemanticProofReasonCode.BINDING_UNSAFE)
        if atom.kind.value=='read_modify_write':
            operands={x.source_operand_index:x for x in s.operands.operands}
            value=operands.get(atom.value_operand_index);result=operands.get(atom.result_operand_index)
            if value is None or (atom.result_operand_index is not None and result is None):
                return reject(r,SemanticProofReasonCode.BINDING_UNSAFE)
            expected_projection='sign_extend_32_to_64' if result is not None and result.width_bits>atom.width_bits else 'identity'
            expected_truncation='low_bits' if value.width_bits>atom.width_bits else 'none'
            if (contract.input_carrier_width_bits!=value.width_bits
                    or contract.result_carrier_width_bits!=(0 if result is None else result.width_bits)
                    or contract.input_truncation!=expected_truncation
                    or contract.result_projection!=expected_projection
                    or (result is not None and contract.result_c_type_id!=result.lvalue.c_type_id)
                    or ((expected_projection!='identity' or expected_truncation!='none')
                        and (atom.width_bits!=32 or atom.register_width_bits!=64 or atom.result_extension not in {'sign_extend','none'}))):
                return reject(r,SemanticProofReasonCode.BINDING_UNSAFE)
        if (contract.object_operand_index != atom.address_operand_index or
                contract.result_operand_index != atom.result_operand_index or
                contract.value_operand_index != atom.value_operand_index or
                contract.width_bits != atom.width_bits or
                contract.alignment_bytes != atom.alignment_bytes or
                contract.success_ordering != atom.success_ordering.value or
                contract.result_semantics != atom.result_semantics or
                contract.memory_object_identity != atom.memory_object_identity or
                contract.address_space_identity != atom.address_space_identity or
                contract.atomicity_scope != atom.atomicity_scope or
                contract.read_effect_identity != atom.read_effect_identity or
                contract.write_effect_identity != atom.write_effect_identity or
                contract.authority_identity != atom.authority_identity or
                contract.arithmetic_relation != atom.arithmetic_relation or
                contract.wraparound_width_bits != atom.wraparound_width_bits):
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
