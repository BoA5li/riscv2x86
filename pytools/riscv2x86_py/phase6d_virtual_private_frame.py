"""Proof gate for a static compiler-managed virtual private frame."""
from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject

def prove(r):
    frame=r.source_model.stack_frame; private=None if frame is None else frame.virtual_private_frame
    target=r.constraints.virtual_private_frame_constraint
    if frame is None or private is None or target is None or not frame.virtual_private_frame_eligible:
        return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    shell=r.source_model.shell
    if any((shell.is_volatile,shell.has_memory_clobber,shell.has_cc_clobber,shell.has_asm_goto,shell.has_early_clobber,shell.has_tied_operands,shell.has_control_flow_surface,r.source_model.atomic.present,r.source_model.barrier.present,r.source_model.operation.has_control_flow,r.source_model.operation.may_trap is not False)):
        return reject(r,SemanticProofReasonCode.SHELL_UNPRESERVED)
    if frame.net_stack_delta_bytes != 0 or not private.complete or not private.no_address_escape_proven or not private.no_real_stack_identity_required:
        return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    expected={(x.source_block_address,x.source_operation_index,x.virtual_offset_bytes,x.width_bits,x.access,x.value_operand_index,x.signed_load) for x in private.accesses}
    actual={(x.source_block_address,x.source_operation_index,x.byte_offset,x.width_bits,x.access,x.value_operand_index,x.signed_load) for x in target.accesses}
    if expected != actual or target.frame_size_bytes != private.frame_size_bytes or target.required_alignment_bytes < private.required_alignment_bytes:
        return reject(r,SemanticProofReasonCode.BINDING_UNSAFE)
    if not all((target.uses_compiler_managed_storage,target.forbids_explicit_host_stack_pointer_mutation,target.forbids_frame_address_builtin,target.requires_layout_proof,target.requires_bounds_proof,target.requires_initialization_proof,target.requires_no_escape_proof)):
        return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,))
