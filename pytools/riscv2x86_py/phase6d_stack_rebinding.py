"""Plan-specific proof for A-class stack-address rebinding."""
from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
from .pcode_ir import StackAccessKind

def prove(r):
    f, c = r.source_model.stack_frame, r.constraints.stack_rebinding_constraint
    if f is None or c is None or not f.stack_address_rebinding_eligible:
        return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    shell = r.source_model.shell
    shell_safe = not any((shell.is_volatile, shell.has_memory_clobber, shell.has_cc_clobber,
                          shell.has_asm_goto, shell.has_early_clobber,
                          shell.has_tied_operands, shell.has_control_flow_surface))
    if (not shell_safe or r.source_model.atomic.present or r.source_model.barrier.present or
            r.source_model.operation.has_control_flow or r.source_model.operation.may_trap is not False):
        return reject(r, SemanticProofReasonCode.SHELL_UNPRESERVED)
    if not c.forbids_host_stack_pointer_mutation or len(c.accesses) != len(f.rebinding_accesses):
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    expected = {(x.source_block_address,x.source_operation_index,x.c_lvalue_binding_id,x.target_object_offset_bytes,x.width_bits,x.access,x.value_operand_index) for x in f.rebinding_accesses}
    actual = {(x.source_block_address,x.source_operation_index,x.c_lvalue_binding_id,x.byte_offset,x.width_bits,x.access,x.value_operand_index) for x in c.accesses}
    if expected != actual or any(x.aliases_external_memory or not x.complete for x in f.rebinding_accesses):
        return reject(r, SemanticProofReasonCode.BINDING_UNSAFE)
    return finalize(r, (PreservationConclusion.ARCHITECTURE_EQUIVALENT,))
