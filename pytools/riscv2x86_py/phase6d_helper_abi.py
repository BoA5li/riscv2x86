from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
from .helper_runtime_manifest import RuntimeHelperContract


def prove(r):
    c, s, registry = r.constraints, r.source_model, r.helper_contract_registry
    contract = c.helper_abi_contract
    if contract is None or not c.control_flow_constraint.requires_helper_abi_contract:
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    registered = None if registry is None else registry.contract(contract.runtime_contract_id)
    if not isinstance(registered, RuntimeHelperContract):
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    if (contract.target_abi != r.target_environment.abi.value or
            (contract.return_operand_index is not None and not contract.return_type_id) or
            contract.may_return != (s.operation.has_return is not True)):
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    if (contract.semantic_family != registered.semantic_family or
            contract.helper_symbol != registered.helper_symbol or
            contract.semantic_version != registered.semantic_version or
            contract.calling_convention != registered.calling_convention or
            contract.parameter_type_ids != registered.parameter_type_ids or
            contract.return_type_id != registered.return_type_id or
            contract.memory_effect.value != registered.memory_effect or
            contract.may_return != registered.may_return or
            contract.may_unwind != registered.may_unwind or
            contract.required_stack_alignment_bytes != registered.required_stack_alignment_bytes or
            contract.preserves_stack_pointer != registered.preserves_stack_pointer or
            contract.preserves_frame_pointer != registered.preserves_frame_pointer or
            contract.caller_saved_registers != registered.caller_saved_registers or
            contract.callee_saved_registers != registered.callee_saved_registers or
            contract.pic_plt_compatible != registered.pic_plt_compatible or
            registered.required_environment_capability not in r.target_environment.helper_contract_capabilities):
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    if s.registers.reads_or_writes_stack_pointer and not c.control_flow_constraint.preserve_stack_pointer:
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    if s.registers.reads_or_writes_frame_pointer and not c.control_flow_constraint.preserve_frame_pointer:
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    if s.atomic.present or s.barrier.present:
        return reject(r, SemanticProofReasonCode.ABI_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
