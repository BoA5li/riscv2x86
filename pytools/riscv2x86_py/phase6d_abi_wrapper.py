"""Proof gate for one exact, registered scalar ABI wrapper call."""
from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject

def prove(r):
    effects=r.source_model.abi_effects; target=r.constraints.abi_wrapper_constraint
    if effects is None or not effects.complete or len(effects.calls)!=1 or target is None:
        return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    call=effects.calls[0]; contract=target.wrapper_contract; shell=r.source_model.shell
    if any((shell.is_volatile,shell.has_memory_clobber,shell.has_cc_clobber,shell.has_asm_goto,shell.has_early_clobber,shell.has_tied_operands,call.reads_ra,call.writes_ra,not call.return_continuation_internal,call.may_return is not True,call.may_unwind is not False)):
        return reject(r,SemanticProofReasonCode.SHELL_UNPRESERVED)
    if contract.source_target_id != call.target.target_id or contract.exact_semantic_contract_id != call.target.semantic_contract_id or contract.semantic_version != call.target.semantic_version:
        return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    if tuple(x.source_operand_index for x in target.arguments)!=contract.argument_operand_indexes or tuple(x.source_operand_index for x in target.returns)!=contract.return_operand_indexes:
        return reject(r,SemanticProofReasonCode.BINDING_UNSAFE)
    if contract.memory_effect != call.memory_effect or not contract.may_return or contract.may_unwind:
        return reject(r,SemanticProofReasonCode.ABI_UNPRESERVED)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,))
