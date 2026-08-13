"""Proof path for x86 memory inline asm, distinct from register-only asm."""
from .phase6d_common import PreservationConclusion, SemanticProofReasonCode, finalize, reject
def prove(r):
    c,s,cc=r.constraints,r.source_model,r.compiler_capabilities
    if not cc.supports_gnu_inline_asm:return reject(r,SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    if c.x86_memory_inline_asm_contract is None:return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if s.atomic.present or s.memory.has_memory_barrier or s.memory.has_instruction_barrier or s.memory.has_unknown_barrier or s.operation.has_control_flow:return reject(r,SemanticProofReasonCode.UNSUPPORTED_PLAN_KIND)
    if (s.shell.has_memory_clobber and not c.memory_constraint.requires_memory_clobber):return reject(r,SemanticProofReasonCode.MEMORY_UNPRESERVED)
    contract = c.x86_memory_inline_asm_contract
    semantic_id = r.candidate_plan.metadata.get("renderer_semantic_contract_id")
    expected = {
        "x86.gnu-att.memory.load.gpr-address.u32.v1": ("load", 32),
        "x86.gnu-att.memory.load.gpr-address.u64.v1": ("load", 64),
        "x86.gnu-att.memory.load.gpr-address-disp32.u32.v1": ("load", 32),
        "x86.gnu-att.memory.load.gpr-address-disp32.u64.v1": ("load", 64),
        "x86.gnu-att.memory.store.gpr-address.u32.v1": ("store", 32),
        "x86.gnu-att.memory.store.gpr-address.u64.v1": ("store", 64),
        "x86.gnu-att.memory.store.gpr-address-disp32.u32.v1": ("store", 32),
        "x86.gnu-att.memory.store.gpr-address-disp32.u64.v1": ("store", 64),
    }.get(semantic_id)
    address = next((item for item in s.operands.operands
                    if item.source_operand_index == contract.address_operand_index), None)
    displacement = getattr(getattr(address, "address", None), "byte_offset", None)
    expects_displacement = "gpr-address-disp32" in str(semantic_id)
    if (expected is None or contract.semantic_contract_id != semantic_id or
            contract.operation_kind != expected[0] or contract.value_width_bits != expected[1] or
            contract.address_operand_index is None or contract.value_operand_index is None or
            not isinstance(displacement, int) or isinstance(displacement, bool) or
            not -(1 << 31) <= displacement < (1 << 31) or
            contract.address_displacement_bytes != displacement or
            (expects_displacement and displacement == 0) or
            (not expects_displacement and displacement != 0) or
            not contract.memory_clobber or not contract.compiler_barrier or
            not c.memory_constraint.requires_memory_clobber or
            not c.memory_constraint.requires_compiler_barrier):
        return reject(r,SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    return finalize(r,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))
