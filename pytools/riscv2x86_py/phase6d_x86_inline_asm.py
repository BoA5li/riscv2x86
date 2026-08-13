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
    if semantic_id == "x86.gnu-att.gpr.out-gpr-boolean-compare.u32-u64.v1":
        value = s.value_operation
        operands = {item.source_operand_index: item for item in c.operand_constraints}
        kinds = {
            "signed_less", "unsigned_less", "signed_less_equal",
            "unsigned_less_equal", "equal", "not_equal",
        }
        if (value is None or value.kind.value not in kinds or
                value.immediate_value is not None or len(value.input_operand_indexes) != 2 or
                contract is None or contract.value_operation_kind is not value.kind or
                not c.preserve_cc_clobber):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        output = operands.get(value.result_operand_index)
        left = operands.get(value.input_operand_indexes[0])
        right = operands.get(value.input_operand_indexes[1])
        if (output is None or left is None or right is None or
                output.role.value != "output" or output.early_clobber or
                left.role.value != "input" or right.role.value != "input" or
                output.required_width_bits not in {32, 64} or
                left.required_width_bits != output.required_width_bits or
                right.required_width_bits != output.required_width_bits):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        # GNU ``r`` operands carry the exact XLEN bit patterns; the signed or
        # unsigned interpretation is supplied by the canonical comparison
        # operation and the registered x86 ``setcc`` contract, not guessed
        # from a host C type string.  This matters because Phase 4 currently
        # provides signless register bindings while p-code remains the
        # authoritative architecture-semantics source.
        return finalize(r, (PreservationConclusion.ARCHITECTURE_EQUIVALENT,
                            PreservationConclusion.SHELL_PRESERVED))
    if semantic_id == "x86.gnu-att.gpr.out-gpr-variable-shift.u32-u64.v1":
        value = s.value_operation
        operands = {item.source_operand_index: item for item in c.operand_constraints}
        if (value is None or value.immediate_value is not None or
                value.kind.value not in {"shift_left_register", "shift_right_logical_register", "shift_right_arithmetic_register"} or
                len(value.input_operand_indexes) != 2 or contract is None or
                contract.value_operation_kind is not value.kind or not c.preserve_cc_clobber):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        output = operands.get(value.result_operand_index)
        source = operands.get(value.input_operand_indexes[0])
        count = operands.get(value.input_operand_indexes[1])
        if (output is None or source is None or count is None or
                output.role.value != "output" or not output.early_clobber or
                source.role.value != "input" or count.role.value != "input" or
                count.gnu_constraint_body != "c" or
                output.required_width_bits not in {32, 64} or
                source.required_width_bits != output.required_width_bits or
                count.required_width_bits != output.required_width_bits):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        if (value.shift_count_mask is not None and
                value.shift_count_mask != output.required_width_bits - 1):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        return finalize(r, (PreservationConclusion.ARCHITECTURE_EQUIVALENT,
                            PreservationConclusion.SHELL_PRESERVED))
    if semantic_id == "x86.gnu-att.gpr.straight-line-u32-u64.v1":
        program = s.value_program
        operands = {item.source_operand_index: item for item in c.operand_constraints}
        if (program is None or not program.complete or contract is None or
                contract.straight_line_program != program or
                r.candidate_plan.metadata.get("program_instruction_count") != len(program.instructions) or
                r.candidate_plan.metadata.get("program_width_bits") != program.width_bits or
                not c.preserve_cc_clobber or
                set(program.output_operand_indexes) != {item.source_operand_index for item in c.operand_constraints if item.role.value == "output"} or
                set(program.input_operand_indexes) != {item.source_operand_index for item in c.operand_constraints if item.role.value == "input"}):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        if (program.variable_shift_count_operand_index is not None and
                operands.get(program.variable_shift_count_operand_index) is None or
                (program.variable_shift_count_operand_index is not None and
                 operands[program.variable_shift_count_operand_index].gnu_constraint_body != "c")):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        for instruction in program.instructions:
            output = operands.get(instruction.output_operand_index)
            inputs = [operands.get(item) for item in instruction.input_operand_indexes]
            if (output is None or output.role.value != "output" or
                    output.required_width_bits != program.width_bits or
                    any(item is None or item.required_width_bits != program.width_bits for item in inputs)):
                return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        return finalize(r, (PreservationConclusion.ARCHITECTURE_EQUIVALENT,
                            PreservationConclusion.SHELL_PRESERVED))
    if semantic_id == "x86.gnu-att.gpr.add-then-shl-imm.u32-u64.early-clobber.v1":
        value = s.value_operation
        operands = {item.source_operand_index: item for item in c.operand_constraints}
        if (value is None or value.kind.value != "add_then_shift_left_immediate" or
                value.temporary_operand_index is None or value.immediate_value is None or
                contract is None or contract.value_operation_kind is not value.kind or
                contract.immediate_value != value.immediate_value or
                r.candidate_plan.metadata.get("temporary_operand_index") != value.temporary_operand_index or
                r.candidate_plan.metadata.get("source_shift_amount") != value.immediate_value or
                len(operands) != 4):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        temporary = operands.get(value.temporary_operand_index)
        result = operands.get(value.result_operand_index)
        inputs = [operands.get(index) for index in value.input_operand_indexes]
        if (temporary is None or result is None or temporary.role.value != "output" or
                result.role.value != "output" or not temporary.early_clobber or
                result.early_clobber or temporary.required_width_bits not in {32, 64} or
                result.required_width_bits != temporary.required_width_bits or
                any(item is None or item.role.value != "input" or
                    item.required_width_bits != temporary.required_width_bits or
                    item.early_clobber for item in inputs) or
                not c.preserve_cc_clobber):
            return reject(r, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
        return finalize(r, (PreservationConclusion.ARCHITECTURE_EQUIVALENT,
                            PreservationConclusion.SHELL_PRESERVED))
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
