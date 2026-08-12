"""Versioned, fail-closed registry for Phase 6F renderer recipes.

Recipes are registered target semantic contracts, never inferred from source
asm text, mnemonics, plan kind, or renderer convenience.
"""
from __future__ import annotations
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

from .phase6e_selection import ApprovedTargetLoweringPlan
from .phase6f_renderer import RendererContract
from .phase6f_renderer import (
    CBuiltinArgument,
    CBuiltinRecipe,
    GnuInlineAsmRecipe,
    GnuAsmGotoRecipe,
    GnuAsmGotoLabelBinding,
    HelperCallRecipe,
    RendererContractKind,
    StructuredControlFlowRecipe,
)
from .phase6c_constraints import TargetOperandRole, TargetOperandClass
from .source_model import SourceAtomicRmwOperation, SourceMemoryOrdering, SourceValueOperationKind, SourceStraightLineValueOpcode
from .plan_types import TargetLoweringKind
from .helper_runtime_manifest import RV64_MULHU_U64, RUNTIME_HELPER_MANIFEST_VERSION


RecipeFactory = Callable[[ApprovedTargetLoweringPlan], object | None]


@dataclass(frozen=True)
class RegisteredRendererContract:
    semantic_contract_id: str
    plan_kind: TargetLoweringKind
    renderer_contract_id: str
    make_payload: RecipeFactory
    required_constraint_field: str
    required_features: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RegisteredHelperAbiContract:
    """Versioned helper registration required before any helper is rendered."""
    semantic_contract_id: str
    helper_symbol: str
    semantic_version: str
    calling_convention: str
    target_abi: str
    parameter_type_ids: tuple[str, ...]
    return_type_id: str | None
    runtime_contract_id: str
    helper_registry_version: str
    memory_effect: str
    may_return: bool
    may_unwind: bool
    pic_plt_compatible: bool
    required_stack_alignment_bytes: int = 0
    preserves_stack_pointer: bool = False
    preserves_frame_pointer: bool = False
    caller_saved_registers: tuple[str, ...] = ()
    callee_saved_registers: tuple[str, ...] = ()
    required_header: str = ""
    runtime_library: str = ""


@dataclass(frozen=True)
class RegisteredStructuredControlFlowContract:
    """An explicit, versioned control-flow renderer registration.

    ``recipe`` must be supplied by a prior, proof-compatible target semantic
    contract.  This registry intentionally does not manufacture conditions,
    labels, fallthroughs, or branch templates from CFG text or source asm.
    """
    semantic_contract_id: str
    renderer_contract_id: str
    uses_asm_goto: bool
    branch_condition_binding_id: str | None
    recipe: GnuAsmGotoRecipe | StructuredControlFlowRecipe
    required_features: frozenset[str] = frozenset()


class RendererContractRegistry:
    """Immutable registry whose lookup is bound to an approved plan id."""
    def __init__(self, *, registry_id: str, version: str,
                 entries: tuple[RegisteredRendererContract, ...] = ()) -> None:
        self.registry_id, self.version = registry_id, version
        by_id = {entry.semantic_contract_id: entry for entry in entries}
        if len(by_id) != len(entries):
            raise ValueError("duplicate renderer semantic contract id")
        self._entries: Mapping[str, RegisteredRendererContract] = MappingProxyType(by_id)

    def resolve(self, approved: ApprovedTargetLoweringPlan) -> RendererContract | None:
        semantic_id = approved.plan.metadata.get("renderer_semantic_contract_id")
        if semantic_id is None and approved.plan.kind is TargetLoweringKind.HELPER_CALL:
            helper = approved.constraints.helper_abi_contract
            semantic_id = None if helper is None else "helper." + helper.runtime_contract_id
        if semantic_id is None and approved.plan.kind is TargetLoweringKind.STRUCTURED_CONTROL_FLOW:
            flow = approved.constraints.structured_control_flow_contract
            semantic_id = None if flow is None else flow.semantic_contract_id
        if not isinstance(semantic_id, str):
            return None
        entry = self._entries.get(semantic_id)
        if entry is None or entry.plan_kind is not approved.plan.kind:
            return None
        if getattr(approved.constraints, entry.required_constraint_field, None) is None:
            return None
        payload = entry.make_payload(approved)
        if payload is None:
            return None
        return RendererContract(
            contract_id=entry.renderer_contract_id + ":" + approved.plan.plan_id,
            plan_id=approved.plan.plan_id,
            kind=payload[0], payload=payload[1],
            required_features=entry.required_features,
        )


EMPTY_RENDERER_CONTRACT_REGISTRY = RendererContractRegistry(
    registry_id="phase6f.target-contracts", version="1"
)


def _helper_registration_entry(registration: RegisteredHelperAbiContract) -> RegisteredRendererContract:
    def make_payload(approved: ApprovedTargetLoweringPlan):
        contract = approved.constraints.helper_abi_contract
        evidence = approved.proof.evidence
        if contract is None or evidence is None:
            return None
        if (contract.runtime_contract_id != registration.runtime_contract_id or
                contract.helper_symbol != registration.helper_symbol or
                contract.semantic_version != registration.semantic_version or
                contract.calling_convention != registration.calling_convention or
                contract.target_abi != registration.target_abi or
                contract.parameter_type_ids != registration.parameter_type_ids or
                contract.return_type_id != registration.return_type_id or
                contract.memory_effect.value != registration.memory_effect or
                contract.may_return != registration.may_return or
                contract.may_unwind != registration.may_unwind or
                contract.pic_plt_compatible != registration.pic_plt_compatible or
                contract.required_stack_alignment_bytes != registration.required_stack_alignment_bytes or
                contract.preserves_stack_pointer != registration.preserves_stack_pointer or
                contract.preserves_frame_pointer != registration.preserves_frame_pointer or
                contract.caller_saved_registers != registration.caller_saved_registers or
                contract.callee_saved_registers != registration.callee_saved_registers or
                evidence.helper_registry_version != registration.helper_registry_version):
            return None
        return (
            RendererContractKind.HELPER_CALL,
            HelperCallRecipe(
                helper_symbol=registration.helper_symbol,
                argument_operand_indexes=contract.parameter_operand_indexes,
                result_operand_index=contract.return_operand_index,
                runtime_contract_id=registration.runtime_contract_id,
                semantic_version=registration.semantic_version,
                required_header=registration.required_header,
                runtime_library=registration.runtime_library,
            ),
        )
    return RegisteredRendererContract(
        registration.semantic_contract_id,
        TargetLoweringKind.HELPER_CALL,
        "helper." + registration.runtime_contract_id,
        make_payload,
        "helper_abi_contract",
    )


def register_helper_abi_contracts(
    base_registry: RendererContractRegistry,
    registrations: tuple[RegisteredHelperAbiContract, ...],
) -> RendererContractRegistry:
    """Return an immutable registry extended with explicit helper contracts."""
    if not isinstance(base_registry, RendererContractRegistry):
        raise TypeError("base_registry must be RendererContractRegistry")
    for item in registrations:
        expected_id = "helper." + item.runtime_contract_id
        if item.semantic_contract_id != expected_id:
            raise ValueError(
                "helper semantic_contract_id must bind runtime_contract_id"
            )
    entries = tuple(base_registry._entries.values()) + tuple(
        _helper_registration_entry(item) for item in registrations
    )
    return RendererContractRegistry(
        registry_id=base_registry.registry_id,
        version=base_registry.version + "+helpers",
        entries=entries,
    )


def _structured_control_flow_entry(
    registration: RegisteredStructuredControlFlowContract,
) -> RegisteredRendererContract:
    def make_payload(approved: ApprovedTargetLoweringPlan):
        contract = approved.constraints.structured_control_flow_contract
        if (contract is None or
                contract.semantic_contract_id != registration.semantic_contract_id or
                contract.uses_asm_goto != registration.uses_asm_goto or
                contract.has_exception_or_trap_edge or
                contract.branch_condition_binding_id != registration.branch_condition_binding_id):
            return None
        expected_labels = {
            (item.label, item.target_continuation_id)
            for item in contract.asm_goto_labels
        }
        recipe_labels = {
            (item.label, item.target_continuation_id)
            for item in registration.recipe.label_bindings
        }
        # Both asm-goto and structured CFG recipes must faithfully encode the
        # complete label/continuation relation.  Empty sets are valid only for
        # non-asm-goto control flow.
        if expected_labels != recipe_labels:
            return None
        if registration.uses_asm_goto:
            if (not isinstance(registration.recipe, GnuAsmGotoRecipe) or
                    not expected_labels or
                    not approved.constraints.control_flow_constraint.preserve_asm_goto):
                return None
            return (RendererContractKind.GNU_ASM_GOTO, registration.recipe)
        if (not isinstance(registration.recipe, StructuredControlFlowRecipe) or
                contract.uses_asm_goto):
            return None
        return (RendererContractKind.STRUCTURED_CONTROL_FLOW, registration.recipe)

    return RegisteredRendererContract(
        registration.semantic_contract_id,
        TargetLoweringKind.STRUCTURED_CONTROL_FLOW,
        registration.renderer_contract_id,
        make_payload,
        "structured_control_flow_contract",
        registration.required_features,
    )


def register_structured_control_flow_contracts(
    base_registry: RendererContractRegistry,
    registrations: tuple[RegisteredStructuredControlFlowContract, ...],
) -> RendererContractRegistry:
    """Extend a registry with audited asm-goto/structured-CFG recipes.

    No control-flow registration is installed by default: ordinary CFG facts
    do not contain an output branch-condition AST or a target branch recipe.
    Callers must supply both as an explicit semantic contract, otherwise the
    renderer remains fail-closed.
    """
    if not isinstance(base_registry, RendererContractRegistry):
        raise TypeError("base_registry must be RendererContractRegistry")
    for item in registrations:
        if not item.semantic_contract_id or not item.renderer_contract_id:
            raise ValueError("control-flow registration needs stable identifiers")
        if not isinstance(item.branch_condition_binding_id, str) or not item.branch_condition_binding_id:
            raise ValueError("control-flow registration needs an explicit condition binding")
        if item.uses_asm_goto != isinstance(item.recipe, GnuAsmGotoRecipe):
            raise ValueError("asm-goto registration recipe kind mismatch")
        if (not item.uses_asm_goto and
                not isinstance(item.recipe, StructuredControlFlowRecipe)):
            raise ValueError("structured-CFG registration recipe kind mismatch")
    entries = tuple(base_registry._entries.values()) + tuple(
        _structured_control_flow_entry(item) for item in registrations
    )
    return RendererContractRegistry(
        registry_id=base_registry.registry_id,
        version=base_registry.version + "+structured-cfg",
        entries=entries,
    )

def _gpr_rw_binary_recipe(
    approved: ApprovedTargetLoweringPlan,
    *,
    input_class: TargetOperandClass,
    output_early_clobber: bool,
):
    """Build one registered 32/64-bit binary GPR recipe.

    ``input_class`` and ``output_early_clobber`` are entry-specific semantic
    contract conditions.  They are intentionally arguments of the registered
    factory rather than defaults inferred from the renderer or asm template.
    """
    c = approved.constraints
    contract = c.x86_gnu_inline_asm_contract
    if contract is None or contract.value_operation_kind not in {
        SourceValueOperationKind.UNSIGNED_ADD, SourceValueOperationKind.UNSIGNED_SUB,
        SourceValueOperationKind.BIT_AND, SourceValueOperationKind.BIT_OR,
        SourceValueOperationKind.BIT_XOR,
    }:
        return None
    outputs = [x for x in c.operand_constraints if x.role is TargetOperandRole.READ_WRITE]
    inputs = [x for x in c.operand_constraints if x.role is TargetOperandRole.INPUT]
    if len(outputs) != 1 or len(inputs) != 1 or outputs[0].required_width_bits not in {32, 64}:
        return None
    output, input_ = outputs[0], inputs[0]
    if inputs[0].required_width_bits != outputs[0].required_width_bits:
        return None
    if TargetOperandClass.GENERAL_REGISTER not in output.allowed_classes:
        return None
    if input_class not in input_.allowed_classes:
        return None
    if output.early_clobber is not output_early_clobber:
        return None
    if input_.early_clobber or output.tied_to_source_operand_index is not None or input_.tied_to_source_operand_index is not None:
        return None
    if output.requires_fixed_register or input_.requires_fixed_register:
        return None
    suffix = "l" if output.required_width_bits == 32 else "q"
    opcode = {
        SourceValueOperationKind.UNSIGNED_ADD:"add", SourceValueOperationKind.UNSIGNED_SUB:"sub",
        SourceValueOperationKind.BIT_AND:"and", SourceValueOperationKind.BIT_OR:"or",
        SourceValueOperationKind.BIT_XOR:"xor",
    }[contract.value_operation_kind]
    return (RendererContractKind.GNU_INLINE_ASM, GnuInlineAsmRecipe(
        template=f"{opcode}{suffix} %1, %0",
        output_operand_indexes=(output.source_operand_index,),
        input_operand_indexes=(input_.source_operand_index,),
    ))


def _gpr_rw_gpr_binary_recipe(approved: ApprovedTargetLoweringPlan):
    return _gpr_rw_binary_recipe(
        approved,
        input_class=TargetOperandClass.GENERAL_REGISTER,
        output_early_clobber=False,
    )


def _gpr_rw_immediate_binary_recipe(approved: ApprovedTargetLoweringPlan):
    return _gpr_rw_binary_recipe(
        approved,
        input_class=TargetOperandClass.IMMEDIATE,
        output_early_clobber=False,
    )


def _gpr_rw_early_clobber_binary_recipe(approved: ApprovedTargetLoweringPlan):
    return _gpr_rw_binary_recipe(
        approved,
        input_class=TargetOperandClass.GENERAL_REGISTER,
        output_early_clobber=True,
    )


def _gpr_output_gpr_binary_recipe(approved: ApprovedTargetLoweringPlan):
    """Encode ``dst = lhs OP rhs`` without reinterpreting source asm.

    x86 is two-address, so this registered recipe uses an early-clobber
    output and an explicit ``mov`` before the binary operation.  The
    early-clobber condition is part of the approved 6C contract: it prevents
    the output from aliasing either input before both inputs are consumed.
    """
    c = approved.constraints
    contract = c.x86_gnu_inline_asm_contract
    if contract is None or contract.value_operation_kind not in {
        SourceValueOperationKind.UNSIGNED_ADD, SourceValueOperationKind.UNSIGNED_SUB,
        SourceValueOperationKind.BIT_AND, SourceValueOperationKind.BIT_OR,
        SourceValueOperationKind.BIT_XOR,
    }:
        return None
    outputs = [item for item in c.operand_constraints if item.role is TargetOperandRole.OUTPUT]
    inputs = [item for item in c.operand_constraints if item.role is TargetOperandRole.INPUT]
    if len(outputs) != 1 or len(inputs) != 2:
        return None
    output = outputs[0]
    if (
        output.required_width_bits not in {32, 64}
        or not output.early_clobber
        or output.tied_to_source_operand_index is not None
        or output.requires_fixed_register
        or TargetOperandClass.GENERAL_REGISTER not in output.allowed_classes
        or any(
            item.required_width_bits != output.required_width_bits
            or item.early_clobber
            or item.tied_to_source_operand_index is not None
            or item.requires_fixed_register
            or TargetOperandClass.GENERAL_REGISTER not in item.allowed_classes
            for item in inputs
        )
    ):
        return None
    suffix = "l" if output.required_width_bits == 32 else "q"
    opcode = {
        SourceValueOperationKind.UNSIGNED_ADD: "add",
        SourceValueOperationKind.UNSIGNED_SUB: "sub",
        SourceValueOperationKind.BIT_AND: "and",
        SourceValueOperationKind.BIT_OR: "or",
        SourceValueOperationKind.BIT_XOR: "xor",
    }[contract.value_operation_kind]
    return (
        RendererContractKind.GNU_INLINE_ASM,
        GnuInlineAsmRecipe(
            # The recipe stores logical assembly text.  Phase 6F alone
            # encodes the newline as a C string escape during serialization.
            # Storing ``\\n`` here would make the serializer emit ``\\\\n``
            # and pass a literal backslash to the assembler.
            template=f"mov{suffix} %1, %0\n\t{opcode}{suffix} %2, %0",
            output_operand_indexes=(output.source_operand_index,),
            input_operand_indexes=(inputs[0].source_operand_index, inputs[1].source_operand_index),
        ),
    )


def _gpr_output_immediate_binary_recipe(approved: ApprovedTargetLoweringPlan):
    """Encode ``dst = src OP immediate`` from an approved p-code constant.

    The immediate is stored in the Phase 6C contract after exact comparison
    with SourceValueOperationModel.  It is not read from source asm text and
    is not an operand the renderer needs to bind or infer.
    """
    c = approved.constraints
    contract = c.x86_gnu_inline_asm_contract
    if (
        contract is None
        or contract.immediate_value is None
        or not -(1 << 31) <= contract.immediate_value <= (1 << 31) - 1
        or contract.value_operation_kind not in {
            SourceValueOperationKind.UNSIGNED_ADD,
            SourceValueOperationKind.UNSIGNED_SUB,
            SourceValueOperationKind.BIT_AND,
            SourceValueOperationKind.BIT_OR,
            SourceValueOperationKind.BIT_XOR,
        }
    ):
        return None
    outputs = [item for item in c.operand_constraints if item.role is TargetOperandRole.OUTPUT]
    inputs = [item for item in c.operand_constraints if item.role is TargetOperandRole.INPUT]
    if len(outputs) != 1 or len(inputs) != 1:
        return None
    output, input_ = outputs[0], inputs[0]
    if (
        output.required_width_bits not in {32, 64}
        or input_.required_width_bits != output.required_width_bits
        or not output.early_clobber
        or input_.early_clobber
        or output.tied_to_source_operand_index is not None
        or input_.tied_to_source_operand_index is not None
        or output.requires_fixed_register
        or input_.requires_fixed_register
        or TargetOperandClass.GENERAL_REGISTER not in output.allowed_classes
        or TargetOperandClass.GENERAL_REGISTER not in input_.allowed_classes
    ):
        return None
    suffix = "l" if output.required_width_bits == 32 else "q"
    opcode = {
        SourceValueOperationKind.UNSIGNED_ADD: "add",
        SourceValueOperationKind.UNSIGNED_SUB: "sub",
        SourceValueOperationKind.BIT_AND: "and",
        SourceValueOperationKind.BIT_OR: "or",
        SourceValueOperationKind.BIT_XOR: "xor",
    }[contract.value_operation_kind]
    return (
        RendererContractKind.GNU_INLINE_ASM,
        GnuInlineAsmRecipe(
            template=(
                f"mov{suffix} %1, %0\n\t"
                f"{opcode}{suffix} ${contract.immediate_value}, %0"
            ),
            output_operand_indexes=(output.source_operand_index,),
            input_operand_indexes=(input_.source_operand_index,),
        ),
    )


def _gpr_add_then_shift_left_recipe(approved: ApprovedTargetLoweringPlan):
    """Encode the finite, proof-bound two-output add/shift sequence.

    The recipe consumes the temporary/result roles and shift count that 6C
    stored in the approved contract.  It does not inspect source asm or pick
    operand order from a template.
    """
    c = approved.constraints
    contract = c.x86_gnu_inline_asm_contract
    if (contract is None or
            contract.value_operation_kind is not SourceValueOperationKind.ADD_THEN_SHIFT_LEFT_IMMEDIATE or
            contract.immediate_value is None or not 0 <= contract.immediate_value < 64):
        return None
    outputs = [item for item in c.operand_constraints if item.role is TargetOperandRole.OUTPUT]
    inputs = [item for item in c.operand_constraints if item.role is TargetOperandRole.INPUT]
    if len(outputs) != 2 or len(inputs) != 2:
        return None
    temporary, result = outputs
    if (temporary.required_width_bits not in {32, 64} or
            result.required_width_bits != temporary.required_width_bits or
            not temporary.early_clobber or result.early_clobber or
            any(item.required_width_bits != temporary.required_width_bits or
                item.early_clobber or item.requires_fixed_register or
                TargetOperandClass.GENERAL_REGISTER not in item.allowed_classes
                for item in inputs) or
            any(item.requires_fixed_register or
                TargetOperandClass.GENERAL_REGISTER not in item.allowed_classes
                for item in outputs)):
        return None
    suffix = "l" if temporary.required_width_bits == 32 else "q"
    return (RendererContractKind.GNU_INLINE_ASM, GnuInlineAsmRecipe(
        template=(f"mov{suffix} %2, %0\n\tadd{suffix} %3, %0\n\t"
                  f"mov{suffix} %0, %1\n\tshl{suffix} ${contract.immediate_value}, %1"),
        output_operand_indexes=(temporary.source_operand_index, result.source_operand_index),
        input_operand_indexes=(inputs[0].source_operand_index, inputs[1].source_operand_index),
    ))


def _gpr_straight_line_program_recipe(approved: ApprovedTargetLoweringPlan):
    """Render a proof-bound canonical GPR dataflow program.

    This is deliberately table-driven from ``SourceStraightLineValueProgram``;
    no source mnemonic, rendered text, or unbound scratch register participates
    in the lowering.  Every intermediate must already be an output operand.
    """
    c = approved.constraints
    contract = c.x86_gnu_inline_asm_contract
    program = None if contract is None else contract.straight_line_program
    if program is None or not program.complete or program.width_bits not in {32, 64}:
        return None
    operands = {item.source_operand_index: item for item in c.operand_constraints}
    output_order = tuple(program.output_operand_indexes)
    input_order = tuple(program.input_operand_indexes)
    if len(set(output_order)) != len(output_order) or any(index not in operands for index in (*output_order, *input_order)):
        return None
    if (any(operands[index].role is not TargetOperandRole.OUTPUT or
            operands[index].required_width_bits != program.width_bits or
            TargetOperandClass.GENERAL_REGISTER not in operands[index].allowed_classes
            for index in output_order) or
            any(operands[index].role is not TargetOperandRole.INPUT or
            operands[index].required_width_bits != program.width_bits or
            TargetOperandClass.GENERAL_REGISTER not in operands[index].allowed_classes
            for index in input_order)):
        return None
    slots = {index: position for position, index in enumerate(output_order)}
    slots.update({index: len(output_order) + position for position, index in enumerate(input_order)})
    suffix = "l" if program.width_bits == 32 else "q"
    binary = {
        SourceStraightLineValueOpcode.UNSIGNED_ADD: "add",
        SourceStraightLineValueOpcode.UNSIGNED_SUB: "sub",
        SourceStraightLineValueOpcode.BIT_AND: "and",
        SourceStraightLineValueOpcode.BIT_OR: "or",
        SourceStraightLineValueOpcode.BIT_XOR: "xor",
    }
    shifts = {
        SourceStraightLineValueOpcode.SHIFT_LEFT_IMMEDIATE: "shl",
        SourceStraightLineValueOpcode.SHIFT_RIGHT_LOGICAL_IMMEDIATE: "shr",
        SourceStraightLineValueOpcode.SHIFT_RIGHT_ARITHMETIC_IMMEDIATE: "sar",
    }
    lines: list[str] = []
    for instruction in program.instructions:
        destination = slots.get(instruction.output_operand_index)
        sources = [slots.get(index) for index in instruction.input_operand_indexes]
        if destination is None or any(item is None for item in sources):
            return None
        dst = f"%{destination}"
        if instruction.opcode is SourceStraightLineValueOpcode.COPY:
            if len(sources) != 1:
                return None
            lines.append(f"mov{suffix} %{sources[0]}, {dst}")
        elif instruction.opcode in binary:
            if len(sources) != 2:
                return None
            lines.extend((f"mov{suffix} %{sources[0]}, {dst}",
                          f"{binary[instruction.opcode]}{suffix} %{sources[1]}, {dst}"))
        elif instruction.opcode in shifts:
            if len(sources) != 1 or instruction.immediate_value is None or not 0 <= instruction.immediate_value < program.width_bits:
                return None
            lines.extend((f"mov{suffix} %{sources[0]}, {dst}",
                          f"{shifts[instruction.opcode]}{suffix} ${instruction.immediate_value}, {dst}"))
        else:
            return None
    return (RendererContractKind.GNU_INLINE_ASM, GnuInlineAsmRecipe(
        template="\n\t".join(lines), output_operand_indexes=output_order,
        input_operand_indexes=input_order,
    ))


_ORDER_CONSTANTS = {
    "relaxed": "__ATOMIC_RELAXED",
    "consume": "__ATOMIC_CONSUME",
    "acquire": "__ATOMIC_ACQUIRE",
    "release": "__ATOMIC_RELEASE",
    "acq_rel": "__ATOMIC_ACQ_REL",
    "seq_cst": "__ATOMIC_SEQ_CST",
}


def _atomic_public_builtin_recipe(approved: ApprovedTargetLoweringPlan):
    """Render only a fully derived __atomic_load_n/store_n contract."""
    contract = approved.constraints.c_builtin_constraint
    if contract is None or contract.semantic_contract_id not in {
        "c.builtin.atomic-load-n.u32-u64.v1",
        "c.builtin.atomic-store-n.u32-u64.v1",
    }:
        return None
    memory = approved.constraints.memory_constraint
    if (contract.builtin_identifier not in {"__atomic_load_n", "__atomic_store_n"} or
            contract.width_bits not in {32, 64} or
            contract.alignment_bytes is None or
            contract.alignment_bytes < contract.width_bits // 8 or
            contract.success_ordering not in _ORDER_CONSTANTS or
            contract.object_operand_index is None or
            not contract.object_pointee_type_id or
            not memory.requires_atomic_ordering or
            not memory.requires_compiler_barrier or
            memory.atomic_success_ordering is None or
            memory.atomic_success_ordering.value != contract.success_ordering or
            memory.required_atomic_width_bits != contract.width_bits or
            memory.required_alignment_bytes != contract.alignment_bytes):
        return None
    order = CBuiltinArgument(literal=_ORDER_CONSTANTS[contract.success_ordering])
    if contract.semantic_contract_id == "c.builtin.atomic-load-n.u32-u64.v1":
        if (contract.result_operand_index is None or
                contract.value_operand_index is not None or
                not contract.result_c_type_id):
            return None
        arguments = (CBuiltinArgument(contract.object_operand_index), order)
        result = contract.result_operand_index
    else:
        if (contract.value_operand_index is None or
                contract.result_operand_index is not None or
                not contract.value_c_type_id):
            return None
        arguments = (
            CBuiltinArgument(contract.object_operand_index),
            CBuiltinArgument(contract.value_operand_index),
            order,
        )
        result = None
    return (
        RendererContractKind.C_BUILTIN,
        CBuiltinRecipe(
            builtin_identifier=contract.builtin_identifier,
            result_operand_index=result,
            argument_sequence=arguments,
            required_declaration=contract.required_declaration,
        ),
    )


def _compiler_barrier_public_builtin_recipe(approved: ApprovedTargetLoweringPlan):
    contract = approved.constraints.c_builtin_constraint
    memory = approved.constraints.memory_constraint
    if (contract is None or
            contract.semantic_contract_id != "c.builtin.atomic-signal-fence.compiler-barrier.seq-cst.v1" or
            contract.builtin_identifier != "__atomic_signal_fence" or
            not contract.compiler_barrier or contract.hardware_barrier or
            not memory.requires_compiler_barrier or
            memory.requires_hardware_barrier or
            memory.requires_atomic_ordering):
        return None
    return (
        RendererContractKind.C_BUILTIN,
        CBuiltinRecipe(
            builtin_identifier="__atomic_signal_fence",
            argument_sequence=(CBuiltinArgument(literal="__ATOMIC_SEQ_CST"),),
        ),
    )


_LOCK_RMW_RECIPES = {
    "x86.gnu-att.atomic.lock-xadd.u32-u64.seq-cst.v1": (
        SourceAtomicRmwOperation.FETCH_ADD,
        "lock xadd",
        "lock_prefix",
    ),
    "x86.gnu-att.atomic.xchg.u32-u64.seq-cst.v1": (
        SourceAtomicRmwOperation.EXCHANGE,
        "xchg",
        "implicit_xchg_lock",
    ),
}


def _x86_lock_atomic_recipe(approved: ApprovedTargetLoweringPlan):
    """Construct an already-proved, two-output lock RMW recipe.

    The value operand is explicitly both the source value and old-value
    result.  The address binding is explicitly dereferenced by the recipe;
    neither relationship is inferred from the x86 template.
    """
    semantic_id = approved.plan.metadata.get("renderer_semantic_contract_id")
    expected = _LOCK_RMW_RECIPES.get(semantic_id)
    contract = approved.constraints.x86_atomic_contract
    memory = approved.constraints.memory_constraint
    if expected is None or contract is None:
        return None
    operation, opcode, lock_mechanism = expected
    if (contract.semantic_contract_id != semantic_id or
            contract.rmw_operation is not operation or
            contract.kind.value != "read_modify_write" or
            contract.lock_mechanism is None or
            contract.lock_mechanism.value != lock_mechanism or
            not contract.requires_lock_semantics or
            not contract.requires_compiler_barrier or
            not contract.requires_hardware_ordering or
            contract.success_ordering is not SourceMemoryOrdering.SEQ_CST or
            contract.failure_ordering is not None or
            contract.width_bits not in {32, 64} or
            contract.alignment_bytes < contract.width_bits // 8 or
            contract.value_operand_index != contract.result_operand_index or
            not memory.requires_memory_clobber or
            not memory.requires_compiler_barrier or
            not memory.requires_hardware_barrier or
            not memory.requires_atomic_ordering or
            memory.atomic_success_ordering is not SourceMemoryOrdering.SEQ_CST or
            memory.atomic_failure_ordering is not None or
            memory.required_atomic_width_bits != contract.width_bits or
            memory.required_alignment_bytes != contract.alignment_bytes):
        return None
    operands = {item.source_operand_index: item for item in approved.constraints.operand_constraints}
    value = operands.get(contract.value_operand_index)
    address = operands.get(contract.object_operand_index)
    if (len(operands) != 2 or value is None or address is None or
            value.role is not TargetOperandRole.READ_WRITE or
            value.allowed_classes != frozenset({TargetOperandClass.GENERAL_REGISTER}) or
            value.required_width_bits != contract.width_bits or
            address.role is not TargetOperandRole.READ_WRITE or
            address.allowed_classes != frozenset({TargetOperandClass.MEMORY})):
        return None
    suffix = "l" if contract.width_bits == 32 else "q"
    return (
        RendererContractKind.GNU_INLINE_ASM,
        GnuInlineAsmRecipe(
            template=f"{opcode}{suffix} %0, %1",
            output_operand_indexes=(value.source_operand_index, address.source_operand_index),
            input_operand_indexes=(),
            memory_dereference_operand_indexes=(address.source_operand_index,),
        ),
    )


def _x86_barrier_recipe(approved: ApprovedTargetLoweringPlan):
    """Encode only the concrete approved full-fence/serialize route."""
    semantic_id = approved.plan.metadata.get("renderer_semantic_contract_id")
    contract = approved.constraints.x86_barrier_contract
    memory = approved.constraints.memory_constraint
    routes = {
        "x86.gnu-att.mfence.full-system-seq-cst.v1": ("mfence", "full_hardware_fence", "x86:hardware_fence"),
        "x86.gnu-att.serialize.instruction-serialization.v1": ("serialize", "instruction_serialization", "x86:serialize"),
    }
    expected = routes.get(semantic_id)
    if expected is None or contract is None:
        return None
    template, route, feature = expected
    if (contract.semantic_contract_id != semantic_id or
            contract.route != route or contract.required_target_feature != feature or
            not contract.compiler_barrier or
            not memory.requires_memory_clobber or
            not memory.requires_compiler_barrier):
        return None
    if route == "full_hardware_fence":
        if (not contract.hardware_memory_fence or not memory.requires_hardware_barrier or
                contract.ordering is not SourceMemoryOrdering.SEQ_CST or
                contract.scope is None or contract.scope.value != "system" or
                contract.instruction_serializing or memory.requires_instruction_serialization):
            return None
    else:
        if (contract.hardware_memory_fence or memory.requires_hardware_barrier or
                not contract.instruction_serializing or
                not memory.requires_instruction_serialization):
            return None
    return (RendererContractKind.GNU_INLINE_ASM, GnuInlineAsmRecipe(
        template=template, output_operand_indexes=(), input_operand_indexes=(),
    ))


def _x86_direct_memory_recipe(approved: ApprovedTargetLoweringPlan):
    """Encode only a checked scalar ``mov`` address-register contract."""
    semantic_id = approved.plan.metadata.get("renderer_semantic_contract_id")
    expected = {
        "x86.gnu-att.memory.load.gpr-address.u32.v1": ("load", 32),
        "x86.gnu-att.memory.load.gpr-address.u64.v1": ("load", 64),
        "x86.gnu-att.memory.store.gpr-address.u32.v1": ("store", 32),
        "x86.gnu-att.memory.store.gpr-address.u64.v1": ("store", 64),
    }.get(semantic_id)
    contract = approved.constraints.x86_memory_inline_asm_contract
    memory = approved.constraints.memory_constraint
    if (expected is None or contract is None or
            contract.semantic_contract_id != semantic_id or
            contract.operation_kind != expected[0] or
            contract.value_width_bits != expected[1] or
            contract.address_operand_index is None or contract.value_operand_index is None or
            not contract.memory_clobber or not contract.compiler_barrier or
            not memory.requires_memory_clobber or not memory.requires_compiler_barrier):
        return None
    operands = {item.source_operand_index: item for item in approved.constraints.operand_constraints}
    address = operands.get(contract.address_operand_index)
    value = operands.get(contract.value_operand_index)
    if (len(operands) != 2 or address is None or value is None or
            address.role is not TargetOperandRole.INPUT or
            address.allowed_classes != frozenset({TargetOperandClass.GENERAL_REGISTER}) or
            value.allowed_classes != frozenset({TargetOperandClass.GENERAL_REGISTER}) or
            value.required_width_bits != expected[1]):
        return None
    suffix = "l" if expected[1] == 32 else "q"
    if expected[0] == "load":
        if value.role is not TargetOperandRole.OUTPUT:
            return None
        recipe = GnuInlineAsmRecipe(
            template=f"mov{suffix} (%1), %0",
            output_operand_indexes=(value.source_operand_index,),
            input_operand_indexes=(address.source_operand_index,),
        )
    else:
        if value.role is not TargetOperandRole.INPUT:
            return None
        recipe = GnuInlineAsmRecipe(
            template=f"mov{suffix} %1, (%0)",
            output_operand_indexes=(),
            input_operand_indexes=(address.source_operand_index, value.source_operand_index),
        )
    return RendererContractKind.GNU_INLINE_ASM, recipe


_ASM_GOTO_ZERO_TEST_RECIPES = {
    "x86.gnu-att.asm-goto.bzero.u32-u64.v1": "je",
    "x86.gnu-att.asm-goto.bnonzero.u32-u64.v1": "jne",
}


def _x86_asm_goto_zero_test_recipe(approved: ApprovedTargetLoweringPlan):
    """Build only the proof-compatible ``test + je/jne`` asm-goto family.

    The branch meaning, operand position, label set, width, cc clobber and
    volatile status are all checked against the approved Phase-6C contract.
    This factory contains no source-asm/mnemonic interpretation.
    """
    semantic_id = approved.plan.metadata.get("renderer_semantic_contract_id")
    jump = _ASM_GOTO_ZERO_TEST_RECIPES.get(semantic_id)
    flow = approved.constraints.structured_control_flow_contract
    operands = tuple(approved.constraints.operand_constraints)
    if (jump is None or flow is None or
            flow.semantic_contract_id != semantic_id or
            not flow.uses_asm_goto or
            not approved.constraints.control_flow_constraint.preserve_asm_goto or
            not approved.constraints.preserve_cc_clobber or
            len(flow.asm_goto_labels) != 1 or
            len(flow.fallthrough_continuations) != 1 or
            flow.has_multiple_exits or flow.has_exception_or_trap_edge or
            flow.state_merge_requirements or
            flow.asm_goto_fallthrough_continuation_id != flow.fallthrough_continuations[0] or
            set(flow.asm_goto_successor_continuation_ids) !=
                ({flow.fallthrough_continuations[0]} | {item.target_continuation_id for item in flow.asm_goto_labels}) or
            len(operands) != 1):
        return None
    operand = operands[0]
    if (operand.role is not TargetOperandRole.INPUT or
            operand.allowed_classes != frozenset({TargetOperandClass.GENERAL_REGISTER}) or
            operand.required_width_bits not in {32, 64} or
            operand.tied_to_source_operand_index is not None or
            operand.early_clobber or operand.requires_fixed_register):
        return None
    suffix = "l" if operand.required_width_bits == 32 else "q"
    label = flow.asm_goto_labels[0]
    return (
        RendererContractKind.GNU_ASM_GOTO,
        GnuAsmGotoRecipe(
            # Keep recipe text logical, rather than pre-escaped for C.
            template=f"test{suffix} %0, %0\n\t{jump} %l[{label.label}]",
            output_operand_indexes=(),
            input_operand_indexes=(operand.source_operand_index,),
            label_bindings=(GnuAsmGotoLabelBinding(
                label=label.label,
                target_continuation_id=label.target_continuation_id,
            ),),
        ),
    )


GPR_INTEGER_RENDERER_CONTRACT_REGISTRY = RendererContractRegistry(
    registry_id="phase6f.target-contracts", version="helper-abi-contract-registry-v1",
    entries=(
        RegisteredRendererContract(
            "x86.gnu-att.gpr.straight-line-u32-u64.v1",
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            "x86.gnu-att.gpr.straight-line-u32-u64",
            _gpr_straight_line_program_recipe,
            "x86_gnu_inline_asm_contract",
            frozenset({"x86:gpr_inline_asm"}),
        ),
        RegisteredRendererContract(
            "x86.gnu-att.gpr.add-then-shl-imm.u32-u64.early-clobber.v1",
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            "x86.gnu-att.gpr.add-then-shl-imm.u32-u64.early-clobber",
            _gpr_add_then_shift_left_recipe,
            "x86_gnu_inline_asm_contract",
            frozenset({"x86:gpr_inline_asm"}),
        ),
        RegisteredRendererContract(
            "x86.gnu-att.gpr.out-gpr-immediate-binary.v1",
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            "x86.gnu-att.gpr.out-gpr-immediate-binary",
            _gpr_output_immediate_binary_recipe,
            "x86_gnu_inline_asm_contract",
        ),
        RegisteredRendererContract(
            "x86.gnu-att.gpr.out-gpr-gpr-binary.v1",
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            "x86.gnu-att.gpr.out-gpr-gpr-binary",
            _gpr_output_gpr_binary_recipe,
            "x86_gnu_inline_asm_contract",
        ),
        RegisteredRendererContract(
            "x86.gnu-att.gpr.rw-gpr-binary.v1",
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            "x86.gnu-att.gpr.rw-gpr-binary",
            _gpr_rw_gpr_binary_recipe,
            "x86_gnu_inline_asm_contract",
        ),
        RegisteredRendererContract(
            "x86.gnu-att.gpr.rw-immediate-binary.v1",
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            "x86.gnu-att.gpr.rw-immediate-binary",
            _gpr_rw_immediate_binary_recipe,
            "x86_gnu_inline_asm_contract",
        ),
        RegisteredRendererContract(
            "x86.gnu-att.gpr.rw-early-clobber-binary.v1",
            TargetLoweringKind.X86_GNU_INLINE_ASM,
            "x86.gnu-att.gpr.rw-early-clobber-binary",
            _gpr_rw_early_clobber_binary_recipe,
            "x86_gnu_inline_asm_contract",
        ),
        RegisteredRendererContract(
            "c.builtin.atomic-load-n.u32-u64.v1",
            TargetLoweringKind.C_BUILTIN,
            "c.builtin.atomic-load-n.u32-u64",
            _atomic_public_builtin_recipe,
            "c_builtin_constraint",
            frozenset({"compiler:atomic-builtin"}),
        ),
        RegisteredRendererContract(
            "c.builtin.atomic-store-n.u32-u64.v1",
            TargetLoweringKind.C_BUILTIN,
            "c.builtin.atomic-store-n.u32-u64",
            _atomic_public_builtin_recipe,
            "c_builtin_constraint",
            frozenset({"compiler:atomic-builtin"}),
        ),
        RegisteredRendererContract(
            "c.builtin.atomic-signal-fence.compiler-barrier.seq-cst.v1",
            TargetLoweringKind.C_BUILTIN,
            "c.builtin.atomic-signal-fence.compiler-barrier",
            _compiler_barrier_public_builtin_recipe,
            "c_builtin_constraint",
            frozenset({"compiler:barrier-builtin"}),
        ),
        RegisteredRendererContract(
            "x86.gnu-att.atomic.lock-xadd.u32-u64.seq-cst.v1",
            TargetLoweringKind.X86_ATOMIC,
            "x86.gnu-att.atomic.lock-xadd.u32-u64.seq-cst",
            _x86_lock_atomic_recipe,
            "x86_atomic_contract",
            frozenset({"x86:atomic"}),
        ),
        RegisteredRendererContract(
            "x86.gnu-att.atomic.xchg.u32-u64.seq-cst.v1",
            TargetLoweringKind.X86_ATOMIC,
            "x86.gnu-att.atomic.xchg.u32-u64.seq-cst",
            _x86_lock_atomic_recipe,
            "x86_atomic_contract",
            frozenset({"x86:atomic"}),
        ),
        RegisteredRendererContract(
            "x86.gnu-att.mfence.full-system-seq-cst.v1",
            TargetLoweringKind.X86_BARRIER,
            "x86.gnu-att.mfence.full-system-seq-cst",
            _x86_barrier_recipe,
            "x86_barrier_contract",
            frozenset({"x86:hardware_fence"}),
        ),
        RegisteredRendererContract(
            "x86.gnu-att.serialize.instruction-serialization.v1",
            TargetLoweringKind.X86_BARRIER,
            "x86.gnu-att.serialize.instruction-serialization",
            _x86_barrier_recipe,
            "x86_barrier_contract",
            frozenset({"x86:serialize"}),
        ),
        *tuple(
            RegisteredRendererContract(
                semantic_id,
                TargetLoweringKind.X86_GNU_INLINE_ASM,
                semantic_id.removesuffix(".v1"),
                _x86_direct_memory_recipe,
                "x86_memory_inline_asm_contract",
                frozenset({"x86:gpr_inline_asm"}),
            )
            for semantic_id in (
                "x86.gnu-att.memory.load.gpr-address.u32.v1",
                "x86.gnu-att.memory.load.gpr-address.u64.v1",
                "x86.gnu-att.memory.store.gpr-address.u32.v1",
                "x86.gnu-att.memory.store.gpr-address.u64.v1",
            )
        ),
        RegisteredRendererContract(
            "x86.gnu-att.asm-goto.bzero.u32-u64.v1",
            TargetLoweringKind.STRUCTURED_CONTROL_FLOW,
            "x86.gnu-att.asm-goto.bzero.u32-u64",
            _x86_asm_goto_zero_test_recipe,
            "structured_control_flow_contract",
            frozenset({"x86:gpr_inline_asm"}),
        ),
        RegisteredRendererContract(
            "x86.gnu-att.asm-goto.bnonzero.u32-u64.v1",
            TargetLoweringKind.STRUCTURED_CONTROL_FLOW,
            "x86.gnu-att.asm-goto.bnonzero.u32-u64",
            _x86_asm_goto_zero_test_recipe,
            "structured_control_flow_contract",
            frozenset({"x86:gpr_inline_asm"}),
        ),
    ),
)

# Default availability is intentionally finite and shipped with this source
# tree.  Additional helpers must be supplied through the same registration
# API, never via a symbol-name fallback.
GPR_INTEGER_RENDERER_CONTRACT_REGISTRY = register_helper_abi_contracts(
    GPR_INTEGER_RENDERER_CONTRACT_REGISTRY,
    (RegisteredHelperAbiContract(
        semantic_contract_id="helper." + RV64_MULHU_U64.runtime_contract_id,
        helper_symbol=RV64_MULHU_U64.helper_symbol,
        semantic_version=RV64_MULHU_U64.semantic_version,
        calling_convention=RV64_MULHU_U64.calling_convention,
        target_abi=RV64_MULHU_U64.target_abi,
        parameter_type_ids=RV64_MULHU_U64.parameter_type_ids,
        return_type_id=RV64_MULHU_U64.return_type_id,
        runtime_contract_id=RV64_MULHU_U64.runtime_contract_id,
        helper_registry_version=RUNTIME_HELPER_MANIFEST_VERSION,
        memory_effect=RV64_MULHU_U64.memory_effect,
        may_return=RV64_MULHU_U64.may_return,
        may_unwind=RV64_MULHU_U64.may_unwind,
        pic_plt_compatible=RV64_MULHU_U64.pic_plt_compatible,
        required_stack_alignment_bytes=RV64_MULHU_U64.required_stack_alignment_bytes,
        preserves_stack_pointer=RV64_MULHU_U64.preserves_stack_pointer,
        preserves_frame_pointer=RV64_MULHU_U64.preserves_frame_pointer,
        caller_saved_registers=RV64_MULHU_U64.caller_saved_registers,
        callee_saved_registers=RV64_MULHU_U64.callee_saved_registers,
        required_header=RV64_MULHU_U64.required_header,
        runtime_library=RV64_MULHU_U64.runtime_library,
    ),),
)
