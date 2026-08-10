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
from .phase6f_renderer import GnuInlineAsmRecipe, RendererContractKind
from .phase6c_constraints import TargetOperandRole, TargetOperandClass
from .source_model import SourceValueOperationKind
from .plan_types import TargetLoweringKind


RecipeFactory = Callable[[ApprovedTargetLoweringPlan], object | None]


@dataclass(frozen=True)
class RegisteredRendererContract:
    semantic_contract_id: str
    plan_kind: TargetLoweringKind
    renderer_contract_id: str
    make_payload: RecipeFactory
    required_constraint_field: str


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
            kind=payload[0], payload=payload[1], required_features=frozenset(),
        )


EMPTY_RENDERER_CONTRACT_REGISTRY = RendererContractRegistry(
    registry_id="phase6f.target-contracts", version="1"
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


GPR_INTEGER_RENDERER_CONTRACT_REGISTRY = RendererContractRegistry(
    registry_id="phase6f.target-contracts", version="gpr-operand-contracts-v1",
    entries=(
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
    ),
)
