"""Phase 6F: fail-closed rendering of an already approved lowering contract.

This module deliberately consumes no raw asm, lift, CFG, or renderer output
from earlier stages.  It serializes only an ``ApprovedTargetLoweringPlan`` and
an explicit renderer contract registered for that exact plan id.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from .phase6c_constraints import (
    TargetAsmDialect, TargetConstraintModel, TargetOperandClass,
    TargetOperandConstraint, TargetOperandRole, TargetEnvironment,
)
from .phase6d_common import SemanticProofResult, constraint_identity
from .phase6e_selection import ApprovedTargetLoweringPlan
from .phase6e_selection import FinalSelectionKind, FinalSelectionResult
from .plan_types import TargetLoweringKind


class RendererContractKind(str, Enum):
    C_EXPRESSION = "c_expression"
    C_BUILTIN = "c_builtin"
    GNU_INLINE_ASM = "gnu_inline_asm"
    GNU_ASM_GOTO = "gnu_asm_goto"
    HELPER_CALL = "helper_call"
    STRUCTURED_CONTROL_FLOW = "structured_control_flow"
    KEEP_ANNOTATION = "keep_annotation"
    UNSUPPORTED_DIAGNOSTIC = "unsupported_diagnostic"


class RenderedReplacementKind(str, Enum):
    C_EXPRESSION = "c_expression"
    C_BUILTIN = "c_builtin"
    GNU_INLINE_ASM = "gnu_inline_asm"
    GNU_ASM_GOTO = "gnu_asm_goto"
    HELPER_CALL = "helper_call"
    STRUCTURED_CONTROL_FLOW = "structured_control_flow"
    KEEP_ANNOTATION = "keep_annotation"
    UNSUPPORTED_DIAGNOSTIC = "unsupported_diagnostic"
    INTERNAL_ERROR = "internal_error"


class RenderReasonCode(str, Enum):
    INTERNAL_INVARIANT_FAILURE = "phase6f.internal_invariant_failure"
    APPROVED_PLAN_INCONSISTENT = "phase6f.approved_plan_inconsistent"
    CONSTRAINT_CONTRACT_INCONSISTENT = "phase6f.constraint_contract_inconsistent"
    RENDERER_CAPABILITY_UNAVAILABLE = "phase6f.renderer_capability_unavailable"
    RENDERER_CONTRACT_MISSING = "phase6f.renderer_contract_missing"
    OPERAND_BINDING_MISSING = "phase6f.operand_binding_missing"
    TIED_OUTPUT_MISSING = "phase6f.tied_output_missing"
    FIXED_REGISTER_UNENCODABLE = "phase6f.fixed_register_constraint_unencodable"
    LABEL_BINDING_MISSING = "phase6f.label_binding_missing"
    HELPER_CONTRACT_MISSING = "phase6f.helper_contract_missing"
    PLAN_KIND_CONTRACT_MISMATCH = "phase6f.plan_kind_contract_mismatch"
    ASM_GOTO_LABEL_CONTRACT_MISMATCH = "phase6f.asm_goto_label_contract_mismatch"
    SELECTION_RESULT_INCONSISTENT = "phase6f.selection_result_inconsistent"


@dataclass(frozen=True)
class COperandRef:
    operand_index: int


@dataclass(frozen=True)
class CBinaryExpression:
    operator: str
    left: "CExpressionNode"
    right: "CExpressionNode"


@dataclass(frozen=True)
class CLiteralExpression:
    spelling: str


CExpressionNode = COperandRef | CBinaryExpression | CLiteralExpression


@dataclass(frozen=True)
class CExpressionRecipe:
    expression: CExpressionNode
    result_operand_index: int | None = None


@dataclass(frozen=True)
class CBuiltinArgument:
    """One explicitly typed renderer argument; never inferred at render time."""
    operand_index: int | None = None
    literal: str | None = None

    def __post_init__(self) -> None:
        if (self.operand_index is None) == (self.literal is None):
            raise ValueError("C builtin argument requires exactly one source")
        if self.operand_index is not None and (
                isinstance(self.operand_index, bool) or
                not isinstance(self.operand_index, int) or self.operand_index < 0):
            raise TypeError("operand_index must be a non-negative int")
        if self.literal is not None and (not isinstance(self.literal, str) or not self.literal.strip()):
            raise TypeError("literal must be a non-empty str")


@dataclass(frozen=True)
class CBuiltinRecipe:
    builtin_identifier: str
    argument_operand_indexes: tuple[int, ...] = ()
    result_operand_index: int | None = None
    # New recipes must use argument_sequence.  The legacy field remains only
    # for existing callers while they migrate to a fully explicit contract.
    argument_sequence: tuple[CBuiltinArgument, ...] = ()
    required_declaration: str | None = None


@dataclass(frozen=True)
class GnuInlineAsmRecipe:
    template: str
    output_operand_indexes: tuple[int, ...]
    input_operand_indexes: tuple[int, ...]
    # A registered atomic recipe may explicitly turn a proven address binding
    # into the C lvalue used by a GNU "m" operand.  Renderer never guesses
    # this from the operand class or template.
    memory_dereference_operand_indexes: tuple[int, ...] = ()


@dataclass(frozen=True)
class GnuAsmGotoRecipe(GnuInlineAsmRecipe):
    label_bindings: tuple["GnuAsmGotoLabelBinding", ...] = ()


@dataclass(frozen=True)
class GnuAsmGotoLabelBinding:
    label: str
    target_continuation_id: str


@dataclass(frozen=True)
class HelperCallRecipe:
    helper_symbol: str
    argument_operand_indexes: tuple[int, ...]
    result_operand_index: int | None = None


@dataclass(frozen=True)
class StructuredControlFlowRecipe:
    statements: tuple["StructuredStatement", ...]
    label_bindings: tuple[GnuAsmGotoLabelBinding, ...] = ()


@dataclass(frozen=True)
class StructuredStatement:
    kind: str
    text: str


@dataclass(frozen=True)
class RendererContract:
    contract_id: str
    plan_id: str
    kind: RendererContractKind
    payload: object
    required_features: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RendererContext:
    """Explicit C-expression/lvalue bindings and plan-id keyed recipes."""
    contracts_by_plan_id: Mapping[str, RendererContract]
    operand_bindings: Mapping[int, str]
    renderer_id: str = "phase6f.gnu-att"
    renderer_version: str = "1"
    source_fragment_id: str = ""


@dataclass(frozen=True)
class Phase6FRenderRequest:
    approved_plan: ApprovedTargetLoweringPlan
    target_environment: TargetEnvironment
    renderer_context: RendererContext


@dataclass(frozen=True)
class GnuAsmOperand:
    constraint: str
    expression: str


@dataclass(frozen=True)
class GnuAsmNode:
    template: str
    volatile: bool
    outputs: tuple[GnuAsmOperand, ...]
    inputs: tuple[GnuAsmOperand, ...]
    clobbers: tuple[str, ...]
    goto_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class RenderedReplacement:
    kind: RenderedReplacementKind
    target_ast: object | None
    emitted_text: str | None
    diagnostics: tuple[RenderReasonCode, ...]
    source_model_id: str
    approved_plan_id: str | None
    renderer_id: str
    renderer_version: str


def _environment_id(e: TargetEnvironment) -> str:
    return f"{e.architecture.value}:{e.abi.value}:{e.asm_dialect.value}"


def _failure(request: Phase6FRenderRequest, code: RenderReasonCode, *, internal: bool) -> RenderedReplacement:
    approved = request.approved_plan if isinstance(request.approved_plan, ApprovedTargetLoweringPlan) else None
    return RenderedReplacement(
        RenderedReplacementKind.INTERNAL_ERROR if internal else RenderedReplacementKind.UNSUPPORTED_DIAGNOSTIC,
        None, None, (code,), "" if approved is None else approved.source_model_id,
        None if approved is None else approved.plan.plan_id,
        request.renderer_context.renderer_id, request.renderer_context.renderer_version,
    )


def _validate(request: Phase6FRenderRequest) -> RenderReasonCode | None:
    if not isinstance(request.approved_plan, ApprovedTargetLoweringPlan):
        return RenderReasonCode.APPROVED_PLAN_INCONSISTENT
    a = request.approved_plan
    if not isinstance(a.constraints, TargetConstraintModel) or not isinstance(a.proof, SemanticProofResult):
        return RenderReasonCode.APPROVED_PLAN_INCONSISTENT
    if not a.proof.approved or a.proof.evidence is None or a.constraints.plan_id != a.plan.plan_id:
        return RenderReasonCode.APPROVED_PLAN_INCONSISTENT
    e = a.proof.evidence
    if (a.proof.plan_id != a.plan.plan_id or e.plan_id != a.plan.plan_id or
            e.constraints_plan_id != a.plan.plan_id or e.constraints_id != constraint_identity(a.constraints) or
            a.target_environment_id != _environment_id(request.target_environment) or
            e.target_environment_id != a.target_environment_id or a.constraints.environment != request.target_environment):
        return RenderReasonCode.CONSTRAINT_CONTRACT_INCONSISTENT
    if not a.plan.supports_features(request.target_environment.available_features):
        return RenderReasonCode.RENDERER_CAPABILITY_UNAVAILABLE
    return None


def _binding(context: RendererContext, index: int) -> str | None:
    value = context.operand_bindings.get(index)
    return value if isinstance(value, str) and value.strip() else None


def _render_c_expression(node: CExpressionNode, context: RendererContext) -> str | None:
    if isinstance(node, COperandRef):
        return _binding(context, node.operand_index)
    if isinstance(node, CLiteralExpression):
        return node.spelling if node.spelling.strip() else None
    if isinstance(node, CBinaryExpression):
        left, right = _render_c_expression(node.left, context), _render_c_expression(node.right, context)
        if left is None or right is None or not node.operator.strip(): return None
        return f"({left} {node.operator} {right})"
    return None


def _operand_map(c: TargetConstraintModel) -> dict[int, TargetOperandConstraint]:
    return {x.source_operand_index: x for x in c.operand_constraints}


def _body(op: TargetOperandConstraint) -> str | None:
    if op.requires_fixed_register:
        return "{" + op.fixed_register_name + "}" if op.fixed_register_name else None
    classes = op.allowed_classes
    # The contract must be unambiguous: renderer cannot pick a class itself.
    if len(classes) != 1:
        return None
    return {TargetOperandClass.GENERAL_REGISTER: "r", TargetOperandClass.MEMORY: "m", TargetOperandClass.IMMEDIATE: "i"}[next(iter(classes))]


def _output(op: TargetOperandConstraint, expression: str) -> GnuAsmOperand | None:
    if op.role not in {TargetOperandRole.OUTPUT, TargetOperandRole.READ_WRITE}:
        return None
    body = _body(op)
    if body is None:
        return None
    return GnuAsmOperand(("=" if op.role is TargetOperandRole.OUTPUT else "+") + ("&" if op.early_clobber else "") + body, expression)


def _input(op: TargetOperandConstraint, expression: str, output_indexes: Mapping[int, int]) -> GnuAsmOperand | None:
    if op.tied_to_source_operand_index is not None:
        index = output_indexes.get(op.tied_to_source_operand_index)
        return None if index is None else GnuAsmOperand(str(index), expression)
    if op.role not in {TargetOperandRole.INPUT, TargetOperandRole.READ_WRITE}:
        return None
    body = _body(op)
    return None if body is None else GnuAsmOperand(body, expression)


def _serialize_asm(node: GnuAsmNode, *, is_goto: bool) -> str:
    q = node.template.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n\\t")
    operands = lambda xs: ", ".join(f'"{x.constraint}"({x.expression})' for x in xs)
    clobbers = ", ".join(f'"{x}"' for x in node.clobbers)
    head = "__asm__ goto" if is_goto else ("__asm__ volatile" if node.volatile else "__asm__")
    tail = " : " + ", ".join(node.goto_labels) if is_goto else ""
    return f'{head} ("{q}" : {operands(node.outputs)} : {operands(node.inputs)} : {clobbers}{tail});'


def _render_gnu(request: Phase6FRenderRequest, recipe: GnuInlineAsmRecipe, *, is_goto: bool) -> RenderedReplacement:
    a, ctx = request.approved_plan, request.renderer_context
    if not request.target_environment.supports_gnu_inline_asm or request.target_environment.asm_dialect is not TargetAsmDialect.GNU_ATT:
        return _failure(request, RenderReasonCode.RENDERER_CAPABILITY_UNAVAILABLE, internal=False)
    if is_goto and not request.target_environment.supports_gnu_asm_goto:
        return _failure(request, RenderReasonCode.RENDERER_CAPABILITY_UNAVAILABLE, internal=False)
    ops = _operand_map(a.constraints); outputs = []
    for i in recipe.output_operand_indexes:
        op, binding = ops.get(i), _binding(ctx, i)
        if binding is not None and i in recipe.memory_dereference_operand_indexes:
            binding = f"*({binding})"
        rendered = None if op is None or binding is None else _output(op, binding)
        if rendered is None:return _failure(request, RenderReasonCode.OPERAND_BINDING_MISSING, internal=True)
        outputs.append(rendered)
    output_indexes = {i: n for n, i in enumerate(recipe.output_operand_indexes)}; inputs=[]
    for i in recipe.input_operand_indexes:
        op, binding = ops.get(i), _binding(ctx, i)
        if binding is not None and i in recipe.memory_dereference_operand_indexes:
            binding = f"*({binding})"
        rendered = None if op is None or binding is None else _input(op, binding, output_indexes)
        if rendered is None:
            code = RenderReasonCode.TIED_OUTPUT_MISSING if op is not None and op.tied_to_source_operand_index is not None else RenderReasonCode.OPERAND_BINDING_MISSING
            return _failure(request, code, internal=True)
        inputs.append(rendered)
    labels = tuple(item.label for item in recipe.label_bindings) if isinstance(recipe, GnuAsmGotoRecipe) else ()
    source_labels = getattr(a.constraints.structured_control_flow_contract, "asm_goto_labels", ())
    expected_labels = {(item.label, item.target_continuation_id) for item in source_labels}
    recipe_labels = {(item.label, item.target_continuation_id) for item in getattr(recipe, "label_bindings", ())}
    if is_goto and (not labels or not a.constraints.control_flow_constraint.preserve_asm_goto):
        return _failure(request, RenderReasonCode.LABEL_BINDING_MISSING, internal=True)
    if is_goto and (not expected_labels or expected_labels != recipe_labels):
        return _failure(request, RenderReasonCode.ASM_GOTO_LABEL_CONTRACT_MISMATCH, internal=True)
    clobbers = (() if not a.constraints.preserve_cc_clobber else ("cc",)) + (() if not a.constraints.memory_constraint.requires_memory_clobber else ("memory",))
    node = GnuAsmNode(recipe.template, a.constraints.preserve_volatile, tuple(outputs), tuple(inputs), clobbers, labels)
    return RenderedReplacement(RenderedReplacementKind.GNU_ASM_GOTO if is_goto else RenderedReplacementKind.GNU_INLINE_ASM, node, _serialize_asm(node, is_goto=is_goto), (), a.source_model_id, a.plan.plan_id, ctx.renderer_id, ctx.renderer_version)


def _render_contract(request: Phase6FRenderRequest, contract: RendererContract) -> RenderedReplacement:
    a, ctx = request.approved_plan, request.renderer_context
    kind, p = contract.kind, contract.payload
    expected = {
        RendererContractKind.C_EXPRESSION: {TargetLoweringKind.C_EXPRESSION, TargetLoweringKind.C_STRUCTURED},
        RendererContractKind.C_BUILTIN: {TargetLoweringKind.C_BUILTIN}, RendererContractKind.GNU_INLINE_ASM: {TargetLoweringKind.X86_GNU_INLINE_ASM, TargetLoweringKind.X86_ATOMIC, TargetLoweringKind.X86_BARRIER},
        RendererContractKind.GNU_ASM_GOTO: {TargetLoweringKind.X86_GNU_INLINE_ASM}, RendererContractKind.HELPER_CALL: {TargetLoweringKind.HELPER_CALL},
        RendererContractKind.STRUCTURED_CONTROL_FLOW: {TargetLoweringKind.STRUCTURED_CONTROL_FLOW},
    }
    if a.plan.kind not in expected.get(kind, set()): return _failure(request, RenderReasonCode.PLAN_KIND_CONTRACT_MISMATCH, internal=True)
    if kind is RendererContractKind.GNU_INLINE_ASM and isinstance(p, GnuInlineAsmRecipe): return _render_gnu(request, p, is_goto=False)
    if kind is RendererContractKind.GNU_ASM_GOTO and isinstance(p, GnuAsmGotoRecipe): return _render_gnu(request, p, is_goto=True)
    if kind is RendererContractKind.C_EXPRESSION and isinstance(p, CExpressionRecipe):
        result = _binding(ctx, p.result_operand_index) if p.result_operand_index is not None else None
        expression = _render_c_expression(p.expression, ctx)
        if expression is None:return _failure(request, RenderReasonCode.OPERAND_BINDING_MISSING, internal=True)
        text = f"{result} = {expression};" if result is not None else f"{expression};"
        return RenderedReplacement(RenderedReplacementKind.C_EXPRESSION, p, text, (), a.source_model_id, a.plan.plan_id, ctx.renderer_id, ctx.renderer_version)
    if kind is RendererContractKind.C_BUILTIN and isinstance(p, CBuiltinRecipe):
        if p.argument_sequence:
            args = [
                _binding(ctx, item.operand_index)
                if item.operand_index is not None else item.literal
                for item in p.argument_sequence
            ]
        else:
            args = [_binding(ctx, i) for i in p.argument_operand_indexes]
        result = _binding(ctx, p.result_operand_index) if p.result_operand_index is not None else None
        if any(x is None for x in args) or (p.result_operand_index is not None and result is None): return _failure(request, RenderReasonCode.OPERAND_BINDING_MISSING, internal=True)
        call = p.builtin_identifier + "(" + ", ".join(args) + ")"
        return RenderedReplacement(RenderedReplacementKind.C_BUILTIN, p, (f"{result} = {call};" if result else f"{call};"), (), a.source_model_id, a.plan.plan_id, ctx.renderer_id, ctx.renderer_version)
    if kind is RendererContractKind.HELPER_CALL and isinstance(p, HelperCallRecipe):
        if a.constraints.helper_abi_contract is None:return _failure(request, RenderReasonCode.HELPER_CONTRACT_MISSING, internal=True)
        args=[_binding(ctx,i) for i in p.argument_operand_indexes]; result=_binding(ctx,p.result_operand_index) if p.result_operand_index is not None else None
        if any(x is None for x in args) or (p.result_operand_index is not None and result is None):return _failure(request,RenderReasonCode.OPERAND_BINDING_MISSING,internal=True)
        call=p.helper_symbol+"("+", ".join(args)+")"
        return RenderedReplacement(RenderedReplacementKind.HELPER_CALL,p,(f"{result} = {call};" if result else f"{call};"),(),a.source_model_id,a.plan.plan_id,ctx.renderer_id,ctx.renderer_version)
    if kind is RendererContractKind.STRUCTURED_CONTROL_FLOW and isinstance(p, StructuredControlFlowRecipe):
        if not a.constraints.control_flow_constraint.preserve_control_flow:return _failure(request,RenderReasonCode.CONSTRAINT_CONTRACT_INCONSISTENT,internal=True)
        if not p.statements:return _failure(request,RenderReasonCode.CONSTRAINT_CONTRACT_INCONSISTENT,internal=True)
        return RenderedReplacement(RenderedReplacementKind.STRUCTURED_CONTROL_FLOW,p,"\n".join(item.text for item in p.statements),(),a.source_model_id,a.plan.plan_id,ctx.renderer_id,ctx.renderer_version)
    return _failure(request, RenderReasonCode.RENDERER_CAPABILITY_UNAVAILABLE, internal=False)


def render_approved_target_lowering(request: Phase6FRenderRequest) -> RenderedReplacement:
    """Render exactly one approved plan; never reselect or synthesize semantics."""
    if not isinstance(request, Phase6FRenderRequest):
        raise TypeError("Phase 6F requires Phase6FRenderRequest")
    error = _validate(request)
    if error is not None:return _failure(request, error, internal=error not in {RenderReasonCode.RENDERER_CAPABILITY_UNAVAILABLE})
    contract = request.renderer_context.contracts_by_plan_id.get(request.approved_plan.plan.plan_id)
    if contract is None:return _failure(request, RenderReasonCode.RENDERER_CONTRACT_MISSING, internal=True)
    if contract.plan_id != request.approved_plan.plan.plan_id:return _failure(request, RenderReasonCode.CONSTRAINT_CONTRACT_INCONSISTENT, internal=True)
    if not contract.required_features.issubset(request.target_environment.available_features):return _failure(request, RenderReasonCode.RENDERER_CAPABILITY_UNAVAILABLE, internal=False)
    return _render_contract(request, contract)


def render_final_selection_result(
    selection: FinalSelectionResult,
    *,
    target_environment: TargetEnvironment,
    renderer_context: RendererContext,
) -> RenderedReplacement:
    """Encode a Phase-6E final result without reopening candidate selection."""
    if not isinstance(selection, FinalSelectionResult):
        raise TypeError("Phase 6F requires FinalSelectionResult")
    if selection.kind is FinalSelectionKind.SELECTED:
        if selection.selected_plan is None:
            return RenderedReplacement(RenderedReplacementKind.INTERNAL_ERROR, None, None, (RenderReasonCode.SELECTION_RESULT_INCONSISTENT,), "", None, renderer_context.renderer_id, renderer_context.renderer_version)
        return render_approved_target_lowering(Phase6FRenderRequest(selection.selected_plan, target_environment, renderer_context))
    if selection.kind is FinalSelectionKind.KEEP:
        text = "/* translator: keep-original\n * source_fragment: " + renderer_context.source_fragment_id + "\n */"
        return RenderedReplacement(RenderedReplacementKind.KEEP_ANNOTATION, text, text, (), "", None, renderer_context.renderer_id, renderer_context.renderer_version)
    if selection.kind is FinalSelectionKind.UNSUPPORTED:
        code = selection.primary_reason_code or "phase6e.no_approved_plan"
        reasons = ", ".join((code,) + selection.secondary_reason_codes)
        text = "/* translator unsupported\n * codes: " + reasons + "\n * source_fragment: " + renderer_context.source_fragment_id + "\n */"
        return RenderedReplacement(RenderedReplacementKind.UNSUPPORTED_DIAGNOSTIC, text, text, (), "", None, renderer_context.renderer_id, renderer_context.renderer_version)
    return RenderedReplacement(RenderedReplacementKind.INTERNAL_ERROR, None, None, (RenderReasonCode.SELECTION_RESULT_INCONSISTENT,), "", None, renderer_context.renderer_id, renderer_context.renderer_version)
