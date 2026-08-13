from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from enum import Enum
import re
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

# 按工程实际路径调整。
from .schema import (
    AsmFragment,
    AsmOperand,
    AsmSymbolRef,
    MaterializedOperandBinding,
    OutputBinding,
    TranslationOutput,
)
from .pcode_ir import Block, IRSummary, StructuredSemanticTag
from .cfg import CFGResult, build_cfg_from_blocks

from .x86_att_integer_lowering import (
    lower_normalized_add_sub_to_x86_att,
    _fragment_outputs_as_tuple,
    _asm_operand_constraint_text,
    _asm_operand_has_early_clobber,

)
from .runtime_facts import (
    TranslationRuntimeFacts,
    canonicalize_riscv_register_name
)
from .semantic_types import (
    PreservationLevel,
    SemanticFeature,
    PreservationDecision,
)
from .source_model import build_source_semantic_model, SourceSemanticModel
from .candidate_plans import generate_candidate_plans
from .phase6c_constraints import (
    FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT,
    TargetConstraintDerivationResult,
    TargetEnvironment,
    derive_target_constraints,
)
from .phase6d_common import (
    CompilerCapabilityModel,
    HelperSemanticContractRegistry,
    SemanticProofResult,
    TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from .phase6e_selection import (
    FinalSelectionKind,
    Phase6ESelectionPolicy,
    Phase6ESelectionRequest,
    ProvenCandidate,
    select_final_target_lowering_plan,
)
from .phase6f_renderer import (
    CBinaryExpression, CExpressionRecipe, COperandRef, RendererContract,
    RendererContractKind,
    Phase6FRenderRequest,
    RenderedReplacementKind,
    RendererContext,
    render_final_selection_result,
)
from .phase6f_contract_registry import (
    GPR_INTEGER_RENDERER_CONTRACT_REGISTRY, RendererContractRegistry,
)
from .helper_runtime_manifest import DEFAULT_RUNTIME_HELPER_CONTRACTS, RUNTIME_HELPER_MANIFEST_VERSION
from .instruction_stream_sync_contracts import (
    INSTRUCTION_STREAM_SYNC_REGISTRY_VERSION,
    NOOP_ELISION_CONTRACT_ID,
    RUNTIME_LOCAL_SYNC,
)
from .plan_types import TargetLoweringKind, TargetLoweringPlan
# =============================================================================
# Translation context
# =============================================================================

@dataclass
class ShellSemantics:
    is_volatile: bool
    has_memory_clobber: bool
    has_cc_clobber: bool
    has_tied_operand: bool
    has_early_clobber: bool

    @property
    def prevents_generic_pure_c(self) -> bool:
        """
        Generic pure-C lowering 不能静默丢弃 GNU inline-asm shell semantics。

        某些专用公开接口策略可以在额外证明后绕过这一限制，但默认 pure-C
        策略不得绕过。
        """
        return (
            self.is_volatile
            or self.has_memory_clobber
            or self.has_cc_clobber
            or self.has_tied_operand
            or self.has_early_clobber
        )


@dataclass
class OperandBindingView:
    """
    translate 使用的 operand 绑定视图。

    rv_to_operand:
        物化后的 RISC-V register 名 -> GNU operand index。

    operands:
        outputs + inputs，与 assemble.materialize_template() 的编号规则一致。
    """

    operands: List[AsmOperand]
    rv_to_operand: Dict[str, int]
    operand_to_rv: Dict[int, List[str]]
    errors: List[str] = field(default_factory=list)

    def operand(self, index: int) -> Optional[AsmOperand]:
        if 0 <= index < len(self.operands):
            return self.operands[index]
        return None

    def expr(self, index: int) -> Optional[str]:
        operand = self.operand(index)

        if operand is None:
            return None

        text = (operand.exprText or "").strip()
        return text or None

@dataclass(frozen=True)
class ExplicitRvOperandBinding:
    """
    Binding consumed by the x86 normalized-p-code lowerer.

    expression is obtained only by resolving operandIndex against:
        fragment.outputs + fragment.inputs

    widthBits is supplied by AST/type-analysis runtime facts.
    """
    operandIndex: int
    role: str
    expression: str
    widthBits: int


@dataclass
class X86LoweringOperandBindingView:
    """
    normalized p-code -> x86 lowerer 使用的显式 binding view。

    rv_to_operand:
        RISC-V register -> ExplicitRvOperandBinding

    例如：

        {
            "a0": ExplicitRvOperandBinding(
                expression="result",
                widthBits=64,
            ),
            "a1": ExplicitRvOperandBinding(
                expression="a",
                widthBits=64,
            ),
        }

    此对象不从 outputs / inputs 的顺序推测寄存器映射。
    """

    rv_to_operand: Dict[str, ExplicitRvOperandBinding] = field(
        default_factory=dict
    )
    errors: List[str] = field(default_factory=list)
    

@dataclass
class TranslationContext:
    """
    Phase-6 translation context.

    This context intentionally exposes only authoritative structured
    representations to Phase-6 strategies:

      * Block / CanonicalInsn / Op / Var
      * CFGResult
      * IRSummary
      * assembler-normalization TranslationRuntimeFacts
      * fragment shell and validated operand metadata
      * Phase-6A SourceSemanticModel

    Raw LiftResult and raw LiftedInsn objects must not be retained in this
    context.  `lift_result` may be consumed at the translate() ingress
    boundary only for compatibility validation and diagnostics.

    Source semantic collection is centralized in Phase 6A:

        build_source_semantic_model(
            fragment,
            blocks,
            cfg,
            summary,
            runtime_facts,
            xlen,
        )

    Therefore later translation routes must not independently derive
    preservation classification by rescanning fragment, blocks, CFG, summary,
    or runtime facts.
    """

    fragment: AsmFragment
    blocks: List[Block]
    cfg: CFGResult
    summary: IRSummary
    machine_code: bytes
    xlen: int

    shell: ShellSemantics
    bindings: OperandBindingView

    # Mandatory authoritative object produced by Phase 4 assembler
    # normalization.  Do not provide a default empty object here.
    #
    # A missing TranslationRuntimeFacts object is a pipeline ingress failure,
    # not a normal route-selection condition.
    runtimeFacts: TranslationRuntimeFacts

    # Authoritative Phase-6A source semantic model.
    #
    # This is assigned by translate() immediately after _create_context().
    # Phase-6B through Phase-6F must consume semantic facts from this model
    # instead of independently rescanning source inputs.
    sourceModel: Optional["SourceSemanticModel"] = None

    # Transitional compatibility field.
    #
    # While legacy _translate_level_a/b/c/d() routes remain in use, this must
    # always equal:
    #
    #     context.sourceModel.preservation
    #
    # New Phase-6B-F code should prefer context.sourceModel.preservation
    # directly.  This field can be removed after legacy routing is retired.
    decision: Optional[PreservationDecision] = None

    @property
    def word_type(self) -> str:
        return "uint32_t" if self.xlen == 32 else "uint64_t"

    @property
    def signed_word_type(self) -> str:
        return "int32_t" if self.xlen == 32 else "int64_t"

    @property
    def word_bytes(self) -> int:
        return self.xlen // 8

    @property
    def mnemonics(self) -> List[str]:
        """
        Return canonical assembly mnemonics for diagnostics / metadata only.

        This property does not consult LiftResult, LiftedInsn, raw p-code
        text, textual p-code operands, or str(Operation).

        Phase-6 strategies must not use mnemonic strings as semantic evidence.
        They must use SourceSemanticModel, PreservationDecision, CFGResult,
        CanonicalInsn semantic fields, Op / Var dataflow facts, and explicit
        target constraint metadata.
        """
        result: List[str] = []

        for insn in _iter_structured_instructions(self.blocks):
            mnemonic = str(
                getattr(insn, "asm_mnem", "") or ""
            ).strip().lower()

            if mnemonic:
                result.append(mnemonic)

        return result

    @property
    def instruction_count(self) -> int:
        """
        Count instructions from authoritative structured canonical IR only.
        """
        return sum(
            1
            for _insn in _iter_structured_instructions(self.blocks)
        )

    @property
    def has_replacement_host_outputs(self) -> bool:
        return any(
            (op.exprText or "").strip()
            for op in self.fragment.outputs
        )

# =============================================================================
# Strategy result
# =============================================================================


@dataclass
class StrategyResult:
    matched: bool
    output: Optional[TranslationOutput] = None
    rejection_reasons: List[str] = field(default_factory=list)

    @classmethod
    def no_match(cls) -> "StrategyResult":
        return cls(False)

    @classmethod
    def rejected(cls, *reasons: str) -> "StrategyResult":
        return cls(
            matched=False,
            rejection_reasons=[reason for reason in reasons if reason],
        )

    @classmethod
    def success(cls, output: TranslationOutput) -> "StrategyResult":
        return cls(True, output=output)


TranslationStrategy = Callable[[TranslationContext], StrategyResult]


@dataclass(frozen=True)
class TargetLoweringAttempt:
    """Stable audit record for a 6C or 6D rejected concrete candidate."""
    plan_id: str
    stage: str
    reason_codes: tuple[str, ...]

    @classmethod
    def from_constraint_failure(
        cls, plan: TargetLoweringPlan, result: TargetConstraintDerivationResult
    ) -> "TargetLoweringAttempt":
        return cls(plan.plan_id, "phase6c", tuple(x.value for x in result.reason_codes))

    @classmethod
    def from_proof_failure(
        cls, plan: TargetLoweringPlan, proof: SemanticProofResult
    ) -> "TargetLoweringAttempt":
        return cls(plan.plan_id, "phase6d", tuple(x.value for x in proof.reason_codes))


# =============================================================================
# General helpers
# =============================================================================

def _iter_structured_instructions(
    blocks: Sequence[Block],
) -> Iterable[CanonicalInsn]:
    """
    Iterate authoritative CanonicalInsn objects from structured blocks.

    Phase-6 code must consume CanonicalInsn / Op / Var structured IR through
    this path, rather than reading LiftResult, LiftedInsn, raw p-code strings,
    or textual p-code operands.
    """
    for block_index, block in enumerate(blocks):
        instructions = getattr(block, "instructions", None)

        if instructions is None:
            raise ValueError(
                f"structured Block[{block_index}] has no 'instructions' field"
            )

        try:
            for instruction_index, insn in enumerate(instructions):
                if insn is None:
                    raise ValueError(
                        f"structured Block[{block_index}] contains None "
                        f"instruction at index {instruction_index}"
                    )

                yield insn

        except TypeError as exc:
            raise ValueError(
                f"structured Block[{block_index}].instructions is not iterable"
            ) from exc


_REGISTER_TOKEN_RE = re.compile(r"[^a-zA-Z0-9_.]+")

_STACK_REGISTERS = {
    "sp",
    "x2",
    "r2",
}

_FRAME_REGISTERS = {
    "fp",
    "s0",
    "x8",
    "r8",
}

_RETURN_ADDRESS_REGISTERS = {
    "ra",
    "x1",
    "r1",
}

_TIMING_MNEMONICS = {
    "rdcycle",
    "rdcycleh",
    "rdtime",
    "rdtimeh",
    "rdinstret",
    "rdinstreth",
}

_CACHE_MNEMONIC_PREFIXES = (
    "cbo.",
    "prefetch.",
)

_SPECULATION_MNEMONICS = {
    # 可继续按工程支持范围扩展。
    "pause",
}

_CALL_MNEMONICS = {
    "call",
    "jal",
    "jalr",
    "c.jal",
    "c.jalr",
}

_RETURN_MNEMONICS = {
    "ret",
    "mret",
    "sret",
    "uret",
}

_TAIL_CALL_MNEMONICS = {
    "tail",
}

_INDIRECT_CF_MNEMONICS = {
    "jr",
    "jalr",
    "c.jr",
    "c.jalr",
}

_NOP_MNEMONICS = {
    "nop",
    "c.nop",
}


def _normalize_register_name(value: Any) -> str:
    text = str(value or "").strip().lower()

    if not text:
        return ""

    # summary 中通常应直接保存寄存器名。这里仅做轻量兼容，不根据
    # p-code register offset 猜测架构寄存器。
    parts = [part for part in _REGISTER_TOKEN_RE.split(text) if part]

    if len(parts) == 1:
        return parts[0]

    for part in reversed(parts):
        if (
            part in _STACK_REGISTERS
            or part in _FRAME_REGISTERS
            or part in _RETURN_ADDRESS_REGISTERS
        ):
            return part

    return text


def _all_summary_registers(summary: IRSummary) -> Set[str]:
    registers: Set[str] = set()

    for value in set(summary.reads_regs or set()) | set(summary.writes_regs or set()):
        registers.add(_normalize_register_name(value))

    registers.discard("")
    return registers


def _get_clobbers(fragment: AsmFragment) -> Set[str]:
    return {
        str(clobber or "").strip().strip('"').lower()
        for clobber in fragment.clobbers
        if str(clobber or "").strip()
    }


def _build_shell_semantics(fragment: AsmFragment) -> ShellSemantics:
    operands = list(fragment.outputs) + list(fragment.inputs)
    clobbers = _get_clobbers(fragment)

    return ShellSemantics(
        is_volatile=bool(fragment.isVolatile),
        has_memory_clobber="memory" in clobbers,
        has_cc_clobber="cc" in clobbers,
        has_tied_operand=any(bool(op.isTied) for op in operands),
        has_early_clobber=any(bool(op.isEarlyClobber) for op in operands),
    )


def _build_operand_binding_view(
    fragment: AsmFragment,
    rv_to_operand_index: Mapping[str, int],
) -> OperandBindingView:
    """
    Build the translation operand view from assembler-normalization facts.

    Important:

      * rv_to_operand_index is authoritative.
      * fragment.materializedOperandBindings is intentionally not used as a
        source of RISC-V-register-to-GNU-operand mapping.
      * outputs + inputs are used only to resolve an already-proven GNU
        operand index to its host expression / role.
    """
    operands = list(fragment.outputs) + list(fragment.inputs)

    rv_to_operand: Dict[str, int] = {}
    operand_to_rv: Dict[int, List[str]] = {}
    errors: List[str] = []

    if rv_to_operand_index is None:
        errors.append(
            "missing assembler-normalization RISC-V-register-to-GNU-operand "
            "bindings"
        )
        return OperandBindingView(
            operands=operands,
            rv_to_operand=rv_to_operand,
            operand_to_rv=operand_to_rv,
            errors=errors,
        )

    for raw_register, operand_index in rv_to_operand_index.items():
        rv_register = _normalize_register_name(raw_register)

        if not rv_register:
            errors.append(
                "assembler-normalization binding contains an empty "
                "RISC-V register name"
            )
            continue

        if (
            isinstance(operand_index, bool)
            or not isinstance(operand_index, int)
            or operand_index < 0
            or operand_index >= len(operands)
        ):
            errors.append(
                "assembler-normalization binding for "
                f"{rv_register!r} has invalid GNU operand index "
                f"{operand_index!r}"
            )
            continue

        previous = rv_to_operand.get(rv_register)

        if previous is not None and previous != operand_index:
            errors.append(
                f"assembler normalization bound RISC-V register "
                f"{rv_register!r} to both %{previous} and %{operand_index}"
            )
            continue

        rv_to_operand[rv_register] = operand_index
        operand_to_rv.setdefault(operand_index, []).append(rv_register)

    return OperandBindingView(
        operands=operands,
        rv_to_operand=rv_to_operand,
        operand_to_rv=operand_to_rv,
        errors=errors,
    )

def _build_x86_lowering_operand_binding_view(
    context: TranslationContext,
) -> X86LoweringOperandBindingView:
    """
    Build bindings consumed by normalized RISC-V ADD/SUB -> x86 AT&T lowering.

    The resulting binding has four independent facts:

      RISC-V register
          -> GNU operand index
          -> host expression text
          -> proven host widthBits

    Sources:

      * register -> operand index:
          assembler normalization runtime facts.

      * operand index -> expression:
          fragment.outputs + fragment.inputs.

      * operand index -> widthBits:
          host AST/type-analysis runtime facts.

    No width is inferred from XLEN, expression text, operand ordering, or
    p-code register ordering.
    """
    view = X86LoweringOperandBindingView()

    if context.bindings.errors:
        view.errors.extend(context.bindings.errors)

    runtime_facts = context.runtimeFacts

    if not runtime_facts.rv_to_operand_index:
        view.errors.append(
            "missing assembler-normalization "
            "RISC-V-register-to-GNU-operand bindings"
        )

    if not runtime_facts.operand_width_bits:
        view.errors.append(
            "missing host AST/type-analysis GNU operand width facts"
        )

    for rv_register, operand_index in context.bindings.rv_to_operand.items():
        operand = context.bindings.operand(operand_index)

        if operand is None:
            view.errors.append(
                f"RISC-V register {rv_register!r} resolves to missing "
                f"GNU operand %{operand_index}"
            )
            continue

        expression = (operand.exprText or "").strip()

        if not expression:
            view.errors.append(
                f"GNU operand %{operand_index} for RISC-V register "
                f"{rv_register!r} has no host expression text"
            )
            continue

        width_bits = runtime_facts.operand_width_bits.get(operand_index)

        if (
            isinstance(width_bits, bool)
            or not isinstance(width_bits, int)
            or width_bits <= 0
        ):
            view.errors.append(
                f"host AST/type analysis did not provide a valid widthBits "
                f"for GNU operand %{operand_index} "
                f"(RISC-V register {rv_register!r})"
            )
            continue

        role = (
            "output"
            if operand_index < len(context.fragment.outputs)
            else "input"
        )

        view.rv_to_operand[rv_register] = ExplicitRvOperandBinding(
            operandIndex=operand_index,
            role=role,
            expression=expression,
            widthBits=width_bits,
        )

    return view

def _instruction_addresses_are_valid(instructions: Sequence[Any]) -> Tuple[bool, str]:
    if not instructions:
        return False, "lift result contains no instructions"

    previous_end: Optional[int] = None

    for index, insn in enumerate(instructions):
        addr = getattr(insn, "addr", None)
        length = getattr(insn, "length", None)

        if isinstance(addr, bool) or not isinstance(addr, int):
            return False, f"lifted instruction[{index}] has invalid addr {addr!r}"

        if (
            isinstance(length, bool)
            or not isinstance(length, int)
            or length <= 0
        ):
            return False, (
                f"lifted instruction[{index}] has invalid length {length!r}"
            )

        if previous_end is not None and addr != previous_end:
            return False, (
                f"non-contiguous lifted instruction stream: expected 0x{previous_end:x}, "
                f"got 0x{addr:x}"
            )

        previous_end = addr + length

    return True, ""


def _output(
    *,
    kind: str,
    replacement: str,
    context: TranslationContext,
    route: str,
    notes: Optional[Iterable[str]] = None,
    reason_codes: Optional[Iterable[str]] = None,
    build_family: str = "",
    requires_build_check: bool = True,
    requires_block_proof: bool = False,
    requires_path_validation: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> TranslationOutput:
    decision = context.decision
    level = decision.level.value if decision is not None else ""

    merged_notes: List[str] = []

    if decision is not None:
        merged_notes.extend(decision.reasons)

    for note in notes or []:
        if note and note not in merged_notes:
            merged_notes.append(note)

    merged_reason_codes: List[str] = []

    if decision is not None:
        merged_reason_codes.extend(decision.reason_codes)

    for code in reason_codes or []:
        if code and code not in merged_reason_codes:
            merged_reason_codes.append(code)

    output_metadata: Dict[str, Any] = {
        "xlen": context.xlen,
        "instructionCount": context.instruction_count,
        "blockCount": len(context.blocks),
        "preservationFeatures": sorted(
            feature.value
            for feature in (
                decision.features if decision is not None else set()
            )
        ),
    }

    if metadata:
        output_metadata.update(metadata)

    return TranslationOutput(
        kind=kind,
        replacement=replacement,
        notes=merged_notes,
        preservationLevel=level,
        preservationRoute=route,
        buildFamily=build_family,
        reasonCodes=merged_reason_codes,
        requiresBuildCheck=requires_build_check,
        requiresBlockProof=requires_block_proof,
        requiresPathValidation=requires_path_validation,
        metadata=output_metadata,
    )


def _needs_route(
    context: TranslationContext,
    *,
    route: str,
    reason: str,
    reason_code: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> TranslationOutput:
    return _output(
        kind="needs_route",
        replacement="",
        context=context,
        route=route,
        notes=[reason],
        reason_codes=[reason_code],
        build_family="none",
        requires_build_check=False,
        requires_block_proof=True,
        requires_path_validation=(
            context.decision is not None
            and context.decision.level in {
                PreservationLevel.C,
                PreservationLevel.D,
            }
        ),
        metadata=metadata,
    )


def _unsupported(
    context: TranslationContext,
    *,
    reason: str,
    reason_code: str,
) -> TranslationOutput:
    return _output(
        kind="unsupported",
        replacement="",
        context=context,
        route="unsupported",
        notes=[reason],
        reason_codes=[reason_code],
        build_family=None,
        requires_build_check=False,
        requires_block_proof=False,
        metadata={
            "unsupportedReason": reason,
            "reasonCode": reason_code,
        },
    )


# =============================================================================
# Context construction
# =============================================================================
def _create_context(
    *,
    fragment: AsmFragment,
    lift_result: Any,
    summary: IRSummary,
    blocks: Sequence[Block],
    machine_code: bytes,
    xlen: int,
    cfg: Optional[CFGResult],
    runtime_facts: Optional[TranslationRuntimeFacts],
) -> Tuple[Optional[TranslationContext], Optional[str]]:
    """
    Validate translation ingress inputs and construct a Phase-6 context.

    This function is intentionally limited to:

      * public-boundary / compatibility validation of lift_result;
      * validation of canonical structured Block[];
      * construction or validation of CFGResult;
      * construction of shell and operand-binding views;
      * retention of authoritative Phase-4 TranslationRuntimeFacts.

    This function must not:

      * derive PreservationDecision;
      * classify source semantic features;
      * choose a target lowering plan;
      * infer target constraints for a candidate plan;
      * perform SemanticProofGate checks.

    Raw LiftResult is intentionally not retained in TranslationContext.
    """

    if xlen not in {32, 64}:
        return None, f"unsupported XLEN: {xlen!r}"

    # lift_result remains a public-boundary compatibility input.  It is not
    # retained in TranslationContext and is not semantic evidence for Phase 6.
    if lift_result is None:
        return None, "missing LiftResult"

    if not bool(getattr(lift_result, "ok", True)):
        error = str(getattr(lift_result, "error", "") or "lifting failed")
        return None, error

    # Raw lifted instructions are permitted only for ingress validation.
    # They must not escape into TranslationContext or later Phase-6 routes.
    lifted_instructions = list(
        getattr(lift_result, "insns", []) or []
    )

    valid, error = _instruction_addresses_are_valid(lifted_instructions)

    if not valid:
        return None, error

    if summary is None:
        return None, "missing authoritative p-code IRSummary"

    if runtime_facts is None:
        return None, (
            "missing TranslationRuntimeFacts; translation requires "
            "authoritative Phase 4 assembler-normalization facts"
        )

    try:
        block_list = list(blocks)
    except Exception as exc:
        return None, f"cannot iterate authoritative blocks: {exc}"

    if not block_list:
        return None, "empty authoritative block sequence"

    try:
        structured_instruction_count = sum(
            1
            for _insn in _iter_structured_instructions(block_list)
        )
    except ValueError as exc:
        return None, f"invalid authoritative structured IR: {exc}"

    if structured_instruction_count == 0:
        return None, (
            "authoritative structured IR contains no canonical instructions"
        )

    cfg_result = cfg if cfg is not None else build_cfg_from_blocks(block_list)

    if not cfg_result.ok:
        return None, f"CFG construction failed: {cfg_result.error}"

    # Do not create a fallback TranslationRuntimeFacts() object.
    #
    # Whether a particular target lowering plan has sufficient register /
    # operand / width facts is a Phase-6C / 6D plan-specific decision.
    facts = runtime_facts

    context = TranslationContext(
        fragment=fragment,
        blocks=block_list,
        cfg=cfg_result,
        summary=summary,
        machine_code=bytes(machine_code or b""),
        xlen=xlen,
        shell=_build_shell_semantics(fragment),
        bindings=_build_operand_binding_view(
            fragment,
            facts.rv_to_operand_index,
        ),
        runtimeFacts=facts,
    )

    return context, None

def _get_phase6a_decision(
    context: TranslationContext,
) -> Tuple[Optional[PreservationDecision], Optional[TranslationOutput]]:
    """
    Return the authoritative Phase-6A PreservationDecision.

    SourceSemanticModel.preservation is authoritative.

    context.decision exists only as a temporary compatibility bridge for
    legacy Level-A/B/C/D route functions and must always equal the decision
    carried by context.sourceModel.
    """
    source_model = context.sourceModel

    if source_model is None:
        return None, _unsupported(
            context,
            reason="missing Phase-6A SourceSemanticModel",
            reason_code="TR_MISSING_SOURCE_SEMANTIC_MODEL",
        )

    decision = source_model.preservation

    if context.decision is None:
        return None, _unsupported(
            context,
            reason=(
                "missing PreservationDecision derived from the Phase-6A "
                "SourceSemanticModel"
            ),
            reason_code="TR_MISSING_PRESERVATION_DECISION",
        )

    if context.decision != decision:
        return None, _unsupported(
            context,
            reason=(
                "TranslationContext preservation decision does not match "
                "the authoritative Phase-6A SourceSemanticModel"
            ),
            reason_code="TR_INCONSISTENT_PRESERVATION_DECISION",
        )

    return decision, None

# =============================================================================
# Preservation classification
# =============================================================================

def _cfg_terminator_kind(block: Block) -> str:
    """
    Return normalized structured CFG terminator kind.

    terminator_kind 是 CFG / structured IR 字段，而非 raw p-code text。
    本函数仅用于识别 CFG terminator 分类。
    """
    kind = getattr(block, "terminator_kind", None)

    if kind is None:
        return ""

    # 支持 Enum 风格 terminator_kind。
    enum_value = getattr(kind, "value", None)

    if isinstance(enum_value, str):
        return enum_value.strip().lower()

    if isinstance(kind, str):
        return kind.strip().lower()

    return ""

# =============================================================================
# Output-expression helpers
# =============================================================================


def _output_operand_expr(
    context: TranslationContext,
    output_index: int,
) -> Optional[str]:
    if output_index < 0 or output_index >= len(context.fragment.outputs):
        return None

    text = (context.fragment.outputs[output_index].exprText or "").strip()
    return text or None


def _render_output_assignment(
    context: TranslationContext,
    output_index: int,
    value_expression: str,
) -> Optional[str]:
    """
    当前 OutputBinding 数据只能完整表达部分输出回填形式。

    因此此函数仅接受能够证明为直接宿主表达式赋值的情况。复杂 sinkKind
    必须由后续专用回填策略处理，不能猜测。
    """
    target = _output_operand_expr(context, output_index)

    if not target:
        return None

    relevant = [
        binding
        for binding in context.fragment.outputBindings
        if binding.outputIndex == output_index
    ]

    for binding in relevant:
        sink_kind = str(binding.sinkKind or "").strip().lower()

        if sink_kind not in {
            "",
            "direct",
            "assign",
            "expression",
            "lvalue",
            "output_operand",
        }:
            return None

    return f"({target}) = ({value_expression});"


# =============================================================================
# Pure-C proof gate
# =============================================================================


@dataclass
class ProofResult:
    ok: bool
    failures: List[str] = field(default_factory=list)
    reason_codes: List[str] = field(default_factory=list)

    def reject(self, reason: str, reason_code: str) -> None:
        self.ok = False

        if reason not in self.failures:
            self.failures.append(reason)

        if reason_code not in self.reason_codes:
            self.reason_codes.append(reason_code)

def _semantic_proof_gate(
    context: TranslationContext,
    *,
    target_kind: str,
) -> ProofResult:
    """
    Transitional semantic proof gate.

    Source semantic facts are authoritative only in the Phase-6A
    SourceSemanticModel and its PreservationDecision.

    This function must not independently reconstruct preservation facts by
    rescanning:

      * IRSummary;
      * Block[];
      * CFGResult;
      * AsmFragment;
      * TranslationRuntimeFacts.

    It may still validate target-specific requirements, including:

      * materialized operand binding consistency;
      * pure-C shell representability;
      * target inline-asm constraints;
      * tied operand / early-clobber handling;
      * generated clobber and barrier preservation.

    Phase 6C / 6D will eventually replace this transitional gate with
    plan-specific TargetConstraintModel derivation plus a plan-specific
    SemanticProofGate.
    """
    result = ProofResult(ok=True)

    source_model = context.sourceModel

    if source_model is None:
        result.reject(
            "Phase-6A SourceSemanticModel was not constructed",
            "TR_MISSING_SOURCE_SEMANTIC_MODEL",
        )
        return result

    decision = source_model.preservation

    if context.decision is None:
        result.reject(
            "PreservationDecision was not attached to TranslationContext",
            "TR_NO_PRESERVATION_DECISION",
        )
        return result

    if context.decision != decision:
        result.reject(
            "TranslationContext decision differs from the authoritative "
            "Phase-6A SourceSemanticModel decision",
            "TR_INCONSISTENT_PRESERVATION_DECISION",
        )
        return result

    if decision.level != PreservationLevel.A:
        result.reject(
            f"{target_kind} generic lowering is forbidden for preservation "
            f"level {decision.level.value}",
            "TR_LEVEL_FORBIDDEN",
        )

    # The materialized binding view is a target-lowering input.  It is
    # legitimate to validate its internal consistency here; this is not
    # a second source-semantic scan.
    if target_kind == "pure_c" and context.bindings.errors:
        result.reject(
            "materialized operand bindings are inconsistent: "
            + "; ".join(context.bindings.errors),
            "TR_OPERAND_BINDING_INVALID",
        )

    if target_kind == "pure_c":
        # These are target-representation restrictions.  They do not
        # reclassify the source fragment; they reject a specific pure-C plan
        # that cannot prove preservation of the source shell semantics.
        if context.shell.is_volatile:
            result.reject(
                "generic pure-C lowering cannot preserve asm volatile semantics",
                "TR_PURE_C_VOLATILE",
            )

        if context.shell.has_memory_clobber:
            result.reject(
                'generic pure-C lowering cannot silently remove a "memory" '
                "clobber",
                "TR_PURE_C_MEMORY_CLOBBER",
            )

        if context.shell.has_cc_clobber:
            result.reject(
                'generic pure-C lowering cannot silently remove a "cc" '
                "clobber",
                "TR_PURE_C_CC_CLOBBER",
            )

        if context.shell.has_tied_operand:
            result.reject(
                "generic pure-C lowering requires an explicit tied-operand "
                "proof",
                "TR_PURE_C_TIED_OPERAND",
            )

        if context.shell.has_early_clobber:
            result.reject(
                "generic pure-C lowering requires an explicit early-clobber "
                "proof",
                "TR_PURE_C_EARLY_CLOBBER",
            )

    elif target_kind == "x86_inline_asm":
        """
        GNU x86 inline asm can represent early-clobber outputs through '&':

            "=&r"  write-only early-clobber output
            "+&r"  read-write early-clobber output

        Therefore early-clobber is not rejected merely because it exists.

        The concrete x86 lowering path remains responsible for proving that:

          * each source output maps to the correct GNU output operand;
          * tied source operands become '+' or matching-number constraints;
          * early-clobber source outputs become constraints containing '&';
          * memory and cc clobbers are retained where required;
          * operand width and register bindings match the selected x86 plan;
          * the generated AT&T assembly preserves the selected plan's
            architecture-level semantics.

        These are Phase-6C / 6D plan-specific checks.
        """
        pass

    else:
        result.reject(
            f"unsupported semantic proof target kind: {target_kind!r}",
            "TR_UNKNOWN_TARGET_KIND",
        )

    return result

# =============================================================================
# x86 normalized-p-code lowering compatibility helpers
# =============================================================================


def _field(obj: Any, *names: str, default: Any = None) -> Any:
    """
    统一读取 dataclass、普通对象或 JSON/dict 风格对象的字段。

    此函数仅用于 lowerer compatibility adapter；translate.py 的正常主路径
    仍以 AsmFragment / TranslationContext 的正式字段模型为准。
    """
    if obj is None:
        return default

    for name in names:
        if isinstance(obj, dict):
            if name in obj:
                return obj[name]
        elif hasattr(obj, name):
            return getattr(obj, name)

    return default


def _operand_role(fragment: AsmFragment, operand_index: int) -> Optional[str]:
    output_count = len(fragment.outputs)
    operand_count = output_count + len(fragment.inputs)

    if operand_index < 0 or operand_index >= operand_count:
        return None

    return "output" if operand_index < output_count else "input"


def _operand_expression(
    fragment: AsmFragment,
    operand_index: int,
) -> Optional[str]:
    operands = list(fragment.outputs) + list(fragment.inputs)

    if operand_index < 0 or operand_index >= len(operands):
        return None

    expression = str(operands[operand_index].exprText or "").strip()
    return expression or None


def _bindings_for_x86_lowering(
    context: Any,
) -> X86LoweringOperandBindingView:
    """
    Construct the validated x86-lowering operand binding view.

    Authoritative sources of truth:

        TranslationRuntimeFacts.rv_to_operand_index:
            canonical RISC-V register -> GNU operand index

        TranslationRuntimeFacts.operand_width_bits:
            GNU operand index -> host operand widthBits

        AsmFragment:
            GNU operand index -> host expression and operand role

    Safety rule:

    This function must never infer RISC-V register -> GNU operand index from:

        * p-code register encounter order;
        * p-code operand order;
        * fragment output/input order;
        * RISC-V xN numbering;
        * XLEN;
        * host expression text;
        * serialized fragment binding order.

    Important compatibility rule:

    context.bindings is intentionally ignored by this function.

    TranslationContext.bindings is a legacy/compatibility projection created by
    _build_operand_binding_view().  It must not be treated as authoritative by
    the x86 lowering path, and errors in that projection must not reject a
    translation whose TranslationRuntimeFacts are valid.

    The x86 lowering binding view is therefore built exclusively from:

        context.runtimeFacts
        context.fragment
    """
    errors: List[str] = []
    rv_to_operand: Dict[str, ExplicitRvOperandBinding] = {}

    facts = getattr(context, "runtimeFacts", None)

    if facts is None:
        return X86LoweringOperandBindingView(
            errors=[
                "missing TranslationRuntimeFacts; x86 lowering requires "
                "runtime RISC-V-register-to-GNU-operand bindings"
            ]
        )

    raw_fact_bindings = getattr(facts, "rv_to_operand_index", None)

    if not raw_fact_bindings:
        return X86LoweringOperandBindingView(
            errors=[
                "missing runtime RISC-V-register-to-GNU-operand bindings; "
                "normalized x86 ADD/SUB lowering must not infer bindings "
                "from operand order, p-code order, xN numbering, or XLEN"
            ]
        )

    operand_width_bits = getattr(facts, "operand_width_bits", None)

    if not operand_width_bits:
        return X86LoweringOperandBindingView(
            errors=[
                "missing runtime GNU-operand width facts; x86 lowering "
                "requires TranslationRuntimeFacts.operand_width_bits"
            ]
        )

    # ------------------------------------------------------------------
    # Step 1: normalize and validate authoritative runtime facts.
    #
    # No information from context.bindings is used here.  In particular,
    # legacy OperandBindingView errors must not reject x86 lowering.
    # ------------------------------------------------------------------
    normalized_fact_bindings: Dict[str, int] = {}

    for raw_register, operand_index in raw_fact_bindings.items():
        register = canonicalize_riscv_register_name(raw_register)

        if not register:
            errors.append(
                "runtime facts contain a non-RISC-V-GPR register binding: "
                f"{raw_register!r}"
            )
            continue

        if (
            isinstance(operand_index, bool)
            or not isinstance(operand_index, int)
            or operand_index < 0
        ):
            errors.append(
                "runtime facts contain an invalid GNU operand index: "
                f"register={raw_register!r}, "
                f"canonical_register={register!r}, "
                f"operand_index={operand_index!r}"
            )
            continue

        previous = normalized_fact_bindings.get(register)

        if previous is not None and previous != operand_index:
            errors.append(
                "runtime facts contain conflicting bindings after RISC-V "
                "register canonicalization: "
                f"canonical_register={register!r}, "
                f"first_operand_index={previous}, "
                f"second_operand_index={operand_index}"
            )
            continue

        normalized_fact_bindings[register] = operand_index

    # ------------------------------------------------------------------
    # Step 2: construct the actual x86-lowering view.
    #
    # Register -> operand index comes exclusively from runtime facts.
    # Fragment access is index-based only after the index is authoritative.
    # ------------------------------------------------------------------
    for register, operand_index in normalized_fact_bindings.items():
        role = _operand_role(context.fragment, operand_index)

        if role is None:
            errors.append(
                f"runtime facts binding for {register!r} refers to invalid "
                f"GNU operand index %{operand_index}"
            )
            continue

        expression = _operand_expression(context.fragment, operand_index)

        if expression is None:
            errors.append(
                f"GNU operand %{operand_index} for RISC-V register "
                f"{register!r} has no usable host expression"
            )
            continue

        width_bits = operand_width_bits.get(operand_index)

        if isinstance(width_bits, bool) or not isinstance(width_bits, int):
            errors.append(
                f"missing host AST/type-analysis widthBits for GNU operand "
                f"%{operand_index} ({register!r})"
            )
            continue

        if width_bits <= 0:
            errors.append(
                f"invalid host AST/type-analysis widthBits={width_bits!r} "
                f"for GNU operand %{operand_index} ({register!r})"
            )
            continue

        rv_to_operand[register] = ExplicitRvOperandBinding(
            operandIndex=operand_index,
            role=role,
            expression=expression,
            widthBits=width_bits,
        )

    if not rv_to_operand and not errors:
        errors.append(
            "runtime operand facts contain no usable RISC-V register bindings"
        )

    return X86LoweringOperandBindingView(
        rv_to_operand=rv_to_operand,
        errors=errors,
    )

class _X86LoweringContextView:
    """
    Read-only-ish view used only by x86 inline-asm lowering.

    It delegates all normal TranslationContext attributes to the original
    context, but replaces `bindings` with the validated authoritative
    X86LoweringOperandBindingView produced from TranslationRuntimeFacts.
    """

    def __init__(
        self,
        base_context: Any,
        bindings: X86LoweringOperandBindingView,
    ) -> None:
        self._base_context = base_context
        self.bindings = bindings

    def __getattr__(self, name: str) -> Any:
        return getattr(self._base_context, name)

def _make_x86_lowering_context(
    *,
    context: TranslationContext,
    bindings: X86LoweringOperandBindingView,
) -> Any:
    """
    Construct the only context object passed to x86 lowering.

    The lowering receives the original TranslationContext surface through
    delegation, but its bindings are replaced by the validated authoritative
    projection derived from TranslationRuntimeFacts.
    """
    return _X86LoweringContextView(
        base_context=context,
        bindings=bindings,
    )

# =============================================================================
# Dedicated strategies
# =============================================================================
_C_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_C_KEYWORDS = frozenset(
    {
        "alignas",
        "alignof",
        "auto",
        "bool",
        "break",
        "case",
        "char",
        "const",
        "constexpr",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "false",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "nullptr",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "static_assert",
        "struct",
        "switch",
        "thread_local",
        "true",
        "typedef",
        "typeof",
        "typeof_unqual",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "_Alignas",
        "_Alignof",
        "_Atomic",
        "_BitInt",
        "_Bool",
        "_Complex",
        "_Decimal128",
        "_Decimal32",
        "_Decimal64",
        "_Generic",
        "_Imaginary",
        "_Noreturn",
        "_Static_assert",
        "_Thread_local",
    }
)


def _is_safe_c_identifier(name: str) -> bool:
    """
    Return whether `name` is safe to interpolate as a C identifier.

    This is intentionally conservative.  Assembly-only symbol spellings such
    as foo@plt, foo.bar, or mangled/linker-specific names are not accepted as
    direct C source identifiers.
    """
    return bool(
        _C_IDENTIFIER_RE.fullmatch(name)
        and name not in _C_KEYWORDS
    )

def _single_instruction_has_structured_semantic_tag(
    context: TranslationContext,
    tag: StructuredSemanticTag,
) -> bool:
    """
    判断 fragment 是否恰好是一条具有指定 structured semantic tag 的指令。

    该函数：

      * 只读取 Block.instructions 中的 CanonicalInsn；
      * 不读取 context.mnemonics；
      * 不读取 CanonicalInsn.asm_mnem；
      * 不读取 CanonicalInsn.asm_body；
      * 不读取 raw LiftResult；
      * 不读取 raw p-code text；
      * 不调用 str(Op) / str(CanonicalInsn)。

    只有 canonicalizer / decoder 明确提供 tag 时才返回 True。
    缺少 tag 时 fail closed。
    """
    summary = context.summary

    if not summary.is_single_block:
        return False

    if len(context.blocks) != 1:
        return False

    block = context.blocks[0]

    if len(block.instructions) != 1:
        return False

    insn = block.instructions[0]

    return tag in insn.semantic_tags

def _has_unreconstructable_operand_surface(
    context: TranslationContext,
) -> bool:
    """
    Return True when replacing an asm statement with a no-operand statement
    would discard compiler-visible operand/constraint semantics.

    Dedicated no-operand strategies may use this to ensure they do not erase
    input evaluation, output assignment, tied constraints, or early-clobber
    constraints.
    """
    fragment = context.fragment
    shell = context.shell

    return bool(
        fragment.outputs
        or fragment.inputs
        or fragment.outputBindings
        or shell.has_tied_operand
        or shell.has_early_clobber
    )

def _try_pic_address_strategy(context: TranslationContext) -> StrategyResult:
    """
    仅处理可以严格证明为“获取单个符号地址”的最简单 PIC 形式。

    该策略故意保守：
      - 只允许一个 symbol；
      - 只允许一个 output；
      - 不允许 memory/call/branch/atomic；
      - symbol 必须有合法 C 名称；
      - output 必须能直接回填。
    """
    fragment = context.fragment
    summary = context.summary

    if (
        fragment.inputs
        or fragment.outputBindings
        or context.shell.is_volatile
        or context.shell.has_memory_clobber
        or context.shell.has_cc_clobber
        or context.shell.has_tied_operand
        or context.shell.has_early_clobber
    ):
        return StrategyResult.no_match()

    if len(fragment.symbols) != 1 or len(fragment.outputs) != 1:
        return StrategyResult.no_match()

    symbol = fragment.symbols[0]

    # cName may be emitted into C source.  asmName is only acceptable as a
    # fallback when it is also a strict C identifier.
    c_name = (symbol.cName or symbol.asmName or "").strip()

    if not c_name:
        return StrategyResult.rejected("PIC symbol has no usable C name")

    if not _is_safe_c_identifier(c_name):
        return StrategyResult.rejected(
            "PIC symbol name is not safe to emit as a C identifier: "
            + repr(c_name)
        )

    if (
        summary.has_branch
        or summary.has_call_or_return
        or summary.has_atomic
        or summary.reads_mem
        or summary.writes_mem
        or summary.has_memory_barrier
        or summary.has_instruction_barrier
    ):
        return StrategyResult.no_match()

    # addrTaken=False 可能表示符号值而非地址，不能猜测。
    if not symbol.addrTaken:
        return StrategyResult.rejected(
            "symbol reference is not explicitly marked address-taken"
        )

    assignment = _render_output_assignment(
        context,
        0,
        f"(uintptr_t)(&{c_name})",
    )

    if assignment is None:
        return StrategyResult.rejected(
            "PIC output cannot be represented as a direct host assignment"
        )

    output = _output(
        kind="pure_c",
        replacement=assignment,
        context=context,
        route="canonical_pic_public_c",
        notes=[
            f"replaced RISC-V address materialization with address of {c_name!r}",
        ],
        reason_codes=["TR_PIC_ADDRESS_TO_C"],
        build_family="c",
        requires_build_check=True,
        requires_block_proof=True,
        metadata={
            "requiredHeaders": ["stdint.h"],
            "symbol": c_name,
            "architectureSemanticsPreserved": True,
            "microarchitectureSemanticsPreserved": False,
        },
    )

    return StrategyResult.success(output)

def _barrier_strength(context: TranslationContext) -> Optional[str]:
    """
    将已恢复的 RISC-V memory fence 保守映射到 C11/GNU atomic order。

    当前选择 seq_cst 是有意的保守强化。它可以用于架构级同步语义，
    但不声称保持微架构实验效果。
    """
    summary = context.summary

    if not summary.has_memory_barrier:
        return None

    if summary.has_unknown_barrier:
        return None

    if summary.has_instruction_barrier:
        return None

    if not summary.barrier_infos:
        return None

    return "__ATOMIC_SEQ_CST"

def _try_architectural_memory_barrier(
    context: TranslationContext,
) -> StrategyResult:
    """
    Lower a proven non-atomic architectural RISC-V memory fence.

    This strategy intentionally refuses any asm fragment whose operand
    surface would be discarded by a no-operand fence replacement.
    """
    summary = context.summary
    shell = context.shell

    if not summary.has_memory_barrier:
        return StrategyResult.no_match()

    # An atomic fragment must be handled by a dedicated LR/SC or AMO route.
    # Do not allow the fence strategy to hide atomic semantics.
    if summary.has_atomic:
        return StrategyResult.no_match()

    if _has_unreconstructable_operand_surface(context):
        return StrategyResult.rejected(
            "memory-fence replacement would discard asm operand, tied-operand, "
            "or early-clobber semantics"
        )

    order = _barrier_strength(context)

    if order is None:
        return StrategyResult.rejected(
            "memory barrier semantics are incomplete or include fence.i"
        )

    if context.fragment.microarchSensitive:
        return StrategyResult.no_match()

    # A pure C atomic fence cannot preserve the compiler-visible volatile asm
    # surface or an explicit cc clobber.  Use inline asm in those cases.
    needs_inline_asm = bool(
        shell.is_volatile
        or shell.has_memory_clobber
        or shell.has_cc_clobber
    )

    if needs_inline_asm:
        clobbers = ['"memory"']

        # Preserve an explicit compiler-visible cc clobber if it existed in
        # the original asm shell.  Declaring an extra cc clobber is
        # conservative for the compiler.
        if shell.has_cc_clobber:
            clobbers.append('"cc"')

        replacement = (
            '__asm__ __volatile__("mfence" ::: '
            + ", ".join(clobbers)
            + ");"
        )

        output = _output(
            kind="x86_inline_asm",
            replacement=replacement,
            context=context,
            route="x86_architectural_memory_fence",
            notes=[
                "lowered architectural RISC-V memory fence to a conservative "
                "x86 mfence",
                "this route preserves architectural ordering but does not claim "
                "cross-ISA microarchitecture equivalence",
            ],
            reason_codes=["TR_MEMORY_FENCE_TO_X86_MFENCE"],
            build_family="x86_gnu_inline_asm",
            requires_build_check=True,
            requires_block_proof=True,
            metadata={
                "architectureSemanticsPreserved": True,
                "microarchitectureSemanticsPreserved": False,
                "requiredArchitecture": "x86",
                "usesVolatileInlineAsm": True,
                "clobbers": (
                    ["memory", "cc"]
                    if shell.has_cc_clobber
                    else ["memory"]
                ),
            },
        )

        return StrategyResult.success(output)

    replacement = f"__atomic_thread_fence({order});"

    output = _output(
        kind="builtin",
        replacement=replacement,
        context=context,
        route="public_atomic_thread_fence",
        notes=[
            "lowered RISC-V memory ordering to a conservative compiler atomic "
            "thread fence",
        ],
        reason_codes=["TR_MEMORY_FENCE_TO_ATOMIC_BUILTIN"],
        build_family="c",
        requires_build_check=True,
        requires_block_proof=True,
        metadata={
            "architectureSemanticsPreserved": True,
            "microarchitectureSemanticsPreserved": False,
        },
    )

    return StrategyResult.success(output)

def _try_nop(context: TranslationContext) -> StrategyResult:
    if not _single_instruction_has_structured_semantic_tag(
        context,
        StructuredSemanticTag.ARCHITECTURAL_NOP,
    ):
        return StrategyResult.no_match()

    # A volatile asm statement remains compiler-observable even when its
    # machine instruction is architecturally a NOP.  Replacing it with C void
    # expression would remove that observable asm execution surface.
    if context.shell.is_volatile:
        return StrategyResult.rejected(
            "NOP strategy does not erase a volatile asm statement"
        )

    if (
        context.fragment.outputs
        or context.fragment.inputs
        or context.fragment.outputBindings
    ):
        return StrategyResult.rejected(
            "NOP strategy does not remove asm operands because input "
            "evaluation and output-constraint semantics are not proven inert"
        )

    if (
        context.shell.has_memory_clobber
        or context.shell.has_cc_clobber
        or context.shell.has_tied_operand
        or context.shell.has_early_clobber
    ):
        return StrategyResult.rejected(
            "NOP strategy does not reconstruct asm clobber or operand "
            "constraint semantics"
        )

    if (
        context.summary.reads_mem
        or context.summary.writes_mem
        or context.summary.has_atomic
        or context.summary.has_branch
        or context.summary.has_call_or_return
        or context.summary.has_memory_barrier
        or context.summary.has_instruction_barrier
    ):
        return StrategyResult.rejected(
            "NOP mnemonic disagrees with p-code summary effects"
        )

    output = _output(
        kind="pure_c",
        replacement="((void)0);",
        context=context,
        route="canonical_noop",
        notes=["translated an effect-free non-volatile RISC-V NOP fragment"],
        reason_codes=["TR_NOP"],
        build_family="c",
        requires_build_check=True,
        requires_block_proof=True,
        metadata={
            "architectureSemanticsPreserved": True,
            "microarchitectureSemanticsPreserved": False,
        },
    )

    return StrategyResult.success(output)

def _try_experiment_preserving_x86(
    context: TranslationContext,
) -> StrategyResult:
    """
    D 级只实现可以明确解释的专用 x86 lowering。

    不能把 rdcycle 无条件替换为 rdtsc：
      - 频率和单位不同；
      - 序列化属性不同；
      - migration/virtualization 行为不同；
      - 实验校准方式不同。
    """
    shell = context.shell

    if not _single_instruction_has_structured_semantic_tag(
        context,
        StructuredSemanticTag.SPIN_WAIT_HINT,
    ):
        return StrategyResult.no_match()

    if _has_unreconstructable_operand_surface(context):
        return StrategyResult.rejected(
            "pause lowering would discard asm operand, tied-operand, or "
            "early-clobber semantics"
        )

    if (
        context.summary.reads_mem
        or context.summary.writes_mem
        or context.summary.has_branch
        or context.summary.has_call_or_return
        or context.summary.has_atomic
        or context.summary.has_memory_barrier
        or context.summary.has_instruction_barrier
    ):
        return StrategyResult.rejected(
            "pause mnemonic disagrees with p-code summary effects"
        )

    clobbers = ['"memory"']

    # Preserve an explicit compiler-visible condition-code clobber.
    if shell.has_cc_clobber:
        clobbers.append('"cc"')

    replacement = (
        '__asm__ __volatile__("pause" ::: '
        + ", ".join(clobbers)
        + ");"
    )

    output = _output(
        kind="x86_inline_asm",
        replacement=replacement,
        context=context,
        route="experiment_preserving_x86_pause",
        notes=[
            "mapped RISC-V pause/spin-loop hint to the x86 PAUSE instruction",
            "the generated instruction preserves spin-loop intent; exact "
            "cycle-level behavior still requires experimental validation",
        ],
        reason_codes=["TR_EXPERIMENT_X86_PAUSE"],
        build_family="x86_gnu_inline_asm",
        requires_build_check=True,
        requires_block_proof=True,
        requires_path_validation=True,
        metadata={
            "architectureSemanticsPreserved": True,
            "microarchitectureSemanticsPreserved": "best_effort",
            "requiresExperimentalValidation": True,
            "usesVolatileInlineAsm": True,
            "clobbers": (
                ["memory", "cc"]
                if shell.has_cc_clobber
                else ["memory"]
            ),
            "requiredArchitecture": "x86",
        },
    )

    return StrategyResult.success(output)

def _try_atomic_builtin(context: TranslationContext) -> StrategyResult:
    """
    Atomic placeholder gate.

    仅凭 IRSummary.has_atomic 和 mnemonic 集合无法可靠恢复：
      - address expression；
      - access width；
      - expected/desired；
      - LR/SC retry condition；
      - weak/strong CAS；
      - success/failure memory order；
      - observable retry behavior。

    因此这里不猜测。后续应在此位置接入基于规范化 Op/dataflow 的
    LR/SC CAS、LR/SC RMW 和 AMO 策略。
    """
    if not context.summary.has_atomic:
        return StrategyResult.no_match()

    return StrategyResult.rejected(
        "atomic semantics detected, but no proven LR/SC or AMO pattern matched"
    )

def _replacement_has_early_clobber_output_constraint(
    replacement: str,
) -> bool:
    """
    检查 generated GNU extended asm 是否含有 early-clobber output
    constraint，例如：

        "=&r"
        "+&r"
        "=&rm"
        "+&rm"

    GNU asm 中 output constraint 通常以 '=' 或 '+' 开始；
    '&' 表示 early-clobber。

    输入约束通常不应以 '=' 或 '+' 开头，因此该匹配可以避免把普通
    input constraint 中的字符误判为 early-clobber output。
    """
    if not isinstance(replacement, str) or not replacement.strip():
        return False

    return re.search(
        r'"[=+][^"]*&[^"]*"',
        replacement,
    ) is not None
    
def _try_generic_integer_x86_att_block(
    context: TranslationContext,
) -> StrategyResult:
    """
    Try lowering a proven normalized RV64 ADD/SUB p-code block into
    x86-64 GNU AT&T inline asm.

    Binding safety contract:

        RISC-V p-code register
            -> TranslationRuntimeFacts.rv_to_operand_index
            -> validated X86LoweringOperandBindingView
            -> GNU inline asm named operand

    No binding may be inferred from p-code ordering, operand ordering,
    RISC-V xN numbering, XLEN, or C expression text.
    """

    def _reject(*reasons: str) -> StrategyResult:
        """
        统一打印策略 rejection 原因。

        StrategyResult.rejection_reasons 仍然是正式的策略返回信息；
        print 仅用于当前 CLI 执行日志中的精确定位。
        """
        normalized_reasons = [
            str(reason)
            for reason in reasons
            if reason
        ]

        print(
            "[X86_ATT_REJECT]",
            {
                "fragment_type": getattr(
                    context,
                    "fragment_type",
                    type(getattr(context, "fragment", None)).__name__,
                ),
                "xlen": getattr(context, "xlen", None),
                "reasons": normalized_reasons,
            },
        )

        return StrategyResult.rejected(*normalized_reasons)

    print(
        "[DEBUG] enter _try_generic_integer_x86_att_block:",
        {
            "xlen": getattr(context, "xlen", None),
            "fragment_type": type(
                getattr(context, "fragment", None)
            ).__name__,
            "has_fragment": getattr(context, "fragment", None) is not None,
            "has_runtimeFacts": getattr(context, "runtimeFacts", None)
            is not None,
            "decision": repr(getattr(context, "decision", None)),
            "block_count": len(getattr(context, "blocks", []) or []),
        },
    )

    if context.xlen != 64:
        return _reject(
            "generic x86-64 AT&T integer lowering supports RV64 only; "
            f"got xlen={context.xlen}"
        )

    if context.decision is None:
        return _reject(
            "preservation classification was not performed"
        )

    if context.decision.level != PreservationLevel.A:
        return _reject(
            "generic x86 integer lowering is valid only for preservation "
            f"level A; got level={context.decision.level!r}"
        )

    proof = _semantic_proof_gate(
        context,
        target_kind="x86_inline_asm",
    )

    print(
        "[DEBUG] x86 AT&T semantic proof result:",
        {
            "ok": getattr(proof, "ok", None),
            "failures": getattr(proof, "failures", None),
        },
    )

    if not proof.ok:
        return _reject(*proof.failures)

    if context.shell.has_memory_clobber:
        return _reject(
            'generic x86 AT&T integer lowering does not yet emit a required '
            '"memory" clobber'
        )

    if getattr(context, "runtimeFacts", None) is None:
        return _reject(
            "x86 AT&T integer lowering requires TranslationRuntimeFacts"
        )

    # Build validated register -> source GNU operand binding projection.
    try:
        bindings = _bindings_for_x86_lowering(context)
    except Exception as exc:
        return _reject(
            "x86 runtime operand binding validation raised an exception: "
            f"{type(exc).__name__}: {exc}"
        )

    print(
        "[DEBUG] x86 validated operand bindings:",
        {
            "bindings_repr": repr(bindings),
            "errors": getattr(bindings, "errors", None),
            "binding_dict": getattr(bindings, "__dict__", None),
        },
    )

    if bindings.errors:
        return _reject(
            *[
                "x86 runtime operand binding validation failed: " + error
                for error in bindings.errors
            ]
        )

    x86_context = _make_x86_lowering_context(
        context=context,
        bindings=bindings,
    )

    print(
        "[DEBUG] constructed x86 lowering context:",
        {
            "type": type(x86_context).__name__,
            "dict": getattr(x86_context, "__dict__", None),
            "fragment_type": type(
                getattr(x86_context, "fragment", None)
            ).__name__,
            "fragment_outputs_type": type(
                getattr(
                    getattr(x86_context, "fragment", None),
                    "outputs",
                    None,
                )
            ).__name__,
            "fragment_outputs_repr": repr(
                getattr(
                    getattr(x86_context, "fragment", None),
                    "outputs",
                    None,
                )
            ),
        },
    )

    try:
        for block_index, block in enumerate(context.blocks):
            print(f"[DEBUG] block={block_index}, addr={block.addr:#x}")

            for op_index, op in enumerate(block.ops):
                output = op.output

                print(
                    "[DEBUG] op",
                    {
                        "block": block_index,
                        "op": op_index,
                        "opcode": op.opcode,
                        "output": {
                            "repr": repr(output),
                            "kind": getattr(output, "kind", None),
                            "name": getattr(output, "name", None),
                            "offset": getattr(output, "offset", None),
                            "size": getattr(output, "size", None),
                        } if output is not None else None,
                        "inputs": [
                            {
                                "repr": repr(var),
                                "kind": getattr(var, "kind", None),
                                "name": getattr(var, "name", None),
                                "offset": getattr(var, "offset", None),
                                "size": getattr(var, "size", None),
                            }
                            for var in op.inputs
                        ],
                    },
                )

        lowering = lower_normalized_add_sub_to_x86_att(x86_context)

    except Exception as exc:
        return _reject(
            "normalized ADD/SUB x86 lowerer raised an exception: "
            f"{type(exc).__name__}: {exc}"
        )

    print(
        "[DEBUG] normalized ADD/SUB x86 lowerer result:",
        {
            "matched": getattr(lowering, "matched", None),
            "error": getattr(lowering, "error", None),
            "replacement": getattr(lowering, "replacement", None),
            "lowering_repr": repr(lowering),
            "lowering_dict": getattr(lowering, "__dict__", None),
        },
    )

    if not lowering.matched:
        if lowering.error:
            return _reject(
                "normalized ADD/SUB x86 lowerer rejected block: "
                + lowering.error
            )

        return _reject(
            "normalized ADD/SUB x86 lowerer did not match this structured "
            "IR block"
        )

    replacement = lowering.replacement or ""

    if not replacement.strip():
        return _reject(
            "normalized ADD/SUB x86 lowerer matched but returned an empty "
            "inline-asm replacement"
        )

    print(
        "[DEBUG] x86 generated replacement:",
        replacement,
    )

    # Route contract:
    #
    # - generated x86 asm must preserve volatile semantics;
    # - generated x86 asm must explicitly declare condition-code clobbering.
    #
    # Do not trust metadata alone: inspect generated source text.
    if not re.search(
        r"\b(?:__asm__|asm)\s+(?:__volatile__|volatile)\b",
        replacement,
    ):
        return _reject(
            "normalized ADD/SUB x86 lowerer returned asm without a proven "
            "volatile qualifier"
        )

    if '"cc"' not in replacement:
        return _reject(
            'normalized ADD/SUB x86 lowerer returned asm without the '
            'required "cc" clobber'
        )

    # 读取 source fragment outputs。
    #
    # 不再假设 outputs 是 list，避免 tuple / AST wrapper 被误判。
    source_outputs, source_outputs_error = _fragment_outputs_as_tuple(context)

    if source_outputs_error is not None:
        return _reject(
            "cannot verify x86 output constraint preservation: "
            + source_outputs_error
        )

    assert source_outputs is not None

    print(
        "[DEBUG] source GNU asm outputs for verification:",
        {
            "count": len(source_outputs),
            "outputs_type": type(source_outputs).__name__,
            "outputs_repr": repr(source_outputs),
            "output_details": [
                {
                    "index": index,
                    "type": type(output).__name__,
                    "repr": repr(output),
                    "dict": getattr(output, "__dict__", None),
                    "constraint": _asm_operand_constraint_text(output),
                    "isEarlyClobber": getattr(
                        output,
                        "isEarlyClobber",
                        None,
                    ),
                    "is_early_clobber": getattr(
                        output,
                        "is_early_clobber",
                        None,
                    ),
                    "resolved_early_clobber": _asm_operand_has_early_clobber(
                        output
                    ),
                }
                for index, output in enumerate(source_outputs)
            ],
        },
    )

    if len(source_outputs) != 1:
        return _reject(
            "normalized ADD/SUB x86 lowerer succeeded, but source fragment "
            "does not have exactly one output operand; cannot verify GNU "
            "output constraint preservation: "
            f"source_output_count={len(source_outputs)}"
        )

    source_output = source_outputs[0]
    source_constraint = _asm_operand_constraint_text(source_output)
    source_has_early_clobber = _asm_operand_has_early_clobber(source_output)

    replacement_has_early_clobber = (
        _replacement_has_early_clobber_output_constraint(replacement)
    )

    print(
        "[DEBUG] early-clobber preservation verification:",
        {
            "source_constraint": source_constraint,
            "source_has_early_clobber": source_has_early_clobber,
            "replacement_has_early_clobber": (
                replacement_has_early_clobber
            ),
        },
    )

    if (
        source_has_early_clobber
        and not replacement_has_early_clobber
    ):
        return _reject(
            "source GNU inline asm has an early-clobber output constraint, "
            "but normalized ADD/SUB x86 lowering did not preserve it: "
            f"source_constraint={source_constraint!r}; "
            f"replacement={replacement!r}"
        )

    print(
        "[DEBUG] x86 AT&T generic integer lowering accepted:",
        {
            "source_constraint": source_constraint,
            "source_has_early_clobber": source_has_early_clobber,
            "replacement_has_early_clobber": (
                replacement_has_early_clobber
            ),
        },
    )

    return StrategyResult.success(
        _output(
            kind="x86_inline_asm_att",
            replacement=replacement,
            context=context,
            route="normalized_pcode_to_x86_att_integer",
            notes=[
                "lowered normalized RISC-V ADD/SUB structured p-code IR to "
                "x86-64 GNU AT&T inline asm",
                "lowering uses runtime-proven register-to-operand bindings "
                "and AST-proven host operand widths",
                "no register mapping or operand width was inferred from "
                "operand order, p-code order, expression text, xN numbering, "
                "or XLEN",
            ],
            reason_codes=[
                "TR_PCODE_INTEGER_TO_X86_ATT",
            ],
            build_family="x86_gnu_inline_asm",
            requires_build_check=True,
            requires_block_proof=True,
            metadata={
                "assemblySyntax": "att",
                "requiredArchitecture": "x86_64",
                "architectureSemanticsPreserved": True,
                "microarchitectureSemanticsPreserved": False,
                "requiresExperimentalValidation": False,
                "genericPureCAllowed": False,
                "normalizedPcodeLowering": True,
                "usesVolatileInlineAsm": True,
                "clobbers": ["cc", "rax"],
            },
        )
    )
# =============================================================================
# Level-specific dispatch
# =============================================================================


def _run_strategies(
    context: TranslationContext,
    strategies: Sequence[Callable[[TranslationContext], StrategyResult]],
) -> Tuple[Optional[TranslationOutput], List[str]]:
    rejected: List[str] = []

    for strategy in strategies:
        strategy_name = getattr(strategy, "__name__", repr(strategy))

        print(
            "[DEBUG] trying translation strategy:",
            strategy_name,
        )

        result = strategy(context)

        print(
            "[DEBUG] translation strategy result:",
            {
                "strategy": strategy_name,
                "matched": result.matched,
                "rejection_reasons": result.rejection_reasons,
                "has_output": result.output is not None,
            },
        )

        if result.matched:
            return result.output, rejected

        rejected.extend(result.rejection_reasons)

    return None, rejected

def _translate_level_a(context: TranslationContext) -> TranslationOutput:
    """
    Transitional legacy Level-A route.

    Source semantic classification must already have been performed by
    Phase 6A build_source_semantic_model().  This function must not rescan
    Block[], CFGResult, IRSummary, AsmFragment, or TranslationRuntimeFacts to
    derive preservation level or source semantic features.

    Level A permits only source fragments whose authoritative
    PreservationDecision is PreservationLevel.A.

    Current policy:

      1. Do not silently lower generic RISC-V integer p-code to ordinary
         pure C.
      2. For proven ADD/SUB data-dependency chains, permit x86-64 GNU AT&T
         inline asm lowering.
      3. If operand mapping, width, constraints, clobbers, CFG shape, or
         normalized p-code shape cannot be proven, return needs_route.
      4. needs_route is a valid scheduling result, never a silent fallback.
    """
    decision, failure = _get_phase6a_decision(context)

    if failure is not None:
        return failure

    assert decision is not None

    if decision.level != PreservationLevel.A:
        return _unsupported(
            context,
            reason=(
                "legacy Level-A route received a non-Level-A "
                f"PreservationDecision: {decision.level.value}"
            ),
            reason_code="TR_LEGACY_LEVEL_ROUTE_MISMATCH",
        )

    output, rejected = _run_strategies(
        context,
        [
            # Specialized semantics-aware strategies.
            _try_pic_address_strategy,
            _try_architectural_memory_barrier,
            _try_atomic_builtin,
            _try_nop,

            # Generic integer route: proven x86-64 AT&T GNU inline asm only.
            _try_generic_integer_x86_att_block,
        ],
    )

    if output is not None:
        return output

    return _needs_route(
        context,
        route="level_a_semantic_lowering_required",
        reason=(
            "no proven Level-A AT&T x86 translation strategy matched"
            + (f": {'; '.join(rejected)}" if rejected else "")
        ),
        reason_code="TR_LEVEL_A_NO_PROVEN_STRATEGY",
        metadata={
            "strategyRejections": rejected,
            "recommendedRoute": (
                "normalized-pcode x86-64 AT&T integer/memory/atomic lowering "
                "or target-specific x86 helper"
            ),
            "genericPureCAllowed": False,
            "requiredAssemblySyntax": "att",
            "architectureSemanticsPreserved": False,
            "microarchitectureSemanticsPreserved": False,
        },
    )

def _translate_level_b(context: TranslationContext) -> TranslationOutput:
    """
    Transitional legacy Level-B route.

    Level B is selected only by the authoritative Phase-6A
    PreservationDecision.  Stack/frame classification must not be repeated
    here by rescanning IRSummary or Block[].
    """
    decision, failure = _get_phase6a_decision(context)

    if failure is not None:
        return failure

    assert decision is not None

    if decision.level != PreservationLevel.B:
        return _unsupported(
            context,
            reason=(
                "legacy Level-B route received a non-Level-B "
                f"PreservationDecision: {decision.level.value}"
            ),
            reason_code="TR_LEGACY_LEVEL_ROUTE_MISMATCH",
        )

    return _needs_route(
        context,
        route="stack_aware_lowering",
        reason=(
            "fragment depends on RISC-V stack/frame state and requires an "
            "ABI-aware x86 lowering or function-level rewrite"
        ),
        reason_code="TR_STACK_AWARE_ROUTE_REQUIRED",
        metadata={
            "recommendedRoute": "x86 ABI-aware stack/frame lowering",
            "genericPureCAllowed": False,
            "preservationFeatures": sorted(
                feature.value
                for feature in decision.features
            ),
        },
    )

def _translate_level_c(context: TranslationContext) -> TranslationOutput:
    """
    Transitional legacy Level-C route.

    Control-flow classification is authoritative only in the Phase-6A
    SourceSemanticModel / PreservationDecision.  This function must not
    rescan AsmFragment, Block[], CFGResult, or IRSummary to independently
    re-classify asm-goto, indirect control flow, external flow, calls,
    returns, tail calls, or multiple exits.
    """
    decision, failure = _get_phase6a_decision(context)

    if failure is not None:
        return failure

    assert decision is not None

    if decision.level != PreservationLevel.C:
        return _unsupported(
            context,
            reason=(
                "legacy Level-C route received a non-Level-C "
                f"PreservationDecision: {decision.level.value}"
            ),
            reason_code="TR_LEGACY_LEVEL_ROUTE_MISMATCH",
        )

    features = decision.features

    # The labels themselves are shell metadata and may still be included in
    # diagnostics.  The semantic determination that this is asm-goto must
    # come from Phase-6A SemanticFeature.ASM_GOTO.
    if SemanticFeature.ASM_GOTO in features:
        return _needs_route(
            context,
            route="function_control_flow_rewrite",
            reason=(
                "asm goto requires host-function CFG rewriting; a local "
                "replacement string is insufficient"
            ),
            reason_code="TR_ASM_GOTO_FUNCTION_REWRITE",
            metadata={
                "gotoLabels": list(context.fragment.gotoLabels),
                "genericPureCAllowed": False,
                "preservationFeatures": sorted(
                    feature.value
                    for feature in features
                ),
            },
        )

    if SemanticFeature.INDIRECT_CONTROL_FLOW in features:
        return _needs_route(
            context,
            route="indirect_control_preserving_x86",
            reason=(
                "indirect control flow requires target and ABI recovery before "
                "x86 emission"
            ),
            reason_code="TR_INDIRECT_CONTROL_ROUTE_REQUIRED",
            metadata={
                "genericPureCAllowed": False,
                "preservationFeatures": sorted(
                    feature.value
                    for feature in features
                ),
            },
        )

    return _needs_route(
        context,
        route="control_preserving_lowering",
        reason=(
            "call/return/tail-call, internal branch, external control-flow, "
            "unknown-target, or multiple-exit semantics require a "
            "control-preserving x86 or function-level lowering"
        ),
        reason_code="TR_CONTROL_PRESERVING_ROUTE_REQUIRED",
        metadata={
            "genericPureCAllowed": False,

            # This is retained as diagnostics/shell metadata only.
            # It must not be used as a second source semantic classifier.
            "controlFlowSurface": context.fragment.controlFlowSurface,

            "preservationFeatures": sorted(
                feature.value
                for feature in features
            ),
            "preservationReasonCodes": list(decision.reason_codes),
        },
    )

def _translate_level_d(context: TranslationContext) -> TranslationOutput:
    """
    Transitional legacy Level-D route.

    Level-D microarchitecture-sensitive classification is derived only from
    the Phase-6A SourceSemanticModel / PreservationDecision.

    This route may invoke dedicated experiment-preserving strategies, but it
    must not independently rescan fragment, blocks, CFG, summary, or runtime
    facts to reconstruct microarchitecture sensitivity.
    """
    decision, failure = _get_phase6a_decision(context)

    if failure is not None:
        return failure

    assert decision is not None

    if decision.level != PreservationLevel.D:
        return _unsupported(
            context,
            reason=(
                "legacy Level-D route received a non-Level-D "
                f"PreservationDecision: {decision.level.value}"
            ),
            reason_code="TR_LEGACY_LEVEL_ROUTE_MISMATCH",
        )

    output, rejected = _run_strategies(
        context,
        [
            _try_experiment_preserving_x86,
        ],
    )

    if output is not None:
        return output

    return _needs_route(
        context,
        route="experiment_preserving_lowering",
        reason=(
            "microarchitecture-sensitive fragment has no proven x86 "
            "experiment-preserving strategy"
            + (f": {'; '.join(rejected)}" if rejected else "")
        ),
        reason_code="TR_EXPERIMENT_PRESERVING_ROUTE_REQUIRED",
        metadata={
            "strategyRejections": rejected,

            # These values originate from Phase 6A collection, not from a
            # second fragment / summary / block scan in this route.
            "microarchReasons": list(decision.reasons),
            "microarchReasonCodes": list(decision.reason_codes),
            "preservationFeatures": sorted(
                feature.value
                for feature in decision.features
            ),

            "architectureSemanticsPreserved": False,
            "microarchitectureSemanticsPreserved": False,
            "requiresExperimentalValidation": True,
            "genericPureCAllowed": False,
        },
    )

# =============================================================================
# Public entry
# =============================================================================
def _render_counter_csr_functional_fallback(
    *,
    context: TranslationContext,
    csr_name: str,
    result_operand_index: int,
    width_bits: int,
    target_environment: TargetEnvironment,
) -> TranslationOutput | None:
    """Render one explicitly approved *functional-only* counter adapter.

    This is deliberately separate from the normal Phase-6 proof pipeline.
    RISC-V counter CSRs are architecture-defined environment interfaces, and
    x86 ``rdtsc`` is not a strict replacement for their time domain.  A caller
    must opt in to this documented semantic downgrade.  The registry is keyed
    by structured Phase-6A CSR facts, never by an asm mnemonic or source text.

    ``time`` and ``cycle`` are the only 64-bit counter families currently
    registered.  ``instret`` has no matching x86 counter contract, while the
    high-half RV32 CSRs need a separate width/rollover contract.  Returning
    ``None`` preserves fail-closed routing for every unregistered family.
    """
    if (csr_name not in {"time", "cycle"} or width_bits != 64 or
            target_environment.architecture.value != "x86_64" or
            "x86:rdtsc" not in target_environment.available_features or
            "compiler:x86-rdtsc-builtin" not in target_environment.builtin_capabilities):
        return None

    binding = _output_operand_expr(context, result_operand_index)
    if not binding:
        return None

    source_contract = f"riscv.readonly-counter-csr.{csr_name}.u64.v1"
    target_contract = "x86.builtin.rdtsc.u64.v1"
    replacement = f"{binding} = (uint64_t)__builtin_ia32_rdtsc();"
    artifact = {
        "artifactVersion": "phase6-functional-fallback-v1",
        "proofStatus": "functional_approved",
        "functionalFallbackEnabled": True,
        "preservationMode": "functional_equivalence_only",
        "sourceSemanticContractId": source_contract,
        "targetSemanticContractId": target_contract,
        "sourceFragmentId": context.fragment.id,
        "sourceModelId": "phase6a:" + context.fragment.id,
        "preservationDecisionId": (
            "phase6a-functional-fallback:" + context.fragment.id
        ),
        "planId": "functional-fallback:" + source_contract,
        "constraintsId": "functional-fallback:x86-rdtsc-u64",
        "targetEnvironmentId": "phase6:" + ":".join((
            target_environment.architecture.value,
            target_environment.abi.value,
            target_environment.asm_dialect.value,
            target_environment.compiler_family,
            target_environment.compiler_version,
        )),
        "targetCatalogVersion": "functional-counter-registry-v1",
        "selectionPolicyId": "explicit-functional-fallback",
        "selectionPolicyVersion": "v1",
        "selectionTier": "functional_fallback",
        "rendererId": "x86-rdtsc-builtin-renderer",
        "rendererVersion": "v1",
        "replacementKind": "c_builtin",
        "replacementDigest": _approval_digest(replacement),
        "sourceSliceDigest": "",
    }
    return _output(
        kind="functional_c",
        replacement=replacement,
        context=context,
        route="explicit_functional_counter_fallback",
        notes=[
            f"functional fallback enabled: RISC-V {csr_name} CSR is rendered "
            "through the registered x86 rdtsc counter adapter; architecture "
            "time-domain equivalence is intentionally not claimed"
        ],
        reason_codes=["TR_FUNCTIONAL_COUNTER_CSR_FALLBACK"],
        build_family="x86_gnu_c_builtin",
        requires_build_check=True,
        metadata={"approvalArtifact": artifact},
    )


def _instruction_stream_environment_id(environment: TargetEnvironment) -> str:
    return "phase6:" + ":".join((
        environment.architecture.value,
        environment.abi.value,
        environment.asm_dialect.value,
        environment.compiler_family,
        environment.compiler_version,
    ))


def _render_instruction_stream_noop_elision(
    *, context: TranslationContext, source_model: SourceSemanticModel,
    target_environment: TargetEnvironment,
) -> TranslationOutput | None:
    """Render only an externally certified, semantically unobservable fence.

    The certificate comes through Phase-4 runtime facts and is recorded in the
    Phase-6A source model.  This function does not establish absence of code
    writes or execution itself, and therefore cannot turn an ordinary
    ``fence.i`` into a no-op.
    """
    memory = source_model.memory
    if (not memory.instruction_stream_sync_noop_proven or
            not memory.instruction_stream_sync_proof_id):
        return None
    replacement = (
        "/* translator: instruction-stream synchronization elided; "
        f"proof={memory.instruction_stream_sync_proof_id} */"
    )
    artifact = {
        "artifactVersion": "phase6-approval-v1",
        "proofStatus": "approved",
        "preservationMode": "architecture_equivalent",
        "sourceSemanticContractId": "riscv.instruction-stream-sync.v1",
        "targetSemanticContractId": NOOP_ELISION_CONTRACT_ID,
        "sourceFragmentId": context.fragment.id,
        "sourceModelId": "phase6a:" + context.fragment.id,
        "preservationDecisionId": "phase6a:" + memory.instruction_stream_sync_proof_id,
        "planId": "phase6f:" + NOOP_ELISION_CONTRACT_ID,
        "constraintsId": "phase6c:" + NOOP_ELISION_CONTRACT_ID,
        "targetEnvironmentId": _instruction_stream_environment_id(target_environment),
        "targetCatalogVersion": INSTRUCTION_STREAM_SYNC_REGISTRY_VERSION,
        "selectionPolicyId": "proof-gated-instruction-stream-sync",
        "selectionPolicyVersion": "v1",
        "selectionTier": "strict_noop_elision",
        "rendererId": "instruction-stream-sync-elision-renderer",
        "rendererVersion": "v1",
        "replacementKind": "instruction_stream_elision",
        "replacementDigest": _approval_digest(replacement),
        "sourceSliceDigest": "",
        "instructionStreamSyncProofId": memory.instruction_stream_sync_proof_id,
    }
    return _output(
        kind="instruction_stream_elision", replacement=replacement,
        context=context, route="approved_instruction_stream_noop_elision",
        notes=[
            "instruction-stream synchronization was elided only because an "
            "authoritative no-observable-effect proof certificate was supplied"
        ],
        reason_codes=["TR_INSTRUCTION_STREAM_SYNC_NOOP_ELIDED"],
        build_family="x86_gnu_c", requires_build_check=True,
        metadata={"approvalArtifact": artifact},
    )


def _render_instruction_stream_functional_helper(
    *, context: TranslationContext, target_environment: TargetEnvironment,
) -> TranslationOutput | None:
    """Render the registered local-thread synchronization helper on opt-in.

    This is a functional fallback, never an architecture-equivalence claim.
    The helper contains the x86 serializing operation behind a versioned ABI;
    the renderer itself does not manufacture CPUID/LFENCE/MFENCE asm.
    """
    contract = RUNTIME_LOCAL_SYNC
    if (target_environment.architecture.value != "x86_64" or
            contract.required_environment_capability not in
            target_environment.helper_contract_capabilities):
        return None
    replacement = contract.helper_symbol + "();"
    artifact = {
        "artifactVersion": "phase6-functional-fallback-v1",
        "proofStatus": "functional_approved",
        "functionalFallbackEnabled": True,
        "preservationMode": contract.preservation_mode,
        "sourceSemanticContractId": contract.source_semantic_contract_id,
        "targetSemanticContractId": contract.target_semantic_contract_id,
        "sourceFragmentId": context.fragment.id,
        "sourceModelId": "phase6a:" + context.fragment.id,
        "preservationDecisionId": "phase6a-functional-instruction-stream:" + context.fragment.id,
        "planId": "functional-fallback:" + contract.semantic_contract_id,
        "constraintsId": "functional-helper:" + contract.semantic_contract_id,
        "targetEnvironmentId": _instruction_stream_environment_id(target_environment),
        "targetCatalogVersion": INSTRUCTION_STREAM_SYNC_REGISTRY_VERSION,
        "selectionPolicyId": "explicit-functional-fallback",
        "selectionPolicyVersion": "v1",
        "selectionTier": "functional_runtime_helper",
        "rendererId": "instruction-stream-sync-helper-renderer",
        "rendererVersion": "v1",
        "replacementKind": "helper_call",
        "replacementDigest": _approval_digest(replacement),
        "sourceSliceDigest": "",
        "helperRuntimeContractId": contract.semantic_contract_id,
        "helperSemanticVersion": "v1",
        "helperRequiredHeader": contract.required_header,
        "helperRuntimeLibrary": contract.runtime_library,
        "helperRuntimeManifestVersion": RUNTIME_HELPER_MANIFEST_VERSION,
    }
    return _output(
        kind="functional_c", replacement=replacement, context=context,
        route="explicit_functional_instruction_stream_sync_helper",
        notes=[
            "functional fallback enabled: instruction-stream synchronization "
            "uses the registered local-thread x86 runtime helper; cross-thread "
            "code publication is not claimed"
        ],
        reason_codes=["TR_FUNCTIONAL_INSTRUCTION_STREAM_SYNC_HELPER"],
        build_family="x86_runtime_helper", requires_build_check=True,
        metadata={"approvalArtifact": artifact},
    )


def translate(
    frag: AsmFragment,
    lift: Any,
    summary: IRSummary,
    machine_code: bytes,
    xlen: int,
    blocks: Optional[Sequence[Block]] = None,
    cfg: Optional[CFGResult] = None,
    runtime_facts: Optional[TranslationRuntimeFacts] = None,
    target_environment: TargetEnvironment = FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT,
    target_semantic_catalog: Optional[TargetSemanticCatalog] = None,
    compiler_capabilities: Optional[CompilerCapabilityModel] = None,
    helper_contract_registry: Optional[HelperSemanticContractRegistry] = None,
    selection_policy: Phase6ESelectionPolicy = Phase6ESelectionPolicy(),
    renderer_context: Optional[RendererContext] = None,
    renderer_contract_registry: RendererContractRegistry = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY,
    allow_functional_fallbacks: bool = False,
) -> TranslationOutput:
    """
    Phase 6 / 7 translation entry.

    Authoritative Phase-6 source-semantic inputs:

        AsmFragment
        + canonical structured Block sequence
        + CFGResult built from canonical blocks
        + IRSummary derived from canonical blocks
        + TranslationRuntimeFacts from Phase 4 assembler normalization

    `lift` remains at this public boundary only for compatibility with the
    existing pipeline and for failure diagnostics.  It is not authoritative
    semantic evidence for Phase 6.

    Phase-6 source semantic collection must be centralized in
    build_source_semantic_model().  TranslationContext and later Phase-6
    stages must not recover semantic facts from raw LiftResult, LiftedInsn,
    rendered p-code text, textual p-code operands, or str(Operation).

    TranslationRuntimeFacts is a mandatory authoritative pipeline input.
    However, the availability of particular facts, such as GNU operand
    bindings or host operand widths, is plan-specific and must be evaluated
    later by Phase 6C / 6D rather than rejected globally at this entry.
    """

    # ------------------------------------------------------------------
    # Phase-6 ingress validation: authoritative canonical Block[] is
    # mandatory.  No fallback to raw lift output is permitted.
    # ------------------------------------------------------------------
    if blocks is None:
        dummy_context = _minimal_failure_context(
            frag=frag,
            lift=lift,
            summary=summary,
            machine_code=machine_code,
            xlen=xlen,
        )

        return _unsupported(
            dummy_context,
            reason=(
                "translate requires the authoritative canonical Block "
                "sequence returned by pcode_ir.from_lifted()"
            ),
            reason_code="TR_MISSING_AUTHORITATIVE_BLOCKS",
        )

    # ------------------------------------------------------------------
    # Phase-6 ingress validation: the runtime-facts object itself must
    # originate from Phase 4 assembler normalization.
    #
    # Do not replace None with TranslationRuntimeFacts().  Such fallback
    # would turn a pipeline integration error into a normal route/proof
    # failure and could permit unsafe lowering decisions.
    #
    # Do not require rv_to_operand_index or operand_width_bits to be
    # non-empty here.  Their adequacy is specific to a later candidate plan.
    # ------------------------------------------------------------------
    if runtime_facts is None:
        dummy_context = _minimal_failure_context(
            frag=frag,
            lift=lift,
            summary=summary,
            machine_code=machine_code,
            xlen=xlen,
        )

        return _unsupported(
            dummy_context,
            reason=(
                "translate requires authoritative TranslationRuntimeFacts "
                "from Phase 4 assembler normalization"
            ),
            reason_code="TR_MISSING_TRANSLATION_RUNTIME_FACTS",
        )

    # ------------------------------------------------------------------
    # Build the ordinary translation context.  This validates structured
    # input consistency and constructs or validates the canonical CFG.
    # ------------------------------------------------------------------
    context, error = _create_context(
        fragment=frag,
        lift_result=lift,
        summary=summary,
        blocks=blocks,
        machine_code=machine_code,
        xlen=xlen,
        cfg=cfg,

        # Must be the authoritative object from Phase 4.
        # Never use: runtime_facts or TranslationRuntimeFacts().
        runtime_facts=runtime_facts,
    )

    if context is None:
        fallback_context = _minimal_failure_context(
            frag=frag,
            lift=lift,
            summary=summary,
            machine_code=machine_code,
            xlen=xlen,
        )

        return _unsupported(
            fallback_context,
            reason=f"invalid translate input: {error}",
            reason_code="TR_INVALID_TRANSLATION_INPUT",
        )

    # ------------------------------------------------------------------
    # Phase 6A: this is the sole source-semantic collection point.
    #
    # The builder consumes only authoritative structured inputs and creates:
    #
    #   SourceSemanticModel
    #       └─ PreservationDecision
    #
    # No later Phase-6 component may independently re-classify source
    # semantics by rescanning AsmFragment / Block[] / CFGResult / IRSummary /
    # TranslationRuntimeFacts.
    # ------------------------------------------------------------------
    try:
        source_model = build_source_semantic_model(
            fragment=context.fragment,
            blocks=context.blocks,
            cfg=context.cfg,
            summary=context.summary,
            runtime_facts=context.runtimeFacts,
            xlen=context.xlen,
        )
    except ValueError as exc:
        return _unsupported(
            context,
            reason=f"cannot build Phase-6A SourceSemanticModel: {exc}",
            reason_code="TR_SOURCE_SEMANTIC_MODEL_FAILURE",
        )

    context.sourceModel = source_model
    context.decision = source_model.preservation

    # A RISC-V counter CSR is an environment-defined architectural source,
    # not an unbound integer register and not a portable x86 timer synonym.
    # Phase 6A recognized this from canonical register varnodes; do not let
    # later phases reinterpret the original asm or substitute rdtsc/clock().
    # A target deployment must explicitly register a versioned runtime time
    # domain contract before this family becomes renderable.
    if source_model.read_only_csr is not None:
        csr = source_model.read_only_csr
        if allow_functional_fallbacks:
            fallback = _render_counter_csr_functional_fallback(
                context=context,
                csr_name=csr.csr_name,
                result_operand_index=csr.result_operand_index,
                width_bits=csr.width_bits,
                target_environment=target_environment,
            )
            if fallback is not None:
                return fallback
        return _needs_route(
            context,
            route="riscv_counter_csr_runtime_adapter",
            reason=(
                f"RISC-V read-only counter CSR '{csr.csr_name}' requires an "
                "explicit target runtime time-domain contract; no implicit "
                "x86 timer or C clock substitute is permitted"
            ),
            reason_code="TR_CSR_COUNTER_RUNTIME_CONTRACT_REQUIRED",
            metadata={
                "csrName": csr.csr_name,
                "resultOperandIndex": csr.result_operand_index,
                "widthBits": csr.width_bits,
                "requiredRuntimeContractFamily": "riscv.readonly-counter-csr",
            },
        )

    # Instruction-stream synchronization is an independently modelled source
    # semantic family.  It is not a memory-ordering fence: in particular,
    # RISC-V ``fence.i`` must not be lowered to ``mfence``, an empty volatile
    # asm statement, or a generic compiler barrier.  Until a target-specific,
    # versioned instruction-stream contract (including code-write scope and
    # CPU/compiler capability) is registered and proved, preserve this as a
    # structured route request rather than reporting it as an opaque failure.
    #
    # The condition consumes only the Phase-6A model, so every instruction
    # family which the lifter classifies as an instruction barrier takes the
    # same fail-closed path without looking at source asm text or mnemonics.
    if source_model.memory.has_instruction_barrier:
        elided = _render_instruction_stream_noop_elision(
            context=context, source_model=source_model,
            target_environment=target_environment,
        )
        if elided is not None:
            return elided
        if allow_functional_fallbacks:
            helper = _render_instruction_stream_functional_helper(
                context=context, target_environment=target_environment,
            )
            if helper is not None:
                return helper
        return _needs_route(
            context,
            route="instruction_stream_synchronization_adapter",
            reason=(
                "source requires instruction-stream synchronization; no "
                "registered x86 target contract may be inferred from a "
                "memory fence or compiler barrier"
            ),
            reason_code="TR_INSTRUCTION_STREAM_SYNC_RUNTIME_CONTRACT_REQUIRED",
            metadata={
                "requiredRuntimeContractFamily": (
                    "instruction-stream-synchronization"
                ),
                "sourceBarrierKind": "instruction_stream",
                "functionalFallbackPermitted": True,
                "functionalFallbackContract": RUNTIME_LOCAL_SYNC.semantic_contract_id,
                "noopElisionContract": NOOP_ELISION_CONTRACT_ID,
            },
        )

    return _translate_phase6_proof_pipeline(
        context=context,
        target_environment=target_environment,
        target_semantic_catalog=target_semantic_catalog,
        compiler_capabilities=compiler_capabilities,
        helper_contract_registry=helper_contract_registry,
        selection_policy=selection_policy,
        renderer_context=renderer_context,
        renderer_contract_registry=renderer_contract_registry,
    )


def _translate_phase6_proof_pipeline(
    *,
    context: TranslationContext,
    target_environment: TargetEnvironment,
    target_semantic_catalog: Optional[TargetSemanticCatalog],
    compiler_capabilities: Optional[CompilerCapabilityModel],
    helper_contract_registry: Optional[HelperSemanticContractRegistry],
    selection_policy: Phase6ESelectionPolicy,
    renderer_context: Optional[RendererContext],
    renderer_contract_registry: RendererContractRegistry,
) -> TranslationOutput:
    """Execute 6B--6F without a legacy or guessed-code fallback path."""
    source_model = context.sourceModel
    if source_model is None or context.decision != source_model.preservation:
        return _unsupported(context, reason="Phase-6A source model/decision binding is unavailable", reason_code="TR_PHASE6A_ARTIFACT_INCONSISTENT")
    if not isinstance(target_environment, TargetEnvironment):
        return _unsupported(context, reason="target environment is not a structured TargetEnvironment", reason_code="TR_INVALID_TARGET_ENVIRONMENT")
    if not isinstance(selection_policy, Phase6ESelectionPolicy):
        return _unsupported(context, reason="selection policy is invalid", reason_code="TR_INVALID_PHASE6E_SELECTION_POLICY")

    catalog = target_semantic_catalog or TargetSemanticCatalog(
        supported_plan_kinds=frozenset(TargetLoweringKind),
        semantic_contract_ids=frozenset({
            "x86.gnu-att.gpr.out-gpr-immediate-binary.v1",
            "x86.gnu-att.gpr.out-gpr-gpr-binary.v1",
            "x86.gnu-att.gpr.rw-gpr-binary.v1",
            "x86.gnu-att.gpr.rw-immediate-binary.v1",
            "x86.gnu-att.gpr.rw-early-clobber-binary.v1",
            "x86.gnu-att.gpr.add-then-shl-imm.u32-u64.early-clobber.v1",
            "x86.gnu-att.gpr.straight-line-u32-u64.v1",
            "x86.gnu-att.gpr.out-gpr-variable-shift.u32-u64.v1",
            "x86.gnu-att.gpr.out-gpr-boolean-compare.u32-u64.v1",
            "x86.gnu-att.local-branch-select.compare.u32-u64.v1",
            "x86.gnu-att.local-unconditional-jump.copy.u32-u64.v1",
            "c.builtin.atomic-load-n.u32-u64.v1",
            "c.builtin.atomic-store-n.u32-u64.v1",
            "c.builtin.atomic-signal-fence.compiler-barrier.seq-cst.v1",
            "x86.gnu-att.atomic.lock-xadd.u32-u64.seq-cst.v1",
            "x86.gnu-att.atomic.xchg.u32-u64.seq-cst.v1",
            "x86.gnu-att.mfence.full-system-seq-cst.v1",
            "x86.gnu-att.serialize.instruction-serialization.v1",
            "x86.gnu-att.memory.load.gpr-address.u32.v1",
            "x86.gnu-att.memory.load.gpr-address.u64.v1",
            "x86.gnu-att.memory.load.gpr-address-disp32.u32.v1",
            "x86.gnu-att.memory.load.gpr-address-disp32.u64.v1",
            "x86.gnu-att.memory.store.gpr-address.u32.v1",
            "x86.gnu-att.memory.store.gpr-address.u64.v1",
            "x86.gnu-att.memory.store.gpr-address-disp32.u32.v1",
            "x86.gnu-att.memory.store.gpr-address-disp32.u64.v1",
            "x86.gnu-att.asm-goto.bzero.u32-u64.v1",
            "x86.gnu-att.asm-goto.bnonzero.u32-u64.v1",
            *("helper." + item for item in DEFAULT_RUNTIME_HELPER_CONTRACTS),
        }),
        version="phase6-default-catalog-runtime-helper-v1",
    )
    capabilities = compiler_capabilities or CompilerCapabilityModel(
        supports_gnu_inline_asm=target_environment.supports_gnu_inline_asm,
        supports_asm_goto=target_environment.supports_gnu_asm_goto,
        builtin_capabilities=target_environment.builtin_capabilities,
    )
    if helper_contract_registry is None:
        helper_contract_registry = HelperSemanticContractRegistry(
            allowed_contract_ids=frozenset(DEFAULT_RUNTIME_HELPER_CONTRACTS),
            version=RUNTIME_HELPER_MANIFEST_VERSION,
            contracts=DEFAULT_RUNTIME_HELPER_CONTRACTS,
        )
    if not isinstance(catalog, TargetSemanticCatalog) or not isinstance(capabilities, CompilerCapabilityModel):
        return _unsupported(context, reason="Phase-6D target catalog or compiler capability artifact is invalid", reason_code="TR_INVALID_PHASE6D_ENVIRONMENT_ARTIFACT")

    candidate_plans = generate_candidate_plans(source_model)
    candidates: list[ProvenCandidate] = []
    rejected_attempts: list[TargetLoweringAttempt] = []
    for plan in candidate_plans:
        constraint_result = derive_target_constraints(
            source_model=source_model,
            candidate_plan=plan,
            target_environment=target_environment,
        )
        if not constraint_result.success:
            rejected_attempts.append(TargetLoweringAttempt.from_constraint_failure(plan, constraint_result))
            continue
        assert constraint_result.constraints is not None
        proof = run_semantic_proof_gate(
            source_model=source_model,
            preservation_decision=source_model.preservation,
            candidate_plan=plan,
            constraints=constraint_result.constraints,
            target_environment=target_environment,
            target_semantic_catalog=catalog,
            compiler_capabilities=capabilities,
            helper_contract_registry=helper_contract_registry,
        )
        candidates.append(ProvenCandidate(plan, constraint_result, proof))
        if not proof.approved:
            rejected_attempts.append(TargetLoweringAttempt.from_proof_failure(plan, proof))

    catalog_id = catalog.version + ":" + ",".join(sorted(catalog.semantic_contract_ids))
    capability_id = f"asm={capabilities.supports_gnu_inline_asm};goto={capabilities.supports_asm_goto}"
    selection = select_final_target_lowering_plan(Phase6ESelectionRequest(
        source_model=source_model,
        preservation_decision=source_model.preservation,
        target_environment=target_environment,
        candidates=tuple(candidates),
        generated_plan_ids=frozenset(plan.plan_id for plan in candidate_plans),
        target_catalog_version=catalog_id,
        compiler_capability_id=capability_id,
        helper_registry_version=None if helper_contract_registry is None else helper_contract_registry.version,
        selection_policy=selection_policy,
    ))
    attempt_metadata = tuple({"planId": item.plan_id, "stage": item.stage, "reasonCodes": item.reason_codes} for item in rejected_attempts)
    if selection.kind is FinalSelectionKind.NEEDS_ROUTE:
        return _needs_route(context, route=selection.route_target or "registered_route", reason="no local proven lowering; Phase 6E selected registered route", reason_code="TR_PHASE6E_NEEDS_ROUTE", metadata={"attempts": attempt_metadata, "candidatePlanCount": len(candidate_plans)})
    if selection.kind is FinalSelectionKind.INVARIANT_VIOLATION:
        return _unsupported(context, reason="Phase-6E artifact consistency validation failed", reason_code="TR_PHASE6E_ARTIFACT_INCONSISTENT")
    if selection.kind is FinalSelectionKind.UNSUPPORTED:
        text = render_final_selection_result(selection, target_environment=target_environment, renderer_context=renderer_context or RendererContext({}, {})).emitted_text or ""
        # Do not collapse Phase 6C/6D's structured failures into a generic
        # message.  The report boundary is the only diagnostic available to
        # the launcher, so keep a deterministic summary here.  This records
        # facts already produced by those stages; it neither retries proof nor
        # reinterprets source/target semantics.
        attempt_notes = tuple(
            f"{item.plan_id}@{item.stage}:"
            f"{','.join(item.reason_codes) if item.reason_codes else 'no_reason_code'}"
            for item in rejected_attempts
        )
        return _output(
            kind="unsupported", replacement=text, context=context,
            route="phase6e_unsupported",
            notes=[
                "no target lowering passed the Phase-6 semantic proof gate",
                *attempt_notes,
            ],
            reason_codes=[selection.primary_reason_code or "TR_NO_PROVEN_TARGET_LOWERING_PLAN"],
            build_family="", requires_build_check=False,
            requires_block_proof=False,
            metadata={
                "attempts": attempt_metadata,
                "candidatePlanCount": len(candidate_plans),
                "approvedPlanCount": 0,
            },
        )
    if selection.kind is FinalSelectionKind.KEEP:
        text = render_final_selection_result(selection, target_environment=target_environment, renderer_context=renderer_context or RendererContext({}, {})).emitted_text or ""
        return _output(kind="keep", replacement=text, context=context, route="phase6e_keep", notes=["Phase 6E policy selected keep"], reason_codes=["TR_PHASE6E_KEEP"], build_family="", requires_build_check=False, requires_block_proof=False, metadata={"attempts": attempt_metadata})
    if renderer_context is None:
        renderer_context = _make_phase6f_context_from_approved_contract(context, selection.selected_plan, renderer_contract_registry)
    if renderer_context is None:
        return _unsupported(context, reason="selected approved plan has no registered Phase-6F renderer contract", reason_code="TR_PHASE6F_RENDERER_CONTEXT_REQUIRED")
    rendered = render_final_selection_result(selection, target_environment=target_environment, renderer_context=renderer_context)
    if rendered.kind in {RenderedReplacementKind.INTERNAL_ERROR, RenderedReplacementKind.UNSUPPORTED_DIAGNOSTIC} or rendered.emitted_text is None:
        code = rendered.diagnostics[0].value if rendered.diagnostics else "TR_PHASE6F_RENDER_FAILURE"
        return _unsupported(context, reason="Phase-6F could not faithfully encode the selected approved contract", reason_code=code)
    kind = ("x86_asm_goto" if rendered.kind is RenderedReplacementKind.GNU_ASM_GOTO
            else "x86_inline_asm" if rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
            else "c")
    proof = selection.selected_plan.proof
    evidence = proof.evidence
    artifact = {
        "artifactVersion": "phase6-approval-v1", "proofStatus": "approved",
        "sourceFragmentId": context.fragment.id,
        "sourceModelId": selection.selected_plan.source_model_id,
        "preservationDecisionId": selection.selected_plan.preservation_decision_id,
        "planId": selection.selected_plan.plan.plan_id,
        "constraintsId": evidence.constraints_id,
        "targetEnvironmentId": selection.selected_plan.target_environment_id,
        "targetCatalogVersion": evidence.target_catalog_version,
        "selectionPolicyId": selection.selected_plan.selection_policy_id,
        "selectionPolicyVersion": selection.selected_plan.selection_policy_version,
        "selectionTier": selection.selected_plan.selection_tier.name,
        "rendererId": rendered.renderer_id, "rendererVersion": rendered.renderer_version,
        "replacementKind": rendered.kind.value,
        "replacementDigest": _approval_digest(rendered.emitted_text),
        "sourceSliceDigest": _approval_digest(context.fragment.rawAsmText),
    }
    if rendered.kind is RenderedReplacementKind.HELPER_CALL:
        recipe = rendered.target_ast
        artifact.update({
            "helperRuntimeContractId": recipe.runtime_contract_id,
            "helperSemanticVersion": recipe.semantic_version,
            "helperRequiredHeader": recipe.required_header,
            "helperRuntimeLibrary": recipe.runtime_library,
            "helperRuntimeManifestVersion": RUNTIME_HELPER_MANIFEST_VERSION,
        })
    return _output(kind=kind, replacement=rendered.emitted_text, context=context, route="phase6f_rendered", notes=[], reason_codes=[], build_family="x86_gnu_att", requires_build_check=True, requires_block_proof=False, metadata={"selectedPlanId": rendered.approved_plan_id, "rendererId": rendered.renderer_id, "rendererVersion": rendered.renderer_version, "candidatePlanCount": len(candidate_plans), "approvedPlanCount": 1, "attempts": attempt_metadata, "approvalArtifact": artifact})


def _approval_digest(value: str) -> str:
    """Cross-language FNV-1a-64 digest for report/apply integrity checks."""
    state = 14695981039346656037
    for byte in value.encode("utf-8"):
        state = ((state ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"fnv1a64:{state:016x}"


def _make_phase6f_context_from_approved_contract(context: TranslationContext, approved, registry: RendererContractRegistry = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY) -> Optional[RendererContext]:
    """Register only a recipe mechanically implied by an approved 6C contract.

    Unsupported contract families intentionally return None; this helper never
    uses asm text, mnemonics, or plan metadata to invent a renderer recipe.
    """
    if approved is None:
        return None
    bindings = {index: context.bindings.expr(index) for index in range(len(context.bindings.operands))}
    if any(value is None for value in bindings.values()): return None
    registered = registry.resolve(approved)
    if registered is not None:
        return RendererContext({approved.plan.plan_id: registered}, bindings, source_fragment_id=context.fragment.id)
    if approved.constraints.c_expression_constraint is None:
        return None
    contract = approved.constraints.c_expression_constraint
    if any((contract.result_type.requires_explicit_width_cast, contract.result_type.requires_explicit_unsigned_cast)):
        return None
    operands = tuple(item.source_operand_index for item in contract.input_bindings)
    if any(item.type_contract.requires_explicit_width_cast or item.type_contract.requires_explicit_unsigned_cast for item in contract.input_bindings):
        return None
    from .c_module.phase6c_c_expression import CExpressionOperationKind
    binary = {CExpressionOperationKind.BIT_AND:"&", CExpressionOperationKind.BIT_OR:"|", CExpressionOperationKind.BIT_XOR:"^", CExpressionOperationKind.UNSIGNED_ADD:"+", CExpressionOperationKind.UNSIGNED_SUB:"-", CExpressionOperationKind.UNSIGNED_MUL:"*", CExpressionOperationKind.UNSIGNED_EQUAL:"==", CExpressionOperationKind.UNSIGNED_NOT_EQUAL:"!=", CExpressionOperationKind.UNSIGNED_LESS_THAN:"<", CExpressionOperationKind.UNSIGNED_LESS_EQUAL:"<=", CExpressionOperationKind.UNSIGNED_GREATER_THAN:">", CExpressionOperationKind.UNSIGNED_GREATER_EQUAL:">="}
    if contract.operation_kind is CExpressionOperationKind.COPY and len(operands) == 1:
        expression = COperandRef(operands[0])
    elif contract.operation_kind in binary and len(operands) == 2:
        expression = CBinaryExpression(binary[contract.operation_kind], COperandRef(operands[0]), COperandRef(operands[1]))
    else:
        return None
    recipe = CExpressionRecipe(expression, contract.result_binding.source_operand_index)
    renderer_contract = RendererContract("phase6f:" + approved.plan.plan_id, approved.plan.plan_id, RendererContractKind.C_EXPRESSION, recipe)
    return RendererContext({approved.plan.plan_id: renderer_contract}, bindings, source_fragment_id=context.fragment.id)

def _translate_legacy_bridge(
    context: TranslationContext,
) -> TranslationOutput:
    """
    Transitional compatibility bridge after Phase 6A.

    New architecture invariant:

      * context.sourceModel is the authoritative source semantic model;
      * context.sourceModel.preservation is the authoritative decision;
      * context.decision is temporary compatibility state only;
      * this bridge must never call the former scanning implementation of
        _classify_preservation().

    Phase 6B-F will eventually replace this bridge with:

        SourceSemanticModel
            -> Candidate TargetLoweringPlan[]
            -> TargetConstraintModel per candidate
            -> plan-specific SemanticProofGate
            -> approved plans
            -> deterministic selection
            -> final rendering
    """
    decision, failure = _get_phase6a_decision(context)

    if failure is not None:
        return failure

    assert decision is not None

    if decision.level == PreservationLevel.D:
        return _translate_level_d(context)

    if decision.level == PreservationLevel.C:
        return _translate_level_c(context)

    if decision.level == PreservationLevel.B:
        return _translate_level_b(context)

    return _translate_level_a(context)

def _minimal_failure_context(
    *,
    frag: AsmFragment,
    lift: Any,
    summary: Optional[IRSummary],
    machine_code: bytes,
    xlen: int,
) -> TranslationContext:
    """
    仅用于构造结构化 unsupported TranslationOutput。

    该 context 不参与正常的 Phase-6 strategy / semantic lowering。

    特别注意：
      * TranslationContext 不保存 LiftResult；
      * TranslationContext 不保存 raw LiftedInsn；
      * 失败路径只能构造最小的 structured-IR context；
      * lift 参数仅为保持调用接口兼容，不能写入 context。
    """
    # lift 在失败 context 中不得被保存或转化为 raw instructions。
    #
    # 保留该赋值仅用于明确说明该参数是有意未使用的，
    # 也避免静态检查工具将其判定为遗漏。
    _ = lift

    if summary is None:
        summary = IRSummary(
            is_single_block=False,
            has_branch=False,
            has_call_or_return=False,
            has_memory_barrier=False,
            has_atomic=False,
            reads_regs=set(),
            writes_regs=set(),
            reads_mem=False,
            writes_mem=False,
        )

    empty_cfg = CFGResult(
        ok=False,
        nodes={},
        entry=None,
        error="translation context construction failed",
    )

    # 不允许为正常 translate 路径伪造 runtime facts。
    #
    # 这里只是为了让 unsupported TranslationOutput 拥有一个
    # 结构完整的 TranslationContext；该 context 不会进入 lowering。
    facts = TranslationRuntimeFacts()

    return TranslationContext(
        fragment=frag,
        blocks=[],
        cfg=empty_cfg,
        summary=summary,
        machine_code=bytes(machine_code or b""),
        xlen=xlen if xlen in {32, 64} else 64,
        shell=_build_shell_semantics(frag),
        bindings=_build_operand_binding_view(
            frag,
            facts.rv_to_operand_index,
        ),
        runtimeFacts=facts,
        decision=PreservationDecision(
            level=PreservationLevel.A,
            reasons=["translation input validation failed"],
            reason_codes=["TR_INPUT_VALIDATION_FAILED"],
        ),
    )
