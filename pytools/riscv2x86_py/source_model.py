# translator/phase6/source_model.py
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import FrozenSet, Iterable, Mapping, Optional, Sequence, Set, Tuple, Union
from enum import Enum
try:
    from .cfg import CFGResult
    from .pcode_ir import BarrierKind, Block, FenceSet, IRSummary, VarKind
    from .runtime_facts import TranslationRuntimeFacts, canonicalize_riscv_register_name
    from .schema import AsmFragment
except ImportError:  # pragma: no cover - direct-module compatibility
    from cfg import CFGResult
    from pcode_ir import BarrierKind, Block, FenceSet, IRSummary, VarKind
    from runtime_facts import TranslationRuntimeFacts, canonicalize_riscv_register_name
    from schema import AsmFragment

from .runtime_fact_model import RuntimeFactStatus
from .semantic_types import (
    PreservationDecision,
    SemanticFeature,
)
from .shell_model import SourceShellModel


# RISC-V architectural register aliases relevant to ABI/frame preservation.
#
# x2 == sp
# x8 == s0/fp
#
# Summary register names are normalized before comparison, so these sets use
# lower-case canonical spellings.
_STACK_REGISTERS: FrozenSet[str] = frozenset(
    {
        "sp",
        "x2",
    }
)

_FRAME_REGISTERS: FrozenSet[str] = frozenset(
    {
        "fp",
        "s0",
        "x8",
    }
)

@dataclass(frozen=True)
class SourceControlFlowSuccessor:
    """A source-CFG edge already normalized before Phase 6C."""
    source_block_address: int
    successor_address: int
    edge_kind: str


@dataclass(frozen=True)
class SourceAsmGotoLabelBinding:
    """Authoritative asm-goto C-label to host-continuation association."""
    label: str
    continuation_id: str


@dataclass(frozen=True)
class SourceControlFlowModel:
    """
    Structured source control-flow semantic snapshot.

    This model is derived only from authoritative Block / CFG / IRSummary
    metadata. It must not inspect raw p-code strings, LiftResult, LiftedInsn,
    assembly mnemonics, or rawAsmText.
    """

    cfg_ok: bool
    cfg_entry: Optional[int]
    cfg_node_count: int
    cfg_error: str

    is_single_block: bool

    has_internal_branch: bool
    has_call: bool

    # Three-state semantic flags:
    #
    # True  -> structured analysis explicitly detected the semantic.
    # False -> structured analysis explicitly proved it absent.
    # None  -> available analysis cannot safely prove absence.
    has_return: Optional[bool]
    has_tail_call: Optional[bool]

    has_indirect_control_flow: Optional[bool]
    has_unknown_target: bool

    has_asm_goto: bool
    has_external_control_flow: bool
    has_multiple_exits: bool
    has_non_local_control_dependency: bool

    # Phase 6C-7 consumes these facts and must not read CFGResult itself.
    successors: Tuple[SourceControlFlowSuccessor, ...] = ()
    successors_complete: bool = False
    asm_goto_label_bindings: Tuple[SourceAsmGotoLabelBinding, ...] = ()
    asm_goto_label_bindings_complete: bool = False
    asm_goto_fallthrough_continuation_id: str | None = None
    asm_goto_successor_continuation_ids: Tuple[str, ...] = ()
    asm_goto_condition_kind: str | None = None
    asm_goto_condition_operand_index: int | None = None


@dataclass(frozen=True)
class SourceMemoryModel:
    """
    Structured source memory semantic snapshot.
    """

    reads_memory: bool
    writes_memory: bool

    has_memory_barrier: bool
    has_instruction_barrier: bool
    has_unknown_barrier: bool

    has_atomic: bool
    atomic_orderings: FrozenSet[str]

@dataclass(frozen=True)
class SourceMicroArchModel:
    """
    Structured microarchitecture / experiment semantic snapshot.
    """

    explicitly_microarch_sensitive: bool
    microarch_reasons: Tuple[str, ...]
    has_structured_microarch_intent: bool

    has_timing_source: Optional[bool]
    has_cache_operation: Optional[bool]
    has_speculation_control: Optional[bool]

    has_retry_loop: bool
    has_experiment_retry_loop: bool

@dataclass(frozen=True)
class SourceRegisterModel:
    """
    Structured source register semantic snapshot.
    """

    reads_registers: FrozenSet[str]
    writes_registers: FrozenSet[str]
    referenced_registers: FrozenSet[str]

    reads_or_writes_stack_pointer: bool
    reads_or_writes_frame_pointer: bool

    has_unresolved_register_identity: bool

@dataclass(frozen=True)
class SourceAnalysisCompletenessModel:
    """
    Snapshot of source semantic-analysis completeness.
    """

    cfg_ok: bool

    runtime_facts_available: bool
    runtime_facts_structurally_valid: bool

    missing_operand_binding_registers: Tuple[str, ...]
    missing_output_binding_registers: Tuple[str, ...]
    missing_operand_width_registers: Tuple[str, ...]

    has_tail_call_summary: bool
    has_timing_source_summary: bool
    has_cache_operation_summary: bool
    has_speculation_control_summary: bool

    has_unknown_barrier: bool
    has_unresolved_register_identity: bool

@dataclass(frozen=True)
class SourceSemanticModel:
    """
    Authoritative Phase-6 source semantic contract.

    Downstream Phase 6B-F code must consume only this model.

    Forbidden downstream inputs include:

      * AsmFragment;
      * Block;
      * CFGResult;
      * IRSummary;
      * TranslationRuntimeFacts;
      * raw asm text;
      * raw instruction mnemonic;
      * p-code text;
      * LiftResult;
      * LiftedInsn.
    """

    # Compiler-shell semantic facts.
    shell: SourceShellModel

    # Validated runtime-fact status, not raw runtime-fact implementation.
    runtime_facts: RuntimeFactStatus

    # Newly explicit 6C-1 semantic facts.
    operands: SourceOperandModel
    operation: SourceOperationModel
    atomic: SourceAtomicOperationModel
    barrier: SourceBarrierModel
    implicit_state: SourceImplicitStateModel
    helper_abi: SourceHelperAbiModel

    # Existing structured source semantic facts.
    control_flow: SourceControlFlowModel
    memory: SourceMemoryModel
    microarch: SourceMicroArchModel
    registers: SourceRegisterModel
    completeness: SourceAnalysisCompletenessModel

    features: FrozenSet[SemanticFeature]
    reasons: Tuple[str, ...]
    reason_codes: Tuple[str, ...]

    preservation: PreservationDecision

    # Source architecture width. This is not an operand width substitute.
    xlen: Optional[int]
    value_operation: SourceValueOperationModel | None

    @property
    def phase6b_candidate_facts(self):
        """Return the Phase-6A-owned, immutable input contract for Phase 6B.

        The import is intentionally lazy: candidate_plans imports this module,
        while this authoritative Phase-6A adapter constructs its DTO.
        Phase 6B must not reconstruct these facts from lower-level artifacts.
        """
        from .candidate_plans import Phase6BCandidateFacts

        operand_facts_complete = (
            self.operands.complete
            and self.completeness.runtime_facts_structurally_valid
            and not self.completeness.missing_operand_binding_registers
            and not self.completeness.missing_operand_width_registers
        )
        control_unknown = (
            not self.control_flow.cfg_ok
            or self.control_flow.has_unknown_target
            or self.control_flow.has_indirect_control_flow is None
        )
        opaque = self.operation.kind in {
            SourceOperationKind.OPAQUE,
            SourceOperationKind.UNKNOWN,
        }
        unmodelled = any((
            not self.operation.complete,
            not self.implicit_state.complete,
            self.memory.has_unknown_barrier,
            self.registers.has_unresolved_register_identity,
            control_unknown,
        ))
        shell_known = isinstance(self.shell, SourceShellModel)
        stack_sensitive = (
            self.registers.reads_or_writes_stack_pointer
            or self.implicit_state.reads_stack_pointer
            or self.implicit_state.writes_stack_pointer
        )
        frame_sensitive = (
            self.registers.reads_or_writes_frame_pointer
            or self.implicit_state.reads_frame_pointer
            or self.implicit_state.writes_frame_pointer
        )
        microarch_known = all(
            value is not None
            for value in (
                self.microarch.has_timing_source,
                self.microarch.has_cache_operation,
                self.microarch.has_speculation_control,
            )
        )
        c_expression_eligible = bool(
            self.value_operation is not None
            and self.value_operation.complete
            and self.operation.kind is SourceOperationKind.REGISTER_ONLY
            and not self.operation.reads_memory
            and not self.operation.writes_memory
            and not self.atomic.present
            and not self.barrier.present
            and not self.operation.has_control_flow
            and self.operation.has_return is False
            and self.operation.may_trap is False
            and shell_known
            and not self.shell.requires_shell_aware_lowering
            and operand_facts_complete
        )
        return Phase6BCandidateFacts(
            model_is_consistent=not unmodelled,
            has_global_fail_closed_state=opaque or unmodelled,
            has_opaque_semantics=opaque,
            has_unmodelled_semantics=unmodelled,
            operand_bindings_are_authoritative=operand_facts_complete,
            operand_widths_are_authoritative=operand_facts_complete,
            target_is_x86=True,
            microarch_classification_is_known=microarch_known,
            has_microarch_sensitive_semantics=(
                self.microarch.explicitly_microarch_sensitive
                or self.microarch.has_structured_microarch_intent
            ),
            has_stack_sensitive_semantics=stack_sensitive,
            has_frame_sensitive_semantics=frame_sensitive,
            has_required_helper_semantics=(
                self.operation.requires_helper_abi_contract and self.helper_abi.complete
            ),
            helper_runtime_contract_id=(
                None if not self.helper_abi.complete or not self.helper_abi.helper_symbol or not self.helper_abi.semantic_version
                else f"{self.helper_abi.helper_symbol}@{self.helper_abi.semantic_version}"
            ),
            has_control_flow_semantics=self.operation.has_control_flow,
            has_asm_goto_semantics=self.control_flow.has_asm_goto,
            has_call_semantics=self.control_flow.has_call,
            has_return_semantics=self.control_flow.has_return is True,
            has_branch_semantics=self.control_flow.has_internal_branch,
            asm_goto_condition_kind=self.control_flow.asm_goto_condition_kind,
            asm_goto_condition_operand_index=self.control_flow.asm_goto_condition_operand_index,
            has_atomic_semantics=self.atomic.present,
            # A shell-only compiler barrier accompanies ordinary memory
            # accesses frequently.  It is preserved by the memory contract,
            # but must not divert LOAD/STORE into the barrier-only family.
            has_barrier_semantics=(
                self.barrier.present
                and not (self.memory.reads_memory or self.memory.writes_memory)
            ),
            has_non_atomic_memory_semantics=(
                (self.memory.reads_memory or self.memory.writes_memory)
                and not self.atomic.present
            ),
            shell_semantics_are_known=shell_known,
            is_shell_neutral=(
                shell_known and not self.shell.requires_shell_aware_lowering
            ),
            c_semantics_are_defined=c_expression_eligible,
            c_expression_eligible=c_expression_eligible,
            c_structured_eligible=False,
        )

def _normalize_register_name(value: object) -> str:
    """
    Normalize a structured register name for ABI-sensitive comparisons.

    This function only normalizes register-name spellings.  It does not parse
    p-code operands, infer register identity from text, or infer operand
    bindings from source/operand order.
    """
    text = str(value or "").strip().lower()

    if not text:
        return ""

    while text.startswith(("%", "$")):
        text = text[1:].strip()

    if ":" in text:
        prefix, suffix = text.rsplit(":", 1)

        if prefix in {
            "reg",
            "register",
            "riscv",
            "rv",
            "gpr",
        }:
            text = suffix.strip()

    aliases = {
        "stack_pointer": "sp",
        "stackpointer": "sp",
        "frame_pointer": "fp",
        "framepointer": "fp",
    }

    return aliases.get(text, text)


def _normalized_summary_register_set(
    value: object,
) -> FrozenSet[str]:
    if value is None:
        return frozenset()

    if isinstance(value, str):
        values = (value,)
    else:
        try:
            values = tuple(value)
        except TypeError:
            values = (value,)

    normalized: Set[str] = set()

    for item in values:
        register = _normalize_register_name(item)

        if register:
            normalized.add(register)

    return frozenset(normalized)


def _cfg_terminator_kind(block: Block) -> str:
    """
    Return normalized structured CFG terminator kind.

    This consumes only Block.terminator_kind metadata and never parses raw
    p-code or assembly text.
    """
    kind = getattr(block, "terminator_kind", None)

    if kind is None:
        return ""

    enum_value = getattr(kind, "value", None)

    if isinstance(enum_value, str):
        return enum_value.strip().lower()

    if isinstance(kind, str):
        return kind.strip().lower()

    return ""


def _normalized_runtime_binding_map(
    fact_status: RuntimeFactStatus,
) -> dict[str, int]:
    """
    Return authoritative register-to-operand bindings keyed by normalized
    register name.

    This does not infer bindings from operand ordering.  It only normalizes
    explicitly supplied runtime-fact keys for comparison against normalized
    IRSummary register names.
    """
    bindings: dict[str, int] = {}

    raw_bindings = getattr(fact_status, "rv_to_operand_index", {}) or {}

    try:
        items = raw_bindings.items()
    except AttributeError:
        return bindings

    for raw_register, raw_operand_index in items:
        register = _normalize_register_name(raw_register)

        if not register:
            continue

        if isinstance(raw_operand_index, bool) or not isinstance(
            raw_operand_index,
            int,
        ):
            continue

        bindings[register] = raw_operand_index

    return bindings


def _runtime_width_map(
    fact_status: RuntimeFactStatus,
) -> dict[int, int]:
    """
    Return authoritative operand-width facts.

    Widths are never inferred from xlen, target ABI, operand order, or source
    register class.
    """
    widths: dict[int, int] = {}

    raw_widths = getattr(fact_status, "operand_width_bits", {}) or {}

    try:
        items = raw_widths.items()
    except AttributeError:
        return widths

    for raw_operand_index, raw_width in items:
        if isinstance(raw_operand_index, bool) or not isinstance(
            raw_operand_index,
            int,
        ):
            continue

        if isinstance(raw_width, bool) or not isinstance(raw_width, int):
            continue

        if raw_width <= 0:
            continue

        widths[raw_operand_index] = raw_width

    return widths


def _missing_operand_bindings(
    registers: Iterable[str],
    bindings: dict[str, int],
) -> Tuple[str, ...]:
    """
    Return source registers lacking an authoritative operand binding.
    """
    return tuple(
        sorted(
            register
            for register in set(registers or ())
            if register and register not in bindings
        )
    )


def _missing_width_facts_for_registers(
    registers: Iterable[str],
    bindings: dict[str, int],
    widths: dict[int, int],
) -> Tuple[str, ...]:
    """
    Return source registers whose authoritative binding exists but whose bound
    host operand has no authoritative positive width fact.

    Registers without a binding are intentionally not returned here: those are
    classified as INCOMPLETE_OPERAND_BINDING / INCOMPLETE_OUTPUT_BINDING rather
    than being redundantly reported as width failures.
    """
    missing: Set[str] = set()

    for register in set(registers or ()):
        if not register:
            continue

        operand_index = bindings.get(register)

        if operand_index is None:
            continue

        if operand_index not in widths:
            missing.add(register)

    return tuple(sorted(missing))

def build_source_semantic_model(
    *,
    fragment: AsmFragment,
    blocks: Sequence[Block],
    cfg: CFGResult,
    summary: IRSummary,
    xlen: Optional[int],
    runtime_facts: Union[
        TranslationRuntimeFacts,
        RuntimeFactStatus,
        None,
    ],
) -> SourceSemanticModel:
    """
    Construct the authoritative immutable Phase-6A SourceSemanticModel.

    This function is the only boundary where Phase 6A raw analysis artifacts
    may be converted into downstream source semantic facts.

    It may consume:
      * AsmFragment;
      * Block;
      * CFGResult;
      * IRSummary;
      * TranslationRuntimeFacts.

    Phase 6B-F must not consume those inputs directly.
    """
    shell = SourceShellModel.from_fragment(fragment)

    runtime_facts_available = runtime_facts is not None
    runtime_status = _runtime_fact_status(runtime_facts)

    control_flow = _build_control_flow_model(
        shell=shell,
        blocks=blocks,
        cfg=cfg,
        summary=summary,
        runtime_facts=runtime_facts,
    )

    memory = _build_memory_model(summary)

    microarch = _build_microarch_model(
        fragment=fragment,
        shell=shell,
        summary=summary,
    )

    registers = _build_register_model(summary)

    # ------------------------------------------------------------------
    # Phase 6C-1 semantic facts.
    # ------------------------------------------------------------------

    operands = _build_operand_model(
        shell=shell,
        blocks=blocks,
        runtime_facts=runtime_facts,
        runtime_status=runtime_status,
    )

    operation = _build_operation_model(
        shell=shell,
        control_flow=control_flow,
        memory=memory,
        operands=operands,
        preservation_input_summary=summary,
    )

    value_operation = _build_value_operation_model(
        blocks=blocks,
        runtime_status=runtime_status,
        operands=operands,
        operation=operation,
    )

    atomic = _build_atomic_operation_model(
        summary=summary,
        memory=memory,
        operands=operands,
    )

    barrier = _build_barrier_model(
        shell=shell,
        memory=memory,
        microarch=microarch,
        summary=summary,
    )

    implicit_state = _build_implicit_state_model(
        shell=shell,
        registers=registers,
    )

    completeness = _build_completeness_model(
        runtime_facts_available=runtime_facts_available,
        runtime_status=runtime_status,
        control_flow=control_flow,
        memory=memory,
        microarch=microarch,
        registers=registers,
        summary=summary,
    )

    features, reasons, reason_codes = _collect_source_semantic_evidence(
        shell=shell,
        control_flow=control_flow,
        memory=memory,
        microarch=microarch,
        registers=registers,
        completeness=completeness,
    )

    from .preservation import derive_preservation_decision
    preservation = derive_preservation_decision(
        features=features,
        reasons=reasons,
        reason_codes=reason_codes,
    )

    return SourceSemanticModel(
        shell=shell,
        runtime_facts=runtime_status,

        operands=operands,
        operation=operation,
        atomic=atomic,
        barrier=barrier,
        implicit_state=implicit_state,
        helper_abi=_build_helper_abi_model(
            summary=summary,
            operation=operation,
            registers=registers,
        ),

        control_flow=control_flow,
        memory=memory,
        microarch=microarch,
        registers=registers,
        completeness=completeness,

        features=features,
        reasons=reasons,
        reason_codes=reason_codes,

        preservation=preservation,

        xlen=xlen,
        value_operation=value_operation,
    )

def _build_control_flow_model(
    *,
    blocks: Sequence[Block],
    cfg: CFGResult,
    summary: IRSummary,
    shell: SourceShellModel,
    runtime_facts: Any,
) -> SourceControlFlowModel:
    """
    Build the structured source control-flow snapshot.

    The model combines IRSummary semantic flags with structured Block / CFG
    metadata. It never parses raw p-code or raw assembly text.

    Optional[bool] semantic flags preserve strict three-state semantics:

      * True:
          The semantic is explicitly detected.

      * False:
          Structured analysis explicitly proves the semantic is absent.

      * None:
          The available analysis cannot safely prove absence.

    In particular, None is never converted into False.
    """
    cfg_ok = _cfg_ok(cfg)
    cfg_entry = _cfg_entry(cfg)
    cfg_node_count = _cfg_node_count(cfg, fallback=len(blocks))
    cfg_error = _cfg_error(cfg)

    summary_has_return = _optional_summary_flag(
        summary,
        "has_return",
    )
    summary_has_tail_call = _optional_summary_flag(
        summary,
        "has_tail_call",
    )
    summary_has_indirect = _optional_summary_flag(
        summary,
        "has_indirect_control_flow",
    )

    summary_has_call_or_return = _summary_bool(
        summary,
        "has_call_or_return",
    )
    summary_has_branch = _summary_bool(
        summary,
        "has_branch",
    )
    summary_is_single_block = _summary_bool(
        summary,
        "is_single_block",
    )

    block_has_call_or_return = any(
        _block_has_call_or_return(block)
        for block in blocks
    )

    block_has_return = any(
        _block_has_return_terminator(block)
        for block in blocks
    )

    block_has_indirect = any(
        _block_has_indirect_control_flow(block)
        for block in blocks
    )

    block_has_unknown_target = any(
        _block_has_unknown_target(block)
        for block in blocks
    )

    has_call_or_return = (
        summary_has_call_or_return
        or block_has_call_or_return
    )

    # Do not collapse a missing/unusable has_return summary into False.
    #
    # A detected return terminator is positive structured evidence and proves
    # True.  Otherwise only an explicit summary False proves False; missing
    # summary data remains None.
    has_return = _merge_optional_summary_with_positive_evidence(
        summary_has_return,
        block_has_return,
    )

    # SourceControlFlowModel currently exposes has_call rather than a separate
    # has_call_or_return field. Preserve the conservative combined fact here.
    #
    # This field remains bool because the existing summary/block logic only
    # provides positive call-or-return evidence. Feature collection must emit
    # CALL_OR_RETURN rather than incorrectly claiming a direct CALL.
    has_call = has_call_or_return

    # Do not collapse a missing/unusable indirect-control-flow summary into
    # False. Block evidence can prove presence, but absence must come from a
    # structured summary that explicitly reports False.
    has_indirect_control_flow = (
        _merge_optional_summary_with_positive_evidence(
            summary_has_indirect,
            block_has_indirect,
        )
    )

    # Unknown target is a separate structured CFG fact. If summary data cannot
    # establish whether call/return-sensitive flow is indirect, preserve this
    # as conservative unknown-target evidence rather than treating it as
    # direct control flow.
    has_unknown_target = (
        block_has_unknown_target
        or (
            summary_has_indirect is None
            and has_call_or_return
        )
    )

    successors = tuple(
        SourceControlFlowSuccessor(
            source_block_address=node.addr,
            successor_address=successor,
            edge_kind=node.successor_kinds.get(successor, "unknown"),
        )
        for node in cfg.nodes.values()
        for successor in node.successors
    ) if cfg_ok else ()

    goto_bindings = ()
    goto_complete = not shell.has_asm_goto
    goto_fallthrough = None
    goto_successors = ()
    # Host-C asm-goto continuations are supplied by the frontend.  Do not
    # derive them from synthetic Phase-4 labels or lifted CFG edge order: the
    # latter is only a local machine-code view and may merge taken/fallthrough.
    if shell.has_asm_goto:
        goto_fallthrough = shell.asm_goto_fallthrough_continuation_id or None
        goto_successors = shell.asm_goto_successor_continuation_ids
        expected_successors = {
            shell.asm_goto_fallthrough_continuation_id,
            *(edge[3] for edge in shell.goto_edges),
        }
        declared_labels = {edge[1] for edge in shell.goto_edges}
        if (shell.asm_goto_control_flow_complete and
                len(shell.goto_edges) == len(shell.goto_labels) and
                declared_labels == set(shell.goto_labels) and
                goto_fallthrough is not None and
                len(goto_successors) == len(expected_successors) and
                set(goto_successors) == expected_successors):
            goto_bindings = tuple(
                SourceAsmGotoLabelBinding(label=edge[1], continuation_id=edge[3])
                for edge in sorted(shell.goto_edges, key=lambda item: item[2])
            )
            goto_complete = True
    return SourceControlFlowModel(
        cfg_ok=cfg_ok,
        cfg_entry=cfg_entry,
        cfg_node_count=cfg_node_count,
        cfg_error=cfg_error,
        is_single_block=summary_is_single_block,
        has_internal_branch=summary_has_branch,
        has_call=has_call,
        has_return=has_return,
        has_tail_call=summary_has_tail_call,
        has_indirect_control_flow=has_indirect_control_flow,
        has_unknown_target=has_unknown_target,
        has_asm_goto=bool(shell.has_asm_goto),
        has_external_control_flow=bool(shell.has_external_control_flow),
        has_multiple_exits=bool(shell.has_multiple_exits),
        has_non_local_control_dependency=bool(
            shell.has_non_local_control_dependency
        ),
        successors=successors,
        successors_complete=cfg_ok and not has_unknown_target,
        asm_goto_label_bindings=goto_bindings,
        asm_goto_label_bindings_complete=goto_complete,
        asm_goto_fallthrough_continuation_id=goto_fallthrough,
        asm_goto_successor_continuation_ids=goto_successors,
        asm_goto_condition_kind=getattr(runtime_facts, "asm_goto_condition_kind", None),
        asm_goto_condition_operand_index=getattr(runtime_facts, "asm_goto_condition_operand_index", None),
    )

def _build_memory_model(
    summary: IRSummary,
) -> SourceMemoryModel:
    # ``IRSummary.atomic_mnemonics`` is legacy diagnostic/display data.  It
    # deliberately has no representation in the authoritative Phase-6A
    # memory model: candidates and proofs must consume structured atomic
    # facts, never instruction spelling.
    atomic_orderings = frozenset(
        _normalized_text_set(
            getattr(summary, "atomic_orderings", set())
        )
    )

    return SourceMemoryModel(
        reads_memory=_summary_bool(summary, "reads_mem"),
        writes_memory=_summary_bool(summary, "writes_mem"),

        has_memory_barrier=_summary_bool(
            summary,
            "has_memory_barrier",
        ),
        has_instruction_barrier=_summary_bool(
            summary,
            "has_instruction_barrier",
        ),
        has_unknown_barrier=_summary_bool(
            summary,
            "has_unknown_barrier",
        ),

        has_atomic=_summary_bool(summary, "has_atomic"),
        atomic_orderings=atomic_orderings,
    )

def _build_microarch_model(
    *,
    fragment: AsmFragment,
    shell: SourceShellModel,
    summary: IRSummary,
) -> SourceMicroArchModel:
    """
    Build the microarchitecture / experiment-sensitive source model.

    Sources of evidence are restricted to structured fragment metadata and
    IRSummary semantic flags.  No mnemonic matching or raw asm parsing occurs
    here.
    """
    has_timing_source = _optional_summary_flag(
        summary,
        "has_timing_source",
    )
    has_cache_operation = _optional_summary_flag(
        summary,
        "has_cache_operation",
    )
    has_speculation_control = _optional_summary_flag(
        summary,
        "has_speculation_control",
    )

    fragment_explicit_microarch = _fragment_bool(
        fragment,
        "microarchSensitive",
        "microarch_sensitive",
    )

    fragment_microarch_reasons = _normalized_text_tuple(
        _fragment_value(
            fragment,
            "microarchReasons",
            "microarch_reasons",
        )
    )

    fragment_structured_microarch = (
        _fragment_value(
            fragment,
            "microArch",
            "microarch",
            "micro_arch",
        )
        is not None
    )

    summary_structured_microarch = (
        has_timing_source is True
        or has_cache_operation is True
        or has_speculation_control is True
    )

    has_structured_microarch_intent = (
        fragment_structured_microarch
        or summary_structured_microarch
    )

    # Preserve explicit fragment metadata from the old classifier.  A retry
    # loop alone is not automatically an experiment-sensitive retry loop:
    # old behavior required both hasRetryLoop and microarchSensitive.
    explicitly_microarch_sensitive = (
        fragment_explicit_microarch
        or bool(fragment_microarch_reasons)
        or fragment_structured_microarch
        or summary_structured_microarch
    )

    has_retry_loop = (
        bool(shell.has_retry_loop)
        or _fragment_bool(
            fragment,
            "hasRetryLoop",
            "has_retry_loop",
        )
    )

    has_experiment_retry_loop = (
        has_retry_loop
        and explicitly_microarch_sensitive
    )

    reasons: List[str] = []

    if fragment_explicit_microarch:
        reasons.append(
            "fragment is explicitly marked microarchitecture-sensitive"
        )

    for reason in fragment_microarch_reasons:
        reasons.append(f"microarchitecture intent: {reason}")

    if fragment_structured_microarch:
        reasons.append(
            "fragment carries structured microarchitecture intent"
        )

    if has_timing_source is True:
        reasons.append(
            "structured source summary contains timing-source semantics"
        )

    if has_cache_operation is True:
        reasons.append(
            "structured source summary contains cache-operation semantics"
        )

    if has_speculation_control is True:
        reasons.append(
            "structured source summary contains speculation-control semantics"
        )

    if has_experiment_retry_loop:
        reasons.append(
            "retry-loop behavior is part of a microarchitecture-sensitive experiment"
        )

    return SourceMicroArchModel(
        explicitly_microarch_sensitive=explicitly_microarch_sensitive,
        microarch_reasons=tuple(reasons),
        has_structured_microarch_intent=has_structured_microarch_intent,
        has_timing_source=has_timing_source,
        has_cache_operation=has_cache_operation,
        has_speculation_control=has_speculation_control,
        has_retry_loop=has_retry_loop,
        has_experiment_retry_loop=has_experiment_retry_loop,
    )

def _build_register_model(
    summary: IRSummary,
) -> SourceRegisterModel:
    """
    Build the source register / ABI sensitivity model.

    Register names are normalized through the same normalization path used by
    runtime-fact binding metadata, preventing mismatches such as:

      * %sp versus sp
      * reg:sp versus sp
      * stack_pointer versus sp
      * frame_pointer versus fp
    """
    reads = _normalized_summary_register_set(
        getattr(summary, "reads_regs", ())
    )
    writes = _normalized_summary_register_set(
        getattr(summary, "writes_regs", ())
    )
    referenced = frozenset(reads | writes)

    return SourceRegisterModel(
        reads_registers=reads,
        writes_registers=writes,
        referenced_registers=referenced,
        reads_or_writes_stack_pointer=bool(
            referenced & _STACK_REGISTERS
        ),
        reads_or_writes_frame_pointer=bool(
            referenced & _FRAME_REGISTERS
        ),
        has_unresolved_register_identity=_summary_bool(
            summary,
            "has_unresolved_register_identity",
        ),
    )

def _build_completeness_model(
    *,
    runtime_facts_available: bool,
    runtime_status: RuntimeFactStatus,
    control_flow: SourceControlFlowModel,
    memory: SourceMemoryModel,
    microarch: SourceMicroArchModel,
    registers: SourceRegisterModel,
    summary: IRSummary,
) -> SourceAnalysisCompletenessModel:
    """
    Completeness checks only describe source evidence quality.

    They do not decide target-plan validity and do not infer target constraints.
    """
    referenced_registers = tuple(
        sorted(registers.referenced_registers)
    )

    written_registers = tuple(
        sorted(registers.writes_registers)
    )

    if runtime_status.structurally_valid:
        missing_operand_bindings = (
            runtime_status.missing_operand_bindings(
                referenced_registers
            )
        )

        missing_output_bindings = (
            runtime_status.missing_operand_bindings(
                written_registers
            )
        )

        missing_operand_widths = (
            runtime_status.missing_width_facts_for_registers(
                referenced_registers
            )
        )
    else:
        # Structurally invalid facts must not be partially trusted.
        missing_operand_bindings = referenced_registers
        missing_output_bindings = written_registers
        missing_operand_widths = referenced_registers

    return SourceAnalysisCompletenessModel(
        cfg_ok=control_flow.cfg_ok,

        runtime_facts_available=runtime_facts_available,
        runtime_facts_structurally_valid=(
            runtime_status.structurally_valid
        ),

        missing_operand_binding_registers=tuple(
            missing_operand_bindings
        ),
        missing_output_binding_registers=tuple(
            missing_output_bindings
        ),
        missing_operand_width_registers=tuple(
            missing_operand_widths
        ),

        has_tail_call_summary=(
            _optional_summary_flag(
                summary,
                "has_tail_call",
            )
            is not None
        ),
        has_timing_source_summary=(
            _optional_summary_flag(
                summary,
                "has_timing_source",
            )
            is not None
        ),
        has_cache_operation_summary=(
            _optional_summary_flag(
                summary,
                "has_cache_operation",
            )
            is not None
        ),
        has_speculation_control_summary=(
            _optional_summary_flag(
                summary,
                "has_speculation_control",
            )
            is not None
        ),

        has_unknown_barrier=memory.has_unknown_barrier,
        has_unresolved_register_identity=(
            registers.has_unresolved_register_identity
        ),
    )

def _collect_source_semantic_evidence(
    *,
    shell: SourceShellModel,
    control_flow: SourceControlFlowModel,
    memory: SourceMemoryModel,
    microarch: SourceMicroArchModel,
    registers: SourceRegisterModel,
    completeness: SourceAnalysisCompletenessModel,
) -> Tuple[
    Set[SemanticFeature],
    Tuple[str, ...],
    Tuple[str, ...],
]:
    """
    Collect structured source-semantic evidence for preservation routing.

    This function records source facts, source-semantic uncertainty, and
    analysis-completeness evidence. It must not decide the final preservation
    level; SemanticFeature -> PreservationLevel routing belongs exclusively to
    derive_preservation_decision().

    Optional[bool] semantic flags preserve strict three-state semantics:

      * True:
          The structured analysis explicitly detected the semantic.

      * False:
          The structured analysis explicitly proved the semantic absent.

      * None:
          The available summary cannot safely prove absence.

    None is never treated as False.  For preservation-sensitive semantics,
    None is recorded as INCOMPLETE_SEMANTIC_SUMMARY so preservation derivation
    follows the D-level fail-closed route.
    """
    features: Set[SemanticFeature] = set()
    reasons: List[str] = []
    reason_codes: List[str] = []

    def add(
        feature: SemanticFeature,
        reason: str,
        reason_code: str,
    ) -> None:
        features.add(feature)

        if reason not in reasons:
            reasons.append(reason)

        if reason_code not in reason_codes:
            reason_codes.append(reason_code)

    def add_incomplete_summary(
        *,
        field_name: str,
        semantic_name: str,
        reason_code: str,
    ) -> None:
        """
        Record that IRSummary cannot safely exclude a preservation-sensitive
        semantic.

        This is intentionally not MICROARCH_SENSITIVE.  The source may have
        genuine microarchitecture-sensitive behavior, but the fact being
        recorded here is analysis incompleteness, not a positive microarch
        semantic detection.
        """
        add(
            _semantic_feature("INCOMPLETE_SEMANTIC_SUMMARY"),
            (
                f"IRSummary does not provide a valid {field_name} semantic "
                f"flag; {semantic_name} semantics cannot be safely excluded"
            ),
            reason_code,
        )

    # ------------------------------------------------------------------
    # Source shell / inline-asm contract
    # ------------------------------------------------------------------

    if shell.is_volatile:
        add(
            _semantic_feature("VOLATILE_ASM"),
            "source shell declares volatile inline assembly",
            "SM_VOLATILE_ASM",
        )

    if shell.has_operands:
        add(
            _semantic_feature("ASM_OPERANDS"),
            "source shell declares inline-assembly operands",
            "SM_INLINE_ASM_OPERANDS",
        )

    if shell.has_clobbers:
        add(
            _semantic_feature("ASM_CLOBBER"),
            "source shell declares inline-assembly clobbers",
            "SM_INLINE_ASM_CLOBBERS",
        )

    if shell.has_memory_clobber:
        add(
            _semantic_feature("MEMORY_CLOBBER"),
            "source shell declares a memory clobber",
            "SM_MEMORY_CLOBBER",
        )

    if shell.has_cc_clobber:
        add(
            _semantic_feature("CONDITION_CODE_CLOBBER"),
            "source shell declares a condition-code clobber",
            "SM_CC_CLOBBER",
        )

    if shell.has_early_clobber:
        add(
            _semantic_feature("EARLY_CLOBBER"),
            "source shell declares an early-clobber operand",
            "SM_EARLY_CLOBBER",
        )

    if shell.has_tied_operands:
        add(
            _semantic_feature("TIED_OPERANDS"),
            "source shell declares tied inline-assembly operands",
            "SM_TIED_OPERANDS",
        )

    if shell.has_declared_operand_binding_metadata:
        add(
            _semantic_feature("OPERAND_BINDING_METADATA"),
            "source shell declares operand-binding metadata",
            "SM_OPERAND_BINDING_METADATA",
        )

    # ------------------------------------------------------------------
    # Control flow
    # ------------------------------------------------------------------

    if control_flow.has_internal_branch:
        add(
            _semantic_feature("INTERNAL_BRANCH"),
            "structured source summary contains internal control flow",
            "SM_INTERNAL_BRANCH",
        )

    # SourceControlFlowModel.has_call currently means that call-or-return
    # sensitive flow exists. It must not be presented as a definite CALL.
    if control_flow.has_call:
        add(
            _semantic_feature(
                "CALL_OR_RETURN",
                "CALL",
            ),
            (
                "structured source summary or CFG contains "
                "call-or-return-sensitive control flow"
            ),
            "SM_CALL_OR_RETURN",
        )

    if control_flow.has_return is True:
        add(
            _semantic_feature("RETURN"),
            "structured CFG or summary contains a return terminator",
            "SM_RETURN",
        )
    elif control_flow.has_return is None:
        add_incomplete_summary(
            field_name="has_return",
            semantic_name="return",
            reason_code="SM_INCOMPLETE_RETURN_SUMMARY",
        )

    if control_flow.has_tail_call is True:
        add(
            _semantic_feature("TAIL_CALL"),
            "structured source summary contains tail-call semantics",
            "SM_TAIL_CALL",
        )
    elif control_flow.has_tail_call is None:
        add_incomplete_summary(
            field_name="has_tail_call",
            semantic_name="tail-call",
            reason_code="SM_INCOMPLETE_TAIL_CALL_SUMMARY",
        )

    if control_flow.has_indirect_control_flow is True:
        add(
            _semantic_feature("INDIRECT_CONTROL_FLOW"),
            "structured CFG contains indirect control flow",
            "SM_INDIRECT_CONTROL_FLOW",
        )
    elif control_flow.has_indirect_control_flow is None:
        add_incomplete_summary(
            field_name="has_indirect_control_flow",
            semantic_name="indirect-control-flow",
            reason_code="SM_INCOMPLETE_INDIRECT_CONTROL_FLOW_SUMMARY",
        )

    if control_flow.has_unknown_target:
        add(
            _semantic_feature(
                "UNKNOWN_CONTROL_FLOW_TARGET",
                "UNKNOWN_TARGET",
            ),
            (
                "structured CFG or incomplete summary contains an unknown "
                "control-flow target"
            ),
            "SM_UNKNOWN_CONTROL_FLOW_TARGET",
        )

    if control_flow.has_asm_goto:
        add(
            _semantic_feature("ASM_GOTO"),
            "source shell uses asm goto",
            "SM_ASM_GOTO",
        )

    if control_flow.has_external_control_flow:
        add(
            _semantic_feature("EXTERNAL_CONTROL_FLOW"),
            "source shell has control-flow edges outside the fragment",
            "SM_EXTERNAL_CONTROL_FLOW",
        )

    if control_flow.has_multiple_exits:
        add(
            _semantic_feature("MULTIPLE_EXITS"),
            "source shell declares multiple exits",
            "SM_MULTIPLE_EXITS",
        )

    if control_flow.has_non_local_control_dependency:
        add(
            _semantic_feature("NON_LOCAL_CONTROL_DEPENDENCY"),
            "source shell declares a non-local control dependency",
            "SM_NON_LOCAL_CONTROL_DEPENDENCY",
        )

    if not control_flow.cfg_ok:
        add(
            _semantic_feature("CFG_INCOMPLETE"),
            "structured CFG analysis is unavailable or invalid",
            "SM_CFG_INCOMPLETE",
        )

    # ------------------------------------------------------------------
    # Memory / atomic / barriers
    # ------------------------------------------------------------------

    if memory.reads_memory:
        add(
            _semantic_feature("MEMORY_READ"),
            "structured source summary reads memory",
            "SM_MEMORY_READ",
        )

    if memory.writes_memory:
        add(
            _semantic_feature("MEMORY_WRITE"),
            "structured source summary writes memory",
            "SM_MEMORY_WRITE",
        )

    if memory.has_atomic:
        add(
            _semantic_feature(
                "ATOMIC_OPERATION",
                "ATOMIC",
            ),
            "structured source summary contains atomic operations",
            "SM_ATOMIC_OPERATION",
        )

    if memory.has_memory_barrier:
        add(
            _semantic_feature("MEMORY_BARRIER"),
            "structured source summary contains a memory barrier",
            "SM_MEMORY_BARRIER",
        )

    if memory.has_instruction_barrier:
        add(
            _semantic_feature("INSTRUCTION_BARRIER"),
            (
                "structured source summary contains an instruction-stream "
                "barrier"
            ),
            "SM_INSTRUCTION_BARRIER",
        )

        # This is a positive instruction-stream synchronization semantic, not
        # merely an incomplete summary. It requires target-specific handling.
        add(
            _semantic_feature("MICROARCH_SENSITIVE"),
            (
                "instruction-stream synchronization requires target-specific "
                "preservation"
            ),
            "SM_INSTRUCTION_STREAM_SYNC",
        )

    if memory.has_unknown_barrier:
        add(
            _semantic_feature("UNKNOWN_BARRIER"),
            "structured source summary contains an unknown barrier semantic",
            "SM_UNKNOWN_BARRIER",
        )

    # ------------------------------------------------------------------
    # Microarchitecture / experiment intent
    # ------------------------------------------------------------------

    if microarch.explicitly_microarch_sensitive:
        add(
            _semantic_feature("MICROARCH_SENSITIVE"),
            (
                "source fragment or structured summary is "
                "microarchitecture-sensitive"
            ),
            "SM_MICROARCH_SENSITIVE",
        )

    for reason in microarch.microarch_reasons:
        add(
            _semantic_feature("MICROARCH_SENSITIVE"),
            reason,
            "SM_MICROARCH_REASON",
        )

    if microarch.has_structured_microarch_intent:
        add(
            _semantic_feature("MICROARCH_SENSITIVE"),
            "source fragment carries structured microarchitecture intent",
            "SM_STRUCTURED_MICROARCH_INTENT",
        )

    if microarch.has_timing_source is True:
        add(
            _semantic_feature("TIMING_SOURCE"),
            (
                "structured IR summary contains a timing/performance-counter "
                "source"
            ),
            "SM_TIMING_SOURCE",
        )
    elif microarch.has_timing_source is None:
        add_incomplete_summary(
            field_name="has_timing_source",
            semantic_name="timing-source",
            reason_code="SM_INCOMPLETE_TIMING_SUMMARY",
        )

    if microarch.has_cache_operation is True:
        add(
            _semantic_feature("CACHE_OPERATION"),
            "structured IR summary contains cache-operation semantics",
            "SM_CACHE_OPERATION",
        )
    elif microarch.has_cache_operation is None:
        add_incomplete_summary(
            field_name="has_cache_operation",
            semantic_name="cache-operation",
            reason_code="SM_INCOMPLETE_CACHE_OPERATION_SUMMARY",
        )

    if microarch.has_speculation_control is True:
        add(
            _semantic_feature("SPECULATION_CONTROL"),
            "structured IR summary contains speculation-control semantics",
            "SM_SPECULATION_CONTROL",
        )
    elif microarch.has_speculation_control is None:
        add_incomplete_summary(
            field_name="has_speculation_control",
            semantic_name="speculation-control",
            reason_code="SM_INCOMPLETE_SPECULATION_CONTROL_SUMMARY",
        )

    # Preserve old behavior: a retry loop becomes experiment-sensitive only
    # when coupled with explicit or structured microarchitecture intent.
    if microarch.has_experiment_retry_loop:
        add(
            _semantic_feature(
                "EXPERIMENT_RETRY_LOOP",
                "RETRY_LOOP",
            ),
            (
                "retry-loop behavior is part of a "
                "microarchitecture-sensitive experiment"
            ),
            "SM_EXPERIMENT_RETRY_LOOP",
        )

    # ------------------------------------------------------------------
    # Register / ABI sensitivity
    # ------------------------------------------------------------------

    if registers.reads_or_writes_stack_pointer:
        add(
            _semantic_feature(
                "STACK_POINTER_ACCESS",
                "STACK_POINTER",
            ),
            (
                "structured source summary reads or writes the architectural "
                "stack pointer"
            ),
            "SM_STACK_POINTER_ACCESS",
        )

    if registers.reads_or_writes_frame_pointer:
        add(
            _semantic_feature(
                "FRAME_POINTER_ACCESS",
                "FRAME_POINTER",
            ),
            (
                "structured source summary reads or writes the architectural "
                "frame pointer"
            ),
            "SM_FRAME_POINTER_ACCESS",
        )

    if registers.has_unresolved_register_identity:
        add(
            _semantic_feature("UNRESOLVED_REGISTER_IDENTITY"),
            (
                "structured source summary contains unresolved register "
                "identity"
            ),
            "SM_UNRESOLVED_REGISTER_IDENTITY",
        )

    # ------------------------------------------------------------------
    # Runtime facts / analysis completeness
    # ------------------------------------------------------------------

    if not completeness.runtime_facts_available:
        add(
            _semantic_feature("RUNTIME_FACTS_UNAVAILABLE"),
            "translation runtime facts are unavailable",
            "SM_RUNTIME_FACTS_UNAVAILABLE",
        )

    if (
        completeness.runtime_facts_available
        and not completeness.runtime_facts_structurally_valid
    ):
        add(
            _semantic_feature("INVALID_RUNTIME_FACTS"),
            "translation runtime facts are structurally invalid",
            "SM_INVALID_RUNTIME_FACTS",
        )

    if completeness.missing_operand_binding_registers:
        names = ", ".join(completeness.missing_operand_binding_registers)

        add(
            _semantic_feature("INCOMPLETE_OPERAND_BINDING"),
            f"missing operand-binding facts for source registers: {names}",
            "SM_INCOMPLETE_OPERAND_BINDING",
        )

    if completeness.missing_output_binding_registers:
        names = ", ".join(completeness.missing_output_binding_registers)

        add(
            _semantic_feature("INCOMPLETE_OUTPUT_BINDING"),
            (
                "missing output-binding facts for written source registers: "
                f"{names}"
            ),
            "SM_INCOMPLETE_OUTPUT_BINDING",
        )

    if completeness.missing_operand_width_registers:
        names = ", ".join(completeness.missing_operand_width_registers)

        add(
            _semantic_feature("INCOMPLETE_OPERAND_WIDTH"),
            f"missing operand-width facts for source registers: {names}",
            "SM_INCOMPLETE_OPERAND_WIDTH",
        )

    return (
        features,
        tuple(reasons),
        tuple(reason_codes),
    )

def _runtime_fact_status(
    runtime_facts: Union[
        TranslationRuntimeFacts,
        RuntimeFactStatus,
        None,
    ],
) -> RuntimeFactStatus:
    """
    Convert authoritative runtime facts into the immutable Phase-6 snapshot.
    """
    if isinstance(runtime_facts, RuntimeFactStatus):
        return runtime_facts

    if runtime_facts is None:
        return _empty_runtime_fact_status()

    try:
        return RuntimeFactStatus.from_runtime_facts(runtime_facts)
    except Exception as exc:
        return RuntimeFactStatus(
            rv_to_operand_index={},
            operand_width_bits={},
            provenance="",
            has_register_operand_bindings=False,
            has_operand_width_facts=False,
            structural_errors=(
                f"cannot construct Phase-6 runtime-fact status: {exc}",
            ),
        )
    
def _empty_runtime_fact_status() -> RuntimeFactStatus:
    return RuntimeFactStatus(
        rv_to_operand_index={},
        operand_width_bits={},
        provenance="",
        has_register_operand_bindings=False,
        has_operand_width_facts=False,
        structural_errors=(),
    )

def _fragment_bool(fragment: object, *field_names: str) -> bool:
    """
    Read a structured AsmFragment boolean field compatibly.

    This helper intentionally does not inspect raw asm text.  It only reads
    structured fragment metadata and supports both historical camelCase and
    newer snake_case field names.
    """
    for field_name in field_names:
        value = getattr(fragment, field_name, None)

        if isinstance(value, bool):
            return value

    return False


def _fragment_value(fragment: object, *field_names: str) -> object:
    """
    Return the first present structured fragment field value.

    ``None`` means absent or explicitly unset.
    """
    for field_name in field_names:
        if hasattr(fragment, field_name):
            return getattr(fragment, field_name)

    return None


def _normalized_text_tuple(value: object) -> Tuple[str, ...]:
    """
    Normalize a structured text collection without parsing source text.

    This is used for fragment-provided diagnostic metadata such as
    ``microarchReasons``.  Non-string members are stringified only because
    they are already structured metadata, not raw assembly/p-code input.
    """
    if value is None:
        return ()

    if isinstance(value, str):
        values = (value,)
    else:
        try:
            values = tuple(value)
        except TypeError:
            values = (value,)

    normalized: List[str] = []

    for item in values:
        text = str(item or "").strip()

        if text and text not in normalized:
            normalized.append(text)

    return tuple(normalized)


_SEMANTIC_FEATURE_NAME_ALIASES: dict[str, str] = {
    # Earlier Phase-6A vocabulary migrations.
    "ATOMIC": "ATOMIC_OPERATION",
    "CALL": "CALL_OR_RETURN",
    "UNKNOWN_TARGET": "UNKNOWN_CONTROL_FLOW_TARGET",
    "STACK_POINTER": "STACK_POINTER_ACCESS",
    "FRAME_POINTER": "FRAME_POINTER_ACCESS",

    # Historical / intermediate inline-asm collector vocabulary.
    "INLINE_ASM_OPERANDS": "ASM_OPERANDS",
    "INLINE_ASM_CLOBBERS": "ASM_CLOBBER",
    "CC_CLOBBER": "CONDITION_CODE_CLOBBER",

    # These names are now canonical enum members, but retaining entries here
    # makes the migration intent explicit and is harmless. They also make
    # future vocabulary refactors localized to this table.
    "EARLY_CLOBBER": "EARLY_CLOBBER",
    "TIED_OPERANDS": "TIED_OPERANDS",
    "OPERAND_BINDING_METADATA": "OPERAND_BINDING_METADATA",
}


def _semantic_feature(
    *candidate_names: str,
) -> SemanticFeature:
    """
    Resolve a SemanticFeature across canonical and historical vocabularies.

    The canonical vocabulary belongs to semantic_types.SemanticFeature.
    source_model.py may temporarily accept names emitted by older summary
    builders or adjacent Phase-6A migration revisions.

    Examples:

        _semantic_feature("ATOMIC")
            -> SemanticFeature.ATOMIC_OPERATION

        _semantic_feature("CC_CLOBBER")
            -> SemanticFeature.CONDITION_CODE_CLOBBER

        _semantic_feature("INLINE_ASM_OPERANDS")
            -> SemanticFeature.ASM_OPERANDS

    Candidate order remains meaningful: the first candidate that resolves to
    a valid canonical SemanticFeature is returned.

    At least one requested feature name must resolve successfully.
    """
    attempted_names: list[str] = []

    for requested_name in candidate_names:
        canonical_name = _SEMANTIC_FEATURE_NAME_ALIASES.get(
            requested_name,
            requested_name,
        )

        attempted_names.append(requested_name)
        if canonical_name != requested_name:
            attempted_names.append(canonical_name)

        feature = getattr(SemanticFeature, canonical_name, None)
        if feature is not None:
            return feature

    raise AttributeError(
        "SemanticFeature is missing all compatible names: "
        + ", ".join(candidate_names)
        + "; attempted canonical names: "
        + ", ".join(attempted_names)
    )

def _block_bool(block: object, *field_names: str) -> bool:
    """
    Read a structured Block/CFG boolean field compatibly.
    """
    for field_name in field_names:
        value = getattr(block, field_name, None)

        if isinstance(value, bool):
            return value

    return False


def _block_has_call_or_return(block: object) -> bool:
    return _block_bool(
        block,
        "is_call_or_return",
        "has_call_or_return",
        "isCallOrReturn",
    )


def _block_has_return_terminator(block: object) -> bool:
    terminator = _cfg_terminator_kind(block)

    return terminator in {
        "return",
        "ret",
        "iret",
        "sysret",
    }


def _block_has_indirect_control_flow(block: object) -> bool:
    terminator = _cfg_terminator_kind(block)

    return (
        _block_bool(
            block,
            "is_indirect",
            "has_indirect_control_flow",
            "isIndirect",
        )
        or terminator
        in {
            "callind",
            "branchind",
            "indirect_call",
            "indirect_branch",
            "indirect_jump",
            "ijmp",
            "icall",
        }
    )


def _block_has_unknown_target(block: object) -> bool:
    return _block_bool(
        block,
        "has_unknown_target",
        "hasUnknownTarget",
        "unknown_target",
    )

def _summary_bool(
    summary: IRSummary,
    field_name: str,
) -> bool:
    """
    Read a non-three-state boolean summary field conservatively.
    """
    value = getattr(summary, field_name, False)
    return value if isinstance(value, bool) else False

def _optional_summary_flag(
    summary: IRSummary,
    name: str,
) -> bool | None:
    """
    Read an Optional[bool] semantic flag from IRSummary.

    Three-state contract:

      * True:
          The structured IRSummary explicitly proves that the semantic is
          present.

      * False:
          The structured IRSummary explicitly proves that the semantic is
          absent.

      * None:
          The current IRSummary schema, producer, or field value cannot safely
          prove absence.  Callers must not treat None as False.

    This helper does not inspect raw p-code, assembly mnemonics, LiftResult,
    LiftedInsn, or textual operands.
    """
    value = getattr(summary, name, None)

    if isinstance(value, bool):
        return value

    return None

def _merge_optional_summary_with_positive_evidence(
    summary_flag: bool | None,
    has_structured_positive_evidence: bool,
) -> bool | None:
    """
    Merge an Optional[bool] summary flag with structured positive evidence.

    Rules:

      * Any structured positive evidence proves True.
      * A summary False proves False only when there is no contradictory
        structured positive evidence.
      * A missing/unusable summary remains None when no positive evidence is
        available.

    In particular, this function never converts None into False.
    """
    if has_structured_positive_evidence:
        return True

    if summary_flag is False:
        return False

    return None

def _cfg_ok(cfg: CFGResult) -> bool:
    for name in ("ok", "is_ok", "valid", "is_valid"):
        value = getattr(cfg, name, None)
        if isinstance(value, bool):
            return value

    # If CFGResult exposes an error string but no boolean, empty error is the
    # conservative compatibility interpretation of "ok".
    error = _cfg_error(cfg)
    return not bool(error)

def _cfg_entry(cfg: CFGResult) -> Optional[int]:
    for name in ("entry", "entry_block", "entry_block_index"):
        value = getattr(cfg, name, None)

        if isinstance(value, int) and not isinstance(value, bool):
            return value

    return None

def _cfg_node_count(
    cfg: CFGResult,
    *,
    fallback: int,
) -> int:
    for name in ("node_count", "num_nodes"):
        value = getattr(cfg, name, None)

        if isinstance(value, int) and not isinstance(value, bool):
            return max(value, 0)

    for name in ("nodes", "blocks"):
        value = getattr(cfg, name, None)

        try:
            return len(value)
        except TypeError:
            pass

    return fallback

def _cfg_error(cfg: CFGResult) -> str:
    for name in ("error", "error_message", "message"):
        value = getattr(cfg, name, "")

        if isinstance(value, str):
            return value.strip()

    return ""

def _normalized_text_set(
    values: Iterable[object],
) -> set[str]:
    result: set[str] = set()

    for value in values or ():
        if not isinstance(value, str):
            continue

        normalized = value.strip().lower()

        if normalized:
            result.add(normalized)

    return result

def _normalized_register_set(
    values: Iterable[object],
) -> set[str]:
    result: set[str] = set()

    for value in values or ():
        if not isinstance(value, str):
            continue

        normalized = value.strip().lower()

        if normalized:
            result.add(normalized)

    return result

def _append_unique(
    values: list[str],
    value: str,
) -> None:
    if value not in values:
        values.append(value)
    

class SourceOperandKind(str, Enum):
    """
    Source-level operand category.

    Important:
        This is not a GNU asm constraint class.

    Forbidden values include:
        "r", "m", "=r", "+r", "&r", "0", etc.
    """

    REGISTER = "register"
    MEMORY = "memory"
    IMMEDIATE = "immediate"
    ADDRESS = "address"
    EXPRESSION = "expression"
    LABEL = "label"
    FIXED_REGISTER = "fixed_register"
    UNKNOWN = "unknown"


class SourceOperandAccess(str, Enum):
    """
    Source-side operand access semantics.

    INPUT:
        Value is consumed by the source operation.

    OUTPUT:
        Value is produced by the source operation.

    READ_WRITE:
        Previous value is consumed and a new value is produced.

    ADDRESS:
        Operand denotes an address rather than a loaded/stored value.

    CONTROL_TARGET:
        Operand denotes a control-flow target.
    """

    INPUT = "input"
    OUTPUT = "output"
    READ_WRITE = "read_write"
    ADDRESS = "address"
    CONTROL_TARGET = "control_target"
    UNKNOWN = "unknown"


class SourceSignedness(str, Enum):
    """
    Source width/sign interpretation.

    SIGNLESS is useful for raw register bit patterns and operations where
    signedness is semantically irrelevant.
    """

    SIGNED = "signed"
    UNSIGNED = "unsigned"
    SIGNLESS = "signless"
    UNKNOWN = "unknown"


class SourceOperationKind(str, Enum):
    """
    Structured source operation classification.

    This enum must never be inferred in Phase 6C from:
      * raw asm;
      * instruction mnemonic;
      * p-code text;
      * low-level IR instruction sequence.
    """

    REGISTER_ONLY = "register_only"

    LOAD = "load"
    STORE = "store"
    MEMORY_READ_MODIFY_WRITE = "memory_read_modify_write"

    ATOMIC_LOAD = "atomic_load"
    ATOMIC_STORE = "atomic_store"
    ATOMIC_READ_MODIFY_WRITE = "atomic_read_modify_write"
    ATOMIC_COMPARE_EXCHANGE = "atomic_compare_exchange"

    COMPILER_BARRIER = "compiler_barrier"
    HARDWARE_BARRIER = "hardware_barrier"

    CONTROL_FLOW = "control_flow"
    CALL = "call"
    RETURN = "return"

    STACK_FRAME = "stack_frame"
    HELPER_REQUIRED = "helper_required"

    OPAQUE = "opaque"
    UNKNOWN = "unknown"


class SourceValueOperationKind(str, Enum):
    """Operations explicitly admitted to the Phase 6C-2 C subset."""
    COPY = "copy"
    BIT_NOT = "bit_not"
    BIT_AND = "bit_and"
    BIT_OR = "bit_or"
    BIT_XOR = "bit_xor"
    UNSIGNED_ADD = "unsigned_add"
    UNSIGNED_SUB = "unsigned_sub"
    UNSIGNED_MUL = "unsigned_mul"
    ZERO_EXTEND = "zero_extend"
    TRUNCATE = "truncate"
    # This is deliberately a named, finite straight-line contract rather
    # than a generic instruction-list escape hatch.  It is used only when
    # Phase 6A can account for both externally visible outputs.
    ADD_THEN_SHIFT_LEFT_IMMEDIATE = "add_then_shift_left_immediate"


class SourceAtomicKind(str, Enum):
    LOAD = "load"
    STORE = "store"
    READ_MODIFY_WRITE = "read_modify_write"
    COMPARE_EXCHANGE = "compare_exchange"


class SourceAtomicRmwOperation(str, Enum):
    """Structured RMW operation identity; never an instruction mnemonic."""
    FETCH_ADD = "fetch_add"
    FETCH_OR = "fetch_or"
    FETCH_AND = "fetch_and"
    EXCHANGE = "exchange"


class SourceMemoryOrdering(str, Enum):
    RELAXED = "relaxed"
    CONSUME = "consume"
    ACQUIRE = "acquire"
    RELEASE = "release"
    ACQ_REL = "acq_rel"
    SEQ_CST = "seq_cst"


class SourceBarrierScope(str, Enum):
    """
    Barrier scope is intentionally independent from ordering.

    COMPILER:
        Compiler ordering only.

    THREAD:
        Cross-thread synchronization scope.

    SYSTEM:
        Full system-visible ordering scope.
    """

    COMPILER = "compiler"
    THREAD = "thread"
    SYSTEM = "system"


class SourceHelperMemoryEffect(str, Enum):
    NONE = "none"
    READS = "reads"
    WRITES = "writes"
    READS_WRITES = "reads_writes"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class SourceExpressionBinding:
    """
    Stable source-expression identity.

    expression_id must identify a source-level expression or expression node.
    It must not contain rendered C source text.
    """

    expression_id: str
    c_type_id: Optional[str]
    is_side_effect_free: bool
    is_repeatable: bool


@dataclass(frozen=True)
class SourceLvalueBinding:
    """
    Stable source lvalue identity for an output/read-write operand.
    """

    lvalue_id: str
    c_type_id: Optional[str]
    is_modifiable: bool


@dataclass(frozen=True)
class SourceAddressBinding:
    """
    Stable source address identity for memory/address operands.
    """

    address_id: str
    pointee_type_id: Optional[str]
    alignment_bytes: Optional[int]
    provenance_known: bool


@dataclass(frozen=True)
class SourceOperandBinding:
    """
    One authoritative source operand semantic fact.

    source_operand_index must come from authoritative runtime facts, typically
    TranslationRuntimeFacts.rv_to_operand_index or an equivalent validated map.

    It must never be inferred from:

      * SourceShellModel.outputs / inputs order;
      * fragment operandBindings;
      * materializedOperandBindings;
      * outputBindings;
      * register encounter order;
      * raw asm textual order;
      * p-code register order.
    """

    source_operand_index: int

    kind: SourceOperandKind
    access: SourceOperandAccess

    width_bits: Optional[int]
    signedness: SourceSignedness

    reads: bool
    writes: bool
    read_before_write: bool

    tied_to_source_operand_index: Optional[int]
    early_clobber: bool

    fixed_register_name: Optional[str]

    expression: Optional[SourceExpressionBinding]
    lvalue: Optional[SourceLvalueBinding]
    address: Optional[SourceAddressBinding]

    def __post_init__(self) -> None:
        if (
            isinstance(self.source_operand_index, bool)
            or not isinstance(self.source_operand_index, int)
            or self.source_operand_index < 0
        ):
            raise TypeError(
                "source_operand_index must be a non-negative int"
            )

        if not isinstance(self.kind, SourceOperandKind):
            raise TypeError("kind must be SourceOperandKind")

        if not isinstance(self.access, SourceOperandAccess):
            raise TypeError("access must be SourceOperandAccess")

        if self.width_bits is not None:
            if (
                isinstance(self.width_bits, bool)
                or not isinstance(self.width_bits, int)
                or self.width_bits <= 0
            ):
                raise TypeError(
                    "width_bits must be None or a positive int"
                )

        if not isinstance(self.signedness, SourceSignedness):
            raise TypeError(
                "signedness must be SourceSignedness"
            )

        for field_name in (
            "reads",
            "writes",
            "read_before_write",
            "early_clobber",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be bool")

        if self.tied_to_source_operand_index is not None:
            if (
                isinstance(self.tied_to_source_operand_index, bool)
                or not isinstance(
                    self.tied_to_source_operand_index,
                    int,
                )
                or self.tied_to_source_operand_index < 0
            ):
                raise TypeError(
                    "tied_to_source_operand_index must be None or "
                    "a non-negative int"
                )

        if (
            self.tied_to_source_operand_index
            == self.source_operand_index
        ):
            raise ValueError(
                "operand must not be tied to itself"
            )

        if self.fixed_register_name is not None:
            if not isinstance(self.fixed_register_name, str):
                raise TypeError(
                    "fixed_register_name must be None or str"
                )


@dataclass(frozen=True)
class SourceOperandModel:
    """
    Complete source operand semantic contract for downstream Phase 6B-F.

    complete=False means Phase 6C must fail closed for every candidate that
    requires operand constraints, output binding, register binding, width,
    tied-operand, or early-clobber semantics.
    """

    operands: Tuple[SourceOperandBinding, ...]
    complete: bool
    missing_fact_codes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be bool")

        indexes = tuple(
            operand.source_operand_index
            for operand in self.operands
        )

        if len(indexes) != len(set(indexes)):
            raise ValueError(
                "source operand indexes must be unique"
            )

        if not self.complete and not self.missing_fact_codes:
            raise ValueError(
                "incomplete SourceOperandModel must provide "
                "missing_fact_codes"
            )

@dataclass(frozen=True)
class SourceOperationModel:
    """
    Source operation classification independent of raw asm and raw IR.
    """

    kind: SourceOperationKind

    reads_memory: bool
    writes_memory: bool

    has_control_flow: bool
    has_call: bool
    has_return: Optional[bool]
    may_trap: Optional[bool]

    requires_helper_abi_contract: bool
    complete: bool

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SourceOperationKind):
            raise TypeError("kind must be SourceOperationKind")

        for field_name in (
            "reads_memory",
            "writes_memory",
            "has_control_flow",
            "has_call",
            "requires_helper_abi_contract",
            "complete",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be bool")

        for field_name in (
            "has_return",
            "may_trap",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, bool):
                raise TypeError(
                    f"{field_name} must be bool or None"
                )


@dataclass(frozen=True)
class SourceValueOperationModel:
    """Exact source-proven pure value operation consumed by Phase 6C-2."""
    kind: SourceValueOperationKind
    input_operand_indexes: Tuple[int, ...]
    result_operand_index: int
    complete: bool
    # A canonical p-code constant, normalized to the source operation width.
    # It is not a GNU asm operand and therefore has no source operand index.
    # ``None`` denotes the all-register form.
    immediate_value: int | None = None
    # For the finite two-result sequence above, this is the first visible
    # result (the temporary produced by ADD).  Keeping it in the authoritative
    # Phase-6A model prevents later stages from inferring it from asm text.
    temporary_operand_index: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SourceValueOperationKind):
            raise TypeError("kind must be SourceValueOperationKind")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be bool")
        if isinstance(self.result_operand_index, bool) or not isinstance(self.result_operand_index, int) or self.result_operand_index < 0:
            raise TypeError("result_operand_index must be a non-negative int")
        if not self.input_operand_indexes or any(isinstance(i, bool) or not isinstance(i, int) or i < 0 for i in self.input_operand_indexes):
            raise TypeError("input_operand_indexes must contain non-negative ints")
        if self.immediate_value is not None and (
            isinstance(self.immediate_value, bool)
            or not isinstance(self.immediate_value, int)
        ):
            raise TypeError("immediate_value must be an int or None")
        if self.temporary_operand_index is not None and (
            isinstance(self.temporary_operand_index, bool)
            or not isinstance(self.temporary_operand_index, int)
            or self.temporary_operand_index < 0
        ):
            raise TypeError("temporary_operand_index must be a non-negative int or None")


@dataclass(frozen=True)
class SourceAtomicOperationModel:
    """
    Structured atomic semantic facts.

    atomic instruction mnemonics must not appear here.
    """

    present: bool

    kind: Optional[SourceAtomicKind]
    rmw_operation: Optional[SourceAtomicRmwOperation]

    width_bits: Optional[int]
    alignment_bytes: Optional[int]

    address_operand_index: Optional[int]
    value_operand_index: Optional[int]
    expected_operand_index: Optional[int]
    desired_operand_index: Optional[int]
    result_operand_index: Optional[int]

    success_ordering: Optional[SourceMemoryOrdering]
    failure_ordering: Optional[SourceMemoryOrdering]

    lock_free_required: Optional[bool]
    complete: bool

    def __post_init__(self) -> None:
        if not isinstance(self.present, bool):
            raise TypeError("present must be bool")

        if self.kind is not None and not isinstance(
            self.kind,
            SourceAtomicKind,
        ):
            raise TypeError(
                "kind must be None or SourceAtomicKind"
            )

        if self.rmw_operation is not None and not isinstance(
            self.rmw_operation,
            SourceAtomicRmwOperation,
        ):
            raise TypeError(
                "rmw_operation must be None or SourceAtomicRmwOperation"
            )
        if self.kind is SourceAtomicKind.READ_MODIFY_WRITE and self.complete:
            if self.rmw_operation is None:
                raise ValueError("read-modify-write atomic requires rmw_operation")
        elif self.rmw_operation is not None and self.complete:
            raise ValueError("rmw_operation is valid only for read-modify-write atomic")

        for field_name in (
            "width_bits",
            "alignment_bytes",
        ):
            value = getattr(self, field_name)
            if value is not None:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value <= 0
                ):
                    raise TypeError(
                        f"{field_name} must be None or positive int"
                    )

        for field_name in (
            "address_operand_index",
            "value_operand_index",
            "expected_operand_index",
            "desired_operand_index",
            "result_operand_index",
        ):
            value = getattr(self, field_name)
            if value is not None:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                ):
                    raise TypeError(
                        f"{field_name} must be None or non-negative int"
                    )

        for field_name in (
            "success_ordering",
            "failure_ordering",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(
                value,
                SourceMemoryOrdering,
            ):
                raise TypeError(
                    f"{field_name} must be None or "
                    "SourceMemoryOrdering"
                )

        if self.lock_free_required is not None:
            if not isinstance(self.lock_free_required, bool):
                raise TypeError(
                    "lock_free_required must be bool or None"
                )

        if not isinstance(self.complete, bool):
            raise TypeError("complete must be bool")

        if not self.present:
            unexpected = (
                self.kind,
                self.rmw_operation,
                self.width_bits,
                self.alignment_bytes,
                self.address_operand_index,
                self.value_operand_index,
                self.expected_operand_index,
                self.desired_operand_index,
                self.result_operand_index,
                self.success_ordering,
                self.failure_ordering,
                self.lock_free_required,
            )
            if any(value is not None for value in unexpected):
                raise ValueError(
                    "non-atomic SourceAtomicOperationModel must not "
                    "contain atomic fields"
                )


@dataclass(frozen=True)
class SourceBarrierModel:
    """
    Structured barrier semantics.

    compiler_barrier and hardware_memory_barrier are intentionally separate.

    A GNU \"memory\" clobber is a compiler barrier, not automatically a
    hardware memory fence.
    """

    present: bool

    compiler_barrier: bool
    hardware_memory_barrier: bool
    instruction_serializing: bool
    speculation_control: bool

    ordering: Optional[SourceMemoryOrdering]
    scope: Optional[SourceBarrierScope]

    complete: bool

    def __post_init__(self) -> None:
        for field_name in (
            "present",
            "compiler_barrier",
            "hardware_memory_barrier",
            "instruction_serializing",
            "speculation_control",
            "complete",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be bool")

        if self.ordering is not None and not isinstance(
            self.ordering,
            SourceMemoryOrdering,
        ):
            raise TypeError(
                "ordering must be None or SourceMemoryOrdering"
            )

        if self.scope is not None and not isinstance(
            self.scope,
            SourceBarrierScope,
        ):
            raise TypeError(
                "scope must be None or SourceBarrierScope"
            )

        if not self.present:
            if any(
                (
                    self.compiler_barrier,
                    self.hardware_memory_barrier,
                    self.instruction_serializing,
                    self.speculation_control,
                    self.ordering is not None,
                    self.scope is not None,
                )

            ):
                raise ValueError(
                    "non-barrier SourceBarrierModel must not contain "
                    "barrier semantics"
                )


@dataclass(frozen=True)
class SourceHelperAbiModel:
    """Versioned source-proven helper contract consumed by Phase 6C-8."""
    present: bool; helper_symbol: Optional[str]; semantic_family: Optional[str]; semantic_version: Optional[str]
    calling_convention: Optional[str]; parameter_operand_indexes: Tuple[int, ...]
    return_operand_index: Optional[int]; memory_effect: SourceHelperMemoryEffect
    may_return: Optional[bool]; may_unwind: Optional[bool]
    required_stack_alignment_bytes: Optional[int]
    preserves_stack_pointer: Optional[bool]; preserves_frame_pointer: Optional[bool]
    caller_saved_registers: Tuple[str, ...]; callee_saved_registers: Tuple[str, ...]
    pic_plt_compatible: Optional[bool]; runtime_available: Optional[bool]; complete: bool


def _build_helper_abi_model(*, summary: IRSummary, operation: SourceOperationModel,
                            registers: SourceRegisterModel) -> SourceHelperAbiModel:
    """Adapt explicit Phase-6A helper metadata; never infer from a symbol."""
    raw = getattr(summary, "helper_abi_semantics", None)
    required = operation.requires_helper_abi_contract or registers.reads_or_writes_stack_pointer or registers.reads_or_writes_frame_pointer
    if raw is None:
        return SourceHelperAbiModel(required, None, None, None, None, (), None, SourceHelperMemoryEffect.UNKNOWN, None, None, None, None, None, (), (), None, None, not required)
    memory_effect = getattr(raw, "memory_effect", SourceHelperMemoryEffect.UNKNOWN)
    if not isinstance(memory_effect, SourceHelperMemoryEffect): memory_effect = SourceHelperMemoryEffect.UNKNOWN
    return SourceHelperAbiModel(True, getattr(raw, "helper_symbol", None), getattr(raw, "semantic_family", None), getattr(raw, "semantic_version", None), getattr(raw, "calling_convention", None), tuple(getattr(raw, "parameter_operand_indexes", ())), getattr(raw, "return_operand_index", None), memory_effect, getattr(raw, "may_return", None), getattr(raw, "may_unwind", None), getattr(raw, "required_stack_alignment_bytes", None), getattr(raw, "preserves_stack_pointer", None), getattr(raw, "preserves_frame_pointer", None), tuple(getattr(raw, "caller_saved_registers", ())), tuple(getattr(raw, "callee_saved_registers", ())), getattr(raw, "pic_plt_compatible", None), getattr(raw, "runtime_available", None), bool(getattr(raw, "complete", False)))


@dataclass(frozen=True)
class SourceImplicitStateModel:
    """
    Structured implicit architectural-state facts.

    This is the only Phase-6C source for:
      * cc state;
      * stack pointer effects;
      * frame pointer effects;
      * implicit/special register effects.

    Phase 6C must not rediscover these semantics from mnemonics or raw asm.
    """

    reads_condition_codes: bool
    writes_condition_codes: bool

    reads_stack_pointer: bool
    writes_stack_pointer: bool

    reads_frame_pointer: bool
    writes_frame_pointer: bool

    reads_implicit_machine_state: bool
    writes_implicit_machine_state: bool

    reads_special_register_names: Tuple[str, ...] = ()
    writes_special_register_names: Tuple[str, ...] = ()

    complete: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "reads_condition_codes",
            "writes_condition_codes",
            "reads_stack_pointer",
            "writes_stack_pointer",
            "reads_frame_pointer",
            "writes_frame_pointer",
            "reads_implicit_machine_state",
            "writes_implicit_machine_state",
            "complete",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be bool")

        for field_name in (
            "reads_special_register_names",
            "writes_special_register_names",
        ):
            values = getattr(self, field_name)
            if not all(
                isinstance(value, str) and value.strip()
                for value in values
            ):
                raise TypeError(
                    f"{field_name} must contain non-empty strings"
                )
            
@dataclass(frozen=True)
class SourceAnalysisArtifacts:
    """
    Phase 6A internal analysis artifacts.

    This DTO is not a valid input to Phase 6B, Phase 6C, Phase 6D,
    Phase 6E, or Phase 6F.

    It exists only so Phase 6A can retain raw structured-analysis products
    while producing the normalized SourceSemanticModel.
    """

    blocks: Tuple[Block, ...]
    cfg: CFGResult
    summary: IRSummary

def _build_operand_model(
    *,
    shell: SourceShellModel,
    blocks: Sequence[Block],
    runtime_facts: Union[
        TranslationRuntimeFacts,
        RuntimeFactStatus,
        None,
    ],
    runtime_status: RuntimeFactStatus,
) -> SourceOperandModel:
    """
    Build authoritative source operand semantic facts.

    Important:
        This function must use validated runtime facts for source operand
        indexes and widths.

    It must not derive rv_to_operand_index from shell operand order.
    """
    if runtime_facts is None:
        return SourceOperandModel(
            operands=(),
            complete=not shell.has_operands,
            missing_fact_codes=(
                ()
                if not shell.has_operands
                else ("runtime_facts_unavailable",)
            ),
        )

    if not _runtime_status_is_structurally_valid(runtime_status):
        return SourceOperandModel(
            operands=(),
            complete=not shell.has_operands,
            missing_fact_codes=(
                ()
                if not shell.has_operands
                else ("runtime_facts_structurally_invalid",)
            ),
        )

    # These three adapters are the only project-specific points that need
    # to be wired to TranslationRuntimeFacts.
    authoritative_bindings = _runtime_operand_bindings(runtime_facts)
    authoritative_widths = _runtime_operand_widths(runtime_facts)
    authoritative_semantics = _runtime_operand_semantics(
        runtime_facts,
        shell=shell,
        authoritative_bindings=authoritative_bindings,
        memory_address_operand_indexes=_memory_address_operand_indexes(
            blocks=blocks,
            runtime_facts=runtime_facts,
        ),
    )

    if not shell.has_operands:
        return SourceOperandModel(
            operands=(),
            complete=True,
        )

    missing_codes: list[str] = []
    result: list[SourceOperandBinding] = []

    if not authoritative_bindings:
        return SourceOperandModel(
            operands=(),
            complete=False,
            missing_fact_codes=(
                "missing_authoritative_operand_index_binding",
            ),
        )

    for source_operand_index, binding in sorted(
        authoritative_bindings.items(),
        key=lambda item: item[0],
    ):
        semantic = authoritative_semantics.get(source_operand_index)
        width_bits = authoritative_widths.get(source_operand_index)

        if semantic is None:
            missing_codes.append(
                f"missing_operand_semantics:{source_operand_index}"
            )
            continue

        if width_bits is None:
            missing_codes.append(
                f"missing_operand_width:{source_operand_index}"
            )
            continue

        result.append(
            SourceOperandBinding(
                source_operand_index=source_operand_index,

                kind=semantic.kind,
                access=semantic.access,

                width_bits=width_bits,
                signedness=semantic.signedness,

                reads=semantic.reads,
                writes=semantic.writes,
                read_before_write=semantic.read_before_write,

                tied_to_source_operand_index=(
                    semantic.tied_to_source_operand_index
                ),
                early_clobber=semantic.early_clobber,

                fixed_register_name=semantic.fixed_register_name,

                expression=semantic.expression,
                lvalue=semantic.lvalue,
                address=semantic.address,
            )
        )

    if missing_codes:
        return SourceOperandModel(
            operands=tuple(result),
            complete=False,
            missing_fact_codes=tuple(sorted(set(missing_codes))),
        )

    return SourceOperandModel(
        operands=tuple(result),
        complete=True,
    )

def _runtime_status_is_structurally_valid(
    runtime_status: RuntimeFactStatus,
) -> bool:
    """
    Check runtime-fact snapshot structure only.

    This does not check fragment-specific completeness.
    """
    return (
        isinstance(runtime_status, RuntimeFactStatus)
        and runtime_status.structurally_valid
    )

@dataclass(frozen=True)
class RuntimeOperandSemanticFact:
    """
    Phase 6A normalized operand semantic fact extracted from authoritative
    runtime/source binding metadata.

    This DTO should be constructed inside Phase 6A only.
    """

    kind: SourceOperandKind
    access: SourceOperandAccess
    signedness: SourceSignedness

    reads: bool
    writes: bool
    read_before_write: bool

    tied_to_source_operand_index: Optional[int]
    early_clobber: bool

    fixed_register_name: Optional[str]

    expression: Optional[SourceExpressionBinding]
    lvalue: Optional[SourceLvalueBinding]
    address: Optional[SourceAddressBinding]

_INVALID_RUNTIME_BINDING: Final[object] = object()
def _is_valid_source_operand_index(value: object) -> bool:
    """
    Return whether value is a valid GNU inline-asm source operand index.

    bool must be rejected explicitly because bool is a subclass of int.
    """
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def _is_valid_width_bits(value: object) -> bool:
    """
    Return whether value is a structurally valid proven width.

    This validates only the runtime-fact container shape. It does not infer
    target suitability, C type suitability, or x86 register class.
    """
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    )


def _is_valid_riscv_register_identity(value: object) -> bool:
    """
    Validate that the runtime fact contains an explicit register identity.

    This function intentionally does not normalize aliases:

        a0 != x10

    unless assembler normalization explicitly supplied both names in
    rv_to_operand_index.

    No RISC-V ABI alias reconstruction is allowed here.
    """
    return (
        isinstance(value, str)
        and bool(value.strip())
    )

def _runtime_operand_bindings(
    runtime_facts: TranslationRuntimeFacts,
) -> dict[int, object]:
    """
    Return authoritative:

        source_operand_index -> runtime register binding evidence

    Authoritative source:
        TranslationRuntimeFacts.rv_to_operand_index

    Forbidden fallback:
        * SourceShellModel.outputs + SourceShellModel.inputs ordering;
        * AsmFragment.outputs / AsmFragment.inputs ordering;
        * p-code register encounter order;
        * RISC-V ABI alias expansion;
        * serialized fragment JSON bindings;
        * source constraint text.

    Notes:
        The runtime schema is register -> operand-index, so this function
        performs a checked inversion.

        If more than one distinct register maps to the same source operand
        index, that index is omitted from the result. The caller must treat
        this as unavailable/ambiguous authoritative binding and fail closed.
    """
    if not isinstance(runtime_facts, TranslationRuntimeFacts):
        return {}

    rv_to_operand_index = runtime_facts.rv_to_operand_index

    if not isinstance(rv_to_operand_index, Mapping):
        return {}

    result: dict[int, object] = {}
    ambiguous_indices: set[int] = set()

    for register_name, source_operand_index in rv_to_operand_index.items():
        if not _is_valid_riscv_register_identity(register_name):
            continue

        if not _is_valid_source_operand_index(source_operand_index):
            continue

        existing = result.get(
            source_operand_index,
            _INVALID_RUNTIME_BINDING,
        )

        if existing is _INVALID_RUNTIME_BINDING:
            # Preserve the exact runtime-provided register spelling.
            #
            # Do not rewrite:
            #   a0 -> x10
            #   x10 -> a0
            result[source_operand_index] = register_name
            continue

        if existing != register_name:
            # A source operand index cannot safely be represented by one
            # opaque register identity if runtime facts report multiple
            # distinct identities for it.
            #
            # Do not pick first/last. Do not synthesize an alias relation.
            ambiguous_indices.add(source_operand_index)

    for source_operand_index in ambiguous_indices:
        result.pop(source_operand_index, None)

    return result

def _runtime_operand_widths(
    runtime_facts: TranslationRuntimeFacts,
) -> dict[int, int]:
    """
    Return authoritative:

        source_operand_index -> proven host expression width_bits

    Authoritative source:
        TranslationRuntimeFacts.operand_width_bits

    Forbidden fallback:
        * XLEN;
        * target pointer width;
        * target ABI;
        * source shell operand ordering;
        * fragment operand_width_bits;
        * source GCC constraint text;
        * expression text;
        * C cast spelling;
        * register name suffix;
        * RISC-V register class.

    The real runtime schema already keys widths by source operand index.
    No register-based conversion is permitted here.
    """
    if not isinstance(runtime_facts, TranslationRuntimeFacts):
        return {}

    operand_width_bits = runtime_facts.operand_width_bits

    if not isinstance(operand_width_bits, Mapping):
        return {}

    result: dict[int, int] = {}

    for source_operand_index, width_bits in operand_width_bits.items():
        if not _is_valid_source_operand_index(source_operand_index):
            continue

        if not _is_valid_width_bits(width_bits):
            continue

        result[source_operand_index] = width_bits

    return result

def _runtime_operand_semantics(
    runtime_facts: TranslationRuntimeFacts,
    *,
    shell: SourceShellModel,
    authoritative_bindings: dict[int, object],
    memory_address_operand_indexes: set[int],
) -> dict[int, RuntimeOperandSemanticFact]:
    """
    Return runtime operand semantic records.

    The Phase-4 mapping supplies the authoritative *register -> GNU operand
    index* association.  GNU's operand numbering then identifies the source
    shell operand at that index; this adapter does not derive register
    bindings from shell order or p-code encounter order.

    Tied operands are deliberately left unavailable here because the current
    frontend does not provide a structured tie target index.  This keeps such
    fragments fail-closed while allowing ordinary ``=r`` outputs and ``r``
    inputs to enter the registered register-only route.
    """
    if not isinstance(runtime_facts, TranslationRuntimeFacts):
        return {}
    all_operands = shell.all_operands
    result: dict[int, RuntimeOperandSemanticFact] = {}
    for index in authoritative_bindings:
        if index < 0 or index >= len(all_operands):
            continue
        operand = all_operands[index]
        if operand.is_tied:
            continue
        constraint = operand.constraint.strip()
        # This classification only recognizes the small GPR/immediate family
        # that Phase 6C can validate; unknown constraints remain unavailable.
        is_immediate = "i" in constraint or "n" in constraint
        is_fixed = "{" in constraint and "}" in constraint
        kind = (
            SourceOperandKind.FIXED_REGISTER if is_fixed else
            SourceOperandKind.IMMEDIATE if is_immediate else
            SourceOperandKind.REGISTER
        )
        if operand.is_output:
            access = (
                SourceOperandAccess.READ_WRITE
                if "+" in constraint else SourceOperandAccess.OUTPUT
            )
        else:
            access = SourceOperandAccess.INPUT
        if index in memory_address_operand_indexes:
            kind = SourceOperandKind.ADDRESS
            access = SourceOperandAccess.ADDRESS
        reads = access in {SourceOperandAccess.INPUT, SourceOperandAccess.READ_WRITE, SourceOperandAccess.ADDRESS}
        writes = access in {SourceOperandAccess.OUTPUT, SourceOperandAccess.READ_WRITE}
        expression = (
            SourceExpressionBinding(
                expression_id=f"asm-operand:{index}",
                c_type_id=None,
                is_side_effect_free=True,
                is_repeatable=True,
            ) if reads else None
        )
        lvalue = (
            SourceLvalueBinding(
                lvalue_id=f"asm-operand:{index}",
                c_type_id=None,
                is_modifiable=True,
            ) if writes else None
        )
        result[index] = RuntimeOperandSemanticFact(
            kind=kind,
            access=access,
            signedness=SourceSignedness.SIGNLESS,
            reads=reads,
            writes=writes,
            read_before_write=access is SourceOperandAccess.READ_WRITE,
            tied_to_source_operand_index=None,
            early_clobber=operand.is_early_clobber,
            fixed_register_name=None,
            expression=expression,
            lvalue=lvalue,
            address=(SourceAddressBinding(
                address_id=f"canonical-memory-address:{index}",
                pointee_type_id=None,
                alignment_bytes=None,
                provenance_known=True,
            ) if index in memory_address_operand_indexes else None),
        )
    return result


def _memory_address_operand_indexes(*, blocks: Sequence[Block], runtime_facts: TranslationRuntimeFacts) -> set[int]:
    """Recover one transparent memory-address binding inside Phase 6A only.

    Lifting commonly represents ``0(base)`` as a UNIQUE varnode produced by
    ``COPY base`` or ``INT_ADD base, 0`` before the LOAD/STORE.  Those are
    representation-only steps, not a different source address contract.  We
    accept only that deliberately tiny transparent chain.  Any non-zero
    offset, arithmetic, merge, or ambiguous producer remains unmodelled and
    is rejected by the memory lowering path.
    """
    raw_map = getattr(runtime_facts, "rv_to_operand_index", {})
    if not isinstance(raw_map, Mapping):
        return set()
    canonical_map = {
        canonicalize_riscv_register_name(register): index
        for register, index in raw_map.items()
        if canonicalize_riscv_register_name(register)
        and isinstance(index, int) and not isinstance(index, bool)
    }
    memory_ops = [op for block in blocks for instruction in block.instructions
                  for op in instruction.ops if op.opcode in {"LOAD", "STORE"}]
    if len(memory_ops) != 1:
        return set()

    memory_op = memory_ops[0]
    if memory_op.opcode == "LOAD":
        # SLEIGH LOAD has (space, address) inputs.
        if len(memory_op.inputs) != 2:
            return set()
        address = memory_op.inputs[1]
    else:
        # SLEIGH STORE has (space, address, value) inputs.
        if len(memory_op.inputs) != 3:
            return set()
        address = memory_op.inputs[1]

    producers = {
        op.output: op
        for block in blocks
        for instruction in block.instructions
        for op in instruction.ops
        if op.output is not None
    }

    def is_proven_zero(item: object, visiting: set[object]) -> bool:
        """Recognize only width-preserving representations of integer zero.

        RISC-V SLEIGH semantics commonly sign-extend the immediate before
        computing an effective address.  For ``0(base)`` this yields a UNIQUE
        ``INT_SEXT(const:0)`` rather than a direct constant input to
        ``INT_ADD``.  Zero remains zero through these listed data-flow nodes;
        every other expression, including a non-zero offset, stays rejected.
        """
        if getattr(item, "kind", None) is VarKind.CONST:
            return getattr(item, "offset", None) == 0
        if item in visiting:
            return False
        producer = producers.get(item)
        if producer is None:
            return False
        next_visiting = visiting | {item}
        if producer.opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
            return (
                len(producer.inputs) == 1
                and is_proven_zero(producer.inputs[0], next_visiting)
            )
        if producer.opcode == "PIECE":
            return (
                len(producer.inputs) == 2
                and all(is_proven_zero(value, next_visiting) for value in producer.inputs)
            )
        return False

    def resolve_transparent_register(item: object, visiting: set[object]) -> set[str]:
        if getattr(item, "kind", None) is VarKind.REG:
            name = getattr(item, "name", "")
            return {canonicalize_riscv_register_name(name)} if isinstance(name, str) and name.strip() else set()
        if item in visiting:
            return set()
        producer = producers.get(item)
        if producer is None:
            return set()
        if producer.opcode == "COPY" and len(producer.inputs) == 1:
            return resolve_transparent_register(producer.inputs[0], visiting | {item})
        if producer.opcode == "INT_ADD" and len(producer.inputs) == 2:
            left, right = producer.inputs
            if is_proven_zero(left, set()):
                return resolve_transparent_register(right, visiting | {item})
            if is_proven_zero(right, set()):
                return resolve_transparent_register(left, visiting | {item})
        return set()

    registers = resolve_transparent_register(address, set())
    if len(registers) != 1:
        return set()
    operand_index = canonical_map.get(next(iter(registers)))
    return set() if operand_index is None else {operand_index}

def _runtime_fact_structural_errors(
    runtime_facts: TranslationRuntimeFacts,
) -> tuple[str, ...]:
    """
    Validate the concrete TranslationRuntimeFacts schema.

    This checks only runtime-fact structural correctness.

    It does not decide whether the facts are complete for the current
    fragment. Completeness depends on actually-used RISC-V registers and
    plan-required source operand indexes.
    """
    if not isinstance(runtime_facts, TranslationRuntimeFacts):
        return (
            "runtime_facts_not_translation_runtime_facts",
        )

    errors: list[str] = []

    rv_to_operand_index = runtime_facts.rv_to_operand_index
    if not isinstance(rv_to_operand_index, Mapping):
        errors.append("rv_to_operand_index_not_mapping")
    else:
        seen_operand_indexes: dict[int, str] = {}

        for register_name, source_operand_index in (
            rv_to_operand_index.items()
        ):
            if not _is_valid_riscv_register_identity(register_name):
                errors.append(
                    "rv_to_operand_index_contains_invalid_register_identity"
                )
                continue

            if not _is_valid_source_operand_index(source_operand_index):
                errors.append(
                    "rv_to_operand_index_contains_invalid_operand_index"
                )
                continue

            previous_register = seen_operand_indexes.get(
                source_operand_index
            )
            if (
                previous_register is not None
                and previous_register != register_name
            ):
                errors.append(
                    "rv_to_operand_index_has_ambiguous_reverse_binding"
                )
                continue

            seen_operand_indexes[source_operand_index] = register_name

    operand_width_bits = runtime_facts.operand_width_bits
    if not isinstance(operand_width_bits, Mapping):
        errors.append("operand_width_bits_not_mapping")
    else:
        for source_operand_index, width_bits in (
            operand_width_bits.items()
        ):
            if not _is_valid_source_operand_index(source_operand_index):
                errors.append(
                    "operand_width_bits_contains_invalid_operand_index"
                )
                continue

            if not _is_valid_width_bits(width_bits):
                errors.append(
                    "operand_width_bits_contains_invalid_width"
                )

    return tuple(sorted(set(errors)))

def _build_operation_model(
    *,
    shell: SourceShellModel,
    control_flow: SourceControlFlowModel,
    memory: SourceMemoryModel,
    operands: SourceOperandModel,
    preservation_input_summary: IRSummary,
) -> SourceOperationModel:
    """
    Build semantic operation category from structured source analysis.

    This helper may inspect IRSummary only inside Phase 6A.
    """
    has_control_flow = any(
        (
            control_flow.has_internal_branch,
            control_flow.has_call,
            control_flow.has_return is True,
            control_flow.has_asm_goto,
            control_flow.has_external_control_flow,
            control_flow.has_multiple_exits,
            control_flow.has_non_local_control_dependency,
        )
    )

    if memory.has_atomic:
        kind = SourceOperationKind.OPAQUE
    elif memory.has_memory_barrier or memory.has_instruction_barrier:
        kind = SourceOperationKind.HARDWARE_BARRIER
    elif memory.reads_memory and memory.writes_memory:
        kind = SourceOperationKind.MEMORY_READ_MODIFY_WRITE
    elif memory.reads_memory:
        kind = SourceOperationKind.LOAD
    elif memory.writes_memory:
        kind = SourceOperationKind.STORE
    elif shell.has_memory_clobber:
        kind = SourceOperationKind.COMPILER_BARRIER
    elif control_flow.has_call:
        kind = SourceOperationKind.CALL
    elif control_flow.has_return is True:
        kind = SourceOperationKind.RETURN
    elif has_control_flow:
        kind = SourceOperationKind.CONTROL_FLOW
    else:
        kind = SourceOperationKind.REGISTER_ONLY

    complete = not any(
        (
            memory.has_unknown_barrier,
            control_flow.has_unknown_target,
            control_flow.has_indirect_control_flow is None,
        )
    )

    proven_straight_line_value_semantics = (
        kind is SourceOperationKind.REGISTER_ONLY
        and preservation_input_summary.is_single_block
        and preservation_input_summary.has_return is False
        and preservation_input_summary.has_tail_call is False
        and preservation_input_summary.has_indirect_control_flow is False
        and preservation_input_summary.has_timing_source is False
        and preservation_input_summary.has_cache_operation is False
        and preservation_input_summary.has_speculation_control is False
    )
    proven_direct_memory_semantics = (
        kind in {SourceOperationKind.LOAD, SourceOperationKind.STORE}
        and any(item.kind is SourceOperandKind.ADDRESS and item.address is not None and item.address.provenance_known for item in operands.operands)
        and preservation_input_summary.is_single_block
        and preservation_input_summary.has_return is False
        and preservation_input_summary.has_tail_call is False
        and preservation_input_summary.has_indirect_control_flow is False
        and preservation_input_summary.has_timing_source is False
        and preservation_input_summary.has_cache_operation is False
        and preservation_input_summary.has_speculation_control is False
    )

    return SourceOperationModel(
        kind=kind,

        reads_memory=memory.reads_memory,
        writes_memory=memory.writes_memory,

        has_control_flow=has_control_flow,
        has_call=control_flow.has_call,
        has_return=control_flow.has_return,
        # A fully modelled asm-goto branch with no memory operation has no
        # architectural faulting access in the current narrow route.  All
        # other operation kinds retain unknown and therefore fail closed.
        may_trap=(False if ((control_flow.has_asm_goto and
                             control_flow.asm_goto_condition_kind in {"zero", "nonzero"} and
                             control_flow.asm_goto_condition_operand_index is not None and
                             not memory.reads_memory and
                             not memory.writes_memory and
                             not control_flow.has_call)
                            or proven_straight_line_value_semantics
                            or proven_direct_memory_semantics)
                  else None),

        requires_helper_abi_contract=(
            control_flow.has_call
            or control_flow.has_tail_call is True
        ),
        complete=complete,
    )


def _build_add_then_shift_left_operation_model(
    *,
    blocks: Sequence[Block], runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel, operation: SourceOperationModel,
) -> SourceValueOperationModel | None:
    """Recognize one fully-modelled ``add; sll immediate`` value sequence.

    This adapter consumes canonical p-code and Phase-4 register bindings only.
    It intentionally rejects any extra arithmetic, memory, CFG, or ambiguous
    copy graph, so a later renderer never has to reconstruct the sequence.
    """
    if (operation.kind is not SourceOperationKind.REGISTER_ONLY or
            operation.may_trap is not False or not operands.complete or
            len(blocks) != 1 or not runtime_status.structurally_valid):
        return None
    items = [item for item in blocks[0].ops
             if getattr(item, "opcode", "").upper() != "IMARK"]
    adds = [item for item in items if getattr(item, "opcode", "").upper() == "INT_ADD"]
    shifts = [item for item in items if getattr(item, "opcode", "").upper() == "INT_LEFT"]
    copies = [item for item in items if getattr(item, "opcode", "").upper() == "COPY"]
    if len(adds) != 1 or len(shifts) != 1 or len(adds) + len(shifts) + len(copies) != len(items):
        return None
    add, shift = adds[0], shifts[0]
    if (getattr(add, "output", None) is None or getattr(shift, "output", None) is None or
            len(add.inputs) != 2 or len(shift.inputs) != 2):
        return None
    copy_source: dict[object, object] = {}
    for copy in copies:
        out, ins = getattr(copy, "output", None), getattr(copy, "inputs", ())
        if (out is None or len(ins) != 1 or out in copy_source or
                getattr(out, "kind", None) is VarKind.CONST or
                getattr(out, "size", None) != getattr(ins[0], "size", None)):
            return None
        copy_source[out] = ins[0]
    def resolve(var: object) -> object | None:
        seen: set[object] = set(); current = var
        while current in copy_source:
            if current in seen:
                return None
            seen.add(current); current = copy_source[current]
        return current
    reg_to_index: dict[str, int] = {}
    for register, index in runtime_status.rv_to_operand_index.items():
        canonical = canonicalize_riscv_register_name(register)
        if not canonical or canonical in reg_to_index:
            return None
        reg_to_index[canonical] = index
    def index_of(var: object) -> int | None:
        if getattr(var, "kind", None) is not VarKind.REG:
            return None
        return reg_to_index.get(canonicalize_riscv_register_name(getattr(var, "name", "")))
    def produced_index(value: object) -> int | None:
        indexes = {index_of(candidate) for candidate in (value, *copy_source)
                   if resolve(candidate) == value and index_of(candidate) is not None}
        return next(iter(indexes)) if len(indexes) == 1 else None
    tmp_index, result_index = produced_index(add.output), produced_index(shift.output)
    if tmp_index is None or result_index is None or tmp_index == result_index:
        return None
    if resolve(shift.inputs[0]) != add.output:
        return None
    amount = resolve(shift.inputs[1])
    if amount is None or getattr(amount, "kind", None) is not VarKind.CONST:
        return None
    raw, size = getattr(amount, "offset", None), getattr(amount, "size", None)
    if (isinstance(raw, bool) or not isinstance(raw, int) or isinstance(size, bool) or
            not isinstance(size, int) or size <= 0):
        return None
    shift_amount = raw & ((1 << (size * 8)) - 1)
    input_indexes = tuple(index_of(resolve(item)) for item in add.inputs)
    if any(index is None for index in input_indexes) or len(set(input_indexes)) != 2:
        return None
    by_index = {item.source_operand_index: item for item in operands.operands}
    tmp, result = by_index.get(tmp_index), by_index.get(result_index)
    inputs = [by_index.get(index) for index in input_indexes]
    if (tmp is None or result is None or tmp.access is not SourceOperandAccess.OUTPUT or
            result.access is not SourceOperandAccess.OUTPUT or not tmp.early_clobber or
            result.early_clobber or tmp.width_bits not in {32, 64} or
            result.width_bits != tmp.width_bits or shift_amount >= tmp.width_bits or
            any(item is None or item.access is not SourceOperandAccess.INPUT or
                item.width_bits != tmp.width_bits for item in inputs)):
        return None
    return SourceValueOperationModel(
        kind=SourceValueOperationKind.ADD_THEN_SHIFT_LEFT_IMMEDIATE,
        input_operand_indexes=tuple(input_indexes), result_operand_index=result_index,
        complete=True, immediate_value=shift_amount,
        temporary_operand_index=tmp_index,
    )


def _build_value_operation_model(
    *,
    blocks: Sequence[Block],
    runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel,
    operation: SourceOperationModel,
) -> SourceValueOperationModel | None:
    """Derive a narrow value contract from canonical p-code only.

    This is a Phase-6A adapter: it consumes canonical ``Block.ops`` and the
    authoritative Phase-4 register-to-operand mapping.  It never reads raw
    asm text, an instruction mnemonic, or renderer output.  The first family
    is intentionally limited to one direct 32/64-bit register binary op.
    """
    sequence = _build_add_then_shift_left_operation_model(
        blocks=blocks, runtime_status=runtime_status, operands=operands,
        operation=operation,
    )
    if sequence is not None:
        return sequence
    if (
        operation.kind is not SourceOperationKind.REGISTER_ONLY
        or operation.may_trap is not False
        or not operands.complete
        or len(blocks) != 1
        or not runtime_status.structurally_valid
    ):
        return None

    # A lifter may route an instruction result through UNIQUE temporaries and
    # final ``COPY`` operations.  COPY is explicitly admitted as pure integer
    # bookkeeping by the canonical summary producer, so Phase 6A must not
    # contradict that contract by counting it as a second value operation.
    # Only exact width-preserving alias chains are accepted here; any other
    # auxiliary p-code remains unmodelled and therefore fails closed.
    canonical_ops = [
        item for item in blocks[0].ops
        if getattr(item, "opcode", "").upper() != "IMARK"
    ]
    value_kind_by_opcode = {
        "INT_ADD": SourceValueOperationKind.UNSIGNED_ADD,
        "INT_SUB": SourceValueOperationKind.UNSIGNED_SUB,
        "INT_AND": SourceValueOperationKind.BIT_AND,
        "INT_OR": SourceValueOperationKind.BIT_OR,
        "INT_XOR": SourceValueOperationKind.BIT_XOR,
    }
    value_ops = [
        item for item in canonical_ops
        if getattr(item, "opcode", "").upper() in value_kind_by_opcode
    ]
    copy_ops = [
        item for item in canonical_ops
        if getattr(item, "opcode", "").upper() == "COPY"
    ]
    if len(value_ops) != 1 or len(value_ops) + len(copy_ops) != len(canonical_ops):
        return None
    op = value_ops[0]
    kind = value_kind_by_opcode.get(getattr(op, "opcode", "").upper())
    if kind is None or getattr(op, "output", None) is None or len(op.inputs) != 2:
        return None

    copy_source_by_output: dict[object, object] = {}
    for copy in copy_ops:
        copy_output = getattr(copy, "output", None)
        copy_inputs = getattr(copy, "inputs", ())
        if (
            copy_output is None
            or len(copy_inputs) != 1
            or getattr(copy_output, "kind", None) is VarKind.CONST
            or getattr(copy_output, "size", None) != getattr(copy_inputs[0], "size", None)
            or copy_output in copy_source_by_output
        ):
            return None
        copy_source_by_output[copy_output] = copy_inputs[0]

    def resolve_copy_source(var: object) -> object | None:
        seen: set[object] = set()
        current = var
        while current in copy_source_by_output:
            if current in seen:
                return None
            seen.add(current)
            current = copy_source_by_output[current]
        return current

    register_to_operand: dict[str, int] = {}
    for register, index in runtime_status.rv_to_operand_index.items():
        canonical = canonicalize_riscv_register_name(register)
        if not canonical or canonical in register_to_operand:
            return None
        register_to_operand[canonical] = index

    def operand_index(var: object) -> int | None:
        if getattr(var, "kind", None) is not VarKind.REG:
            return None
        canonical = canonicalize_riscv_register_name(getattr(var, "name", ""))
        return register_to_operand.get(canonical)

    # Identify the host output register after transparent COPY propagation.
    # A single primary operation must have exactly one registered host output.
    result_indexes = {
        index
        for candidate in (getattr(op, "output", None), *copy_source_by_output)
        if resolve_copy_source(candidate) == op.output
        for index in (operand_index(candidate),)
        if index is not None
    }
    if len(result_indexes) != 1:
        return None
    result_index = next(iter(result_indexes))
    by_index = {item.source_operand_index: item for item in operands.operands}
    result = by_index.get(result_index)
    if (
        result is None
        or result.access is not SourceOperandAccess.OUTPUT
        or result.width_bits not in {32, 64}
    ):
        return None

    input_indexes: list[int] = []
    constants: list[tuple[int, object]] = []
    for input_position, input_var in enumerate(op.inputs):
        resolved_input = resolve_copy_source(input_var)
        if resolved_input is None:
            return None
        index = operand_index(resolved_input)
        if index is not None:
            input_indexes.append(index)
        elif getattr(resolved_input, "kind", None) is VarKind.CONST:
            constants.append((input_position, resolved_input))
        else:
            return None
    if len(constants) > 1 or len(input_indexes) not in {1, 2}:
        return None
    if constants and len(input_indexes) != 1:
        return None
    inputs = tuple(by_index.get(item) for item in input_indexes)
    if any(item is None or item.access is not SourceOperandAccess.INPUT
           or item.width_bits != result.width_bits for item in inputs):
        return None

    immediate_value: int | None = None
    if constants:
        constant_position, constant = constants[0]
        # Subtraction is not commutative.  The registered x86 recipe has the
        # source register as its first operand and the immediate as second.
        if kind is SourceValueOperationKind.UNSIGNED_SUB and constant_position != 1:
            return None
        raw_value = getattr(constant, "offset", None)
        byte_size = getattr(constant, "size", None)
        if (
            isinstance(raw_value, bool)
            or not isinstance(raw_value, int)
            or isinstance(byte_size, bool)
            or not isinstance(byte_size, int)
            or byte_size <= 0
            or byte_size * 8 > result.width_bits
        ):
            return None
        constant_width_bits = byte_size * 8
        mask = (1 << constant_width_bits) - 1
        raw_value &= mask
        immediate_value = (
            raw_value - (1 << constant_width_bits)
            if raw_value & (1 << (constant_width_bits - 1))
            else raw_value
        )
        # x86-64 ALU immediate encodings sign-extend an imm32.  Restricting
        # this contract to that exact shared value domain prevents a renderer
        # from silently changing a 64-bit source constant's upper bits.
        if not -(1 << 31) <= immediate_value <= (1 << 31) - 1:
            return None
    return SourceValueOperationModel(
        kind=kind,
        input_operand_indexes=tuple(input_indexes),
        result_operand_index=result_index,
        complete=True,
        immediate_value=immediate_value,
    )

def _build_atomic_operation_model(
    *,
    summary: IRSummary,
    memory: SourceMemoryModel,
    operands: SourceOperandModel,
) -> SourceAtomicOperationModel:
    """
    Build structured atomic facts.

    Important:
        This implementation intentionally does not inspect
        memory.atomic_mnemonics.

    If IRSummary does not yet expose structured atomic kind / width /
    operand-role / success-failure ordering facts, the result remains
    incomplete and Phase 6C must reject atomic candidates.
    """
    if not memory.has_atomic:
        return SourceAtomicOperationModel(
            present=False,
            kind=None,
            rmw_operation=None,
            width_bits=None,
            alignment_bytes=None,
            address_operand_index=None,
            value_operand_index=None,
            expected_operand_index=None,
            desired_operand_index=None,
            result_operand_index=None,
            success_ordering=None,
            failure_ordering=None,
            lock_free_required=None,
            complete=True,
        )

    structured_atomic = getattr(
        summary,
        "atomic_semantics",
        None,
    )

    if structured_atomic is None:
        return SourceAtomicOperationModel(
            present=True,
            kind=None,
            rmw_operation=None,
            width_bits=None,
            alignment_bytes=None,
            address_operand_index=None,
            value_operand_index=None,
            expected_operand_index=None,
            desired_operand_index=None,
            result_operand_index=None,
            success_ordering=None,
            failure_ordering=None,
            lock_free_required=None,
            complete=False,
        )

    # The following field names are an explicit required IRSummary contract.
    # Adjust only this adapter if your actual normalized summary names differ.
    return SourceAtomicOperationModel(
        present=True,
        kind=getattr(structured_atomic, "kind", None),
        rmw_operation=getattr(structured_atomic, "rmw_operation", None),
        width_bits=getattr(structured_atomic, "width_bits", None),
        alignment_bytes=getattr(
            structured_atomic,
            "alignment_bytes",
            None,
        ),
        address_operand_index=getattr(
            structured_atomic,
            "address_operand_index",
            None,
        ),
        value_operand_index=getattr(
            structured_atomic,
            "value_operand_index",
            None,
        ),
        expected_operand_index=getattr(
            structured_atomic,
            "expected_operand_index",
            None,
        ),
        desired_operand_index=getattr(
            structured_atomic,
            "desired_operand_index",
            None,
        ),
        result_operand_index=getattr(
            structured_atomic,
            "result_operand_index",
            None,
        ),
        success_ordering=getattr(
            structured_atomic,
            "success_ordering",
            None,
        ),
        failure_ordering=getattr(
            structured_atomic,
            "failure_ordering",
            None,
        ),
        lock_free_required=getattr(
            structured_atomic,
            "lock_free_required",
            None,
        ),
        complete=bool(
            getattr(
                structured_atomic,
                "complete",
                False,
            )
        ),
    )

def _build_barrier_model(
    *,
    shell: SourceShellModel,
    memory: SourceMemoryModel,
    microarch: SourceMicroArchModel,
    summary: IRSummary,
) -> SourceBarrierModel:
    """
    Build structured barrier semantics.

    A memory clobber means compiler barrier semantics.
    It is not sufficient evidence for hardware fence semantics.
    """
    present = any(
        (
            shell.has_memory_clobber,
            memory.has_memory_barrier,
            memory.has_instruction_barrier,
            memory.has_unknown_barrier,
        )
    )

    if not present:
        return SourceBarrierModel(
            present=False,
            compiler_barrier=False,
            hardware_memory_barrier=False,
            instruction_serializing=False,
            speculation_control=False,
            ordering=None,
            scope=None,
            complete=True,
        )

    if memory.has_unknown_barrier:
        return SourceBarrierModel(
            present=True,
            compiler_barrier=shell.has_memory_clobber,
            hardware_memory_barrier=memory.has_memory_barrier,
            instruction_serializing=memory.has_instruction_barrier,
            speculation_control=False,
            ordering=None,
            scope=None,
            complete=False,
        )

    structured_barrier = getattr(
        summary,
        "barrier_semantics",
        None,
    )

    # ``IRSummary.barrier_info`` is Phase-5's typed, single-instruction
    # source barrier contract.  It is deliberately consumed here, at the
    # Phase-6A boundary, rather than re-reading a source asm mnemonic later.
    #
    # The only automatic hardware-fence route is the narrow, architecture
    # defined ``fence rw,rw`` case.  Its R/W predecessor and successor sets
    # are both complete, and the selected x86 ``mfence`` plan is explicitly a
    # system-scope seq_cst strengthening.  Directional fences, I/O fences,
    # fence.tso, fence.i, multiple barriers and incomplete metadata retain the
    # existing fail-closed path.
    summary_barrier = getattr(summary, "barrier_info", None)
    full_rw_fence = bool(
        structured_barrier is None
        and summary_barrier is not None
        and getattr(summary_barrier, "kind", None) is BarrierKind.MEMORY_FENCE
        and getattr(summary_barrier, "semantics_complete", False)
        and getattr(summary_barrier, "pred_mask", FenceSet.NONE)
            == (FenceSet.R | FenceSet.W)
        and getattr(summary_barrier, "succ_mask", FenceSet.NONE)
            == (FenceSet.R | FenceSet.W)
    )

    if full_rw_fence:
        return SourceBarrierModel(
            present=True,
            # This preserves an explicit GNU ``memory`` clobber.  It must not
            # be confused with the hardware-fence fact below.
            compiler_barrier=shell.has_memory_clobber,
            hardware_memory_barrier=True,
            instruction_serializing=False,
            speculation_control=False,
            ordering=SourceMemoryOrdering.SEQ_CST,
            scope=SourceBarrierScope.SYSTEM,
            complete=True,
        )

    if structured_barrier is None:
        return SourceBarrierModel(
            present=True,
            compiler_barrier=shell.has_memory_clobber,
            hardware_memory_barrier=memory.has_memory_barrier,
            instruction_serializing=memory.has_instruction_barrier,
            speculation_control=False,
            ordering=None,
            scope=(
                SourceBarrierScope.COMPILER
                if shell.has_memory_clobber
                and not memory.has_memory_barrier
                else None
            ),
            complete=(
                shell.has_memory_clobber
                and not memory.has_memory_barrier
                and not memory.has_instruction_barrier
            ),
        )

    return SourceBarrierModel(
        present=True,
        compiler_barrier=bool(
            shell.has_memory_clobber
            or getattr(
                structured_barrier,
                "compiler_barrier",
                False,
            )
        ),
        hardware_memory_barrier=bool(
            getattr(
                structured_barrier,
                "hardware_memory_barrier",
                memory.has_memory_barrier,
            )
        ),
        instruction_serializing=bool(
            getattr(
                structured_barrier,
                "instruction_serializing",
                memory.has_instruction_barrier,
            )
        ),
        speculation_control=bool(
            getattr(
                structured_barrier,
                "speculation_control",
                False,
            )
        ),
        ordering=getattr(
            structured_barrier,
            "ordering",
            None,
        ),
        scope=getattr(
            structured_barrier,
            "scope",
            None,
        ),
        complete=bool(
            getattr(
                structured_barrier,
                "complete",
                False,
            )
        ),
    )

def _build_implicit_state_model(
    *,
    shell: SourceShellModel,
    registers: SourceRegisterModel,
) -> SourceImplicitStateModel:
    """
    Build implicit architectural-state semantic facts.

    This implementation is intentionally conservative:
      * shell.has_cc_clobber is authoritative shell evidence for cc write;
      * stack/frame pointer effects are derived from structured register model;
      * unrecognized implicit machine state remains incomplete.
    """
    reads_stack_pointer = (
        "sp" in registers.reads_registers
        or "x2" in registers.reads_registers
    )
    writes_stack_pointer = (
        "sp" in registers.writes_registers
        or "x2" in registers.writes_registers
    )

    reads_frame_pointer = (
        "fp" in registers.reads_registers
        or "s0" in registers.reads_registers
        or "x8" in registers.reads_registers
    )
    writes_frame_pointer = (
        "fp" in registers.writes_registers
        or "s0" in registers.writes_registers
        or "x8" in registers.writes_registers
    )

    # General RISC-V GPR reads/writes are explicit value operands, not
    # implicit machine state.  Treating a0/a1/a2 as "special" incorrectly
    # blocks every ordinary register-only lowering.  Stack/frame and shell
    # cc effects remain explicit above; genuinely unmodelled special state is
    # represented by unresolved-register analysis rather than a GPR list.
    special_reads: tuple[str, ...] = ()
    special_writes: tuple[str, ...] = ()

    return SourceImplicitStateModel(
        reads_condition_codes=False,
        writes_condition_codes=shell.has_cc_clobber,

        reads_stack_pointer=reads_stack_pointer,
        writes_stack_pointer=writes_stack_pointer,

        reads_frame_pointer=reads_frame_pointer,
        writes_frame_pointer=writes_frame_pointer,

        reads_implicit_machine_state=False,
        writes_implicit_machine_state=shell.has_cc_clobber,

        reads_special_register_names=special_reads,
        writes_special_register_names=special_writes,

        complete=not registers.has_unresolved_register_identity,
    )
