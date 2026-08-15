# translator/phase6/source_model.py
from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import FrozenSet, Iterable, Mapping, Optional, Sequence, Set, Tuple, Union
from enum import Enum
try:
    from .cfg import CFGResult
    from .pcode_ir import BarrierKind, Block, FenceSet, IRSummary, VarKind, StackFrameSemantics, StackFrameClassification, StackAddressBase, PrivateFrameLayoutFacts, StackAccessKind
    from .runtime_facts import TranslationRuntimeFacts, canonicalize_riscv_register_name
    from .schema import AsmFragment
    from .stack_rebinding import StackAddressRebindingFacts, SourceStackRebindingAccess
    from .abi_effects import SourceAbiCallBinding, SourceAbiEffectModel, build_abi_effects, collect_canonical_call_sites
    from .whole_function import WholeFunctionRouteDecision, classify_whole_function_route
    from .privileged_state_analysis import SourcePrivilegedStateModel
    from .functional_observability import FunctionalObservabilityContract
    from .privileged_state_adapter import (
        SourcePrivilegedAccessModel, SourcePrivilegedSemanticModel,
        SourceReadOnlyCounterCsrModel, SourceReadOnlyCsrModel,
        build_privileged_state_adapter,
    )
except ImportError:  # pragma: no cover - direct-module compatibility
    from cfg import CFGResult
    from pcode_ir import BarrierKind, Block, FenceSet, IRSummary, VarKind, StackFrameSemantics, StackFrameClassification, StackAddressBase, PrivateFrameLayoutFacts, StackAccessKind
    from runtime_facts import TranslationRuntimeFacts, canonicalize_riscv_register_name
    from schema import AsmFragment
    from stack_rebinding import StackAddressRebindingFacts, SourceStackRebindingAccess
    from abi_effects import SourceAbiCallBinding, SourceAbiEffectModel, build_abi_effects, collect_canonical_call_sites
    from whole_function import WholeFunctionRouteDecision, classify_whole_function_route
    from privileged_state_analysis import SourcePrivilegedStateModel
    from functional_observability import FunctionalObservabilityContract
    from privileged_state_adapter import (
        SourcePrivilegedAccessModel, SourcePrivilegedSemanticModel,
        SourceReadOnlyCounterCsrModel, SourceReadOnlyCsrModel,
        build_privileged_state_adapter,
    )

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
class SourceLocalBranchSelectModel:
    """Canonical local two-way value selection proven in Phase 6A.

    This is deliberately distinct from ``asm goto``: both branch arms remain
    inside the inline-assembly fragment and merge into one declared output.
    No source label spelling or source-template order is retained here.
    """
    condition_kind: "SourceValueOperationKind"
    left_operand_index: int
    right_operand_index: int
    true_value_operand_index: int
    false_value_operand_index: int
    result_operand_index: int
    width_bits: int


@dataclass(frozen=True)
class SourceLocalUnconditionalJumpModel:
    """A direct local jump whose sole reachable effect is one bound copy.

    This is deliberately a CFG proof object, not a recognition of a source
    ``j`` spelling.  The entry must have exactly one direct successor, that
    successor must copy one declared input to one declared output, and no
    other fragment block may be reachable from the entry.
    """
    selected_input_operand_index: int
    result_operand_index: int
    width_bits: int
    entry_block_address: int
    target_block_address: int


class SourceStackFrameKind(str, Enum):
    """Phase-6A classification of source stack/frame semantics.

    The classification describes the *source logical frame*, never the host
    compiler's physical stack.  In particular, a non-NONE classification must
    not be lowered by writing x86 %rsp/%rbp from ordinary GNU inline asm.
    """

    NONE = "none"
    ADDRESS_ONLY = "address_only"
    PRIVATE_BALANCED = "private_balanced"
    CALL_FRAME = "call_frame"
    WHOLE_FUNCTION = "whole_function"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class SourcePrivateFrameAccess:
    source_block_address:int; source_operation_index:int
    source_offset_bytes:int; virtual_offset_bytes:int
    width_bits:int; required_alignment_bytes:int; access:StackAccessKind
    signed_load:bool|None; value_operand_index:int|None
    definitely_initialized_before_read:bool; complete:bool

@dataclass(frozen=True)
class SourceVirtualPrivateFrameModel:
    frame_size_bytes:int; required_alignment_bytes:int
    source_frame_start_offset_bytes:int; source_frame_end_offset_bytes:int
    accesses:Tuple[SourcePrivateFrameAccess,...]
    initialization_complete:bool; overlap_complete:bool; layout_complete:bool
    no_address_escape_proven:bool; no_real_stack_identity_required:bool
    complete:bool; missing_fact_codes:Tuple[str,...]=()


@dataclass(frozen=True)
class SourceStackFrameModel:
    """Structured stack/frame facts owned by Phase 6A.

    Phase 6B-F may route and prove these facts, but may not recreate them from
    mnemonics, raw p-code, or rendered target code.  ``UNKNOWN`` is an
    intentional fail-closed result, not a request to use the target stack.
    """

    kind: SourceStackFrameKind
    frame_size_bytes: int | None = None
    required_alignment_bytes: int | None = None
    net_stack_delta_bytes: int | None = None
    pointer_escapes: bool = False
    requires_real_stack_identity: bool = False
    complete: bool = False
    initial_sp_origin: str = "unknown"
    source_abi_alignment_bytes: int | None = None
    accesses: Tuple[object, ...] = ()
    adjustments: Tuple[object, ...] = ()
    escape_facts: object | None = None
    has_dynamic_adjustment: bool = False
    rebinding_accesses: Tuple[SourceStackRebindingAccess, ...] = ()
    stack_address_rebinding_eligible: bool = False
    virtual_private_frame: SourceVirtualPrivateFrameModel | None = None
    virtual_private_frame_eligible: bool = False
    missing_fact_codes: Tuple[str, ...] = ()
    pointer_uses: Tuple[object, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SourceStackFrameKind):
            raise TypeError("kind must be SourceStackFrameKind")
        for name in ("frame_size_bytes", "required_alignment_bytes"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
                raise ValueError(f"{name} must be a positive int or None")
        if self.net_stack_delta_bytes is not None and (isinstance(self.net_stack_delta_bytes, bool) or not isinstance(self.net_stack_delta_bytes, int)):
            raise TypeError("net_stack_delta_bytes must be an int or None")
        if not isinstance(self.pointer_escapes, bool) or not isinstance(self.requires_real_stack_identity, bool) or not isinstance(self.complete, bool):
            raise TypeError("stack-frame flags must be bool")
        if self.kind is SourceStackFrameKind.NONE and not self.complete:
            raise ValueError("NONE stack-frame model must be complete")
        if self.kind is SourceStackFrameKind.PRIVATE_BALANCED:
            if (not self.complete or self.frame_size_bytes is None or
                    self.required_alignment_bytes is None or
                    self.net_stack_delta_bytes != 0 or self.pointer_escapes or
                    self.requires_real_stack_identity):
                raise ValueError("PRIVATE_BALANCED requires a closed balanced logical frame")
        if not self.complete and not self.missing_fact_codes:
            raise ValueError("incomplete stack-frame model needs reason codes")

    @property
    def requires_whole_function_lowering(self) -> bool:
        return self.kind in {SourceStackFrameKind.CALL_FRAME, SourceStackFrameKind.WHOLE_FUNCTION}

    @property
    def is_local_virtual_frame_candidate(self) -> bool:
        return self.kind is SourceStackFrameKind.PRIVATE_BALANCED


@dataclass(frozen=True)
class SourceMemoryModel:
    """
    Structured source memory semantic snapshot.
    """

    reads_memory: bool
    writes_memory: bool

    has_memory_barrier: bool
    has_instruction_barrier: bool
    instruction_stream_sync_noop_proven: bool
    instruction_stream_sync_proof_id: str | None
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
    # A finite, canonical straight-line register program.  Unlike
    # ``value_operation`` it can retain multiple observable values and their
    # data dependencies without exposing raw p-code to Phase 6B-F.
    value_program: SourceStraightLineValueProgram | None
    local_branch_select: SourceLocalBranchSelectModel | None
    local_unconditional_jump: SourceLocalUnconditionalJumpModel | None
    privileged_state: SourcePrivilegedSemanticModel | None
    # Optional only for constructor compatibility with older callers.  Phase
    # 6A always supplies it; a missing value is treated as UNKNOWN whenever
    # stack/frame registers are observed.
    stack_frame: SourceStackFrameModel | None = None
    # Phase-5 typed call-boundary facts.  This is deliberately independent
    # from stack-frame facts and is the sole input for ABI wrapper lowering.
    abi_effects: SourceAbiEffectModel | None = None
    whole_function_route: WholeFunctionRouteDecision | None = None

    @property
    def read_only_csr(self) -> SourceReadOnlyCounterCsrModel | None:
        """Compatibility view of the nested privileged counter model."""
        if self.privileged_state is None:
            return None
        return self.privileged_state.read_only_counter

    @property
    def phase6b_candidate_facts(self):
        """Return the Phase-6A-owned, immutable input contract for Phase 6B.

        The import is intentionally lazy: candidate_plans imports this module,
        while this authoritative Phase-6A adapter constructs its DTO.
        Phase 6B must not reconstruct these facts from lower-level artifacts.
        """
        from .candidate_plans import Phase6BCandidateFacts

        stack_frame = self.stack_frame
        # sp/fp themselves are deliberately not GNU operands on this route;
        # their accesses are covered by a stronger object-binding witness.
        missing_non_stack_bindings = tuple(x for x in self.completeness.missing_operand_binding_registers
                                           if x not in _STACK_REGISTERS | _FRAME_REGISTERS)
        missing_non_stack_widths = tuple(x for x in self.completeness.missing_operand_width_registers
                                         if x not in _STACK_REGISTERS | _FRAME_REGISTERS)
        operand_facts_complete = (
            (self.operands.complete or (stack_frame is not None and (stack_frame.stack_address_rebinding_eligible or stack_frame.virtual_private_frame_eligible)))
            and self.completeness.runtime_facts_structurally_valid
            and not missing_non_stack_bindings
            and not missing_non_stack_widths
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
        stack_frame_unknown = (
            (self.registers.reads_or_writes_stack_pointer or
             self.registers.reads_or_writes_frame_pointer) and
            (stack_frame is None or not stack_frame.complete or
             stack_frame.kind is SourceStackFrameKind.UNKNOWN)
        )
        private_frame_route = stack_frame is not None and stack_frame.virtual_private_frame_eligible
        abi_wrapper_route = self.abi_effects is not None and self.abi_effects.complete
        unmodelled = any((
            not self.operation.complete and not private_frame_route and not abi_wrapper_route,
            not self.implicit_state.complete and not private_frame_route and not abi_wrapper_route,
            self.memory.has_unknown_barrier,
            self.registers.has_unresolved_register_identity,
            control_unknown and not private_frame_route and not abi_wrapper_route,
            stack_frame_unknown,
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
            has_private_balanced_stack_frame=(
                stack_frame is not None and
                stack_frame.is_local_virtual_frame_candidate
            ),
            has_virtual_private_frame_eligibility=(
                stack_frame is not None and stack_frame.virtual_private_frame_eligible
            ),
            has_exact_abi_wrapper_eligibility=abi_wrapper_route and shell_known and not self.shell.is_volatile and not self.shell.has_memory_clobber and not self.shell.has_cc_clobber and not self.shell.has_asm_goto,
            has_stack_address_rebinding_eligibility=(
                stack_frame is not None and
                stack_frame.stack_address_rebinding_eligible
            ),
            requires_whole_function_abi_lowering=(
                self.whole_function_route is not None and self.whole_function_route.required and not (
                    abi_wrapper_route and len(self.abi_effects.calls) == 1 and
                    not self.abi_effects.calls[0].reads_ra and
                    self.abi_effects.calls[0].return_continuation_internal and
                    (stack_frame is None or not stack_frame.requires_whole_function_lowering)
                )
            ),
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
            has_proven_local_branch_select=self.local_branch_select is not None,
            has_proven_local_unconditional_jump=self.local_unconditional_jump is not None,
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
    stack_rebinding_facts: StackAddressRebindingFacts | None = None,
    abi_call_bindings: tuple[SourceAbiCallBinding, ...] = (),
    privileged_state: SourcePrivilegedStateModel | None = None,
    functional_observability: FunctionalObservabilityContract | None = None,
    whole_function_facts: object | None = None,
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

    memory = _build_memory_model(summary, runtime_facts)

    # ------------------------------------------------------------------
    # Phase 6C-1 semantic facts.
    # ------------------------------------------------------------------

    operands = _build_operand_model(
        shell=shell,
        blocks=blocks,
        runtime_facts=runtime_facts,
        runtime_status=runtime_status,
    )

    local_branch_select = _build_local_branch_select_model(
        blocks=blocks, runtime_status=runtime_status, operands=operands,
        memory=memory,
    )
    local_unconditional_jump = _build_local_unconditional_jump_model(
        blocks=blocks, runtime_status=runtime_status, operands=operands,
        memory=memory, cfg=cfg,
    )
    read_only_csr_candidate = _build_read_only_csr_model(
        blocks=blocks, runtime_status=runtime_status, operands=operands,
    )
    # A matched local select has no calls, returns, indirect edges or
    # microarchitecture operation.  Record these facts here at the Phase-6A
    # boundary instead of treating the summary producer's former
    # straight-line-only policy as an unknown semantic effect.
    analysis_summary = summary
    if local_branch_select is not None or local_unconditional_jump is not None:
        analysis_summary = replace(
            summary, has_return=False, has_tail_call=False,
            has_indirect_control_flow=False, has_timing_source=False,
            has_cache_operation=False, has_speculation_control=False,
        )
        control_flow = _build_control_flow_model(
            shell=shell, blocks=blocks, cfg=cfg, summary=analysis_summary,
            runtime_facts=runtime_facts,
        )
        memory = _build_memory_model(analysis_summary, runtime_facts)

    microarch = _build_microarch_model(
        fragment=fragment, shell=shell, summary=analysis_summary,
    )
    registers = _build_register_model(analysis_summary)

    operation = _build_operation_model(
        shell=shell,
        control_flow=control_flow,
        memory=memory,
        operands=operands,
        preservation_input_summary=analysis_summary,
        proven_local_branch_select=(local_branch_select is not None or
                                    local_unconditional_jump is not None),
    )

    if privileged_state is not None and privileged_state.present:
        privileged_may_trap = bool(
            privileged_state.trap_effects
            or any(item.may_trap is True
                   for item in privileged_state.csr_effects)
        )
        trap_complete = privileged_state.complete and all(
            item.may_trap is not None
            for item in privileged_state.csr_effects
        )
        operation = replace(
            operation,
            kind=SourceOperationKind.PRIVILEGED,
            may_trap=(privileged_may_trap if trap_complete else None),
            complete=operation.complete and privileged_state.complete,
        )

    value_operation = _build_value_operation_model(
        blocks=blocks,
        runtime_status=runtime_status,
        operands=operands,
        operation=operation,
    )

    # This is a Phase-6A input ledger for diagnosing unsupported canonical
    # dataflow.  It serializes structured opcode/varnode metadata only; no
    # later Phase-6 stage consumes it and it never changes a lowering choice.
    # Keeping the ledger at this boundary prevents debugging from becoming a
    # raw-asm or textual-pcode backdoor in 6B--6F.
    if (value_operation is None and local_branch_select is None and
            local_unconditional_jump is None and
            read_only_csr_candidate is None and
            not memory.has_instruction_barrier):
        def _var_ledger(value: object) -> dict[str, object]:
            return {
                "kind": getattr(getattr(value, "kind", None), "value", None),
                "size_bits": getattr(value, "size", 0) * 8,
                "named_register": getattr(value, "name", "") or None,
                "constant": (getattr(value, "offset", None)
                             if getattr(value, "kind", None) is VarKind.CONST
                             else None),
            }

        print("[DEBUG] phase6a-unmodelled-canonical-dataflow:", {
            "operation_kind": operation.kind.value,
            "operation_complete": operation.complete,
            "may_trap": operation.may_trap,
            "operand_model_complete": operands.complete,
            "blocks": tuple(
                tuple({
                    "opcode": getattr(item, "opcode", ""),
                    "output": _var_ledger(getattr(item, "output", None)),
                    "inputs": tuple(_var_ledger(value)
                                    for value in getattr(item, "inputs", ())),
                } for item in block.ops
                      if getattr(item, "opcode", "").upper() != "IMARK")
                for block in blocks
            ),
        })

    atomic = _build_atomic_operation_model(
        summary=analysis_summary,
        memory=memory,
        operands=operands,
    )

    barrier = _build_barrier_model(
        shell=shell,
        memory=memory,
        microarch=microarch,
        summary=analysis_summary,
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
        summary=analysis_summary,
    )

    stack_frame_model = _build_stack_frame_model(
        summary=analysis_summary, registers=registers,
        stack_rebinding_facts=stack_rebinding_facts, runtime_status=runtime_status,
    )
    abi_effects = build_abi_effects(
        has_call=control_flow.has_call,
        bindings=abi_call_bindings,
        call_sites=collect_canonical_call_sites(blocks=blocks, cfg=cfg),
        returns_from_containing_function=control_flow.has_return is True,
    )
    whole_function_route = classify_whole_function_route(
        reads_registers=registers.reads_registers, writes_registers=registers.writes_registers,
        has_call=control_flow.has_call, has_return=control_flow.has_return,
        has_tail_call=control_flow.has_tail_call,
        stack_kind=None if stack_frame_model is None else stack_frame_model.kind.value,
        dynamic_adjustment=False if stack_frame_model is None else stack_frame_model.has_dynamic_adjustment,
        stack_complete=True if stack_frame_model is None else stack_frame_model.complete,
        has_unwind_or_exception_edge=_optional_summary_flag(analysis_summary,"has_unwind_or_exception_edge"),
    )
    privileged_semantics = build_privileged_state_adapter(
        fragment_id=fragment.id or fragment.fragmentId,
        phase5_state=privileged_state,
        observability=functional_observability,
        read_only_counter_candidate=read_only_csr_candidate,
        shell=shell,
        memory=memory,
        control_flow=control_flow,
        abi_effects=abi_effects,
        whole_function_route=whole_function_route,
        whole_function_facts=whole_function_facts,
    )

    features, reasons, reason_codes = _collect_source_semantic_evidence(
        shell=shell,
        control_flow=control_flow,
        memory=memory,
        microarch=microarch,
        registers=registers,
        completeness=completeness,
        privileged=privileged_semantics,
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
            summary=analysis_summary,
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
        value_program=_build_straight_line_value_program(
            blocks=blocks, runtime_status=runtime_status, operands=operands,
            operation=operation,
        ),
        local_branch_select=local_branch_select,
        local_unconditional_jump=local_unconditional_jump,
        privileged_state=privileged_semantics,
        stack_frame=stack_frame_model,
        abi_effects=abi_effects,
        whole_function_route=whole_function_route,
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
    runtime_facts: object,
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

    noop_proven = getattr(runtime_facts, "instruction_stream_sync_noop_proven", False)
    proof_id = getattr(runtime_facts, "instruction_stream_sync_proof_id", None)
    if not isinstance(noop_proven, bool):
        noop_proven = False
    if not isinstance(proof_id, str) or not proof_id.strip():
        proof_id = None
    # A certificate without both fields is not evidence.  Do not use a
    # missing identifier as an optimistic no-op proof.
    if noop_proven != (proof_id is not None):
        noop_proven, proof_id = False, None

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
        instruction_stream_sync_noop_proven=noop_proven,
        instruction_stream_sync_proof_id=proof_id,
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
    privileged: SourcePrivilegedSemanticModel | None = None,
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

    # ------------------------------------------------------------------
    # Privileged state and functional-only fallback facts.
    # ------------------------------------------------------------------

    if privileged is not None:
        state = privileged.state
        if state is None or not privileged.complete:
            add(
                _semantic_feature("PRIVILEGED_STATE_INCOMPLETE"),
                "privileged Phase-5 state/observability adapter is incomplete",
                "SM_PRIVILEGED_STATE_INCOMPLETE",
            )
            for code in privileged.reason_codes:
                if code not in reason_codes:
                    reason_codes.append(code)
        if state is not None and state.present:
            add(
                _semantic_feature("PRIVILEGED_STATE"),
                "source fragment has typed privileged architectural state",
                "SM_PRIVILEGED_STATE",
            )
            if state.csr_effects:
                add(
                    _semantic_feature("CSR_ACCESS"),
                    "source fragment accesses typed RISC-V CSR state",
                    "SM_CSR_ACCESS",
                )
            if state.trap_effects:
                add(
                    _semantic_feature("PRIVILEGED_TRAP"),
                    "source fragment has an architecturally observable trap",
                    "SM_PRIVILEGED_TRAP",
                )
            if state.return_effects:
                add(
                    _semantic_feature("PRIVILEGE_RETURN"),
                    "source fragment performs a privilege return",
                    "SM_PRIVILEGE_RETURN",
                )
            if state.interrupt_effects:
                add(
                    _semantic_feature("INTERRUPT_STATE"),
                    "source fragment reads or modifies interrupt state",
                    "SM_INTERRUPT_STATE",
                )
            if state.address_translation_effects:
                add(
                    _semantic_feature("ADDRESS_TRANSLATION_STATE"),
                    "source fragment affects address-translation state",
                    "SM_ADDRESS_TRANSLATION_STATE",
                )
            if state.virtualization_effects:
                add(
                    _semantic_feature("VIRTUALIZATION_STATE"),
                    "source fragment affects virtualization state",
                    "SM_VIRTUALIZATION_STATE",
                )
            if state.debug_effects:
                add(
                    _semantic_feature("DEBUG_STATE"),
                    "source fragment affects privileged debug state",
                    "SM_DEBUG_STATE",
                )
        if privileged.read_only_counter is not None:
            add(
                _semantic_feature("READ_ONLY_COUNTER_CSR"),
                "source fragment reads a bound read-only counter CSR",
                "SM_READ_ONLY_COUNTER_CSR",
            )
        observability = privileged.observability
        if observability is not None and not observability.complete:
            add(
                _semantic_feature("FUNCTIONAL_OBSERVABILITY_INCOMPLETE"),
                "functional observability facts are incomplete",
                "SM_FUNCTIONAL_OBSERVABILITY_INCOMPLETE",
            )
        if observability is not None and observability.ignored_states:
            add(
                _semantic_feature("IGNORED_PRIVILEGED_STATE"),
                "functional contract explicitly ignores privileged state",
                "SM_IGNORED_PRIVILEGED_STATE",
            )
        if privileged.functional_fallback_possible:
            add(
                _semantic_feature("FUNCTIONAL_PRIVILEGED_FALLBACK_POSSIBLE"),
                "source facts permit proof of an exact functional fallback",
                "SM_FUNCTIONAL_PRIVILEGED_FALLBACK_POSSIBLE",
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
    PRIVILEGED = "privileged"
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
    SHIFT_LEFT_REGISTER = "shift_left_register"
    SHIFT_RIGHT_LOGICAL_REGISTER = "shift_right_logical_register"
    SHIFT_RIGHT_ARITHMETIC_REGISTER = "shift_right_arithmetic_register"
    SHIFT_LEFT_IMMEDIATE = "shift_left_immediate"
    SHIFT_RIGHT_LOGICAL_IMMEDIATE = "shift_right_logical_immediate"
    SHIFT_RIGHT_ARITHMETIC_IMMEDIATE = "shift_right_arithmetic_immediate"
    SIGNED_LESS = "signed_less"
    UNSIGNED_LESS = "unsigned_less"
    SIGNED_LESS_EQUAL = "signed_less_equal"
    UNSIGNED_LESS_EQUAL = "unsigned_less_equal"
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"


class SourceStraightLineValueOpcode(str, Enum):
    """Finite source-independent operation set for the generic GPR route."""
    COPY = "copy"
    UNSIGNED_ADD = "unsigned_add"
    UNSIGNED_SUB = "unsigned_sub"
    BIT_AND = "bit_and"
    BIT_OR = "bit_or"
    BIT_XOR = "bit_xor"
    SHIFT_LEFT_IMMEDIATE = "shift_left_immediate"
    SHIFT_RIGHT_LOGICAL_IMMEDIATE = "shift_right_logical_immediate"
    SHIFT_RIGHT_ARITHMETIC_IMMEDIATE = "shift_right_arithmetic_immediate"
    SHIFT_LEFT_REGISTER = "shift_left_register"
    SHIFT_RIGHT_LOGICAL_REGISTER = "shift_right_logical_register"
    SHIFT_RIGHT_ARITHMETIC_REGISTER = "shift_right_arithmetic_register"


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
    # Canonical byte displacement from the bound address operand.  It is
    # derived from typed p-code address arithmetic, never from asm text.
    byte_offset: int = 0


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
    # RISC-V SLEIGH commonly materializes the architectural register-shift
    # count mask (XLEN - 1) as ``INT_AND count, constant`` into a UNIQUE
    # temporary before INT_LEFT/RIGHT/SRIGHT.  Retain that normalization as a
    # structured source fact; it is never reconstructed from asm text.
    shift_count_mask: int | None = None

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
        if self.shift_count_mask is not None and (
            isinstance(self.shift_count_mask, bool)
            or not isinstance(self.shift_count_mask, int)
            or self.shift_count_mask < 0
        ):
            raise TypeError("shift_count_mask must be a non-negative int or None")


@dataclass(frozen=True)
class SourceStraightLineValueInstruction:
    """One canonical dataflow instruction, referenced only by operand IDs."""
    opcode: SourceStraightLineValueOpcode
    output_operand_index: int
    input_operand_indexes: Tuple[int, ...]
    immediate_value: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.opcode, SourceStraightLineValueOpcode):
            raise TypeError("opcode must be SourceStraightLineValueOpcode")
        if isinstance(self.output_operand_index, bool) or not isinstance(self.output_operand_index, int) or self.output_operand_index < 0:
            raise TypeError("output_operand_index must be a non-negative int")
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 0
               for item in self.input_operand_indexes):
            raise TypeError("input_operand_indexes must contain non-negative ints")
        immediate_ops = {
            SourceStraightLineValueOpcode.SHIFT_LEFT_IMMEDIATE,
            SourceStraightLineValueOpcode.SHIFT_RIGHT_LOGICAL_IMMEDIATE,
            SourceStraightLineValueOpcode.SHIFT_RIGHT_ARITHMETIC_IMMEDIATE,
        }
        if (self.opcode in immediate_ops) != (self.immediate_value is not None):
            raise ValueError("shift-immediate instructions require exactly one immediate value")


@dataclass(frozen=True)
class SourceStraightLineValueProgram:
    """Authoritative Phase-6A pure register dataflow program.

    All values are source operand bindings; unbound lifter temporaries are
    rejected rather than being guessed as renderer scratch registers.
    """
    width_bits: int
    instructions: Tuple[SourceStraightLineValueInstruction, ...]
    output_operand_indexes: Tuple[int, ...]
    input_operand_indexes: Tuple[int, ...]
    # x86 variable shifts use CL.  A program with more than one distinct
    # dynamic count would require a separate register-scheduling contract and
    # is intentionally rejected by the Phase-6A adapter for now.
    variable_shift_count_operand_index: int | None = None
    complete: bool = True

    def __post_init__(self) -> None:
        if self.width_bits not in {32, 64}:
            raise ValueError("straight-line GPR program width must be 32 or 64")
        if len(self.instructions) < 2 or not self.complete:
            raise ValueError("straight-line GPR program must contain at least two complete instructions")
        if len(set(self.output_operand_indexes)) != len(self.output_operand_indexes):
            raise ValueError("straight-line program outputs must be unique")


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


def _build_stack_frame_model(
    *,
    summary: IRSummary,
    registers: SourceRegisterModel,
    stack_rebinding_facts: StackAddressRebindingFacts | None = None,
    runtime_status: RuntimeFactStatus | None = None,
) -> SourceStackFrameModel:
    """Adapt typed Phase-5 stack metadata without inspecting assembly text.

    The decoder/lifter may provide ``summary.stack_frame_semantics`` as a
    mapping or DTO with the fields below.  Until it does, any observed source
    stack/frame register is deliberately UNKNOWN.  This prevents accidental
    use of the host x86 stack as a stand-in for the RISC-V frame.
    """
    sensitive = (
        registers.reads_or_writes_stack_pointer or
        registers.reads_or_writes_frame_pointer
    )
    raw = summary.stack_frame_semantics
    if not isinstance(raw, StackFrameSemantics):
        return SourceStackFrameModel(
            SourceStackFrameKind.UNKNOWN if sensitive else SourceStackFrameKind.NONE,
            complete=not sensitive,
            missing_fact_codes=() if not sensitive else ("stack-frame-semantics-unavailable",),
        )
    try:
        kind = SourceStackFrameKind(raw.classification.value)
    except ValueError:
        kind = SourceStackFrameKind.UNKNOWN
    try:
        rebinding_accesses: list[SourceStackRebindingAccess] = []
        reasons = list(raw.missing_fact_codes)
        eligible = False
        private_model = None
        private_eligible = False
        if kind is SourceStackFrameKind.PRIVATE_BALANCED:
            layout = raw.private_frame_layout
            bindings = _normalized_runtime_binding_map(runtime_status) if isinstance(runtime_status, RuntimeFactStatus) else {}
            if isinstance(layout, PrivateFrameLayoutFacts) and layout.frame_range is not None and layout.complete:
                private_accesses=[]; private_reasons=list(layout.missing_fact_codes)
                for slot in layout.slots:
                    reg = (slot.value_node_id or "").removeprefix("reg:")
                    value_index = bindings.get(reg)
                    if value_index is None or not slot.complete:
                        private_reasons.append("private-frame-value-flow-incomplete"); continue
                    private_accesses.append(SourcePrivateFrameAccess(slot.source_block_address,slot.source_operation_index,slot.source_offset_bytes,slot.virtual_offset_bytes,slot.width_bits,slot.required_alignment_bytes,slot.access,slot.signed_load,value_index,slot.definitely_initialized_before_read,slot.complete))
                private_eligible=(len(private_accesses)==len(layout.slots) and not private_reasons and raw.net_stack_delta_bytes==0 and not raw.escape_facts.pointer_escapes and not raw.escape_facts.requires_real_stack_identity and not raw.has_call and raw.has_return is False and raw.has_unwind_or_exception_edge is False)
                private_model=SourceVirtualPrivateFrameModel(layout.frame_range.frame_size_bytes,layout.frame_range.required_alignment_bytes,layout.frame_range.start_offset_bytes,layout.frame_range.end_offset_bytes,tuple(private_accesses),layout.initialization_complete,layout.overlap_complete,layout.all_accesses_in_range,not raw.escape_facts.pointer_escapes,not raw.escape_facts.requires_real_stack_identity,private_eligible,tuple(sorted(set(private_reasons))))
        if kind is SourceStackFrameKind.ADDRESS_ONLY:
            if not isinstance(stack_rebinding_facts, StackAddressRebindingFacts):
                reasons.append("stack-rebind.binding-missing")
            elif not stack_rebinding_facts.complete:
                reasons.extend(stack_rebinding_facts.missing_fact_codes)
            elif raw.escape_facts.pointer_escapes or raw.escape_facts.requires_real_stack_identity:
                reasons.append("stack-rebind.address-escapes")
            else:
                by_location: dict[tuple[int, int], list[object]] = {}
                for binding in stack_rebinding_facts.bindings:
                    by_location.setdefault((binding.source_block_address, binding.source_operation_index), []).append(binding)
                for access in raw.accesses:
                    candidates = by_location.get((access.block_address, access.operation_index), [])
                    if len(candidates) != 1:
                        reasons.append("stack-rebind.binding-ambiguous" if candidates else "stack-rebind.binding-missing")
                        continue
                    binding = candidates[0]
                    width_bytes = None if access.width_bits is None else access.width_bits // 8
                    bounds_ok = (width_bytes is not None and binding.object_size_bytes is not None and
                                 0 <= binding.object_offset_bytes and
                                 binding.object_offset_bytes + width_bytes <= binding.object_size_bytes)
                    alignment_ok = (access.required_alignment_bytes is not None and
                                    binding.guaranteed_alignment_bytes is not None and
                                    binding.guaranteed_alignment_bytes >= access.required_alignment_bytes)
                    same = (binding.binding_complete and binding.lifetime_proven and binding.effective_type_proven and
                            binding.source_offset_bytes == access.offset_bytes and binding.access is access.access and
                            access.width_bits is not None and bounds_ok and alignment_ok)
                    if not same:
                        reasons.append("stack-rebind.object-bounds-unproven" if not bounds_ok else "stack-rebind.alignment-unproven")
                        continue
                    rebinding_accesses.append(SourceStackRebindingAccess(
                        access.block_address, access.operation_index, binding.c_object_id,
                        binding.c_lvalue_binding_id, binding.c_base_operand_index,
                        binding.source_offset_bytes, binding.object_offset_bytes,
                        binding.object_size_bytes, access.required_alignment_bytes,
                        binding.guaranteed_alignment_bytes, access.width_bits, access.access,
                        access.signed_load, binding.value_operand_index,
                        access.aliases_external_memory, binding.source_compiler_provenance, True))
                eligible = len(rebinding_accesses) == len(raw.accesses) and bool(raw.accesses) and not reasons
        complete = raw.complete and (kind is not SourceStackFrameKind.ADDRESS_ONLY or eligible)
        return SourceStackFrameModel(
            kind=kind,
            frame_size_bytes=raw.frame_size_bytes,
            required_alignment_bytes=raw.source_abi_alignment_bytes,
            net_stack_delta_bytes=raw.net_stack_delta_bytes,
            pointer_escapes=raw.escape_facts.pointer_escapes,
            requires_real_stack_identity=raw.escape_facts.requires_real_stack_identity,
            complete=complete,
            initial_sp_origin=raw.initial_sp_origin.value,
            source_abi_alignment_bytes=raw.source_abi_alignment_bytes,
            accesses=raw.accesses,
            adjustments=raw.adjustments,
            escape_facts=raw.escape_facts,
            pointer_uses=raw.pointer_uses,
            has_dynamic_adjustment=raw.has_dynamic_adjustment,
            rebinding_accesses=tuple(sorted(rebinding_accesses, key=lambda x: (x.source_block_address, x.source_operation_index))),
            stack_address_rebinding_eligible=eligible,
            virtual_private_frame=private_model,
            virtual_private_frame_eligible=private_eligible,
            missing_fact_codes=tuple(sorted(set(reasons))) if not complete else (),
        )
    except (TypeError, ValueError):
        return SourceStackFrameModel(SourceStackFrameKind.UNKNOWN, complete=False,
            missing_fact_codes=("invalid-stack-frame-semantics",))


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
        memory_address_operand_offsets=_memory_address_operand_offsets(
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
    memory_address_operand_offsets: Mapping[int, int],
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
        if index in memory_address_operand_offsets:
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
                byte_offset=memory_address_operand_offsets[index],
            ) if index in memory_address_operand_offsets else None),
        )
    return result


def _memory_address_operand_offsets(*, blocks: Sequence[Block], runtime_facts: TranslationRuntimeFacts) -> dict[int, int]:
    """Recover one ``base + signed-disp32`` address binding in Phase 6A.

    Lifting commonly represents ``0(base)`` as a UNIQUE varnode produced by
    ``COPY base`` or ``INT_ADD base, constant`` before the LOAD/STORE.  The
    accepted arithmetic is deliberately finite: transparent width-preserving
    copies/extensions plus additions of typed constants, with a final signed
    32-bit byte displacement.  General arithmetic, merges and ambiguous
    producers remain unmodelled and are rejected by the memory path.
    """
    raw_map = getattr(runtime_facts, "rv_to_operand_index", {})
    if not isinstance(raw_map, Mapping):
        return {}
    canonical_map = {
        canonicalize_riscv_register_name(register): index
        for register, index in raw_map.items()
        if canonicalize_riscv_register_name(register)
        and isinstance(index, int) and not isinstance(index, bool)
    }
    memory_ops = [op for block in blocks for instruction in block.instructions
                  for op in instruction.ops if op.opcode in {"LOAD", "STORE"}]
    if len(memory_ops) != 1:
        return {}

    memory_op = memory_ops[0]
    if memory_op.opcode == "LOAD":
        # SLEIGH LOAD has (space, address) inputs.
        if len(memory_op.inputs) != 2:
            return {}
        address = memory_op.inputs[1]
    else:
        # SLEIGH STORE has (space, address, value) inputs.
        if len(memory_op.inputs) != 3:
            return {}
        address = memory_op.inputs[1]

    producers = {
        op.output: op
        for block in blocks
        for instruction in block.instructions
        for op in instruction.ops
        if op.output is not None
    }

    def literal_constant(item: object, visiting: set[object]) -> int | None:
        """Return a typed signed integer constant through transparent nodes."""
        if getattr(item, "kind", None) is VarKind.CONST:
            raw, size = getattr(item, "offset", None), getattr(item, "size", None)
            if not isinstance(raw, int) or not isinstance(size, int) or size <= 0:
                return None
            bits = size * 8
            return raw - (1 << bits) if raw & (1 << (bits - 1)) else raw
        if item in visiting:
            return None
        producer = producers.get(item)
        if producer is None:
            return None
        next_visiting = visiting | {item}
        if producer.opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
            return (literal_constant(producer.inputs[0], next_visiting)
                    if len(producer.inputs) == 1 else None)
        return None

    def resolve_address(item: object, visiting: set[object]) -> set[tuple[str, int]]:
        if getattr(item, "kind", None) is VarKind.REG:
            name = getattr(item, "name", "")
            canonical = (canonicalize_riscv_register_name(name)
                         if isinstance(name, str) and name.strip() else "")
            return {(canonical, 0)} if canonical else set()
        if item in visiting:
            return set()
        producer = producers.get(item)
        if producer is None:
            return set()
        if producer.opcode == "COPY" and len(producer.inputs) == 1:
            return resolve_address(producer.inputs[0], visiting | {item})
        if producer.opcode in {"INT_ZEXT", "INT_SEXT", "SUBPIECE"} and len(producer.inputs) == 1:
            return resolve_address(producer.inputs[0], visiting | {item})
        if producer.opcode == "INT_ADD" and len(producer.inputs) == 2:
            left, right = producer.inputs
            left_constant = literal_constant(left, set())
            right_constant = literal_constant(right, set())
            if left_constant is not None:
                return {(register, offset + left_constant)
                        for register, offset in resolve_address(right, visiting | {item})}
            if right_constant is not None:
                return {(register, offset + right_constant)
                        for register, offset in resolve_address(left, visiting | {item})}
        return set()

    addresses = resolve_address(address, set())
    if len(addresses) != 1:
        return {}
    register, byte_offset = next(iter(addresses))
    operand_index = canonical_map.get(register)
    if (operand_index is None or not isinstance(byte_offset, int) or
            not -(1 << 31) <= byte_offset < (1 << 31)):
        return {}
    return {operand_index: byte_offset}

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

def _build_local_branch_select_model(
    *, blocks: Sequence[Block], runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel, memory: SourceMemoryModel,
) -> SourceLocalBranchSelectModel | None:
    """Recognize a fully local canonical compare-and-select CFG.

    Accepted shape: one canonical integer comparison predicate feeds one
    ``CBRANCH``; its taken and fallthrough blocks each copy one declared input
    into the same declared output; the fallthrough arm has one direct local
    join branch.  This consumes typed operations and authoritative block-edge
    metadata only, never source labels or instruction spelling.
    """
    if (len(blocks) != 3 or not runtime_status.structurally_valid or
            not operands.complete or memory.reads_memory or memory.writes_memory or
            memory.has_atomic or memory.has_memory_barrier or memory.has_instruction_barrier):
        return None
    entry = blocks[0]
    taken_address = next((address for address, kind in getattr(entry, "successor_kinds", {}).items()
                          if kind in {"taken", "branch_taken"}), None)
    fallthrough_address = next((address for address, kind in getattr(entry, "successor_kinds", {}).items()
                                if kind == "fallthrough"), None)
    by_address = {block.addr: block for block in blocks}
    taken, fallthrough = by_address.get(taken_address), by_address.get(fallthrough_address)
    if (taken is None or fallthrough is None or taken is fallthrough or
            set(getattr(entry, "successors", ())) != {taken_address, fallthrough_address}):
        return None
    entry_ops = [item for item in entry.ops if getattr(item, "opcode", "").upper() != "IMARK"]
    comparison_kinds = {
        "INT_EQUAL": SourceValueOperationKind.EQUAL,
        "INT_NOTEQUAL": SourceValueOperationKind.NOT_EQUAL,
        "INT_SLESS": SourceValueOperationKind.SIGNED_LESS,
        "INT_LESS": SourceValueOperationKind.UNSIGNED_LESS,
        "INT_SLESSEQUAL": SourceValueOperationKind.SIGNED_LESS_EQUAL,
        "INT_LESSEQUAL": SourceValueOperationKind.UNSIGNED_LESS_EQUAL,
    }
    compares = [item for item in entry_ops
                if getattr(item, "opcode", "").upper() in comparison_kinds]
    branches = [item for item in entry_ops if getattr(item, "opcode", "").upper() == "CBRANCH"]
    if len(entry_ops) != 2 or len(compares) != 1 or len(branches) != 1:
        return None
    compare, branch = compares[0], branches[0]
    if (getattr(compare, "output", None) is None or len(getattr(compare, "inputs", ())) != 2 or
            len(getattr(branch, "inputs", ())) != 2 or branch.inputs[-1] != compare.output):
        return None

    def arm_copy(block: Block, *, requires_branch: bool) -> object | None:
        items = [item for item in block.ops if getattr(item, "opcode", "").upper() != "IMARK"]
        copies = [item for item in items if getattr(item, "opcode", "").upper() == "COPY"]
        jumps = [item for item in items if getattr(item, "opcode", "").upper() == "BRANCH"]
        if len(copies) != 1 or len(getattr(copies[0], "inputs", ())) != 1:
            return None
        if requires_branch:
            if len(items) != 2 or len(jumps) != 1:
                return None
        elif len(items) != 1 or jumps:
            return None
        return copies[0]

    true_copy = arm_copy(taken, requires_branch=False)
    false_copy = arm_copy(fallthrough, requires_branch=True)
    if true_copy is None or false_copy is None or true_copy.output != false_copy.output:
        return None
    reg_to_index: dict[str, int] = {}
    for register, index in runtime_status.rv_to_operand_index.items():
        canonical = canonicalize_riscv_register_name(register)
        if not canonical or canonical in reg_to_index:
            return None
        reg_to_index[canonical] = index
    def operand_index(value: object) -> int | None:
        if getattr(value, "kind", None) is not VarKind.REG:
            return None
        return reg_to_index.get(canonicalize_riscv_register_name(getattr(value, "name", "")))
    result = operand_index(true_copy.output)
    indexes = tuple(operand_index(item) for item in (*compare.inputs, true_copy.inputs[0], false_copy.inputs[0]))
    if result is None or any(index is None for index in indexes):
        return None
    bound = {item.source_operand_index: item for item in operands.operands}
    result_binding = bound.get(result)
    inputs = tuple(bound.get(index) for index in indexes)
    if (result_binding is None or result_binding.access is not SourceOperandAccess.OUTPUT or
            result_binding.width_bits not in {32, 64} or
            any(item is None or item.access is not SourceOperandAccess.INPUT or
                item.width_bits != result_binding.width_bits for item in inputs)):
        return None
    if set(indexes) | {result} != set(bound):
        return None
    kind = comparison_kinds[getattr(compare, "opcode", "").upper()]
    return SourceLocalBranchSelectModel(kind, indexes[0], indexes[1], indexes[2], indexes[3], result, result_binding.width_bits)


def _build_local_unconditional_jump_model(
    *, blocks: Sequence[Block], runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel, memory: SourceMemoryModel, cfg: CFGResult,
) -> SourceLocalUnconditionalJumpModel | None:
    """Prove a finite direct-jump-to-copy CFG family.

    The proof consumes canonical block edges and typed COPY/BRANCH operations
    only.  It intentionally rejects indirect targets, joins, calls, memory,
    and any target block containing more than the one observable copy.  All
    source input bindings remain in the later GNU-asm contract, including
    inputs used solely by unreachable fragment blocks, so C operand evaluation
    is not silently discarded by the CFG simplification.
    """
    if (len(blocks) < 2 or not runtime_status.structurally_valid or
            not operands.complete or memory.reads_memory or memory.writes_memory or
            memory.has_atomic or memory.has_memory_barrier or
            memory.has_instruction_barrier):
        return None
    entry = blocks[0]
    if getattr(entry, "is_indirect", False) or getattr(entry, "has_unknown_target", False):
        return None
    entry_ops = [item for item in entry.ops if getattr(item, "opcode", "").upper() != "IMARK"]
    if len(entry_ops) != 1 or getattr(entry_ops[0], "opcode", "").upper() != "BRANCH":
        return None
    by_address = {block.addr: block for block in blocks}
    branch_target = None
    branch_inputs = getattr(entry_ops[0], "inputs", ())
    if len(branch_inputs) == 1 and getattr(branch_inputs[0], "kind", None) is VarKind.MEM:
        candidate = getattr(branch_inputs[0], "offset", None)
        if isinstance(candidate, int) and candidate in by_address:
            branch_target = candidate
    block_successors = tuple(getattr(entry, "successors", ()))
    node = getattr(cfg, "nodes", {}).get(entry.addr) if _cfg_ok(cfg) else None
    cfg_successors = tuple(getattr(node, "successors", ())) if node is not None else ()
    edge_candidates = [candidate for candidate in (
        branch_target,
        block_successors[0] if len(block_successors) == 1 else None,
        cfg_successors[0] if len(cfg_successors) == 1 else None,
    ) if candidate is not None]
    # Every available structured edge representation must agree.  A missing
    # Block successor is normal for canonical p-code; it is not license to
    # guess the target from source text or block order.
    if (not edge_candidates or len(block_successors) > 1 or len(cfg_successors) > 1 or
            len(set(edge_candidates)) != 1):
        return None
    target_address = edge_candidates[0]
    edge_kind = getattr(entry, "successor_kinds", {}).get(target_address)
    if edge_kind is None and node is not None:
        edge_kind = getattr(node, "successor_kinds", {}).get(target_address)
    if edge_kind is not None and edge_kind not in {"taken", "branch", "direct", "jump", "direct_jump", "branch_taken"}:
        return None
    target = by_address.get(target_address)
    target_node = getattr(cfg, "nodes", {}).get(target_address) if _cfg_ok(cfg) else None
    if (target is None or target is entry or getattr(target, "successors", ()) or
            (target_node is not None and getattr(target_node, "successors", ()))):
        return None
    target_ops = [item for item in target.ops if getattr(item, "opcode", "").upper() != "IMARK"]
    if (len(target_ops) != 1 or getattr(target_ops[0], "opcode", "").upper() != "COPY" or
            getattr(target_ops[0], "output", None) is None or
            len(getattr(target_ops[0], "inputs", ())) != 1):
        return None
    copy = target_ops[0]
    reg_to_index: dict[str, int] = {}
    for register, index in runtime_status.rv_to_operand_index.items():
        canonical = canonicalize_riscv_register_name(register)
        if not canonical or canonical in reg_to_index:
            return None
        reg_to_index[canonical] = index
    def operand_index(value: object) -> int | None:
        if getattr(value, "kind", None) is not VarKind.REG:
            return None
        return reg_to_index.get(canonicalize_riscv_register_name(getattr(value, "name", "")))
    result = operand_index(copy.output)
    selected = operand_index(copy.inputs[0])
    if result is None or selected is None or result == selected:
        return None
    bound = {item.source_operand_index: item for item in operands.operands}
    result_binding, selected_binding = bound.get(result), bound.get(selected)
    if (result_binding is None or selected_binding is None or
            result_binding.access is not SourceOperandAccess.OUTPUT or
            selected_binding.access is not SourceOperandAccess.INPUT or
            result_binding.width_bits not in {32, 64} or
            selected_binding.width_bits != result_binding.width_bits):
        return None
    # BRANCH has exactly one direct target and the target terminates locally;
    # therefore no other fragment block is reachable from the entry.  The
    # proof is from typed terminators/edges, not block sequence order.
    return SourceLocalUnconditionalJumpModel(
        selected, result, result_binding.width_bits, entry.addr, target_address,
    )


def _build_read_only_csr_model(
    *, blocks: Sequence[Block], runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel,
) -> SourceReadOnlyCsrModel | None:
    """Identify a read-only counter CSR through typed register varnodes.

    The input is canonical p-code and the Phase-4 operand binding map; no raw
    assembly spelling is inspected.  We intentionally model a finite family
    of architecturally read-only counters and return a route request rather
    than manufacturing an x86 timer equivalence.
    """
    if not runtime_status.structurally_valid or not operands.complete:
        return None
    known_csrs = frozenset({"cycle", "cycleh", "time", "timeh", "instret", "instreth"})
    by_register: dict[str, int] = {}
    for register, index in runtime_status.rv_to_operand_index.items():
        canonical = canonicalize_riscv_register_name(register)
        if canonical:
            by_register[canonical] = index
    bindings = {item.source_operand_index: item for item in operands.operands}
    matches: list[tuple[str, int]] = []
    for block in blocks:
        for operation in block.ops:
            if getattr(operation, "opcode", "").upper() != "COPY":
                continue
            output = getattr(operation, "output", None)
            inputs = tuple(getattr(operation, "inputs", ()))
            if len(inputs) != 1 or getattr(output, "kind", None) is not VarKind.REG:
                continue
            source = inputs[0]
            if getattr(source, "kind", None) is not VarKind.REG:
                continue
            csr_name = (getattr(source, "name", "") or "").strip().lower()
            if csr_name not in known_csrs:
                continue
            result_index = by_register.get(canonicalize_riscv_register_name(getattr(output, "name", "")))
            result = None if result_index is None else bindings.get(result_index)
            if (result is None or result.access is not SourceOperandAccess.OUTPUT or
                    result.width_bits not in {32, 64}):
                return None
            matches.append((csr_name, result_index))
    if len(matches) != 1:
        return None
    csr_name, result_index = matches[0]
    # A counter CSR read has exactly the declared result binding; any other
    # source operand would require a distinct contract family.
    if set(bindings) != {result_index}:
        return None
    return SourceReadOnlyCsrModel(
        effect_id="",
        result_operand_index=result_index,
        width_bits=bindings[result_index].width_bits,
        complete=False,
        csr_name=csr_name,
    )


def _build_operation_model(
    *,
    shell: SourceShellModel,
    control_flow: SourceControlFlowModel,
    memory: SourceMemoryModel,
    operands: SourceOperandModel,
    preservation_input_summary: IRSummary,
    proven_local_branch_select: bool = False,
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
        may_trap=(False if (proven_local_branch_select or
                            (control_flow.has_asm_goto and
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


def _build_straight_line_value_program(
    *,
    blocks: Sequence[Block], runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel, operation: SourceOperationModel,
) -> SourceStraightLineValueProgram | None:
    """Build a generic, finite GPR dataflow program from canonical p-code.

    This intentionally solves a class of straight-line programs rather than a
    source mnemonic/template.  It accepts only values that can be represented
    by existing GNU asm operands: every non-copy computation must write one
    externally visible output operand, and every input must be either a source
    input or a value written by an earlier program instruction.
    """
    if (operation.kind is not SourceOperationKind.REGISTER_ONLY or
            operation.may_trap is not False or not operands.complete or
            len(blocks) != 1 or not runtime_status.structurally_valid):
        return None
    items = [item for item in blocks[0].ops if getattr(item, "opcode", "").upper() != "IMARK"]
    copy_source: dict[object, object] = {}
    raw_ops: list[object] = []
    opcode_map = {
        "INT_ADD": SourceStraightLineValueOpcode.UNSIGNED_ADD,
        "INT_SUB": SourceStraightLineValueOpcode.UNSIGNED_SUB,
        "INT_AND": SourceStraightLineValueOpcode.BIT_AND,
        "INT_OR": SourceStraightLineValueOpcode.BIT_OR,
        "INT_XOR": SourceStraightLineValueOpcode.BIT_XOR,
        "INT_LEFT": SourceStraightLineValueOpcode.SHIFT_LEFT_IMMEDIATE,
        "INT_RIGHT": SourceStraightLineValueOpcode.SHIFT_RIGHT_LOGICAL_IMMEDIATE,
        "INT_SRIGHT": SourceStraightLineValueOpcode.SHIFT_RIGHT_ARITHMETIC_IMMEDIATE,
    }
    for item in items:
        opcode = getattr(item, "opcode", "").upper()
        if opcode == "COPY":
            output, inputs = getattr(item, "output", None), getattr(item, "inputs", ())
            if (output is None or len(inputs) != 1 or output in copy_source or
                    getattr(output, "kind", None) is VarKind.CONST or
                    getattr(output, "size", None) != getattr(inputs[0], "size", None)):
                return None
            copy_source[output] = inputs[0]
        elif opcode in opcode_map:
            raw_ops.append(item)
        else:
            return None
    if len(raw_ops) < 2:
        return None
    def resolve(value: object) -> object | None:
        seen: set[object] = set(); current = value
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
    def operand_index(value: object) -> int | None:
        if getattr(value, "kind", None) is not VarKind.REG:
            return None
        return reg_to_index.get(canonicalize_riscv_register_name(getattr(value, "name", "")))
    def result_index(value: object) -> int | None:
        matches = {operand_index(candidate) for candidate in (value, *copy_source)
                   if resolve(candidate) == value and operand_index(candidate) is not None}
        return next(iter(matches)) if len(matches) == 1 else None
    bindings = {item.source_operand_index: item for item in operands.operands}
    program: list[SourceStraightLineValueInstruction] = []
    written: set[int] = set()
    used_inputs: set[int] = set()
    width: int | None = None
    shift_ops = {
        SourceStraightLineValueOpcode.SHIFT_LEFT_IMMEDIATE,
        SourceStraightLineValueOpcode.SHIFT_RIGHT_LOGICAL_IMMEDIATE,
        SourceStraightLineValueOpcode.SHIFT_RIGHT_ARITHMETIC_IMMEDIATE,
    }
    variable_shift_ops = {
        "INT_LEFT": SourceStraightLineValueOpcode.SHIFT_LEFT_REGISTER,
        "INT_RIGHT": SourceStraightLineValueOpcode.SHIFT_RIGHT_LOGICAL_REGISTER,
        "INT_SRIGHT": SourceStraightLineValueOpcode.SHIFT_RIGHT_ARITHMETIC_REGISTER,
    }
    variable_shift_count: int | None = None
    for raw in raw_ops:
        opcode = opcode_map[getattr(raw, "opcode", "").upper()]
        output = getattr(raw, "output", None)
        inputs = getattr(raw, "inputs", ())
        output_index = None if output is None else result_index(output)
        target = None if output_index is None else bindings.get(output_index)
        if (target is None or target.access is not SourceOperandAccess.OUTPUT or
                output_index in written or target.width_bits not in {32, 64}):
            return None
        if width is None:
            width = target.width_bits
        if target.width_bits != width:
            return None
        if opcode in shift_ops:
            if len(inputs) != 2:
                return None
            source = resolve(inputs[0]); constant = resolve(inputs[1])
            if source is None or constant is None:
                return None
            if getattr(constant, "kind", None) is VarKind.CONST:
                indexes = (operand_index(source),)
                raw_value, size = getattr(constant, "offset", None), getattr(constant, "size", None)
                if (isinstance(raw_value, bool) or not isinstance(raw_value, int) or
                        isinstance(size, bool) or not isinstance(size, int) or size <= 0):
                    return None
                immediate = raw_value & ((1 << (size * 8)) - 1)
                if immediate >= width:
                    return None
            else:
                count_index = operand_index(constant)
                indexes = (operand_index(source), count_index)
                if count_index is None or (variable_shift_count is not None and variable_shift_count != count_index):
                    return None
                variable_shift_count = count_index
                opcode = variable_shift_ops[getattr(raw, "opcode", "").upper()]
                immediate = None
        else:
            if len(inputs) != 2:
                return None
            resolved = (resolve(inputs[0]), resolve(inputs[1]))
            if any(item is None for item in resolved):
                return None
            indexes = tuple(operand_index(item) for item in resolved)
            immediate = None
        if any(index is None for index in indexes):
            return None
        for index in indexes:
            binding = bindings.get(index)
            if binding is None or binding.width_bits != width:
                return None
            if binding.access is SourceOperandAccess.INPUT:
                used_inputs.add(index)
            elif binding.access is SourceOperandAccess.OUTPUT:
                if index not in written:
                    return None
            else:
                return None
        program.append(SourceStraightLineValueInstruction(opcode, output_index, tuple(indexes), immediate))
        written.add(output_index)
    output_indexes = tuple(item.source_operand_index for item in operands.operands
                           if item.access is SourceOperandAccess.OUTPUT)
    input_indexes = tuple(item.source_operand_index for item in operands.operands
                          if item.access is SourceOperandAccess.INPUT)
    if (width is None or set(output_indexes) != written or set(input_indexes) != used_inputs or
            any(bindings[index].kind is not SourceOperandKind.REGISTER or
                bindings[index].signedness.value == "unknown" or
                bindings[index].tied_to_source_operand_index is not None or
                bindings[index].fixed_register_name is not None
                for index in (*output_indexes, *input_indexes))):
        return None
    return SourceStraightLineValueProgram(
        width_bits=width, instructions=tuple(program),
        output_operand_indexes=output_indexes, input_operand_indexes=input_indexes,
        variable_shift_count_operand_index=variable_shift_count,
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


def _build_register_shift_value_operation_model(
    *,
    blocks: Sequence[Block],
    runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel,
    operation: SourceOperationModel,
) -> SourceValueOperationModel | None:
    """Model a register-count shift through its canonical count-expression DAG.

    RISC-V defines register shifts through the low ``log2(XLEN)`` count bits.
    SLEIGH is free to make that rule explicit with ``INT_AND``, ``SUBPIECE``,
    ``INT_ZEXT`` and ``COPY`` UNIQUE temporaries.  This Phase-6A adapter
    accepts only that closed, structured normalization family; auxiliary
    arithmetic is never ignored or inferred from source-asm text.
    """
    if (
        operation.kind is not SourceOperationKind.REGISTER_ONLY
        or operation.may_trap is not False
        or not operands.complete
        or len(blocks) != 1
        or not runtime_status.structurally_valid
    ):
        return None

    items = [item for item in blocks[0].ops
             if getattr(item, "opcode", "").upper() != "IMARK"]
    shift_kind_by_opcode = {
        "INT_LEFT": SourceValueOperationKind.SHIFT_LEFT_REGISTER,
        "INT_RIGHT": SourceValueOperationKind.SHIFT_RIGHT_LOGICAL_REGISTER,
        "INT_SRIGHT": SourceValueOperationKind.SHIFT_RIGHT_ARITHMETIC_REGISTER,
    }
    shifts = [item for item in items
              if getattr(item, "opcode", "").upper() in shift_kind_by_opcode]
    if len(shifts) != 1:
        return None
    shift = shifts[0]
    if getattr(shift, "output", None) is None or len(getattr(shift, "inputs", ())) != 2:
        return None

    producers: dict[object, object] = {}
    for item in items:
        output = getattr(item, "output", None)
        if output is not None:
            if output in producers:
                return None
            producers[output] = item

    register_to_operand: dict[str, int] = {}
    for register, index in runtime_status.rv_to_operand_index.items():
        canonical = canonicalize_riscv_register_name(register)
        if not canonical or canonical in register_to_operand:
            return None
        register_to_operand[canonical] = index

    def operand_index(value: object) -> int | None:
        if getattr(value, "kind", None) is not VarKind.REG:
            return None
        return register_to_operand.get(
            canonicalize_riscv_register_name(getattr(value, "name", ""))
        )

    bindings = {item.source_operand_index: item for item in operands.operands}
    width = getattr(shift.output, "size", 0) * 8
    if width not in {32, 64}:
        return None
    count_mask = width - 1
    consumed: set[int] = set()

    def literal_constant(value: object) -> int | None:
        if getattr(value, "kind", None) is not VarKind.CONST:
            return None
        raw, size = getattr(value, "offset", None), getattr(value, "size", None)
        if (isinstance(raw, bool) or not isinstance(raw, int) or
                isinstance(size, bool) or not isinstance(size, int) or size <= 0):
            return None
        return raw & ((1 << (size * 8)) - 1)

    def is_architectural_shift_count_mask(value: object) -> bool:
        """Recognize only a literal mask or the SLEIGH ``XLEN - 1`` DAG."""
        if literal_constant(value) == count_mask:
            return True
        producer = producers.get(value)
        if producer is None or getattr(producer, "opcode", "").upper() != "INT_SUB":
            return False
        inputs = getattr(producer, "inputs", ())
        # This is intentionally not a general constant folder.  The one
        # admitted non-literal form is the architectural shift-count mask
        # synthesized by SLEIGH: INT_SUB(XLEN, 1) == XLEN - 1.
        if (len(inputs) == 2 and literal_constant(inputs[0]) == width and
                literal_constant(inputs[1]) == 1):
            consumed.add(id(producer))
            return True
        return False

    def resolve_register(value: object, *, allow_count_normalization: bool) -> tuple[int, bool] | None:
        """Return a source operand index and whether XLEN count masking was seen."""
        seen: set[object] = set()
        current = value
        saw_mask = False
        while True:
            if current in seen:
                return None
            seen.add(current)
            index = operand_index(current)
            if index is not None:
                return index, saw_mask
            producer = producers.get(current)
            if producer is None:
                return None
            opcode = getattr(producer, "opcode", "").upper()
            values = getattr(producer, "inputs", ())
            if opcode == "COPY" and len(values) == 1:
                consumed.add(id(producer))
                current = values[0]
                continue
            if not allow_count_normalization:
                return None
            if opcode == "INT_ZEXT" and len(values) == 1:
                consumed.add(id(producer))
                current = values[0]
                continue
            if opcode == "SUBPIECE" and len(values) == 2:
                offset = literal_constant(values[1])
                # Low-byte extraction preserves every architecturally used
                # count bit for both RV32 and RV64.
                if (offset == 0 and getattr(producer.output, "size", 0) * 8 >=
                        (5 if width == 32 else 6)):
                    consumed.add(id(producer))
                    current = values[0]
                    continue
                return None
            if opcode == "INT_AND" and len(values) == 2:
                left, right = values
                if is_architectural_shift_count_mask(left):
                    current = right
                elif is_architectural_shift_count_mask(right):
                    current = left
                else:
                    return None
                consumed.add(id(producer))
                saw_mask = True
                continue
            return None

    source = resolve_register(shift.inputs[0], allow_count_normalization=False)
    count = resolve_register(shift.inputs[1], allow_count_normalization=True)
    if source is None or count is None:
        return None
    source_index, _ = source
    count_index, saw_count_mask = count

    # The visible result may be copied from the machine-operation temporary.
    output_indexes: set[int] = set()
    output_alias_nodes: set[int] = set()
    for candidate in [shift.output, *producers]:
        index = operand_index(candidate)
        if index is None:
            continue
        # Only aliases originating at the shift result are output aliases.
        current = candidate
        aliases_shift = current == shift.output
        aliases: list[object] = []
        seen: set[object] = set()
        while not aliases_shift and current not in seen:
            seen.add(current)
            producer = producers.get(current)
            if producer is None or getattr(producer, "opcode", "").upper() != "COPY":
                break
            values = getattr(producer, "inputs", ())
            if len(values) != 1:
                break
            aliases.append(producer)
            current = values[0]
            aliases_shift = current == shift.output
        if aliases_shift:
            output_indexes.add(index)
            output_alias_nodes.update(id(item) for item in aliases)
    if len(output_indexes) != 1:
        return None
    result_index = next(iter(output_indexes))

    result = bindings.get(result_index)
    source_binding = bindings.get(source_index)
    count_binding = bindings.get(count_index)
    if (
        result is None or result.access is not SourceOperandAccess.OUTPUT
        or source_binding is None or source_binding.access is not SourceOperandAccess.INPUT
        or count_binding is None or count_binding.access is not SourceOperandAccess.INPUT
        or any(item.width_bits != width for item in (result, source_binding, count_binding))
    ):
        return None

    # Every auxiliary semantic node must have been consumed by the source or
    # count proof above.  This prevents a matched shift from hiding unrelated
    # dataflow in the same fragment.
    permitted = {id(shift), *consumed, *output_alias_nodes}
    if any(id(item) not in permitted for item in items):
        return None

    return SourceValueOperationModel(
        kind=shift_kind_by_opcode[getattr(shift, "opcode", "").upper()],
        input_operand_indexes=(source_index, count_index),
        result_operand_index=result_index,
        complete=True,
        shift_count_mask=count_mask if saw_count_mask else None,
    )


def _build_boolean_comparison_value_operation_model(
    *, blocks: Sequence[Block], runtime_status: RuntimeFactStatus,
    operands: SourceOperandModel, operation: SourceOperationModel,
) -> SourceValueOperationModel | None:
    """Model canonical integer comparison followed by boolean zero extension.

    SLEIGH represents RV ``slt/sltu`` (and the wider comparison family) as a
    narrow boolean p-code result followed by ``INT_ZEXT`` into XLEN.  This
    adapter consumes that typed DAG directly; it does not rely on instruction
    spelling or source template order.
    """
    if (operation.kind is not SourceOperationKind.REGISTER_ONLY or
            operation.may_trap is not False or not operands.complete or
            len(blocks) != 1 or not runtime_status.structurally_valid):
        return None
    items = [item for item in blocks[0].ops
             if getattr(item, "opcode", "").upper() != "IMARK"]
    kind_by_opcode = {
        "INT_SLESS": SourceValueOperationKind.SIGNED_LESS,
        "INT_LESS": SourceValueOperationKind.UNSIGNED_LESS,
        "INT_SLESSEQUAL": SourceValueOperationKind.SIGNED_LESS_EQUAL,
        "INT_LESSEQUAL": SourceValueOperationKind.UNSIGNED_LESS_EQUAL,
        "INT_EQUAL": SourceValueOperationKind.EQUAL,
        "INT_NOTEQUAL": SourceValueOperationKind.NOT_EQUAL,
    }
    compares = [item for item in items
                if getattr(item, "opcode", "").upper() in kind_by_opcode]
    extends = [item for item in items
               if getattr(item, "opcode", "").upper() == "INT_ZEXT"]
    if len(compares) != 1 or len(extends) != 1 or len(items) != 2:
        return None
    compare, extend = compares[0], extends[0]
    if (getattr(compare, "output", None) is None or
            getattr(extend, "output", None) is None or
            len(getattr(compare, "inputs", ())) != 2 or
            len(getattr(extend, "inputs", ())) != 1 or
            extend.inputs[0] != compare.output or
            getattr(compare.output, "size", 0) * 8 not in {1, 8}):
        return None
    width = getattr(extend.output, "size", 0) * 8
    if width not in {32, 64}:
        return None
    register_to_operand = {
        canonicalize_riscv_register_name(register): index
        for register, index in runtime_status.rv_to_operand_index.items()
    }
    if "" in register_to_operand or len(register_to_operand) != len(runtime_status.rv_to_operand_index):
        return None
    def index(value: object) -> int | None:
        if getattr(value, "kind", None) is not VarKind.REG:
            return None
        return register_to_operand.get(canonicalize_riscv_register_name(getattr(value, "name", "")))
    result_index = index(extend.output)
    input_indexes = tuple(index(value) for value in compare.inputs)
    if result_index is None or any(value is None for value in input_indexes):
        return None
    bindings = {item.source_operand_index: item for item in operands.operands}
    result = bindings.get(result_index)
    inputs = tuple(bindings.get(value) for value in input_indexes)
    if (result is None or result.access is not SourceOperandAccess.OUTPUT or
            result.width_bits != width or
            any(value is None or value.access is not SourceOperandAccess.INPUT or
                value.width_bits != width for value in inputs)):
        return None
    return SourceValueOperationModel(
        kind=kind_by_opcode[getattr(compare, "opcode", "").upper()],
        input_operand_indexes=tuple(input_indexes),
        result_operand_index=result_index,
        complete=True,
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
    comparison = _build_boolean_comparison_value_operation_model(
        blocks=blocks, runtime_status=runtime_status, operands=operands,
        operation=operation,
    )
    if comparison is not None:
        return comparison
    shift = _build_register_shift_value_operation_model(
        blocks=blocks, runtime_status=runtime_status, operands=operands,
        operation=operation,
    )
    if shift is not None:
        return shift
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
        "INT_LEFT": SourceValueOperationKind.SHIFT_LEFT_REGISTER,
        "INT_RIGHT": SourceValueOperationKind.SHIFT_RIGHT_LOGICAL_REGISTER,
        "INT_SRIGHT": SourceValueOperationKind.SHIFT_RIGHT_ARITHMETIC_REGISTER,
    }
    # A register-count shift is frequently lifted as a two-node semantic DAG:
    #
    #   tmp = INT_AND(count, XLEN - 1)
    #   dst = INT_LEFT/RIGHT/SRIGHT(value, tmp)
    #
    # ``tmp`` is a lifter-only normalization temporary, not a second source
    # operation.  Admit it only as this exact, closed pattern.  In particular,
    # an arbitrary ``and; shift`` sequence remains unmodelled and therefore
    # fail-closed.
    shift_opcodes = frozenset({"INT_LEFT", "INT_RIGHT", "INT_SRIGHT"})
    shift_ops = [
        item for item in canonical_ops
        if getattr(item, "opcode", "").upper() in shift_opcodes
    ]
    potential_shift_count_masks = [
        item for item in canonical_ops
        if getattr(item, "opcode", "").upper() == "INT_AND"
    ]
    shift_count_mask_op = (
        potential_shift_count_masks[0]
        if len(shift_ops) == 1 and len(potential_shift_count_masks) == 1
        else None
    )
    value_ops = [
        item for item in canonical_ops
        if (getattr(item, "opcode", "").upper() in value_kind_by_opcode
            and item is not shift_count_mask_op)
    ]
    copy_ops = [
        item for item in canonical_ops
        if getattr(item, "opcode", "").upper() == "COPY"
    ]
    if (len(value_ops) != 1 or
            len(value_ops) + len(copy_ops) +
            (1 if shift_count_mask_op is not None else 0) != len(canonical_ops)):
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

    def _unsigned_constant_value(value: object) -> int | None:
        raw_value = getattr(value, "offset", None)
        byte_size = getattr(value, "size", None)
        if (
            getattr(value, "kind", None) is not VarKind.CONST
            or isinstance(raw_value, bool)
            or not isinstance(raw_value, int)
            or isinstance(byte_size, bool)
            or not isinstance(byte_size, int)
            or byte_size <= 0
            or byte_size * 8 > result.width_bits
        ):
            return None
        return raw_value & ((1 << (byte_size * 8)) - 1)

    def _resolve_shift_count(value: object) -> tuple[object, int | None] | None:
        """Resolve the sole admitted lifted count-mask normalization."""
        resolved = resolve_copy_source(value)
        if resolved is None:
            return None
        if shift_count_mask_op is None or resolved != shift_count_mask_op.output:
            return resolved, None
        mask_inputs = getattr(shift_count_mask_op, "inputs", ())
        if len(mask_inputs) != 2:
            return None
        for count, mask in ((mask_inputs[0], mask_inputs[1]),
                            (mask_inputs[1], mask_inputs[0])):
            resolved_count = resolve_copy_source(count)
            mask_value = _unsigned_constant_value(resolve_copy_source(mask))
            if (resolved_count is not None and mask_value == result.width_bits - 1):
                return resolved_count, mask_value
        return None

    input_indexes: list[int] = []
    constants: list[tuple[int, object]] = []
    shift_count_mask: int | None = None
    for input_position, input_var in enumerate(op.inputs):
        resolved_input = resolve_copy_source(input_var)
        if resolved_input is None:
            return None
        if kind in {
            SourceValueOperationKind.SHIFT_LEFT_REGISTER,
            SourceValueOperationKind.SHIFT_RIGHT_LOGICAL_REGISTER,
            SourceValueOperationKind.SHIFT_RIGHT_ARITHMETIC_REGISTER,
        } and input_position == 1:
            normalized_count = _resolve_shift_count(resolved_input)
            if normalized_count is None:
                return None
            resolved_input, shift_count_mask = normalized_count
        index = operand_index(resolved_input)
        if index is not None:
            input_indexes.append(index)
        elif getattr(resolved_input, "kind", None) is VarKind.CONST:
            constants.append((input_position, resolved_input))
        else:
            return None
    variable_shift_kinds = {
        SourceValueOperationKind.SHIFT_LEFT_REGISTER,
        SourceValueOperationKind.SHIFT_RIGHT_LOGICAL_REGISTER,
        SourceValueOperationKind.SHIFT_RIGHT_ARITHMETIC_REGISTER,
    }
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
        # x86 shifts and RISC-V immediate shifts both define only counts in
        # the operand width domain; keep the count canonical rather than using
        # the generic ALU imm32 policy below.
        if kind in variable_shift_kinds:
            if constant_position != 1 or immediate_value < 0 or immediate_value >= result.width_bits:
                return None
            kind = {
                SourceValueOperationKind.SHIFT_LEFT_REGISTER: SourceValueOperationKind.SHIFT_LEFT_IMMEDIATE,
                SourceValueOperationKind.SHIFT_RIGHT_LOGICAL_REGISTER: SourceValueOperationKind.SHIFT_RIGHT_LOGICAL_IMMEDIATE,
                SourceValueOperationKind.SHIFT_RIGHT_ARITHMETIC_REGISTER: SourceValueOperationKind.SHIFT_RIGHT_ARITHMETIC_IMMEDIATE,
            }[kind]
        # x86-64 ALU immediate encodings sign-extend an imm32.  Restricting
        # this contract to that exact shared value domain prevents a renderer
        # from silently changing a 64-bit source constant's upper bits.
        if kind not in variable_shift_kinds and not -(1 << 31) <= immediate_value <= (1 << 31) - 1:
            return None
    return SourceValueOperationModel(
        kind=kind,
        input_operand_indexes=tuple(input_indexes),
        result_operand_index=result_index,
        complete=True,
        immediate_value=immediate_value,
        shift_count_mask=shift_count_mask,
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
