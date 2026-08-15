"""Phase-5 functional observability analysis for privileged fallbacks.

``--allow-functional-fallbacks`` permits an explicit architecture-semantic
downgrade.  It does not permit the translator to drop functional outputs,
memory effects, errors, termination, traps, or compiler-shell effects.  This
module builds the source-side contract that a later target-specific fallback
must satisfy; it never approves or renders target code.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Sequence

from .cfg import CFGResult
from .pcode_ir import IRSummary
from .privileged_state_analysis import (
    CsrEffectOperation,
    SourcePrivilegedStateModel,
)
from .shell_model import SourceShellModel


FUNCTIONAL_OBSERVABILITY_CONTRACT_SCHEMA = (
    "riscv2x86.functional-observability-contract.v1"
)


class FunctionalObservabilityReasonCode(str, Enum):
    PRIVILEGED_STATE_MISSING = (
        "functional-observability.privileged-state-missing"
    )
    PRIVILEGED_STATE_INCOMPLETE = (
        "functional-observability.privileged-state-incomplete"
    )
    OUTPUT_WIDTH_UNKNOWN = "functional-observability.output-width-unknown"
    OUTPUT_BINDING_INCOMPLETE = (
        "functional-observability.output-binding-incomplete"
    )
    MEMORY_EFFECT_UNKNOWN = "functional-observability.memory-effect-unknown"
    ERROR_EFFECT_UNKNOWN = "functional-observability.error-effect-unknown"
    TERMINATION_EFFECT_UNKNOWN = (
        "functional-observability.termination-effect-unknown"
    )
    SHELL_CONTROL_FLOW_INCOMPLETE = (
        "functional-observability.shell-control-flow-incomplete"
    )
    CALL_EFFECT_UNMODELLED = (
        "functional-observability.call-effect-unmodelled"
    )
    TRAP_EFFECT_UNKNOWN = "functional-observability.trap-effect-unknown"
    IGNORED_STATE_DECLARATION_INCOMPLETE = (
        "functional-observability.ignored-state-declaration-incomplete"
    )
    IGNORED_STATE_DUPLICATE = (
        "functional-observability.ignored-state-duplicate"
    )
    IGNORED_STATE_NOT_PRESENT = (
        "functional-observability.ignored-state-not-present"
    )
    OBSERVABLE_EFFECT_CANNOT_BE_IGNORED = (
        "functional-observability.observable-effect-cannot-be-ignored"
    )
    PRIVILEGE_RETURN_REQUIRES_EXACT_CONTROL_FLOW = (
        "functional-observability.privilege-return-requires-exact-control-flow"
    )
    PRIVILEGED_STATE_NOT_IGNORED = (
        "functional-observability.privileged-state-not-ignored"
    )


class FunctionalFallbackPossibility(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    POSSIBLE_WITH_EXACT_TARGET_CONTRACT = (
        "possible_with_exact_target_contract"
    )
    IMPOSSIBLE = "impossible"
    UNKNOWN = "unknown"


class OutputAccess(str, Enum):
    WRITE = "write"
    READ_WRITE = "read_write"


class FunctionalErrorKind(str, Enum):
    NONE = "none"
    ARCHITECTURAL_TRAP = "architectural_trap"
    UNKNOWN = "unknown"


class FunctionalTerminationKind(str, Enum):
    FALLTHROUGH = "fallthrough"
    MULTIPLE_LOCAL_EXITS = "multiple_local_exits"
    NONLOCAL_RETURN = "nonlocal_return"
    NORETURN = "noreturn"
    UNKNOWN = "unknown"


class IgnoredPrivilegedStateKind(str, Enum):
    CSR = "csr"
    INTERRUPT = "interrupt"
    ADDRESS_TRANSLATION = "address_translation"
    VIRTUALIZATION = "virtualization"
    DEBUG = "debug"


@dataclass(frozen=True)
class FunctionalObservableOutput:
    output_operand_index: int
    output_id: str
    width_bits: int | None
    access: OutputAccess
    complete: bool


@dataclass(frozen=True)
class FunctionalMemoryObservability:
    reads_memory: bool
    writes_memory: bool
    compiler_memory_order_observable: bool
    volatile_execution_observable: bool
    complete: bool


@dataclass(frozen=True)
class FunctionalErrorObservability:
    kind: FunctionalErrorKind
    observable: bool
    complete: bool


@dataclass(frozen=True)
class FunctionalTerminationObservability:
    kind: FunctionalTerminationKind
    observable: bool
    normal_exit_count: int | None
    complete: bool


@dataclass(frozen=True)
class FunctionalTrapObservability:
    present: bool | None
    observable: bool
    trap_kinds: tuple[str, ...]
    complete: bool


@dataclass(frozen=True)
class IgnoredStateDeclaration:
    """Explicit authority to omit one non-functional privileged state.

    The stable ``state_id`` must match an effect emitted by this module.  A
    declaration cannot suppress output, memory, error, termination, or trap
    behavior.  Those remain mandatory functional proof obligations.
    """

    state_id: str
    kind: IgnoredPrivilegedStateKind
    justification: str
    provenance: str
    complete: bool

    def __post_init__(self) -> None:
        if not self.state_id:
            raise ValueError("ignored state requires a stable state_id")
        if not isinstance(self.kind, IgnoredPrivilegedStateKind):
            raise TypeError("ignored state kind is invalid")


@dataclass(frozen=True)
class IgnoredPrivilegedState:
    state_id: str
    kind: IgnoredPrivilegedStateKind
    justification: str
    provenance: str


@dataclass(frozen=True)
class FunctionalObservabilityContract:
    fragment_id: str
    outputs: tuple[FunctionalObservableOutput, ...]
    memory: FunctionalMemoryObservability
    error: FunctionalErrorObservability
    termination: FunctionalTerminationObservability
    trap: FunctionalTrapObservability
    ignored_states: tuple[IgnoredPrivilegedState, ...]
    required_privileged_value_sources: tuple[str, ...]
    unignored_privileged_state_ids: tuple[str, ...]
    required_target_obligations: tuple[str, ...]
    fallback_possibility: FunctionalFallbackPossibility
    complete: bool
    missing_fact_codes: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.fragment_id:
            raise ValueError("functional observability requires fragment_id")
        if tuple(sorted(
            self.outputs, key=lambda item: item.output_operand_index
        )) != self.outputs:
            raise ValueError("observable outputs must use stable sorting")
        for values, name in (
            (self.ignored_states, "ignored states"),
            (self.required_privileged_value_sources, "value sources"),
            (self.unignored_privileged_state_ids, "unignored states"),
            (self.required_target_obligations, "target obligations"),
            (self.missing_fact_codes, "missing fact codes"),
            (self.reason_codes, "reason codes"),
        ):
            if tuple(sorted(values, key=_stable_value)) != values:
                raise ValueError(f"{name} must use stable sorting")
        if self.complete and self.missing_fact_codes:
            raise ValueError("complete observability contract has missing facts")
        if not self.complete and not self.missing_fact_codes:
            raise ValueError("incomplete observability contract needs reasons")
        if self.fallback_possibility is (
            FunctionalFallbackPossibility.POSSIBLE_WITH_EXACT_TARGET_CONTRACT
        ) and not self.complete:
            raise ValueError("possible fallback requires a complete contract")

    @property
    def privileged_fallback_possible(self) -> bool:
        return self.fallback_possibility is (
            FunctionalFallbackPossibility.POSSIBLE_WITH_EXACT_TARGET_CONTRACT
        )


def _stable_value(value: object) -> str:
    return str(getattr(value, "state_id", value))


def _reason_codes(
    values: Iterable[str | FunctionalObservabilityReasonCode],
) -> tuple[str, ...]:
    return tuple(sorted(set(
        item.value if isinstance(item, FunctionalObservabilityReasonCode)
        else item
        for item in values
        if item
    )))


def _site_id(prefix: str, block_address: int, operation_index: int) -> str:
    return f"{prefix}@0x{block_address:x}:{operation_index}"


def _privileged_state_inventory(
    model: SourcePrivilegedStateModel,
) -> tuple[
    dict[str, IgnoredPrivilegedStateKind],
    tuple[str, ...],
    frozenset[str],
]:
    """Return mutable state, value sources, and non-ignorable effect IDs."""
    mutable: dict[str, IgnoredPrivilegedStateKind] = {}
    value_sources: list[str] = []
    non_ignorable: set[str] = set()

    for effect in model.csr_effects:
        base = _site_id(
            f"csr:{effect.csr_id}",
            effect.block_address,
            effect.operation_index,
        )
        if effect.operation in {
            CsrEffectOperation.READ,
            CsrEffectOperation.READ_WRITE,
            CsrEffectOperation.SET_BITS,
            CsrEffectOperation.CLEAR_BITS,
        }:
            value_sources.append(base + ":value")
        if effect.operation in {
            CsrEffectOperation.WRITE,
            CsrEffectOperation.READ_WRITE,
            CsrEffectOperation.SET_BITS,
            CsrEffectOperation.CLEAR_BITS,
        }:
            mutable[base + ":state"] = IgnoredPrivilegedStateKind.CSR

    for effect in model.interrupt_effects:
        state_id = _site_id(
            f"interrupt:{effect.kind.value}",
            effect.block_address,
            effect.operation_index,
        )
        mutable[state_id] = IgnoredPrivilegedStateKind.INTERRUPT
    for effect in model.address_translation_effects:
        state_id = _site_id(
            f"address-translation:{effect.kind.value}",
            effect.block_address,
            effect.operation_index,
        )
        mutable[state_id] = IgnoredPrivilegedStateKind.ADDRESS_TRANSLATION
    for effect in model.virtualization_effects:
        state_id = _site_id(
            f"virtualization:{effect.kind.value}",
            effect.block_address,
            effect.operation_index,
        )
        mutable[state_id] = IgnoredPrivilegedStateKind.VIRTUALIZATION
    for effect in model.debug_effects:
        state_id = _site_id(
            f"debug:{effect.kind}",
            effect.block_address,
            effect.operation_index,
        )
        mutable[state_id] = IgnoredPrivilegedStateKind.DEBUG
    for effect in model.trap_effects:
        non_ignorable.add(_site_id(
            f"trap:{effect.kind.value}",
            effect.block_address,
            effect.operation_index,
        ))
    for effect in model.return_effects:
        non_ignorable.add(_site_id(
            f"privilege-return:{effect.kind.value}",
            effect.block_address,
            effect.operation_index,
        ))

    return mutable, tuple(sorted(set(value_sources))), frozenset(non_ignorable)


def _outputs(
    shell: SourceShellModel,
    operand_width_bits: Mapping[int, int],
    reasons: list[str | FunctionalObservabilityReasonCode],
) -> tuple[FunctionalObservableOutput, ...]:
    result: list[FunctionalObservableOutput] = []
    for index, operand in enumerate(shell.outputs):
        width = operand_width_bits.get(index)
        complete = bool(
            operand.has_constraint
            and operand.has_expression
            and isinstance(width, int)
            and not isinstance(width, bool)
            and width > 0
        )
        if not operand.has_constraint or not operand.has_expression:
            reasons.append(
                FunctionalObservabilityReasonCode.OUTPUT_BINDING_INCOMPLETE
            )
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            width = None
            reasons.append(
                FunctionalObservabilityReasonCode.OUTPUT_WIDTH_UNKNOWN
            )
        access = (
            OutputAccess.READ_WRITE
            if "+" in operand.constraint or operand.is_tied
            else OutputAccess.WRITE
        )
        result.append(FunctionalObservableOutput(
            output_operand_index=index,
            output_id=f"gnu-output:{index}",
            width_bits=width,
            access=access,
            complete=complete,
        ))
    return tuple(result)


def _termination(
    *,
    shell: SourceShellModel,
    summary: IRSummary,
    cfg: CFGResult | None,
) -> FunctionalTerminationObservability:
    if shell.has_control_flow_surface:
        if (
            shell.has_non_local_control_dependency
            or shell.has_external_control_flow
            or (shell.has_asm_goto and not shell.asm_goto_control_flow_complete)
        ):
            return FunctionalTerminationObservability(
                FunctionalTerminationKind.UNKNOWN, True, None, False
            )
        shell_exit_count = len(shell.asm_goto_successor_continuation_ids)
        if shell.asm_goto_fallthrough_continuation_id:
            shell_exit_count += 1
        if shell.has_asm_goto and shell_exit_count:
            return FunctionalTerminationObservability(
                FunctionalTerminationKind.MULTIPLE_LOCAL_EXITS,
                True,
                shell_exit_count,
                True,
            )
    cfg_complete = cfg is not None and cfg.ok and bool(cfg.nodes)
    semantic_complete = (
        summary.has_return is not None
        and summary.has_tail_call is not None
        and summary.has_indirect_control_flow is not None
    )
    if not cfg_complete or not semantic_complete:
        return FunctionalTerminationObservability(
            FunctionalTerminationKind.UNKNOWN, True, None, False
        )
    if summary.has_indirect_control_flow or summary.has_tail_call:
        return FunctionalTerminationObservability(
            FunctionalTerminationKind.UNKNOWN, True, None, False
        )
    if summary.has_return:
        return FunctionalTerminationObservability(
            FunctionalTerminationKind.NONLOCAL_RETURN, True, 1, True
        )
    normal_exits = sum(
        1 for node in cfg.nodes.values()
        if not node.successors and not node.has_unknown_target
    )
    kind = (
        FunctionalTerminationKind.MULTIPLE_LOCAL_EXITS
        if normal_exits > 1
        else FunctionalTerminationKind.FALLTHROUGH
    )
    return FunctionalTerminationObservability(
        kind, True, normal_exits, normal_exits > 0
    )


def analyze_functional_observability(
    *,
    fragment_id: str,
    shell: SourceShellModel,
    summary: IRSummary,
    cfg: CFGResult | None,
    privileged_state: SourcePrivilegedStateModel | None,
    operand_width_bits: Mapping[int, int],
    ignored_state_declarations: Sequence[IgnoredStateDeclaration] = (),
) -> FunctionalObservabilityContract:
    """Build a fail-closed source contract for privileged fallback routing."""
    if not fragment_id:
        raise ValueError("functional observability requires fragment_id")
    if not isinstance(shell, SourceShellModel):
        raise TypeError("shell must be a SourceShellModel")
    if not isinstance(summary, IRSummary):
        raise TypeError("summary must be an IRSummary")

    missing: list[str | FunctionalObservabilityReasonCode] = []
    blockers: list[str | FunctionalObservabilityReasonCode] = []
    outputs = _outputs(shell, operand_width_bits, missing)

    memory_complete = all(isinstance(value, bool) for value in (
        summary.reads_mem,
        summary.writes_mem,
        summary.has_unknown_barrier,
    )) and not summary.has_unknown_barrier
    if not memory_complete:
        missing.append(FunctionalObservabilityReasonCode.MEMORY_EFFECT_UNKNOWN)
    memory = FunctionalMemoryObservability(
        reads_memory=bool(summary.reads_mem),
        writes_memory=bool(summary.writes_mem),
        compiler_memory_order_observable=shell.has_memory_clobber,
        volatile_execution_observable=shell.is_volatile,
        complete=memory_complete,
    )

    termination = _termination(shell=shell, summary=summary, cfg=cfg)
    if not termination.complete:
        missing.append(
            FunctionalObservabilityReasonCode.TERMINATION_EFFECT_UNKNOWN
        )
        if shell.has_control_flow_surface:
            missing.append(
                FunctionalObservabilityReasonCode.SHELL_CONTROL_FLOW_INCOMPLETE
            )
    if (
        summary.has_call_or_return
        and summary.has_return is False
        and not (
            privileged_state is not None
            and (privileged_state.trap_effects
                 or privileged_state.return_effects)
        )
    ):
        missing.append(
            FunctionalObservabilityReasonCode.CALL_EFFECT_UNMODELLED
        )

    if privileged_state is None:
        missing.append(
            FunctionalObservabilityReasonCode.PRIVILEGED_STATE_MISSING
        )
        privileged_present = True
        mutable_states: dict[str, IgnoredPrivilegedStateKind] = {}
        value_sources: tuple[str, ...] = ()
        non_ignorable = frozenset()
        error = FunctionalErrorObservability(
            FunctionalErrorKind.UNKNOWN, True, False
        )
        trap = FunctionalTrapObservability(None, True, (), False)
    else:
        privileged_present = privileged_state.present
        if privileged_present and not privileged_state.complete:
            missing.append(
                FunctionalObservabilityReasonCode.PRIVILEGED_STATE_INCOMPLETE
            )
            missing.extend(privileged_state.missing_fact_codes)
        mutable_states, value_sources, non_ignorable = (
            _privileged_state_inventory(privileged_state)
        )
        trap_unknown = any(
            effect.may_trap is None for effect in privileged_state.csr_effects
        )
        trap_kinds = tuple(sorted(set(
            effect.kind.value for effect in privileged_state.trap_effects
        )))
        trap_present = bool(
            trap_kinds
            or any(effect.may_trap is True
                   for effect in privileged_state.csr_effects)
        )
        trap_complete = privileged_state.complete and not trap_unknown
        if not trap_complete:
            missing.append(
                FunctionalObservabilityReasonCode.TRAP_EFFECT_UNKNOWN
            )
        trap = FunctionalTrapObservability(
            trap_present if trap_complete else None,
            True,
            trap_kinds,
            trap_complete,
        )
        error = FunctionalErrorObservability(
            FunctionalErrorKind.ARCHITECTURAL_TRAP
            if trap_present else FunctionalErrorKind.NONE,
            trap_present,
            trap_complete,
        )
        if not error.complete:
            missing.append(
                FunctionalObservabilityReasonCode.ERROR_EFFECT_UNKNOWN
            )

    declaration_ids = [item.state_id for item in ignored_state_declarations]
    if len(declaration_ids) != len(set(declaration_ids)):
        missing.append(
            FunctionalObservabilityReasonCode.IGNORED_STATE_DUPLICATE
        )

    ignored: list[IgnoredPrivilegedState] = []
    for declaration in sorted(
        ignored_state_declarations, key=lambda item: item.state_id
    ):
        if (
            not declaration.complete
            or not declaration.justification
            or not declaration.provenance
        ):
            missing.append(
                FunctionalObservabilityReasonCode.
                IGNORED_STATE_DECLARATION_INCOMPLETE
            )
            continue
        if declaration.state_id in non_ignorable:
            blockers.append(
                FunctionalObservabilityReasonCode.
                OBSERVABLE_EFFECT_CANNOT_BE_IGNORED
            )
            continue
        actual_kind = mutable_states.get(declaration.state_id)
        if actual_kind is None or actual_kind is not declaration.kind:
            missing.append(
                FunctionalObservabilityReasonCode.IGNORED_STATE_NOT_PRESENT
            )
            continue
        ignored.append(IgnoredPrivilegedState(
            declaration.state_id,
            declaration.kind,
            declaration.justification,
            declaration.provenance,
        ))

    ignored_ids = frozenset(item.state_id for item in ignored)
    unignored = tuple(sorted(set(mutable_states) - ignored_ids))
    if unignored:
        blockers.append(
            FunctionalObservabilityReasonCode.PRIVILEGED_STATE_NOT_IGNORED
        )
    if privileged_state is not None and privileged_state.return_effects:
        blockers.append(
            FunctionalObservabilityReasonCode.
            PRIVILEGE_RETURN_REQUIRES_EXACT_CONTROL_FLOW
        )

    missing_fact_codes = _reason_codes(missing)
    blocker_codes = _reason_codes(blockers)
    reason_codes = tuple(sorted(set(missing_fact_codes + blocker_codes)))
    complete = not missing_fact_codes
    if not privileged_present and complete:
        possibility = FunctionalFallbackPossibility.NOT_APPLICABLE
    elif not complete:
        possibility = FunctionalFallbackPossibility.UNKNOWN
    elif blocker_codes:
        possibility = FunctionalFallbackPossibility.IMPOSSIBLE
    else:
        possibility = (
            FunctionalFallbackPossibility.
            POSSIBLE_WITH_EXACT_TARGET_CONTRACT
        )

    obligations = ["preserve-output-values", "preserve-termination"]
    if memory.reads_memory or memory.writes_memory:
        obligations.append("preserve-memory-effects")
    if memory.compiler_memory_order_observable:
        obligations.append("preserve-compiler-memory-order")
    if memory.volatile_execution_observable:
        obligations.append("preserve-volatile-execution")
    if shell.has_cc_clobber:
        obligations.append("preserve-condition-code-clobber")
    if shell.has_tied_operands or shell.has_early_clobber:
        obligations.append("preserve-operand-shell-contract")
    if shell.has_control_flow_surface:
        obligations.append("preserve-shell-control-flow")
    if trap.present is not False:
        obligations.extend(("preserve-error-behavior", "preserve-trap-behavior"))
    if value_sources:
        obligations.append("provide-exact-functional-value-contract")

    return FunctionalObservabilityContract(
        fragment_id=fragment_id,
        outputs=outputs,
        memory=memory,
        error=error,
        termination=termination,
        trap=trap,
        ignored_states=tuple(sorted(ignored, key=_stable_value)),
        required_privileged_value_sources=value_sources,
        unignored_privileged_state_ids=unignored,
        required_target_obligations=tuple(sorted(set(obligations))),
        fallback_possibility=possibility,
        complete=complete,
        missing_fact_codes=missing_fact_codes,
        reason_codes=reason_codes,
    )


def functional_observability_contract_to_dict(
    contract: FunctionalObservabilityContract,
) -> dict[str, object]:
    """Serialize the immutable Phase-5 artifact without source/asm text."""
    if not isinstance(contract, FunctionalObservabilityContract):
        raise TypeError("contract must be FunctionalObservabilityContract")
    return {
        "schemaVersion": FUNCTIONAL_OBSERVABILITY_CONTRACT_SCHEMA,
        "fragmentId": contract.fragment_id,
        "outputs": [
            {
                "outputOperandIndex": item.output_operand_index,
                "outputId": item.output_id,
                "widthBits": item.width_bits,
                "access": item.access.value,
                "complete": item.complete,
            }
            for item in contract.outputs
        ],
        "memory": {
            "readsMemory": contract.memory.reads_memory,
            "writesMemory": contract.memory.writes_memory,
            "compilerMemoryOrderObservable": (
                contract.memory.compiler_memory_order_observable
            ),
            "volatileExecutionObservable": (
                contract.memory.volatile_execution_observable
            ),
            "complete": contract.memory.complete,
        },
        "error": {
            "kind": contract.error.kind.value,
            "observable": contract.error.observable,
            "complete": contract.error.complete,
        },
        "termination": {
            "kind": contract.termination.kind.value,
            "observable": contract.termination.observable,
            "normalExitCount": contract.termination.normal_exit_count,
            "complete": contract.termination.complete,
        },
        "trap": {
            "present": contract.trap.present,
            "observable": contract.trap.observable,
            "trapKinds": list(contract.trap.trap_kinds),
            "complete": contract.trap.complete,
        },
        "ignoredStates": [
            {
                "stateId": item.state_id,
                "kind": item.kind.value,
                "justification": item.justification,
                "provenance": item.provenance,
            }
            for item in contract.ignored_states
        ],
        "requiredPrivilegedValueSources": list(
            contract.required_privileged_value_sources
        ),
        "unignoredPrivilegedStateIds": list(
            contract.unignored_privileged_state_ids
        ),
        "requiredTargetObligations": list(
            contract.required_target_obligations
        ),
        "fallbackPossibility": contract.fallback_possibility.value,
        "privilegedFallbackPossible": contract.privileged_fallback_possible,
        "complete": contract.complete,
        "missingFactCodes": list(contract.missing_fact_codes),
        "reasonCodes": list(contract.reason_codes),
    }
