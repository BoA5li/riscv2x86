"""Phase-6A read-only adapter for privileged Phase-5 products."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .functional_observability import (
    FunctionalFallbackPossibility,
    FunctionalObservabilityContract,
)
from .privileged_state_analysis import (
    CsrEffectOperation,
    PrivilegedSemanticClass,
    SourcePrivilegedStateModel,
)


class PrivilegedAdapterReasonCode:
    STATE_MISSING = "phase6a.privileged-state-missing"
    STATE_INCOMPLETE = "phase6a.privileged-state-incomplete"
    OBSERVABILITY_MISSING = "phase6a.privileged-observability-missing"
    OBSERVABILITY_INCOMPLETE = "phase6a.privileged-observability-incomplete"
    FRAGMENT_ID_MISMATCH = "phase6a.privileged-fragment-id-mismatch"
    OUTPUT_SURFACE_MISMATCH = "phase6a.privileged-output-surface-mismatch"
    SHELL_MEMORY_MISMATCH = "phase6a.privileged-shell-memory-mismatch"
    SHELL_VOLATILE_MISMATCH = "phase6a.privileged-shell-volatile-mismatch"
    MEMORY_EFFECT_MISMATCH = "phase6a.privileged-memory-effect-mismatch"
    TRAP_EFFECT_MISMATCH = "phase6a.privileged-trap-effect-mismatch"
    CONTROL_FLOW_EFFECT_MISMATCH = (
        "phase6a.privileged-control-flow-effect-mismatch"
    )
    ABI_EFFECT_CONFLICT = "phase6a.privileged-abi-effect-conflict"
    WHOLE_FUNCTION_ROUTE_MISSING = (
        "phase6a.privileged-whole-function-route-missing"
    )
    WHOLE_FUNCTION_FACTS_MISMATCH = (
        "phase6a.privileged-whole-function-facts-mismatch"
    )
    COUNTER_EFFECT_MISSING = "phase6a.privileged-counter-effect-missing"
    COUNTER_EFFECT_AMBIGUOUS = "phase6a.privileged-counter-effect-ambiguous"
    COUNTER_ACCESS_UNPROVEN = "phase6a.privileged-counter-access-unproven"
    COUNTER_VALUE_SOURCE_MISMATCH = (
        "phase6a.privileged-counter-value-source-mismatch"
    )


@dataclass(frozen=True)
class SourcePrivilegedAccessModel:
    effect_id: str
    result_operand_index: int
    width_bits: int
    complete: bool


@dataclass(frozen=True)
class SourceReadOnlyCounterCsrModel(SourcePrivilegedAccessModel):
    """A bound counter read nested under the privileged source model."""

    csr_name: str


# Compatibility type name used by existing callers.  The object itself now
# belongs to SourcePrivilegedSemanticModel.read_only_counter.
SourceReadOnlyCsrModel = SourceReadOnlyCounterCsrModel


@dataclass(frozen=True)
class SourcePrivilegedSemanticModel:
    state: SourcePrivilegedStateModel | None
    observability: FunctionalObservabilityContract | None
    read_only_counter: SourceReadOnlyCounterCsrModel | None
    functional_fallback_possible: bool
    requires_whole_function_lowering: bool
    complete: bool
    reason_codes: tuple[str, ...]
    semantic_classes: tuple[PrivilegedSemanticClass, ...] = ()
    classification_complete: bool = False

    def __post_init__(self) -> None:
        if tuple(sorted(set(self.reason_codes))) != self.reason_codes:
            raise ValueError("privileged adapter reasons must be unique/sorted")
        if self.complete and self.reason_codes:
            raise ValueError("complete privileged adapter cannot have reasons")
        if tuple(sorted(set(self.semantic_classes), key=lambda item: item.value)) != self.semantic_classes:
            raise ValueError("adapter semantic classes must be unique and sorted")
        if self.complete and not self.classification_complete:
            raise ValueError("complete privileged adapter needs classification")
        if self.functional_fallback_possible and (
            not self.complete or self.observability is None
        ):
            raise ValueError("functional fallback requires complete observability")


def _ordered(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(value for value in values if value)))


def _counter_effect_id(effect: object) -> str:
    csr_id = str(getattr(effect, "csr_id", "")).lower()
    block = int(getattr(effect, "block_address"))
    operation = int(getattr(effect, "operation_index"))
    return f"csr:{csr_id}@0x{block:x}:{operation}:value"


def _counter_name(csr_id: str) -> str:
    return csr_id.strip().lower().rsplit(".", 1)[-1]


def build_privileged_state_adapter(
    *,
    fragment_id: str,
    phase5_state: SourcePrivilegedStateModel | None,
    observability: FunctionalObservabilityContract | None,
    read_only_counter_candidate: SourceReadOnlyCounterCsrModel | None,
    shell: object,
    memory: object,
    control_flow: object,
    abi_effects: object | None,
    whole_function_route: object | None,
    whole_function_facts: object | None = None,
) -> SourcePrivilegedSemanticModel | None:
    """Cross-check Phase-5 products without reading asm, p-code, or CFG."""
    if (
        phase5_state is None
        and observability is None
        and read_only_counter_candidate is None
    ):
        return None

    reasons: list[str] = []
    if phase5_state is None:
        reasons.append(PrivilegedAdapterReasonCode.STATE_MISSING)
    elif not phase5_state.complete:
        reasons.append(PrivilegedAdapterReasonCode.STATE_INCOMPLETE)
        reasons.extend(phase5_state.missing_fact_codes)

    privileged_present = bool(
        phase5_state is not None and phase5_state.present
    )
    if privileged_present and observability is None:
        reasons.append(PrivilegedAdapterReasonCode.OBSERVABILITY_MISSING)
    if observability is not None:
        if observability.fragment_id != fragment_id:
            reasons.append(PrivilegedAdapterReasonCode.FRAGMENT_ID_MISMATCH)
        if not observability.complete:
            reasons.append(PrivilegedAdapterReasonCode.OBSERVABILITY_INCOMPLETE)
            reasons.extend(observability.missing_fact_codes)
        if len(observability.outputs) != int(getattr(shell, "output_count", -1)):
            reasons.append(PrivilegedAdapterReasonCode.OUTPUT_SURFACE_MISMATCH)
        if (
            observability.memory.compiler_memory_order_observable
            != bool(getattr(shell, "has_memory_clobber", False))
        ):
            reasons.append(PrivilegedAdapterReasonCode.SHELL_MEMORY_MISMATCH)
        if (
            observability.memory.volatile_execution_observable
            != bool(getattr(shell, "is_volatile", False))
        ):
            reasons.append(PrivilegedAdapterReasonCode.SHELL_VOLATILE_MISMATCH)
        if (
            observability.memory.reads_memory
            != bool(getattr(memory, "reads_memory", False))
            or observability.memory.writes_memory
            != bool(getattr(memory, "writes_memory", False))
        ):
            reasons.append(PrivilegedAdapterReasonCode.MEMORY_EFFECT_MISMATCH)
        trap_present = bool(
            phase5_state is not None
            and (
                phase5_state.trap_effects
                or any(item.may_trap is True
                       for item in phase5_state.csr_effects)
            )
        )
        if observability.trap.present is not trap_present:
            reasons.append(PrivilegedAdapterReasonCode.TRAP_EFFECT_MISMATCH)

    semantic_classes = (
        () if phase5_state is None else phase5_state.semantic_classes
    )
    classification_complete = bool(
        phase5_state is not None and phase5_state.classification_complete
    )
    requires_whole_function = (
        PrivilegedSemanticClass.PRIVILEGE_RETURN in semantic_classes
    )
    if requires_whole_function and getattr(control_flow, "has_return", None) is not True:
        reasons.append(
            PrivilegedAdapterReasonCode.CONTROL_FLOW_EFFECT_MISMATCH
        )
    if requires_whole_function and not bool(
        getattr(whole_function_route, "required", False)
    ):
        reasons.append(PrivilegedAdapterReasonCode.WHOLE_FUNCTION_ROUTE_MISSING)
    if requires_whole_function and whole_function_facts is not None:
        member_ids = tuple(getattr(whole_function_facts, "fragment_ids", ()))
        if (
            not bool(getattr(whole_function_facts, "complete", False))
            or fragment_id not in member_ids
        ):
            reasons.append(
                PrivilegedAdapterReasonCode.WHOLE_FUNCTION_FACTS_MISMATCH
            )

    if privileged_present and abi_effects is not None and bool(
        getattr(abi_effects, "calls", ())
    ):
        # A combined privileged transition and local ABI call requires a
        # dedicated contract; it must not enter the ordinary exact wrapper.
        reasons.append(PrivilegedAdapterReasonCode.ABI_EFFECT_CONFLICT)

    # Keep the compatibility candidate nested under this model even when the
    # Phase-5 join is incomplete.  Strict translation can then retain its
    # explicit needs-route diagnostic, while functional fallback remains
    # impossible until the candidate is replaced by a complete joined model.
    counter: SourceReadOnlyCounterCsrModel | None = read_only_counter_candidate
    if read_only_counter_candidate is not None:
        if phase5_state is None:
            pass
        else:
            matches = [
                effect for effect in phase5_state.csr_effects
                if _counter_name(effect.csr_id)
                == read_only_counter_candidate.csr_name
                and effect.operation is CsrEffectOperation.READ
            ]
            if not matches:
                reasons.append(PrivilegedAdapterReasonCode.COUNTER_EFFECT_MISSING)
            elif len(matches) != 1:
                reasons.append(PrivilegedAdapterReasonCode.COUNTER_EFFECT_AMBIGUOUS)
            else:
                effect = matches[0]
                effect_id = _counter_effect_id(effect)
                if not (
                    effect.complete
                    and effect.access_allowed is True
                    and effect.may_trap is False
                ):
                    reasons.append(
                        PrivilegedAdapterReasonCode.COUNTER_ACCESS_UNPROVEN
                    )
                elif (
                    observability is None
                    or effect_id not in
                    observability.required_privileged_value_sources
                ):
                    reasons.append(
                        PrivilegedAdapterReasonCode.COUNTER_VALUE_SOURCE_MISMATCH
                    )
                else:
                    counter = SourceReadOnlyCounterCsrModel(
                        effect_id=effect_id,
                        result_operand_index=(
                            read_only_counter_candidate.result_operand_index
                        ),
                        width_bits=read_only_counter_candidate.width_bits,
                        complete=True,
                        csr_name=read_only_counter_candidate.csr_name,
                    )

    reason_codes = _ordered(reasons)
    complete = bool(
        phase5_state is not None
        and phase5_state.complete
        and (not privileged_present or (
            observability is not None and observability.complete
        ))
        and not reason_codes
    )
    fallback_possible = bool(
        complete
        and observability is not None
        and observability.fallback_possibility is (
            FunctionalFallbackPossibility.POSSIBLE_WITH_EXACT_TARGET_CONTRACT
        )
    )
    return SourcePrivilegedSemanticModel(
        state=phase5_state,
        observability=observability,
        read_only_counter=counter,
        functional_fallback_possible=fallback_possible,
        requires_whole_function_lowering=requires_whole_function,
        complete=complete,
        reason_codes=reason_codes,
        semantic_classes=semantic_classes,
        classification_complete=classification_complete,
    )
