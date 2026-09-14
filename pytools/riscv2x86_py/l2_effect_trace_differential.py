"""L2-B normalized effect-trace, approved-relation and shell validation."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping

from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .l2_operand_differential import (
    L2OperandRunnerConfig, load_logical_operand_authority,
    compare_logical_operands,
)
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_observation import ExecutionObservation, SemanticEvent
from .validation_status import ValidationStatus
from .effect_relation import ApprovedEffectRelation, approved_effect_relation_from_dict
from .l2_authority import effect_relation_set_identity


EFFECT_TRACE_AUTHORITY_SCHEMA = "riscv2x86.effect-trace-authority.v1"
L2_EFFECT_RUNNER_SCHEMA = "riscv2x86.l2-effect-trace-differential-runner.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEMORY_KINDS = {"read_memory", "write_memory", "atomic"}


def _digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(data.encode()).hexdigest()


def _fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(label + " fields are incomplete or unknown")


def _string(value: Mapping[str, object], name: str, label: str, *, empty: bool = False) -> str:
    item = value.get(name)
    if not isinstance(item, str) or (not empty and not item):
        raise ValueError(f"{label}.{name} must be a string")
    return item


def _boolean(value: Mapping[str, object], name: str, label: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool):
        raise ValueError(f"{label}.{name} must be boolean")
    return item


def _strings(value: object, label: str, *, allowed: set[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be a string array")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ValueError(label + " must be unique and canonically ordered")
    if allowed is not None and not set(result).issubset(allowed):
        raise ValueError(label + " contains an unsupported requirement")
    return result


@dataclass(frozen=True)
class SourceLocation:
    file_identity: str
    line: int
    column: int

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.file_identity) or self.line <= 0 or self.column <= 0:
            raise ValueError("effect source location is invalid")


@dataclass(frozen=True)
class SourceEffectDeclaration:
    event_id: str
    fragment_id: str
    event_kind: str
    logical_subject: str
    source_location: SourceLocation

    def __post_init__(self) -> None:
        if not self.event_id or not self.fragment_id or not self.event_kind:
            raise ValueError("source effect declaration is incomplete")


@dataclass(frozen=True)
class SourceShellContract:
    volatile: bool
    memory_clobber: bool
    cc_clobber: bool
    compiler_barrier: bool
    asm_goto: bool
    memory_operand_ids: tuple[str, ...]
    immediate_operand_ids: tuple[str, ...]
    host_type_facts_identity: str


@dataclass(frozen=True)
class TargetShellRecipe:
    recipe_id: str
    volatile_carried: bool
    memory_ordering_carrier: str
    cc_clobber_carried: bool
    asm_goto_carrier: str
    memory_operand_ids: tuple[str, ...]
    immediate_operand_ids: tuple[str, ...]
    host_type_facts_identity: str
    abi_stack_frame_safety_status: str
    operand_semantics_carried_by_l2a: bool

    def __post_init__(self) -> None:
        if self.memory_ordering_carrier not in {"none", "compiler-barrier", "hardware-fence", "runtime"}:
            raise ValueError("target memory ordering carrier is invalid")
        if self.asm_goto_carrier not in {"none", "asm-goto", "structured-control-flow"}:
            raise ValueError("target asm-goto carrier is invalid")
        if self.abi_stack_frame_safety_status not in {"verified", "failed", "inconclusive"}:
            raise ValueError("target ABI/stack/frame status is invalid")


@dataclass(frozen=True)
class FragmentEffectAuthority:
    fragment_id: str
    source_events: tuple[SourceEffectDeclaration, ...]
    relations: tuple[ApprovedEffectRelation, ...]
    source_shell: SourceShellContract
    target_shell: TargetShellRecipe

    def __post_init__(self) -> None:
        source_ids = tuple(item.event_id for item in self.source_events)
        relation_ids = tuple(item.source_effect_id for item in self.relations)
        if source_ids != tuple(sorted(set(source_ids))):
            raise ValueError("source effects must be unique and canonically ordered")
        if relation_ids != tuple(sorted(set(relation_ids))):
            raise ValueError("effect relations must be unique and canonically ordered")
        if any(item.fragment_id != self.fragment_id for item in self.source_events):
            raise ValueError("source effect references another fragment")
        target_ids = [item for relation in self.relations for item in relation.target_effect_ids]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("a target effect cannot satisfy multiple source relations")


@dataclass(frozen=True)
class EffectTraceAuthoritySidecar:
    producer_kind: str
    producer_id: str
    producer_version: str
    producer_binary_digest: str
    source_shell_facts_identity: str
    runtime_contract_id: str
    runtime_contract_version: str
    fragments: tuple[FragmentEffectAuthority, ...]
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.producer_kind != "translation-proof-sidecar":
            raise ValueError("effect relations must come from the translation proof")
        if not self.producer_id or not self.producer_version or not _SHA256.fullmatch(self.producer_binary_digest):
            raise ValueError("effect authority producer identity is incomplete")
        if not _SHA256.fullmatch(self.source_shell_facts_identity):
            raise ValueError("effect authority shell identity is invalid")
        ids = tuple(item.fragment_id for item in self.fragments)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("effect authority fragments must be unique and sorted")

    @property
    def identity(self) -> str:
        return _digest(self.payload)

    def for_fragment(self, fragment_id: str) -> FragmentEffectAuthority | None:
        return next((item for item in self.fragments if item.fragment_id == fragment_id), None)


@dataclass(frozen=True)
class L2EffectRunnerConfig:
    operand_authority_sidecar_path: str
    effect_authority_sidecar_path: str
    comparison_policy: str = ARCHITECTURAL_COMPARISON_POLICY
    schema_version: str = L2_EFFECT_RUNNER_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != L2_EFFECT_RUNNER_SCHEMA or
                self.comparison_policy != ARCHITECTURAL_COMPARISON_POLICY or
                not self.operand_authority_sidecar_path or not self.effect_authority_sidecar_path):
            raise ValueError("L2 effect runner configuration is invalid")


def _parse_location(value: object) -> SourceLocation:
    if not isinstance(value, Mapping):
        raise ValueError("sourceLocation must be an object")
    _fields(value, {"fileIdentity", "line", "column"}, "source location")
    line, column = value.get("line"), value.get("column")
    if isinstance(line, bool) or not isinstance(line, int) or isinstance(column, bool) or not isinstance(column, int):
        raise ValueError("source location coordinates must be integers")
    return SourceLocation(_string(value, "fileIdentity", "source location"), line, column)


def _parse_shell(source: object, target: object) -> tuple[SourceShellContract, TargetShellRecipe]:
    if not isinstance(source, Mapping) or not isinstance(target, Mapping):
        raise ValueError("shell contracts must be objects")
    source_fields = {"volatile", "memoryClobber", "ccClobber", "compilerBarrier", "asmGoto",
                     "memoryOperandIds", "immediateOperandIds", "hostTypeFactsIdentity"}
    target_fields = {"recipeId", "volatileCarried", "memoryOrderingCarrier", "ccClobberCarried",
                     "asmGotoCarrier", "memoryOperandIds", "immediateOperandIds", "hostTypeFactsIdentity",
                     "abiStackFrameSafetyStatus", "operandSemanticsCarriedByL2A"}
    _fields(source, source_fields, "source shell")
    _fields(target, target_fields, "target shell")
    source_shell = SourceShellContract(
        *(_boolean(source, name, "source shell") for name in
          ("volatile", "memoryClobber", "ccClobber", "compilerBarrier", "asmGoto")),
        _strings(source.get("memoryOperandIds"), "source memory operands"),
        _strings(source.get("immediateOperandIds"), "source immediate operands"),
        _string(source, "hostTypeFactsIdentity", "source shell"),
    )
    target_shell = TargetShellRecipe(
        _string(target, "recipeId", "target shell"), _boolean(target, "volatileCarried", "target shell"),
        _string(target, "memoryOrderingCarrier", "target shell"),
        _boolean(target, "ccClobberCarried", "target shell"),
        _string(target, "asmGotoCarrier", "target shell"),
        _strings(target.get("memoryOperandIds"), "target memory operands"),
        _strings(target.get("immediateOperandIds"), "target immediate operands"),
        _string(target, "hostTypeFactsIdentity", "target shell"),
        _string(target, "abiStackFrameSafetyStatus", "target shell"),
        _boolean(target, "operandSemanticsCarriedByL2A", "target shell"),
    )
    return source_shell, target_shell


def effect_trace_authority_from_dict(value: Mapping[str, object]) -> EffectTraceAuthoritySidecar:
    fields = {"schemaVersion", "producerKind", "producerId", "producerVersion", "producerBinaryDigest",
              "sourceShellFactsIdentity", "runtimeContractId", "runtimeContractVersion", "fragments"}
    _fields(value, fields, "effect trace authority")
    if value.get("schemaVersion") != EFFECT_TRACE_AUTHORITY_SCHEMA:
        raise ValueError("effect trace authority schema is unsupported")
    raw_fragments = value.get("fragments")
    if not isinstance(raw_fragments, list):
        raise ValueError("effect authority fragments must be an array")
    fragments = []
    for raw in raw_fragments:
        if not isinstance(raw, Mapping):
            raise ValueError("effect authority fragment must be an object")
        _fields(raw, {"fragmentId", "sourceEvents", "relations", "sourceShell", "targetShellRecipe"},
                "effect authority fragment")
        fragment_id = _string(raw, "fragmentId", "effect fragment")
        raw_events, raw_relations = raw.get("sourceEvents"), raw.get("relations")
        if not isinstance(raw_events, list) or not isinstance(raw_relations, list):
            raise ValueError("source events and relations must be arrays")
        events = []
        for event in raw_events:
            if not isinstance(event, Mapping): raise ValueError("source event declaration must be an object")
            _fields(event, {"eventId", "fragmentId", "eventKind", "logicalSubject", "sourceLocation"}, "source event")
            events.append(SourceEffectDeclaration(
                _string(event, "eventId", "source event"), _string(event, "fragmentId", "source event"),
                _string(event, "eventKind", "source event"), _string(event, "logicalSubject", "source event", empty=True),
                _parse_location(event.get("sourceLocation")),
            ))
        relations = []
        for relation in raw_relations:
            if not isinstance(relation, Mapping): raise ValueError("effect relation must be an object")
            relations.append(approved_effect_relation_from_dict(relation))
        source_shell, target_shell = _parse_shell(raw.get("sourceShell"), raw.get("targetShellRecipe"))
        fragments.append(FragmentEffectAuthority(fragment_id, tuple(events), tuple(relations), source_shell, target_shell))
    return EffectTraceAuthoritySidecar(
        _string(value, "producerKind", "effect authority"), _string(value, "producerId", "effect authority"),
        _string(value, "producerVersion", "effect authority"),
        _string(value, "producerBinaryDigest", "effect authority"),
        _string(value, "sourceShellFactsIdentity", "effect authority"),
        _string(value, "runtimeContractId", "effect authority"),
        _string(value, "runtimeContractVersion", "effect authority"), tuple(fragments), dict(value),
    )


def load_effect_trace_authority(path: str | Path) -> EffectTraceAuthoritySidecar:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping): raise ValueError("effect trace authority must be an object")
    return effect_trace_authority_from_dict(value)


def load_l2_effect_runner_config(value: Mapping[str, object]) -> L2EffectRunnerConfig:
    _fields(value, {"schemaVersion", "operandAuthoritySidecarPath", "effectAuthoritySidecarPath",
                    "comparisonPolicy"}, "L2 effect runner")
    return L2EffectRunnerConfig(
        _string(value, "operandAuthoritySidecarPath", "L2 effect runner"),
        _string(value, "effectAuthoritySidecarPath", "L2 effect runner"),
        _string(value, "comparisonPolicy", "L2 effect runner"),
        _string(value, "schemaVersion", "L2 effect runner"),
    )


def _required_obligations(event: SemanticEvent) -> set[str]:
    required = {"kind", "subject"}
    if event.kind in _MEMORY_KINDS: required |= {"value", "memory_coordinates", "memory_order"}
    if event.kind == "fence": required.add("memory_order")
    if event.kind in {"read_operand", "write_operand", "return"}: required.add("value")
    if event.kind == "branch":
        required.update({"branch_condition", "branch_outcome", "branch_continuation"})
    if event.kind in {"call", "return"}: required.add("target")
    if event.kind == "trap":
        required.update({"trap_cause", "trap_continuation", "trap_termination"})
    if event.kind == "external": required.add("external_detail")
    if event.kind in {"csr_read", "csr_write"}: required.add("csr_value")
    if event.kind == "privilege_transition": required.add("privilege_state")
    return required


def _obligations_match(source: SemanticEvent, target: SemanticEvent, obligations: tuple[str, ...]) -> bool:
    checks = {
        "kind": source.kind == target.kind,
        "subject": source.subject_id == target.subject_id,
        "value": source.value == target.value,
        "memory_coordinates": (source.object_id, source.offset, source.access_size, source.alignment,
                               source.atomicity) == (target.object_id, target.offset, target.access_size,
                                                      target.alignment, target.atomicity),
        "memory_order": source.memory_order == target.memory_order,
        "compiler_ordering": source.memory_order == target.memory_order,
        "hardware_ordering": source.memory_order == target.memory_order,
        "branch_condition": source.value == target.value,
        "branch_outcome": source.branch_taken == target.branch_taken,
        "branch_continuation": source.target_id == target.target_id,
        "target": source.target_id == target.target_id,
        "trap_cause": source.detail == target.detail,
        "trap_continuation": source.target_id == target.target_id,
        "trap_termination": source.termination == target.termination,
        "external_detail": source.detail == target.detail,
        "csr_value": source.value == target.value,
        "privilege_state": (source.subject_id, source.value, source.detail) ==
                           (target.subject_id, target.value, target.detail),
    }
    return all(checks[item] for item in obligations)


def _order_strengthens(source: str, target: str) -> bool:
    if source == target: return True
    allowed = {
        "relaxed": {"acquire", "release", "acq_rel", "seq_cst"},
        "acquire": {"acq_rel", "seq_cst"}, "release": {"acq_rel", "seq_cst"},
        "acq_rel": {"seq_cst"}, "compiler": {"hardware", "seq_cst"},
        "hardware": {"seq_cst"},
    }
    return target in allowed.get(source, set())


def validate_shell_contract(fragment: FragmentEffectAuthority, *, recipe_id: str,
                            shell_identity: str) -> tuple[str, ...]:
    source, target = fragment.source_shell, fragment.target_shell
    reasons = []
    if target.recipe_id != recipe_id: reasons.append("target-recipe-identity-mismatch")
    if source.host_type_facts_identity != shell_identity or target.host_type_facts_identity != shell_identity:
        reasons.append("host-type-authority-identity-mismatch")
    if source.volatile and not target.volatile_carried: reasons.append("volatile-not-preserved")
    if ((source.memory_clobber or source.compiler_barrier) and
            target.memory_ordering_carrier == "none"):
        reasons.append("compiler-memory-ordering-not-preserved")
    if source.cc_clobber and not target.cc_clobber_carried: reasons.append("cc-clobber-not-preserved")
    if source.asm_goto and target.asm_goto_carrier == "none": reasons.append("asm-goto-not-preserved")
    if source.memory_operand_ids != target.memory_operand_ids: reasons.append("memory-operands-not-preserved")
    if source.immediate_operand_ids != target.immediate_operand_ids: reasons.append("immediates-not-preserved")
    if target.abi_stack_frame_safety_status != "verified": reasons.append("abi-stack-frame-safety-not-verified")
    if not target.operand_semantics_carried_by_l2a: reasons.append("operand-shell-semantics-not-carried")
    return tuple(sorted(reasons))


def compare_effect_traces(*, source: ExecutionObservation, target: ExecutionObservation,
                          authority: EffectTraceAuthoritySidecar, fragment_id: str) -> tuple[str, ...]:
    fragment = authority.for_fragment(fragment_id)
    if fragment is None: return ("effect-authority-fragment-missing",)
    source_events = {item.event_id: item for item in source.semantic_events if item.fragment_id == fragment_id}
    target_events = {item.event_id: item for item in target.semantic_events if item.fragment_id == fragment_id}
    declared = {item.event_id: item for item in fragment.source_events}
    relations = {item.source_effect_id: item for item in fragment.relations}
    reasons = []
    if set(source_events) != set(declared): reasons.append("source-trace-authority-coverage-mismatch")
    covered_targets = {item for relation in fragment.relations for item in relation.target_effect_ids}
    if set(target_events) != covered_targets: reasons.append("target-trace-relation-coverage-mismatch")
    target_sequences = {event.event_id: event.sequence for event in target_events.values()}
    for source_id in sorted(set(source_events) & set(declared)):
        relation = relations.get(source_id)
        if relation is None:
            reasons.append("effect:" + source_id + ":approved-relation-missing")
            continue
        event, declaration = source_events[source_id], declared[source_id]
        prefix = "effect:" + source_id + ":"
        if not relation.authority_complete:
            reasons.append(prefix + "approved-relation-incomplete")
            continue
        if (event.kind, event.subject_id) != (declaration.event_kind, declaration.logical_subject):
            reasons.append(prefix + "source-declaration-mismatch")
        if not _required_obligations(event).issubset(relation.observable_requirements):
            reasons.append(prefix + "observable-requirements-incomplete")
        targets = [target_events[item] for item in relation.target_effect_ids if item in target_events]
        if len(targets) != len(relation.target_effect_ids): continue
        if relation.relation_kind == "runtime_mediated":
            if not any(item.kind in {"call", "external"} for item in targets):
                reasons.append(prefix + "runtime-carrier-missing")
            obligations = tuple(item for item in relation.observable_requirements if item not in {"kind", "target"})
            if obligations and not any(_obligations_match(event, item, obligations) for item in targets):
                reasons.append(prefix + "runtime-observable-effect-mismatch")
        else:
            carrier = targets[-1]
            obligations = tuple(
                item for item in relation.observable_requirements
                if item not in {"kind", "memory_order", "compiler_ordering", "hardware_ordering"}
            ) if relation.relation_kind == "strengthened" else relation.observable_requirements
            if not _obligations_match(event, carrier, obligations):
                reasons.append(prefix + "observable-effect-mismatch")
            if relation.relation_kind == "strengthened":
                if event.kind not in _MEMORY_KINDS | {"fence"} or carrier.kind not in _MEMORY_KINDS | {"fence"}:
                    reasons.append(prefix + "invalid-strengthening-kind")
                elif event.kind != carrier.kind:
                    reasons.append(prefix + "invalid-strengthening-kind")
                if not _order_strengthens(event.memory_order, carrier.memory_order):
                    reasons.append(prefix + "unproved-order-strengthening")
        for ordering in relation.ordering_requirements:
            before_relation = relations.get(ordering.before)
            after_relation = relations.get(ordering.after)
            if before_relation is None or after_relation is None:
                reasons.append(prefix + "ordering-relation-missing")
                continue
            before = [target_sequences[item] for item in before_relation.target_effect_ids
                      if item in target_sequences]
            after = [target_sequences[item] for item in after_relation.target_effect_ids
                     if item in target_sequences]
            if not before or not after or max(before) >= min(after):
                reasons.append(prefix + "ordering-requirement-not-preserved")
    return tuple(sorted(set(reasons)))


def run_l2_effect_trace_differential(config: L2EffectRunnerConfig, **kwargs: object) -> ValidationLayerResult:
    if kwargs.get("level") is not ValidationLevel.L2:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="L2-B invoked for wrong level")
    source, target = kwargs.get("source_observation"), kwargs.get("target_observation")
    if not isinstance(source, ExecutionObservation) or not isinstance(target, ExecutionObservation):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail="L2-A/B requires source and target observations")
    if kwargs.get("comparison_policy") != config.comparison_policy:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="L2 policy mismatch")
    try:
        operand_authority = load_logical_operand_authority(config.operand_authority_sidecar_path)
        effect_authority = load_effect_trace_authority(config.effect_authority_sidecar_path)
    except OSError as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail="L2 authority unavailable: " + str(exc))
    except (ValueError, json.JSONDecodeError) as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail="L2 authority invalid: " + str(exc))
    artifact = kwargs.get("translation_artifact")
    fragment_id = getattr(artifact, "fragment_id", "")
    shell_identity = getattr(artifact, "shell_facts_identity", "")
    if operand_authority.identity != shell_identity or effect_authority.source_shell_facts_identity != shell_identity:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail="L2 shell authority mismatch")
    if effect_authority.identity != getattr(artifact, "proof_identity", ""):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail="L2 relation proof identity mismatch")
    if (effect_authority.runtime_contract_id, effect_authority.runtime_contract_version) != (
            getattr(artifact, "runtime_contract_id", ""), getattr(artifact, "runtime_contract_version", "")):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail="L2 runtime contract mismatch")
    fragment = effect_authority.for_fragment(fragment_id)
    if fragment is None:
        return ValidationLayerResult(
            ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
            detail="effect-authority-fragment-missing",
        )
    relation_set_identity = effect_relation_set_identity(
        fragment_id, [item.to_dict() for item in fragment.relations],
    )
    if relation_set_identity != getattr(artifact, "effect_relation_set_identity", ""):
        return ValidationLayerResult(
            ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
            detail="L2 approved relation set identity mismatch",
        )
    incomplete = tuple(
        item.relation_id for item in fragment.relations
        if not item.authority_complete
        or (item.relation_kind == "runtime_mediated"
            and item.runtime_contract_id != getattr(artifact, "runtime_contract_id", ""))
    )
    declared_ids = {item.event_id for item in fragment.source_events}
    related_ids = {item.source_effect_id for item in fragment.relations}
    if incomplete or declared_ids != related_ids:
        detail = {
            "reasonCode": "L2_APPROVED_EFFECT_RELATION_INCOMPLETE",
            "incompleteRelationIds": list(incomplete),
            "missingSourceEffectIds": sorted(declared_ids - related_ids),
        }
        return ValidationLayerResult(
            ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
            detail=json.dumps(detail, sort_keys=True),
        )
    else:
        reasons = (
            *compare_logical_operands(source=source, target=target, authority=operand_authority,
                                      fragment_id=fragment_id),
            *validate_shell_contract(fragment, recipe_id=getattr(artifact, "recipe_id", ""),
                                     shell_identity=shell_identity),
            *compare_effect_traces(source=source, target=target, authority=effect_authority,
                                   fragment_id=fragment_id),
        )
    reasons = tuple(sorted(set(reasons)))
    evidence = _digest({"schemaVersion": L2_EFFECT_RUNNER_SCHEMA, "operandAuthority": operand_authority.identity,
                        "effectAuthority": effect_authority.identity, "sourceObservation": source.identity,
                        "targetObservation": target.identity, "fragmentId": fragment_id,
                        "comparisonPolicy": config.comparison_policy, "reasons": reasons})
    return ValidationLayerResult(
        ValidationLevel.L2, ValidationStatus.FAILED if reasons else ValidationStatus.VERIFIED, evidence,
        json.dumps(reasons, separators=(",", ":")) if reasons else "logical operands, effects, ordering and shell match",
    )


def build_l2_effect_validator(config: L2EffectRunnerConfig):
    def validate(**kwargs: object) -> ValidationLayerResult:
        return run_l2_effect_trace_differential(config, **kwargs)
    return validate
