"""Strict, typed, content-addressed L2 authority facts."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Callable, Mapping, Sequence, TypeVar

from .effect_relation import ApprovedEffectRelation, approved_effect_relation_from_dict

LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA = "riscv2x86.l2-authority-sidecar.v1"
L2_AUTHORITY_SIDECAR_SCHEMA = "riscv2x86.l2-authority-sidecar.v2"
L2_AUTHORITY_MIGRATION_VERSION = "l2-authority-v1-to-v2-migration-v1"
L2_EFFECT_RELATION_SET_SCHEMA = "riscv2x86.l2-effect-relation-set.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


def _fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(label + " fields are incomplete or unknown")


def _str(value: Mapping[str, object], key: str, label: str, empty: bool = False) -> str:
    result = value.get(key)
    if not isinstance(result, str) or (not empty and not result):
        raise ValueError(f"{label} {key} is invalid")
    return result


def _int(value: Mapping[str, object], key: str, label: str, minimum: int = 0) -> int:
    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, int) or result < minimum:
        raise ValueError(f"{label} {key} is invalid")
    return result


def _bool(value: Mapping[str, object], key: str, label: str) -> bool:
    result = value.get(key)
    if not isinstance(result, bool):
        raise ValueError(f"{label} {key} must be boolean")
    return result


def _strings(value: object, label: str, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(label + " must be an array of non-empty strings")
    result = tuple(value)
    if (nonempty and not result) or result != tuple(sorted(set(result))):
        raise ValueError(label + " must be unique and sorted")
    return result


@dataclass(frozen=True)
class L2OperandAuthority:
    operand_id: str
    operand_index: int
    logical_name: str
    access_mode: str
    type_kind: str
    width_bits: int
    signedness: str
    tied_to_operand_id: str
    early_clobber: bool
    fixed_register_contract: str
    escape_kind: str
    declaration_id: str = ""
    parameter_index: int | None = None
    source_constraint: str = ""
    target_contract_carried_by_proof: bool = True

    def __post_init__(self) -> None:
        if not self.operand_id or not self.logical_name or self.operand_index < 0:
            raise ValueError("operand authority identity/index is invalid")
        if self.access_mode not in {"input", "output", "read_write", "address", "control_target"}:
            raise ValueError("operand authority access mode is unsupported")
        if self.type_kind not in {"integer", "pointer", "floating", "aggregate"}:
            raise ValueError("operand authority type kind is unsupported")
        if self.width_bits <= 0 or self.signedness not in {"signed", "unsigned", "not_applicable"}:
            raise ValueError("operand authority width/signedness is invalid")
        if self.type_kind == "integer" and self.signedness == "not_applicable":
            raise ValueError("integer operand authority requires signedness")
        if self.parameter_index is not None and (isinstance(self.parameter_index, bool)
                                                  or self.parameter_index < 0):
            raise ValueError("operand authority parameter index is invalid")
        if self.escape_kind not in {"none", "function_argument", "function_return",
                                    "memory_object", "external", "non_escaping"}:
            raise ValueError("operand authority escape kind is unsupported")

    def to_dict(self) -> dict[str, object]:
        return {"operandId": self.operand_id, "operandIndex": self.operand_index,
                "logicalName": self.logical_name, "accessMode": self.access_mode,
                "typeKind": self.type_kind, "widthBits": self.width_bits,
                "signedness": self.signedness, "tiedToOperandId": self.tied_to_operand_id,
                "earlyClobber": self.early_clobber,
                "fixedRegisterContract": self.fixed_register_contract,
                "escapeKind": self.escape_kind, "declarationId": self.declaration_id,
                "parameterIndex": self.parameter_index,
                "sourceConstraint": self.source_constraint,
                "targetContractCarriedByProof": self.target_contract_carried_by_proof}


_OPERAND_FIELDS = {"operandId", "operandIndex", "logicalName", "accessMode", "typeKind",
                   "widthBits", "signedness", "tiedToOperandId", "earlyClobber",
                   "fixedRegisterContract", "escapeKind", "declarationId", "parameterIndex",
                   "sourceConstraint", "targetContractCarriedByProof"}


def l2_operand_authority_from_dict(v: Mapping[str, object]) -> L2OperandAuthority:
    _fields(v, _OPERAND_FIELDS, "operand authority")
    parameter = v.get("parameterIndex")
    if parameter is not None and (isinstance(parameter, bool) or not isinstance(parameter, int)):
        raise ValueError("operand authority parameterIndex is invalid")
    return L2OperandAuthority(_str(v, "operandId", "operand authority"),
        _int(v, "operandIndex", "operand authority"), _str(v, "logicalName", "operand authority"),
        _str(v, "accessMode", "operand authority"), _str(v, "typeKind", "operand authority"),
        _int(v, "widthBits", "operand authority", 1), _str(v, "signedness", "operand authority"),
        _str(v, "tiedToOperandId", "operand authority", True),
        _bool(v, "earlyClobber", "operand authority"),
        _str(v, "fixedRegisterContract", "operand authority", True),
        _str(v, "escapeKind", "operand authority"),
        _str(v, "declarationId", "operand authority", True), parameter,
        _str(v, "sourceConstraint", "operand authority", True),
        _bool(v, "targetContractCarriedByProof", "operand authority"))


@dataclass(frozen=True)
class L2MemoryObjectAuthority:
    object_id: str
    origin_kind: str
    size_bytes: int
    minimum_alignment: int
    lifetime_scope: str
    alias_class: str
    readable_ranges: tuple[tuple[int, int], ...]
    writable_ranges: tuple[tuple[int, int], ...]
    complete: bool

    def __post_init__(self) -> None:
        if not all((self.object_id, self.origin_kind, self.lifetime_scope, self.alias_class)):
            raise ValueError("memory object authority identity/origin is incomplete")
        if self.size_bytes <= 0 or self.minimum_alignment <= 0:
            raise ValueError("memory object size/alignment is invalid")
        for ranges in (self.readable_ranges, self.writable_ranges):
            if ranges != tuple(sorted(set(ranges))):
                raise ValueError("memory object ranges must be unique and sorted")
            if any(start < 0 or end <= start or end > self.size_bytes for start, end in ranges):
                raise ValueError("memory object range is outside bounds")
        if self.complete and not (self.readable_ranges or self.writable_ranges):
            raise ValueError("complete memory object authority requires bounds")

    def to_dict(self) -> dict[str, object]:
        return {"objectId": self.object_id, "originKind": self.origin_kind,
                "sizeBytes": self.size_bytes, "minimumAlignment": self.minimum_alignment,
                "lifetimeScope": self.lifetime_scope, "aliasClass": self.alias_class,
                "readableRanges": [list(x) for x in self.readable_ranges],
                "writableRanges": [list(x) for x in self.writable_ranges], "complete": self.complete}


def _ranges(value: object, label: str) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list):
        raise ValueError(label + " must be an array")
    result = []
    for item in value:
        if (not isinstance(item, list) or len(item) != 2
                or any(isinstance(x, bool) or not isinstance(x, int) for x in item)):
            raise ValueError(label + " entries must be integer pairs")
        result.append((item[0], item[1]))
    return tuple(result)


def l2_memory_object_authority_from_dict(v: Mapping[str, object]) -> L2MemoryObjectAuthority:
    _fields(v, {"objectId", "originKind", "sizeBytes", "minimumAlignment", "lifetimeScope",
                "aliasClass", "readableRanges", "writableRanges", "complete"}, "memory object")
    return L2MemoryObjectAuthority(_str(v, "objectId", "memory object"),
        _str(v, "originKind", "memory object"), _int(v, "sizeBytes", "memory object", 1),
        _int(v, "minimumAlignment", "memory object", 1),
        _str(v, "lifetimeScope", "memory object"), _str(v, "aliasClass", "memory object"),
        _ranges(v.get("readableRanges"), "readable ranges"),
        _ranges(v.get("writableRanges"), "writable ranges"), _bool(v, "complete", "memory object"))


@dataclass(frozen=True)
class L2SourceEffectAuthority:
    effect_id: str
    effect_kind: str
    logical_subject: str
    complete: bool
    def __post_init__(self) -> None:
        if not self.effect_id or not self.effect_kind:
            raise ValueError("source effect authority is incomplete")
    def to_dict(self) -> dict[str, object]:
        return {"effectId": self.effect_id, "effectKind": self.effect_kind,
                "logicalSubject": self.logical_subject, "complete": self.complete}


def l2_source_effect_authority_from_dict(v: Mapping[str, object]) -> L2SourceEffectAuthority:
    _fields(v, {"effectId", "effectKind", "logicalSubject", "complete"}, "source effect")
    return L2SourceEffectAuthority(_str(v, "effectId", "source effect"),
        _str(v, "effectKind", "source effect"), _str(v, "logicalSubject", "source effect", True),
        _bool(v, "complete", "source effect"))


@dataclass(frozen=True)
class L2ControlFlowAuthority:
    condition_id: str
    input_operand_ids: tuple[str, ...]
    continuations: tuple[str, ...]
    continuation_complete: bool
    transfer_kind: str = ""
    condition_kind: str = ""
    result_operand_id: str = ""
    true_value_operand_id: str = ""
    false_value_operand_id: str = ""
    selected_value_operand_id: str = ""
    source_continuation: str = ""
    target_continuation: str = ""
    termination_kind: str = "normal_return"
    def __post_init__(self) -> None:
        if not self.condition_id or not self.input_operand_ids or not self.continuations:
            raise ValueError("control-flow authority is incomplete")
        if self.input_operand_ids != tuple(sorted(set(self.input_operand_ids))):
            raise ValueError("control-flow operands must be unique and sorted")
        if self.continuations != tuple(sorted(set(self.continuations))):
            raise ValueError("control-flow continuations must be unique and sorted")
        if self.continuation_complete:
            if self.transfer_kind == "conditional":
                if (self.condition_kind not in {"equal", "not_equal", "signed_less",
                        "unsigned_less", "signed_less_equal", "unsigned_less_equal"}
                        or not self.result_operand_id or not self.true_value_operand_id
                        or not self.false_value_operand_id
                        or set(self.continuations) != {
                            "continuation:not-taken", "continuation:taken"}):
                    raise ValueError("complete branch authority lacks typed condition/value facts")
            elif self.transfer_kind == "direct":
                if (not self.result_operand_id or not self.selected_value_operand_id
                        or not self.source_continuation or not self.target_continuation):
                    raise ValueError("complete direct-transfer authority lacks target/value facts")
                if self.continuations != (self.target_continuation,):
                    raise ValueError("direct-transfer continuation set is incomplete")
            else:
                raise ValueError("complete control-flow authority transfer kind is unsupported")
            if self.termination_kind not in {"normal_return", "fallthrough"}:
                raise ValueError("control-flow termination kind is unsupported")
    def to_dict(self) -> dict[str, object]:
        return {"conditionId": self.condition_id, "inputOperandIds": list(self.input_operand_ids),
                "continuations": list(self.continuations),
                "continuationComplete": self.continuation_complete,
                "transferKind": self.transfer_kind, "conditionKind": self.condition_kind,
                "resultOperandId": self.result_operand_id,
                "trueValueOperandId": self.true_value_operand_id,
                "falseValueOperandId": self.false_value_operand_id,
                "selectedValueOperandId": self.selected_value_operand_id,
                "sourceContinuation": self.source_continuation,
                "targetContinuation": self.target_continuation,
                "terminationKind": self.termination_kind}


def l2_control_flow_authority_from_dict(v: Mapping[str, object]) -> L2ControlFlowAuthority:
    _fields(v, {"conditionId", "inputOperandIds", "continuations", "continuationComplete",
                "transferKind", "conditionKind", "resultOperandId", "trueValueOperandId",
                "falseValueOperandId", "selectedValueOperandId", "sourceContinuation",
                "targetContinuation", "terminationKind"},
            "control-flow")
    return L2ControlFlowAuthority(_str(v, "conditionId", "control-flow"),
        _strings(v.get("inputOperandIds"), "control-flow operands", True),
        _strings(v.get("continuations"), "control-flow continuations", True),
        _bool(v, "continuationComplete", "control-flow"),
        _str(v, "transferKind", "control-flow", True),
        _str(v, "conditionKind", "control-flow", True),
        _str(v, "resultOperandId", "control-flow", True),
        _str(v, "trueValueOperandId", "control-flow", True),
        _str(v, "falseValueOperandId", "control-flow", True),
        _str(v, "selectedValueOperandId", "control-flow", True),
        _str(v, "sourceContinuation", "control-flow", True),
        _str(v, "targetContinuation", "control-flow", True),
        _str(v, "terminationKind", "control-flow"))


@dataclass(frozen=True)
class L2OrderingAuthority:
    ordering_id: str
    before_effect_id: str
    after_effect_id: str
    complete: bool
    def __post_init__(self) -> None:
        if not self.ordering_id or not self.before_effect_id or not self.after_effect_id:
            raise ValueError("ordering authority is incomplete")
        if self.before_effect_id == self.after_effect_id:
            raise ValueError("ordering authority contains a self edge")
    def to_dict(self) -> dict[str, object]:
        return {"orderingId": self.ordering_id, "beforeEffectId": self.before_effect_id,
                "afterEffectId": self.after_effect_id, "complete": self.complete}


def l2_ordering_authority_from_dict(v: Mapping[str, object]) -> L2OrderingAuthority:
    _fields(v, {"orderingId", "beforeEffectId", "afterEffectId", "complete"}, "ordering")
    return L2OrderingAuthority(_str(v, "orderingId", "ordering"),
        _str(v, "beforeEffectId", "ordering"), _str(v, "afterEffectId", "ordering"),
        _bool(v, "complete", "ordering"))


@dataclass(frozen=True)
class L2InternalValueAuthority:
    value_id: str
    type_kind: str
    width_bits: int
    signedness: str
    escape_kind: str
    complete: bool
    def __post_init__(self) -> None:
        if not self.value_id or not self.type_kind or self.width_bits <= 0:
            raise ValueError("internal value authority is incomplete")
        if self.signedness not in {"signed", "unsigned", "not_applicable"}:
            raise ValueError("internal value signedness is invalid")
        if self.escape_kind not in {"non_escaping", "operand", "memory_object", "external"}:
            raise ValueError("internal value escape is missing or unsupported")
    def to_dict(self) -> dict[str, object]:
        return {"valueId": self.value_id, "typeKind": self.type_kind, "widthBits": self.width_bits,
                "signedness": self.signedness, "escapeKind": self.escape_kind, "complete": self.complete}


def l2_internal_value_authority_from_dict(v: Mapping[str, object]) -> L2InternalValueAuthority:
    _fields(v, {"valueId", "typeKind", "widthBits", "signedness", "escapeKind", "complete"},
            "internal value")
    return L2InternalValueAuthority(_str(v, "valueId", "internal value"),
        _str(v, "typeKind", "internal value"), _int(v, "widthBits", "internal value", 1),
        _str(v, "signedness", "internal value"), _str(v, "escapeKind", "internal value"),
        _bool(v, "complete", "internal value"))


@dataclass(frozen=True)
class L2IgnoredStateAuthority:
    state_id: str
    reason: str
    escape_kind: str
    complete: bool
    def __post_init__(self) -> None:
        if not self.state_id or not self.reason or self.escape_kind != "non_escaping":
            raise ValueError("ignored state must be explicitly non-escaping")
    def to_dict(self) -> dict[str, object]:
        return {"stateId": self.state_id, "reason": self.reason,
                "escapeKind": self.escape_kind, "complete": self.complete}


def l2_ignored_state_authority_from_dict(v: Mapping[str, object]) -> L2IgnoredStateAuthority:
    _fields(v, {"stateId", "reason", "escapeKind", "complete"}, "ignored state")
    return L2IgnoredStateAuthority(_str(v, "stateId", "ignored state"),
        _str(v, "reason", "ignored state"), _str(v, "escapeKind", "ignored state"),
        _bool(v, "complete", "ignored state"))


@dataclass(frozen=True)
class L2RuntimeContractBinding:
    runtime_contract_id: str
    contract_version: str
    contract_identity: str
    complete: bool
    def __post_init__(self) -> None:
        if not self.runtime_contract_id or not self.contract_version:
            raise ValueError("runtime contract binding is incomplete")
        if _SHA256.fullmatch(self.contract_identity) is None:
            raise ValueError("runtime contract identity is invalid")
    def to_dict(self) -> dict[str, object]:
        return {"runtimeContractId": self.runtime_contract_id,
                "contractVersion": self.contract_version,
                "contractIdentity": self.contract_identity, "complete": self.complete}


def l2_runtime_contract_binding_from_dict(v: Mapping[str, object]) -> L2RuntimeContractBinding:
    _fields(v, {"runtimeContractId", "contractVersion", "contractIdentity", "complete"},
            "runtime contract")
    return L2RuntimeContractBinding(_str(v, "runtimeContractId", "runtime contract"),
        _str(v, "contractVersion", "runtime contract"),
        _str(v, "contractIdentity", "runtime contract"), _bool(v, "complete", "runtime contract"))


def effect_relation_set_identity(fragment_id: str,
        relations: Sequence[ApprovedEffectRelation | Mapping[str, object]]) -> str:
    # This public identity helper accepts serialized transport values, but
    # validates them into the same typed DTO before hashing.
    typed = tuple(x if isinstance(x, ApprovedEffectRelation)
                  else approved_effect_relation_from_dict(x) for x in relations)
    return _identity({"schemaVersion": L2_EFFECT_RELATION_SET_SCHEMA, "fragmentId": fragment_id,
                      "approvedEffectRelations": [x.to_dict() for x in typed]})


@dataclass(frozen=True)
class L2AuthorityProducer:
    kind: str
    producer_id: str
    producer_version: str
    producer_binary_digest: str
    def __post_init__(self) -> None:
        if self.kind not in {"frontend-compiler-sidecar", "translation-proof-sidecar"}:
            raise ValueError("L2 authority producer kind is unsupported")
        if not self.producer_id or not self.producer_version:
            raise ValueError("L2 authority producer identity is incomplete")
        if _SHA256.fullmatch(self.producer_binary_digest) is None:
            raise ValueError("L2 authority producer binary digest is invalid")
    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "producerId": self.producer_id,
                "producerVersion": self.producer_version,
                "producerBinaryDigest": self.producer_binary_digest}


@dataclass(frozen=True)
class L2AuthoritySidecar:
    fragment_id: str
    producer: L2AuthorityProducer
    shell_fact_identity: str
    operands: tuple[L2OperandAuthority, ...]
    memory_objects: tuple[L2MemoryObjectAuthority, ...]
    source_effects: tuple[L2SourceEffectAuthority, ...]
    approved_effect_relations: tuple[ApprovedEffectRelation, ...]
    runtime_contracts: tuple[L2RuntimeContractBinding, ...]
    ignored_state: tuple[L2IgnoredStateAuthority, ...]
    complete: bool
    control_flow: tuple[L2ControlFlowAuthority, ...] = ()
    ordering: tuple[L2OrderingAuthority, ...] = ()
    internal_values: tuple[L2InternalValueAuthority, ...] = ()
    authority_identity: str = ""
    schema_version: str = L2_AUTHORITY_SIDECAR_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_AUTHORITY_SIDECAR_SCHEMA:
            raise ValueError("L2 authority sidecar schema is unsupported")
        if not self.fragment_id or _SHA256.fullmatch(self.shell_fact_identity) is None:
            raise ValueError("L2 authority fragment/shell identity is invalid")
        groups = (self.operands, self.memory_objects, self.source_effects,
                  self.approved_effect_relations, self.runtime_contracts, self.ignored_state,
                  self.control_flow, self.ordering, self.internal_values)
        types = (L2OperandAuthority, L2MemoryObjectAuthority, L2SourceEffectAuthority,
                 ApprovedEffectRelation, L2RuntimeContractBinding, L2IgnoredStateAuthority,
                 L2ControlFlowAuthority, L2OrderingAuthority, L2InternalValueAuthority)
        if any(not all(isinstance(x, kind) for x in group) for group, kind in zip(groups, types)):
            raise TypeError("L2 authority sidecar accepts typed DTOs only")
        ids = tuple(x.operand_id for x in self.operands)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("operand authority IDs must be unique and sorted")
        if tuple(x.operand_index for x in self.operands) != tuple(range(len(ids))):
            raise ValueError("operand indices must be contiguous")
        known_operands = set(ids)
        if any(x.tied_to_operand_id and x.tied_to_operand_id not in known_operands
               for x in self.operands):
            raise ValueError("operand tie names an unknown operand")
        if any(not set(x.input_operand_ids).issubset(known_operands) for x in self.control_flow):
            raise ValueError("control-flow authority names an unknown operand")
        if any(not {item for item in (
                x.result_operand_id, x.true_value_operand_id, x.false_value_operand_id,
                x.selected_value_operand_id) if item}.issubset(known_operands)
               for x in self.control_flow):
            raise ValueError("control-flow authority value binding names an unknown operand")
        control_ids = tuple(item.condition_id for item in self.control_flow)
        if control_ids != tuple(sorted(set(control_ids))):
            raise ValueError("control-flow authority IDs must be unique and sorted")
        relation_ids = tuple(x.relation_id for x in self.approved_effect_relations)
        source_ids = tuple(x.source_effect_id for x in self.approved_effect_relations)
        if relation_ids != tuple(sorted(set(relation_ids))) or len(source_ids) != len(set(source_ids)):
            raise ValueError("approved effect relations are not canonical and unique")
        known_effects = {x.effect_id for x in self.source_effects}
        if any(x.source_effect_id not in known_effects for x in self.approved_effect_relations):
            raise ValueError("effect relation names an unknown source effect")
        if any(x.before_effect_id not in known_effects or x.after_effect_id not in known_effects
               for x in self.ordering):
            raise ValueError("ordering authority names an unknown source effect")
        if any(edge.before not in known_effects or edge.after not in known_effects
               for relation in self.approved_effect_relations
               for edge in relation.ordering_requirements):
            raise ValueError("approved ordering relation names an unknown source effect")
        runtime_ids = {x.runtime_contract_id for x in self.runtime_contracts}
        if any(x.relation_kind == "runtime_mediated" and x.runtime_contract_id not in runtime_ids
               for x in self.approved_effect_relations):
            raise ValueError("runtime-mediated relation lacks its runtime contract")
        complete = [x.complete for group in (self.memory_objects, self.source_effects,
                    self.runtime_contracts, self.ignored_state, self.ordering, self.internal_values)
                    for x in group]
        complete += [x.continuation_complete for x in self.control_flow]
        complete += [x.authority_complete for x in self.approved_effect_relations]
        if self.complete and not all(complete):
            raise ValueError("complete sidecar contains incomplete authority facts")
        expected = _identity(self._payload(False))
        if self.authority_identity and self.authority_identity != expected:
            raise ValueError("L2 authority identity does not match content (stale sidecar)")
        object.__setattr__(self, "authority_identity", expected)

    @property
    def effect_relation_set_identity(self) -> str:
        return effect_relation_set_identity(self.fragment_id, self.approved_effect_relations)

    def _payload(self, include_identity: bool) -> dict[str, object]:
        result = {"schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
          "producer": self.producer.to_dict(), "shellFactIdentity": self.shell_fact_identity,
          "operands": [x.to_dict() for x in self.operands],
          "memoryObjects": [x.to_dict() for x in self.memory_objects],
          "sourceEffects": [x.to_dict() for x in self.source_effects],
          "controlFlow": [x.to_dict() for x in self.control_flow],
          "ordering": [x.to_dict() for x in self.ordering],
          "internalValues": [x.to_dict() for x in self.internal_values],
          "approvedEffectRelations": [x.to_dict() for x in self.approved_effect_relations],
          "runtimeContracts": [x.to_dict() for x in self.runtime_contracts],
          "ignoredState": [x.to_dict() for x in self.ignored_state], "complete": self.complete}
        if include_identity:
            result["authorityIdentity"] = self.authority_identity
        return result
    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


T = TypeVar("T")
def _array(value: object, label: str, parser: Callable[[Mapping[str, object]], T]) -> tuple[T, ...]:
    if not isinstance(value, list) or not all(isinstance(x, Mapping) for x in value):
        raise ValueError("L2 authority " + label + " must be an array of objects")
    return tuple(parser(x) for x in value)


def l2_authority_sidecar_from_dict(value: Mapping[str, object], *, expected_fragment_id: str = "",
                                   expected_shell_fact_identity: str = "") -> L2AuthoritySidecar:
    if value.get("schemaVersion") != L2_AUTHORITY_SIDECAR_SCHEMA:
        raise ValueError("L2 authority schema is unsupported; migrate v1 explicitly")
    fields = {"schemaVersion", "fragmentId", "producer", "shellFactIdentity", "operands",
      "memoryObjects", "sourceEffects", "controlFlow", "ordering", "internalValues",
      "approvedEffectRelations", "runtimeContracts", "ignoredState", "complete", "authorityIdentity"}
    _fields(value, fields, "L2 authority sidecar")
    producer = value.get("producer")
    if not isinstance(producer, Mapping):
        raise ValueError("L2 authority producer must be an object")
    _fields(producer, {"kind", "producerId", "producerVersion", "producerBinaryDigest"}, "producer")
    fragment = _str(value, "fragmentId", "sidecar")
    shell = _str(value, "shellFactIdentity", "sidecar")
    if expected_fragment_id and fragment != expected_fragment_id:
        raise ValueError("L2 authority fragment identity mismatch")
    if expected_shell_fact_identity and shell != expected_shell_fact_identity:
        raise ValueError("L2 authority shell fact identity mismatch")
    return L2AuthoritySidecar(fragment, L2AuthorityProducer(_str(producer, "kind", "producer"),
      _str(producer, "producerId", "producer"), _str(producer, "producerVersion", "producer"),
      _str(producer, "producerBinaryDigest", "producer")), shell,
      _array(value.get("operands"), "operands", l2_operand_authority_from_dict),
      _array(value.get("memoryObjects"), "memoryObjects", l2_memory_object_authority_from_dict),
      _array(value.get("sourceEffects"), "sourceEffects", l2_source_effect_authority_from_dict),
      _array(value.get("approvedEffectRelations"), "relations", approved_effect_relation_from_dict),
      _array(value.get("runtimeContracts"), "runtimeContracts", l2_runtime_contract_binding_from_dict),
      _array(value.get("ignoredState"), "ignoredState", l2_ignored_state_authority_from_dict),
      _bool(value, "complete", "sidecar"),
      _array(value.get("controlFlow"), "controlFlow", l2_control_flow_authority_from_dict),
      _array(value.get("ordering"), "ordering", l2_ordering_authority_from_dict),
      _array(value.get("internalValues"), "internalValues", l2_internal_value_authority_from_dict),
      _str(value, "authorityIdentity", "sidecar"))


def migrate_l2_authority_v1_to_v2(value: Mapping[str, object]) -> dict[str, object]:
    """Explicitly migrate the known scalar v1 shape without inventing facts."""
    old_fields = {"schemaVersion", "fragmentId", "producer", "shellFactIdentity", "operands",
      "memoryObjects", "sourceEffects", "approvedEffectRelations", "runtimeContracts",
      "ignoredState", "complete", "authorityIdentity"}
    _fields(value, old_fields, "legacy sidecar")
    if value.get("schemaVersion") != LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA:
        raise ValueError("only L2 authority v1 can be migrated")
    if any(value.get(x) for x in ("memoryObjects", "runtimeContracts", "ignoredState")):
        raise ValueError("legacy non-scalar facts require producer regeneration")
    raw = value.get("operands")
    if not isinstance(raw, list) or not all(isinstance(x, Mapping) for x in raw):
        raise ValueError("legacy operands are invalid")
    old_operand_fields = {"operandIndex", "operandName", "operandId", "declarationId",
      "accessMode", "widthBits", "parameterIndex", "signedness", "tiedToOperandIndex",
      "earlyClobber", "sourceConstraint", "targetContractCarriedByProof", "escaped", "escapeKind"}
    ids = {x.get("operandIndex"): x.get("operandId") for x in raw}
    operands = []
    for x in raw:
        _fields(x, old_operand_fields, "legacy operand")
        tie = x.get("tiedToOperandIndex")
        if tie is not None and tie not in ids:
            raise ValueError("legacy operand tie cannot be resolved")
        operands.append(L2OperandAuthority(str(x["operandId"]), int(x["operandIndex"]),
          str(x["operandName"]), str(x["accessMode"]), "integer", int(x["widthBits"]),
          str(x["signedness"]), str(ids[tie]) if tie is not None else "", bool(x["earlyClobber"]),
          "", str(x["escapeKind"]), str(x["declarationId"]), x["parameterIndex"],
          str(x["sourceConstraint"]), bool(x["targetContractCarriedByProof"])).to_dict())
    raw_effects = value.get("sourceEffects")
    if not isinstance(raw_effects, list) or not all(isinstance(x, Mapping) for x in raw_effects):
        raise ValueError("legacy source effects are invalid")
    effects = []
    for x in raw_effects:
        _fields(x, {"eventId", "eventKind"}, "legacy source effect")
        effects.append(L2SourceEffectAuthority(str(x["eventId"]), str(x["eventKind"]),
                                               "", False).to_dict())
    strict = {"schemaVersion": L2_AUTHORITY_SIDECAR_SCHEMA, "fragmentId": value["fragmentId"],
      "producer": value["producer"], "shellFactIdentity": value["shellFactIdentity"],
      "operands": operands, "memoryObjects": [], "sourceEffects": effects, "controlFlow": [],
      "ordering": [], "internalValues": [], "approvedEffectRelations": value["approvedEffectRelations"],
      "runtimeContracts": [], "ignoredState": [], "complete": False}
    strict["authorityIdentity"] = _identity(strict)
    return {"schemaVersion": "riscv2x86.l2-authority-migration-result.v1",
            "sourceSchemaVersion": LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA,
            "canonicalizationVersion": L2_AUTHORITY_MIGRATION_VERSION,
            "sidecar": strict}


def load_l2_authority_sidecar(path: str | Path, *, expected_fragment_id: str = "",
                              expected_shell_fact_identity: str = "") -> L2AuthoritySidecar:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("L2 authority sidecar root must be an object")
    return l2_authority_sidecar_from_dict(value, expected_fragment_id=expected_fragment_id,
                                          expected_shell_fact_identity=expected_shell_fact_identity)


def authority_identity_set(identities: Sequence[str], *, role: str) -> str:
    values = tuple(identities)
    if any(_SHA256.fullmatch(x) is None for x in values):
        return ""
    return _identity({"schemaVersion": "riscv2x86.l2-authority-binding-set.v1",
                      "role": role, "identities": list(values)})
