"""Content-bound, fail-closed authority envelopes for source semantic facts.

This module is deliberately independent from route selection.  Constructing a
valid envelope does not make a translation applicable; it only establishes a
uniform, auditable ingress contract that later phases may explicitly consume.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Mapping, TypeAlias


SEMANTIC_AUTHORITY_SCHEMA = "riscv2x86.semantic-authority-envelope.v1"
SEMANTIC_AUTHORITY_BUNDLE_SCHEMA = "riscv2x86.semantic-authority-bundle.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]*$")


class SemanticAuthorityError(ValueError):
    """An authority artifact is malformed, stale, untrusted, or conflicting."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _identity(value: object) -> str:
    return "sha256:" + sha256(_canonical(value)).hexdigest()


def _non_empty(value: object) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, tuple):
        return bool(value) and all(_non_empty(item) for item in value)
    if isinstance(value, bool):
        return value
    return True


class _AuthorityPayload:
    FACT_KIND = ""
    REQUIRED_FIELDS: tuple[str, ...] = ()
    NODE_FIELDS: tuple[str, ...] = ()
    KEY_FIELDS: tuple[str, ...] = ()

    def missing_fields(self) -> tuple[str, ...]:
        return tuple(name for name in self.REQUIRED_FIELDS
                     if not _non_empty(getattr(self, name)))

    def referenced_node_ids(self) -> tuple[str, ...]:
        result: list[str] = []
        for name in self.NODE_FIELDS:
            value = getattr(self, name)
            if isinstance(value, str) and value:
                result.append(value)
            elif isinstance(value, tuple):
                result.extend(item for item in value if isinstance(item, str) and item)
        return tuple(sorted(set(result)))

    def fact_key(self) -> tuple[object, ...]:
        return tuple(getattr(self, name) for name in self.KEY_FIELDS)

    def invalid_fields(self) -> tuple[str, ...]:
        invalid: list[str] = []
        for item in fields(self):
            value = getattr(self, item.name)
            if value is None:
                continue
            if item.name in {"width_bytes", "alignment_bytes", "width_bits",
                             "wraparound_width_bits"}:
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    invalid.append(item.name)
            elif item.name in {"operand_index", "address_operand_index"}:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    invalid.append(item.name)
            elif item.name == "offset_bytes":
                if isinstance(value, bool) or not isinstance(value, int):
                    invalid.append(item.name)
            elif item.name in {"bounds_proven", "escape_proven"}:
                if not isinstance(value, bool):
                    invalid.append(item.name)
            elif isinstance(value, tuple):
                if (any(not isinstance(entry, str) or not entry for entry in value)
                        or len(value) != len(set(value))):
                    invalid.append(item.name)
            elif not isinstance(value, str):
                invalid.append(item.name)
        return tuple(sorted(set(invalid)))

    def to_dict(self) -> dict[str, object]:
        return {
            item.name: (list(value) if isinstance(value, tuple) else value)
            for item in fields(self)
            for value in (getattr(self, item.name),)
        }


@dataclass(frozen=True)
class MemoryOperandBoundaryFacts(_AuthorityPayload):
    object_identity: str | None = None
    address_node_id: str | None = None
    base_operand_identity: str | None = None
    offset_bytes: int | None = None
    width_bytes: int | None = None
    alignment_bytes: int | None = None
    bounds_proven: bool | None = None
    value_node_id: str | None = None
    address_space_identity: str | None = None

    FACT_KIND = "memory_operand_boundary"
    REQUIRED_FIELDS = ("object_identity", "address_node_id", "base_operand_identity",
                       "offset_bytes", "width_bytes", "alignment_bytes", "bounds_proven",
                       "value_node_id", "address_space_identity")
    NODE_FIELDS = ("address_node_id", "value_node_id")
    KEY_FIELDS = ("address_node_id",)


@dataclass(frozen=True)
class OperandValueFlowFacts(_AuthorityPayload):
    value_node_id: str | None = None
    operand_index: int | None = None
    access: str | None = None
    width_bits: int | None = None
    signedness: str | None = None
    declaration_identity: str | None = None
    escape_proven: bool | None = None

    FACT_KIND = "operand_value_flow"
    REQUIRED_FIELDS = ("value_node_id", "operand_index", "access", "width_bits",
                       "signedness", "declaration_identity", "escape_proven")
    NODE_FIELDS = ("value_node_id",)
    KEY_FIELDS = ("value_node_id",)


@dataclass(frozen=True)
class StructuredControlFlowFacts(_AuthorityPayload):
    entry_node_id: str | None = None
    successor_node_ids: tuple[str, ...] = ()
    taken_continuation_id: str | None = None
    fallthrough_continuation_id: str | None = None
    condition_kind: str | None = None
    condition_node_ids: tuple[str, ...] = ()
    label_binding_identity: str | None = None

    FACT_KIND = "structured_control_flow"
    REQUIRED_FIELDS = ("entry_node_id", "successor_node_ids", "taken_continuation_id",
                       "fallthrough_continuation_id", "condition_kind",
                       "condition_node_ids", "label_binding_identity")
    NODE_FIELDS = ("entry_node_id", "successor_node_ids", "condition_node_ids")
    KEY_FIELDS = ("entry_node_id",)


@dataclass(frozen=True)
class AtomicOperationFacts(_AuthorityPayload):
    effect_identity: str | None = None
    operation_kind: str | None = None
    width_bits: int | None = None
    address_node_id: str | None = None
    input_value_node_id: str | None = None
    result_value_node_id: str | None = None
    result_semantics: str | None = None
    ordering: tuple[str, ...] = ()
    atomicity_scope: str | None = None
    alignment_bytes: int | None = None
    memory_object_identity: str | None = None
    address_space_identity: str | None = None
    pointee_type_id: str | None = None
    arithmetic_relation: str | None = None
    wraparound_width_bits: int | None = None
    address_operand_index: int | None = None
    read_effect_identity: str | None = None
    write_effect_identity: str | None = None

    FACT_KIND = "atomic_operation"
    REQUIRED_FIELDS = ("effect_identity", "operation_kind", "width_bits",
                       "address_node_id", "input_value_node_id", "result_semantics",
                       "ordering", "atomicity_scope", "alignment_bytes",
                       "memory_object_identity", "address_space_identity",
                       "pointee_type_id", "arithmetic_relation",
                       "wraparound_width_bits", "address_operand_index",
                       "read_effect_identity", "write_effect_identity")
    NODE_FIELDS = ("address_node_id", "input_value_node_id", "result_value_node_id")
    KEY_FIELDS = ("effect_identity",)

    def missing_fields(self) -> tuple[str, ...]:
        missing = list(super().missing_fields())
        if self.result_semantics != "none" and not self.result_value_node_id:
            missing.append("result_value_node_id")
        return tuple(sorted(set(missing)))

    def invalid_fields(self) -> tuple[str, ...]:
        invalid = list(super().invalid_fields())
        if (self.wraparound_width_bits is not None and
                (isinstance(self.wraparound_width_bits, bool) or
                 self.wraparound_width_bits not in {32, 64})):
            invalid.append("wraparound_width_bits")
        if (self.address_operand_index is not None and
                (isinstance(self.address_operand_index, bool) or
                 not isinstance(self.address_operand_index, int) or
                 self.address_operand_index < 0)):
            invalid.append("address_operand_index")
        if (self.width_bits is not None and self.wraparound_width_bits is not None
                and self.width_bits != self.wraparound_width_bits):
            invalid.append("wraparound_width_bits")
        if self.arithmetic_relation is not None and self.arithmetic_relation not in {
            "exchange", "add_mod_2n", "and_bits", "or_bits", "xor_bits",
            "compare_exchange",
        }:
            invalid.append("arithmetic_relation")
        return tuple(sorted(set(invalid)))


@dataclass(frozen=True)
class PrivilegedOperationFacts(_AuthorityPayload):
    effect_identity: str | None = None
    operation_kind: str | None = None
    semantic_class: str | None = None
    privilege_mode: str | None = None
    state_effect_ids: tuple[str, ...] = ()
    value_node_ids: tuple[str, ...] = ()
    trap_relation_identity: str | None = None

    FACT_KIND = "privileged_operation"
    REQUIRED_FIELDS = ("effect_identity", "operation_kind", "semantic_class",
                       "privilege_mode", "state_effect_ids", "trap_relation_identity")
    NODE_FIELDS = ("value_node_ids",)
    KEY_FIELDS = ("effect_identity",)


@dataclass(frozen=True)
class InstructionStreamSyncFacts(_AuthorityPayload):
    effect_identity: str | None = None
    scope_identity: str | None = None
    address_range_identity: str | None = None
    publication_effect_id: str | None = None
    instruction_fetch_effect_id: str | None = None
    coherence_model_identity: str | None = None

    FACT_KIND = "instruction_stream_sync"
    REQUIRED_FIELDS = ("effect_identity", "scope_identity", "address_range_identity",
                       "publication_effect_id", "instruction_fetch_effect_id",
                       "coherence_model_identity")
    KEY_FIELDS = ("effect_identity",)


@dataclass(frozen=True)
class CsrOperationFacts(_AuthorityPayload):
    effect_identity: str | None = None
    csr_identity: str | None = None
    access_kind: str | None = None
    read_value_node_id: str | None = None
    write_value_node_id: str | None = None
    privilege_mode: str | None = None
    required_extension: str | None = None
    trap_policy_identity: str | None = None

    FACT_KIND = "csr_operation"
    REQUIRED_FIELDS = ("effect_identity", "csr_identity", "access_kind",
                       "privilege_mode", "required_extension", "trap_policy_identity")
    NODE_FIELDS = ("read_value_node_id", "write_value_node_id")
    KEY_FIELDS = ("effect_identity",)

    def missing_fields(self) -> tuple[str, ...]:
        missing = list(super().missing_fields())
        if self.access_kind in {"read", "read_write"} and not self.read_value_node_id:
            missing.append("read_value_node_id")
        if self.access_kind in {"write", "read_write"} and not self.write_value_node_id:
            missing.append("write_value_node_id")
        return tuple(sorted(set(missing)))


AuthorityPayload: TypeAlias = (
    MemoryOperandBoundaryFacts | OperandValueFlowFacts | StructuredControlFlowFacts |
    AtomicOperationFacts | PrivilegedOperationFacts | InstructionStreamSyncFacts |
    CsrOperationFacts
)

_PAYLOAD_TYPES: Mapping[str, type[_AuthorityPayload]] = MappingProxyType({
    item.FACT_KIND: item for item in (
        MemoryOperandBoundaryFacts, OperandValueFlowFacts, StructuredControlFlowFacts,
        AtomicOperationFacts, PrivilegedOperationFacts, InstructionStreamSyncFacts,
        CsrOperationFacts,
    )
})


@dataclass(frozen=True)
class RegisteredAuthorityProducer:
    producer_identity: str
    versions: tuple[str, ...]
    fact_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _IDENTITY.fullmatch(self.producer_identity):
            raise SemanticAuthorityError("producer identity is invalid")
        if (not self.versions or self.versions != tuple(sorted(set(self.versions)))
                or not all(_IDENTITY.fullmatch(item) for item in self.versions)):
            raise SemanticAuthorityError("producer versions must be canonical identities")
        if (not self.fact_kinds or self.fact_kinds != tuple(sorted(set(self.fact_kinds)))
                or any(item not in _PAYLOAD_TYPES for item in self.fact_kinds)):
            raise SemanticAuthorityError("producer fact kinds are invalid or noncanonical")


@dataclass(frozen=True)
class AuthorityProducerRegistry:
    producers: tuple[RegisteredAuthorityProducer, ...]

    def __post_init__(self) -> None:
        identities = tuple(item.producer_identity for item in self.producers)
        if identities != tuple(sorted(set(identities))):
            raise SemanticAuthorityError("producer registry must be unique and canonical")

    def require(self, identity: str, version: str, fact_kind: str) -> None:
        producer = next((item for item in self.producers
                         if item.producer_identity == identity), None)
        if producer is None:
            raise SemanticAuthorityError("semantic authority producer is not registered")
        if version not in producer.versions:
            raise SemanticAuthorityError("semantic authority producer version is not registered")
        if fact_kind not in producer.fact_kinds:
            raise SemanticAuthorityError("producer is not registered for semantic fact kind")


@dataclass(frozen=True)
class SemanticAuthorityEnvelope:
    schema_version: str
    fragment_id: str
    source_digest: str
    producer_identity: str
    producer_version: str
    fact_kind: str
    complete: bool
    reason_codes: tuple[str, ...]
    payload: AuthorityPayload

    def __post_init__(self) -> None:
        if self.schema_version != SEMANTIC_AUTHORITY_SCHEMA:
            raise SemanticAuthorityError("semantic authority schema is unsupported")
        if not self.fragment_id or not _DIGEST.fullmatch(self.source_digest):
            raise SemanticAuthorityError("semantic authority source binding is invalid")
        if not _IDENTITY.fullmatch(self.producer_identity) or not _IDENTITY.fullmatch(
                self.producer_version):
            raise SemanticAuthorityError("semantic authority producer binding is invalid")
        if self.fact_kind not in _PAYLOAD_TYPES or self.payload.FACT_KIND != self.fact_kind:
            raise SemanticAuthorityError("semantic authority fact kind/payload mismatch")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise SemanticAuthorityError("semantic authority reason codes are not canonical")
        missing = self.payload.missing_fields()
        invalid = self.payload.invalid_fields()
        if invalid:
            raise SemanticAuthorityError(
                "semantic authority payload has invalid fields: " + ",".join(invalid)
            )
        if self.complete and missing:
            raise SemanticAuthorityError(
                "complete semantic authority is missing required fields: " + ",".join(missing)
            )
        if not self.complete and not self.reason_codes:
            raise SemanticAuthorityError("incomplete semantic authority needs reason codes")

    @property
    def authority_identity(self) -> str:
        return _identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schemaVersion": self.schema_version,
            "fragmentId": self.fragment_id,
            "sourceDigest": self.source_digest,
            "producerIdentity": self.producer_identity,
            "producerVersion": self.producer_version,
            "factKind": self.fact_kind,
            "complete": self.complete,
            "reasonCodes": list(self.reason_codes),
            "payload": self.payload.to_dict(),
        }
        if include_identity:
            value["authorityIdentity"] = self.authority_identity
        return value


def make_semantic_authority_envelope(*, fragment_id: str, source_digest: str,
                                     producer_identity: str, producer_version: str,
                                     payload: AuthorityPayload,
                                     reason_codes: tuple[str, ...] = ()) -> SemanticAuthorityEnvelope:
    missing = payload.missing_fields()
    reasons = set(reason_codes)
    reasons.update("semantic-authority.required-field-missing:" + item for item in missing)
    return SemanticAuthorityEnvelope(
        SEMANTIC_AUTHORITY_SCHEMA, fragment_id, source_digest, producer_identity,
        producer_version, payload.FACT_KIND, not missing and not reasons,
        tuple(sorted(reasons)), payload,
    )


def _payload_from_dict(fact_kind: str, value: object) -> AuthorityPayload:
    payload_type = _PAYLOAD_TYPES.get(fact_kind)
    if payload_type is None or not isinstance(value, Mapping):
        raise SemanticAuthorityError("semantic authority payload kind or shape is invalid")
    expected = {item.name for item in fields(payload_type)}
    if not set(value) <= expected:
        raise SemanticAuthorityError("semantic authority payload has unknown fields")
    normalized = dict(value)
    for item in fields(payload_type):
        if item.name not in normalized:
            continue
        if item.type == tuple[str, ...] or item.name in {
            "successor_node_ids", "condition_node_ids", "ordering", "state_effect_ids",
            "value_node_ids",
        }:
            raw = normalized[item.name]
            if not isinstance(raw, list) or not all(isinstance(entry, str) and entry for entry in raw):
                raise SemanticAuthorityError("semantic authority tuple field is invalid")
            normalized[item.name] = tuple(raw)
    try:
        return payload_type(**normalized)
    except TypeError as exc:
        raise SemanticAuthorityError("semantic authority payload fields are invalid") from exc


def semantic_authority_envelope_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str,
    expected_source_digest: str, producer_registry: AuthorityProducerRegistry,
    known_decoder_node_ids: frozenset[str],
) -> SemanticAuthorityEnvelope:
    required = {"schemaVersion", "fragmentId", "sourceDigest", "producerIdentity",
                "producerVersion", "factKind", "complete", "reasonCodes", "payload",
                "authorityIdentity"}
    if set(value) != required:
        raise SemanticAuthorityError("semantic authority envelope fields are incomplete or unknown")
    if value.get("schemaVersion") != SEMANTIC_AUTHORITY_SCHEMA:
        raise SemanticAuthorityError("semantic authority schema is unsupported")
    if value.get("fragmentId") != expected_fragment_id:
        raise SemanticAuthorityError("semantic authority fragment identity mismatch")
    if value.get("sourceDigest") != expected_source_digest:
        raise SemanticAuthorityError("semantic authority source digest mismatch")
    fact_kind = value.get("factKind")
    identity, version = value.get("producerIdentity"), value.get("producerVersion")
    if not all(isinstance(item, str) for item in (fact_kind, identity, version)):
        raise SemanticAuthorityError("semantic authority producer/fact identity is invalid")
    producer_registry.require(identity, version, fact_kind)
    reasons = value.get("reasonCodes")
    if not isinstance(reasons, list) or not all(isinstance(item, str) and item for item in reasons):
        raise SemanticAuthorityError("semantic authority reason codes are invalid")
    complete = value.get("complete")
    if not isinstance(complete, bool):
        raise SemanticAuthorityError("semantic authority completeness flag is invalid")
    envelope = SemanticAuthorityEnvelope(
        str(value["schemaVersion"]), str(value["fragmentId"]), str(value["sourceDigest"]),
        identity, version, fact_kind, complete, tuple(reasons),
        _payload_from_dict(fact_kind, value.get("payload")),
    )
    if value.get("authorityIdentity") != envelope.authority_identity:
        raise SemanticAuthorityError("semantic authority content identity mismatch")
    missing_nodes = set(envelope.payload.referenced_node_ids()) - set(known_decoder_node_ids)
    if missing_nodes:
        raise SemanticAuthorityError(
            "semantic authority references unknown decoder/value nodes: " +
            ",".join(sorted(missing_nodes))
        )
    return envelope


def merge_semantic_authorities(
    authorities: tuple[SemanticAuthorityEnvelope, ...],
) -> tuple[SemanticAuthorityEnvelope, ...]:
    """Merge identical duplicate evidence and reject semantic disagreement."""
    by_key: dict[tuple[object, ...], SemanticAuthorityEnvelope] = {}
    for authority in authorities:
        key = (authority.fragment_id, authority.fact_kind, authority.payload.fact_key())
        previous = by_key.get(key)
        if previous is None:
            by_key[key] = authority
        elif previous.payload.to_dict() != authority.payload.to_dict():
            raise SemanticAuthorityError("conflicting authorities for the same semantic fact")
        elif previous.complete != authority.complete:
            raise SemanticAuthorityError("conflicting completeness claims for semantic fact")
    return tuple(by_key[key] for key in sorted(by_key, key=repr))


@dataclass(frozen=True)
class SemanticAuthorityBundle:
    source_digest: str
    fragment_id: str
    authorities: tuple[SemanticAuthorityEnvelope, ...]
    schema_version: str = SEMANTIC_AUTHORITY_BUNDLE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != SEMANTIC_AUTHORITY_BUNDLE_SCHEMA:
            raise SemanticAuthorityError("semantic authority bundle schema is unsupported")
        if not _DIGEST.fullmatch(self.source_digest) or not self.fragment_id:
            raise SemanticAuthorityError("semantic authority bundle binding is invalid")
        if not self.authorities:
            raise SemanticAuthorityError("semantic authority bundle must not be empty")
        if any(item.source_digest != self.source_digest or item.fragment_id != self.fragment_id
               for item in self.authorities):
            raise SemanticAuthorityError("semantic authority bundle contains stale authority")
        if self.authorities != merge_semantic_authorities(self.authorities):
            raise SemanticAuthorityError("semantic authority bundle contains duplicate authority")

    @property
    def bundle_identity(self) -> str:
        return _identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schemaVersion": self.schema_version,
            "sourceDigest": self.source_digest,
            "fragmentId": self.fragment_id,
            "authorities": [item.to_dict() for item in self.authorities],
        }
        if include_identity:
            value["bundleIdentity"] = self.bundle_identity
        return value


def semantic_authority_bundle_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str,
    expected_source_digest: str, producer_registry: AuthorityProducerRegistry,
    known_decoder_node_ids: frozenset[str],
) -> SemanticAuthorityBundle:
    if set(value) != {"schemaVersion", "sourceDigest", "fragmentId", "authorities",
                      "bundleIdentity"}:
        raise SemanticAuthorityError("semantic authority bundle fields are incomplete or unknown")
    if value.get("schemaVersion") != SEMANTIC_AUTHORITY_BUNDLE_SCHEMA:
        raise SemanticAuthorityError("semantic authority bundle schema is unsupported")
    if value.get("fragmentId") != expected_fragment_id:
        raise SemanticAuthorityError("semantic authority bundle fragment identity mismatch")
    if value.get("sourceDigest") != expected_source_digest:
        raise SemanticAuthorityError("semantic authority bundle source digest mismatch")
    raw = value.get("authorities")
    if not isinstance(raw, list) or not raw or not all(isinstance(item, Mapping) for item in raw):
        raise SemanticAuthorityError("semantic authority bundle authorities are invalid")
    parsed = tuple(semantic_authority_envelope_from_dict(
        item, expected_fragment_id=expected_fragment_id,
        expected_source_digest=expected_source_digest, producer_registry=producer_registry,
        known_decoder_node_ids=known_decoder_node_ids,
    ) for item in raw)
    merged = merge_semantic_authorities(parsed)
    if len(merged) != len(parsed):
        raise SemanticAuthorityError("semantic authority bundle contains duplicate authority")
    bundle = SemanticAuthorityBundle(expected_source_digest, expected_fragment_id, merged)
    if value.get("bundleIdentity") != bundle.bundle_identity:
        raise SemanticAuthorityError("semantic authority bundle content identity mismatch")
    return bundle


def adapt_legacy_authority(*, legacy_schema_version: str, fact_kind: str,
                           fragment_id: str, source_digest: str,
                           producer_identity: str, producer_version: str) -> SemanticAuthorityEnvelope:
    """Create an explicit incomplete bridge without inferring legacy semantics."""
    if not legacy_schema_version or legacy_schema_version in {
            SEMANTIC_AUTHORITY_SCHEMA, SEMANTIC_AUTHORITY_BUNDLE_SCHEMA}:
        raise SemanticAuthorityError("legacy authority schema identity is invalid")
    payload_type = _PAYLOAD_TYPES.get(fact_kind)
    if payload_type is None:
        raise SemanticAuthorityError("legacy authority fact kind is unsupported")
    payload = payload_type()
    reasons = {
        "semantic-authority.legacy-format-incomplete",
        "semantic-authority.legacy-schema:" + legacy_schema_version,
    }
    reasons.update("semantic-authority.required-field-missing:" + item
                   for item in payload.missing_fields())
    return SemanticAuthorityEnvelope(
        SEMANTIC_AUTHORITY_SCHEMA, fragment_id, source_digest, producer_identity,
        producer_version, fact_kind, False, tuple(sorted(reasons)), payload,
    )
