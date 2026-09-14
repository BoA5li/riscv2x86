"""Unified, content-addressed L2 authority emitted by the translation boundary.

The validation side only parses and binds this envelope.  It deliberately has
no fallback that reconstructs operand, shell, or effect facts from C text or
machine registers.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping, Sequence


L2_AUTHORITY_SIDECAR_SCHEMA = "riscv2x86.l2-authority-sidecar.v1"
L2_EFFECT_RELATION_SET_SCHEMA = "riscv2x86.l2-effect-relation-set.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _identity(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def effect_relation_set_identity(
    fragment_id: str, relations: Sequence[Mapping[str, object]],
) -> str:
    return _identity({
        "schemaVersion": L2_EFFECT_RELATION_SET_SCHEMA,
        "fragmentId": fragment_id,
        "approvedEffectRelations": [dict(item) for item in relations],
    })


def _objects(value: object, label: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise ValueError("L2 authority " + label + " must be an array of objects")
    return tuple(dict(item) for item in value)


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
        return {
            "kind": self.kind, "producerId": self.producer_id,
            "producerVersion": self.producer_version,
            "producerBinaryDigest": self.producer_binary_digest,
        }


@dataclass(frozen=True)
class L2AuthoritySidecar:
    fragment_id: str
    producer: L2AuthorityProducer
    shell_fact_identity: str
    operands: tuple[Mapping[str, object], ...]
    memory_objects: tuple[Mapping[str, object], ...]
    source_effects: tuple[Mapping[str, object], ...]
    approved_effect_relations: tuple[Mapping[str, object], ...]
    runtime_contracts: tuple[Mapping[str, object], ...]
    ignored_state: tuple[Mapping[str, object], ...]
    complete: bool
    authority_identity: str = ""
    schema_version: str = L2_AUTHORITY_SIDECAR_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_AUTHORITY_SIDECAR_SCHEMA:
            raise ValueError("L2 authority sidecar schema is unsupported")
        if not self.fragment_id:
            raise ValueError("L2 authority fragment identity is missing")
        if _SHA256.fullmatch(self.shell_fact_identity) is None:
            raise ValueError("L2 authority shell fact identity is invalid")
        from .effect_relation import approved_effect_relation_from_dict
        relations = tuple(
            approved_effect_relation_from_dict(item)
            for item in self.approved_effect_relations
        )
        relation_ids = tuple(item.relation_id for item in relations)
        source_ids = tuple(item.source_effect_id for item in relations)
        if (relation_ids != tuple(sorted(set(relation_ids)))
                or len(source_ids) != len(set(source_ids))):
            raise ValueError("approved effect relations are not canonical and unique")
        expected = _identity(self._payload(False))
        if self.authority_identity and self.authority_identity != expected:
            raise ValueError("L2 authority identity does not match content (stale sidecar)")
        object.__setattr__(self, "authority_identity", expected)

    @property
    def effect_relation_set_identity(self) -> str:
        return effect_relation_set_identity(
            self.fragment_id, self.approved_effect_relations,
        )

    def _payload(self, include_identity: bool) -> dict[str, object]:
        value: dict[str, object] = {
            "schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
            "producer": self.producer.to_dict(),
            "shellFactIdentity": self.shell_fact_identity,
            "operands": [dict(item) for item in self.operands],
            "memoryObjects": [dict(item) for item in self.memory_objects],
            "sourceEffects": [dict(item) for item in self.source_effects],
            "approvedEffectRelations": [dict(item) for item in self.approved_effect_relations],
            "runtimeContracts": [dict(item) for item in self.runtime_contracts],
            "ignoredState": [dict(item) for item in self.ignored_state],
            "complete": self.complete,
        }
        if include_identity:
            value["authorityIdentity"] = self.authority_identity
        return value

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


def l2_authority_sidecar_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
    expected_shell_fact_identity: str = "",
) -> L2AuthoritySidecar:
    fields = {
        "schemaVersion", "fragmentId", "producer", "shellFactIdentity", "operands",
        "memoryObjects", "sourceEffects", "approvedEffectRelations", "runtimeContracts",
        "ignoredState", "complete", "authorityIdentity",
    }
    if set(value) != fields:
        raise ValueError("L2 authority sidecar fields are incomplete or unknown")
    producer = value.get("producer")
    producer_fields = {"kind", "producerId", "producerVersion", "producerBinaryDigest"}
    if not isinstance(producer, Mapping) or set(producer) != producer_fields:
        raise ValueError("L2 authority producer fields are invalid")
    fragment_id = value.get("fragmentId")
    shell_identity = value.get("shellFactIdentity")
    authority_identity = value.get("authorityIdentity")
    complete = value.get("complete")
    if not all(isinstance(item, str) for item in (
            fragment_id, shell_identity, authority_identity, value.get("schemaVersion"))):
        raise ValueError("L2 authority identity fields are invalid")
    if not isinstance(complete, bool):
        raise ValueError("L2 authority completeness flag is invalid")
    if expected_fragment_id and fragment_id != expected_fragment_id:
        raise ValueError("L2 authority fragment identity mismatch")
    if expected_shell_fact_identity and shell_identity != expected_shell_fact_identity:
        raise ValueError("L2 authority shell fact identity mismatch")
    return L2AuthoritySidecar(
        fragment_id=fragment_id,
        producer=L2AuthorityProducer(
            str(producer["kind"]), str(producer["producerId"]),
            str(producer["producerVersion"]), str(producer["producerBinaryDigest"]),
        ),
        shell_fact_identity=shell_identity,
        operands=_objects(value.get("operands"), "operands"),
        memory_objects=_objects(value.get("memoryObjects"), "memoryObjects"),
        source_effects=_objects(value.get("sourceEffects"), "sourceEffects"),
        approved_effect_relations=_objects(
            value.get("approvedEffectRelations"), "approvedEffectRelations",
        ),
        runtime_contracts=_objects(value.get("runtimeContracts"), "runtimeContracts"),
        ignored_state=_objects(value.get("ignoredState"), "ignoredState"),
        complete=complete, authority_identity=authority_identity,
        schema_version=str(value["schemaVersion"]),
    )


def load_l2_authority_sidecar(
    path: str | Path, *, expected_fragment_id: str = "",
    expected_shell_fact_identity: str = "",
) -> L2AuthoritySidecar:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("L2 authority sidecar root must be an object")
    return l2_authority_sidecar_from_dict(
        value, expected_fragment_id=expected_fragment_id,
        expected_shell_fact_identity=expected_shell_fact_identity,
    )


def authority_identity_set(identities: Sequence[str], *, role: str) -> str:
    """Bind a possibly multi-fragment candidate without losing member identity."""
    values = tuple(identities)
    if any(_SHA256.fullmatch(item) is None for item in values):
        return ""
    return _identity({"schemaVersion": "riscv2x86.l2-authority-binding-set.v1",
                      "role": role, "identities": list(values)})
