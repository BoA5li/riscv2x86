"""Strict Phase L2-C4 approved effect-relation authority.

This module parses proof-produced relations.  It contains no route, mnemonic,
helper-name, or runtime-text inference.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping


EFFECT_RELATION_SCHEMA = "riscv2x86.effect-relation.v2"
EFFECT_RELATION_KINDS = {"exact", "strengthened", "runtime_mediated"}
OBSERVABLE_REQUIREMENTS = {
    "kind", "subject", "value", "memory_coordinates", "memory_order",
    "branch_outcome", "target", "trap_detail", "external_detail",
    "csr_value", "privilege_state", "compiler_ordering", "hardware_ordering",
}
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_identity(value: object) -> str:
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


def _text(value: Mapping[str, object], name: str, *, empty: bool = False) -> str:
    item = value.get(name)
    if not isinstance(item, str) or (not empty and not item):
        raise ValueError("effect relation " + name + " is invalid")
    return item


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an array of non-empty strings")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ValueError(label + " must be unique and sorted")
    return result


@dataclass(frozen=True)
class EffectOrderingRequirement:
    before: str
    after: str

    def __post_init__(self) -> None:
        if not self.before or not self.after or self.before == self.after:
            raise ValueError("effect ordering requirement is invalid")

    def to_dict(self) -> dict[str, str]:
        return {"before": self.before, "after": self.after}


@dataclass(frozen=True)
class ApprovedEffectRelation:
    relation_id: str
    source_effect_id: str
    target_effect_ids: tuple[str, ...]
    relation_kind: str
    observable_requirements: tuple[str, ...]
    ordering_requirements: tuple[EffectOrderingRequirement, ...]
    runtime_contract_id: str
    complete: bool
    approval_identity: str = ""
    schema_version: str = EFFECT_RELATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != EFFECT_RELATION_SCHEMA:
            raise ValueError("effect relation schema is unsupported")
        if not self.relation_id or not self.source_effect_id or not self.target_effect_ids:
            raise ValueError("effect relation identity/effects are incomplete")
        if self.relation_kind not in EFFECT_RELATION_KINDS:
            raise ValueError("effect relation kind is unsupported")
        if self.target_effect_ids != tuple(sorted(set(self.target_effect_ids))):
            raise ValueError("target effect IDs must be unique and sorted")
        if (not self.observable_requirements
                or not set(self.observable_requirements).issubset(OBSERVABLE_REQUIREMENTS)):
            raise ValueError("effect observable requirements are incomplete or unsupported")
        order = tuple((item.before, item.after) for item in self.ordering_requirements)
        if order != tuple(sorted(set(order))):
            raise ValueError("effect ordering requirements must be unique and sorted")
        if self.relation_kind == "exact" and len(self.target_effect_ids) != 1:
            raise ValueError("exact relation requires one target effect")
        if self.relation_kind != "runtime_mediated" and self.runtime_contract_id:
            raise ValueError("non-runtime relation cannot name a runtime contract")
        expected = canonical_identity(self._payload(False))
        if self.approval_identity and self.approval_identity != expected:
            raise ValueError("effect relation approval identity does not match content")
        object.__setattr__(self, "approval_identity", expected)

    @property
    def authority_complete(self) -> bool:
        return self.complete and (
            self.relation_kind != "runtime_mediated" or bool(self.runtime_contract_id)
        )

    def _payload(self, include_identity: bool) -> dict[str, object]:
        value: dict[str, object] = {
            "schemaVersion": self.schema_version, "relationId": self.relation_id,
            "sourceEffectId": self.source_effect_id,
            "targetEffectIds": list(self.target_effect_ids),
            "relationKind": self.relation_kind,
            "observableRequirements": list(self.observable_requirements),
            "orderingRequirements": [item.to_dict() for item in self.ordering_requirements],
            "runtimeContractId": self.runtime_contract_id, "complete": self.complete,
        }
        if include_identity:
            value["approvalIdentity"] = self.approval_identity
        return value

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


def approved_effect_relation_from_dict(value: Mapping[str, object]) -> ApprovedEffectRelation:
    fields = {
        "schemaVersion", "relationId", "sourceEffectId", "targetEffectIds",
        "relationKind", "observableRequirements", "orderingRequirements",
        "runtimeContractId", "complete", "approvalIdentity",
    }
    if set(value) != fields:
        raise ValueError("effect relation fields are incomplete or unknown")
    ordering = value.get("orderingRequirements")
    if not isinstance(ordering, list):
        raise ValueError("effect ordering requirements must be an array")
    parsed_ordering = []
    for item in ordering:
        if not isinstance(item, Mapping) or set(item) != {"before", "after"}:
            raise ValueError("effect ordering requirement fields are invalid")
        parsed_ordering.append(EffectOrderingRequirement(
            _text(item, "before"), _text(item, "after"),
        ))
    complete = value.get("complete")
    if not isinstance(complete, bool):
        raise ValueError("effect relation complete must be boolean")
    approval_identity = value.get("approvalIdentity")
    if not isinstance(approval_identity, str) or _SHA256.fullmatch(approval_identity) is None:
        raise ValueError("effect relation approval identity is invalid")
    return ApprovedEffectRelation(
        _text(value, "relationId"), _text(value, "sourceEffectId"),
        _strings(value.get("targetEffectIds"), "target effect IDs"),
        _text(value, "relationKind"),
        _strings(value.get("observableRequirements"), "observable requirements"),
        tuple(parsed_ordering), _text(value, "runtimeContractId", empty=True),
        complete, approval_identity, _text(value, "schemaVersion"),
    )
