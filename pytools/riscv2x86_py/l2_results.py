"""Typed, content-addressed L2 dimension and fragment results.

This module is the sole authority for closing a fragment's required L2
dimensions.  Callers may retain additional diagnostic dimensions, but they
cannot use them to replace or enlarge the requirement being proved.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .l2_dimensions import (
    L2ClaimConclusion, L2ClaimScope, L2Dimension, L2DimensionStatus,
    l2_claim_conclusion,
    parse_l2_dimension, parse_l2_dimensions,
)


L2_DIMENSION_RESULT_SCHEMA = "riscv2x86.l2-dimension-result.v2"
L2_FRAGMENT_RESULT_SCHEMA = "riscv2x86.l2-fragment-result.v2"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _identity(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _valid_identity(value: str) -> bool:
    return _SHA256.fullmatch(value) is not None


@dataclass(frozen=True)
class L2DimensionResult:
    dimension: L2Dimension
    status: L2DimensionStatus
    claim_scope: L2ClaimScope
    evidence_identity: str
    authority_identity: str
    source_observation_identity: str
    target_observation_identity: str
    effect_relation_identity: str
    execution_identity: str
    reason_codes: tuple[str, ...]
    relation_kind: str = ""
    verified_properties: tuple[str, ...] = ()
    not_claimed_properties: tuple[str, ...] = ()

    @property
    def conclusion(self) -> L2ClaimConclusion:
        return l2_claim_conclusion(self.status, self.claim_scope)

    def __post_init__(self) -> None:
        if tuple(sorted(set(self.reason_codes))) != self.reason_codes:
            raise ValueError("L2 dimension reason codes must be unique and sorted")
        if not all(isinstance(item, str) and item for item in self.reason_codes):
            raise ValueError("L2 dimension reason codes are invalid")
        for values in (self.verified_properties, self.not_claimed_properties):
            if values != tuple(sorted(set(values))) or not all(
                    isinstance(item, str) and item for item in values):
                raise ValueError("L2 claim properties must be unique and sorted")
        if self.relation_kind not in {"", "exact", "strengthened", "runtime_mediated", "diagnostic"}:
            raise ValueError("L2 relation kind is unsupported")
        identities = (
            self.authority_identity, self.source_observation_identity,
            self.target_observation_identity, self.effect_relation_identity,
            self.execution_identity,
        )
        if any(value and not _valid_identity(value) for value in identities):
            raise ValueError("L2 dimension dependency identity is invalid")
        if self.status is L2DimensionStatus.VERIFIED:
            if self.claim_scope is L2ClaimScope.NONE:
                raise ValueError("verified L2 dimension has no claim scope")
            if not all(_valid_identity(value) for value in identities):
                raise ValueError("verified L2 dimension identity chain is incomplete")
            if self.reason_codes:
                raise ValueError("verified L2 dimension carries failure reasons")
            if not self.evidence_identity:
                raise ValueError("verified L2 dimension has no evidence identity")
            if self.claim_scope is L2ClaimScope.APPROVED_FUNCTIONAL_RELATION and (
                    self.relation_kind != "runtime_mediated" or
                    not self.verified_properties or not self.not_claimed_properties):
                raise ValueError("functional L2 claim boundary is incomplete")
            if self.claim_scope is L2ClaimScope.DIAGNOSTIC_ONLY and self.relation_kind != "diagnostic":
                raise ValueError("diagnostic L2 claim relation is invalid")
        elif self.claim_scope is not L2ClaimScope.NONE:
            raise ValueError("unverified L2 dimension must not carry a claim scope")
        if self.evidence_identity:
            if not _valid_identity(self.evidence_identity):
                raise ValueError("L2 dimension evidence identity is invalid")
            if self.evidence_identity != _identity(self._evidence_payload()):
                raise ValueError("L2 dimension evidence identity does not match content")

    def _evidence_payload(self) -> dict[str, object]:
        return {
            "schemaVersion": L2_DIMENSION_RESULT_SCHEMA,
            "dimension": self.dimension.value,
            "status": self.status.value,
            "claimScope": self.claim_scope.value,
            "authorityIdentity": self.authority_identity,
            "sourceObservationIdentity": self.source_observation_identity,
            "targetObservationIdentity": self.target_observation_identity,
            "effectRelationIdentity": self.effect_relation_identity,
            "executionIdentity": self.execution_identity,
            "reasonCodes": list(self.reason_codes),
            "relationKind": self.relation_kind,
            "verifiedProperties": list(self.verified_properties),
            "notClaimedProperties": list(self.not_claimed_properties),
        }

    @classmethod
    def create(
        cls, *, dimension: L2Dimension, status: L2DimensionStatus,
        claim_scope: L2ClaimScope = L2ClaimScope.NONE,
        authority_identity: str = "", source_observation_identity: str = "",
        target_observation_identity: str = "", effect_relation_identity: str = "",
        execution_identity: str = "", reason_codes: Sequence[str] = (),
        relation_kind: str = "", verified_properties: Sequence[str] = (),
        not_claimed_properties: Sequence[str] = (),
        materialize_evidence: bool = True,
    ) -> "L2DimensionResult":
        reasons = tuple(sorted(set(reason_codes)))
        payload = {
            "schemaVersion": L2_DIMENSION_RESULT_SCHEMA,
            "dimension": dimension.value, "status": status.value,
            "claimScope": claim_scope.value,
            "authorityIdentity": authority_identity,
            "sourceObservationIdentity": source_observation_identity,
            "targetObservationIdentity": target_observation_identity,
            "effectRelationIdentity": effect_relation_identity,
            "executionIdentity": execution_identity,
            "reasonCodes": list(reasons),
            "relationKind": relation_kind,
            "verifiedProperties": sorted(set(verified_properties)),
            "notClaimedProperties": sorted(set(not_claimed_properties)),
        }
        evidence_identity = _identity(payload) if materialize_evidence else ""
        return cls(
            dimension, status, claim_scope, evidence_identity, authority_identity,
            source_observation_identity, target_observation_identity,
            effect_relation_identity, execution_identity, reasons, relation_kind,
            tuple(sorted(set(verified_properties))),
            tuple(sorted(set(not_claimed_properties))),
        )

    def to_dict(self) -> dict[str, object]:
        value = self._evidence_payload()
        value["evidenceIdentity"] = self.evidence_identity
        value["conclusion"] = self.conclusion.value
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2DimensionResult":
        expected = {
            "schemaVersion", "dimension", "status", "claimScope",
            "evidenceIdentity", "authorityIdentity", "sourceObservationIdentity",
            "targetObservationIdentity", "effectRelationIdentity",
            "executionIdentity", "reasonCodes", "conclusion",
            "relationKind", "verifiedProperties", "notClaimedProperties",
        }
        if set(value) != expected or value.get("schemaVersion") != L2_DIMENSION_RESULT_SCHEMA:
            raise ValueError("L2 dimension result schema or fields are invalid")
        reasons = value.get("reasonCodes")
        if (not isinstance(reasons, list)
                or not all(isinstance(item, str) and item for item in reasons)):
            raise ValueError("L2 dimension result reason codes must be an array")
        verified_properties = value.get("verifiedProperties")
        not_claimed_properties = value.get("notClaimedProperties")
        if (not isinstance(verified_properties, list) or
                not isinstance(not_claimed_properties, list)):
            raise ValueError("L2 dimension claim properties must be arrays")
        string_fields = (
            "evidenceIdentity", "authorityIdentity", "sourceObservationIdentity",
            "targetObservationIdentity", "effectRelationIdentity", "executionIdentity",
        )
        if any(not isinstance(value.get(name), str) for name in string_fields):
            raise ValueError("L2 dimension result identity fields are invalid")
        result = cls(
            parse_l2_dimension(value.get("dimension")),
            L2DimensionStatus(str(value.get("status"))),
            L2ClaimScope(str(value.get("claimScope"))),
            str(value["evidenceIdentity"]), str(value["authorityIdentity"]),
            str(value["sourceObservationIdentity"]),
            str(value["targetObservationIdentity"]),
            str(value["effectRelationIdentity"]), str(value["executionIdentity"]),
            tuple(reasons),
            str(value.get("relationKind")), tuple(verified_properties),
            tuple(not_claimed_properties),
        )
        if value.get("conclusion") != result.conclusion.value:
            raise ValueError("L2 dimension conclusion does not match status and scope")
        return result


def _closed_status(
    required: tuple[L2Dimension, ...], by_dimension: Mapping[L2Dimension, L2DimensionResult],
) -> L2DimensionStatus:
    if any(dimension not in by_dimension for dimension in required):
        return L2DimensionStatus.INCONCLUSIVE
    statuses = tuple(by_dimension[dimension].status for dimension in required)
    if L2DimensionStatus.FAILED in statuses:
        return L2DimensionStatus.FAILED
    if L2DimensionStatus.INCONCLUSIVE in statuses:
        return L2DimensionStatus.INCONCLUSIVE
    if L2DimensionStatus.NOT_RUN in statuses:
        return L2DimensionStatus.NOT_RUN
    if L2DimensionStatus.NOT_APPLICABLE in statuses:
        return L2DimensionStatus.INCONCLUSIVE
    if statuses and all(status is L2DimensionStatus.VERIFIED for status in statuses):
        return L2DimensionStatus.VERIFIED
    return L2DimensionStatus.INCONCLUSIVE


def _closed_scope(
    status: L2DimensionStatus, required: tuple[L2Dimension, ...],
    by_dimension: Mapping[L2Dimension, L2DimensionResult],
) -> L2ClaimScope:
    if status is not L2DimensionStatus.VERIFIED:
        return L2ClaimScope.NONE
    scopes = {by_dimension[dimension].claim_scope for dimension in required}
    if scopes == {L2ClaimScope.ARCHITECTURAL}:
        return L2ClaimScope.ARCHITECTURAL
    if L2ClaimScope.NONE in scopes:
        return L2ClaimScope.NONE
    if L2ClaimScope.DIAGNOSTIC_ONLY in scopes:
        return L2ClaimScope.DIAGNOSTIC_ONLY
    return L2ClaimScope.APPROVED_FUNCTIONAL_RELATION


@dataclass(frozen=True)
class L2FragmentResult:
    fragment_id: str
    requirement_identity: str
    required_dimensions: tuple[L2Dimension, ...]
    dimension_results: tuple[L2DimensionResult, ...]
    status: L2DimensionStatus
    claim_scope: L2ClaimScope

    @property
    def conclusion(self) -> L2ClaimConclusion:
        return l2_claim_conclusion(self.status, self.claim_scope)

    @property
    def architectural_verified(self) -> bool:
        return self.conclusion is L2ClaimConclusion.ARCHITECTURAL_VERIFIED

    def __post_init__(self) -> None:
        if not self.fragment_id or not _valid_identity(self.requirement_identity):
            raise ValueError("L2 fragment result identities are invalid")
        parse_l2_dimensions([item.value for item in self.required_dimensions])
        dimensions = tuple(item.dimension for item in self.dimension_results)
        parse_l2_dimensions([item.value for item in dimensions])
        by_dimension = {item.dimension: item for item in self.dimension_results}
        expected_status = _closed_status(self.required_dimensions, by_dimension)
        expected_scope = _closed_scope(
            expected_status, self.required_dimensions, by_dimension,
        )
        if self.status is not expected_status or self.claim_scope is not expected_scope:
            raise ValueError("L2 fragment result does not satisfy the closed-dimension gate")

    @classmethod
    def close(
        cls, *, fragment_id: str, requirement_identity: str,
        required_dimensions: Sequence[L2Dimension],
        dimension_results: Sequence[L2DimensionResult],
    ) -> "L2FragmentResult":
        required = tuple(required_dimensions)
        results = tuple(sorted(dimension_results, key=lambda item: item.dimension.value))
        by_dimension = {item.dimension: item for item in results}
        status = _closed_status(required, by_dimension)
        return cls(
            fragment_id, requirement_identity, required, results, status,
            _closed_scope(status, required, by_dimension),
        )

    @property
    def evidence_identity(self) -> str:
        return _identity(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": L2_FRAGMENT_RESULT_SCHEMA,
            "fragmentId": self.fragment_id,
            "requirementIdentity": self.requirement_identity,
            "requiredDimensions": [item.value for item in self.required_dimensions],
            "dimensionResults": {
                item.dimension.value: item.to_dict() for item in self.dimension_results
            },
            "status": self.status.value,
            "claimScope": self.claim_scope.value,
            "conclusion": self.conclusion.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2FragmentResult":
        expected = {
            "schemaVersion", "fragmentId", "requirementIdentity",
            "requiredDimensions", "dimensionResults", "status", "claimScope",
            "conclusion",
        }
        if set(value) != expected or value.get("schemaVersion") != L2_FRAGMENT_RESULT_SCHEMA:
            raise ValueError("L2 fragment result schema or fields are invalid")
        required, raw_results = value.get("requiredDimensions"), value.get("dimensionResults")
        if not isinstance(required, list) or not isinstance(raw_results, Mapping):
            raise ValueError("L2 fragment result dimensions are invalid")
        results = []
        for name, raw in raw_results.items():
            if not isinstance(name, str) or not isinstance(raw, Mapping):
                raise ValueError("L2 fragment dimension result is malformed")
            result = L2DimensionResult.from_dict(raw)
            if result.dimension.value != name:
                raise ValueError("L2 fragment result dimension key does not match content")
            results.append(result)
        result = cls(
            str(value.get("fragmentId") or ""),
            str(value.get("requirementIdentity") or ""),
            parse_l2_dimensions(required),
            tuple(sorted(results, key=lambda item: item.dimension.value)),
            L2DimensionStatus(str(value.get("status"))),
            L2ClaimScope(str(value.get("claimScope"))),
        )
        if value.get("conclusion") != result.conclusion.value:
            raise ValueError("L2 fragment conclusion does not match status and scope")
        return result


def validate_l2_fragment_result(value: Mapping[str, object]) -> None:
    L2FragmentResult.from_dict(value)
