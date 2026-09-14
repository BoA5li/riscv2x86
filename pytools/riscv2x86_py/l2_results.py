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
    L2ClaimScope, L2Dimension, L2DimensionStatus,
    parse_l2_dimension, parse_l2_dimensions,
)


L2_DIMENSION_RESULT_SCHEMA = "riscv2x86.l2-dimension-result.v1"
L2_FRAGMENT_RESULT_SCHEMA = "riscv2x86.l2-fragment-result.v1"
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

    def __post_init__(self) -> None:
        if tuple(sorted(set(self.reason_codes))) != self.reason_codes:
            raise ValueError("L2 dimension reason codes must be unique and sorted")
        if not all(isinstance(item, str) and item for item in self.reason_codes):
            raise ValueError("L2 dimension reason codes are invalid")
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
        }

    @classmethod
    def create(
        cls, *, dimension: L2Dimension, status: L2DimensionStatus,
        claim_scope: L2ClaimScope = L2ClaimScope.NONE,
        authority_identity: str = "", source_observation_identity: str = "",
        target_observation_identity: str = "", effect_relation_identity: str = "",
        execution_identity: str = "", reason_codes: Sequence[str] = (),
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
        }
        evidence_identity = _identity(payload) if materialize_evidence else ""
        return cls(
            dimension, status, claim_scope, evidence_identity, authority_identity,
            source_observation_identity, target_observation_identity,
            effect_relation_identity, execution_identity, reasons,
        )

    def to_dict(self) -> dict[str, object]:
        value = self._evidence_payload()
        value["evidenceIdentity"] = self.evidence_identity
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2DimensionResult":
        expected = {
            "schemaVersion", "dimension", "status", "claimScope",
            "evidenceIdentity", "authorityIdentity", "sourceObservationIdentity",
            "targetObservationIdentity", "effectRelationIdentity",
            "executionIdentity", "reasonCodes",
        }
        if set(value) != expected or value.get("schemaVersion") != L2_DIMENSION_RESULT_SCHEMA:
            raise ValueError("L2 dimension result schema or fields are invalid")
        reasons = value.get("reasonCodes")
        if (not isinstance(reasons, list)
                or not all(isinstance(item, str) and item for item in reasons)):
            raise ValueError("L2 dimension result reason codes must be an array")
        string_fields = (
            "evidenceIdentity", "authorityIdentity", "sourceObservationIdentity",
            "targetObservationIdentity", "effectRelationIdentity", "executionIdentity",
        )
        if any(not isinstance(value.get(name), str) for name in string_fields):
            raise ValueError("L2 dimension result identity fields are invalid")
        return cls(
            parse_l2_dimension(value.get("dimension")),
            L2DimensionStatus(str(value.get("status"))),
            L2ClaimScope(str(value.get("claimScope"))),
            str(value["evidenceIdentity"]), str(value["authorityIdentity"]),
            str(value["sourceObservationIdentity"]),
            str(value["targetObservationIdentity"]),
            str(value["effectRelationIdentity"]), str(value["executionIdentity"]),
            tuple(reasons),
        )


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
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2FragmentResult":
        expected = {
            "schemaVersion", "fragmentId", "requirementIdentity",
            "requiredDimensions", "dimensionResults", "status", "claimScope",
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
        return cls(
            str(value.get("fragmentId") or ""),
            str(value.get("requirementIdentity") or ""),
            parse_l2_dimensions(required),
            tuple(sorted(results, key=lambda item: item.dimension.value)),
            L2DimensionStatus(str(value.get("status"))),
            L2ClaimScope(str(value.get("claimScope"))),
        )


def validate_l2_fragment_result(value: Mapping[str, object]) -> None:
    L2FragmentResult.from_dict(value)
