"""Closed, content-addressed L2 evidence for multi-fragment programs."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .l2_dimensions import L2ClaimScope, L2DimensionStatus
from .l2_results import L2FragmentResult


PROGRAM_EXECUTION_EVIDENCE_SCHEMA = "riscv2x86.l2-program-execution-evidence.v1"
PROGRAM_L2_GROUP_RESULT_SCHEMA = "riscv2x86.l2-program-group-result.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_identity(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def sample_set_identity(source_identity: str, target_identity: str) -> str:
    """Bind the paired source/target observations used for one sample set."""
    return canonical_identity({
        "schemaVersion": "riscv2x86.l2-sample-set.v1",
        "sourceObservationIdentity": source_identity,
        "targetObservationIdentity": target_identity,
    })


@dataclass(frozen=True)
class ProgramExecutionEvidence:
    execution_identity: str
    program_id: str
    source_observation_identity: str
    target_observation_identity: str
    sample_set_identity: str
    member_fragment_ids: tuple[str, ...]
    schema_version: str = PROGRAM_EXECUTION_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != PROGRAM_EXECUTION_EVIDENCE_SCHEMA or not self.program_id:
            raise ValueError("L2 program execution evidence schema/program is invalid")
        identities = (
            self.execution_identity, self.source_observation_identity,
            self.target_observation_identity, self.sample_set_identity,
        )
        if any(_SHA256.fullmatch(item) is None for item in identities):
            raise ValueError("L2 program execution evidence identity is invalid")
        if (not self.member_fragment_ids
                or self.member_fragment_ids != tuple(sorted(set(self.member_fragment_ids)))
                or not all(self.member_fragment_ids)):
            raise ValueError("L2 program execution member fragments are not canonical")
        expected_sample = sample_set_identity(
            self.source_observation_identity, self.target_observation_identity,
        )
        if self.sample_set_identity != expected_sample:
            raise ValueError("L2 program execution sample-set identity does not match observations")

    @property
    def deduplication_key(self) -> tuple[str, str, str]:
        return self.program_id, self.execution_identity, self.sample_set_identity

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "executionIdentity": self.execution_identity,
            "programId": self.program_id,
            "sourceObservationIdentity": self.source_observation_identity,
            "targetObservationIdentity": self.target_observation_identity,
            "sampleSetIdentity": self.sample_set_identity,
            "memberFragmentIds": list(self.member_fragment_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProgramExecutionEvidence":
        fields = {
            "schemaVersion", "executionIdentity", "programId",
            "sourceObservationIdentity", "targetObservationIdentity",
            "sampleSetIdentity", "memberFragmentIds",
        }
        if set(value) != fields:
            raise ValueError("L2 program execution evidence fields are incomplete or unknown")
        members = value.get("memberFragmentIds")
        if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
            raise ValueError("L2 program execution member fragments must be an array")
        strings = {name: value.get(name) for name in fields - {"memberFragmentIds"}}
        if not all(isinstance(item, str) for item in strings.values()):
            raise ValueError("L2 program execution evidence strings are invalid")
        return cls(
            str(value["executionIdentity"]), str(value["programId"]),
            str(value["sourceObservationIdentity"]),
            str(value["targetObservationIdentity"]), str(value["sampleSetIdentity"]),
            tuple(members), str(value["schemaVersion"]),
        )


def deduplicate_program_executions(
    values: Sequence[ProgramExecutionEvidence],
) -> tuple[ProgramExecutionEvidence, ...]:
    """Deduplicate only identical program/execution/sample tuples, fail on conflict."""
    unique: dict[tuple[str, str, str], ProgramExecutionEvidence] = {}
    for value in values:
        previous = unique.get(value.deduplication_key)
        if previous is not None and previous != value:
            raise ValueError("conflicting L2 program execution evidence has the same sample key")
        unique[value.deduplication_key] = value
    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True)
class ProgramL2MemberResult:
    fragment_id: str
    required: bool
    fragment_result: L2FragmentResult | None
    uncovered_observable_effects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.fragment_id:
            raise ValueError("L2 program member fragment is missing")
        if self.fragment_result is not None and self.fragment_result.fragment_id != self.fragment_id:
            raise ValueError("L2 program member fragment result belongs to another fragment")
        if (self.uncovered_observable_effects
                != tuple(sorted(set(self.uncovered_observable_effects)))
                or not all(self.uncovered_observable_effects)):
            raise ValueError("uncovered observable effects are not canonical")

    @property
    def status(self) -> L2DimensionStatus:
        if self.fragment_result is None:
            return L2DimensionStatus.INCONCLUSIVE if self.required else L2DimensionStatus.NOT_APPLICABLE
        if self.required and self.uncovered_observable_effects:
            return L2DimensionStatus.FAILED
        return self.fragment_result.status

    def to_dict(self) -> dict[str, object]:
        return {
            "fragmentId": self.fragment_id, "required": self.required,
            "status": self.status.value,
            "fragmentResult": (
                None if self.fragment_result is None else self.fragment_result.to_dict()
            ),
            "uncoveredObservableEffects": list(self.uncovered_observable_effects),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProgramL2MemberResult":
        fields = {"fragmentId", "required", "status", "fragmentResult",
                  "uncoveredObservableEffects"}
        if set(value) != fields or not isinstance(value.get("fragmentId"), str):
            raise ValueError("L2 program member result fields are invalid")
        if not isinstance(value.get("required"), bool):
            raise ValueError("L2 program member required flag is invalid")
        raw_result, effects = value.get("fragmentResult"), value.get("uncoveredObservableEffects")
        if raw_result is not None and not isinstance(raw_result, Mapping):
            raise ValueError("L2 program member fragment result is invalid")
        if not isinstance(effects, list) or not all(isinstance(item, str) for item in effects):
            raise ValueError("L2 program member uncovered effects are invalid")
        result = cls(
            str(value["fragmentId"]), bool(value["required"]),
            None if raw_result is None else L2FragmentResult.from_dict(raw_result),
            tuple(effects),
        )
        if value.get("status") != result.status.value:
            raise ValueError("L2 program member status does not satisfy closure")
        return result


def _program_status(
    required: tuple[str, ...], members: tuple[ProgramL2MemberResult, ...],
    evidence: tuple[ProgramExecutionEvidence, ...], scope: L2ClaimScope,
) -> L2DimensionStatus:
    if not required:
        return L2DimensionStatus.NOT_APPLICABLE
    by_fragment = {item.fragment_id: item for item in members}
    statuses: list[L2DimensionStatus] = []
    for fragment_id in required:
        member = by_fragment.get(fragment_id)
        if member is None or not member.required or member.fragment_result is None:
            statuses.append(L2DimensionStatus.INCONCLUSIVE); continue
        result = member.fragment_result
        if member.uncovered_observable_effects:
            statuses.append(L2DimensionStatus.FAILED); continue
        if result.status is L2DimensionStatus.VERIFIED and result.claim_scope is not scope:
            statuses.append(L2DimensionStatus.INCONCLUSIVE); continue
        referenced = {
            item.execution_identity for item in result.dimension_results
            if item.dimension in result.required_dimensions
            and item.status is L2DimensionStatus.VERIFIED
        }
        available = {
            item.execution_identity for item in evidence
            if fragment_id in item.member_fragment_ids
        }
        if result.status is L2DimensionStatus.VERIFIED and (
                len(referenced) != 1 or not referenced.issubset(available)):
            statuses.append(L2DimensionStatus.INCONCLUSIVE)
        else:
            statuses.append(result.status)
    return (
        L2DimensionStatus.FAILED if L2DimensionStatus.FAILED in statuses else
        L2DimensionStatus.INCONCLUSIVE if L2DimensionStatus.INCONCLUSIVE in statuses else
        L2DimensionStatus.NOT_RUN if L2DimensionStatus.NOT_RUN in statuses else
        L2DimensionStatus.VERIFIED
        if all(item is L2DimensionStatus.VERIFIED for item in statuses)
        else L2DimensionStatus.INCONCLUSIVE
    )


@dataclass(frozen=True)
class ProgramL2GroupResult:
    program_id: str
    required_member_fragment_ids: tuple[str, ...]
    member_results: tuple[ProgramL2MemberResult, ...]
    execution_evidence: tuple[ProgramExecutionEvidence, ...]
    required_claim_scope: L2ClaimScope
    status: L2DimensionStatus

    def __post_init__(self) -> None:
        if not self.program_id or self.required_claim_scope is L2ClaimScope.NONE:
            raise ValueError("L2 program group identity/scope is invalid")
        if self.required_member_fragment_ids != tuple(sorted(set(
                self.required_member_fragment_ids))):
            raise ValueError("L2 program required members are not canonical")
        if self.member_results != tuple(sorted(
                self.member_results, key=lambda item: item.fragment_id)):
            raise ValueError("L2 program member results are not canonical")
        if len(self.member_results) != len({item.fragment_id for item in self.member_results}):
            raise ValueError("L2 program member result is duplicated")
        if self.execution_evidence != deduplicate_program_executions(self.execution_evidence):
            raise ValueError("L2 program execution evidence is not canonical")
        if self.status is not _program_status(
                self.required_member_fragment_ids, self.member_results,
                self.execution_evidence, self.required_claim_scope):
            raise ValueError("L2 program group status does not satisfy closure")

    @classmethod
    def close(
        cls, *, program_id: str, required_member_fragment_ids: Sequence[str],
        member_results: Sequence[ProgramL2MemberResult],
        execution_evidence: Sequence[ProgramExecutionEvidence],
        required_claim_scope: L2ClaimScope = L2ClaimScope.ARCHITECTURAL,
    ) -> "ProgramL2GroupResult":
        required = tuple(sorted(set(required_member_fragment_ids)))
        members = tuple(sorted(member_results, key=lambda item: item.fragment_id))
        if len(members) != len({item.fragment_id for item in members}):
            raise ValueError("L2 program member result is duplicated")
        evidence = deduplicate_program_executions(execution_evidence)
        status = _program_status(required, members, evidence, required_claim_scope)
        return cls(program_id, required, members, evidence, required_claim_scope, status)

    @property
    def execution_sample_count(self) -> int:
        return len(self.execution_evidence)

    def _payload(self) -> dict[str, object]:
        return {
            "schemaVersion": PROGRAM_L2_GROUP_RESULT_SCHEMA,
            "programId": self.program_id,
            "requiredMemberFragmentIds": list(self.required_member_fragment_ids),
            "requiredClaimScope": self.required_claim_scope.value,
            "status": self.status.value,
            "executionSampleCount": self.execution_sample_count,
            "programExecutionEvidence": [item.to_dict() for item in self.execution_evidence],
            "memberResults": [item.to_dict() for item in self.member_results],
        }

    @property
    def group_identity(self) -> str:
        return canonical_identity(self._payload())

    def to_dict(self) -> dict[str, object]:
        value = self._payload()
        value["groupIdentity"] = self.group_identity
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProgramL2GroupResult":
        fields = {
            "schemaVersion", "programId", "requiredMemberFragmentIds",
            "requiredClaimScope", "status", "executionSampleCount",
            "programExecutionEvidence", "memberResults", "groupIdentity",
        }
        if set(value) != fields or value.get("schemaVersion") != PROGRAM_L2_GROUP_RESULT_SCHEMA:
            raise ValueError("L2 program group result schema or fields are invalid")
        required, raw_evidence, raw_members = (
            value.get("requiredMemberFragmentIds"), value.get("programExecutionEvidence"),
            value.get("memberResults"),
        )
        if (not isinstance(required, list) or not all(isinstance(item, str) for item in required)
                or not isinstance(raw_evidence, list) or not isinstance(raw_members, list)):
            raise ValueError("L2 program group result collections are invalid")
        if not all(isinstance(item, Mapping) for item in (*raw_evidence, *raw_members)):
            raise ValueError("L2 program group result entry is invalid")
        result = cls.close(
            program_id=str(value.get("programId", "")),
            required_member_fragment_ids=required,
            member_results=tuple(ProgramL2MemberResult.from_dict(item) for item in raw_members),
            execution_evidence=tuple(ProgramExecutionEvidence.from_dict(item)
                                     for item in raw_evidence),
            required_claim_scope=L2ClaimScope(str(value.get("requiredClaimScope"))),
        )
        if (value.get("status") != result.status.value
                or value.get("executionSampleCount") != result.execution_sample_count
                or value.get("groupIdentity") != result.group_identity):
            raise ValueError("L2 program group result does not satisfy closed evidence")
        return result
