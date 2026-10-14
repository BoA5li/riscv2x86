"""Common fail-closed binding from an approved translation to L2 evidence."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .l2_dimensions import L2Dimension


L2_EXECUTION_PLAN_SCHEMA = "riscv2x86.l2-execution-plan.v1"
L2_PROVIDER_EVIDENCE_SCHEMA = "riscv2x86.l2-provider-evidence.v4"
L2_DIMENSION_EVIDENCE_SCHEMA = "riscv2x86.l2-dimension-evidence.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class L2ProviderExecutionDisposition(Enum):
    """How far a provider progressed before producing its result."""

    PRECONDITION_REJECTED = "precondition_rejected"
    NOT_EXECUTED = "not_executed"
    EXECUTED_INCONCLUSIVE = "executed_inconclusive"
    EXECUTED_FAILED = "executed_failed"
    EXECUTED_VERIFIED = "executed_verified"


class L2EvidenceProductionDisposition(Enum):
    """How much typed evidence exists independently of the execution verdict."""

    NOT_PRODUCED = "not_produced"
    PARTIAL = "partial"
    COMPLETE = "complete"


@dataclass(frozen=True)
class L2DimensionEvidence:
    """Provider observation material owned by exactly one L2 dimension."""

    source_evidence_identity: str
    target_evidence_identity: str
    observed_properties: tuple[str, ...]

    def __post_init__(self) -> None:
        if (_SHA.fullmatch(self.source_evidence_identity) is None
                or _SHA.fullmatch(self.target_evidence_identity) is None):
            raise ValueError("L2 dimension observation evidence is incomplete")
        if (not self.observed_properties
                or any(not item for item in self.observed_properties)
                or len(set(self.observed_properties)) != len(self.observed_properties)):
            raise ValueError("L2 dimension observed properties are incomplete")

    def bind(
        self, *, dimension: str, fragment_id: str, authority_identity: str,
        effect_relation_identity: str, execution_identity: str,
    ) -> dict[str, object]:
        result = {
            "schemaVersion": L2_DIMENSION_EVIDENCE_SCHEMA,
            "dimension": dimension,
            "authorityIdentity": authority_identity,
            "effectRelationIdentity": effect_relation_identity,
            "executionIdentity": execution_identity,
            "sourceEvidenceIdentity": self.source_evidence_identity,
            "targetEvidenceIdentity": self.target_evidence_identity,
            "observedProperties": list(self.observed_properties),
        }
        for side in ("source", "target"):
            evidence = str(result[side + "EvidenceIdentity"])
            result[side + "ObservationIdentity"] = identity({
                "schemaVersion": "riscv2x86.l2-dimension-observation.v1",
                "executionIdentity": execution_identity,
                "fragmentId": fragment_id, "dimension": dimension,
                "side": side, "evidenceIdentity": evidence,
                "authorityIdentity": authority_identity,
                "effectRelationIdentity": effect_relation_identity,
                "observedProperties": list(self.observed_properties),
            })
        return result


_TOTAL_EVIDENCE_DISPOSITIONS = {
    L2ProviderExecutionDisposition.EXECUTED_FAILED,
    L2ProviderExecutionDisposition.EXECUTED_VERIFIED,
}


def identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _binding_identity(kind: str, value: object) -> str:
    return identity({"schemaVersion": "riscv2x86.l2-declared-binding.v1",
                     "kind": kind, "value": value})


def provider_precondition_detail(
    reason_code: str, **extra: object,
) -> dict[str, object]:
    """Create the canonical detail for a provider rejected before execution."""
    if not reason_code:
        raise ValueError("provider precondition reason code is empty")
    return {
        "executionDisposition":
            L2ProviderExecutionDisposition.PRECONDITION_REJECTED.value,
        "evidenceProductionDisposition":
            L2EvidenceProductionDisposition.NOT_PRODUCED.value,
        "reasonCode": reason_code,
        **extra,
    }


@dataclass(frozen=True)
class L2ExecutionPlan:
    fragment_id: str
    provider_id: str
    translation_approval_identity: str
    environment_authority_identity: str
    semantic_authority_identity: str
    effect_relation_identity: str
    runtime_adapter_identity: str
    harness_identity: str

    def __post_init__(self) -> None:
        if not self.fragment_id or not self.provider_id:
            raise ValueError("L2 execution plan has no fragment/provider binding")
        for value in (
            self.translation_approval_identity,
            self.environment_authority_identity,
            self.semantic_authority_identity,
            self.effect_relation_identity,
            self.runtime_adapter_identity,
            self.harness_identity,
        ):
            if _SHA.fullmatch(value) is None:
                raise ValueError("L2 execution plan authority chain is incomplete")

    @property
    def plan_identity(self) -> str:
        return identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        result = {
            "schemaVersion": L2_EXECUTION_PLAN_SCHEMA,
            "fragmentId": self.fragment_id,
            "providerId": self.provider_id,
            "translationApprovalIdentity": self.translation_approval_identity,
            "environmentAuthorityIdentity": self.environment_authority_identity,
            "semanticAuthorityIdentity": self.semantic_authority_identity,
            "effectRelationIdentity": self.effect_relation_identity,
            "runtimeAdapterIdentity": self.runtime_adapter_identity,
            "harnessIdentity": self.harness_identity,
        }
        if include_identity:
            result["executionPlanIdentity"] = self.plan_identity
        return result


def execution_plan_from_dict(value: Mapping[str, object]) -> L2ExecutionPlan:
    fields = {
        "schemaVersion", "fragmentId", "providerId",
        "translationApprovalIdentity", "environmentAuthorityIdentity",
        "semanticAuthorityIdentity", "effectRelationIdentity",
        "runtimeAdapterIdentity", "harnessIdentity", "executionPlanIdentity",
    }
    if set(value) != fields or value.get("schemaVersion") != L2_EXECUTION_PLAN_SCHEMA:
        raise ValueError("L2 execution plan schema or fields are invalid")
    plan = L2ExecutionPlan(
        str(value.get("fragmentId") or ""), str(value.get("providerId") or ""),
        str(value.get("translationApprovalIdentity") or ""),
        str(value.get("environmentAuthorityIdentity") or ""),
        str(value.get("semanticAuthorityIdentity") or ""),
        str(value.get("effectRelationIdentity") or ""),
        str(value.get("runtimeAdapterIdentity") or ""),
        str(value.get("harnessIdentity") or ""),
    )
    if value.get("executionPlanIdentity") != plan.plan_identity:
        raise ValueError("L2 execution plan identity does not match content")
    return plan


def execution_plan_for_provider(
    artifact: object, *, provider_id: str, harness_identity: str,
) -> L2ExecutionPlan:
    """Bind every execution input without treating a declared name as a hash."""
    proof = str(getattr(artifact, "proof_identity", ""))
    if _SHA.fullmatch(proof) is None:
        raise ValueError("translation approval identity is unavailable")
    authority = str(getattr(artifact, "l2_authority_identity", ""))
    relation = str(getattr(artifact, "effect_relation_set_identity", ""))
    if not bool(getattr(artifact, "l2_authority_complete", False)):
        raise ValueError("semantic authority is incomplete")
    return L2ExecutionPlan(
        fragment_id=str(getattr(artifact, "fragment_id", "")),
        provider_id=provider_id,
        translation_approval_identity=proof,
        environment_authority_identity=_binding_identity(
            "target-environment",
            {"targetRoute": str(getattr(artifact, "target_route", "")),
             "rendererSemanticContractId": str(getattr(
                 artifact, "renderer_semantic_contract_id", ""))}),
        semantic_authority_identity=authority,
        effect_relation_identity=relation,
        runtime_adapter_identity=_binding_identity(
            "runtime-adapter",
            {"contractId": str(getattr(artifact, "runtime_contract_id", "")),
             "contractVersion": str(getattr(
                 artifact, "runtime_contract_version", ""))}),
        harness_identity=harness_identity,
    )


def provider_evidence_fields(
    artifact: object, *, provider_id: str, harness_identity: str,
    execution_nonce: object,
    dimensions: Sequence[L2Dimension],
    dimension_evidence: Mapping[L2Dimension, L2DimensionEvidence],
    authorized_execution_identity: str = "",
    execution_disposition: L2ProviderExecutionDisposition =
        L2ProviderExecutionDisposition.EXECUTED_VERIFIED,
) -> dict[str, object]:
    if execution_disposition not in {
            L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE,
            *_TOTAL_EVIDENCE_DISPOSITIONS}:
        raise ValueError("provider evidence disposition did not execute")
    plan = execution_plan_for_provider(
        artifact, provider_id=provider_id, harness_identity=harness_identity)
    if authorized_execution_identity:
        if _SHA.fullmatch(authorized_execution_identity) is None:
            raise ValueError("authorized provider execution identity is invalid")
        execution_identity = authorized_execution_identity
    else:
        execution_identity = identity({
            "schemaVersion": "riscv2x86.l2-authorized-execution.v1",
            "executionPlanIdentity": plan.plan_identity,
            "executionNonce": execution_nonce,
        })
    if (not dimensions or any(not isinstance(item, L2Dimension) for item in dimensions)
            or len(set(dimensions)) != len(dimensions)):
        raise ValueError("provider evidence dimensions are incomplete")
    canonical_dimensions = tuple(sorted(set(dimensions), key=lambda item: item.value))
    if (not all(isinstance(item, L2Dimension) for item in dimension_evidence)
            or set(dimension_evidence) != set(canonical_dimensions)):
        raise ValueError("provider dimension evidence does not match declared dimensions")
    observations = {}
    for dimension in canonical_dimensions:
        raw_evidence = dimension_evidence.get(dimension)
        if not isinstance(raw_evidence, L2DimensionEvidence):
            raise ValueError("provider dimension evidence is not typed")
        observations[dimension.value] = raw_evidence.bind(
            dimension=dimension.value, fragment_id=plan.fragment_id,
            authority_identity=plan.semantic_authority_identity,
            effect_relation_identity=plan.effect_relation_identity,
            execution_identity=execution_identity,
        )
    return {
        "executionDisposition": execution_disposition.value,
        "evidenceProductionDisposition":
            L2EvidenceProductionDisposition.COMPLETE.value,
        "evidenceSchemaVersion": L2_PROVIDER_EVIDENCE_SCHEMA,
        "authorityIdentity": plan.semantic_authority_identity,
        "effectRelationIdentity": plan.effect_relation_identity,
        "executionPlanIdentity": plan.plan_identity,
        "executionPlan": plan.to_dict(),
        "environmentAuthorityIdentity": plan.environment_authority_identity,
        "runtimeAdapterIdentity": plan.runtime_adapter_identity,
        "harnessIdentity": plan.harness_identity,
        "dimensionObservations": observations,
        "executionIdentity": execution_identity,
    }


def validate_provider_dimension_contract(
    detail: Mapping[str, object], expected_dimensions: Sequence[str],
) -> tuple[str, ...]:
    """Validate the executed provider's declared/result dimension boundary.

    Provider applicability is resolved before execution.  An executed provider
    must therefore return exactly the dimensions bound to it: neither a missing
    observation nor an undeclared extra observation may be accepted later by a
    per-dimension closer.
    """
    expected = tuple(sorted(set(expected_dimensions)))
    observations = detail.get("dimensionObservations")
    if (not expected or not isinstance(observations, Mapping)
            or tuple(sorted(observations)) != expected):
        return ("l2.provider-evidence.dimension-contract-mismatch",)
    return ()


def provider_execution_disposition(
    detail: Mapping[str, object], status: str,
) -> tuple[L2ProviderExecutionDisposition, tuple[str, ...]]:
    """Parse the mandatory execution disposition without inferring execution."""
    raw = detail.get("executionDisposition")
    if isinstance(raw, str):
        try:
            disposition = L2ProviderExecutionDisposition(raw)
        except ValueError:
            return (L2ProviderExecutionDisposition.NOT_EXECUTED,
                    ("l2.provider-execution-disposition.unsupported",))
        allowed = {
            "verified": {L2ProviderExecutionDisposition.EXECUTED_VERIFIED},
            "failed": {L2ProviderExecutionDisposition.EXECUTED_FAILED},
            "inconclusive": {
                L2ProviderExecutionDisposition.PRECONDITION_REJECTED,
                L2ProviderExecutionDisposition.NOT_EXECUTED,
                L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE,
            },
        }.get(status, set())
        if disposition not in allowed:
            return disposition, ("l2.provider-execution-disposition.status-mismatch",)
        return disposition, ()
    return (L2ProviderExecutionDisposition.NOT_EXECUTED,
            ("l2.provider-execution-disposition.missing",))


def provider_evidence_production_disposition(
    detail: Mapping[str, object],
    execution_disposition: L2ProviderExecutionDisposition,
) -> tuple[L2EvidenceProductionDisposition, tuple[str, ...]]:
    """Parse evidence production without inferring it from execution status."""
    raw = detail.get("evidenceProductionDisposition")
    if not isinstance(raw, str):
        return (L2EvidenceProductionDisposition.NOT_PRODUCED,
                ("l2.provider-evidence-production-disposition.missing",))
    try:
        disposition = L2EvidenceProductionDisposition(raw)
    except ValueError:
        return (L2EvidenceProductionDisposition.NOT_PRODUCED,
                ("l2.provider-evidence-production-disposition.unsupported",))
    allowed = {
        L2ProviderExecutionDisposition.PRECONDITION_REJECTED: {
            L2EvidenceProductionDisposition.NOT_PRODUCED},
        L2ProviderExecutionDisposition.NOT_EXECUTED: {
            L2EvidenceProductionDisposition.NOT_PRODUCED},
        L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE: {
            L2EvidenceProductionDisposition.NOT_PRODUCED,
            L2EvidenceProductionDisposition.PARTIAL,
            L2EvidenceProductionDisposition.COMPLETE},
        L2ProviderExecutionDisposition.EXECUTED_FAILED: {
            L2EvidenceProductionDisposition.COMPLETE},
        L2ProviderExecutionDisposition.EXECUTED_VERIFIED: {
            L2EvidenceProductionDisposition.COMPLETE},
    }[execution_disposition]
    if disposition not in allowed:
        return disposition, (
            "l2.provider-evidence-production-disposition.status-mismatch",)
    return disposition, ()


def partial_provider_evidence(
    detail: Mapping[str, object], artifact: object, *, dimension: str,
    provider_id: str,
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Retain formed identities after an inconclusive executed comparison."""
    names = (
        "authorityIdentity", "effectRelationIdentity", "executionPlanIdentity",
        "environmentAuthorityIdentity", "runtimeAdapterIdentity", "harnessIdentity",
        "executionIdentity",
    )
    values = {name: str(detail.get(name)) for name in names
              if isinstance(detail.get(name), str)
              and _SHA.fullmatch(str(detail.get(name)))}
    reasons: set[str] = set()
    if detail.get("evidenceSchemaVersion") != L2_PROVIDER_EVIDENCE_SCHEMA:
        reasons.add("l2.provider-evidence.schema-missing-or-unsupported")
    observations = detail.get("dimensionObservations")
    selected = observations.get(dimension) if isinstance(observations, Mapping) else None
    _validate_dimension_observation(selected, values, dimension, str(
        getattr(artifact, "fragment_id", "")), reasons)
    authority = values.get("authorityIdentity")
    if authority and authority != str(getattr(artifact, "l2_authority_identity", "")):
        reasons.add("l2.provider-evidence.authority-mismatch")
    relation = values.get("effectRelationIdentity")
    if relation and relation != str(getattr(artifact, "effect_relation_set_identity", "")):
        reasons.add("l2.provider-evidence.effect-relation-mismatch")
    if not _execution_plan_is_valid(detail, artifact, provider_id, values):
        reasons.add("l2.provider-evidence.execution-plan-invalid")
    return values, tuple(sorted(reasons))


def validated_provider_evidence(
    detail: Mapping[str, object], artifact: object, *, dimension: str,
    provider_id: str,
) -> tuple[dict[str, str] | None, tuple[str, ...]]:
    """Validate the total evidence chain; never synthesize a missing link."""
    names = (
        "authorityIdentity", "effectRelationIdentity", "executionPlanIdentity",
        "environmentAuthorityIdentity", "runtimeAdapterIdentity", "harnessIdentity",
        "executionIdentity",
    )
    reasons: set[str] = set()
    if detail.get("evidenceSchemaVersion") != L2_PROVIDER_EVIDENCE_SCHEMA:
        reasons.add("l2.provider-evidence.schema-missing-or-unsupported")
    values = {name: detail.get(name) if isinstance(detail.get(name), str) else ""
              for name in names}
    for name, value in values.items():
        if _SHA.fullmatch(value) is None:
            reasons.add("l2.provider-evidence.identity-missing:" + name)
    if values["authorityIdentity"] != str(getattr(artifact, "l2_authority_identity", "")):
        reasons.add("l2.provider-evidence.authority-mismatch")
    if values["effectRelationIdentity"] != str(
            getattr(artifact, "effect_relation_set_identity", "")):
        reasons.add("l2.provider-evidence.effect-relation-mismatch")
    if not _execution_plan_is_valid(detail, artifact, provider_id, values):
        reasons.add("l2.provider-evidence.execution-plan-invalid")
    observations = detail.get("dimensionObservations")
    selected = observations.get(dimension) if isinstance(observations, Mapping) else None
    _validate_dimension_observation(selected, values, dimension, str(
        getattr(artifact, "fragment_id", "")), reasons)
    if reasons:
        return None, tuple(sorted(reasons))
    return values, ()


def _execution_plan_is_valid(
    detail: Mapping[str, object], artifact: object, provider_id: str,
    values: Mapping[str, str],
) -> bool:
    raw_plan = detail.get("executionPlan")
    try:
        if not isinstance(raw_plan, Mapping):
            return False
        plan = execution_plan_from_dict(raw_plan)
        expected = execution_plan_for_provider(
            artifact, provider_id=provider_id,
            harness_identity=values.get("harnessIdentity", ""))
        return (plan.plan_identity == values.get("executionPlanIdentity")
                and plan.plan_identity == expected.plan_identity
                and plan.fragment_id == str(getattr(artifact, "fragment_id", ""))
                and plan.provider_id == provider_id
                and plan.translation_approval_identity == str(
                    getattr(artifact, "proof_identity", ""))
                and plan.semantic_authority_identity == values.get("authorityIdentity")
                and plan.effect_relation_identity == values.get("effectRelationIdentity")
                and plan.environment_authority_identity
                    == values.get("environmentAuthorityIdentity")
                and plan.runtime_adapter_identity == values.get("runtimeAdapterIdentity")
                and plan.harness_identity == values.get("harnessIdentity"))
    except (TypeError, ValueError):
        return False


def _validate_dimension_observation(
    selected: object, values: dict[str, str], dimension: str,
    fragment_id: str, reasons: set[str],
) -> None:
    fields = {
        "schemaVersion", "dimension", "authorityIdentity",
        "effectRelationIdentity", "executionIdentity", "observedProperties",
        "sourceEvidenceIdentity", "targetEvidenceIdentity",
        "sourceObservationIdentity", "targetObservationIdentity",
    }
    if not isinstance(selected, Mapping) or set(selected) != fields:
        reasons.add("l2.provider-evidence.dimension-observation-missing:" + dimension)
        return
    if (selected.get("schemaVersion") != L2_DIMENSION_EVIDENCE_SCHEMA
            or selected.get("dimension") != dimension):
        reasons.add("l2.provider-evidence.dimension-binding-invalid:" + dimension)
    for field in ("authorityIdentity", "effectRelationIdentity", "executionIdentity"):
        selected_value = str(selected.get(field) or "")
        if (_SHA.fullmatch(selected_value) is None
                or selected_value != values.get(field, "")):
            reasons.add("l2.provider-evidence.dimension-identity-invalid:"
                        + dimension + ":" + field)
        else:
            values[field] = selected_value
    properties = selected.get("observedProperties")
    if (not isinstance(properties, list) or not properties
            or any(not isinstance(item, str) or not item for item in properties)
            or len(set(properties)) != len(properties)):
        reasons.add("l2.provider-evidence.observed-properties-incomplete:" + dimension)
        properties = []
    execution = str(selected.get("executionIdentity") or "")
    authority = str(selected.get("authorityIdentity") or "")
    relation = str(selected.get("effectRelationIdentity") or "")
    for side in ("source", "target"):
        evidence_name = side + "EvidenceIdentity"
        observation_name = side + "ObservationIdentity"
        evidence = str(selected.get(evidence_name) or "")
        observation = str(selected.get(observation_name) or "")
        expected = identity({
            "schemaVersion": "riscv2x86.l2-dimension-observation.v1",
            "executionIdentity": execution, "fragmentId": fragment_id,
            "dimension": dimension, "side": side,
            "evidenceIdentity": evidence,
            "authorityIdentity": authority,
            "effectRelationIdentity": relation,
            "observedProperties": properties,
        }) if (all(_SHA.fullmatch(item) for item in
                   (execution, evidence, authority, relation)) and properties) else ""
        if _SHA.fullmatch(observation) is None or observation != expected:
            reasons.add("l2.provider-evidence.dimension-observation-invalid:"
                        + dimension + ":" + observation_name)
        else:
            values[observation_name] = observation
