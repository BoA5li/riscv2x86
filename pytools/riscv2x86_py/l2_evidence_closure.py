"""Common fail-closed binding from an approved translation to L2 evidence."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping


L2_EXECUTION_PLAN_SCHEMA = "riscv2x86.l2-execution-plan.v1"
L2_PROVIDER_EVIDENCE_SCHEMA = "riscv2x86.l2-provider-evidence.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


def identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _binding_identity(kind: str, value: object) -> str:
    return identity({"schemaVersion": "riscv2x86.l2-declared-binding.v1",
                     "kind": kind, "value": value})


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
    source_observation_identity: str, target_observation_identity: str,
    execution_nonce: object,
) -> dict[str, str]:
    plan = execution_plan_for_provider(
        artifact, provider_id=provider_id, harness_identity=harness_identity)
    for value in (source_observation_identity, target_observation_identity):
        if _SHA.fullmatch(value) is None:
            raise ValueError("provider observations are incomplete")
    execution_identity = identity({
        "schemaVersion": "riscv2x86.l2-authorized-execution.v1",
        "executionPlanIdentity": plan.plan_identity,
        "sourceObservationIdentity": source_observation_identity,
        "targetObservationIdentity": target_observation_identity,
        "executionNonce": execution_nonce,
    })
    return {
        "evidenceSchemaVersion": L2_PROVIDER_EVIDENCE_SCHEMA,
        "authorityIdentity": plan.semantic_authority_identity,
        "effectRelationIdentity": plan.effect_relation_identity,
        "executionPlanIdentity": plan.plan_identity,
        "environmentAuthorityIdentity": plan.environment_authority_identity,
        "runtimeAdapterIdentity": plan.runtime_adapter_identity,
        "harnessIdentity": plan.harness_identity,
        "sourceObservationIdentity": source_observation_identity,
        "targetObservationIdentity": target_observation_identity,
        "executionIdentity": execution_identity,
    }


def validated_provider_evidence(
    detail: Mapping[str, object], artifact: object,
) -> tuple[dict[str, str] | None, tuple[str, ...]]:
    """Validate the total evidence chain; never synthesize a missing link."""
    names = (
        "authorityIdentity", "effectRelationIdentity", "executionPlanIdentity",
        "environmentAuthorityIdentity", "runtimeAdapterIdentity", "harnessIdentity",
        "sourceObservationIdentity", "targetObservationIdentity", "executionIdentity",
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
    if reasons:
        return None, tuple(sorted(reasons))
    return values, ()
