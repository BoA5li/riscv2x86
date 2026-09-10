"""Versioned, content-addressed archive for terminal translation attempts."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from .schema import PublicationOutcome, TranslationOutcome, ValidationOutcome


TRANSLATION_ATTEMPT_SCHEMA = "riscv2x86.translation-attempt.v1"
TRANSLATION_ATTEMPT_ARCHIVE_SCHEMA = "riscv2x86.translation-attempt-archive.v1"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _identity(payload: Mapping[str, object]) -> str:
    return "sha256:" + sha256(_canonical(payload)).hexdigest()


def _text(value: object, label: str, *, optional: bool = False) -> str:
    if not isinstance(value, str) or (not optional and not value):
        raise ValueError(label + " must be a non-empty string")
    return value


def _sha(value: object, label: str, *, optional: bool = False) -> str:
    text = _text(value, label, optional=optional)
    if text or not optional:
        if _SHA256.fullmatch(text) is None:
            raise ValueError(label + " must be a sha256 identity")
    return text


def _ordered_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an array of non-empty strings")
    items = tuple(value)
    if items != tuple(sorted(set(items))):
        raise ValueError(label + " must already be unique and canonically sorted")
    return items


@dataclass(frozen=True)
class TranslationAttempt:
    finding_id: str
    fragment_id: str
    candidate_kind: str
    candidate_route: str
    candidate_replacement: str
    candidate_replacement_digest: str
    candidate_rule_name: str
    translation_outcome: TranslationOutcome
    validation_outcome: ValidationOutcome
    publication_outcome: PublicationOutcome
    reason_codes: tuple[str, ...]
    source_model_id: str = ""
    preservation_decision_id: str = ""
    plan_id: str = ""
    constraints_id: str = ""
    proof_status: str = ""
    proof_binding_identity: str = ""
    target_environment_id: str = ""
    renderer_id: str = ""
    renderer_version: str = ""
    renderer_contract_id: str = ""
    renderer_registry_id: str = ""
    renderer_registry_version: str = ""
    binding_complete: bool = False
    artifact_id: str = ""
    schema_version: str = TRANSLATION_ATTEMPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != TRANSLATION_ATTEMPT_SCHEMA:
            raise ValueError("translation attempt schema is unsupported")
        if not self.finding_id or not self.fragment_id:
            raise ValueError("translation attempt finding/fragment identity is missing")
        digest = "sha256:" + sha256(self.candidate_replacement.encode("utf-8")).hexdigest()
        if self.candidate_replacement_digest != digest:
            raise ValueError("candidate replacement digest does not match candidate text")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("translation attempt reason codes are not canonical")
        emitted = self.translation_outcome in {
            TranslationOutcome.EMITTED, TranslationOutcome.STRENGTHENED,
            TranslationOutcome.FUNCTIONAL_FALLBACK,
        }
        if emitted and not self.candidate_replacement.strip():
            raise ValueError("emitted translation attempt has no archived candidate")
        if not emitted and self.candidate_replacement:
            raise ValueError("non-emitted translation attempt cannot archive candidate text")
        if self.publication_outcome is PublicationOutcome.PENDING:
            raise ValueError("archive accepts terminal publication outcomes only")
        binding_values = (
            self.source_model_id, self.preservation_decision_id, self.plan_id,
            self.constraints_id, self.proof_status, self.proof_binding_identity,
            self.target_environment_id, self.renderer_id, self.renderer_version,
            self.renderer_contract_id, self.renderer_registry_id,
            self.renderer_registry_version,
        )
        actual_complete = all(binding_values) and self.proof_status == "approved"
        if self.binding_complete != actual_complete:
            raise ValueError("proof/plan/renderer binding completeness is inconsistent")
        if self.proof_binding_identity:
            _sha(self.proof_binding_identity, "proof binding identity")
        expected = _identity(self._payload(include_artifact_id=False))
        if self.artifact_id and self.artifact_id != expected:
            raise ValueError("translation attempt artifact ID does not match content")
        object.__setattr__(self, "artifact_id", expected)

    @property
    def evaluation_binding_complete(self) -> bool:
        """Whether this candidate has enough provenance for L0/L1 evaluation.

        This is intentionally weaker than ``binding_complete``.  The latter
        remains the publication/writeback contract and additionally requires
        preservation, target-environment, renderer-contract, and registry
        identities.  Build and functional experiments need an approved,
        reproducible candidate binding, but must not be suppressed merely
        because publication metadata is incomplete.
        """
        return not self.evaluation_binding_missing_fields

    @property
    def evaluation_binding_missing_fields(self) -> tuple[str, ...]:
        required = {
            "sourceModelId": self.source_model_id,
            "planId": self.plan_id,
            "constraintsId": self.constraints_id,
            "proofStatus": self.proof_status if self.proof_status == "approved" else "",
            "proofBindingIdentity": self.proof_binding_identity,
            "rendererId": self.renderer_id,
            "rendererVersion": self.renderer_version,
            "candidateReplacementDigest": self.candidate_replacement_digest,
        }
        return tuple(name for name, value in required.items() if not value)

    def _payload(self, *, include_artifact_id: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "schemaVersion": self.schema_version,
            "findingId": self.finding_id,
            "fragmentId": self.fragment_id,
            "candidateKind": self.candidate_kind,
            "candidateRoute": self.candidate_route,
            "candidateReplacement": self.candidate_replacement,
            "candidateReplacementDigest": self.candidate_replacement_digest,
            "candidateRuleName": self.candidate_rule_name,
            "translationOutcome": self.translation_outcome.value,
            "validationOutcome": self.validation_outcome.value,
            "publicationOutcome": self.publication_outcome.value,
            "reasonCodes": list(self.reason_codes),
            "sourceModelId": self.source_model_id,
            "preservationDecisionId": self.preservation_decision_id,
            "planId": self.plan_id,
            "constraintsId": self.constraints_id,
            "proofStatus": self.proof_status,
            "proofBindingIdentity": self.proof_binding_identity,
            "targetEnvironmentId": self.target_environment_id,
            "rendererId": self.renderer_id,
            "rendererVersion": self.renderer_version,
            "rendererContractId": self.renderer_contract_id,
            "rendererRegistryId": self.renderer_registry_id,
            "rendererRegistryVersion": self.renderer_registry_version,
            "bindingComplete": self.binding_complete,
        }
        if include_artifact_id:
            payload["artifactId"] = self.artifact_id
        return payload

    def to_dict(self) -> dict[str, object]:
        return self._payload(include_artifact_id=True)


_ATTEMPT_FIELDS = {
    "schemaVersion", "artifactId", "findingId", "fragmentId",
    "candidateKind", "candidateRoute", "candidateReplacement",
    "candidateReplacementDigest", "candidateRuleName", "translationOutcome",
    "validationOutcome", "publicationOutcome", "reasonCodes", "sourceModelId",
    "preservationDecisionId", "planId", "constraintsId", "proofStatus",
    "proofBindingIdentity", "targetEnvironmentId", "rendererId",
    "rendererVersion", "rendererContractId", "rendererRegistryId",
    "rendererRegistryVersion", "bindingComplete",
}


def translation_attempt_from_dict(value: Mapping[str, object]) -> TranslationAttempt:
    if set(value) != _ATTEMPT_FIELDS:
        raise ValueError("translation attempt fields are invalid")
    if not isinstance(value.get("bindingComplete"), bool):
        raise ValueError("translation attempt bindingComplete must be boolean")
    return TranslationAttempt(
        finding_id=_text(value.get("findingId"), "findingId"),
        fragment_id=_text(value.get("fragmentId"), "fragmentId"),
        candidate_kind=_text(value.get("candidateKind"), "candidateKind", optional=True),
        candidate_route=_text(value.get("candidateRoute"), "candidateRoute", optional=True),
        candidate_replacement=_text(value.get("candidateReplacement"), "candidateReplacement", optional=True),
        candidate_replacement_digest=_sha(value.get("candidateReplacementDigest"), "candidateReplacementDigest"),
        candidate_rule_name=_text(value.get("candidateRuleName"), "candidateRuleName", optional=True),
        translation_outcome=TranslationOutcome(_text(value.get("translationOutcome"), "translationOutcome")),
        validation_outcome=ValidationOutcome(_text(value.get("validationOutcome"), "validationOutcome")),
        publication_outcome=PublicationOutcome(_text(value.get("publicationOutcome"), "publicationOutcome")),
        reason_codes=_ordered_strings(value.get("reasonCodes"), "reasonCodes"),
        source_model_id=_text(value.get("sourceModelId"), "sourceModelId", optional=True),
        preservation_decision_id=_text(value.get("preservationDecisionId"), "preservationDecisionId", optional=True),
        plan_id=_text(value.get("planId"), "planId", optional=True),
        constraints_id=_text(value.get("constraintsId"), "constraintsId", optional=True),
        proof_status=_text(value.get("proofStatus"), "proofStatus", optional=True),
        proof_binding_identity=_sha(value.get("proofBindingIdentity"), "proofBindingIdentity", optional=True),
        target_environment_id=_text(value.get("targetEnvironmentId"), "targetEnvironmentId", optional=True),
        renderer_id=_text(value.get("rendererId"), "rendererId", optional=True),
        renderer_version=_text(value.get("rendererVersion"), "rendererVersion", optional=True),
        renderer_contract_id=_text(value.get("rendererContractId"), "rendererContractId", optional=True),
        renderer_registry_id=_text(value.get("rendererRegistryId"), "rendererRegistryId", optional=True),
        renderer_registry_version=_text(value.get("rendererRegistryVersion"), "rendererRegistryVersion", optional=True),
        binding_complete=value["bindingComplete"],
        artifact_id=_sha(value.get("artifactId"), "artifactId"),
        schema_version=_text(value.get("schemaVersion"), "schemaVersion"),
    )


def _proof_binding(approval: Mapping[str, object]) -> tuple[dict[str, str], bool]:
    names = {
        "source_model_id": "sourceModelId",
        "preservation_decision_id": "preservationDecisionId",
        "plan_id": "planId", "constraints_id": "constraintsId",
        "proof_status": "proofStatus", "target_environment_id": "targetEnvironmentId",
        "renderer_id": "rendererId", "renderer_version": "rendererVersion",
        "renderer_contract_id": "rendererContractId",
        "renderer_registry_id": "rendererRegistryId",
        "renderer_registry_version": "rendererRegistryVersion",
    }
    result = {
        field: value if isinstance((value := approval.get(key)), str) else ""
        for field, key in names.items()
    }
    proof_payload = {
        key: approval.get(key, "") for key in (
            "sourceModelId", "preservationDecisionId", "planId", "constraintsId",
            "proofStatus", "targetEnvironmentId", "targetCatalogVersion",
        )
    }
    proof_identity = approval.get("proofIdentity")
    if not isinstance(proof_identity, str) or _SHA256.fullmatch(proof_identity) is None:
        proof_identity = _identity(proof_payload) if all(proof_payload.values()) else ""
    result["proof_binding_identity"] = proof_identity
    complete = all(result.values()) and result["proof_status"] == "approved"
    return result, complete


def terminal_attempt_from_finding(finding: object, finding_index: int) -> TranslationAttempt:
    artifact = getattr(finding, "translationAttemptArtifact", {})
    if not isinstance(artifact, Mapping):
        raise ValueError("finding translationAttemptArtifact must be an object")
    fragment = getattr(finding, "fragment", None)
    fragment_id = str(getattr(fragment, "id", "") or artifact.get("fragmentId", ""))
    finding_id = "finding:%d:%s" % (finding_index, fragment_id)
    replacement = str(artifact.get("candidateReplacement", ""))
    approval = getattr(finding, "approvalArtifact", {})
    if not isinstance(approval, Mapping) or not approval:
        public = getattr(finding, "publicApprovalArtifact", {})
        approval = public if isinstance(public, Mapping) else {}
    binding, complete = _proof_binding(approval)
    return TranslationAttempt(
        finding_id=finding_id,
        fragment_id=fragment_id or str(artifact.get("fragmentId", "")),
        candidate_kind=str(artifact.get("candidateKind", "")),
        candidate_route=str(artifact.get("candidateRoute", "")),
        candidate_replacement=replacement,
        candidate_replacement_digest="sha256:" + sha256(replacement.encode("utf-8")).hexdigest(),
        candidate_rule_name=str(artifact.get("candidateRuleName", "")),
        translation_outcome=TranslationOutcome(str(getattr(finding, "translationOutcome"))),
        validation_outcome=ValidationOutcome(str(getattr(finding, "validationOutcome"))),
        publication_outcome=PublicationOutcome(str(getattr(finding, "publicationOutcome"))),
        reason_codes=tuple(sorted(set(str(item) for item in artifact.get("reasonCodes", []) if str(item)))),
        binding_complete=complete, **binding,
    )


@dataclass(frozen=True)
class TranslationAttemptArchive:
    attempts: tuple[TranslationAttempt, ...]
    archive_id: str = ""
    schema_version: str = TRANSLATION_ATTEMPT_ARCHIVE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != TRANSLATION_ATTEMPT_ARCHIVE_SCHEMA:
            raise ValueError("translation attempt archive schema is unsupported")
        ids = tuple(item.finding_id for item in self.attempts)
        if len(set(ids)) != len(ids):
            raise ValueError("archive contains more than one attempt for a finding")
        expected = _identity(self._payload(include_archive_id=False))
        if self.archive_id and self.archive_id != expected:
            raise ValueError("translation attempt archive ID does not match content")
        object.__setattr__(self, "archive_id", expected)

    def _payload(self, *, include_archive_id: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "schemaVersion": self.schema_version,
            "attempts": [item.to_dict() for item in self.attempts],
        }
        if include_archive_id:
            payload["archiveId"] = self.archive_id
        return payload

    def to_dict(self) -> dict[str, object]:
        return self._payload(include_archive_id=True)


def translation_attempt_archive_from_dict(value: Mapping[str, object]) -> TranslationAttemptArchive:
    if set(value) != {"schemaVersion", "archiveId", "attempts"}:
        raise ValueError("translation attempt archive fields are invalid")
    raw = value.get("attempts")
    if not isinstance(raw, list) or not all(isinstance(item, Mapping) for item in raw):
        raise ValueError("translation attempt archive attempts are malformed")
    return TranslationAttemptArchive(
        attempts=tuple(translation_attempt_from_dict(item) for item in raw),
        archive_id=_sha(value.get("archiveId"), "archiveId"),
        schema_version=_text(value.get("schemaVersion"), "schemaVersion"),
    )


def save_translation_attempt_archive(attempts: Sequence[TranslationAttempt], path: str | Path) -> TranslationAttemptArchive:
    archive = TranslationAttemptArchive(tuple(attempts))
    destination = Path(path)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(
        json.dumps(archive.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return archive


def load_translation_attempt_archive(path: str | Path) -> TranslationAttemptArchive:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("translation attempt archive root must be an object")
    return translation_attempt_archive_from_dict(value)
