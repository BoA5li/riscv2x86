"""Versioned Phase-9 output manifest bound to validation and writeback."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from .translation_validation import (
    ProgramArtifact, TargetEnvironment, TranslationArtifact,
    TranslationValidationResult, ValidationPlan,
)
from .validation_status import PreservationMode, ValidationStatus


OUTPUT_MANIFEST_SCHEMA = "riscv2x86.output-manifest.v3"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_MICROARCH_PRESERVATION = {"not_preserved", "not_claimed", "intent_preserved", "strengthened", "best_effort"}


def _canonical_digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(encoded.encode()).hexdigest()


def _canonical_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be a string array")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ValueError(label + " must be unique and sorted")
    return result


def _text(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str):
        raise ValueError("output manifest " + name + " must be a string")
    return item


def _boolean(value: Mapping[str, object], name: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool):
        raise ValueError("output manifest " + name + " must be boolean")
    return item


@dataclass(frozen=True)
class RequiredEnvironment:
    source_profile: str
    target_mode: str
    environment_id: str
    runtime_identity: str
    loader_identity: str

    def to_dict(self) -> dict[str, object]:
        return {"sourceProfile": self.source_profile, "targetMode": self.target_mode,
                "environmentId": self.environment_id, "runtimeIdentity": self.runtime_identity,
                "loaderIdentity": self.loader_identity}


@dataclass(frozen=True)
class OutputManifest:
    translation_id: str
    fragment_id: str
    preservation_mode: PreservationMode
    architecture_semantics_preserved: bool
    shell_semantics_preserved: bool
    microarchitecture_semantics_preserved: bool
    microarchitecture_preservation: str
    runtime_contracts: tuple[str, ...]
    runtime_registry_version: str
    proof_identity: str
    shell_facts_identity: str
    validation_identity: str
    validation_profile: str
    validation_status: ValidationStatus
    validation_levels: tuple[str, ...]
    ignored_source_state: tuple[str, ...]
    ignored_state_escapes: bool
    required_environment: RequiredEnvironment
    artifact_manifest_digest: str
    source_artifact_digest: str
    target_artifact_digest: str
    experiment_contract_id: str
    l3_required: bool
    complete: bool
    schema_version: str = OUTPUT_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != OUTPUT_MANIFEST_SCHEMA:
            raise ValueError("output manifest schema unsupported")
        if self.microarchitecture_preservation not in _MICROARCH_PRESERVATION:
            raise ValueError("output manifest microarchitecture preservation is invalid")
        for value, label in ((self.runtime_contracts, "runtime contracts"),
                             (self.validation_levels, "validation levels"),
                             (self.ignored_source_state, "ignored source state")):
            if value != tuple(sorted(set(value))):
                raise ValueError("output manifest " + label + " must be unique and sorted")

    @property
    def identity(self) -> str:
        return _canonical_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version, "translationId": self.translation_id,
            "fragmentId": self.fragment_id, "preservationMode": self.preservation_mode.value,
            "architectureSemanticsPreserved": self.architecture_semantics_preserved,
            "shellSemanticsPreserved": self.shell_semantics_preserved,
            "microarchitectureSemanticsPreserved": self.microarchitecture_semantics_preserved,
            "microarchitecturePreservation": self.microarchitecture_preservation,
            "runtimeContracts": list(self.runtime_contracts),
            "runtimeRegistryVersion": self.runtime_registry_version,
            "proofIdentity": self.proof_identity, "shellFactsIdentity": self.shell_facts_identity,
            "validationIdentity": self.validation_identity,
            "validationProfile": self.validation_profile, "validationStatus": self.validation_status.value,
            "validationLevels": list(self.validation_levels),
            "ignoredSourceState": list(self.ignored_source_state),
            "ignoredStateEscapes": self.ignored_state_escapes,
            "requiredEnvironment": self.required_environment.to_dict(),
            "artifactManifestDigest": self.artifact_manifest_digest,
            "sourceArtifactDigest": self.source_artifact_digest,
            "targetArtifactDigest": self.target_artifact_digest,
            "experimentContractId": self.experiment_contract_id,
            "l3Required": self.l3_required, "complete": self.complete,
        }


def output_manifest_from_dict(value: Mapping[str, object]) -> OutputManifest:
    fields = {"schemaVersion", "translationId", "fragmentId", "preservationMode",
              "architectureSemanticsPreserved", "shellSemanticsPreserved",
              "microarchitectureSemanticsPreserved", "microarchitecturePreservation",
              "runtimeContracts", "runtimeRegistryVersion", "proofIdentity", "shellFactsIdentity",
              "validationIdentity", "validationProfile", "validationStatus", "validationLevels",
              "ignoredSourceState", "ignoredStateEscapes", "requiredEnvironment",
              "artifactManifestDigest", "sourceArtifactDigest", "targetArtifactDigest",
              "experimentContractId", "l3Required", "complete"}
    if set(value) != fields or value.get("schemaVersion") != OUTPUT_MANIFEST_SCHEMA:
        raise ValueError("output manifest schema or fields are invalid")
    environment = value.get("requiredEnvironment")
    env_fields = {"sourceProfile", "targetMode", "environmentId", "runtimeIdentity", "loaderIdentity"}
    if not isinstance(environment, Mapping) or set(environment) != env_fields:
        raise ValueError("output manifest required environment is invalid")
    return OutputManifest(
        _text(value, "translationId"), _text(value, "fragmentId"),
        PreservationMode(_text(value, "preservationMode")),
        _boolean(value, "architectureSemanticsPreserved"), _boolean(value, "shellSemanticsPreserved"),
        _boolean(value, "microarchitectureSemanticsPreserved"),
        _text(value, "microarchitecturePreservation"),
        _canonical_strings(value.get("runtimeContracts"), "runtimeContracts"),
        _text(value, "runtimeRegistryVersion"), _text(value, "proofIdentity"),
        _text(value, "shellFactsIdentity"), _text(value, "validationIdentity"),
        _text(value, "validationProfile"), ValidationStatus(_text(value, "validationStatus")),
        _canonical_strings(value.get("validationLevels"), "validationLevels"),
        _canonical_strings(value.get("ignoredSourceState"), "ignoredSourceState"),
        _boolean(value, "ignoredStateEscapes"), RequiredEnvironment(
            _text(environment, "sourceProfile"), _text(environment, "targetMode"),
            _text(environment, "environmentId"), _text(environment, "runtimeIdentity"),
            _text(environment, "loaderIdentity"),
        ), _text(value, "artifactManifestDigest"), _text(value, "sourceArtifactDigest"),
        _text(value, "targetArtifactDigest"), _text(value, "experimentContractId"),
        _boolean(value, "l3Required"), _boolean(value, "complete"), _text(value, "schemaVersion"),
    )


def build_output_manifest(
    *, result: TranslationValidationResult, plan: ValidationPlan,
    translation: TranslationArtifact, source: ProgramArtifact, target: ProgramArtifact,
    environment: TargetEnvironment, artifact_manifest_digest: str,
    approval_artifact: Mapping[str, object], ignored_state_escapes: bool,
    l3_required: bool,
) -> OutputManifest:
    runtime_contract = ""
    if translation.runtime_contract_id and translation.runtime_contract_version:
        runtime_contract = translation.runtime_contract_id + "@" + translation.runtime_contract_version
    explicit_microarch = approval_artifact.get("microarchitecturePreservation")
    microarch = "not_preserved" if approval_artifact.get("microarchitectureSemanticsPreserved") is False else "not_claimed"
    if explicit_microarch in _MICROARCH_PRESERVATION:
        microarch = str(explicit_microarch)
    if translation.preservation_mode is PreservationMode.MICROARCHITECTURE_INTENT_PRESERVED:
        microarch = "intent_preserved"
    return OutputManifest(
        translation.identity, translation.fragment_id, translation.preservation_mode,
        approval_artifact.get("architectureSemanticsPreserved") is True,
        approval_artifact.get("shellSemanticsPreserved") is True,
        approval_artifact.get("microarchitectureSemanticsPreserved") is True, microarch,
        (() if not runtime_contract else (runtime_contract,)), plan.runtime_registry_version,
        translation.proof_identity, translation.shell_facts_identity,
        result.validation_identity, result.profile.value, result.status,
        tuple(sorted(item.value for item in result.completed_levels)), translation.ignored_source_state,
        ignored_state_escapes, RequiredEnvironment(
            environment.source_isa + "-user", environment.target_isa + "-user",
            environment.environment_id, environment.runtime_identity, environment.loader_identity,
        ), artifact_manifest_digest, source.artifact_digest, target.artifact_digest,
        plan.experiment_contract_id, l3_required,
        bool(
            approval_artifact.get("shellSemanticsPreserved") is True
            and _SHA256.fullmatch(result.validation_identity)
            and _SHA256.fullmatch(translation.proof_identity)
            and _SHA256.fullmatch(translation.shell_facts_identity)
            and runtime_contract and plan.runtime_registry_version
            and environment.environment_id and environment.runtime_identity and environment.loader_identity
        ),
    )


def is_sha256_identity(value: str) -> bool:
    return _SHA256.fullmatch(value) is not None
