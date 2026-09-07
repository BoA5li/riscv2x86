"""Versioned bridge from the translation pipeline to its sole validator."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .translation_validation import (
    ProgramArtifact, TargetEnvironment, TranslationArtifact,
    TranslationValidationResult, ValidationLevel, ValidationPlan,
    ValidationRuntimeRegistry,
    program_artifact_from_dict, run_translation_validation,
    target_environment_from_dict, translation_artifact_from_dict,
    validation_plan_from_dict,
)
from .validation_observation import ExecutionObservation
from .validation_runtime_registry import validation_runtime_registry_from_dict
from .validation_status import WRITEBACK_VALIDATION_EVIDENCE_VERSION


PIPELINE_VALIDATION_CONTEXT_SCHEMA = "riscv2x86.pipeline-validation-context.v1"


@dataclass(frozen=True)
class PipelineValidationContext:
    plan: ValidationPlan
    target_environment: TargetEnvironment
    runtime_registry: ValidationRuntimeRegistry
    source_program_artifact: ProgramArtifact
    target_program_artifact: ProgramArtifact
    translation_artifacts: Mapping[str, TranslationArtifact]
    source_observations: Mapping[str, ExecutionObservation]
    target_observations: Mapping[str, ExecutionObservation]
    ignored_state_escapes: Mapping[str, bool]
    translation_manifest_digest: str
    comparison_policy: str

    def __post_init__(self) -> None:
        if self.runtime_registry.version != self.plan.runtime_registry_version:
            raise ValueError("pipeline validation registry version does not match plan")
        if not self.translation_manifest_digest.startswith("sha256:"):
            raise ValueError("pipeline validation manifest digest is invalid")
        if not self.comparison_policy:
            raise ValueError("pipeline validation comparison policy is missing")
        l0_validator = self.runtime_registry.validator_for(ValidationLevel.L0)
        l0_matrix = getattr(l0_validator, "l0_matrix", None)
        if l0_validator is not None and l0_matrix is None:
            raise ValueError("pipeline L0 validator lacks a manifest-bound matrix")
        if l0_matrix is not None and (
            getattr(l0_matrix, "translation_manifest_digest", "")
            != self.translation_manifest_digest
        ):
            raise ValueError("pipeline and L0 validator manifest digests differ")
        keys = set(self.translation_artifacts)
        if not keys or set(self.ignored_state_escapes) != keys:
            raise ValueError("pipeline validation fragment coverage is incomplete")
        if not set(self.source_observations).issubset(keys):
            raise ValueError("source observation references an unknown fragment")
        if not set(self.target_observations).issubset(keys):
            raise ValueError("target observation references an unknown fragment")
        for observations, program, label in (
            (self.source_observations, self.source_program_artifact, "source"),
            (self.target_observations, self.target_program_artifact, "target"),
        ):
            for fragment_id, observation in observations.items():
                if observation.provenance.translation_manifest_digest != self.translation_manifest_digest:
                    raise ValueError(label + " observation manifest binding mismatch")
                if observation.provenance.artifact_digest != program.artifact_digest:
                    raise ValueError(label + " observation artifact binding mismatch")
                observation.validate_translation_artifact(self.translation_artifacts[fragment_id])

    def __call__(self, *, finding: object, **_kwargs: object) -> TranslationValidationResult:
        fragment = getattr(finding, "fragment", None)
        fragment_id = str(getattr(fragment, "id", ""))
        if fragment_id not in self.translation_artifacts:
            raise ValueError("pipeline validation has no artifact for fragment")
        translation = self.translation_artifacts[fragment_id]
        result = run_translation_validation(
            translation, self.source_program_artifact, self.target_program_artifact,
            self.plan, self.target_environment, self.runtime_registry,
            source_observation=self.source_observations.get(fragment_id),
            target_observation=self.target_observations.get(fragment_id),
            comparison_policy=self.comparison_policy,
        )
        self._bind_writeback_evidence(finding, translation, result)
        return result

    def _bind_writeback_evidence(
        self, finding: object, translation: TranslationArtifact,
        result: TranslationValidationResult,
    ) -> None:
        artifact = getattr(finding, "approvalArtifact", None)
        if not isinstance(artifact, dict):
            raise ValueError("pipeline validation approval artifact is unavailable")
        source_observation = self.source_observations.get(translation.fragment_id)
        target_observation = self.target_observations.get(translation.fragment_id)
        levels = {
            item.level.value: {
                "status": item.status.value,
                "evidenceIdentity": item.evidence_identity,
            }
            for item in result.layer_results
        }
        evidence = {
            "schemaVersion": WRITEBACK_VALIDATION_EVIDENCE_VERSION,
            "validationStatus": result.status.value,
            "validationIdentity": result.validation_identity,
            "validationProfile": result.profile.value,
            "levels": levels,
            "proofStatus": artifact.get("proofStatus"),
            "proofIdentity": translation.proof_identity,
            "shellSemanticsPreserved": artifact.get("shellSemanticsPreserved"),
            "shellFactsIdentity": translation.shell_facts_identity,
            "translationManifestDigest": self.translation_manifest_digest,
            "sourceArtifactDigest": self.source_program_artifact.artifact_digest,
            "targetArtifactDigest": self.target_program_artifact.artifact_digest,
            "artifactManifestBinding": {
                "translationManifestDigest": self.translation_manifest_digest,
                "sourceArtifactDigest": self.source_program_artifact.artifact_digest,
                "targetArtifactDigest": self.target_program_artifact.artifact_digest,
            },
            "observationBinding": {
                "sourceObservationIdentity": (
                    "" if source_observation is None else source_observation.identity
                ),
                "targetObservationIdentity": (
                    "" if target_observation is None else target_observation.identity
                ),
                "translationManifestDigest": self.translation_manifest_digest,
                "sourceArtifactDigest": self.source_program_artifact.artifact_digest,
                "targetArtifactDigest": self.target_program_artifact.artifact_digest,
            },
            "runtimeContractId": translation.runtime_contract_id,
            "runtimeContractVersion": translation.runtime_contract_version,
            "ignoredSourceState": list(translation.ignored_source_state),
            "ignoredStateEscapes": self.ignored_state_escapes[translation.fragment_id],
        }
        if self.plan.experiment_contract_id:
            evidence["microarchitectureExperimentContractId"] = (
                self.plan.experiment_contract_id
            )
        artifact["validationEvidence"] = evidence
        artifact["shellFactsIdentity"] = translation.shell_facts_identity
        for name in (
            "validationStatus", "validationIdentity", "validationProfile",
            "translationManifestDigest", "sourceArtifactDigest",
            "targetArtifactDigest",
        ):
            artifact[name] = evidence[name]


def _observations(value: object, label: str) -> dict[str, ExecutionObservation]:
    if not isinstance(value, Mapping):
        raise ValueError(label + " must be an object")
    observations = {}
    for fragment_id, item in value.items():
        if not isinstance(fragment_id, str) or not isinstance(item, Mapping):
            raise ValueError(label + " entry is malformed")
        observations[fragment_id] = ExecutionObservation.from_dict(item)
    return observations


def pipeline_validation_context_from_dict(
    data: Mapping[str, object],
) -> PipelineValidationContext:
    fields = {
        "schemaVersion", "validationPlan", "targetEnvironment",
        "runtimeRegistry", "sourceProgramArtifact", "targetProgramArtifact",
        "translationArtifacts", "sourceObservations", "targetObservations",
        "ignoredStateEscapes", "translationManifestDigest", "comparisonPolicy",
    }
    if set(data) != fields or data.get("schemaVersion") != PIPELINE_VALIDATION_CONTEXT_SCHEMA:
        raise ValueError("pipeline validation context schema or fields are invalid")
    mappings = {}
    for name in (
        "validationPlan", "targetEnvironment", "runtimeRegistry",
        "sourceProgramArtifact", "targetProgramArtifact", "translationArtifacts",
        "ignoredStateEscapes",
    ):
        value = data.get(name)
        if not isinstance(value, Mapping):
            raise ValueError(name + " must be an object")
        mappings[name] = value
    translations = {
        str(fragment_id): translation_artifact_from_dict(item)
        for fragment_id, item in mappings["translationArtifacts"].items()
        if isinstance(item, Mapping)
    }
    if set(translations) != set(mappings["translationArtifacts"]):
        raise ValueError("translation artifact entry is malformed")
    if any(item.fragment_id != fragment_id for fragment_id, item in translations.items()):
        raise ValueError("translation artifact key does not match fragment ID")
    escapes = mappings["ignoredStateEscapes"]
    if not all(isinstance(key, str) and isinstance(value, bool)
               for key, value in escapes.items()):
        raise ValueError("ignored-state escape facts are malformed")
    return PipelineValidationContext(
        plan=validation_plan_from_dict(mappings["validationPlan"]),
        target_environment=target_environment_from_dict(mappings["targetEnvironment"]),
        runtime_registry=validation_runtime_registry_from_dict(mappings["runtimeRegistry"]),
        source_program_artifact=program_artifact_from_dict(mappings["sourceProgramArtifact"]),
        target_program_artifact=program_artifact_from_dict(mappings["targetProgramArtifact"]),
        translation_artifacts=translations,
        source_observations=_observations(data.get("sourceObservations"), "source observations"),
        target_observations=_observations(data.get("targetObservations"), "target observations"),
        ignored_state_escapes=dict(escapes),
        translation_manifest_digest=str(data.get("translationManifestDigest", "")),
        comparison_policy=str(data.get("comparisonPolicy", "")),
    )


def load_pipeline_validation_context(path: str | Path) -> PipelineValidationContext:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("pipeline validation context must be an object")
    return pipeline_validation_context_from_dict(data)
