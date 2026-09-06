"""Versioned orchestration entry point for translation-result validation.

This module deliberately owns no emulator, native execution, or trace
inference.  It validates the evidence contract and invokes registered L0-L3
layers in their only permitted order.  Missing evidence is inconclusive, never
a synthetic pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from .validation_status import PreservationMode, ValidationStatus
from .validation_observation import ExecutionObservation


VALIDATION_PLAN_SCHEMA = "riscv2x86.validation-plan.v1"
TRANSLATION_VALIDATION_VERSION = "riscv2x86.translation-validation.v1"


class ValidationProfile(str, Enum):
    BUILD = "build"
    FUNCTIONAL = "functional"
    ARCHITECTURAL = "architectural"
    MICROARCH = "microarch"


class ValidationLevel(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


_PROFILE_LEVELS = {
    ValidationProfile.BUILD: (ValidationLevel.L0,),
    ValidationProfile.FUNCTIONAL: (ValidationLevel.L0, ValidationLevel.L1),
    ValidationProfile.ARCHITECTURAL: (
        ValidationLevel.L0, ValidationLevel.L1, ValidationLevel.L2,
    ),
    ValidationProfile.MICROARCH: (
        ValidationLevel.L0, ValidationLevel.L1, ValidationLevel.L2,
        ValidationLevel.L3,
    ),
}


@dataclass(frozen=True)
class TranslationArtifact:
    fragment_id: str
    source_model_identity: str
    translation_plan_id: str
    constraint_id: str
    proof_identity: str
    preservation_mode: PreservationMode
    shell_facts_identity: str
    runtime_contract_id: str
    runtime_contract_version: str
    recipe_id: str
    ignored_source_state: tuple[str, ...]
    semantic_class: str
    target_route: str

    def __post_init__(self) -> None:
        required = (
            self.fragment_id, self.source_model_identity,
            self.translation_plan_id, self.constraint_id,
            self.shell_facts_identity, self.semantic_class, self.target_route,
        )
        if not all(required):
            raise ValueError("translation artifact is missing required identity facts")
        if tuple(sorted(set(self.ignored_source_state))) != self.ignored_source_state:
            raise ValueError("ignored source state must be unique and sorted")


@dataclass(frozen=True)
class ProgramArtifact:
    artifact_id: str
    artifact_path: str
    artifact_kind: str
    artifact_digest: str
    build_identity: str = ""

    def __post_init__(self) -> None:
        if not all((self.artifact_id, self.artifact_path, self.artifact_kind, self.artifact_digest)):
            raise ValueError("program artifact is incomplete")


@dataclass(frozen=True)
class ValidationPlan:
    plan_id: str
    profile: ValidationProfile
    source_runner: str
    target_runner: str
    seed: int
    timeout_seconds: int
    runtime_registry_version: str
    experiment_contract_id: str = ""

    def __post_init__(self) -> None:
        if not self.plan_id or not self.runtime_registry_version:
            raise ValueError("validation plan identity is incomplete")
        if self.source_runner not in {"spike", "qemu", "custom"}:
            raise ValueError("source runner is unsupported")
        if self.target_runner not in {"native", "logical-csr-runtime", "custom"}:
            raise ValueError("target runner is unsupported")
        if self.seed < 0 or self.timeout_seconds <= 0:
            raise ValueError("validation seed/timeout is invalid")
        if self.profile is ValidationProfile.MICROARCH and not self.experiment_contract_id:
            raise ValueError("microarch profile requires an experiment contract")

    @property
    def required_levels(self) -> tuple[ValidationLevel, ...]:
        return _PROFILE_LEVELS[self.profile]


@dataclass(frozen=True)
class ValidationLayerResult:
    level: ValidationLevel
    status: ValidationStatus
    evidence_identity: str = ""
    detail: str = ""


@dataclass(frozen=True)
class TranslationValidationResult:
    status: ValidationStatus
    profile: ValidationProfile
    completed_levels: tuple[ValidationLevel, ...]
    layer_results: tuple[ValidationLayerResult, ...]
    reason_codes: tuple[str, ...]
    validation_identity: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": TRANSLATION_VALIDATION_VERSION,
            "status": self.status.value,
            "profile": self.profile.value,
            "completedLevels": [item.value for item in self.completed_levels],
            "layers": [
                {"level": item.level.value, "status": item.status.value,
                 "evidenceIdentity": item.evidence_identity, "detail": item.detail}
                for item in self.layer_results
            ],
            "reasonCodes": list(self.reason_codes),
            "validationIdentity": self.validation_identity,
        }


LayerValidator = Callable[..., ValidationLayerResult]


@dataclass(frozen=True)
class ValidationRuntimeRegistry:
    version: str
    layer_validators: Mapping[ValidationLevel, LayerValidator]

    def validator_for(self, level: ValidationLevel) -> LayerValidator | None:
        return self.layer_validators.get(level)


def _canonical_identity(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()


def _artifact_payload(artifact: TranslationArtifact | ProgramArtifact) -> Mapping[str, object]:
    return dict(artifact.__dict__)


def _result(
    *, status: ValidationStatus, plan: ValidationPlan,
    layers: tuple[ValidationLayerResult, ...] = (), reasons: tuple[str, ...] = (),
    translation_artifact: TranslationArtifact, source_program_artifact: ProgramArtifact,
    target_program_artifact: ProgramArtifact, target_environment: Mapping[str, object],
    source_observation: ExecutionObservation | None = None,
    target_observation: ExecutionObservation | None = None,
    comparison_policy: str = "riscv2x86.comparison-policy.none.v1",
) -> TranslationValidationResult:
    payload = {
        "version": TRANSLATION_VALIDATION_VERSION,
        "plan": dict(plan.__dict__),
        "translation": _artifact_payload(translation_artifact),
        "source": _artifact_payload(source_program_artifact),
        "target": _artifact_payload(target_program_artifact),
        "environment": dict(target_environment),
        "comparisonPolicy": comparison_policy,
        "sourceObservation": None if source_observation is None else source_observation.to_dict(),
        "targetObservation": None if target_observation is None else target_observation.to_dict(),
        "layers": [dict(item.__dict__) for item in layers],
        "reasons": list(reasons),
    }
    completed = tuple(item.level for item in layers if item.status is ValidationStatus.VERIFIED)
    return TranslationValidationResult(status, plan.profile, completed, layers, reasons, _canonical_identity(payload))


def _validate_profile(artifact: TranslationArtifact, plan: ValidationPlan) -> str | None:
    if artifact.preservation_mode is PreservationMode.ARCHITECTURE_EQUIVALENT:
        if plan.profile not in {ValidationProfile.ARCHITECTURAL, ValidationProfile.MICROARCH}:
            return "validation.strict-profile-insufficient"
    if artifact.preservation_mode is PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY:
        if plan.profile is ValidationProfile.BUILD:
            return "validation.functional-profile-insufficient"
    if artifact.preservation_mode is PreservationMode.MICROARCHITECTURE_INTENT_PRESERVED:
        if plan.profile is not ValidationProfile.MICROARCH:
            return "validation.microarch-profile-insufficient"
    return None


def run_translation_validation(
    translation_artifact: TranslationArtifact,
    source_program_artifact: ProgramArtifact,
    target_program_artifact: ProgramArtifact,
    validation_plan: ValidationPlan,
    target_environment: Mapping[str, object],
    runtime_registry: ValidationRuntimeRegistry,
    *,
    source_observation: ExecutionObservation | None = None,
    target_observation: ExecutionObservation | None = None,
    comparison_policy: str = "riscv2x86.comparison-policy.none.v1",
) -> TranslationValidationResult:
    """Run registered validation layers in mandatory L0 → L3 order.

    Each validator receives only structured artifacts and may return verified,
    failed, or inconclusive.  A missing validator is inconclusive; it cannot be
    replaced by a build-only success or by a later layer.
    """
    def finish(**kwargs: object) -> TranslationValidationResult:
        return _result(
            **kwargs, source_observation=source_observation,
            target_observation=target_observation, comparison_policy=comparison_policy,
        )

    reason = _validate_profile(translation_artifact, validation_plan)
    if runtime_registry.version != validation_plan.runtime_registry_version:
        reason = reason or "validation.runtime-registry-version-mismatch"
    if reason:
        return finish(
            status=ValidationStatus.FAILED, plan=validation_plan,
            reasons=(reason,), translation_artifact=translation_artifact,
            source_program_artifact=source_program_artifact,
            target_program_artifact=target_program_artifact,
            target_environment=target_environment,
        )

    layers: list[ValidationLayerResult] = []
    for level in validation_plan.required_levels:
        validator = runtime_registry.validator_for(level)
        if validator is None:
            layers.append(ValidationLayerResult(
                level, ValidationStatus.INCONCLUSIVE,
                detail="no registered validation layer runner",
            ))
            return finish(
                status=ValidationStatus.INCONCLUSIVE, plan=validation_plan,
                layers=tuple(layers), reasons=("validation.layer-runner-missing:" + level.value,),
                translation_artifact=translation_artifact,
                source_program_artifact=source_program_artifact,
                target_program_artifact=target_program_artifact,
                target_environment=target_environment,
            )
        layer = validator(
            level=level, translation_artifact=translation_artifact,
            source_program_artifact=source_program_artifact,
            target_program_artifact=target_program_artifact,
            validation_plan=validation_plan,
            target_environment=target_environment,
        )
        if not isinstance(layer, ValidationLayerResult) or layer.level is not level:
            layers.append(ValidationLayerResult(level, ValidationStatus.FAILED, detail="invalid layer runner result"))
            return finish(
                status=ValidationStatus.FAILED, plan=validation_plan, layers=tuple(layers),
                reasons=("validation.layer-runner-protocol-error:" + level.value,),
                translation_artifact=translation_artifact, source_program_artifact=source_program_artifact,
                target_program_artifact=target_program_artifact, target_environment=target_environment,
            )
        layers.append(layer)
        if layer.status is not ValidationStatus.VERIFIED:
            return finish(
                status=layer.status, plan=validation_plan, layers=tuple(layers),
                reasons=("validation.layer-not-verified:" + level.value,),
                translation_artifact=translation_artifact, source_program_artifact=source_program_artifact,
                target_program_artifact=target_program_artifact, target_environment=target_environment,
            )
    return finish(
        status=ValidationStatus.VERIFIED, plan=validation_plan, layers=tuple(layers),
        translation_artifact=translation_artifact, source_program_artifact=source_program_artifact,
        target_program_artifact=target_program_artifact, target_environment=target_environment,
    )


def load_validation_plan(path: str | Path) -> ValidationPlan:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping) or data.get("schemaVersion") != VALIDATION_PLAN_SCHEMA:
        raise ValueError("validation plan schema version is unsupported")
    return ValidationPlan(
        plan_id=str(data.get("planId", "")), profile=ValidationProfile(str(data.get("profile", ""))),
        source_runner=str(data.get("sourceRunner", "")), target_runner=str(data.get("targetRunner", "")),
        seed=int(data.get("seed", -1)), timeout_seconds=int(data.get("timeoutSeconds", 0)),
        runtime_registry_version=str(data.get("runtimeRegistryVersion", "")),
        experiment_contract_id=str(data.get("experimentContractId", "")),
    )
