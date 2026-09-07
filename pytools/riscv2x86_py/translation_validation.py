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
import re
from typing import Any, Callable, Mapping

from .validation_status import PreservationMode, ValidationStatus
from .validation_observation import ExecutionObservation


VALIDATION_PLAN_SCHEMA = "riscv2x86.validation-plan.v1"
TARGET_ENVIRONMENT_SCHEMA = "riscv2x86.target-environment.v1"
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


@dataclass(frozen=True)
class TargetEnvironment:
    environment_id: str
    source_isa: str
    source_abi: str
    target_isa: str
    target_abi: str
    source_runner_capabilities: tuple[str, ...]
    target_runner_capabilities: tuple[str, ...]
    sanitizer_capabilities: tuple[str, ...]
    runtime_identity: str
    loader_identity: str
    schema_version: str = TARGET_ENVIRONMENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != TARGET_ENVIRONMENT_SCHEMA:
            raise ValueError("target environment schema version is unsupported")
        if not all((self.environment_id, self.runtime_identity, self.loader_identity)):
            raise ValueError("target environment identity is incomplete")
        if re.fullmatch(r"rv64(?:i|e|g)[a-z0-9_]*", self.source_isa) is None:
            raise ValueError("initial validation environment requires an RV64 source ISA")
        if self.source_abi not in {"lp64", "lp64f", "lp64d"}:
            raise ValueError("source ABI is unsupported")
        if self.target_isa != "x86_64" or self.target_abi != "sysv_amd64":
            raise ValueError("initial validation environment requires x86-64 SysV")
        self._validate_capabilities(
            self.source_runner_capabilities, {"spike", "qemu", "custom"},
            "source runner",
        )
        self._validate_capabilities(
            self.target_runner_capabilities,
            {"native", "logical-csr-runtime", "custom"}, "target runner",
        )
        self._validate_capabilities(
            self.sanitizer_capabilities, {"none", "asan", "ubsan"},
            "sanitizer",
        )
        if "none" not in self.sanitizer_capabilities:
            raise ValueError("target environment must support the none sanitizer cell")

    @staticmethod
    def _validate_capabilities(
        values: tuple[str, ...], allowed: set[str], name: str,
    ) -> None:
        if not values or tuple(sorted(set(values))) != values:
            raise ValueError(name + " capabilities must be non-empty, unique and sorted")
        if not set(values).issubset(allowed):
            raise ValueError(name + " capability is unsupported")

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "environmentId": self.environment_id,
            "sourceIsa": self.source_isa,
            "sourceAbi": self.source_abi,
            "targetIsa": self.target_isa,
            "targetAbi": self.target_abi,
            "sourceRunnerCapabilities": list(self.source_runner_capabilities),
            "targetRunnerCapabilities": list(self.target_runner_capabilities),
            "sanitizerCapabilities": list(self.sanitizer_capabilities),
            "runtimeIdentity": self.runtime_identity,
            "loaderIdentity": self.loader_identity,
        }


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
    schema_version: str = VALIDATION_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_PLAN_SCHEMA:
            raise ValueError("validation plan schema version is unsupported")
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
    target_environment: TargetEnvironment,
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

    environment_payload = target_environment.to_dict()

    reason = _validate_profile(translation_artifact, validation_plan)
    if runtime_registry.version != validation_plan.runtime_registry_version:
        reason = reason or "validation.runtime-registry-version-mismatch"
    if reason:
        return finish(
            status=ValidationStatus.FAILED, plan=validation_plan,
            reasons=(reason,), translation_artifact=translation_artifact,
            source_program_artifact=source_program_artifact,
            target_program_artifact=target_program_artifact,
            target_environment=environment_payload,
        )

    if validation_plan.source_runner not in target_environment.source_runner_capabilities:
        return finish(
            status=ValidationStatus.INCONCLUSIVE, plan=validation_plan,
            reasons=("validation.source-runner-capability-missing",),
            translation_artifact=translation_artifact,
            source_program_artifact=source_program_artifact,
            target_program_artifact=target_program_artifact,
            target_environment=environment_payload,
        )
    if validation_plan.target_runner not in target_environment.target_runner_capabilities:
        return finish(
            status=ValidationStatus.INCONCLUSIVE, plan=validation_plan,
            reasons=("validation.target-runner-capability-missing",),
            translation_artifact=translation_artifact,
            source_program_artifact=source_program_artifact,
            target_program_artifact=target_program_artifact,
            target_environment=environment_payload,
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
                target_environment=environment_payload,
            )
        layer = validator(
            level=level, translation_artifact=translation_artifact,
            source_program_artifact=source_program_artifact,
            target_program_artifact=target_program_artifact,
            validation_plan=validation_plan,
            target_environment=environment_payload,
        )
        if not isinstance(layer, ValidationLayerResult) or layer.level is not level:
            layers.append(ValidationLayerResult(level, ValidationStatus.FAILED, detail="invalid layer runner result"))
            return finish(
                status=ValidationStatus.FAILED, plan=validation_plan, layers=tuple(layers),
                reasons=("validation.layer-runner-protocol-error:" + level.value,),
                translation_artifact=translation_artifact, source_program_artifact=source_program_artifact,
                target_program_artifact=target_program_artifact, target_environment=environment_payload,
            )
        layers.append(layer)
        if layer.status is not ValidationStatus.VERIFIED:
            return finish(
                status=layer.status, plan=validation_plan, layers=tuple(layers),
                reasons=("validation.layer-not-verified:" + level.value,),
                translation_artifact=translation_artifact, source_program_artifact=source_program_artifact,
                target_program_artifact=target_program_artifact, target_environment=environment_payload,
            )
    return finish(
        status=ValidationStatus.VERIFIED, plan=validation_plan, layers=tuple(layers),
        translation_artifact=translation_artifact, source_program_artifact=source_program_artifact,
        target_program_artifact=target_program_artifact, target_environment=environment_payload,
    )


def _strict_fields(
    data: Mapping[str, object], expected: set[str], label: str,
) -> None:
    if set(data) != expected:
        missing = sorted(expected - set(data))
        unknown = sorted(set(data) - expected)
        raise ValueError(
            f"{label} fields are incomplete or unknown: "
            f"missing={missing}, unknown={unknown}"
        )


def _required_string(data: Mapping[str, object], name: str, label: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} {name} must be a non-empty string")
    return value


def _string(data: Mapping[str, object], name: str, label: str) -> str:
    value = data.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{label} {name} must be a string")
    return value


def translation_artifact_from_dict(data: Mapping[str, object]) -> TranslationArtifact:
    fields = {
        "fragment_id", "source_model_identity", "translation_plan_id",
        "constraint_id", "proof_identity", "preservation_mode",
        "shell_facts_identity", "runtime_contract_id",
        "runtime_contract_version", "recipe_id", "ignored_source_state",
        "semantic_class", "target_route",
    }
    _strict_fields(data, fields, "translation artifact")
    ignored = data.get("ignored_source_state")
    if not isinstance(ignored, list) or not all(isinstance(item, str) for item in ignored):
        raise ValueError("translation artifact ignored source state must be an array")
    return TranslationArtifact(
        fragment_id=str(data.get("fragment_id", "")),
        source_model_identity=str(data.get("source_model_identity", "")),
        translation_plan_id=str(data.get("translation_plan_id", "")),
        constraint_id=str(data.get("constraint_id", "")),
        proof_identity=str(data.get("proof_identity", "")),
        preservation_mode=PreservationMode(str(data.get("preservation_mode", ""))),
        shell_facts_identity=str(data.get("shell_facts_identity", "")),
        runtime_contract_id=str(data.get("runtime_contract_id", "")),
        runtime_contract_version=str(data.get("runtime_contract_version", "")),
        recipe_id=str(data.get("recipe_id", "")),
        ignored_source_state=tuple(ignored),
        semantic_class=str(data.get("semantic_class", "")),
        target_route=str(data.get("target_route", "")),
    )


def program_artifact_from_dict(data: Mapping[str, object]) -> ProgramArtifact:
    fields = {
        "artifact_id", "artifact_path", "artifact_kind", "artifact_digest",
        "build_identity",
    }
    _strict_fields(data, fields, "program artifact")
    return ProgramArtifact(
        artifact_id=str(data.get("artifact_id", "")),
        artifact_path=str(data.get("artifact_path", "")),
        artifact_kind=str(data.get("artifact_kind", "")),
        artifact_digest=str(data.get("artifact_digest", "")),
        build_identity=str(data.get("build_identity", "")),
    )


def validation_plan_from_dict(data: Mapping[str, object]) -> ValidationPlan:
    fields = {
        "schemaVersion", "planId", "profile", "sourceRunner", "targetRunner",
        "seed", "timeoutSeconds", "runtimeRegistryVersion",
        "experimentContractId",
    }
    _strict_fields(data, fields, "validation plan")
    if data.get("schemaVersion") != VALIDATION_PLAN_SCHEMA:
        raise ValueError("validation plan schema version is unsupported")
    seed = data.get("seed")
    timeout = data.get("timeoutSeconds")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("validation plan seed must be an integer")
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ValueError("validation plan timeout must be an integer")
    return ValidationPlan(
        plan_id=_required_string(data, "planId", "validation plan"),
        profile=ValidationProfile(_required_string(data, "profile", "validation plan")),
        source_runner=_required_string(data, "sourceRunner", "validation plan"),
        target_runner=_required_string(data, "targetRunner", "validation plan"),
        seed=seed, timeout_seconds=timeout,
        runtime_registry_version=_required_string(
            data, "runtimeRegistryVersion", "validation plan",
        ),
        experiment_contract_id=_string(
            data, "experimentContractId", "validation plan",
        ),
        schema_version=_required_string(data, "schemaVersion", "validation plan"),
    )


def load_validation_plan(path: str | Path) -> ValidationPlan:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("validation plan must be an object")
    return validation_plan_from_dict(data)


def target_environment_from_dict(data: Mapping[str, object]) -> TargetEnvironment:
    fields = {
        "schemaVersion", "environmentId", "sourceIsa", "sourceAbi",
        "targetIsa", "targetAbi", "sourceRunnerCapabilities",
        "targetRunnerCapabilities", "sanitizerCapabilities", "runtimeIdentity",
        "loaderIdentity",
    }
    _strict_fields(data, fields, "target environment")

    def capabilities(name: str) -> tuple[str, ...]:
        value = data.get(name)
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise ValueError(name + " must be a non-empty string array")
        return tuple(value)

    return TargetEnvironment(
        environment_id=_required_string(data, "environmentId", "target environment"),
        source_isa=_required_string(data, "sourceIsa", "target environment"),
        source_abi=_required_string(data, "sourceAbi", "target environment"),
        target_isa=_required_string(data, "targetIsa", "target environment"),
        target_abi=_required_string(data, "targetAbi", "target environment"),
        source_runner_capabilities=capabilities("sourceRunnerCapabilities"),
        target_runner_capabilities=capabilities("targetRunnerCapabilities"),
        sanitizer_capabilities=capabilities("sanitizerCapabilities"),
        runtime_identity=_required_string(
            data, "runtimeIdentity", "target environment",
        ),
        loader_identity=_required_string(
            data, "loaderIdentity", "target environment",
        ),
        schema_version=_required_string(
            data, "schemaVersion", "target environment",
        ),
    )


def load_target_environment(path: str | Path) -> TargetEnvironment:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("target environment must be an object")
    return target_environment_from_dict(data)
