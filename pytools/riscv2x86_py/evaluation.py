"""End-to-end, replayable evaluation orchestration for translation attempts."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from typing import Callable, Mapping, Sequence

from .candidate_materialization import (
    CandidateArtifactManifest, materialize_candidate_tree,
    verify_candidate_artifact_manifest,
)
from .schema import TranslationOutcome
from .translation_attempt import load_translation_attempt_archive
from .translation_artifact_binding import artifacts_from_report
from .translation_validation import (
    ProgramArtifact, TranslationValidationResult, load_target_environment,
    load_validation_plan, run_translation_validation,
    translation_artifact_from_dict,
)
from .validation_runtime_registry import validation_runtime_registry_from_dict
from .validation_status import ValidationStatus


LEGACY_EVALUATION_REQUEST_SCHEMA = "riscv2x86.evaluation-request.v1"
EVALUATION_REQUEST_SCHEMA = "riscv2x86.evaluation-request.v2"
LEGACY_EVALUATION_RESULT_SCHEMA = "riscv2x86.evaluation-result.v1"
EVALUATION_RESULT_SCHEMA = "riscv2x86.evaluation-result.v2"
EVALUATION_REPLAY_SCHEMA = "riscv2x86.evaluation-replay.v1"
TRANSLATION_EVALUATION_LINK_SCHEMA = "riscv2x86.translation-evaluation-link.v1"
_EMITTED = {
    TranslationOutcome.EMITTED, TranslationOutcome.STRENGTHENED,
    TranslationOutcome.FUNCTIONAL_FALLBACK,
}
_NON_CANDIDATE_STATUS = {
    TranslationOutcome.NEEDS_ROUTE: ValidationStatus.NEEDS_ROUTE,
    TranslationOutcome.UNSUPPORTED: ValidationStatus.UNSUPPORTED,
    TranslationOutcome.KEEP: ValidationStatus.KEEP,
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _safe_relative(value: str, label: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(label + " must be a safe relative path")
    return path.as_posix()


def _strings(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an array of non-empty strings")
    if not allow_empty and not value:
        raise ValueError(label + " must not be empty")
    return tuple(value)


@dataclass(frozen=True)
class BuildSpec:
    artifact_id: str
    artifact_kind: str
    output_relative_path: str
    command: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.artifact_id or self.artifact_kind not in {"object", "executable", "shared_library"}:
            raise ValueError("evaluation build artifact contract is invalid")
        _safe_relative(self.output_relative_path, "build output")
        if not self.command:
            raise ValueError("evaluation build command is empty")


@dataclass(frozen=True)
class EvaluationRequest:
    source_root: str
    source_relative_path: str
    target_relative_path: str
    translated_report: str
    attempt_archive: str
    validation_plan: str
    target_environment: str
    runtime_registry_template: Mapping[str, object]
    translation_artifacts: Mapping[str, Mapping[str, object]]
    source_build: BuildSpec
    target_build: BuildSpec
    translation_command: tuple[str, ...] = ()
    comparison_policy: str = "riscv2x86.comparison-policy.none.v1"
    validation_unit: str = "program"
    validation_group_id: str = ""
    selected_attempt_ids: tuple[str, ...] = ()
    schema_version: str = EVALUATION_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version not in {LEGACY_EVALUATION_REQUEST_SCHEMA, EVALUATION_REQUEST_SCHEMA}:
            raise ValueError("evaluation request schema is unsupported")
        for value, label in ((self.source_relative_path, "source path"),
                             (self.target_relative_path, "target path")):
            _safe_relative(value, label)
        if not self.source_root or not self.translated_report or not self.attempt_archive:
            raise ValueError("evaluation source/report/archive identity is incomplete")
        if not self.validation_plan or not self.target_environment or not self.comparison_policy:
            raise ValueError("evaluation validation contract is incomplete")
        if self.validation_unit not in {"program", "single_candidate", "group"}:
            raise ValueError("evaluation validation unit is unsupported")
        if self.selected_attempt_ids != tuple(sorted(set(self.selected_attempt_ids))):
            raise ValueError("evaluation selected attempts must be unique and sorted")
        if self.validation_unit == "program" and self.selected_attempt_ids:
            raise ValueError("program validation cannot select individual attempts")
        if self.validation_unit == "single_candidate" and len(self.selected_attempt_ids) != 1:
            raise ValueError("single-candidate validation requires exactly one attempt")
        if self.validation_unit == "group" and not self.selected_attempt_ids:
            raise ValueError("group validation requires selected attempts")
        if self.validation_unit != "program" and not self.validation_group_id:
            raise ValueError("candidate validation requires a group identity")


def _build_spec(value: object, label: str) -> BuildSpec:
    if not isinstance(value, Mapping) or set(value) != {
        "artifactId", "artifactKind", "outputRelativePath", "command",
    }:
        raise ValueError(label + " build spec fields are invalid")
    for name in ("artifactId", "artifactKind", "outputRelativePath"):
        if not isinstance(value.get(name), str):
            raise ValueError(label + " build spec strings are invalid")
    return BuildSpec(str(value["artifactId"]), str(value["artifactKind"]),
                     str(value["outputRelativePath"]), _strings(value["command"], label + ".command"))


def evaluation_request_from_dict(value: Mapping[str, object]) -> EvaluationRequest:
    fields = {
        "schemaVersion", "sourceRoot", "sourceRelativePath", "targetRelativePath",
        "translatedReport", "attemptArchive", "validationPlan", "targetEnvironment",
        "runtimeRegistryTemplate", "translationArtifacts", "sourceBuild", "targetBuild",
        "translationCommand", "comparisonPolicy",
    }
    grouping_fields = {"validationUnit", "validationGroupId", "selectedAttemptIds"}
    schema_version = value.get("schemaVersion")
    expected = (fields if schema_version == LEGACY_EVALUATION_REQUEST_SCHEMA else fields | grouping_fields)
    if schema_version not in {LEGACY_EVALUATION_REQUEST_SCHEMA, EVALUATION_REQUEST_SCHEMA} or set(value) != expected:
        raise ValueError("evaluation request fields are incomplete or unknown")
    registry, artifacts = value.get("runtimeRegistryTemplate"), value.get("translationArtifacts")
    if not isinstance(registry, Mapping) or not isinstance(artifacts, Mapping):
        raise ValueError("evaluation registry/artifact maps are invalid")
    artifact_map: dict[str, Mapping[str, object]] = {}
    for name, artifact in artifacts.items():
        if not isinstance(name, str) or not name or not isinstance(artifact, Mapping):
            raise ValueError("evaluation translation artifact entry is malformed")
        artifact_map[name] = artifact
    def text(name: str) -> str:
        item = value.get(name)
        if not isinstance(item, str):
            raise ValueError(name + " must be a string")
        return item
    selected = value.get("selectedAttemptIds", [])
    if not isinstance(selected, list) or not all(isinstance(item, str) and item for item in selected):
        raise ValueError("selectedAttemptIds must be an array of non-empty strings")
    return EvaluationRequest(
        text("sourceRoot"), text("sourceRelativePath"), text("targetRelativePath"),
        text("translatedReport"), text("attemptArchive"), text("validationPlan"),
        text("targetEnvironment"), registry, artifact_map,
        _build_spec(value.get("sourceBuild"), "source"),
        _build_spec(value.get("targetBuild"), "target"),
        _strings(value.get("translationCommand"), "translationCommand", allow_empty=True),
        text("comparisonPolicy"),
        str(value.get("validationUnit", "program")),
        str(value.get("validationGroupId", "")), tuple(selected),
        text("schemaVersion"),
    )


def load_evaluation_request(path: str | Path) -> EvaluationRequest:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("evaluation request root must be an object")
    return evaluation_request_from_dict(value)


@dataclass(frozen=True)
class CommandRecord:
    phase: str
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    status: ValidationStatus

    def to_dict(self) -> dict[str, object]:
        return {"phase": self.phase, "command": list(self.command), "returnCode": self.returncode,
                "stdout": self.stdout, "stderr": self.stderr, "timedOut": self.timed_out,
                "status": self.status.value}


CommandExecutor = Callable[[Sequence[str], Path, int], CommandRecord]


def _execute(command: Sequence[str], cwd: Path, timeout: int, phase: str) -> CommandRecord:
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True,
                                check=False, timeout=timeout)
        status = ValidationStatus.VERIFIED if result.returncode == 0 else ValidationStatus.FAILED
        return CommandRecord(phase, tuple(command), result.returncode, result.stdout, result.stderr, False, status)
    except FileNotFoundError as exc:
        return CommandRecord(phase, tuple(command), 127, "", str(exc), False, ValidationStatus.INCONCLUSIVE)
    except subprocess.TimeoutExpired as exc:
        return CommandRecord(phase, tuple(command), 124, str(exc.stdout or ""),
                             str(exc.stderr or ""), True, ValidationStatus.INCONCLUSIVE)


def _replace(value: object, variables: Mapping[str, str]) -> object:
    if isinstance(value, str):
        for name, replacement in variables.items():
            value = value.replace("${" + name + "}", replacement)
        unresolved = re.findall(r"\$\{[A-Z0-9_]+\}", value)
        if unresolved:
            raise ValueError("unresolved evaluation placeholder: " + unresolved[0])
        return value
    if isinstance(value, list):
        return [_replace(item, variables) for item in value]
    if isinstance(value, Mapping):
        return {key: _replace(item, variables) for key, item in value.items()}
    return value


def _path(value: str, base: Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _program(spec: BuildSpec, output: Path, record: CommandRecord) -> ProgramArtifact | None:
    if record.status is not ValidationStatus.VERIFIED or not output.is_file():
        return None
    digest = _digest_file(output)
    identity = _digest_bytes(_canonical({"command": list(record.command), "digest": digest}))
    return ProgramArtifact(spec.artifact_id, str(output), spec.artifact_kind, digest, identity)


def _overall(statuses: Sequence[ValidationStatus]) -> ValidationStatus:
    if any(item is ValidationStatus.FAILED for item in statuses):
        return ValidationStatus.FAILED
    if any(item is ValidationStatus.INCONCLUSIVE for item in statuses):
        return ValidationStatus.INCONCLUSIVE
    for status in (ValidationStatus.NEEDS_ROUTE, ValidationStatus.UNSUPPORTED,
                   ValidationStatus.KEEP, ValidationStatus.NOT_VERIFIED):
        if any(item is status for item in statuses):
            return status
    return ValidationStatus.VERIFIED


def _non_candidate_result(attempt: object) -> dict[str, object]:
    outcome = getattr(attempt, "translation_outcome")
    status = _NON_CANDIDATE_STATUS.get(outcome, ValidationStatus.INCONCLUSIVE)
    return _attempt_result(
        attempt, None, status,
        ("evaluation.translation-outcome-" + outcome.value.replace("_", "-"),),
    )


def _tool_version(executable: str) -> str:
    try:
        result = subprocess.run((executable, "--version"), text=True, capture_output=True,
                                check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    text = (result.stdout or result.stderr).splitlines()
    return text[0].strip() if text else "unavailable"


def _environment_provenance(
    request: EvaluationRequest, commands: Sequence[CommandRecord], environment: object | None,
) -> dict[str, object]:
    executables = sorted({item.command[0] for item in commands if item.command})
    cpu_model = "unavailable"
    microcode = "unavailable"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith(("model name", "hardware")) and ":" in line:
                cpu_model = line.split(":", 1)[1].strip()
            if line.lower().startswith("microcode") and ":" in line:
                microcode = line.split(":", 1)[1].strip()
            if cpu_model != "unavailable" and microcode != "unavailable":
                break
    except OSError:
        pass
    environment_payload = environment.to_dict() if environment is not None else {}
    return {
        "schemaVersion": "riscv2x86.environment-provenance.v1",
        "kernel": platform.release(), "platform": platform.platform(),
        "machine": platform.machine(), "cpuModel": cpu_model, "microcode": microcode,
        "toolVersions": {name: _tool_version(name) for name in executables},
        "runnerVersions": {
            "source": (_tool_version("qemu-riscv64")
                       if environment_payload.get("sourceRunnerCapabilities")
                       and "qemu" in environment_payload["sourceRunnerCapabilities"] else "custom-or-unavailable"),
            "target": platform.platform(),
        },
        "sourceBuildCommand": list(request.source_build.command),
        "targetBuildCommand": list(request.target_build.command),
        "runtimeIdentity": str(environment_payload.get("runtimeIdentity", "unavailable")),
        "loaderIdentity": str(environment_payload.get("loaderIdentity", "unavailable")),
        "containerImageDigest": os.environ.get("CONTAINER_IMAGE_DIGEST", "unavailable"),
    }


def run_evaluation(
    request: EvaluationRequest, *, work_directory: str | Path,
    command_executor: Callable[[Sequence[str], Path, int, str], CommandRecord] = _execute,
) -> dict[str, object]:
    """Translate, materialize, build and validate while retaining every outcome."""
    work = Path(work_directory).resolve()
    source_root = Path(request.source_root).resolve()
    if work.exists():
        raise ValueError("evaluation work directory already exists; refusing to overwrite")
    if not source_root.is_dir():
        raise ValueError("evaluation source root is unavailable")
    if work == source_root or source_root in work.parents or work in source_root.parents:
        raise ValueError("evaluation work directory and source root must not overlap")
    work.mkdir(parents=True)
    replay = work / "replay"
    replay.mkdir()
    plan = load_validation_plan(request.validation_plan)
    environment = load_target_environment(request.target_environment)
    variables = {"SOURCE_ROOT": str(source_root), "WORK_DIR": str(work),
                 "REPLAY_DIR": str(replay),
                 "TRANSLATED_REPORT": str(_path(request.translated_report, work)),
                 "ATTEMPT_ARCHIVE": str(_path(request.attempt_archive, work))}
    commands: list[CommandRecord] = []
    if request.translation_command:
        command = tuple(str(item) for item in _replace(list(request.translation_command), variables))
        record = command_executor(command, work, plan.timeout_seconds, "translation")
        commands.append(record)
        if record.status is not ValidationStatus.VERIFIED:
            return _result(request, work, commands, (), record.status,
                           ("evaluation.translation-command-not-verified",), None)

    report = _path(request.translated_report, work)
    archive_path = _path(request.attempt_archive, work)
    staging = work / "candidate-staging"
    candidate_manifest_path = work / "candidate-artifact-manifest.json"
    candidate_manifest = materialize_candidate_tree(
        source_root=source_root, staging_root=staging, translated_report=report,
        attempt_archive=archive_path, manifest_output=candidate_manifest_path,
        selected_attempt_ids=(request.selected_attempt_ids or None),
    )
    verify_candidate_artifact_manifest(
        candidate_manifest, source_root=source_root, staging_root=staging,
        translated_report=report, attempt_archive=archive_path,
    )
    source_path = source_root / request.source_relative_path
    target_path = staging / request.target_relative_path
    if not source_path.is_file() or not target_path.is_file():
        raise ValueError("evaluation source or materialized target source is missing")
    variables.update({
        "SOURCE_PATH": str(source_path), "TARGET_PATH": str(target_path),
        "SOURCE_DIGEST": _digest_file(source_path), "TARGET_DIGEST": _digest_file(target_path),
        "CANDIDATE_MANIFEST": str(candidate_manifest_path),
        "CANDIDATE_MANIFEST_ID": candidate_manifest.manifest_id,
    })
    archive = load_translation_attempt_archive(archive_path)
    attributable_archive = tuple(
        item for item in archive.attempts
        if not request.selected_attempt_ids or item.artifact_id in request.selected_attempt_ids
    )
    emitted_archive = tuple(
        item for item in attributable_archive if item.translation_outcome in _EMITTED
    )
    programs = []
    build_specs = [("source-build", request.source_build)]
    if emitted_archive:
        build_specs.append(("target-build", request.target_build))
    for phase, spec in build_specs:
        output = work / _safe_relative(spec.output_relative_path, phase + " output")
        output.parent.mkdir(parents=True, exist_ok=True)
        local = dict(variables); local["OUTPUT"] = str(output)
        command = tuple(str(item) for item in _replace(list(spec.command), local))
        record = command_executor(command, work, plan.timeout_seconds, phase)
        if record.status is ValidationStatus.VERIFIED and not output.is_file():
            record = CommandRecord(phase, command, record.returncode, record.stdout,
                                   record.stderr + "\nbuild output is missing", False, ValidationStatus.FAILED)
        commands.append(record)
        programs.append(_program(spec, output, record))
        variables[("SOURCE" if phase == "source-build" else "TARGET") + "_ARTIFACT_PATH"] = str(output)
        if programs[-1] is not None:
            variables[("SOURCE" if phase == "source-build" else "TARGET") + "_ARTIFACT_DIGEST"] = programs[-1].artifact_digest
    source_record = next(item for item in commands if item.phase == "source-build")
    target_record = next((item for item in commands if item.phase == "target-build"), None)
    if not emitted_archive:
        per_attempt = tuple(
            _non_candidate_result(item)
            if item in attributable_archive else _attempt_result(
                item, None, ValidationStatus.INCONCLUSIVE,
                ("evaluation.attempt-not-in-validation-group",),
            )
            for item in archive.attempts
        )
        attributable = [item for item in per_attempt if not request.selected_attempt_ids
                        or item["attemptArtifactId"] in request.selected_attempt_ids]
        status = _overall(tuple(ValidationStatus(item["status"]) for item in attributable))
        reasons = tuple(sorted({reason for item in attributable for reason in item["reasonCodes"]}))
        if source_record.status is not ValidationStatus.VERIFIED:
            status = source_record.status
            reasons = tuple(sorted(set(reasons) | {"evaluation.source-build-not-verified"}))
        return _result(
            request, work, commands, per_attempt, status, reasons, candidate_manifest,
            plan=plan, environment=environment,
            source_program=programs[0] if programs else None, target_program=None,
        )
    missing_artifact_ids = {
        item.finding_id for item in archive.attempts
        if item.translation_outcome in _EMITTED
        and item.finding_id not in request.translation_artifacts
    }
    derived_artifacts = artifacts_from_report(
        report, archive, finding_ids=missing_artifact_ids,
    ) if missing_artifact_ids else {}
    build_status = _overall(tuple(item.status for item in commands if item.phase.endswith("build")))
    if build_status is not ValidationStatus.VERIFIED:
        if source_record.status is not ValidationStatus.VERIFIED:
            reason = "evaluation.source-build-not-verified"
            failing_status = source_record.status
        else:
            assert target_record is not None
            reason = ("evaluation.target-build-failed"
                      if target_record.status is ValidationStatus.FAILED
                      else "evaluation.target-build-inconclusive")
            failing_status = target_record.status
        attempts = tuple(
            _attempt_result(item, None, failing_status, (reason,))
            if item.translation_outcome in _EMITTED else _non_candidate_result(item)
            for item in archive.attempts
        )
        return _result(request, work, commands, attempts, build_status,
                       (reason,), candidate_manifest, plan=plan, environment=environment,
                       source_program=programs[0] if programs else None,
                       target_program=programs[1] if len(programs) > 1 else None)
    source_program, target_program = programs
    assert source_program is not None and target_program is not None
    per_attempt = []
    for attempt in archive.attempts:
        if (request.selected_attempt_ids
                and attempt.artifact_id not in request.selected_attempt_ids):
            per_attempt.append(_attempt_result(
                attempt, None, ValidationStatus.INCONCLUSIVE,
                ("evaluation.attempt-not-in-validation-group",),
            ))
            continue
        if attempt.translation_outcome not in _EMITTED:
            per_attempt.append(_attempt_result(
                attempt, None, ValidationStatus.INCONCLUSIVE,
                ("evaluation.translation-outcome-not-emitted",),
            ))
            continue
        raw_artifact = request.translation_artifacts.get(attempt.finding_id)
        if raw_artifact is None and attempt.finding_id not in derived_artifacts:
            per_attempt.append(_attempt_result(
                attempt, None, ValidationStatus.INCONCLUSIVE,
                ("evaluation.translation-artifact-missing",),
            ))
            continue
        translation = (derived_artifacts[attempt.finding_id]
                       if raw_artifact is None
                       else translation_artifact_from_dict(raw_artifact))
        if translation.fragment_id != attempt.fragment_id:
            per_attempt.append(_attempt_result(
                attempt, None, ValidationStatus.FAILED,
                ("evaluation.translation-artifact-fragment-mismatch",),
            ))
            continue
        attempt_variables = dict(variables)
        attempt_variables.update({"ATTEMPT_ID": attempt.artifact_id,
                                  "TRANSLATION_ID": translation.identity})
        registry_replay = replay / (attempt.artifact_id.replace(":", "-") + "-registry.json")
        try:
            registry_payload = _replace(request.runtime_registry_template, attempt_variables)
            if not isinstance(registry_payload, Mapping):
                raise ValueError("resolved runtime registry is malformed")
            registry_replay.write_text(json.dumps(registry_payload, indent=2, sort_keys=True) + "\n")
            registry = validation_runtime_registry_from_dict(registry_payload)
            validation = run_translation_validation(
                translation, source_program, target_program, plan, environment, registry,
                comparison_policy=request.comparison_policy,
            )
            per_attempt.append(_attempt_result(attempt, validation, validation.status,
                                               validation.reason_codes,
                                               (str(registry_replay.relative_to(work)),),
                                               translation))
        except Exception as exc:
            failure = replay / (attempt.artifact_id.replace(":", "-") + "-failure.json")
            failure.write_text(json.dumps({
                "schemaVersion": EVALUATION_REPLAY_SCHEMA,
                "attemptArtifactId": attempt.artifact_id,
                "errorType": type(exc).__name__, "detail": str(exc),
            }, indent=2, sort_keys=True) + "\n")
            per_attempt.append(_attempt_result(
                attempt, None, ValidationStatus.INCONCLUSIVE,
                ("evaluation.attempt-validation-error",),
                (str(failure.relative_to(work)),),
            ))
    attributable = [item for item in per_attempt if not request.selected_attempt_ids
                    or item["attemptArtifactId"] in request.selected_attempt_ids]
    overall = _overall(tuple(ValidationStatus(item["status"]) for item in attributable))
    reasons = tuple(sorted(set(reason for item in attributable for reason in item["reasonCodes"])))
    return _result(
        request, work, commands, tuple(per_attempt), overall, reasons, candidate_manifest,
        plan=plan, environment=environment,
        source_program=source_program, target_program=target_program,
    )


def _attempt_result(attempt: object, validation: TranslationValidationResult | None,
                    status: ValidationStatus, reasons: Sequence[str],
                    replay_artifacts: Sequence[str] = (),
                    translation: object | None = None) -> dict[str, object]:
    return {
        "findingId": getattr(attempt, "finding_id"),
        "fragmentId": getattr(attempt, "fragment_id"),
        "attemptArtifactId": getattr(attempt, "artifact_id"),
        "translationOutcome": getattr(attempt, "translation_outcome").value,
        "status": status.value,
        "validation": None if validation is None else validation.to_dict(),
        "translationArtifact": None if translation is None else {
            "fragment_id": translation.fragment_id,
            "source_model_identity": translation.source_model_identity,
            "translation_plan_id": translation.translation_plan_id,
            "constraint_id": translation.constraint_id,
            "proof_identity": translation.proof_identity,
            "preservation_mode": translation.preservation_mode.value,
            "shell_facts_identity": translation.shell_facts_identity,
            "runtime_contract_id": translation.runtime_contract_id,
            "runtime_contract_version": translation.runtime_contract_version,
            "recipe_id": translation.recipe_id,
            "ignored_source_state": list(translation.ignored_source_state),
            "semantic_class": translation.semantic_class,
            "target_route": translation.target_route,
        },
        "reasonCodes": list(sorted(set(reasons))),
        "replayArtifacts": list(replay_artifacts),
    }


def _request_identity(request: EvaluationRequest) -> str:
    payload = {
        "schemaVersion": request.schema_version, "sourceRoot": request.source_root,
        "sourceRelativePath": request.source_relative_path,
        "targetRelativePath": request.target_relative_path,
        "translatedReport": request.translated_report, "attemptArchive": request.attempt_archive,
        "validationPlan": request.validation_plan, "targetEnvironment": request.target_environment,
        "runtimeRegistryTemplate": request.runtime_registry_template,
        "translationArtifacts": request.translation_artifacts,
        "sourceBuild": request.source_build.__dict__, "targetBuild": request.target_build.__dict__,
        "translationCommand": list(request.translation_command),
        "comparisonPolicy": request.comparison_policy,
        "validationUnit": request.validation_unit,
        "validationGroupId": request.validation_group_id,
        "selectedAttemptIds": list(request.selected_attempt_ids),
    }
    return _digest_bytes(_canonical(payload))


def _result(request: EvaluationRequest, work: Path, commands: Sequence[CommandRecord],
            attempts: Sequence[Mapping[str, object]], status: ValidationStatus,
            reasons: Sequence[str], manifest: CandidateArtifactManifest | None, *,
            plan: object | None = None, environment: object | None = None,
            source_program: ProgramArtifact | None = None,
            target_program: ProgramArtifact | None = None) -> dict[str, object]:
    def program(value: ProgramArtifact | None) -> object:
        return None if value is None else {
            "artifact_id": value.artifact_id, "artifact_path": value.artifact_path,
            "artifact_kind": value.artifact_kind, "artifact_digest": value.artifact_digest,
            "build_identity": value.build_identity,
        }
    linkage = _translation_evaluation_linkage(request, work, attempts)
    payload: dict[str, object] = {
        "schemaVersion": EVALUATION_RESULT_SCHEMA,
        "requestIdentity": _request_identity(request), "status": status.value,
        "reasonCodes": list(sorted(set(reasons))),
        "candidateManifestId": "" if manifest is None else manifest.manifest_id,
        "attempts": list(attempts), "commands": [item.to_dict() for item in commands],
        "replayArtifact": "replay/evaluation-replay.json",
        "validationPlan": None if plan is None else {
            "schemaVersion": plan.schema_version, "planId": plan.plan_id,
            "profile": plan.profile.value, "sourceRunner": plan.source_runner,
            "targetRunner": plan.target_runner, "seed": plan.seed,
            "timeoutSeconds": plan.timeout_seconds,
            "runtimeRegistryVersion": plan.runtime_registry_version,
            "experimentContractId": plan.experiment_contract_id,
        },
        "targetEnvironment": None if environment is None else environment.to_dict(),
        "sourceProgramArtifact": program(source_program),
        "targetProgramArtifact": program(target_program),
        "comparisonPolicy": request.comparison_policy,
        "validationUnit": request.validation_unit,
        "validationGroupId": request.validation_group_id,
        "selectedAttemptIds": list(request.selected_attempt_ids),
        "environmentProvenance": _environment_provenance(request, commands, environment),
        "translationEvaluationLink": linkage,
    }
    identity_payload = dict(payload); identity_payload.pop("replayArtifact")
    payload["evaluationIdentity"] = _digest_bytes(_canonical(identity_payload))
    replay_payload = {
        "schemaVersion": EVALUATION_REPLAY_SCHEMA,
        "requestIdentity": payload["requestIdentity"],
        "evaluationIdentity": payload["evaluationIdentity"],
        "commands": payload["commands"], "attempts": payload["attempts"],
        "candidateManifestId": payload["candidateManifestId"],
    }
    replay = work / "replay"
    replay.mkdir(exist_ok=True)
    (replay / "evaluation-replay.json").write_text(
        json.dumps(replay_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return payload


def _translation_evaluation_linkage(
    request: EvaluationRequest, work: Path, attempts: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Bind immutable translation-stage facts to final evaluation outcomes.

    The translated report remains historical evidence.  This joined view is
    the authoritative place to read the later L0-L3 result and avoids
    rewriting a translation-stage ``verificationDetail`` after the fact.
    """
    report_path = _path(request.translated_report, work)
    archive_path = _path(request.attempt_archive, work)
    final_by_finding = {
        str(item.get("findingId")): item for item in attempts
        if isinstance(item.get("findingId"), str)
    }
    findings: list[dict[str, object]] = []
    raw: object = {}
    if report_path.is_file():
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    report_findings = raw.get("findings", []) if isinstance(raw, Mapping) else []
    if isinstance(report_findings, list):
        for index, finding in enumerate(report_findings):
            if not isinstance(finding, Mapping):
                continue
            fragment = finding.get("fragment")
            fragment_id = (
                str(fragment.get("id", "")) if isinstance(fragment, Mapping) else ""
            )
            finding_id = f"finding:{index}:{fragment_id}"
            final = final_by_finding.get(finding_id, {})
            validation = final.get("validation") if isinstance(final, Mapping) else None
            completed = (
                validation.get("completedLevels", [])
                if isinstance(validation, Mapping) else []
            )
            layers = validation.get("layers", []) if isinstance(validation, Mapping) else []
            level_status = {
                str(layer.get("level")): str(layer.get("status", "inconclusive"))
                for layer in layers
                if isinstance(layer, Mapping) and isinstance(layer.get("level"), str)
            }
            for level in ("L0", "L1", "L2", "L3"):
                level_status.setdefault(level, "not_run")
            findings.append({
                "findingId": finding_id,
                "fragmentId": fragment_id,
                "translationOutcome": finding.get("translationOutcome", ""),
                "translationKind": finding.get("translationKind", ""),
                "translationStageVerificationStatus": finding.get("verificationStatus", ""),
                "translationStageVerificationDetail": finding.get("verificationDetail", ""),
                "candidateArchived": bool(
                    isinstance(final, Mapping)
                    and final.get("translationOutcome") in {
                        "emitted", "strengthened", "functional_fallback"
                    }
                ),
                "publicationReplacementPresent": bool(finding.get("suggestedReplacement")),
                "finalEvaluationStatus": final.get("status", "not_run"),
                "completedLevels": completed,
                "levelStatus": level_status,
                "validationProfile": (
                    validation.get("profile", "")
                    if isinstance(validation, Mapping) else ""
                ),
                "validationIdentity": (
                    validation.get("validationIdentity", "")
                    if isinstance(validation, Mapping) else ""
                ),
                "reasonCodes": final.get("reasonCodes", []),
            })
    return {
        "schemaVersion": TRANSLATION_EVALUATION_LINK_SCHEMA,
        "translatedReportPath": request.translated_report,
        "translatedReportDigest": _digest_file(report_path) if report_path.is_file() else "",
        "attemptArchivePath": request.attempt_archive,
        "attemptArchiveDigest": _digest_file(archive_path) if archive_path.is_file() else "",
        "findings": findings,
    }


def persist_evaluation_result(result: Mapping[str, object], output: str | Path) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(destination)
