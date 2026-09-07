"""Replayable RV64GC/QEMU versus x86-64/native L1 differential runner."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import re
from typing import Callable, Mapping, Sequence

from .validation_case import (
    ComparisonContract, ValidationCase,
    generate_validation_inputs, load_validation_case,
)
from .validation_observation import CanonicalValue
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus


L1_RUNNER_SCHEMA = "riscv2x86.l1-differential-runner.v1"
L1_HARNESS_OUTPUT_SCHEMA = "riscv2x86.l1-harness-output.v1"
L1_COMPARISON_POLICY = "riscv2x86.l1-observable-comparison.v1"
ARCHITECTURAL_COMPARISON_POLICY = "riscv2x86.comparison-policy.architectural.v1"
L1_REPLAY_SCHEMA = "riscv2x86.l1-failure-replay.v1"
_SHA256_PREFIX = "sha256:"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _digest_bytes(value: bytes) -> str:
    return _SHA256_PREFIX + sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


@dataclass(frozen=True)
class L1RunnerConfig:
    case_paths: tuple[str, ...]
    source_path: str
    source_digest: str
    target_path: str
    target_digest: str
    source_compiler: str
    target_compiler: str
    source_flags: tuple[str, ...]
    target_flags: tuple[str, ...]
    qemu_binary: str
    qemu_sysroot: str
    work_directory: str
    replay_directory: str
    timeout_seconds: int
    schema_version: str = L1_RUNNER_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L1_RUNNER_SCHEMA or not self.case_paths:
            raise ValueError("L1 runner schema/cases are invalid")
        if tuple(sorted(set(self.case_paths))) != self.case_paths:
            raise ValueError("L1 case paths must be unique and sorted")
        if not all((self.source_path, self.target_path, self.source_compiler,
                    self.target_compiler, self.qemu_binary, self.work_directory,
                    self.replay_directory)):
            raise ValueError("L1 runner identity is incomplete")
        if not all(_SHA256.fullmatch(x) for x in (self.source_digest, self.target_digest)):
            raise ValueError("L1 source/target digests are invalid")
        if isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0:
            raise ValueError("L1 timeout is invalid")
        source_contract = " ".join((self.source_compiler, *self.source_flags)).lower()
        if not all(item in source_contract for item in ("riscv64", "rv64gc", "lp64d")):
            raise ValueError("L1 source compiler contract must target RV64GC/LP64D")
        if Path(self.qemu_binary).name != "qemu-riscv64":
            raise ValueError("initial L1 source runner must be qemu-riscv64")
        if Path(self.target_compiler).name not in {"gcc", "clang"}:
            raise ValueError("initial L1 target compiler must be GCC or Clang")


def load_l1_runner_config(value: Mapping[str, object]) -> L1RunnerConfig:
    expected = {"schemaVersion", "casePaths", "sourcePath", "sourceDigest", "targetPath",
                "targetDigest", "sourceCompiler", "targetCompiler", "sourceFlags", "targetFlags",
                "qemuBinary", "qemuSysroot", "workDirectory", "replayDirectory", "timeoutSeconds"}
    if set(value) != expected:
        raise ValueError("L1 runner fields are incomplete or unknown")
    def text(name: str, empty: bool = False) -> str:
        item = value.get(name)
        if not isinstance(item, str) or (not empty and not item):
            raise ValueError(name + " must be a string")
        return item
    def strings(name: str) -> tuple[str, ...]:
        item = value.get(name)
        if not isinstance(item, list) or not all(isinstance(x, str) and x for x in item):
            raise ValueError(name + " must be an array of strings")
        return tuple(item)
    timeout = value.get("timeoutSeconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ValueError("timeoutSeconds must be an integer")
    return L1RunnerConfig(
        strings("casePaths"), text("sourcePath"), text("sourceDigest"),
        text("targetPath"), text("targetDigest"), text("sourceCompiler"),
        text("targetCompiler"), strings("sourceFlags"), strings("targetFlags"),
        text("qemuBinary"), text("qemuSysroot", True), text("workDirectory"),
        text("replayDirectory"), timeout, text("schemaVersion"),
    )


@dataclass(frozen=True)
class HarnessObservation:
    return_value: CanonicalValue | None
    assertions: tuple[tuple[str, bool], ...]
    exported_state: tuple[tuple[str, CanonicalValue], ...]
    memory_objects: tuple[tuple[str, str], ...]
    api_results: tuple[tuple[str, CanonicalValue], ...]


@dataclass(frozen=True)
class ProcessObservation:
    harness: HarnessObservation
    exit_code: int
    stdout: str
    stderr: str
    files: tuple[tuple[str, str], ...]


def _named_values(raw: object, label: str) -> tuple[tuple[str, CanonicalValue], ...]:
    if not isinstance(raw, Mapping):
        raise ValueError(label + " must be an object")
    result = []
    for name, value in raw.items():
        if not isinstance(name, str) or not name or not isinstance(value, Mapping):
            raise ValueError(label + " entry is malformed")
        result.append((name, CanonicalValue.from_dict(value)))
    result.sort(key=lambda item: item[0])
    return tuple(result)


def parse_harness_observation(value: Mapping[str, object]) -> HarnessObservation:
    expected = {"schemaVersion", "testId", "inputIdentity", "returnValue", "assertions",
                "exportedState", "memoryObjects", "apiResults"}
    if set(value) != expected or value.get("schemaVersion") != L1_HARNESS_OUTPUT_SCHEMA:
        raise ValueError("L1 harness output schema/fields are invalid")
    if not isinstance(value.get("testId"), str) or not isinstance(value.get("inputIdentity"), str):
        raise ValueError("L1 harness output identity is invalid")
    ret = value.get("returnValue")
    if ret is not None and not isinstance(ret, Mapping):
        raise ValueError("returnValue must be null or a canonical value")
    assertions_raw = value.get("assertions")
    if not isinstance(assertions_raw, Mapping):
        raise ValueError("assertions must be an object")
    assertions = []
    for name, passed in assertions_raw.items():
        if not isinstance(name, str) or not name or not isinstance(passed, bool):
            raise ValueError("assertion result is malformed")
        assertions.append((name, passed))
    memory = value.get("memoryObjects")
    if not isinstance(memory, Mapping):
        raise ValueError("memoryObjects must be an object")
    memory_values = []
    for name, digest in memory.items():
        if not isinstance(name, str) or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("memory object observation is malformed")
        memory_values.append((name, digest))
    return HarnessObservation(
        CanonicalValue.from_dict(ret) if isinstance(ret, Mapping) else None,
        tuple(sorted(assertions)), _named_values(value.get("exportedState"), "exportedState"),
        tuple(sorted(memory_values)), _named_values(value.get("apiResults"), "apiResults"),
    )


def _select(mapping: tuple[tuple[str, object], ...], names: tuple[str, ...], label: str) -> tuple[tuple[str, object], ...]:
    values = dict(mapping)
    missing = set(names) - set(values)
    if missing:
        raise ValueError(label + " lacks declared observations: " + ",".join(sorted(missing)))
    return tuple((name, values[name]) for name in names)


def compare_l1_observations(
    source: ProcessObservation, target: ProcessObservation,
    contract: ComparisonContract,
) -> tuple[str, ...]:
    """Compare only explicitly declared architecture-independent observables."""
    mismatches = []
    if contract.return_value and source.harness.return_value != target.harness.return_value:
        mismatches.append("returnValue")
    if contract.exit_code and source.exit_code != target.exit_code:
        mismatches.append("exitCode")
    if contract.stdout and source.stdout != target.stdout:
        mismatches.append("stdout")
    if contract.stderr and source.stderr != target.stderr:
        mismatches.append("stderr")
    if contract.assertions:
        if source.harness.assertions != target.harness.assertions:
            mismatches.append("assertions")
        elif any(not passed for _, passed in source.harness.assertions):
            mismatches.append("assertions.failed")
    for label, left, right, names in (
        ("exportedState", source.harness.exported_state, target.harness.exported_state, contract.exported_state),
        ("memoryObjects", source.harness.memory_objects, target.harness.memory_objects, contract.memory_objects),
        ("apiResults", source.harness.api_results, target.harness.api_results, contract.api_results),
        ("externalFiles", source.files, target.files, contract.external_files),
    ):
        try:
            if _select(left, names, label) != _select(right, names, label):
                mismatches.append(label)
        except ValueError:
            mismatches.append(label + ".missing")
    return tuple(mismatches)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


CommandRunner = Callable[[Sequence[str], Path, int], CommandResult]


def _run(argv: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
    try:
        completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                                   check=False, timeout=timeout)
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(124, str(exc.stdout or ""), str(exc.stderr or ""), True)


def _execute(
    argv: tuple[str, ...], directory: Path, case: ValidationCase,
    input_payload: Mapping[str, object], timeout: int, runner: CommandRunner,
) -> ProcessObservation:
    directory.mkdir(parents=True, exist_ok=True)
    input_path, output_path = directory / "input.json", directory / "output.json"
    input_path.write_text(json.dumps(input_payload, sort_keys=True), encoding="utf-8")
    result = runner((*argv, str(input_path), str(output_path)), directory, timeout)
    if result.timed_out:
        raise RuntimeError("runner timeout")
    if not output_path.is_file():
        raise RuntimeError("runner did not produce L1 harness output")
    raw = json.loads(output_path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or raw.get("testId") != case.test_id or raw.get("inputIdentity") != input_payload["inputIdentity"]:
        raise RuntimeError("L1 harness output/input identity mismatch")
    files = []
    for relative in case.comparison.external_files:
        path = directory / relative
        if not path.is_file():
            raise RuntimeError("declared external file is missing: " + relative)
        files.append((relative, _digest_file(path)))
    return ProcessObservation(parse_harness_observation(raw), result.returncode,
                              result.stdout, result.stderr, tuple(files))


def _reidentify_input(payload: Mapping[str, object]) -> dict[str, object]:
    result = dict(payload)
    result.pop("inputIdentity", None)
    result["inputIdentity"] = _digest_bytes(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    )
    return result


def run_l1_differential(
    config: L1RunnerConfig, *, validation_plan: object,
    target_environment: Mapping[str, object], translation_artifact: object,
    source_program_artifact: object, target_program_artifact: object,
    comparison_policy: str,
    command_runner: CommandRunner = _run,
    tool_available: Callable[[str], bool] = lambda name: bool(shutil.which(name)),
) -> ValidationLayerResult:
    if comparison_policy not in {L1_COMPARISON_POLICY, ARCHITECTURAL_COMPARISON_POLICY}:
        return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                     detail="L1 comparison policy identity mismatch")
    if (getattr(validation_plan, "source_runner", None) != "qemu" or
            getattr(validation_plan, "target_runner", None) != "native"):
        return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.INCONCLUSIVE,
                                     detail="initial L1 runner requires qemu source and native target")
    if (target_environment.get("sourceIsa") != "rv64gc" or target_environment.get("sourceAbi") != "lp64d" or
            target_environment.get("targetIsa") != "x86_64" or target_environment.get("targetAbi") != "sysv_amd64"):
        return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.INCONCLUSIVE,
                                     detail="initial L1 environment must be RV64GC/LP64D to x86-64/SysV")
    tools = (config.source_compiler, config.target_compiler, config.qemu_binary)
    missing = tuple(name for name in tools if not tool_available(name))
    if missing:
        return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.INCONCLUSIVE,
                                     detail="L1 tools unavailable: " + ",".join(missing))
    work, replay = Path(config.work_directory), Path(config.replay_directory)
    work.mkdir(parents=True, exist_ok=True); replay.mkdir(parents=True, exist_ok=True)
    tool_versions = {}
    for tool in tools:
        version = command_runner((tool, "--version"), work, config.timeout_seconds)
        if version.timed_out or version.returncode or not (version.stdout or version.stderr).strip():
            return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.INCONCLUSIVE,
                                         detail="L1 tool identity unavailable: " + tool)
        resolved = shutil.which(tool)
        tool_versions[tool] = {
            "version": (version.stdout or version.stderr).splitlines()[0],
            "binaryDigest": _digest_file(Path(resolved)) if resolved else "unresolved-by-test-runner",
        }
    source_path, target_path = Path(config.source_path), Path(config.target_path)
    if (not source_path.is_file() or not target_path.is_file() or
            _digest_file(source_path) != config.source_digest or _digest_file(target_path) != config.target_digest):
        return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                     detail="L1 source/target input digest mismatch")
    source_exe, target_exe = work / "source-rv64", work / "target-x86_64"
    source_build = command_runner((config.source_compiler, *config.source_flags, str(source_path), "-o", str(source_exe)),
                                  work, config.timeout_seconds)
    target_build = command_runner((config.target_compiler, *config.target_flags, str(target_path), "-o", str(target_exe)),
                                  work, config.timeout_seconds)
    if source_build.timed_out or target_build.timed_out:
        return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.INCONCLUSIVE, detail="L1 compiler timeout")
    if source_build.returncode or target_build.returncode:
        return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                     detail="L1 harness compilation failed: " + source_build.stderr + target_build.stderr)
    source_argv = (config.qemu_binary, *(('-L', config.qemu_sysroot) if config.qemu_sysroot else ()), str(source_exe))
    target_argv = (str(target_exe),)
    evidence_cases = []
    for case_path in config.case_paths:
        case = load_validation_case(case_path)
        if case.execution_profile != "rv64gc-linux-user-v1":
            return ValidationLayerResult(
                ValidationLevel.L1, ValidationStatus.INCONCLUSIVE,
                detail="case requires a system-mode or privileged validation route",
            )
        if case.seed != getattr(validation_plan, "seed", None):
            return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                         detail="validation case seed does not match validation plan")
        for payload in generate_validation_inputs(case):
            try:
                ident = str(payload["caseIndex"])
                source = _execute(source_argv, work / case.test_id / (ident + "-source"), case,
                                  payload, config.timeout_seconds, command_runner)
                target = _execute(target_argv, work / case.test_id / (ident + "-target"), case,
                                  payload, config.timeout_seconds, command_runner)
                mismatches = compare_l1_observations(source, target, case.comparison)
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
                mismatches = ("runner:" + str(exc),)
            record = {"testId": case.test_id, "inputIdentity": payload["inputIdentity"],
                      "mismatches": list(mismatches)}
            evidence_cases.append(record)
            if mismatches:
                minimized = dict(payload)
                if not any(item.startswith("runner:") for item in mismatches):
                    arguments = dict(minimized.get("arguments", {}))
                    for name in sorted(arguments):
                        if arguments[name] == 0:
                            continue
                        candidate_arguments = dict(arguments); candidate_arguments[name] = 0
                        candidate = _reidentify_input({**minimized, "arguments": candidate_arguments})
                        try:
                            source_min = _execute(
                                source_argv, work / case.test_id / ("min-" + name + "-source"),
                                case, candidate, config.timeout_seconds, command_runner,
                            )
                            target_min = _execute(
                                target_argv, work / case.test_id / ("min-" + name + "-target"),
                                case, candidate, config.timeout_seconds, command_runner,
                            )
                            candidate_mismatches = compare_l1_observations(
                                source_min, target_min, case.comparison,
                            )
                        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                            candidate_mismatches = ()
                        if candidate_mismatches:
                            minimized, arguments, mismatches = candidate, candidate_arguments, candidate_mismatches
                replay_payload = {"schemaVersion": L1_REPLAY_SCHEMA,
                                  "comparisonPolicy": comparison_policy,
                                  "minimization": "greedy-zero-1minimal-v1",
                                  "input": minimized, "mismatches": list(mismatches)}
                replay_path = replay / (case.test_id + "-" + str(payload["caseIndex"]) + ".json")
                replay_path.write_text(json.dumps(replay_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                evidence = _digest_bytes(json.dumps(evidence_cases, sort_keys=True).encode())
                return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED, evidence,
                                             "L1 mismatch; replay=" + str(replay_path) + "; fields=" + ",".join(mismatches))
    evidence_payload = {"schemaVersion": L1_RUNNER_SCHEMA, "comparisonPolicy": comparison_policy,
                        "translationIdentity": getattr(translation_artifact, "identity", ""),
                        "sourceProgramDigest": getattr(source_program_artifact, "artifact_digest", ""),
                        "targetProgramDigest": getattr(target_program_artifact, "artifact_digest", ""),
                        "toolIdentities": tool_versions,
                        "cases": evidence_cases}
    evidence = _digest_bytes(json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode())
    return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.VERIFIED, evidence,
                                 "L1 functional observations match within the declared replayable input domain")


def build_l1_validator(config: L1RunnerConfig):
    def validator(**kwargs: object) -> ValidationLayerResult:
        if kwargs.get("level") is not ValidationLevel.L1:
            return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                         detail="L1 validator invoked for wrong level")
        return run_l1_differential(config, validation_plan=kwargs["validation_plan"],
                                   target_environment=kwargs["target_environment"],
                                   translation_artifact=kwargs["translation_artifact"],
                                   source_program_artifact=kwargs["source_program_artifact"],
                                   target_program_artifact=kwargs["target_program_artifact"],
                                   comparison_policy=kwargs["comparison_policy"])
    return validator
