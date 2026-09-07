"""Contract-driven L3 validation without cross-ISA hardware-state equality."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import math
from pathlib import Path
import random
import re
import shutil
import statistics
import subprocess
from typing import Callable, Mapping, Sequence

from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .l2_concurrency_runner import (
    L2ConcurrencyRunnerConfig, load_l2_concurrency_runner_config,
    run_l2_concurrency_differential,
)
from .l2_effect_trace_differential import (
    L2EffectRunnerConfig, load_l2_effect_runner_config,
    run_l2_effect_trace_differential,
)
from .translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
from .validation_status import ValidationStatus


EXPERIMENT_CONTRACT_SCHEMA = "riscv2x86.microarchitecture-experiment-contract.v1"
EXPERIMENT_RUNNER_SCHEMA = "riscv2x86.l3-experiment-runner.v1"
EXPERIMENT_REPORT_SCHEMA = "riscv2x86.l3-experiment-report.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRESERVATION = {
    "microarchitecture_intent_preserved", "microarchitecture_strengthened", "best_effort",
}
_EXPERIMENT_CLASSES = {"memory_access", "control_flow", "statistical"}
_METHODS = {"bootstrap_median_effect_v1", "mean_effect_ci_v1"}
_DIRECTIONS = {"increase", "decrease", "nonzero"}
_ENV_FIELDS = {"cpuModel", "microcode", "kernel", "emulator", "emulatorArguments", "governor",
               "turbo", "cpuAffinity", "numaNode", "pageSize", "aslr"}


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(raw.encode()).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(label + " fields are incomplete or unknown")


def _string(value: Mapping[str, object], name: str, label: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{label}.{name} must be a non-empty string")
    return item


def _integer(value: Mapping[str, object], name: str, label: str, *, minimum: int = 0) -> int:
    item = value.get(name)
    if isinstance(item, bool) or not isinstance(item, int) or item < minimum:
        raise ValueError(f"{label}.{name} must be an integer >= {minimum}")
    return item


def _number(value: Mapping[str, object], name: str, label: str) -> float:
    item = value.get(name)
    if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item):
        raise ValueError(f"{label}.{name} must be a finite number")
    return float(item)


def _strings(value: object, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (nonempty and not value) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(label + " must be a canonical string array")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ValueError(label + " must be unique and sorted")
    return result


@dataclass(frozen=True)
class LogicalAccess:
    event_id: str
    object_id: str
    offset: int
    size: int
    access: str
    alignment: int
    atomicity: str
    required_ordering: str
    ordering_predecessors: tuple[str, ...]


@dataclass(frozen=True)
class LogicalControlEvent:
    event_id: str
    kind: str
    subject: str
    outcome: str
    ordering_predecessors: tuple[str, ...]


@dataclass(frozen=True)
class MetricContract:
    metric_id: str
    source_metric: str
    target_metric: str
    observation_domain: str
    statistical_test: str
    direction: str
    minimum_absolute_effect_size: float
    confidence_level: float


@dataclass(frozen=True)
class ExperimentContract:
    experiment_id: str
    translation_plan_id: str
    proof_identity: str
    source_intent: str
    target_strategy: str
    strategy_registration_id: str
    preservation_level: str
    experiment_classes: tuple[str, ...]
    required_access_pattern: tuple[LogicalAccess, ...]
    approved_extra_accesses: tuple[str, ...]
    required_control_flow: tuple[LogicalControlEvent, ...]
    required_sync_semantics: tuple[str, ...]
    metrics: tuple[MetricContract, ...]
    calibration_protocol: str
    sample_count: int
    warmup_count: int
    random_seed: int
    affinity_policy: str
    noise_policy: str
    source_environment_requirements: Mapping[str, object]
    target_environment_requirements: Mapping[str, object]
    known_non_equivalences: tuple[str, ...]
    complete: bool
    payload: Mapping[str, object]

    @property
    def identity(self) -> str:
        return _digest(self.payload)

    def __post_init__(self) -> None:
        if not self.experiment_id or not self.translation_plan_id or not _SHA256.fullmatch(self.proof_identity):
            raise ValueError("experiment identity is incomplete")
        if self.preservation_level not in _PRESERVATION or not self.strategy_registration_id:
            raise ValueError("preservation/target strategy registration is invalid")
        if set(self.experiment_classes) - _EXPERIMENT_CLASSES or not self.experiment_classes:
            raise ValueError("experiment classes are invalid")
        if self.experiment_classes != tuple(sorted(set(self.experiment_classes))):
            raise ValueError("experiment classes must be canonical")
        if "memory_access" in self.experiment_classes and not self.required_access_pattern:
            raise ValueError("memory-access experiment requires a logical access pattern")
        if "control_flow" in self.experiment_classes and not self.required_control_flow:
            raise ValueError("control-flow experiment requires logical control events")
        if "statistical" in self.experiment_classes and not self.metrics:
            raise ValueError("statistical experiment requires metrics")
        if self.sample_count <= 1 or self.warmup_count < 0 or not self.complete:
            raise ValueError("sample/warmup/complete contract is invalid")


@dataclass(frozen=True)
class ExperimentRunnerConfig:
    base_l2_kind: str
    base_concurrency_config: L2ConcurrencyRunnerConfig | None
    base_effect_config: L2EffectRunnerConfig | None
    contract_path: str
    contract_digest: str
    source_runner_id: str
    target_runner_id: str
    source_command: tuple[str, ...]
    target_command: tuple[str, ...]
    timeout_seconds: int
    comparison_policy: str = ARCHITECTURAL_COMPARISON_POLICY
    schema_version: str = EXPERIMENT_RUNNER_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != EXPERIMENT_RUNNER_SCHEMA or self.comparison_policy != ARCHITECTURAL_COMPARISON_POLICY:
            raise ValueError("L3 runner schema/policy is invalid")
        if self.base_l2_kind not in {"concurrency", "effect"}:
            raise ValueError("L3 base L2 kind is invalid")
        if (self.base_l2_kind == "concurrency") != (self.base_concurrency_config is not None):
            raise ValueError("L3 concurrency base configuration is inconsistent")
        if (self.base_l2_kind == "effect") != (self.base_effect_config is not None):
            raise ValueError("L3 effect base configuration is inconsistent")
        if not _SHA256.fullmatch(self.contract_digest) or self.timeout_seconds <= 0:
            raise ValueError("L3 contract digest/timeout is invalid")
        if not self.source_runner_id or not self.target_runner_id or not self.source_command or not self.target_command:
            raise ValueError("L3 runner identity/commands are incomplete")


@dataclass(frozen=True)
class PlatformReport:
    side: str
    runner_id: str
    contract_identity: str
    calibration_protocol: str
    random_seed: int
    affinity_policy: str
    noise_policy: str
    warmups_completed: int
    environment: Mapping[str, object]
    logical_accesses: tuple[LogicalAccess, ...]
    control_flow: tuple[LogicalControlEvent, ...]
    sync_observations: tuple[str, ...]
    metric_samples: Mapping[str, tuple[tuple[float, ...], tuple[float, ...]]]

    @property
    def identity(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


CommandRunner = Callable[[Sequence[str], str, int], CommandResult]


def _parse_access(raw: Mapping[str, object], label: str) -> LogicalAccess:
    _fields(raw, {"eventId", "objectId", "offset", "size", "access", "alignment", "atomicity",
                  "requiredOrdering", "orderingPredecessors"}, label)
    access = _string(raw, "access", label)
    if access not in {"read", "write", "read_write"}:
        raise ValueError(label + ".access is invalid")
    return LogicalAccess(
        _string(raw, "eventId", label), _string(raw, "objectId", label),
        _integer(raw, "offset", label), _integer(raw, "size", label, minimum=1), access,
        _integer(raw, "alignment", label, minimum=1), _string(raw, "atomicity", label),
        _string(raw, "requiredOrdering", label),
        _strings(raw.get("orderingPredecessors"), label + ".orderingPredecessors"),
    )


def _parse_control(raw: Mapping[str, object], label: str) -> LogicalControlEvent:
    _fields(raw, {"eventId", "kind", "subject", "outcome", "orderingPredecessors"}, label)
    return LogicalControlEvent(
        _string(raw, "eventId", label), _string(raw, "kind", label),
        _string(raw, "subject", label), _string(raw, "outcome", label),
        _strings(raw.get("orderingPredecessors"), label + ".orderingPredecessors"),
    )


def _parse_array(value: object, parser: Callable[[Mapping[str, object], str], object], label: str) -> tuple:
    if not isinstance(value, list):
        raise ValueError(label + " must be an array")
    result = []
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping):
            raise ValueError(label + " item must be an object")
        result.append(parser(raw, f"{label}[{index}]"))
    ids = tuple(getattr(item, "event_id") for item in result)
    if ids != tuple(sorted(set(ids))):
        raise ValueError(label + " event IDs must be unique and sorted")
    known = set(ids)
    if any(not set(getattr(item, "ordering_predecessors")) <= known for item in result):
        raise ValueError(label + " has unknown ordering predecessor")
    graph = {item.event_id: item.ordering_predecessors for item in result}
    visiting, visited = set(), set()
    def visit(event_id: str) -> None:
        if event_id in visiting:
            raise ValueError(label + " partial order contains a cycle")
        if event_id in visited:
            return
        visiting.add(event_id)
        for predecessor in graph[event_id]:
            visit(predecessor)
        visiting.remove(event_id)
        visited.add(event_id)
    for event_id in graph:
        visit(event_id)
    return tuple(result)


def load_experiment_contract(path: str | Path) -> ExperimentContract:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("experiment contract must be an object")
    fields = {"schemaVersion", "experimentId", "translationPlanId", "proofIdentity", "sourceIntent",
              "targetStrategy", "strategyRegistrationId", "preservationLevel", "experimentClasses",
              "requiredAccessPattern", "approvedExtraAccesses", "requiredControlFlow",
              "requiredSyncSemantics", "metrics", "calibrationProtocol", "sampleCount", "warmupCount",
              "randomSeed", "affinityPolicy", "noisePolicy", "sourceEnvironmentRequirements",
              "targetEnvironmentRequirements", "knownNonEquivalences", "complete"}
    _fields(value, fields, "experiment contract")
    if value.get("schemaVersion") != EXPERIMENT_CONTRACT_SCHEMA:
        raise ValueError("experiment contract schema unsupported")
    raw_metrics = value.get("metrics")
    if not isinstance(raw_metrics, list):
        raise ValueError("metrics must be an array")
    metrics = []
    for index, raw in enumerate(raw_metrics):
        if not isinstance(raw, Mapping):
            raise ValueError("metric must be an object")
        label = f"metrics[{index}]"
        _fields(raw, {"metricId", "sourceMetric", "targetMetric", "observationDomain", "statisticalTest",
                      "acceptanceCriteria"}, label)
        criteria = raw.get("acceptanceCriteria")
        if not isinstance(criteria, Mapping):
            raise ValueError(label + ".acceptanceCriteria must be an object")
        _fields(criteria, {"direction", "minimumAbsoluteEffectSize", "confidenceLevel"}, label + ".acceptanceCriteria")
        method = _string(raw, "statisticalTest", label)
        direction = _string(criteria, "direction", label + ".acceptanceCriteria")
        confidence = _number(criteria, "confidenceLevel", label + ".acceptanceCriteria")
        if method not in _METHODS or direction not in _DIRECTIONS or not 0.5 < confidence < 1:
            raise ValueError(label + " statistical declaration is invalid")
        metrics.append(MetricContract(
            _string(raw, "metricId", label), _string(raw, "sourceMetric", label),
            _string(raw, "targetMetric", label), _string(raw, "observationDomain", label), method,
            direction, _number(criteria, "minimumAbsoluteEffectSize", label + ".acceptanceCriteria"), confidence,
        ))
    metric_ids = tuple(item.metric_id for item in metrics)
    if metric_ids != tuple(sorted(set(metric_ids))):
        raise ValueError("metric IDs must be unique and sorted")
    source_env, target_env = value.get("sourceEnvironmentRequirements"), value.get("targetEnvironmentRequirements")
    if not isinstance(source_env, Mapping) or not isinstance(target_env, Mapping):
        raise ValueError("environment requirements must be objects")
    if not set(source_env) <= _ENV_FIELDS or not set(target_env) <= _ENV_FIELDS:
        raise ValueError("environment requirement fields are unknown")
    complete = value.get("complete")
    if not isinstance(complete, bool):
        raise ValueError("complete must be boolean")
    return ExperimentContract(
        _string(value, "experimentId", "contract"), _string(value, "translationPlanId", "contract"),
        _string(value, "proofIdentity", "contract"), _string(value, "sourceIntent", "contract"),
        _string(value, "targetStrategy", "contract"), _string(value, "strategyRegistrationId", "contract"),
        _string(value, "preservationLevel", "contract"),
        _strings(value.get("experimentClasses"), "experimentClasses", nonempty=True),
        _parse_array(value.get("requiredAccessPattern"), _parse_access, "requiredAccessPattern"),
        _strings(value.get("approvedExtraAccesses"), "approvedExtraAccesses"),
        _parse_array(value.get("requiredControlFlow"), _parse_control, "requiredControlFlow"),
        _strings(value.get("requiredSyncSemantics"), "requiredSyncSemantics"), tuple(metrics),
        _string(value, "calibrationProtocol", "contract"), _integer(value, "sampleCount", "contract", minimum=2),
        _integer(value, "warmupCount", "contract"), _integer(value, "randomSeed", "contract"),
        _string(value, "affinityPolicy", "contract"), _string(value, "noisePolicy", "contract"),
        dict(source_env), dict(target_env),
        _strings(value.get("knownNonEquivalences"), "knownNonEquivalences", nonempty=True),
        complete, dict(value),
    )


def _command(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
        raise ValueError(label + " must be a non-empty command array")
    return tuple(value)


def load_l3_experiment_runner_config(value: Mapping[str, object]) -> ExperimentRunnerConfig:
    _fields(value, {"schemaVersion", "comparisonPolicy", "baseL2Kind", "baseL2Runner", "contractPath",
                    "contractDigest", "sourceRunnerId", "targetRunnerId", "sourceCommand", "targetCommand",
                    "timeoutSeconds"}, "L3 runner")
    base_kind = _string(value, "baseL2Kind", "runner")
    base = value.get("baseL2Runner")
    if not isinstance(base, Mapping):
        raise ValueError("baseL2Runner must be an object")
    return ExperimentRunnerConfig(
        base_kind,
        load_l2_concurrency_runner_config(base) if base_kind == "concurrency" else None,
        load_l2_effect_runner_config(base) if base_kind == "effect" else None,
        _string(value, "contractPath", "runner"), _string(value, "contractDigest", "runner"),
        _string(value, "sourceRunnerId", "runner"), _string(value, "targetRunnerId", "runner"),
        _command(value.get("sourceCommand"), "sourceCommand"),
        _command(value.get("targetCommand"), "targetCommand"),
        _integer(value, "timeoutSeconds", "runner", minimum=1),
        _string(value, "comparisonPolicy", "runner"), _string(value, "schemaVersion", "runner"),
    )


def parse_platform_report(value: Mapping[str, object], *, side: str, runner_id: str,
                          contract: ExperimentContract) -> PlatformReport:
    _fields(value, {"schemaVersion", "side", "runnerId", "contractIdentity", "calibrationProtocol",
                    "randomSeed", "affinityPolicy", "noisePolicy",
                    "warmupsCompleted", "environment", "logicalAccesses", "controlFlow",
                    "syncObservations", "metricSamples"}, "L3 report")
    if value.get("schemaVersion") != EXPERIMENT_REPORT_SCHEMA:
        raise ValueError("L3 report schema unsupported")
    if (_string(value, "side", "report") != side or _string(value, "runnerId", "report") != runner_id or
            _string(value, "contractIdentity", "report") != contract.identity):
        raise ValueError("L3 report side/runner/contract binding mismatch")
    environment = value.get("environment")
    if not isinstance(environment, Mapping) or set(environment) != _ENV_FIELDS:
        raise ValueError("L3 environment fields are incomplete or unknown")
    if not all(isinstance(x, (str, int, bool)) and not (isinstance(x, str) and not x) for x in environment.values()):
        raise ValueError("L3 environment values are invalid")
    raw_samples = value.get("metricSamples")
    if not isinstance(raw_samples, Mapping) or tuple(raw_samples) != tuple(sorted(raw_samples)):
        raise ValueError("metricSamples must be a sorted object")
    samples = {}
    for metric_id, raw in raw_samples.items():
        if not isinstance(raw, Mapping):
            raise ValueError("metric sample must be an object")
        _fields(raw, {"baseline", "treatment"}, "metric sample")
        pair = []
        for name in ("baseline", "treatment"):
            data = raw.get(name)
            if not isinstance(data, list) or len(data) != contract.sample_count or not all(
                    isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in data):
                raise ValueError("metric raw sample count/value is invalid")
            pair.append(tuple(float(x) for x in data))
        samples[str(metric_id)] = (pair[0], pair[1])
    expected_metrics = {m.source_metric if side == "source" else m.target_metric for m in contract.metrics}
    if set(samples) != expected_metrics:
        raise ValueError("metric report coverage mismatch")
    return PlatformReport(
        side, runner_id, contract.identity, _string(value, "calibrationProtocol", "report"),
        _integer(value, "randomSeed", "report"), _string(value, "affinityPolicy", "report"),
        _string(value, "noisePolicy", "report"),
        _integer(value, "warmupsCompleted", "report"), dict(environment),
        _parse_array(value.get("logicalAccesses"), _parse_access, "logicalAccesses"),
        _parse_array(value.get("controlFlow"), _parse_control, "controlFlow"),
        _strings(value.get("syncObservations"), "syncObservations"), samples,
    )


def _environment_matches(actual: Mapping[str, object], required: Mapping[str, object]) -> bool:
    return set(required) <= _ENV_FIELDS and all(actual.get(key) == expected for key, expected in required.items())


def _logical_checks(report: PlatformReport, contract: ExperimentContract) -> tuple[str, ...]:
    reasons = []
    if (report.calibration_protocol != contract.calibration_protocol or
            report.random_seed != contract.random_seed or
            report.affinity_policy != contract.affinity_policy or report.noise_policy != contract.noise_policy or
            report.warmups_completed < contract.warmup_count):
        reasons.append("calibration-or-warmup-mismatch")
    required_access = {item.event_id: item for item in contract.required_access_pattern}
    actual_access = {item.event_id: item for item in report.logical_accesses}
    if not set(required_access) <= set(actual_access):
        reasons.append("required-logical-access-missing")
    if set(actual_access) - set(required_access) - set(contract.approved_extra_accesses):
        reasons.append("unapproved-explicit-access")
    if any(actual_access.get(key) != item for key, item in required_access.items()):
        reasons.append("logical-access-semantics-mismatch")
    if report.control_flow != contract.required_control_flow:
        reasons.append("logical-control-flow-mismatch")
    if not set(contract.required_sync_semantics) <= set(report.sync_observations):
        reasons.append("required-sync-semantics-missing")
    return tuple(sorted(set(reasons)))


def _bootstrap_effect_ci(baseline: tuple[float, ...], treatment: tuple[float, ...], *, seed: int,
                         confidence: float, median: bool) -> tuple[float, float, float, float, float, float]:
    center = statistics.median if median else statistics.mean
    effect = center(treatment) - center(baseline)
    baseline_variance = statistics.variance(baseline) if len(baseline) > 1 else 0.0
    variance = statistics.variance(treatment) if len(treatment) > 1 else 0.0
    pooled = math.sqrt((baseline_variance + variance) / 2) if len(baseline) > 1 else 0.0
    standardized = effect / pooled if pooled else (math.copysign(math.inf, effect) if effect else 0.0)
    rng = random.Random(seed)
    effects = []
    for _ in range(1000):
        b = [baseline[rng.randrange(len(baseline))] for _ in baseline]
        t = [treatment[rng.randrange(len(treatment))] for _ in treatment]
        effects.append(center(t) - center(b))
    effects.sort()
    alpha = (1 - confidence) / 2
    low = effects[max(0, int(alpha * len(effects)))]
    high = effects[min(len(effects) - 1, int((1 - alpha) * len(effects)) - 1)]
    return effect, standardized, low, high, baseline_variance, variance


def _metric_summary(report: PlatformReport, metric: MetricContract, contract: ExperimentContract) -> Mapping[str, object]:
    name = metric.source_metric if report.side == "source" else metric.target_metric
    baseline, treatment = report.metric_samples[name]
    median = metric.statistical_test == "bootstrap_median_effect_v1"
    effect, standardized, low, high, baseline_variance, variance = _bootstrap_effect_ci(
        baseline, treatment, seed=contract.random_seed, confidence=metric.confidence_level, median=median,
    )
    direction_ok = ((metric.direction == "increase" and low > 0) or
                    (metric.direction == "decrease" and high < 0) or
                    (metric.direction == "nonzero" and (low > 0 or high < 0)))
    accepted = direction_ok and abs(standardized) >= metric.minimum_absolute_effect_size
    return {"metricId": metric.metric_id, "side": report.side, "method": metric.statistical_test,
            "sampleCount": len(baseline), "baselineMedian": statistics.median(baseline),
            "treatmentMedian": statistics.median(treatment), "baselineMean": statistics.mean(baseline),
            "treatmentMean": statistics.mean(treatment), "baselineVariance": baseline_variance,
            "treatmentVariance": variance,
            "effect": effect, "standardizedEffect": standardized, "confidenceInterval": [low, high],
            "accepted": accepted}


def _run_command(command: Sequence[str], stdin: str, timeout: int) -> CommandResult:
    try:
        result = subprocess.run(command, input=stdin, text=True, capture_output=True, timeout=timeout, check=False)
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(-1, str(exc.stdout or ""), str(exc.stderr or ""), True)


def run_l3_experiment_validation(config: ExperimentRunnerConfig, **kwargs: object) -> ValidationLayerResult:
    base = (run_l2_concurrency_differential(config.base_concurrency_config, **kwargs)
            if config.base_l2_kind == "concurrency" else run_l2_effect_trace_differential(config.base_effect_config, **kwargs))
    if base.status is not ValidationStatus.VERIFIED:
        return base
    plan = kwargs.get("validation_plan")
    if getattr(plan, "profile", None) is not ValidationProfile.MICROARCH:
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, detail="L3 requires microarch validation profile")
    if kwargs.get("comparison_policy") != config.comparison_policy:
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, detail="L3 comparison policy mismatch")
    try:
        path = Path(config.contract_path)
        if _file_digest(path) != config.contract_digest:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, detail="experiment contract digest mismatch")
        contract = load_experiment_contract(path)
    except OSError as exc:
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE, detail="experiment contract unavailable: " + str(exc))
    except (ValueError, json.JSONDecodeError) as exc:
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, detail="experiment contract invalid: " + str(exc))
    artifact = kwargs.get("translation_artifact")
    if (contract.experiment_id != getattr(plan, "experiment_contract_id", "") or
            contract.translation_plan_id != getattr(artifact, "translation_plan_id", "") or
            contract.proof_identity != getattr(artifact, "proof_identity", "")):
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, detail="experiment/plan/proof binding mismatch")
    for command in (config.source_command, config.target_command):
        if not (Path(command[0]).is_file() or shutil.which(command[0])):
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                         detail="L3 controlled runner unavailable: " + command[0])
    command_runner = kwargs.get("l3_command_runner", _run_command)
    if not callable(command_runner):
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, detail="L3 command runner invalid")
    reports = []
    summaries = []
    request = {"schemaVersion": EXPERIMENT_RUNNER_SCHEMA, "experimentId": contract.experiment_id,
               "contractIdentity": contract.identity, "sampleCount": contract.sample_count,
               "warmupCount": contract.warmup_count, "randomSeed": contract.random_seed,
               "affinityPolicy": contract.affinity_policy, "noisePolicy": contract.noise_policy,
               "calibrationProtocol": contract.calibration_protocol}
    for side, runner_id, command, requirements in (
            ("source", config.source_runner_id, config.source_command, contract.source_environment_requirements),
            ("target", config.target_runner_id, config.target_command, contract.target_environment_requirements)):
        current = dict(request, side=side, runnerId=runner_id)
        try:
            result = command_runner(command, json.dumps(current, sort_keys=True), config.timeout_seconds)
        except OSError as exc:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                         detail=side + " runner unavailable: " + str(exc))
        if result.timed_out:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, detail=side + " runner timed out")
        if result.returncode == 75:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                         detail=side + " required measurement capability unavailable: " + result.stderr)
        if result.returncode:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED,
                                         detail=side + " runner failed: " + result.stderr)
        try:
            raw = json.loads(result.stdout)
            if not isinstance(raw, Mapping):
                raise ValueError("report root must be an object")
            report = parse_platform_report(raw, side=side, runner_id=runner_id, contract=contract)
        except (ValueError, json.JSONDecodeError) as exc:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED,
                                         detail=side + " report invalid: " + str(exc))
        if not _environment_matches(report.environment, requirements):
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                         detail=side + " controlled environment does not satisfy contract")
        reasons = _logical_checks(report, contract)
        if reasons:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, report.identity,
                                         side + ": " + json.dumps(reasons, separators=(",", ":")))
        platform_summaries = [_metric_summary(report, metric, contract) for metric in contract.metrics]
        summaries.extend(platform_summaries)
        if any(not item["accepted"] for item in platform_summaries):
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.FAILED, report.identity,
                                         json.dumps({"side": side, "rawSampleSummary": platform_summaries}, sort_keys=True))
        binary = Path(command[0]) if Path(command[0]).is_file() else Path(str(shutil.which(command[0])))
        reports.append({"side": side, "report": report.identity, "runnerId": runner_id,
                        "environment": report.environment,
                        "runnerCommand": _digest(list(command)), "runnerBinary": _file_digest(binary)})
    evidence = _digest({"schemaVersion": EXPERIMENT_RUNNER_SCHEMA, "baseEvidence": base.evidence_identity,
                        "contractIdentity": contract.identity, "contractDigest": config.contract_digest,
                        "reports": reports, "statistics": summaries, "knownNonEquivalences": contract.known_non_equivalences})
    detail = json.dumps({
        "conclusion": "logical access/control-flow intent and per-platform statistical conclusions satisfy the experiment contract",
        "statisticalSummary": summaries, "environments": [item["environment"] for item in reports],
        "knownNonEquivalences": contract.known_non_equivalences,
    }, sort_keys=True)
    return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.VERIFIED, evidence, detail)


def build_l3_experiment_validator(config: ExperimentRunnerConfig):
    def validate(**kwargs: object) -> ValidationLayerResult:
        return run_l3_experiment_validation(config, **kwargs)
    return validate
