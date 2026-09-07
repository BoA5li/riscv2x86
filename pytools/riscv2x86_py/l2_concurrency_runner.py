"""L2 concurrency, atomicity and weak-memory differential runner."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable, Mapping, Sequence

from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .l2_effect_trace_differential import (
    L2EffectRunnerConfig, load_l2_effect_runner_config,
    run_l2_effect_trace_differential,
)
from .l2_privileged_runner import (
    L2PrivilegedRunnerConfig, load_l2_privileged_runner_config,
    run_l2_privileged_differential,
)
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus


CONCURRENCY_CONTRACT_SCHEMA = "riscv2x86.concurrency-memory-model-contract.v1"
CONCURRENCY_RUNNER_SCHEMA = "riscv2x86.l2-concurrency-runner.v1"
CONCURRENCY_OBSERVATION_SCHEMA = "riscv2x86.concurrency-observation.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPERATIONS = {"atomic_load", "atomic_store", "atomic_rmw", "compare_exchange", "lr_sc", "fence"}
_ORDERS = {"relaxed", "acquire", "release", "acq_rel", "seq_cst", "compiler", "hardware"}
_FAILURE_ORDERS = {"not_applicable", "relaxed", "acquire", "seq_cst"}
_FAILURE_BEHAVIORS = {"not_applicable", "no_spurious_failure", "spurious_failure_allowed",
                      "retry_until_success", "bounded_failure_observable"}
_SCENARIO_KINDS = {"single_thread", "stress", "litmus"}


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(raw.encode()).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected: raise ValueError(label + " fields are incomplete or unknown")


def _string(value: Mapping[str, object], name: str, label: str, *, empty: bool = False) -> str:
    item = value.get(name)
    if not isinstance(item, str) or (not empty and not item): raise ValueError(f"{label}.{name} must be a string")
    return item


def _boolean(value: Mapping[str, object], name: str, label: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool): raise ValueError(f"{label}.{name} must be boolean")
    return item


def _integer(value: Mapping[str, object], name: str, label: str) -> int:
    item = value.get(name)
    if isinstance(item, bool) or not isinstance(item, int): raise ValueError(f"{label}.{name} must be an integer")
    return item


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be a string array")
    result = tuple(value)
    if result != tuple(sorted(set(result))): raise ValueError(label + " must be unique and sorted")
    return result


@dataclass(frozen=True)
class ConcurrencyScenario:
    test_id: str
    kind: str
    minimum_iterations: int
    allowed_final_states: tuple[str, ...]
    forbidden_outcomes: tuple[str, ...]
    required_ordering_observations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.test_id or self.kind not in _SCENARIO_KINDS or self.minimum_iterations <= 0:
            raise ValueError("concurrency scenario identity/kind/iterations are invalid")
        if not self.allowed_final_states or set(self.allowed_final_states) & set(self.forbidden_outcomes):
            raise ValueError("allowed and forbidden outcomes are incomplete or overlap")


@dataclass(frozen=True)
class AtomicMemoryModelContract:
    contract_id: str
    translation_plan_id: str
    proof_identity: str
    source_operation: str
    required_ordering: str
    target_ordering: str
    required_failure_ordering: str
    target_failure_ordering: str
    required_atomic_width_bits: int
    required_alignment_bytes: int
    allowed_target_strengthening: bool
    retry_failure_behavior: str
    retry_shape_policy: str
    scenarios: tuple[ConcurrencyScenario, ...]
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if not self.contract_id or not self.translation_plan_id or not _SHA256.fullmatch(self.proof_identity):
            raise ValueError("concurrency contract identity is incomplete")
        if self.source_operation not in _OPERATIONS or self.required_ordering not in _ORDERS or self.target_ordering not in _ORDERS:
            raise ValueError("atomic operation or ordering is unsupported")
        if self.required_failure_ordering not in _FAILURE_ORDERS or self.target_failure_ordering not in _FAILURE_ORDERS:
            raise ValueError("atomic failure ordering is unsupported")
        has_failure_order = self.source_operation in {"compare_exchange", "lr_sc"}
        if has_failure_order != (self.required_failure_ordering != "not_applicable"):
            raise ValueError("failure ordering applicability is inconsistent")
        if has_failure_order != (self.target_failure_ordering != "not_applicable"):
            raise ValueError("target failure ordering applicability is inconsistent")
        if self.source_operation == "fence":
            if self.required_atomic_width_bits != 0 or self.required_alignment_bytes != 0:
                raise ValueError("fence must explicitly use zero atomic width/alignment")
        elif self.required_atomic_width_bits not in {8, 16, 32, 64, 128} or self.required_alignment_bytes <= 0:
            raise ValueError("atomic width/alignment contract is invalid")
        if self.retry_failure_behavior not in _FAILURE_BEHAVIORS:
            raise ValueError("retry/failure behavior is unsupported")
        if self.retry_shape_policy not in {"not_observable_at_l2", "requires_l3"}:
            raise ValueError("retry shape policy is unsupported")
        ids = tuple(item.test_id for item in self.scenarios)
        if ids != tuple(sorted(set(ids))) or {item.kind for item in self.scenarios} != _SCENARIO_KINDS:
            raise ValueError("contract requires unique single-thread, stress and litmus scenarios")

    @property
    def identity(self) -> str: return _digest(self.payload)


@dataclass(frozen=True)
class ScenarioRunner:
    test_id: str
    source_runner_id: str
    target_runner_id: str
    source_command: tuple[str, ...]
    target_command: tuple[str, ...]


@dataclass(frozen=True)
class L2ConcurrencyRunnerConfig:
    base_kind: str
    base_effect_config: L2EffectRunnerConfig | None
    base_privileged_config: L2PrivilegedRunnerConfig | None
    contract_path: str
    contract_digest: str
    runners: tuple[ScenarioRunner, ...]
    timeout_seconds: int
    comparison_policy: str = ARCHITECTURAL_COMPARISON_POLICY
    schema_version: str = CONCURRENCY_RUNNER_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != CONCURRENCY_RUNNER_SCHEMA or self.comparison_policy != ARCHITECTURAL_COMPARISON_POLICY:
            raise ValueError("concurrency runner schema/policy is invalid")
        if self.base_kind not in {"effect", "privileged"}:
            raise ValueError("concurrency base L2 kind is invalid")
        if (self.base_kind == "effect") != (self.base_effect_config is not None) or (self.base_kind == "privileged") != (self.base_privileged_config is not None):
            raise ValueError("concurrency base L2 configuration is inconsistent")
        if not self.contract_path or not _SHA256.fullmatch(self.contract_digest) or self.timeout_seconds <= 0:
            raise ValueError("concurrency contract/timeout is invalid")
        ids = tuple(item.test_id for item in self.runners)
        if ids != tuple(sorted(set(ids))): raise ValueError("scenario runners must be unique and sorted")


@dataclass(frozen=True)
class ConcurrencyObservation:
    test_id: str
    runner_id: str
    contract_identity: str
    iterations_completed: int
    outcome_counts: tuple[tuple[str, int], ...]
    ordering_observations: tuple[str, ...]
    atomic_widths_observed: tuple[int, ...]
    alignments_observed: tuple[int, ...]
    success_count: int
    failure_count: int
    retry_count: int
    completed: bool

    @property
    def identity(self) -> str: return _digest(self.__dict__)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


CommandRunner = Callable[[Sequence[str], str, int], CommandResult]


def _run(command: Sequence[str], stdin: str, timeout: int) -> CommandResult:
    try:
        result = subprocess.run(command, input=stdin, text=True, capture_output=True, timeout=timeout, check=False)
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(-1, str(exc.stdout or ""), str(exc.stderr or ""), True)


def load_concurrency_contract(path: str | Path) -> AtomicMemoryModelContract:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping): raise ValueError("concurrency contract must be an object")
    fields = {"schemaVersion", "contractId", "translationPlanId", "proofIdentity", "sourceOperation",
              "requiredOrdering", "targetOrdering", "requiredFailureOrdering", "targetFailureOrdering",
              "requiredAtomicWidthBits", "requiredAlignmentBytes",
              "allowedTargetStrengthening", "retryFailureBehavior", "retryShapePolicy", "scenarios"}
    _fields(value, fields, "concurrency contract")
    if value.get("schemaVersion") != CONCURRENCY_CONTRACT_SCHEMA: raise ValueError("concurrency contract schema unsupported")
    raw_scenarios = value.get("scenarios")
    if not isinstance(raw_scenarios, list): raise ValueError("concurrency scenarios must be an array")
    scenarios = []
    for raw in raw_scenarios:
        if not isinstance(raw, Mapping): raise ValueError("concurrency scenario must be an object")
        _fields(raw, {"testId", "kind", "minimumIterations", "allowedFinalStates", "forbiddenOutcomes",
                      "requiredOrderingObservations"}, "concurrency scenario")
        scenarios.append(ConcurrencyScenario(
            _string(raw, "testId", "scenario"), _string(raw, "kind", "scenario"),
            _integer(raw, "minimumIterations", "scenario"),
            _strings(raw.get("allowedFinalStates"), "allowed final states"),
            _strings(raw.get("forbiddenOutcomes"), "forbidden outcomes"),
            _strings(raw.get("requiredOrderingObservations"), "required ordering observations"),
        ))
    return AtomicMemoryModelContract(
        _string(value, "contractId", "contract"), _string(value, "translationPlanId", "contract"),
        _string(value, "proofIdentity", "contract"), _string(value, "sourceOperation", "contract"),
        _string(value, "requiredOrdering", "contract"), _string(value, "targetOrdering", "contract"),
        _string(value, "requiredFailureOrdering", "contract"),
        _string(value, "targetFailureOrdering", "contract"),
        _integer(value, "requiredAtomicWidthBits", "contract"),
        _integer(value, "requiredAlignmentBytes", "contract"),
        _boolean(value, "allowedTargetStrengthening", "contract"),
        _string(value, "retryFailureBehavior", "contract"),
        _string(value, "retryShapePolicy", "contract"), tuple(scenarios), dict(value),
    )


def load_l2_concurrency_runner_config(value: Mapping[str, object]) -> L2ConcurrencyRunnerConfig:
    fields = {"schemaVersion", "comparisonPolicy", "baseL2Kind", "baseL2Runner", "contractPath",
              "contractDigest", "scenarioRunners", "timeoutSeconds"}
    _fields(value, fields, "L2 concurrency runner")
    base_kind = _string(value, "baseL2Kind", "runner")
    base_raw = value.get("baseL2Runner")
    if not isinstance(base_raw, Mapping): raise ValueError("baseL2Runner must be an object")
    raw_runners = value.get("scenarioRunners")
    if not isinstance(raw_runners, list): raise ValueError("scenarioRunners must be an array")
    runners = []
    for raw in raw_runners:
        if not isinstance(raw, Mapping): raise ValueError("scenario runner must be an object")
        _fields(raw, {"testId", "sourceRunnerId", "targetRunnerId", "sourceCommand", "targetCommand"}, "scenario runner")
        commands = []
        for name in ("sourceCommand", "targetCommand"):
            command = raw.get(name)
            if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
                raise ValueError(name + " must be a non-empty string array")
            commands.append(tuple(command))
        runners.append(ScenarioRunner(
            _string(raw, "testId", "scenario runner"),
            _string(raw, "sourceRunnerId", "scenario runner"),
            _string(raw, "targetRunnerId", "scenario runner"), *commands,
        ))
    timeout = _integer(value, "timeoutSeconds", "runner")
    return L2ConcurrencyRunnerConfig(
        base_kind, load_l2_effect_runner_config(base_raw) if base_kind == "effect" else None,
        load_l2_privileged_runner_config(base_raw) if base_kind == "privileged" else None,
        _string(value, "contractPath", "runner"), _string(value, "contractDigest", "runner"),
        tuple(runners), timeout, _string(value, "comparisonPolicy", "runner"),
        _string(value, "schemaVersion", "runner"),
    )


def _order_strengthens(required: str, target: str) -> bool:
    if required == target: return True
    allowed = {"relaxed": {"acquire", "release", "acq_rel", "seq_cst"},
               "acquire": {"acq_rel", "seq_cst"}, "release": {"acq_rel", "seq_cst"},
               "acq_rel": {"seq_cst"}, "compiler": {"hardware", "seq_cst"},
               "hardware": {"seq_cst"}}
    return target in allowed.get(required, set())


def parse_concurrency_observation(value: Mapping[str, object], *, test_id: str,
                                  runner_id: str, contract_identity: str) -> ConcurrencyObservation:
    fields = {"schemaVersion", "testId", "runnerId", "contractIdentity", "iterationsCompleted",
              "outcomeCounts", "orderingObservations", "atomicWidthsObserved", "alignmentsObserved",
              "successCount", "failureCount", "retryCount", "completed"}
    _fields(value, fields, "concurrency observation")
    if value.get("schemaVersion") != CONCURRENCY_OBSERVATION_SCHEMA: raise ValueError("observation schema unsupported")
    if (_string(value, "testId", "observation") != test_id or
            _string(value, "runnerId", "observation") != runner_id or
            _string(value, "contractIdentity", "observation") != contract_identity):
        raise ValueError("observation test/runner/contract binding mismatch")
    raw_counts = value.get("outcomeCounts")
    if not isinstance(raw_counts, Mapping): raise ValueError("outcomeCounts must be an object")
    counts = tuple(raw_counts.items())
    if counts != tuple(sorted(counts)) or not all(isinstance(k, str) and k and isinstance(v, int) and not isinstance(v, bool) and v >= 0 for k, v in counts):
        raise ValueError("outcomeCounts must be a sorted non-negative integer map")
    def integers(name: str) -> tuple[int, ...]:
        raw = value.get(name)
        if not isinstance(raw, list) or not all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in raw):
            raise ValueError(name + " must be a non-negative integer array")
        result = tuple(raw)
        if result != tuple(sorted(set(result))): raise ValueError(name + " must be unique and sorted")
        return result
    completed = value.get("completed")
    if not isinstance(completed, bool): raise ValueError("completed must be boolean")
    result = ConcurrencyObservation(
        test_id, runner_id, contract_identity,
        _integer(value, "iterationsCompleted", "observation"), counts,
        _strings(value.get("orderingObservations"), "ordering observations"),
        integers("atomicWidthsObserved"), integers("alignmentsObserved"),
        _integer(value, "successCount", "observation"), _integer(value, "failureCount", "observation"),
        _integer(value, "retryCount", "observation"), completed,
    )
    if sum(count for _, count in counts) != result.iterations_completed:
        raise ValueError("outcome counts do not equal completed iterations")
    return result


def compare_concurrency_observation(observation: ConcurrencyObservation, scenario: ConcurrencyScenario,
                                    contract: AtomicMemoryModelContract) -> tuple[str, ...]:
    reasons = []
    counts = dict(observation.outcome_counts)
    observed = {name for name, count in counts.items() if count}
    if not observation.completed or observation.iterations_completed < scenario.minimum_iterations:
        reasons.append("iterations-or-completion-insufficient")
    if not observed <= set(scenario.allowed_final_states): reasons.append("outcome-outside-source-contract")
    if any(counts.get(item, 0) for item in scenario.forbidden_outcomes): reasons.append("forbidden-outcome-observed")
    if not set(scenario.required_ordering_observations) <= set(observation.ordering_observations):
        reasons.append("required-ordering-observation-missing")
    if contract.source_operation != "fence":
        if observation.atomic_widths_observed != (contract.required_atomic_width_bits,):
            reasons.append("atomic-width-mismatch")
        if not observation.alignments_observed or min(observation.alignments_observed) < contract.required_alignment_bytes:
            reasons.append("atomic-alignment-mismatch")
    if contract.retry_failure_behavior in {"not_applicable", "no_spurious_failure"} and observation.retry_count:
        reasons.append("retry-not-allowed")
    if contract.retry_failure_behavior == "retry_until_success" and observation.success_count <= 0:
        reasons.append("retry-success-contract-unsatisfied")
    if observation.success_count + observation.failure_count > observation.iterations_completed:
        reasons.append("success-failure-count-invalid")
    return tuple(sorted(set(reasons)))


def _execute(command: Sequence[str], request: Mapping[str, object], timeout: int,
             command_runner: CommandRunner, test_id: str, runner_id: str,
             contract_identity: str) -> tuple[ConcurrencyObservation | None, str, ValidationStatus]:
    try: result = command_runner(command, json.dumps(request, sort_keys=True), timeout)
    except OSError as exc: return None, "runner unavailable: " + str(exc), ValidationStatus.INCONCLUSIVE
    if result.timed_out: return None, "concurrency runner timed out", ValidationStatus.FAILED
    if result.returncode: return None, "concurrency runner failed: " + result.stderr, ValidationStatus.FAILED
    try:
        raw = json.loads(result.stdout)
        if not isinstance(raw, Mapping): raise ValueError("observation root must be an object")
        return parse_concurrency_observation(
            raw, test_id=test_id, runner_id=runner_id,
            contract_identity=contract_identity,
        ), "", ValidationStatus.VERIFIED
    except (ValueError, json.JSONDecodeError) as exc:
        return None, "concurrency observation invalid: " + str(exc), ValidationStatus.FAILED


def run_l2_concurrency_differential(config: L2ConcurrencyRunnerConfig, **kwargs: object) -> ValidationLayerResult:
    base = (run_l2_effect_trace_differential(config.base_effect_config, **kwargs)
            if config.base_kind == "effect" else run_l2_privileged_differential(config.base_privileged_config, **kwargs))
    if base.status is not ValidationStatus.VERIFIED: return base
    if kwargs.get("comparison_policy") != config.comparison_policy:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="concurrency policy mismatch")
    try:
        contract_path = Path(config.contract_path)
        if _file_digest(contract_path) != config.contract_digest:
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="concurrency contract digest mismatch")
        contract = load_concurrency_contract(contract_path)
    except OSError as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail="concurrency contract unavailable: " + str(exc))
    except (ValueError, json.JSONDecodeError) as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="concurrency contract invalid: " + str(exc))
    artifact = kwargs.get("translation_artifact")
    if (contract.translation_plan_id != getattr(artifact, "translation_plan_id", "") or
            contract.proof_identity != getattr(artifact, "proof_identity", "")):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="concurrency plan/proof binding mismatch")
    if contract.retry_shape_policy == "requires_l3":
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail="retry shape is microarchitecture-observable and requires L3")
    if contract.target_ordering != contract.required_ordering:
        if not contract.allowed_target_strengthening or not _order_strengthens(contract.required_ordering, contract.target_ordering):
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="target memory-order strengthening is not allowed/proved")
    if contract.target_failure_ordering != contract.required_failure_ordering:
        if (not contract.allowed_target_strengthening or
                not _order_strengthens(contract.required_failure_ordering, contract.target_failure_ordering)):
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                         detail="target failure-order strengthening is not allowed/proved")
    scenarios = {item.test_id: item for item in contract.scenarios}
    runners = {item.test_id: item for item in config.runners}
    if set(runners) != set(scenarios):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="scenario runner coverage mismatch")
    for runner in config.runners:
        for command in (runner.source_command, runner.target_command):
            if not (Path(command[0]).is_file() or shutil.which(command[0])):
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                             detail="concurrency runner unavailable: " + command[0])
    command_runner = kwargs.get("concurrency_command_runner", _run)
    if not callable(command_runner):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="concurrency command runner invalid")
    evidence_runs = []
    for test_id in sorted(scenarios):
        scenario, runner = scenarios[test_id], runners[test_id]
        request = {"schemaVersion": CONCURRENCY_RUNNER_SCHEMA, "testId": test_id,
                   "contractIdentity": contract.identity, "scenarioKind": scenario.kind,
                   "minimumIterations": scenario.minimum_iterations, "requiredOrdering": contract.required_ordering,
                   "targetOrdering": contract.target_ordering, "atomicWidthBits": contract.required_atomic_width_bits,
                   "alignmentBytes": contract.required_alignment_bytes,
                   "requiredFailureOrdering": contract.required_failure_ordering,
                   "targetFailureOrdering": contract.target_failure_ordering,
                   "retryFailureBehavior": contract.retry_failure_behavior}
        pair = []
        for side, runner_id, command in (
                ("source", runner.source_runner_id, runner.source_command),
                ("target", runner.target_runner_id, runner.target_command)):
            request["runnerId"] = runner_id
            request["side"] = side
            observation, detail, status = _execute(command, request, config.timeout_seconds, command_runner,
                                                   test_id, runner_id, contract.identity)
            if observation is None: return ValidationLayerResult(ValidationLevel.L2, status, detail=side + ": " + detail)
            reasons = compare_concurrency_observation(observation, scenario, contract)
            if reasons:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, observation.identity,
                                             side + ": " + json.dumps(reasons, separators=(",", ":")))
            pair.append({"side": side, "observation": observation.identity,
                         "runnerId": runner_id, "runnerCommand": _digest(list(command)),
                         "runnerBinary": _file_digest(Path(command[0]) if Path(command[0]).is_file() else Path(str(shutil.which(command[0]))))})
        evidence_runs.append({"testId": test_id, "runs": pair})
    evidence = _digest({"schemaVersion": CONCURRENCY_RUNNER_SCHEMA, "baseEvidence": base.evidence_identity,
                        "contractIdentity": contract.identity, "contractDigest": config.contract_digest,
                        "runs": evidence_runs})
    return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED, evidence,
                                 "single-thread, stress and litmus outcomes satisfy the source memory-model contract")


def build_l2_concurrency_validator(config: L2ConcurrencyRunnerConfig):
    def validate(**kwargs: object) -> ValidationLayerResult:
        return run_l2_concurrency_differential(config, **kwargs)
    return validate
