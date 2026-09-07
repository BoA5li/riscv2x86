"""Real L2-C privileged source/target runner and route-isolation gate."""
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
    L2EffectRunnerConfig, run_l2_effect_trace_differential,
)
from .privileged_differential_validation import (
    DifferentialPreservationMode, PrivilegedMachineObservation,
    validate_privileged_differential,
)
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus


PRIVILEGED_RUNNER_SCHEMA = "riscv2x86.l2-privileged-runner.v1"
PRIVILEGED_OBSERVATION_SCHEMA = "riscv2x86.privileged-observation.v1"
PRIVILEGED_MANIFEST_SCHEMA = "riscv2x86.privileged-validation-manifest.v1"
PRIVILEGED_INITIAL_STATE_SCHEMA = "riscv2x86.privileged-initial-state.v1"
CSR_ROUTE_CONTRACT_SCHEMA = "riscv2x86.csr-route-contract.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_KINDS = {"spike", "qemu-system", "controlled-linux-guest", "real-riscv"}
_TARGET_KINDS = {"x86-logical-runtime", "x86-system-adapter", "x86-vmm-adapter",
                 "x86-debug-adapter", "emulator-only"}
_TARGET_MODES = {"ordinary-user-process", "logical-csr-runtime", "system-adapter",
                 "vmm-adapter", "debug-adapter", "emulator-only"}
_CATEGORIES = {"time", "cycle", "instret", "status", "mmu", "interrupt", "pmp", "debug", "h", "custom"}
_OPERATIONS = {"read", "write", "read_write"}
_REQUIRED_FALLBACK_EFFECTS = {"c-output", "memory", "error-status", "termination",
                              "trap-to-result", "external-events"}
_CSR_FIELD = re.compile(r"^csr:[a-z0-9_.:-]+\.[a-z0-9_.:-]+$")
_CANONICAL_BITS = re.compile(r"^0x[0-9a-f]+$")


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(raw.encode()).hexdigest()


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


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be a string array")
    result = tuple(value)
    if result != tuple(sorted(set(result))): raise ValueError(label + " must be unique and sorted")
    return result


def _pairs(value: object, label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or not all(isinstance(k, str) and k and isinstance(v, str) for k, v in value.items()):
        raise ValueError(label + " must be a string map")
    result = tuple(value.items())
    if result != tuple(sorted(result)): raise ValueError(label + " must already be sorted")
    return result


def _events(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an ordered string array")
    return tuple(value)


@dataclass(frozen=True)
class PrivilegedRunnerSpec:
    command: tuple[str, ...]
    runner_kind: str
    runner_id: str
    runtime_version: str
    execution_profile: str
    target_execution_mode: str

    def __post_init__(self) -> None:
        if not self.command or not self.runner_id or not self.runtime_version or not self.execution_profile:
            raise ValueError("privileged runner identity is incomplete")
        if self.runner_kind not in _SOURCE_KINDS | _TARGET_KINDS:
            raise ValueError("privileged runner kind is unsupported")
        if self.target_execution_mode not in _TARGET_MODES:
            raise ValueError("target execution mode is unsupported")
        if self.runner_kind in _SOURCE_KINDS and self.target_execution_mode != "emulator-only":
            raise ValueError("source runner cannot claim a target adapter mode")
        expected = {
            "x86-logical-runtime": {"ordinary-user-process", "logical-csr-runtime"},
            "x86-system-adapter": {"system-adapter"}, "x86-vmm-adapter": {"vmm-adapter"},
            "x86-debug-adapter": {"debug-adapter"}, "emulator-only": {"emulator-only"},
        }
        if self.runner_kind in expected and self.target_execution_mode not in expected[self.runner_kind]:
            raise ValueError("runner kind cannot provide the declared target execution mode")


@dataclass(frozen=True)
class CsrRoute:
    csr_id: str
    category: str
    operation: str
    target_route: str
    observation_domain_contract_id: str
    domain_relation_proof_identity: str
    registered: bool
    source_write_observable: bool


@dataclass(frozen=True)
class CsrRouteContract:
    routes: tuple[CsrRoute, ...]
    payload: Mapping[str, object]

    @property
    def identity(self) -> str: return _digest(self.payload)


@dataclass(frozen=True)
class PrivilegedValidationManifest:
    preservation_mode: DifferentialPreservationMode
    proof_status: str
    proof_identity: str
    architecture_semantics_preserved: bool
    microarchitecture_semantics_preserved: bool
    ignored_source_state: tuple[str, ...]
    ignored_state_escapes: bool
    observable_effects: tuple[str, ...]
    route_contract_identity: str
    initial_state_identity: str
    runtime_old_new_relation_id: str
    runtime_contract_id: str
    runtime_contract_version: str
    payload: Mapping[str, object]


@dataclass(frozen=True)
class L2PrivilegedRunnerConfig:
    base_effect_config: L2EffectRunnerConfig
    source_runner: PrivilegedRunnerSpec
    target_runner: PrivilegedRunnerSpec
    initial_state_path: str
    privileged_manifest_path: str
    csr_route_contract_path: str
    timeout_seconds: int
    comparison_policy: str = ARCHITECTURAL_COMPARISON_POLICY
    schema_version: str = PRIVILEGED_RUNNER_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != PRIVILEGED_RUNNER_SCHEMA or self.comparison_policy != ARCHITECTURAL_COMPARISON_POLICY or
                not all((self.initial_state_path, self.privileged_manifest_path, self.csr_route_contract_path)) or
                isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0):
            raise ValueError("privileged runner configuration is invalid")


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


def _runner(value: object, label: str) -> PrivilegedRunnerSpec:
    if not isinstance(value, Mapping): raise ValueError(label + " must be an object")
    _fields(value, {"command", "runnerKind", "runnerId", "runtimeVersion", "executionProfile",
                    "targetExecutionMode"}, label)
    command = value.get("command")
    if not isinstance(command, list) or not all(isinstance(item, str) and item for item in command):
        raise ValueError(label + ".command must be a string array")
    return PrivilegedRunnerSpec(tuple(command), _string(value, "runnerKind", label),
                                _string(value, "runnerId", label), _string(value, "runtimeVersion", label),
                                _string(value, "executionProfile", label),
                                _string(value, "targetExecutionMode", label))


def load_l2_privileged_runner_config(value: Mapping[str, object]) -> L2PrivilegedRunnerConfig:
    _fields(value, {"schemaVersion", "comparisonPolicy", "baseEffectRunner", "sourceRunner", "targetRunner",
                    "initialStatePath", "privilegedManifestPath", "csrRouteContractPath", "timeoutSeconds"},
            "L2 privileged runner")
    base = value.get("baseEffectRunner")
    if not isinstance(base, Mapping): raise ValueError("baseEffectRunner must be an object")
    from .l2_effect_trace_differential import load_l2_effect_runner_config
    timeout = value.get("timeoutSeconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int): raise ValueError("timeoutSeconds must be an integer")
    return L2PrivilegedRunnerConfig(
        load_l2_effect_runner_config(base), _runner(value.get("sourceRunner"), "source runner"),
        _runner(value.get("targetRunner"), "target runner"),
        _string(value, "initialStatePath", "L2 privileged runner"),
        _string(value, "privilegedManifestPath", "L2 privileged runner"),
        _string(value, "csrRouteContractPath", "L2 privileged runner"), timeout,
        _string(value, "comparisonPolicy", "L2 privileged runner"),
        _string(value, "schemaVersion", "L2 privileged runner"),
    )


def load_csr_route_contract(path: str | Path) -> CsrRouteContract:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping): raise ValueError("CSR route contract must be an object")
    _fields(value, {"schemaVersion", "routes"}, "CSR route contract")
    if value.get("schemaVersion") != CSR_ROUTE_CONTRACT_SCHEMA: raise ValueError("CSR route schema is unsupported")
    raw = value.get("routes")
    if not isinstance(raw, list): raise ValueError("CSR routes must be an array")
    routes = []
    for item in raw:
        if not isinstance(item, Mapping): raise ValueError("CSR route must be an object")
        _fields(item, {"csrId", "category", "operation", "targetRoute", "observationDomainContractId",
                       "domainRelationProofIdentity", "registered", "sourceWriteObservable"}, "CSR route")
        route = CsrRoute(
            _string(item, "csrId", "CSR route"), _string(item, "category", "CSR route"),
            _string(item, "operation", "CSR route"), _string(item, "targetRoute", "CSR route"),
            _string(item, "observationDomainContractId", "CSR route", empty=True),
            _string(item, "domainRelationProofIdentity", "CSR route", empty=True),
            _boolean(item, "registered", "CSR route"), _boolean(item, "sourceWriteObservable", "CSR route"),
        )
        if route.category not in _CATEGORIES or route.operation not in _OPERATIONS:
            raise ValueError("CSR route category/operation is unsupported")
        routes.append(route)
    keys = tuple((item.csr_id, item.operation) for item in routes)
    if keys != tuple(sorted(set(keys))): raise ValueError("CSR routes must be unique and sorted")
    return CsrRouteContract(tuple(routes), dict(value))


def load_privileged_manifest(path: str | Path) -> PrivilegedValidationManifest:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping): raise ValueError("privileged manifest must be an object")
    fields = {"schemaVersion", "preservationMode", "proofStatus", "proofIdentity",
              "architectureSemanticsPreserved", "microarchitectureSemanticsPreserved", "ignoredSourceState",
              "ignoredStateEscapes", "observableEffectsProved", "routeContractIdentity", "initialStateIdentity",
              "runtimeOldNewRelationId", "runtimeContractId", "runtimeContractVersion"}
    _fields(value, fields, "privileged manifest")
    mode = DifferentialPreservationMode(_string(value, "preservationMode", "privileged manifest"))
    manifest = PrivilegedValidationManifest(
        mode, _string(value, "proofStatus", "privileged manifest"),
        _string(value, "proofIdentity", "privileged manifest"),
        _boolean(value, "architectureSemanticsPreserved", "privileged manifest"),
        _boolean(value, "microarchitectureSemanticsPreserved", "privileged manifest"),
        _strings(value.get("ignoredSourceState"), "ignored source state"),
        _boolean(value, "ignoredStateEscapes", "privileged manifest"),
        _strings(value.get("observableEffectsProved"), "observable effects"),
        _string(value, "routeContractIdentity", "privileged manifest"),
        _string(value, "initialStateIdentity", "privileged manifest"),
        _string(value, "runtimeOldNewRelationId", "privileged manifest", empty=True),
        _string(value, "runtimeContractId", "privileged manifest"),
        _string(value, "runtimeContractVersion", "privileged manifest"),
        dict(value),
    )
    for name in (manifest.proof_identity, manifest.route_contract_identity, manifest.initial_state_identity):
        if not _SHA256.fullmatch(name): raise ValueError("privileged manifest identity is invalid")
    if mode is DifferentialPreservationMode.STRICT:
        if (manifest.proof_status != "approved" or not manifest.architecture_semantics_preserved or
                manifest.ignored_source_state or manifest.ignored_state_escapes or not manifest.runtime_old_new_relation_id):
            raise ValueError("strict privileged manifest is incomplete")
    else:
        if (manifest.proof_status != "functional_approved" or manifest.architecture_semantics_preserved or
                manifest.microarchitecture_semantics_preserved or not manifest.ignored_source_state or
                manifest.ignored_state_escapes or not _REQUIRED_FALLBACK_EFFECTS <= set(manifest.observable_effects)):
            raise ValueError("fallback privileged manifest is incomplete")
    return manifest


def validate_csr_routes(contract: CsrRouteContract, *, target_mode: str,
                        preservation_mode: DifferentialPreservationMode) -> tuple[str, ...]:
    allowed = {
        "time": {"monotonic-time-adapter"}, "cycle": {"counter-domain-adapter"},
        "instret": {"emulator-only"}, "status": {"logical-privileged-runtime", "vmm-adapter"},
        "mmu": {"mmu-adapter", "vmm-adapter"}, "interrupt": {"interrupt-adapter", "vmm-adapter"},
        "pmp": {"system-adapter", "vmm-adapter"}, "debug": {"debug-adapter"},
        "h": {"vmm-adapter"}, "custom": {"custom-registered-runtime"},
    }
    mode_routes = {
        "ordinary-user-process": {"monotonic-time-adapter", "counter-domain-adapter"},
        "logical-csr-runtime": {"monotonic-time-adapter", "counter-domain-adapter", "logical-privileged-runtime",
                                "interrupt-adapter", "custom-registered-runtime"},
        "system-adapter": {"system-adapter"}, "vmm-adapter": {"vmm-adapter", "mmu-adapter"},
        "debug-adapter": {"debug-adapter"}, "emulator-only": {"emulator-only"},
    }
    reasons = []
    for route in contract.routes:
        prefix = "csr-route:" + route.csr_id + ":"
        if route.target_route not in allowed[route.category] or route.target_route not in mode_routes[target_mode]:
            reasons.append(prefix + "target-route-mode-invalid")
        if route.category in {"time", "cycle"} and not route.observation_domain_contract_id:
            reasons.append(prefix + "observation-domain-contract-missing")
        if route.category == "cycle" and not _SHA256.fullmatch(route.domain_relation_proof_identity):
            reasons.append(prefix + "cycle-domain-relation-unproved")
        if route.category == "custom" and not route.registered:
            reasons.append(prefix + "custom-csr-unregistered")
        elif not route.registered:
            reasons.append(prefix + "adapter-unregistered")
        if route.operation in {"write", "read_write"}:
            if route.target_route == "deleted" or not route.source_write_observable:
                reasons.append(prefix + "source-write-observable-effect-unpreserved")
            if preservation_mode is DifferentialPreservationMode.FUNCTIONAL:
                reasons.append(prefix + "fallback-write-forbidden")
    return tuple(sorted(set(reasons)))


def parse_privileged_observation(value: Mapping[str, object], spec: PrivilegedRunnerSpec,
                                 initial_identity: str) -> PrivilegedMachineObservation:
    fields = {"schemaVersion", "runnerId", "runtimeVersion", "executionProfile", "initialStateIdentity",
              "csrFields", "privilegeMode", "trap", "continuation", "memory", "interrupt", "mmuTlb",
              "termination", "outputs", "status", "trapToResult", "externalEvents", "observableEffects",
              "ignoredState", "runtimeOldNewState"}
    _fields(value, fields, "privileged observation")
    if value.get("schemaVersion") != PRIVILEGED_OBSERVATION_SCHEMA: raise ValueError("observation schema unsupported")
    if (_string(value, "runnerId", "observation") != spec.runner_id or
            _string(value, "runtimeVersion", "observation") != spec.runtime_version or
            _string(value, "executionProfile", "observation") != spec.execution_profile or
            _string(value, "initialStateIdentity", "observation") != initial_identity):
        raise ValueError("observation runner/runtime/profile/initial-state binding mismatch")
    csr_fields = _pairs(value.get("csrFields"), "CSR fields")
    if any(not _CSR_FIELD.fullmatch(name) or not _CANONICAL_BITS.fullmatch(bits) for name, bits in csr_fields):
        raise ValueError("CSR fields must use canonical field IDs and hexadecimal values")
    privilege_mode = _string(value, "privilegeMode", "observation")
    if privilege_mode not in {"u", "s", "vs", "m", "hs"}: raise ValueError("privilege mode is invalid")
    termination = _string(value, "termination", "observation")
    if termination not in {"normal", "trap", "signal", "timeout", "error", "unsupported"}:
        raise ValueError("termination class is invalid")
    mmu_tlb = _pairs(value.get("mmuTlb"), "MMU/TLB")
    if "addressSpaceIdentity" not in dict(mmu_tlb): raise ValueError("MMU/TLB state lacks address-space identity")
    outputs, status, external = _pairs(value.get("outputs"), "outputs"), _pairs(value.get("status"), "status"), _events(value.get("externalEvents"), "external events")
    custom = dict(_pairs(value.get("observableEffects"), "observable effects"))
    builtin = {
        "c-output": _digest(outputs), "memory": _digest(_pairs(value.get("memory"), "memory")),
        "error-status": _digest(status), "termination": termination,
        "trap-to-result": _string(value, "trapToResult", "observation"), "external-events": _digest(external),
    }
    if set(builtin) & set(custom): raise ValueError("custom observable effect shadows a built-in effect")
    effects = tuple(sorted({**builtin, **custom}.items()))
    return PrivilegedMachineObservation(
        spec.runner_id, spec.runtime_version, initial_identity, csr_fields,
        privilege_mode, _pairs(value.get("trap"), "trap"),
        _string(value, "continuation", "observation"), _pairs(value.get("memory"), "memory"),
        _pairs(value.get("interrupt"), "interrupt"), mmu_tlb,
        termination, effects, external,
        _pairs(value.get("runtimeOldNewState"), "runtime old/new state"),
        _strings(value.get("ignoredState"), "ignored state"),
    )


def _execute(spec: PrivilegedRunnerSpec, request: Mapping[str, object], timeout: int,
             command_runner: CommandRunner) -> tuple[PrivilegedMachineObservation | None, str, ValidationStatus]:
    try:
        result = command_runner(spec.command, json.dumps(request, sort_keys=True), timeout)
    except OSError as exc:
        return None, "runner unavailable: " + str(exc), ValidationStatus.INCONCLUSIVE
    if result.timed_out: return None, "runner timed out", ValidationStatus.FAILED
    if result.returncode: return None, "runner failed: " + result.stderr, ValidationStatus.FAILED
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, Mapping): raise ValueError("observation root must be an object")
        observation = parse_privileged_observation(value, spec, str(request["initialStateIdentity"]))
    except (ValueError, json.JSONDecodeError) as exc:
        return None, "runner observation invalid: " + str(exc), ValidationStatus.FAILED
    return observation, "", ValidationStatus.VERIFIED


def run_l2_privileged_differential(config: L2PrivilegedRunnerConfig, **kwargs: object) -> ValidationLayerResult:
    base = run_l2_effect_trace_differential(config.base_effect_config, **kwargs)
    if base.status is not ValidationStatus.VERIFIED: return base
    if kwargs.get("comparison_policy") != config.comparison_policy:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="L2-C policy mismatch")
    for spec in (config.source_runner, config.target_runner):
        binary = spec.command[0]
        if not (Path(binary).is_file() or shutil.which(binary)):
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                         detail="L2-C runner unavailable: " + binary)
    try:
        initial = json.loads(Path(config.initial_state_path).read_text(encoding="utf-8"))
        if not isinstance(initial, Mapping): raise ValueError("initial state must be an object")
        _fields(initial, {"schemaVersion", "csrFields", "privilegeMode", "trap", "continuation", "memory",
                          "interrupt", "mmuTlb", "addressSpaceIdentity"}, "initial privileged state")
        if initial.get("schemaVersion") != PRIVILEGED_INITIAL_STATE_SCHEMA:
            raise ValueError("initial privileged state schema is unsupported")
        for name in ("csrFields", "trap", "memory", "interrupt", "mmuTlb"):
            _pairs(initial.get(name), "initial " + name)
        for name in ("privilegeMode", "continuation", "addressSpaceIdentity"):
            _string(initial, name, "initial privileged state")
        initial_identity = _digest(initial)
        manifest = load_privileged_manifest(config.privileged_manifest_path)
        routes = load_csr_route_contract(config.csr_route_contract_path)
    except OSError as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail="L2-C input unavailable: " + str(exc))
    except (ValueError, json.JSONDecodeError) as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="L2-C input invalid: " + str(exc))
    artifact = kwargs.get("translation_artifact")
    if (manifest.initial_state_identity != initial_identity or manifest.route_contract_identity != routes.identity or
            manifest.proof_identity != getattr(artifact, "proof_identity", "") or
            manifest.preservation_mode.value != getattr(getattr(artifact, "preservation_mode", None), "value", "") or
            (manifest.runtime_contract_id, manifest.runtime_contract_version) !=
            (getattr(artifact, "runtime_contract_id", ""), getattr(artifact, "runtime_contract_version", "")) or
            manifest.runtime_contract_version != config.target_runner.runtime_version):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="L2-C manifest identity mismatch")
    route_reasons = validate_csr_routes(routes, target_mode=config.target_runner.target_execution_mode,
                                        preservation_mode=manifest.preservation_mode)
    if route_reasons:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, _digest(route_reasons),
                                     json.dumps(route_reasons, separators=(",", ":")))
    request = {"schemaVersion": PRIVILEGED_RUNNER_SCHEMA, "initialState": initial,
               "initialStateIdentity": initial_identity, "preservationMode": manifest.preservation_mode.value,
               "runtimeOldNewRelationId": manifest.runtime_old_new_relation_id,
               "routeContractIdentity": routes.identity,
               "observableEffects": list(manifest.observable_effects),
               "ignoredState": list(manifest.ignored_source_state),
               "runtimeContractId": manifest.runtime_contract_id,
               "runtimeContractVersion": manifest.runtime_contract_version}
    command_runner = kwargs.get("privileged_command_runner", _run)
    if not callable(command_runner):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="L2-C command runner invalid")
    source, detail, status = _execute(config.source_runner, request, config.timeout_seconds, command_runner)
    if source is None: return ValidationLayerResult(ValidationLevel.L2, status, detail=detail)
    target, detail, status = _execute(config.target_runner, request, config.timeout_seconds, command_runner)
    if target is None: return ValidationLayerResult(ValidationLevel.L2, status, detail=detail)
    old_new_id = _digest(source.runtime_state_relation)
    if manifest.preservation_mode is DifferentialPreservationMode.STRICT and old_new_id != manifest.runtime_old_new_relation_id:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="L2-C runtime old/new relation identity mismatch")
    result = validate_privileged_differential(
        source=source, target=target,
        manifest={"preservationMode": manifest.preservation_mode.value, "proofStatus": manifest.proof_status,
                  "architectureSemanticsPreserved": manifest.architecture_semantics_preserved,
                  "microarchitectureSemanticsPreserved": manifest.microarchitecture_semantics_preserved,
                  "observableEffectsProved": manifest.observable_effects,
                  "ignoredSourceState": manifest.ignored_source_state,
                  "ignoredStateEscapes": manifest.ignored_state_escapes,
                  "proof": {"identity": manifest.proof_identity}},
        engineering_records=(), require_engineering_matrix=False,
    )
    def binary_identity(spec: PrivilegedRunnerSpec) -> str:
        resolved = Path(spec.command[0]) if Path(spec.command[0]).is_file() else Path(str(shutil.which(spec.command[0])))
        return "sha256:" + sha256(resolved.read_bytes()).hexdigest()
    evidence = _digest({"baseEvidence": base.evidence_identity, "privilegedValidation": result.validation_identity,
                        "sourceRunner": config.source_runner.__dict__, "targetRunner": config.target_runner.__dict__,
                        "sourceRunnerBinary": binary_identity(config.source_runner),
                        "targetRunnerBinary": binary_identity(config.target_runner),
                        "routeContract": routes.identity, "initialState": initial_identity,
                        "runtimeContractId": manifest.runtime_contract_id,
                        "runtimeContractVersion": manifest.runtime_contract_version})
    return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED if result.approved else ValidationStatus.FAILED,
                                 evidence, "privileged state matches" if result.approved else json.dumps(result.mismatch_codes))


def build_l2_privileged_validator(config: L2PrivilegedRunnerConfig):
    def validate(**kwargs: object) -> ValidationLayerResult:
        return run_l2_privileged_differential(config, **kwargs)
    return validate
