from copy import deepcopy
from hashlib import sha256
import json
import sys
from types import SimpleNamespace

import pytest

import riscv2x86_py.l2_privileged_runner as privileged
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.l2_effect_trace_differential import L2_EFFECT_RUNNER_SCHEMA, L2EffectRunnerConfig
from riscv2x86_py.l2_privileged_runner import (
    CSR_ROUTE_CONTRACT_SCHEMA, PRIVILEGED_INITIAL_STATE_SCHEMA, PRIVILEGED_MANIFEST_SCHEMA,
    PRIVILEGED_OBSERVATION_SCHEMA, CommandResult, L2PrivilegedRunnerConfig,
    PrivilegedRunnerSpec, load_csr_route_contract, run_l2_privileged_differential,
    validate_csr_routes,
)
from riscv2x86_py.privileged_differential_validation import DifferentialPreservationMode
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus
from riscv2x86_py.validation_runtime_registry import (
    VALIDATION_RUNTIME_REGISTRY_SCHEMA, validation_runtime_registry_from_dict,
)


def _digest(value):
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _initial():
    return {
        "schemaVersion": PRIVILEGED_INITIAL_STATE_SCHEMA,
        "csrFields": {"csr:mstatus.mie": "0x0"}, "privilegeMode": "m",
        "trap": {"cause": "none"}, "continuation": "pc:entry",
        "memory": {"arg:buffer": "sha256:before"}, "interrupt": {"pending": "0"},
        "mmuTlb": {"addressSpaceIdentity": "asid:1", "mode": "bare"},
        "addressSpaceIdentity": "asid:1",
    }


def _route(category="status", target_route="logical-privileged-runtime", operation="write",
           *, domain="", proof="", registered=True, write_observable=True, csr="mstatus"):
    return {
        "schemaVersion": CSR_ROUTE_CONTRACT_SCHEMA,
        "routes": [{
            "csrId": csr, "category": category, "operation": operation,
            "targetRoute": target_route, "observationDomainContractId": domain,
            "domainRelationProofIdentity": proof, "registered": registered,
            "sourceWriteObservable": write_observable,
        }],
    }


def _runner(source, *, target_mode="logical-csr-runtime"):
    if source:
        return PrivilegedRunnerSpec(("/bin/true", "source"), "qemu-system", "rv64-system",
                                    "runtime-v1", "rv64gc-system-v1", "emulator-only")
    return PrivilegedRunnerSpec(("/bin/true", "target"), "x86-logical-runtime", "x86-csr-runtime",
                                "runtime-v1", "x86-logical-csr-v1", target_mode)


def _observation(runner_id, profile, initial_identity, *, csr="0x1", ignored=()):
    return {
        "schemaVersion": PRIVILEGED_OBSERVATION_SCHEMA, "runnerId": runner_id,
        "runtimeVersion": "runtime-v1", "executionProfile": profile,
        "initialStateIdentity": initial_identity, "csrFields": {"csr:mstatus.mie": csr},
        "privilegeMode": "m", "trap": {"cause": "none", "value": "0"},
        "continuation": "pc:next", "memory": {"arg:buffer": "sha256:after"},
        "interrupt": {"pending": "0"},
        "mmuTlb": {"addressSpaceIdentity": "asid:1", "mode": "bare"},
        "termination": "normal", "outputs": {"result": "0"}, "status": {"error": "0"},
        "trapToResult": "none", "externalEvents": ["event:done"], "observableEffects": {},
        "ignoredState": list(ignored), "runtimeOldNewState": {"csr:mstatus.mie": "0x0->0x1"},
    }


def _write_inputs(tmp_path, *, mode="architecture_equivalent", route=None, ignored=()):
    initial = _initial(); initial_identity = _digest(initial)
    route_raw = route or _route(); route_path = tmp_path / "routes.json"
    route_path.write_text(json.dumps(route_raw), encoding="utf-8")
    route_identity = load_csr_route_contract(route_path).identity
    relation_identity = _digest((("csr:mstatus.mie", "0x0->0x1"),))
    strict = mode == "architecture_equivalent"
    manifest = {
        "schemaVersion": PRIVILEGED_MANIFEST_SCHEMA, "preservationMode": mode,
        "proofStatus": "approved" if strict else "functional_approved",
        "proofIdentity": "sha256:" + "7" * 64,
        "architectureSemanticsPreserved": strict, "microarchitectureSemanticsPreserved": False,
        "ignoredSourceState": list(ignored), "ignoredStateEscapes": False,
        "observableEffectsProved": [] if strict else [
            "c-output", "error-status", "external-events", "memory", "termination", "trap-to-result"],
        "routeContractIdentity": route_identity, "initialStateIdentity": initial_identity,
        "runtimeOldNewRelationId": relation_identity if strict else "",
        "runtimeContractId": "runtime-1", "runtimeContractVersion": "runtime-v1",
    }
    paths = (tmp_path / "initial.json", tmp_path / "manifest.json", route_path)
    paths[0].write_text(json.dumps(initial), encoding="utf-8")
    paths[1].write_text(json.dumps(manifest), encoding="utf-8")
    return paths, manifest, initial_identity


def _config(paths, *, target_mode="logical-csr-runtime"):
    return L2PrivilegedRunnerConfig(
        L2EffectRunnerConfig("operand-sidecar.json", "effect-sidecar.json"),
        _runner(True), _runner(False, target_mode=target_mode),
        str(paths[0]), str(paths[1]), str(paths[2]), 10,
    )


def _execute(config, manifest, initial_identity, *, target_csr="0x1", ignored=()):
    def command(argv, stdin, timeout):
        source = argv[-1] == "source"
        spec = config.source_runner if source else config.target_runner
        payload = _observation(spec.runner_id, spec.execution_profile, initial_identity,
                               csr="0x1" if source else target_csr, ignored=ignored)
        return CommandResult(0, json.dumps(payload))

    artifact = SimpleNamespace(
        proof_identity=manifest["proofIdentity"], runtime_contract_id="runtime-1",
        runtime_contract_version="runtime-v1",
        preservation_mode=(PreservationMode.ARCHITECTURE_EQUIVALENT
                           if manifest["preservationMode"] == "architecture_equivalent"
                           else PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY),
    )
    return run_l2_privileged_differential(
        config, level=ValidationLevel.L2, translation_artifact=artifact,
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        privileged_command_runner=command,
    )


@pytest.fixture(autouse=True)
def _verified_l2ab(monkeypatch):
    monkeypatch.setattr(privileged, "run_l2_effect_trace_differential", lambda config, **kwargs:
                        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED,
                                              "sha256:" + "1" * 64))


def test_real_runner_protocol_strictly_compares_complete_privileged_state(tmp_path):
    paths, manifest, initial_identity = _write_inputs(tmp_path)
    result = _execute(_config(paths), manifest, initial_identity, target_csr="0x1")
    assert result.status is ValidationStatus.VERIFIED
    assert result.evidence_identity.startswith("sha256:")

    mismatch = _execute(_config(paths), manifest, initial_identity, target_csr="0x0")
    assert mismatch.status is ValidationStatus.FAILED
    assert "strict-csr-mismatch" in mismatch.detail


def test_fallback_compares_only_required_projection_and_declared_non_escaping_state(tmp_path):
    ignored = ("csr:cycle-rate",)
    route = _route("time", "monotonic-time-adapter", "read", domain="monotonic-domain-v1",
                   csr="time", write_observable=False)
    paths, manifest, initial_identity = _write_inputs(
        tmp_path, mode="functional_equivalence_only", route=route, ignored=ignored)
    result = _execute(_config(paths, target_mode="ordinary-user-process"), manifest,
                      initial_identity, target_csr="0x9", ignored=ignored)
    assert result.status is ValidationStatus.VERIFIED

    escaped = deepcopy(manifest); escaped["ignoredStateEscapes"] = True
    paths[1].write_text(json.dumps(escaped), encoding="utf-8")
    assert _execute(_config(paths, target_mode="ordinary-user-process"), escaped,
                    initial_identity, ignored=ignored).status is ValidationStatus.FAILED


@pytest.mark.parametrize("route,target_mode,expected", [
    (_route("cycle", "counter-domain-adapter", "read", domain="cycle-domain", csr="cycle"),
     "ordinary-user-process", "cycle-domain-relation-unproved"),
    (_route("instret", "counter-domain-adapter", "read", csr="instret"),
     "ordinary-user-process", "target-route-mode-invalid"),
    (_route("mmu", "mmu-adapter", "write", csr="satp"),
     "ordinary-user-process", "target-route-mode-invalid"),
    (_route("custom", "custom-registered-runtime", "read", registered=False, csr="custom:7c0"),
     "logical-csr-runtime", "custom-csr-unregistered"),
    (_route("status", "logical-privileged-runtime", "write", write_observable=False),
     "logical-csr-runtime", "source-write-observable-effect-unpreserved"),
])
def test_csr_category_route_and_execution_mode_are_hard_constraints(tmp_path, route, target_mode, expected):
    path = tmp_path / "route.json"; path.write_text(json.dumps(route), encoding="utf-8")
    reasons = validate_csr_routes(load_csr_route_contract(path), target_mode=target_mode,
                                  preservation_mode=DifferentialPreservationMode.STRICT)
    assert any(expected in item for item in reasons)


def test_system_or_vmm_adapter_cannot_be_claimed_by_ordinary_x86_process():
    with pytest.raises(ValueError):
        PrivilegedRunnerSpec(("runner",), "x86-logical-runtime", "fake-vmm", "v1",
                             "x86-user", "vmm-adapter")


def test_timeout_and_malformed_observation_are_failed_not_skipped(tmp_path):
    paths, manifest, initial_identity = _write_inputs(tmp_path)
    config = _config(paths)
    artifact = SimpleNamespace(proof_identity=manifest["proofIdentity"], runtime_contract_id="runtime-1",
                               runtime_contract_version="runtime-v1",
                               preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT)
    timeout = run_l2_privileged_differential(
        config, level=ValidationLevel.L2, translation_artifact=artifact,
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        privileged_command_runner=lambda *args: CommandResult(-1, timed_out=True),
    )
    assert timeout.status is ValidationStatus.FAILED
    malformed = run_l2_privileged_differential(
        config, level=ValidationLevel.L2, translation_artifact=artifact,
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        privileged_command_runner=lambda *args: CommandResult(0, "{}"),
    )
    assert malformed.status is ValidationStatus.FAILED


def test_runner_protocol_executes_a_real_subprocess(tmp_path):
    script = tmp_path / "privileged_harness.py"
    template = _observation("placeholder", "placeholder", "placeholder")
    script.write_text(
        "import json,sys\n"
        f"value=json.loads({json.dumps(json.dumps(template))})\n"
        "request=json.load(sys.stdin)\n"
        "value['runnerId']='rv64-system'\n"
        "value['executionProfile']='rv64gc-system-v1'\n"
        "value['initialStateIdentity']=request['initialStateIdentity']\n"
        "json.dump(value,sys.stdout,sort_keys=True)\n",
        encoding="utf-8",
    )
    spec = PrivilegedRunnerSpec((sys.executable, str(script)), "controlled-linux-guest", "rv64-system",
                                "runtime-v1", "rv64gc-system-v1", "emulator-only")
    initial_identity = _digest(_initial())
    observation, detail, status = privileged._execute(
        spec, {"initialStateIdentity": initial_identity}, 10, privileged._run)
    assert status is ValidationStatus.VERIFIED
    assert detail == "" and observation is not None
    assert observation.initial_state_id == initial_identity


def test_runtime_registry_exposes_composite_l2c_as_the_single_l2_runner(tmp_path):
    paths, _, _ = _write_inputs(tmp_path)
    runner = lambda source: {
        "command": ["/bin/true", "source" if source else "target"],
        "runnerKind": "qemu-system" if source else "x86-logical-runtime",
        "runnerId": "rv64-system" if source else "x86-csr-runtime",
        "runtimeVersion": "runtime-v1",
        "executionProfile": "rv64gc-system-v1" if source else "x86-logical-csr-v1",
        "targetExecutionMode": "emulator-only" if source else "logical-csr-runtime",
    }
    registry = validation_runtime_registry_from_dict({
        "schemaVersion": VALIDATION_RUNTIME_REGISTRY_SCHEMA, "version": "registry-v1",
        "validators": {"L2": {"type": "l2-privileged-real-runner", "config": {
            "schemaVersion": "riscv2x86.l2-privileged-runner.v1",
            "comparisonPolicy": ARCHITECTURAL_COMPARISON_POLICY,
            "baseEffectRunner": {
                "schemaVersion": L2_EFFECT_RUNNER_SCHEMA,
                "operandAuthoritySidecarPath": "operands.json",
                "effectAuthoritySidecarPath": "effects.json",
                "comparisonPolicy": ARCHITECTURAL_COMPARISON_POLICY,
            },
            "sourceRunner": runner(True), "targetRunner": runner(False),
            "initialStatePath": str(paths[0]), "privilegedManifestPath": str(paths[1]),
            "csrRouteContractPath": str(paths[2]), "timeoutSeconds": 10,
        }}},
    })
    assert registry.validator_for(ValidationLevel.L2) is not None
