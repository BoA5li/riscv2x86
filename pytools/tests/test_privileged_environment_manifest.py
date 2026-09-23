from __future__ import annotations

from hashlib import sha256
import json

import pytest

from riscv2x86_py.privileged_environment import (
    EnvironmentRelationKind,
    PrivilegedEnvironmentError,
    load_privileged_environment_manifest,
)


def _manifest(tmp_path, *, operation="ecall", relation="architectural_equivalence"):
    source = tmp_path / "case.c"
    source.write_text("void probe(void) {}\n", encoding="utf-8")
    for name in ("execution.json", "runtime.json"):
        (tmp_path / name).write_text("{}\n", encoding="utf-8")
    route = {
        "runtimeAdapterIdentity": "project_runtime_adapter",
        "targetMechanism": "registered-runtime-adapter",
        "preservedSemantics": ["architectural_state"],
        "notPreservedSemantics": [],
    }
    if operation == "ecall":
        route.update({
            "trapHandlerIdentity": "trap-handler:1", "sourceAbi": "rv64-service.v1",
            "serviceIdentity": "service:1", "callNumberSource": "operand:a7",
            "argumentMapping": "rv64-to-adapter-args.v1",
            "resultMapping": "adapter-to-rv64-result.v1",
            "errorRepresentation": "rv64-error.v1", "memoryEffects": "exact.v1",
            "clobbers": "rv64-ecall-clobbers.v1", "continuation": "return.v1",
            "addressSpaceRelation": "same-logical-space.v1",
        })
    else:
        route.update({
            "interruptEnableState": "mie-state.v1",
            "pendingInterruptModel": "pending.v1",
            "delegationRelation": "delegation.v1",
            "virtualizationRelation": "virtualization.v1",
            "trapWakeupContinuation": "wakeup.v1",
            "spuriousWakeupPolicy": "none.v1",
            "targetWaitAdapter": "project_runtime_adapter",
            "schedulerRuntimeInteraction": "scheduler.v1",
        })
    value = {
        "schemaVersion": "riscv2x86.privileged-environment.v1",
        "sourceDigest": "sha256:" + sha256(source.read_bytes()).hexdigest(),
        "fragmentId": "fragment:1", "operation": operation,
        "relationKind": relation,
        "sourceExecutionProfile": {
            "privilegeSpecVersion": "1.12", "initialPrivilegeMode": "u",
            "isaExtensions": ["i"], "interruptModel": "interrupt:1",
            "delegationModel": "delegation:1",
            "virtualizationModel": "virtualization:none",
            "addressSpaceIdentity": "address-space:1",
            "csrAccessPolicy": "csr-policy:1",
        },
        "runtimeContractSet": {"identity": "runtime-set", "version": "1"},
        "targetProfile": {"os": "runtime-os", "abi": "sysv", "cpuProfile": "x86-v1"},
        "routeContract": route,
        "pipelineInputs": {"executionSidecar": "execution.json", "runtimeRegistry": "runtime.json"},
    }
    path = tmp_path / "case.c.privileged-environment.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return source, path, value


def test_ecall_manifest_is_content_bound_and_uses_registered_adapter(tmp_path) -> None:
    source, path, _ = _manifest(tmp_path)
    result = load_privileged_environment_manifest(path, source=source)
    assert result.operation.value == "ecall"
    assert result.relation is EnvironmentRelationKind.ARCHITECTURAL
    assert result.runtime_adapter_identity == "project_runtime_adapter"


def test_missing_route_fact_has_precise_reason(tmp_path) -> None:
    source, path, value = _manifest(tmp_path)
    del value["routeContract"]["callNumberSource"]
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PrivilegedEnvironmentError) as caught:
        load_privileged_environment_manifest(path, source=source)
    assert caught.value.reason_code == "PRIV_ENV_ECALL_CALL_NUMBER_SOURCE_MISSING"


def test_manifest_cannot_be_copied_to_another_source(tmp_path) -> None:
    source, path, _ = _manifest(tmp_path)
    other = tmp_path / "other.c"
    other.write_text(source.read_text() + "/* different */\n", encoding="utf-8")
    with pytest.raises(PrivilegedEnvironmentError) as caught:
        load_privileged_environment_manifest(path, source=other)
    assert caught.value.reason_code == "PRIV_ENV_SOURCE_DIGEST_MISMATCH"


def test_direct_x86_syscall_is_never_assumed_equivalent(tmp_path) -> None:
    source, path, value = _manifest(tmp_path)
    value["routeContract"]["targetMechanism"] = "direct-x86-syscall"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PrivilegedEnvironmentError) as caught:
        load_privileged_environment_manifest(path, source=source)
    assert caught.value.reason_code == "PRIV_ENV_ECALL_DIRECT_SYSCALL_FORBIDDEN"


def test_wfi_functional_fallback_records_exact_preservation_boundary(tmp_path) -> None:
    source, path, value = _manifest(tmp_path, operation="wfi", relation="functional_fallback")
    value["routeContract"].update({
        "targetMechanism": "pause",
        "preservedSemantics": ["waiting_intent"],
        "notPreservedSemantics": [
            "architectural_interrupt_wakeup", "architectural_state_transition"
        ],
    })
    path.write_text(json.dumps(value), encoding="utf-8")
    result = load_privileged_environment_manifest(path, source=source)
    assert result.relation is EnvironmentRelationKind.FUNCTIONAL


def test_wfi_pause_cannot_claim_architectural_equivalence(tmp_path) -> None:
    source, path, value = _manifest(tmp_path, operation="wfi")
    value["routeContract"].update({
        "targetMechanism": "pause",
        "preservedSemantics": ["waiting_intent"],
        "notPreservedSemantics": [
            "architectural_interrupt_wakeup", "architectural_state_transition"
        ],
    })
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PrivilegedEnvironmentError) as caught:
        load_privileged_environment_manifest(path, source=source)
    assert caught.value.reason_code == "PRIV_ENV_ARCHITECTURAL_RELATION_INCOMPLETE"
