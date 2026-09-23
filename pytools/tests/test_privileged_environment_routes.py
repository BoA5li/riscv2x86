from __future__ import annotations

import pytest

from riscv2x86_py.privileged_runtime_contracts import (
    PrivilegedEnvironmentRouteKind,
    PrivilegedEnvironmentRelationKind,
    PrivilegedRuntimeContract,
)


def _contract(**overrides):
    values = dict(
        contract_id="environment-route",
        semantic_version="1",
        source_privileged_identity="sha256:source",
        target_environment_id="x86_64:sysv:gnu",
        runtime_symbol="runtime_adapter",
        callable_identifier="runtime_adapter",
        required_target_capability="environment-adapter",
        required_capabilities=("environment-adapter",),
    )
    values.update(overrides)
    return PrivilegedRuntimeContract(**values)


def test_generic_contract_does_not_implicitly_claim_ecall_or_wfi() -> None:
    contract = _contract()
    assert contract.environment_route_kind is PrivilegedEnvironmentRouteKind.GENERIC
    assert contract.environment_contract_id == "generic-privileged-environment.v1"


def test_ecall_requires_an_explicit_environment_identity_and_service_abi() -> None:
    with pytest.raises(ValueError, match="explicit service ABI"):
        _contract(
            environment_route_kind=PrivilegedEnvironmentRouteKind.ECALL,
            environment_contract_id="linux-rv64-ecall-to-runtime.v1",
        )

    contract = _contract(
        environment_route_kind=PrivilegedEnvironmentRouteKind.ECALL,
        environment_contract_id="linux-rv64-ecall-to-runtime.v1",
        abi_contract_id="linux-rv64-syscall-service-abi.v1",
    )
    assert contract.environment_route_kind is PrivilegedEnvironmentRouteKind.ECALL
    assert contract.environment_contract_id == "linux-rv64-ecall-to-runtime.v1"


def test_wfi_contract_must_preserve_wait_intent() -> None:
    with pytest.raises(ValueError, match="preserve wait intent"):
        _contract(
            environment_route_kind=PrivilegedEnvironmentRouteKind.WFI,
            environment_contract_id="machine-wfi-event-loop.v1",
            preserves_microarchitecture_intent=False,
        )

    contract = _contract(
        environment_route_kind=PrivilegedEnvironmentRouteKind.WFI,
        environment_contract_id="machine-wfi-event-loop.v1",
        preserves_microarchitecture_intent=True,
    )
    assert contract.environment_route_kind is PrivilegedEnvironmentRouteKind.WFI


def test_strict_registry_contract_cannot_encode_a_functional_environment_relation() -> None:
    with pytest.raises(ValueError, match="functional relations belong"):
        _contract(
            environment_relation_kind=PrivilegedEnvironmentRelationKind.FUNCTIONAL_FALLBACK,
        )


def test_architectural_contract_cannot_list_unpreserved_semantics() -> None:
    with pytest.raises(ValueError, match="cannot omit semantics"):
        _contract(not_preserved_environment_semantics=("interrupt-wakeup",))
