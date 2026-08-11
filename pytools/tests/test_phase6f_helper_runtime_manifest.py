"""Regression guards for the closed, versioned Phase-6 helper route."""
from riscv2x86_py.helper_runtime_manifest import (
    DEFAULT_RUNTIME_HELPER_CONTRACTS,
    RV64_MULHU_U64,
    RUNTIME_HELPER_MANIFEST_VERSION,
)
from riscv2x86_py.phase6d_common import HelperSemanticContractRegistry
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY


def test_shipped_helper_has_complete_non_generic_runtime_contract() -> None:
    contract = RV64_MULHU_U64
    assert contract.runtime_contract_id in DEFAULT_RUNTIME_HELPER_CONTRACTS
    assert contract.helper_symbol != "helper_unknown"
    assert contract.semantic_family == "rv64.mulhu.u64"
    assert contract.memory_effect == contract.atomic_effect == contract.barrier_effect == "none"
    assert contract.required_header == "riscv2x86_runtime_helpers.h"


def test_default_renderer_registry_requires_exact_helper_contract_id() -> None:
    assert "helper." + RV64_MULHU_U64.runtime_contract_id in GPR_INTEGER_RENDERER_CONTRACT_REGISTRY._entries
    registry = HelperSemanticContractRegistry(
        allowed_contract_ids=frozenset(DEFAULT_RUNTIME_HELPER_CONTRACTS),
        version=RUNTIME_HELPER_MANIFEST_VERSION,
        contracts=DEFAULT_RUNTIME_HELPER_CONTRACTS,
    )
    assert registry.contract(RV64_MULHU_U64.runtime_contract_id) is RV64_MULHU_U64
    assert registry.contract("helper_unknown@v1") is None
