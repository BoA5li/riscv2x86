from __future__ import annotations

from hashlib import sha256
import json

import pytest

from riscv2x86_py.csr_environment_contract import (
    CsrEnvironmentContractError,
    load_csr_environment_contract,
)
from riscv2x86_py.automatic_translation_command import _identity


def _contract(tmp_path, *, relation="architectural-equivalence"):
    source = tmp_path / "case_029.c"
    source.write_text("unsigned long f(void){return 0;}\n", encoding="utf-8")
    exact = relation == "architectural-equivalence"
    value = {
        "schemaVersion": "riscv2x86.csr-environment-contract.v1",
        "sourceDigest": "sha256:" + sha256(source.read_bytes()).hexdigest(),
        "fragmentId": "fragment:csr-time", "relationKind": relation,
        "runtimeRegistry": {
            "registryVersion": "counter-registry.v1", "runtimeVersion": "v1",
            "executionProfile": "user", "shellTransportable": True,
            "externalStateComplete": True,
            "mapping": {
                "sourceEffectId": "effect:time", "sourceCsrId": "riscv.csr.time",
                "targetStateObjectId": "runtime:time", "targetOperationId": "read-time",
                "stateLifetimeId": "process", "readResultMapping": "runtime-result",
                "writeValueMapping": None, "fieldMappings": ["riscv.csr.time.all"],
                "oldNewStateRelationId": "observation-only", "accessPolicyMappingId": "counter-policy",
                "deniedAccessTrapMappingId": None, "sideEffectMappingIds": [],
                "orderingRelationId": "counter-read-order.v1",
            },
            "counterContract": {
                "contractId": "time-contract.v1", "relationKind": relation,
                "sourceEpoch": "riscv-time-epoch",
                "targetEpoch": "riscv-time-epoch" if exact else "monotonic-runtime-epoch",
                "frequencyHz": 10000000, "scaleNumerator": 1,
                "scaleDenominator": 1 if exact else 10, "monotonicity": "monotonic",
                "wraparoundBits": 64, "scope": "hart",
                "migrationBehavior": "source-hart-stable" if exact else "thread-monotonic",
                "serialization": "source-defined", "targetObservationMechanism": "registered-runtime-call",
                "errorBoundTicks": 0 if exact else 100, "availabilityPolicy": "runtime-checked",
                "trapPolicy": "runtime-reported", "complete": True,
            },
        },
        "rendererRegistry": {
            "registryVersion": "counter-renderer.v1", "targetOperationId": "read-time",
            "recipe": {
                "recipeId": "read-time.v1", "callableIdentifier": "rv2x86_csr_read",
                "csrToken": "RV2X86_CSR_TIME", "contextExpression": "ctx",
                "inputExpression": None, "outputExpression": "out",
                "requiredHeader": "riscv2x86_csr_runtime.h",
                "requiredLibrary": "riscv2x86_csr_runtime", "runtimeVersion": "v1",
                "trapResultPolicy": "no-trap-observation", "approved": True,
            },
        },
    }
    value["contractIdentity"] = _identity(value)
    path = tmp_path / "case_029.c.csr-environment.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return source, path, value


def test_complete_counter_contract_materializes_production_registries(tmp_path):
    source, path, _ = _contract(tmp_path)
    loaded = load_csr_environment_contract(path, source=source)
    assert loaded.fragment_id == "fragment:csr-time"
    assert loaded.runtime_registry.mappings[0].counter_contract_identity == "time-contract.v1"
    assert "read-time" in loaded.renderer_registry.recipes_by_target_operation


def test_contract_is_source_content_bound(tmp_path):
    source, path, _ = _contract(tmp_path)
    source.write_text(source.read_text() + "/* changed */\n", encoding="utf-8")
    with pytest.raises(CsrEnvironmentContractError) as caught:
        load_csr_environment_contract(path, source=source)
    assert caught.value.reason_code == "CSR_ENV_SOURCE_DIGEST_MISMATCH"


def test_counter_and_route_relation_must_match(tmp_path):
    source, path, value = _contract(tmp_path)
    value["runtimeRegistry"]["counterContract"]["relationKind"] = "functional-monotonic-observation"
    value["contractIdentity"] = _identity({key: item for key, item in value.items()
                                           if key != "contractIdentity"})
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(CsrEnvironmentContractError) as caught:
        load_csr_environment_contract(path, source=source)
    assert caught.value.reason_code == "CSR_ENV_COUNTER_RELATION_MISMATCH"


def test_architectural_counter_cannot_hide_scale_or_epoch_change(tmp_path):
    source, path, value = _contract(tmp_path)
    value["runtimeRegistry"]["counterContract"]["scaleDenominator"] = 10
    value["contractIdentity"] = _identity({key: item for key, item in value.items()
                                           if key != "contractIdentity"})
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="exact epoch, scale, and value"):
        load_csr_environment_contract(path, source=source)


def test_unapproved_renderer_recipe_fails_closed(tmp_path):
    source, path, value = _contract(tmp_path)
    value["rendererRegistry"]["recipe"]["approved"] = False
    value["contractIdentity"] = _identity({key: item for key, item in value.items()
                                           if key != "contractIdentity"})
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(CsrEnvironmentContractError) as caught:
        load_csr_environment_contract(path, source=source)
    assert caught.value.reason_code == "CSR_ENV_RECIPE_NOT_APPROVED"


def test_contract_payload_is_content_addressed(tmp_path):
    source, path, value = _contract(tmp_path)
    value["runtimeRegistry"]["mapping"]["orderingRelationId"] = "changed"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(CsrEnvironmentContractError) as caught:
        load_csr_environment_contract(path, source=source)
    assert caught.value.reason_code == "CSR_ENV_CONTRACT_IDENTITY_MISMATCH"
