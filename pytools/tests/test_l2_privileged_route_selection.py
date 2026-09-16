from hashlib import sha256
import json

import pytest
from types import SimpleNamespace

from riscv2x86_py.l2_dimensions import L2ClaimScope
from riscv2x86_py.l2_privileged_routes import (
    CSR_AUTHORITY_SCHEMA, L2CsrAuthority, L2PrivilegedRouteKind,
    canonical_identity, select_privileged_route,
)
from riscv2x86_py.l2_privileged_runner import (
    CSR_ROUTE_CONTRACT_SCHEMA_V2, load_csr_route_contract,
)
from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_runtime_registry import _result_claim_scope
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


def _authority(*, privilege="u", observable=("csr-value",), ignored=(),
               escape=False, environment=None, runtime_id="runtime-1",
               runtime_version="runtime-v1"):
    environment = {"environmentId": "env-1"} if environment is None else environment
    payload = {
        "schemaVersion": CSR_AUTHORITY_SCHEMA,
        "csrIdentity": "csr:time", "accessKind": "read",
        "requiredPrivilege": privilege,
        "observableProperties": sorted(observable),
        "ignoredProperties": sorted(ignored),
        "environmentIdentity": canonical_identity(environment),
        "runtimeContractIdentity": canonical_identity({
            "runtimeContractId": runtime_id,
            "runtimeContractVersion": runtime_version,
        }),
        "ignoredPropertiesEscape": escape, "complete": True,
    }
    payload["authorityIdentity"] = canonical_identity(payload)
    return payload


def _select(authority, kind, **overrides):
    args = {
        "authority": L2CsrAuthority.from_dict(authority),
        "requested_kind": kind,
        "actual_environment_identity": authority["environmentIdentity"],
        "actual_runtime_contract_identity": authority["runtimeContractIdentity"],
        "actual_privilege": "m", "adapter_registered": True,
        "target_route_supported": True,
    }
    args.update(overrides)
    return select_privileged_route(**args)


def test_environment_matched_architectural_route_is_typed_and_executable():
    result = _select(_authority(), L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT)
    assert result.executable
    assert result.route_kind is L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT
    assert result.claim_scope is L2ClaimScope.ARCHITECTURAL
    assert result.reason_codes == ()


def test_runtime_mediated_time_claim_is_functional_and_strictly_bounded():
    authority = _authority(
        observable=("declared-return-relation", "monotonicity", "progress"),
        ignored=("absolute-value-equivalence", "epoch-equivalence",
                 "frequency-equivalence", "resolution-equivalence"),
    )
    result = _select(authority, L2PrivilegedRouteKind.APPROVED_RUNTIME_MEDIATED)
    assert result.executable
    assert result.claim_scope is L2ClaimScope.APPROVED_FUNCTIONAL_RELATION

    overclaim = _authority(observable=("absolute-value-equivalence", "monotonicity"))
    rejected = _select(overclaim, L2PrivilegedRouteKind.APPROVED_RUNTIME_MEDIATED)
    assert not rejected.executable
    assert "l2.privileged.runtime-mediated-claim-out-of-scope" in rejected.reason_codes


def test_runtime_version_environment_and_privilege_mismatch_are_inconclusive_routes():
    authority = _authority(privilege="m")
    runtime = _select(
        authority, L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT,
        actual_runtime_contract_identity="sha256:" + "0" * 64,
    )
    assert runtime.route_kind is L2PrivilegedRouteKind.NEEDS_ROUTE
    assert "l2.privileged.runtime-contract-mismatch" in runtime.reason_codes
    environment = _select(
        authority, L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT,
        actual_environment_identity="sha256:" + "1" * 64,
    )
    assert "l2.privileged.environment-identity-mismatch" in environment.reason_codes
    privilege = _select(
        authority, L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT,
        actual_privilege="u",
    )
    assert "l2.privileged.insufficient-privilege" in privilege.reason_codes


def test_diagnostic_scope_cannot_enter_architectural_numerator_and_escape_rejects_verified():
    diagnostic = _select(_authority(), L2PrivilegedRouteKind.DIAGNOSTIC_ONLY)
    assert diagnostic.executable
    assert diagnostic.claim_scope is L2ClaimScope.DIAGNOSTIC_ONLY
    escaped = _select(
        _authority(ignored=("csr:implementation-state",), escape=True),
        L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT,
    )
    assert not escaped.executable
    assert escaped.claim_scope is L2ClaimScope.NONE
    assert "l2.privileged.ignored-state-escapes" in escaped.reason_codes

    validator_result = ValidationLayerResult(
        ValidationLevel.L2, ValidationStatus.VERIFIED, "sha256:" + "2" * 64,
        json.dumps({"claimScope": "diagnostic_only"}),
    )
    artifact = SimpleNamespace(preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT)
    assert _result_claim_scope(validator_result, artifact) is L2ClaimScope.DIAGNOSTIC_ONLY


def test_v2_route_contract_binds_typed_authority_without_filename_inference(tmp_path):
    authority = _authority()
    value = {
        "schemaVersion": CSR_ROUTE_CONTRACT_SCHEMA_V2,
        "routes": [{
            "csrId": "csr:time", "category": "time", "operation": "read",
            "targetRoute": "monotonic-time-adapter",
            "observationDomainContractId": "monotonic-domain-v1",
            "domainRelationProofIdentity": "", "registered": True,
            "sourceWriteObservable": False,
            "routeKind": "approved_runtime_mediated",
            "csrAuthority": authority,
        }],
    }
    path = tmp_path / "arbitrary-name.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    parsed = load_csr_route_contract(path)
    assert parsed.routes[0].authority.authority_identity == authority["authorityIdentity"]

    stale = json.loads(json.dumps(value))
    stale["routes"][0]["csrAuthority"]["requiredPrivilege"] = "m"
    path.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(ValueError, match="identity"):
        load_csr_route_contract(path)
