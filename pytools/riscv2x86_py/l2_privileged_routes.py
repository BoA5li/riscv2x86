"""Typed, fail-closed CSR authority and privileged route selection."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Mapping

from .l2_dimensions import L2ClaimScope


CSR_AUTHORITY_SCHEMA = "riscv2x86.l2-csr-authority.v1"
PRIVILEGED_ROUTE_SELECTION_SCHEMA = "riscv2x86.l2-privileged-route-selection.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACCESS = {"read", "write", "read_write"}
_PRIVILEGES = {"u", "s", "vs", "hs", "m"}
_PRIVILEGE_RANK = {"u": 0, "s": 1, "vs": 1, "hs": 2, "m": 3}
_RUNTIME_PROPERTIES = {"monotonicity", "progress", "declared-return-relation"}
_FORBIDDEN_RUNTIME_CLAIMS = {
    "absolute-value-equivalence", "epoch-equivalence",
    "frequency-equivalence", "resolution-equivalence",
}


def canonical_identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(encoded).hexdigest()


class L2PrivilegedRouteKind(str, Enum):
    ARCHITECTURAL_DIRECT = "architectural_direct"
    APPROVED_RUNTIME_MEDIATED = "approved_runtime_mediated"
    DIAGNOSTIC_ONLY = "diagnostic_only"
    NEEDS_ROUTE = "needs_route"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class L2CsrAuthority:
    csr_identity: str
    access_kind: str
    required_privilege: str
    observable_properties: tuple[str, ...]
    ignored_properties: tuple[str, ...]
    environment_identity: str
    runtime_contract_identity: str
    ignored_properties_escape: bool
    complete: bool
    authority_identity: str

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2CsrAuthority":
        fields = {
            "schemaVersion", "csrIdentity", "accessKind", "requiredPrivilege",
            "observableProperties", "ignoredProperties", "environmentIdentity",
            "runtimeContractIdentity", "ignoredPropertiesEscape", "complete",
            "authorityIdentity",
        }
        if set(value) != fields or value.get("schemaVersion") != CSR_AUTHORITY_SCHEMA:
            raise ValueError("CSR authority schema or fields are invalid")
        payload = dict(value)
        identity = payload.pop("authorityIdentity")
        for name in ("csrIdentity", "accessKind", "requiredPrivilege",
                     "environmentIdentity", "runtimeContractIdentity"):
            if not isinstance(value.get(name), str) or not value[name]:
                raise ValueError("CSR authority lacks " + name)
        access = str(value["accessKind"]); privilege = str(value["requiredPrivilege"])
        if access not in _ACCESS or privilege not in _PRIVILEGES:
            raise ValueError("CSR authority access/privilege is unsupported")
        def strings(name: str) -> tuple[str, ...]:
            raw = value.get(name)
            if not isinstance(raw, list) or not all(isinstance(x, str) and x for x in raw):
                raise ValueError("CSR authority " + name + " must be a string array")
            result = tuple(raw)
            if result != tuple(sorted(set(result))):
                raise ValueError("CSR authority " + name + " is not canonical")
            return result
        observable = strings("observableProperties")
        ignored = strings("ignoredProperties")
        if set(observable) & set(ignored):
            raise ValueError("CSR observable and ignored properties overlap")
        if not isinstance(value.get("ignoredPropertiesEscape"), bool) or not isinstance(value.get("complete"), bool):
            raise ValueError("CSR authority completeness/escape flags are invalid")
        for name in ("environmentIdentity", "runtimeContractIdentity"):
            if not _SHA256.fullmatch(str(value[name])):
                raise ValueError("CSR authority " + name + " is invalid")
        if identity != canonical_identity(payload):
            raise ValueError("CSR authority identity does not match content")
        return cls(str(value["csrIdentity"]), access, privilege, observable, ignored,
                   str(value["environmentIdentity"]), str(value["runtimeContractIdentity"]),
                   bool(value["ignoredPropertiesEscape"]), bool(value["complete"]), str(identity))


@dataclass(frozen=True)
class L2PrivilegedRouteSelection:
    route_kind: L2PrivilegedRouteKind
    claim_scope: L2ClaimScope
    authority_identity: str
    reason_codes: tuple[str, ...]
    selection_identity: str

    @property
    def executable(self) -> bool:
        return self.route_kind in {
            L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT,
            L2PrivilegedRouteKind.APPROVED_RUNTIME_MEDIATED,
            L2PrivilegedRouteKind.DIAGNOSTIC_ONLY,
        }


def select_privileged_route(*, authority: L2CsrAuthority,
                            requested_kind: L2PrivilegedRouteKind,
                            actual_environment_identity: str,
                            actual_runtime_contract_identity: str,
                            actual_privilege: str,
                            adapter_registered: bool,
                            target_route_supported: bool) -> L2PrivilegedRouteSelection:
    reasons: list[str] = []
    kind = requested_kind
    if requested_kind is L2PrivilegedRouteKind.NEEDS_ROUTE:
        reasons.append("l2.privileged.route-not-registered")
    elif requested_kind is L2PrivilegedRouteKind.UNSUPPORTED:
        reasons.append("l2.privileged.route-unsupported")
    if not authority.complete:
        reasons.append("l2.privileged.authority-incomplete")
        kind = L2PrivilegedRouteKind.NEEDS_ROUTE
    if authority.ignored_properties_escape:
        reasons.append("l2.privileged.ignored-state-escapes")
        kind = L2PrivilegedRouteKind.NEEDS_ROUTE
    if authority.environment_identity != actual_environment_identity:
        reasons.append("l2.privileged.environment-identity-mismatch")
        kind = L2PrivilegedRouteKind.NEEDS_ROUTE
    if authority.runtime_contract_identity != actual_runtime_contract_identity:
        reasons.append("l2.privileged.runtime-contract-mismatch")
        kind = L2PrivilegedRouteKind.NEEDS_ROUTE
    if actual_privilege not in _PRIVILEGES or _PRIVILEGE_RANK.get(actual_privilege, -1) < _PRIVILEGE_RANK[authority.required_privilege]:
        reasons.append("l2.privileged.insufficient-privilege")
        kind = L2PrivilegedRouteKind.NEEDS_ROUTE
    if not adapter_registered:
        reasons.append("l2.privileged.adapter-unregistered")
        kind = L2PrivilegedRouteKind.NEEDS_ROUTE
    if not target_route_supported:
        reasons.append("l2.privileged.target-route-unsupported")
        kind = L2PrivilegedRouteKind.UNSUPPORTED
    if requested_kind is L2PrivilegedRouteKind.APPROVED_RUNTIME_MEDIATED:
        invalid = set(authority.observable_properties) - _RUNTIME_PROPERTIES
        forbidden = set(authority.observable_properties) & _FORBIDDEN_RUNTIME_CLAIMS
        if invalid or forbidden:
            reasons.append("l2.privileged.runtime-mediated-claim-out-of-scope")
            kind = L2PrivilegedRouteKind.NEEDS_ROUTE
    scope = {
        L2PrivilegedRouteKind.ARCHITECTURAL_DIRECT: L2ClaimScope.ARCHITECTURAL,
        L2PrivilegedRouteKind.APPROVED_RUNTIME_MEDIATED: L2ClaimScope.APPROVED_FUNCTIONAL_RELATION,
        L2PrivilegedRouteKind.DIAGNOSTIC_ONLY: L2ClaimScope.DIAGNOSTIC_ONLY,
    }.get(kind, L2ClaimScope.NONE)
    payload = {
        "schemaVersion": PRIVILEGED_ROUTE_SELECTION_SCHEMA,
        "routeKind": kind.value, "claimScope": scope.value,
        "authorityIdentity": authority.authority_identity,
        "reasonCodes": sorted(set(reasons)),
    }
    return L2PrivilegedRouteSelection(kind, scope, authority.authority_identity,
                                      tuple(payload["reasonCodes"]), canonical_identity(payload))
