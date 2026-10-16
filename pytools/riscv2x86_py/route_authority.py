"""Content-bound diagnostic decisions. These records never grant authority."""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Mapping
from .semantic_authority import SemanticAuthorityError

SCHEMA = "riscv2x86.route-authority-decision.v1"


def content_identity(value: object) -> str:
    return "sha256:" + sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


@dataclass(frozen=True)
class RouteAuthorityDecision:
    route: str
    fragment_id: str
    stage: str
    reason_code: str
    detail: str
    inputs_identity: str
    accepted: bool = False
    inputs_payload: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        payload = {"schemaVersion": SCHEMA, "route": self.route,
            "fragmentIdentity": self.fragment_id, "failureStage": self.stage,
            "reasonCode": self.reason_code, "detail": self.detail,
            "inputsIdentity": self.inputs_identity, "accepted": self.accepted,
            "inputsPayload": dict(self.inputs_payload)}
        payload["decisionIdentity"] = content_identity(payload)
        validate_route_decision(payload)
        return payload


def validate_route_decision(value: Mapping) -> None:
    fields = {"schemaVersion", "route", "fragmentIdentity", "failureStage",
        "reasonCode", "detail", "inputsIdentity", "inputsPayload", "accepted", "decisionIdentity"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("route decision fields invalid")
    if (value["schemaVersion"] != SCHEMA or type(value["accepted"]) is not bool
            or not all(isinstance(value[k], str) and value[k] for k in
                fields - {"schemaVersion", "accepted", "decisionIdentity", "inputsPayload"})):
        raise ValueError("route decision payload invalid")
    if not isinstance(value["inputsPayload"], Mapping) or content_identity(value["inputsPayload"]) != value["inputsIdentity"]:
        raise ValueError("route decision inputs identity mismatch")
    if value["decisionIdentity"] != content_identity({k:v for k,v in value.items()
                                                     if k != "decisionIdentity"}):
        raise ValueError("route decision identity mismatch")
    import re
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value["inputsIdentity"]) is None:
        raise ValueError("route decision input identity invalid")


class AtomicAuthorityError(SemanticAuthorityError):
    """Field-level rejection with stable stage/code, independent of prose."""
    def __init__(self, reason_code: str, detail: str, stage="atomic_compiler_join"):
        super().__init__(detail)
        self.reason_code, self.failure_stage = reason_code, stage
