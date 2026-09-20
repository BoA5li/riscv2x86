"""Strict L3 dynamic trace protocol. An observer must attest the bounded binary region.

These records are produced by registered source/target observers; they are never
inferred from C text or reconstructed from output values.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Mapping

TRACE_CONTRACT_SCHEMA = "riscv2x86.l3-attributed-trace-contract.v1"
LOGICAL_TRACE_SCHEMA = "riscv2x86.l3-logical-trace.v1"
MACHINE_TRACE_SCHEMA = "riscv2x86.l3-machine-region-trace.v1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MEMORY = {"ReadMemory", "WriteMemory"}
_CONTROL = {"Branch", "ControlTransfer", "BasicBlock", "LoopIteration"}
_MACHINE = _MEMORY | {"Call", "Fence", "Atomic", "Branch", "ControlTransfer"}


def _fields(obj, names, label):
    if not isinstance(obj, Mapping) or set(obj) != names:
        raise ValueError(label + " fields incomplete or unknown")


def _hash(value, label):
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError(label + " identity invalid")
    return value


def _str(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(label + " must be a nonempty string")
    return value


def _int(value, label, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(label + " must be a nonnegative integer")
    return value


def _complete(value, label):
    if value is not True:
        raise ValueError(label + " completeness not attested")


def identity(value):
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_trace_contract(raw):
    _fields(raw, {"schemaVersion", "authorityIdentity", "fragmentId", "sourceEffectIds", "memoryObjects",
                  "sourceRegion", "targetRegion", "complete"}, "trace contract")
    if raw["schemaVersion"] != TRACE_CONTRACT_SCHEMA:
        raise ValueError("trace contract schema unsupported")
    _complete(raw["complete"], "trace contract")
    _hash(raw["authorityIdentity"], "authority")
    _str(raw["fragmentId"], "fragmentId")
    effects = raw["sourceEffectIds"]
    if (not isinstance(effects, list) or not effects or
            any(not isinstance(e, str) or not e for e in effects) or effects != sorted(set(effects))):
        raise ValueError("source authority effect IDs missing or noncanonical")
    objects = raw["memoryObjects"]
    if not isinstance(objects, list) or not objects:
        raise ValueError("memory objects missing")
    seen = set()
    for obj in objects:
        _fields(obj, {"objectId", "sizeBytes", "minimumAlignment", "complete"}, "memory object")
        name = _str(obj["objectId"], "objectId")
        if name in seen:
            raise ValueError("duplicate memory object")
        seen.add(name)
        _int(obj["sizeBytes"], "sizeBytes", 1)
        _int(obj["minimumAlignment"], "minimumAlignment", 1)
        _complete(obj["complete"], "memory object")
    for side in ("source", "target"):
        region = raw[side + "Region"]
        _fields(region, {"regionIdentity", "binaryDigest", "entryIdentity", "compilerId",
                         "compilerVersion", "optimizationLevel", "abi", "captureProofIdentity",
                         "observerBinaryDigest", "approvedExclusions", "complete"}, side + " region")
        for field in ("regionIdentity", "binaryDigest", "captureProofIdentity", "observerBinaryDigest"):
            _hash(region[field], side + "." + field)
        for field in ("entryIdentity", "compilerId", "compilerVersion", "optimizationLevel", "abi"):
            _str(region[field], side + "." + field)
        _complete(region["complete"], side + " region")
        exclusions = region["approvedExclusions"]
        if not isinstance(exclusions, list):
            raise ValueError("approved exclusions must be a list")
        ids = set()
        for item in exclusions:
            _fields(item, {"eventId", "eventKind", "attributionKind", "proofIdentity"}, "exclusion")
            eid = _str(item["eventId"], "excluded event ID")
            if eid in ids or item["eventKind"] not in _MACHINE or item["attributionKind"] not in {"compiler_artifact", "runtime_helper"}:
                raise ValueError("ambiguous exclusion")
            ids.add(eid)
            _hash(item["proofIdentity"], "exclusion proof")
    return dict(raw)


def parse_logical_trace(raw, contract):
    _fields(raw, {"schemaVersion", "authorityIdentity", "fragmentId", "complete", "events"}, "logical trace")
    if raw["schemaVersion"] != LOGICAL_TRACE_SCHEMA or raw["authorityIdentity"] != contract["authorityIdentity"] or raw["fragmentId"] != contract["fragmentId"]:
        raise ValueError("logical trace authority/fragment/schema mismatch")
    _complete(raw["complete"], "logical trace")
    events = raw["events"]
    if not isinstance(events, list):
        raise ValueError("logical events missing")
    ids = set()
    objects = {obj["objectId"]: obj for obj in contract["memoryObjects"]}
    for order, event in enumerate(events):
        _fields(event, {"eventId", "sourceEffectId", "executionOrder", "eventKind", "payload", "orderingPredecessors"}, "logical event")
        eid = _str(event["eventId"], "eventId")
        if _str(event["sourceEffectId"], "sourceEffectId") not in contract["sourceEffectIds"]:
            raise ValueError("logical event not in approved source authority effects")
        if eid in ids or _int(event["executionOrder"], "executionOrder") != order:
            raise ValueError("duplicate or noncanonical logical event order")
        kind = event["eventKind"]
        if kind not in _MEMORY | _CONTROL:
            raise ValueError("unknown logical event kind")
        predecessors = event["orderingPredecessors"]
        if not isinstance(predecessors, list) or len(predecessors) != len(set(predecessors)) or any(p not in ids for p in predecessors):
            raise ValueError("logical predecessor missing, cyclic or duplicated")
        ids.add(eid)
        payload = event["payload"]
        if kind in _MEMORY:
            _fields(payload, {"objectId", "offset", "size", "alignment", "atomicity", "memoryOrder"}, "memory payload")
            obj = objects.get(payload["objectId"])
            offset = _int(payload["offset"], "offset")
            size = _int(payload["size"], "size", 1)
            alignment = _int(payload["alignment"], "alignment", 1)
            if obj is None or offset + size > obj["sizeBytes"] or alignment < obj["minimumAlignment"] or offset % alignment:
                raise ValueError("memory object bounds/alignment attribution invalid")
            _str(payload["atomicity"], "atomicity")
            _str(payload["memoryOrder"], "memoryOrder")
        else:
            _fields(payload, {"subjectId", "outcome"}, "control payload")
            _str(payload["subjectId"], "subjectId")
            _str(payload["outcome"], "outcome")
    return dict(raw)


def parse_machine_trace(raw, contract, side, logical):
    _fields(raw, {"schemaVersion", "regionIdentity", "binaryDigest", "entryIdentity", "compilerId",
                  "compilerVersion", "optimizationLevel", "abi", "captureProofIdentity",
                  "observerBinaryDigest", "complete", "events"}, "machine trace")
    region = contract[side + "Region"]
    if raw["schemaVersion"] != MACHINE_TRACE_SCHEMA or any(raw[k] != region[k] for k in
            ("regionIdentity", "binaryDigest", "entryIdentity", "compilerId", "compilerVersion",
             "optimizationLevel", "abi", "captureProofIdentity", "observerBinaryDigest")):
        raise ValueError("machine trace region/binary/compiler/observer binding mismatch")
    _complete(raw["complete"], "machine trace")
    events = raw["events"]
    if not isinstance(events, list):
        raise ValueError("machine events missing")
    logical_ids = {e["eventId"] for e in logical["events"]}
    exclusions = {e["eventId"]: e for e in region["approvedExclusions"]}
    seen = set()
    visible = []
    for order, event in enumerate(events):
        _fields(event, {"eventId", "executionOrder", "regionOffset", "eventKind", "logicalEventId",
                        "objectId", "offset", "size", "attributionKind", "attributionProofIdentity"}, "machine event")
        eid = _str(event["eventId"], "machine event ID")
        if eid in seen or _int(event["executionOrder"], "machine order") != order:
            raise ValueError("duplicate or reordered machine event")
        seen.add(eid)
        _int(event["regionOffset"], "regionOffset")
        if event["eventKind"] not in _MACHINE:
            raise ValueError("unknown machine event kind")
        _hash(event["attributionProofIdentity"], "machine attribution")
        _int(event["offset"], "machine object offset")
        _int(event["size"], "machine access width")
        if event["attributionKind"] == "logical":
            if event["logicalEventId"] not in logical_ids:
                raise ValueError("machine logical attribution missing")
            parent = next(e for e in logical["events"] if e["eventId"] == event["logicalEventId"])
            if parent["eventKind"] != event["eventKind"] or (
                    parent["eventKind"] in _MEMORY and
                    (event["objectId"], event["offset"], event["size"]) !=
                    (parent["payload"]["objectId"], parent["payload"]["offset"], parent["payload"]["size"])):
                raise ValueError("machine event does not match attributed logical effect")
            if parent["eventKind"] not in _MEMORY and (event["objectId"] != "" or event["size"] != 0):
                raise ValueError("control event has unexpected machine memory payload")
            visible.append(event)
        elif event["attributionKind"] in {"compiler_artifact", "runtime_helper"}:
            approved = exclusions.get(eid)
            if (approved is None or approved["eventKind"] != event["eventKind"] or
                    approved["attributionKind"] != event["attributionKind"] or
                    approved["proofIdentity"] != event["attributionProofIdentity"] or event["logicalEventId"] != ""):
                raise ValueError("machine exclusion lacks exact region-bound proof")
        else:
            raise ValueError("machine attribution unknown")
    return dict(raw), visible


def compare_traces(source, target, contract):
    """Return mismatch codes for valid complete traces; malformed attribution raises ValueError."""
    parsed = {}
    for side, raw in (("source", source), ("target", target)):
        logical = parse_logical_trace(raw["logicalTrace"], contract)
        machine, visible = parse_machine_trace(raw["machineTrace"], contract, side, logical)
        parsed[side] = (logical, machine, visible)
    def normalized(logical):
        positions = {e["eventId"]: i for i, e in enumerate(logical["events"])}
        return [(e["sourceEffectId"], e["eventKind"], e["payload"],
                 tuple(positions[p] for p in e["orderingPredecessors"])) for e in logical["events"]]
    reasons = []
    if normalized(parsed["source"][0]) != normalized(parsed["target"][0]):
        reasons.append("logical-access-or-control-path-mismatch")
    for side in ("source", "target"):
        logical = parsed[side][0]
        visible = parsed[side][2]
        expected = [e["eventId"] for e in logical["events"] if e["eventKind"] in _MEMORY | {"Branch", "ControlTransfer"}]
        if [e["logicalEventId"] for e in visible] != expected:
            reasons.append(side + "-machine-region-extra-or-missing-effect")
    return reasons, {side: {"logicalTraceIdentity": identity(parsed[side][0]),
                            "machineTraceIdentity": identity(parsed[side][1])} for side in parsed}
