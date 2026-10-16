"""Actual continuation trace ingress, independent of function return values.

This is an observation reader, not a provider or a control-flow proof. A caller
must bind compiler-owned instrumentation sites and an approved relation before
using its output. No event is inferred from an input/predicate or final result.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping

from .compiler_value_flow import identity
from .effect_relation import approved_effect_relation_from_dict

SCHEMA = "riscv2x86.continuation-trace-contract.v1"
TRACE_SCHEMA = "riscv2x86.continuation-trace.v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}")


class ContinuationTraceError(ValueError):
    failure_stage = "continuation_observation"

    def __init__(self, reason_code, detail):
        super().__init__(detail)
        self.reason_code = reason_code


def _fail(code, detail):
    raise ContinuationTraceError(code, detail)


def validate_contract(raw):
    fields = {"schemaVersion", "fragmentId", "sourceDigest", "targetDigest",
        "authorityIdentity", "proofIdentity", "relation", "continuations", "sites",
        "samples", "contractIdentity"}
    if not isinstance(raw, Mapping) or set(raw) != fields or raw["schemaVersion"] != SCHEMA:
        _fail("L2_CONTINUATION_CONTRACT_SCHEMA_INVALID", "Continuation trace contract fields/schema invalid")
    if raw["contractIdentity"] != identity({k:v for k,v in raw.items() if k != "contractIdentity"}):
        _fail("L2_CONTINUATION_CONTRACT_IDENTITY_MISMATCH", "Continuation contract is stale")
    if (not isinstance(raw["fragmentId"], str) or not raw["fragmentId"]
            or any(not isinstance(raw[k], str) or _SHA.fullmatch(raw[k]) is None for k in
                ("sourceDigest", "targetDigest", "authorityIdentity", "proofIdentity"))):
        _fail("L2_CONTINUATION_AUTHORITY_IDENTITY_INVALID", "Continuation authority identities invalid")
    try:
        relation = approved_effect_relation_from_dict(raw["relation"])
    except (ValueError, TypeError) as exc:
        _fail("L2_CONTINUATION_RELATION_INVALID", str(exc))
    if not relation.authority_complete or not {"branch_continuation", "target"}.issubset(relation.observable_requirements):
        _fail("L2_CONTINUATION_RELATION_INCOMPLETE", "Approved relation does not cover actual continuations")
    for key in ("continuations", "samples"):
        values = raw[key]
        if (not isinstance(values, list) or not values or any(not isinstance(x, str) or not x for x in values)
                or len(set(values)) != len(values)):
            _fail("L2_CONTINUATION_DOMAIN_INVALID", "Continuation/sample domain invalid")
    if not isinstance(raw["sites"], dict) or set(raw["sites"]) != {"source", "target"}:
        _fail("L2_CONTINUATION_SITE_BINDING_INVALID", "Both instrumentation site maps are required")
    for side in ("source", "target"):
        sites = raw["sites"][side]
        if not isinstance(sites, list) or len(sites) != len(raw["continuations"]):
            _fail("L2_CONTINUATION_SITE_BINDING_INVALID", "Site map does not cover all continuations")
        seen = set()
        for site in sites:
            if (not isinstance(site, dict) or set(site) != {"continuationId", "compilerSiteIdentity", "markerIdentity"}
                    or site["continuationId"] not in raw["continuations"]
                    or site["continuationId"] in seen
                    or not isinstance(site["compilerSiteIdentity"], str)
                    or _SHA.fullmatch(site["compilerSiteIdentity"]) is None):
                _fail("L2_CONTINUATION_SITE_BINDING_INVALID", "Site map has unknown/duplicate/unbound continuation")
            seen.add(site["continuationId"])
            expected = identity({"fragmentId": raw["fragmentId"], "side": side,
                "artifactDigest": raw[side + "Digest"],
                "compilerSiteIdentity": site["compilerSiteIdentity"],
                "continuationId": site["continuationId"]})
            if site["markerIdentity"] != expected:
                _fail("L2_CONTINUATION_MARKER_IDENTITY_MISMATCH", "Marker/site identity differs")
    return relation


def read_continuation_observations(stdout, contract, *, side, execution_identity):
    """Read exactly one executed exit per bounded fragment invocation/sample."""
    relation = validate_contract(contract)
    if side not in {"source", "target"} or not isinstance(execution_identity, str) or _SHA.fullmatch(execution_identity) is None:
        _fail("L2_CONTINUATION_EXECUTION_IDENTITY_INVALID", "Execution side/identity invalid")
    sites = {s["markerIdentity"]: s["continuationId"] for s in contract["sites"][side]}
    found = {}
    prefix = "continuation_trace="
    for line in stdout.splitlines():
        if not line.startswith(prefix):
            continue
        try:
            record = json.loads(line[len(prefix):])
        except ValueError as exc:
            _fail("L2_CONTINUATION_TRACE_MALFORMED", str(exc))
        if (not isinstance(record, dict) or set(record) != {"schemaVersion", "sampleId", "markerIdentity", "ordinal"}
                or record["schemaVersion"] != TRACE_SCHEMA):
            _fail("L2_CONTINUATION_TRACE_SCHEMA_INVALID", "Trace event schema invalid")
        sample = record["sampleId"]
        if not isinstance(sample, str) or sample not in contract["samples"]:
            _fail("L2_CONTINUATION_SAMPLE_UNKNOWN", "Trace sample is outside execution domain")
        if sample in found:
            _fail("L2_CONTINUATION_MULTIPLE_EXITS_OBSERVED", "Multiple exits observed for one bounded invocation")
        marker = record["markerIdentity"]
        if not isinstance(marker, str) or marker not in sites:
            _fail("L2_CONTINUATION_MARKER_UNKNOWN", "Trace marker is not compiler-site bound")
        if type(record["ordinal"]) is not int or record["ordinal"] != 0:
            _fail("L2_CONTINUATION_TRACE_ORDINAL_INVALID", "Bounded invocation exit ordinal must be zero")
        found[sample] = {"sampleId": sample, "continuationId": sites[marker], "ordinal": 0}
    if set(found) != set(contract["samples"]):
        _fail("L2_CONTINUATION_TRACE_ARITY_MISMATCH", "Not every executed sample produced a continuation event")
    result = {"schemaVersion": "riscv2x86.continuation-observations.v1",
        "fragmentId": contract["fragmentId"], "dimension": "control_flow", "side": side,
        "authorityIdentity": contract["authorityIdentity"],
        "proofIdentity": contract["proofIdentity"], "effectRelationIdentity": relation.approval_identity,
        "executionIdentity": execution_identity, "contractIdentity": contract["contractIdentity"],
        "events": [found[s] for s in contract["samples"]]}
    result["observationIdentity"] = identity(result)
    return result


def continuation_observations_match(source, target):
    """Validate payloads and compare actual exits under one execution/relation."""
    for side, value in (("source", source), ("target", target)):
        if (value.get("side") != side or value.get("dimension") != "control_flow"
                or value.get("observationIdentity") != identity({k:v for k,v in value.items() if k != "observationIdentity"})):
            _fail("L2_CONTINUATION_OBSERVATION_IDENTITY_MISMATCH", "Observation content/side is stale")
    keys = ("schemaVersion", "fragmentId", "dimension", "authorityIdentity", "proofIdentity",
            "effectRelationIdentity", "executionIdentity", "contractIdentity")
    if any(source[k] != target[k] for k in keys):
        _fail("L2_CONTINUATION_OBSERVATION_BINDING_MISMATCH", "Observation execution/authority/relation differs")
    return source["events"] == target["events"]
