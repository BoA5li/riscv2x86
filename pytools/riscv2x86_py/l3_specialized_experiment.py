"""Explicit platform-specific L3 experimental claims, never ISA-wide equality.

This validates aggregate observations supplied by approved, externally registered
experiment executors; it does not synthesize probes, secrets or attack payloads.
"""
from __future__ import annotations

from hashlib import sha256
import json
import math
import re
from typing import Mapping

CONTRACT_SCHEMA = "riscv2x86.l3-specialized-experiment.v1"
OBSERVATION_SCHEMA = "riscv2x86.l3-specialized-observation.v1"
RESULT_SCHEMA = "riscv2x86.l3-specialized-result.v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MODELS = {"cache_timing", "branch_prediction", "instruction_visibility", "speculation_probe", "custom"}
_METRICS = {"success_rate", "leakage_rate", "visibility_rate"}


def identity(value):
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _fields(value, expected, label):
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(label + " fields incomplete or unknown")
    return value


def _text(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(label + " must be a nonempty string")
    return value


def _sha(value, label):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(label + " identity invalid")
    return value


def _int(value, label, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(label + " must be integer >= " + str(minimum))
    return value


def _num(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(label + " must be finite")
    return float(value)


def _strings(value, label, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value) or any(not isinstance(x, str) or not x for x in value) or value != sorted(set(value)):
        raise ValueError(label + " must be sorted unique strings")
    return value


def parse_contract(value):
    c = _fields(value, {"schemaVersion", "experimentId", "programId", "fragmentId", "profileIdentity",
        "proofIdentity", "model", "sourceMechanism", "targetMechanism", "targetRelationIdentity",
        "dataVisibility", "timingConfig", "cacheConfig", "sourceEnvironmentIdentity",
        "targetEnvironmentIdentity", "sourceArtifactDigest", "targetArtifactDigest",
        "sampleCount", "warmupCount", "samplingPlanIdentity", "metrics", "notClaimedProperties", "complete"}, "specialized contract")
    if c["schemaVersion"] != CONTRACT_SCHEMA or c["complete"] is not True:
        raise ValueError("specialized contract schema or completeness invalid")
    for name in ("experimentId", "programId", "fragmentId"):
        _text(c[name], name)
    for name in ("profileIdentity", "proofIdentity", "targetRelationIdentity",
                 "sourceEnvironmentIdentity", "targetEnvironmentIdentity", "sourceArtifactDigest", "targetArtifactDigest",
                 "samplingPlanIdentity"):
        _sha(c[name], name)
    if c["model"] not in _MODELS:
        raise ValueError("unknown experimental model")
    for side in ("source", "target"):
        mechanism = _fields(c[side + "Mechanism"], {"mechanismId", "publicInterface",
            "registrationIdentity", "approvalIdentity", "requiredCapabilities", "complete"}, side + " mechanism")
        if mechanism["complete"] is not True:
            raise ValueError(side + " mechanism incomplete")
        _text(mechanism["mechanismId"], "mechanismId")
        _text(mechanism["publicInterface"], "publicInterface")
        _sha(mechanism["registrationIdentity"], "mechanism registration")
        _sha(mechanism["approvalIdentity"], "mechanism approval")
        _strings(mechanism["requiredCapabilities"], "mechanism capabilities", nonempty=True)
    visibility = _fields(c["dataVisibility"], {"scopeId", "boundaryIdentity", "allowedOutputs",
                                                 "rawSensitiveDataExport", "complete"}, "data visibility")
    _text(visibility["scopeId"], "scopeId")
    _sha(visibility["boundaryIdentity"], "data boundary")
    _strings(visibility["allowedOutputs"], "allowedOutputs", nonempty=True)
    if visibility["rawSensitiveDataExport"] is not False or visibility["complete"] is not True:
        raise ValueError("raw sensitive data export is outside the measurement contract")
    timing = _fields(c["timingConfig"], {"clockDomain", "measurementWindowIdentity", "samplingPolicy",
                                          "resolution", "complete"}, "timing")
    for name in ("clockDomain", "samplingPolicy"):
        _text(timing[name], name)
    _sha(timing["measurementWindowIdentity"], "measurement window")
    if _num(timing["resolution"], "resolution") <= 0 or timing["complete"] is not True:
        raise ValueError("timing configuration invalid")
    cache = _fields(c["cacheConfig"], {"configurationIdentity", "cacheLineBytes", "statePolicy",
                                          "complete"}, "cache")
    _sha(cache["configurationIdentity"], "cache configuration")
    _int(cache["cacheLineBytes"], "cacheLineBytes", 1)
    _text(cache["statePolicy"], "cache state policy")
    if cache["complete"] is not True:
        raise ValueError("cache configuration incomplete")
    _int(c["sampleCount"], "sampleCount", 2)
    _int(c["warmupCount"], "warmupCount")
    metric_ids = []
    if not isinstance(c["metrics"], list) or not c["metrics"]:
        raise ValueError("specialized metrics missing")
    for metric in c["metrics"]:
        _fields(metric, {"metricId", "metricKind", "declaredConclusion", "sourceMinimumRate",
                         "targetMinimumRate", "confidenceLevel"}, "specialized metric")
        metric_ids.append(_text(metric["metricId"], "metricId"))
        _text(metric["declaredConclusion"], "declaredConclusion")
        if metric["metricKind"] not in _METRICS:
            raise ValueError("metricKind unsupported")
        for side in ("source", "target"):
            threshold = _num(metric[side + "MinimumRate"], "minimumRate")
            if not 0 < threshold < 1:
                raise ValueError("minimumRate outside (0,1)")
        confidence = _num(metric["confidenceLevel"], "confidenceLevel")
        if not 0.5 < confidence < 1:
            raise ValueError("confidenceLevel invalid")
    if metric_ids != sorted(set(metric_ids)):
        raise ValueError("specialized metrics not unique/canonical")
    claims = _strings(c["notClaimedProperties"], "notClaimedProperties", nonempty=True)
    if "cross-ISA-hardware-equivalence" not in claims or "identical-cache-or-timing-parameters" not in claims:
        raise ValueError("platform-specific claim boundary missing")
    return dict(c)


def mechanism_route_status(contract, registry, capabilities):
    """Return missing route/capability codes. Registry is supplied independently.

    A contract alone cannot approve its own target mechanism.
    """
    if not isinstance(registry, Mapping) or not isinstance(capabilities, Mapping):
        return ["l3.specialized.mechanism-registry-unavailable"]
    reasons = []
    for side in ("source", "target"):
        mechanism = contract[side + "Mechanism"]
        registered = registry.get(mechanism["registrationIdentity"])
        expected = {key: mechanism[key] for key in ("mechanismId", "publicInterface", "approvalIdentity")}
        expected["environmentIdentity"] = contract[side + "EnvironmentIdentity"]
        if not isinstance(registered, Mapping) or set(registered) != set(expected) or dict(registered) != expected:
            reasons.append("l3.specialized." + side + "-mechanism-unapproved")
        actual = capabilities.get(side)
        if (not isinstance(actual, (tuple, list)) or not all(isinstance(x, str) for x in actual) or
                not set(mechanism["requiredCapabilities"]) <= set(actual)):
            reasons.append("l3.specialized." + side + "-capability-missing")
    return reasons


def parse_observation(value, contract, side, runner_id):
    o = _fields(value, {"schemaVersion", "experimentIdentity", "side", "runnerId", "programId",
        "mechanismId", "registrationIdentity", "environmentIdentity", "artifactDigest",
        "dataBoundaryIdentity", "measurementWindowIdentity", "cacheConfigurationIdentity",
        "sampleCount", "independentRuns", "samplingPlanIdentity", "warmupsCompleted", "metricCounts", "complete"}, "specialized observation")
    mechanism = contract[side + "Mechanism"]
    if (o["schemaVersion"] != OBSERVATION_SCHEMA or o["experimentIdentity"] != identity(contract) or
            o["side"] != side or o["runnerId"] != runner_id or o["programId"] != contract["programId"] or
            o["mechanismId"] != mechanism["mechanismId"] or
            o["registrationIdentity"] != mechanism["registrationIdentity"] or
            o["environmentIdentity"] != contract[side + "EnvironmentIdentity"] or
            o["artifactDigest"] != contract[side + "ArtifactDigest"] or
            o["dataBoundaryIdentity"] != contract["dataVisibility"]["boundaryIdentity"] or
            o["measurementWindowIdentity"] != contract["timingConfig"]["measurementWindowIdentity"] or
            o["cacheConfigurationIdentity"] != contract["cacheConfig"]["configurationIdentity"] or
            o["samplingPlanIdentity"] != contract["samplingPlanIdentity"] or
            _int(o["sampleCount"], "sampleCount", 2) != contract["sampleCount"] or
            _int(o["independentRuns"], "independentRuns", 2) != contract["sampleCount"] or
            _int(o["warmupsCompleted"], "warmupsCompleted") < contract["warmupCount"] or
            o["complete"] is not True):
        raise ValueError("specialized report identity/environment/mechanism/measurement mismatch")
    counts = o["metricCounts"]
    if not isinstance(counts, Mapping) or list(counts) != sorted(counts) or set(counts) != {m["metricId"] for m in contract["metrics"]}:
        raise ValueError("specialized metric coverage incomplete")
    for item in counts.values():
        _fields(item, {"hits", "trials"}, "metric counts")
        hits, trials = _int(item["hits"], "hits"), _int(item["trials"], "trials", 1)
        if hits > trials or trials != o["sampleCount"]:
            raise ValueError("metric counts invalid")
    return dict(o)


def _wilson(hits, n, confidence):
    # Conservative normal-quantile construction; Wilson interval has reliable
    # finite-sample behavior near 0 and 1 compared with a Wald interval.
    from statistics import NormalDist
    z = NormalDist().inv_cdf((1 + confidence) / 2)
    p = hits / n
    denom = 1 + z*z/n
    center = (p + z*z/(2*n)) / denom
    spread = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / denom
    return max(0., center-spread), min(1., center+spread)


def evaluate_experiment(contract, source, target):
    c = parse_contract(contract)
    summaries, reasons = [], []
    for metric in c["metrics"]:
        for side, report in (("source", source), ("target", target)):
            counts = report["metricCounts"][metric["metricId"]]
            low, high = _wilson(counts["hits"], counts["trials"], metric["confidenceLevel"])
            threshold = metric[side + "MinimumRate"]
            decision = "supported" if low >= threshold else "contradicted" if high < threshold else "undetermined"
            summaries.append({"side": side, "metricId": metric["metricId"], "metricKind": metric["metricKind"],
                "declaredConclusion": metric["declaredConclusion"], "hits": counts["hits"], "trials": counts["trials"],
                "independentRuns": report["independentRuns"],
                "rate": counts["hits"]/counts["trials"], "confidenceLevel": metric["confidenceLevel"],
                "confidenceInterval": [low, high], "minimumRate": threshold, "decision": decision,
                "platformMechanismId": c[side + "Mechanism"]["mechanismId"]})
    source_ok = all(s["decision"] == "supported" for s in summaries if s["side"] == "source")
    target = [s["decision"] for s in summaries if s["side"] == "target"]
    if not source_ok:
        status = "inconclusive"
        reasons.append("source:experiment-conclusion-not-reproduced")
    elif "contradicted" in target:
        status = "failed"
        reasons.append("target:registered-platform-conclusion-contradicted")
    elif all(x == "supported" for x in target):
        status = "verified"
    else:
        status = "inconclusive"
        reasons.append("target:threshold-uncertain")
    result = {"schemaVersion": RESULT_SCHEMA, "experimentIdentity": identity(c), "programId": c["programId"],
        "fragmentId": c["fragmentId"], "status": status, "reasonCodes": reasons,
        "observedProperties": summaries, "sourceObservationIdentity": identity(source),
        "targetObservationIdentity": identity(target), "notClaimedProperties": c["notClaimedProperties"],
        "claimScope": "registered-platform-experiment-only"}
    result["resultIdentity"] = identity(result)
    return result


def aggregate_specialized_results(results):
    unique = {}
    for item in results:
        if (item.get("schemaVersion") != RESULT_SCHEMA or
                item.get("resultIdentity") != identity({k: v for k, v in item.items() if k != "resultIdentity"})):
            raise ValueError("specialized experiment result identity invalid")
        key = (item["programId"], item["experimentIdentity"])
        if key in unique and unique[key] != item["resultIdentity"]:
            raise ValueError("conflicting platform experiment results")
        unique[key] = item["resultIdentity"]
    group = {"schemaVersion": "riscv2x86.l3-specialized-group.v1",
             "experimentSampleCount": len(unique),
             "resultIdentities": [unique[key] for key in sorted(unique)]}
    group["groupIdentity"] = identity(group)
    return group
