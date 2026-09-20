"""L3 program-level concurrency campaigns with bounded statistical claims.

Outcome labels are contract identities, not inferred from a litmus test name.
A run is an independent sample for probability comparisons; iterations within a
run are never assumed independent.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import math
import re
from typing import Mapping

CAMPAIGN_SCHEMA = "riscv2x86.l3-concurrency-campaign.v1"
OBSERVATION_SCHEMA = "riscv2x86.l3-concurrency-campaign-observation.v1"
_GROUP_SCHEMA = "riscv2x86.l3-concurrency-campaign-group.v1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KINDS = {"SB", "LB", "MP", "IRIW", "lock", "atomic_counter", "custom"}
_CRITERIA = {"safety", "observed_support", "probability"}


def identity(value: object) -> str:
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _fields(value: object, names: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != names:
        raise ValueError(label + " fields missing or unknown")
    return value


def _str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(label + " must be nonempty")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError(label + " digest invalid")
    return value


def _int(value: object, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(label + " must be an integer >= " + str(minimum))
    return value


def _sorted(value: object, label: str, *, nonempty: bool = False) -> list[str]:
    if (not isinstance(value, list) or (nonempty and not value) or
            any(not isinstance(x, str) or not x for x in value) or value != sorted(set(value))):
        raise ValueError(label + " must be sorted unique names")
    return value


def parse_campaign(raw: object) -> dict:
    c = _fields(raw, {"schemaVersion", "campaignId", "programId", "memberFragmentIds", "kind",
        "semanticFactsIdentity", "l2ConcurrencyContractIdentity", "approvedRelationIdentity",
        "threadTopology", "initialState", "sourceAllowedOutcomes", "targetAllowedOutcomes",
        "forbiddenOutcomes", "protocolInvariants", "criterion", "requiredOutcomeSupport",
        "minimumIterations", "minimumIndependentRuns", "schedulePolicy", "sourcePlatform",
        "targetPlatform", "sourceCompilation", "targetCompilation", "confidenceLevel",
        "minimumDetectableProbability", "maximumProbabilityDifference", "complete"}, "campaign")
    if c["schemaVersion"] != CAMPAIGN_SCHEMA or c["complete"] is not True:
        raise ValueError("campaign schema/completeness invalid")
    for field in ("campaignId", "programId", "schedulePolicy"):
        _str(c[field], field)
    for field in ("semanticFactsIdentity", "l2ConcurrencyContractIdentity", "approvedRelationIdentity"):
        _digest(c[field], field)
    members = _sorted(c["memberFragmentIds"], "memberFragmentIds", nonempty=True)
    if c["kind"] not in _KINDS or c["criterion"] not in _CRITERIA:
        raise ValueError("campaign kind/criterion unsupported")
    source = set(_sorted(c["sourceAllowedOutcomes"], "sourceAllowedOutcomes", nonempty=True))
    target = set(_sorted(c["targetAllowedOutcomes"], "targetAllowedOutcomes", nonempty=True))
    forbidden = set(_sorted(c["forbiddenOutcomes"], "forbiddenOutcomes"))
    support = set(_sorted(c["requiredOutcomeSupport"], "requiredOutcomeSupport"))
    if (not target <= source or source & forbidden or target & forbidden or
            not support <= target or (c["criterion"] != "safety" and not support)):
        raise ValueError("approved outcome relation invalid")
    if c["criterion"] == "safety" and support:
        raise ValueError("safety criterion cannot claim reachability")
    if target != source and not c["approvedRelationIdentity"]:
        raise ValueError("strengthened relation missing")
    topology = _fields(c["threadTopology"], {"threads", "roles", "complete"}, "thread topology")
    count = _int(topology["threads"], "threads", 2)
    if topology["complete"] is not True or len(_sorted(topology["roles"], "thread roles", nonempty=True)) != count:
        raise ValueError("thread topology incomplete")
    init = _fields(c["initialState"], {"stateIdentity", "complete"}, "initial state")
    _digest(init["stateIdentity"], "initial state")
    if init["complete"] is not True:
        raise ValueError("initial state incomplete")
    _sorted(c["protocolInvariants"], "protocolInvariants")
    _int(c["minimumIterations"], "minimumIterations", 1)
    _int(c["minimumIndependentRuns"], "minimumIndependentRuns", 2)
    for side in ("source", "target"):
        platform = _fields(c[side + "Platform"], {"environmentIdentity", "capabilities", "complete"}, side + " platform")
        _digest(platform["environmentIdentity"], side + " environment")
        _sorted(platform["capabilities"], "platform capabilities")
        if platform["complete"] is not True:
            raise ValueError(side + " platform incomplete")
        compilation = _fields(c[side + "Compilation"], {"artifactDigest", "compilerDigest",
            "optimizationLevel", "abi", "complete"}, side + " compilation")
        _digest(compilation["artifactDigest"], "artifact")
        _digest(compilation["compilerDigest"], "compiler")
        _str(compilation["optimizationLevel"], "optimizationLevel")
        _str(compilation["abi"], "abi")
        if compilation["complete"] is not True:
            raise ValueError(side + " compilation incomplete")
    alpha = c["confidenceLevel"]
    probability = c["minimumDetectableProbability"]
    tolerance = c["maximumProbabilityDifference"]
    if any(isinstance(x, bool) or not isinstance(x, (float, int)) or not math.isfinite(x) for x in (alpha, probability, tolerance)):
        raise ValueError("statistical parameters invalid")
    if not 0.5 < alpha < 1 or not 0 < probability <= 1 or not 0 <= tolerance < 1:
        raise ValueError("statistical parameters out of range")
    if c["criterion"] == "probability" and tolerance == 0:
        raise ValueError("probability comparison requires explicit tolerance")
    return dict(c)


def parse_observation(raw: object, campaign: Mapping, side: str, runner_id: str) -> dict:
    o = _fields(raw, {"schemaVersion", "campaignIdentity", "side", "runnerId", "programId",
        "environmentIdentity", "artifactDigest", "compilerDigest", "schedulePolicy",
        "initialStateIdentity", "threadCount", "iterationsCompleted", "independentRunsCompleted",
        "outcomeCounts", "runSamples", "protocolViolations", "complete"}, "campaign observation")
    if o["schemaVersion"] != OBSERVATION_SCHEMA or o["campaignIdentity"] != identity(campaign) or o["side"] != side or o["runnerId"] != runner_id or o["programId"] != campaign["programId"]:
        raise ValueError("campaign observation identity mismatch")
    if (o["environmentIdentity"] != campaign[side + "Platform"]["environmentIdentity"] or
            o["artifactDigest"] != campaign[side + "Compilation"]["artifactDigest"] or
            o["compilerDigest"] != campaign[side + "Compilation"]["compilerDigest"] or
            o["schedulePolicy"] != campaign["schedulePolicy"] or
            o["initialStateIdentity"] != campaign["initialState"]["stateIdentity"] or
            o["threadCount"] != campaign["threadTopology"]["threads"]):
        raise ValueError("campaign environment, binary or scheduling mismatch")
    if o["complete"] is not True:
        raise ValueError("campaign observation incomplete")
    n = _int(o["iterationsCompleted"], "iterationsCompleted", 1)
    independent = _int(o["independentRunsCompleted"], "independentRunsCompleted", 1)
    counts = o["outcomeCounts"]
    if (not isinstance(counts, Mapping) or list(counts) != sorted(counts) or
            any(not isinstance(k, str) or not k or isinstance(v, bool) or not isinstance(v, int) or v < 0 for k, v in counts.items()) or
            sum(counts.values()) != n):
        raise ValueError("outcome counts invalid or incomplete")
    violations = o["protocolViolations"]
    if (not isinstance(violations, Mapping) or list(violations) != sorted(violations) or
            set(violations) != set(campaign["protocolInvariants"]) or
            any(isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > n for v in violations.values())):
        raise ValueError("protocol invariant observation incomplete")
    runs = o["runSamples"]
    if not isinstance(runs, list) or len(runs) != independent:
        raise ValueError("independent run evidence incomplete")
    ids = set()
    seeds = set()
    for run in runs:
        _fields(run, {"runId", "seed", "outcome", "iterations"}, "run sample")
        name = _str(run["runId"], "runId")
        if name in ids:
            raise ValueError("duplicate independent run")
        ids.add(name)
        seed = _int(run["seed"], "seed")
        if seed in seeds:
            raise ValueError("independent run seeds repeated")
        seeds.add(seed)
        _int(run["iterations"], "run iterations", 1)
        _str(run["outcome"], "run outcome")
    if sum(run["iterations"] for run in runs) != n:
        raise ValueError("run coverage differs from outcome counts")
    if all(run["iterations"] == 1 for run in runs) and dict(sorted(Counter(r["outcome"] for r in runs).items())) != counts:
        raise ValueError("independent run outcomes disagree with counts")
    return dict(o)


def evaluate_campaign(campaign: Mapping, source: Mapping, target: Mapping) -> dict:
    """Classifies complete observations; zero occurrences never prove unreachable."""
    c = parse_campaign(campaign)
    evidence = {"schemaVersion": "riscv2x86.l3-concurrency-campaign-result.v1",
                "programId": c["programId"], "campaignId": c["campaignId"],
                "campaignIdentity": identity(c), "memberFragmentIds": c["memberFragmentIds"],
                "criterion": c["criterion"], "approvedRelationIdentity": c["approvedRelationIdentity"],
                "iterations": {}, "independentRuns": {}, "observedOutcomes": {},
                "protocolViolations": {}, "confidenceLevel": c["confidenceLevel"],
                "minimumDetectableProbability": c["minimumDetectableProbability"],
                "detectionPower": {}, "confidenceBounds": {}, "reasonCodes": [], "status": "inconclusive"}
    reasons = []
    for side, observation in (("source", source), ("target", target)):
        counts = observation["outcomeCounts"]
        n = observation["iterationsCompleted"]
        evidence["iterations"][side] = n
        evidence["independentRuns"][side] = observation["independentRunsCompleted"]
        evidence["observedOutcomes"][side] = sorted(k for k, v in counts.items() if v)
        evidence["protocolViolations"][side] = dict(observation["protocolViolations"])
        # P(no occurrence | p >= p_min) <= (1 - p_min)^N if independent.
        independent = observation["independentRunsCompleted"]
        evidence["detectionPower"][side] = (1 - c["minimumDetectableProbability"]) ** independent
        allowed = set(c[side + "AllowedOutcomes"])
        if any(v and (k not in allowed or k in c["forbiddenOutcomes"]) for k, v in counts.items()):
            reasons.append(side + ":forbidden-or-outside-approved-outcome")
        if any(v for v in observation["protocolViolations"].values()):
            reasons.append(side + ":protocol-invariant-violated")
    if reasons:
        evidence["status"] = "failed"
    elif any(ob["iterationsCompleted"] < c["minimumIterations"] or
             ob["independentRunsCompleted"] < c["minimumIndependentRuns"] for ob in (source, target)):
        reasons.append("campaign:insufficient-iterations-or-independent-runs")
    elif c["criterion"] == "observed_support":
        # Absence is only inconclusive, irrespective of how many iterations ran.
        if not set(c["requiredOutcomeSupport"]) <= set(evidence["observedOutcomes"]["target"]):
            reasons.append("campaign:required-outcome-not-observed;reachability-undetermined")
        else:
            evidence["status"] = "verified"
    elif c["criterion"] == "probability":
        outcomes = c["requiredOutcomeSupport"]
        if any(any(run["iterations"] != 1 for run in ob["runSamples"]) for ob in (source, target)):
            reasons.append("campaign:per-run-outcome-distribution-unavailable")
        else:
            # Union bound over both platforms and all declared outcomes.
            confidence = c["confidenceLevel"]
            for side, obs in (("source", source), ("target", target)):
                n = obs["independentRunsCompleted"]
                radius = math.sqrt(math.log(4 * len(outcomes) / (1 - confidence)) / (2 * n))
                evidence["confidenceBounds"][side] = {name: [max(0, obs["outcomeCounts"].get(name, 0) / n - radius),
                    min(1, obs["outcomeCounts"].get(name, 0) / n + radius)] for name in outcomes}
            if any(evidence["detectionPower"][side] > 1 - confidence for side in ("source", "target")):
                reasons.append("campaign:insufficient-detection-power")
            else:
                tolerance = c["maximumProbabilityDifference"]
                intervals = [(evidence["confidenceBounds"]["source"][name], evidence["confidenceBounds"]["target"][name]) for name in outcomes]
                if any(a[1] + tolerance < b[0] or b[1] + tolerance < a[0] for a, b in intervals):
                    evidence["status"] = "failed"
                    reasons.append("campaign:probability-difference-exceeds-tolerance")
                elif all(max(abs(a[0] - b[1]), abs(a[1] - b[0])) <= tolerance for a, b in intervals):
                    evidence["status"] = "verified"
                else:
                    reasons.append("campaign:probability-confidence-interval-overlap-undecided")
    else:
        evidence["status"] = "verified"
    evidence["reasonCodes"] = sorted(reasons)
    evidence["claimBoundary"] = "finite-independent-sample-safety-and-declared-criterion;not-memory-model-equivalence"
    evidence["sourceObservationIdentity"] = identity(source)
    evidence["targetObservationIdentity"] = identity(target)
    evidence["resultIdentity"] = identity(evidence)
    return evidence


def aggregate_campaign_results(results: list[Mapping]) -> dict:
    """Program/campaign is the sampling unit; members and threads are not samples."""
    unique = {}
    for result in results:
        if (result.get("schemaVersion") != "riscv2x86.l3-concurrency-campaign-result.v1" or
                result.get("resultIdentity") != identity({k: v for k, v in result.items() if k != "resultIdentity"})):
            raise ValueError("campaign result identity invalid")
        key = (result["programId"], result["campaignIdentity"])
        if key in unique and unique[key]["resultIdentity"] != result["resultIdentity"]:
            raise ValueError("conflicting evidence for the same program/campaign")
        unique[key] = result
    payload = {"schemaVersion": _GROUP_SCHEMA, "campaignSampleCount": len(unique),
               "campaignResults": [unique[key]["resultIdentity"] for key in sorted(unique)]}
    payload["groupIdentity"] = identity(payload)
    return payload
