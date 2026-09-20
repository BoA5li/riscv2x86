"""Predeclared, within-platform L3 paired-round experimental conclusions.

No raw cycle values are ever compared between source and target platforms.
Bootstrap resamples independent experiment rounds; samples within one round
are paired and never counted as separate independent rounds.
"""
from __future__ import annotations

from hashlib import sha256
import json
import math
import random
import re
import statistics
from typing import Mapping

CONTRACT_SCHEMA = "riscv2x86.l3-statistical-experiment.v1"
OBSERVATION_SCHEMA = "riscv2x86.l3-statistical-observation.v1"
RESULT_SCHEMA = "riscv2x86.l3-statistical-experiment-result.v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIRECTIONS = {"increase", "decrease", "equivalent", "noninferior"}
_NORMALIZATIONS = {"difference", "relative_to_baseline"}
_ORDERS = {"baseline_first", "treatment_first"}


def identity(value):
    return "sha256:" + sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _fields(raw, fields, label):
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise ValueError(label + " fields missing or unknown")
    return raw


def _str(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(label + " must be nonempty")
    return value


def _sha(value, label):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(label + " identity invalid")
    return value


def _int(value, label, minval=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minval:
        raise ValueError(label + " must be an integer >= " + str(minval))
    return value


def _num(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(label + " must be finite")
    return float(value)


def parse_experiment(raw):
    c = _fields(raw, {"schemaVersion", "experimentId", "programId", "proofIdentity",
        "baselineLabel", "treatmentLabel", "independentUnit", "roundClusterUnit", "randomSeed",
        "randomizeOrder", "roundCount", "minimumRounds", "pairsPerRound", "warmupsPerRound", "bootstrapDraws",
        "confidenceLevel", "multipleTestingCorrection", "exclusionRule", "noiseThreshold",
        "sourceEnvironmentIdentity", "targetEnvironmentIdentity", "sourceArtifactDigest",
        "targetArtifactDigest", "sourceCompilerDigest", "targetCompilerDigest", "metrics", "complete"}, "statistical experiment")
    if c["schemaVersion"] != CONTRACT_SCHEMA or c["complete"] is not True:
        raise ValueError("statistical experiment schema/completeness invalid")
    for key in ("experimentId", "programId", "baselineLabel", "treatmentLabel"):
        _str(c[key], key)
    if c["baselineLabel"] == c["treatmentLabel"] or c["independentUnit"] != "experiment_round" or c["roundClusterUnit"] != "program/round" or c["randomizeOrder"] is not True:
        raise ValueError("paired independent-round experimental design incomplete")
    for key in ("proofIdentity", "sourceEnvironmentIdentity", "targetEnvironmentIdentity",
                "sourceArtifactDigest", "targetArtifactDigest", "sourceCompilerDigest", "targetCompilerDigest"):
        _sha(c[key], key)
    _int(c["randomSeed"], "randomSeed")
    _int(c["roundCount"], "roundCount", 2)
    _int(c["minimumRounds"], "minimumRounds", 2)
    if c["roundCount"] < c["minimumRounds"]:
        raise ValueError("scheduled rounds below minimum retained rounds")
    _int(c["pairsPerRound"], "pairsPerRound", 1)
    _int(c["warmupsPerRound"], "warmupsPerRound")
    _int(c["bootstrapDraws"], "bootstrapDraws", 200)
    confidence = _num(c["confidenceLevel"], "confidenceLevel")
    if not 0.5 < confidence < 1 or c["multipleTestingCorrection"] != "bonferroni":
        raise ValueError("confidence or multiple testing policy invalid")
    if c["exclusionRule"] != "exclude-entire-round-if-noise-exceeds-threshold" or _num(c["noiseThreshold"], "noiseThreshold") < 0:
        raise ValueError("exclusion/noise rule invalid")
    metrics = c["metrics"]
    if not isinstance(metrics, list) or not metrics:
        raise ValueError("statistical metrics missing")
    ids = []
    for metric in metrics:
        _fields(metric, {"metricId", "sourceMetric", "targetMetric", "sourceUnit", "targetUnit",
            "normalization", "valueRange", "conclusion", "direction", "minimumMeaningfulEffect",
            "equivalenceMargin", "nonInferiorityMargin"}, "metric")
        ids.append(_str(metric["metricId"], "metricId"))
        for field in ("sourceMetric", "targetMetric", "sourceUnit", "targetUnit", "conclusion"):
            _str(metric[field], field)
        if metric["normalization"] not in _NORMALIZATIONS or metric["direction"] not in _DIRECTIONS:
            raise ValueError("metric normalization/direction invalid")
        bounds = metric["valueRange"]
        if not isinstance(bounds, list) or len(bounds) != 2 or _num(bounds[0], "range minimum") >= _num(bounds[1], "range maximum"):
            raise ValueError("metric range invalid")
        for field in ("minimumMeaningfulEffect", "equivalenceMargin", "nonInferiorityMargin"):
            if _num(metric[field], field) < 0:
                raise ValueError("effect or margin cannot be negative")
        if metric["direction"] == "equivalent" and metric["equivalenceMargin"] <= 0:
            raise ValueError("equivalence needs a prespecified positive margin")
    if ids != sorted(set(ids)):
        raise ValueError("metric identities must be sorted and unique")
    return dict(c)


def parse_observation(raw, contract, side, runner_id):
    o = _fields(raw, {"schemaVersion", "experimentIdentity", "side", "runnerId", "programId",
        "environmentIdentity", "artifactDigest", "compilerDigest", "warmupsPerRound",
        "randomSeed", "rounds", "complete"}, "statistical observation")
    if (o["schemaVersion"] != OBSERVATION_SCHEMA or o["experimentIdentity"] != identity(contract) or
            o["side"] != side or o["runnerId"] != runner_id or o["programId"] != contract["programId"] or
            o["environmentIdentity"] != contract[side + "EnvironmentIdentity"] or
            o["artifactDigest"] != contract[side + "ArtifactDigest"] or
            o["compilerDigest"] != contract[side + "CompilerDigest"] or
            o["warmupsPerRound"] != contract["warmupsPerRound"] or
            o["randomSeed"] != contract["randomSeed"] or o["complete"] is not True):
        raise ValueError("statistical observation identity/environment/warmup mismatch")
    rounds = o["rounds"]
    if not isinstance(rounds, list) or len(rounds) != contract["roundCount"]:
        raise ValueError("statistical rounds missing")
    rng = random.Random(contract["randomSeed"])
    ids = set()
    metric_names = {m[side + "Metric"] for m in contract["metrics"]}
    for rnd in rounds:
        _fields(rnd, {"roundId", "programId", "order", "noiseScore", "excluded",
                      "exclusionReason", "pairs"}, "round")
        rid = _str(rnd["roundId"], "roundId")
        if rid in ids or rnd["programId"] != contract["programId"]:
            raise ValueError("round ID/program identity invalid")
        ids.add(rid)
        expected_order = "treatment_first" if rng.randrange(2) else "baseline_first"
        if rnd["order"] not in _ORDERS or rnd["order"] != expected_order:
            raise ValueError("round ordering does not match preregistered seed")
        score = _num(rnd["noiseScore"], "noiseScore")
        excluded = score > contract["noiseThreshold"]
        if rnd["excluded"] is not excluded or rnd["exclusionReason"] != ("noise-threshold" if excluded else ""):
            raise ValueError("round exclusion not determined by preregistered rule")
        pairs = rnd["pairs"]
        if not isinstance(pairs, Mapping) or set(pairs) != metric_names:
            raise ValueError("metric pair coverage incomplete")
        for metric in contract["metrics"]:
            values = pairs[metric[side + "Metric"]]
            if not isinstance(values, list) or len(values) != contract["pairsPerRound"]:
                raise ValueError("paired samples incomplete")
            for pair in values:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ValueError("paired baseline/treatment sample invalid")
                lo, hi = metric["valueRange"]
                b, t = (_num(pair[0], "baseline"), _num(pair[1], "treatment"))
                if not lo <= b <= hi or not lo <= t <= hi or (metric["normalization"] == "relative_to_baseline" and b == 0):
                    raise ValueError("sample outside range or relative normalization undefined")
    return dict(o)


def _interval(values, seed, draws, adjusted_confidence):
    center = statistics.mean(values)
    rng = random.Random(seed)
    means = sorted(statistics.mean(values[rng.randrange(len(values))] for _ in values) for _ in range(draws))
    alpha = (1 - adjusted_confidence) / 2
    low = means[max(0, math.floor(alpha * draws))]
    high = means[min(draws - 1, math.ceil((1 - alpha) * draws) - 1)]
    return center, low, high


def _conclusion(metric, low, high):
    minimum = metric["minimumMeaningfulEffect"]
    direction = metric["direction"]
    if direction == "increase":
        return ("supported" if low > minimum else "contradicted" if high < -minimum else "undetermined")
    if direction == "decrease":
        return ("supported" if high < -minimum else "contradicted" if low > minimum else "undetermined")
    if direction == "equivalent":
        margin = metric["equivalenceMargin"]
        return ("supported" if low > -margin and high < margin else
                "contradicted" if low >= margin or high <= -margin else "undetermined")
    margin = metric["nonInferiorityMargin"]
    return "supported" if low > -margin else "contradicted" if high < -margin else "undetermined"


def evaluate_experiment(contract, source, target):
    c = parse_experiment(contract)
    summaries = []
    reasons = []
    source_conclusions = []
    target_conclusions = []
    k = len(c["metrics"])
    adjusted_confidence = 1 - (1 - c["confidenceLevel"]) / k
    for index, metric in enumerate(c["metrics"]):
        for side, obs in (("source", source), ("target", target)):
            rounds = obs["rounds"]
            retained = [r for r in rounds if not r["excluded"]]
            excluded = [r["roundId"] for r in rounds if r["excluded"]]
            round_effects = []
            for rnd in retained:
                pairs = rnd["pairs"][metric[side + "Metric"]]
                effects = [(t - b) if metric["normalization"] == "difference" else (t - b) / abs(b)
                           for b, t in pairs]
                round_effects.append(statistics.mean(effects))
            # Noise is measured before looking at the effect and excludes a whole
            # round. Never rescue a weak conclusion by dropping individual pairs.
            summary = {"metricId": metric["metricId"], "conclusion": metric["conclusion"], "side": side,
                "unit": metric[side + "Unit"], "normalization": metric["normalization"],
                "independentUnit": c["independentUnit"], "roundClusterUnit": c["roundClusterUnit"],
                "roundCount": len(rounds), "retainedRoundCount": len(retained),
                "pairsPerRound": c["pairsPerRound"], "excludedRoundIds": excluded,
                "method": "paired-round-cluster-bootstrap-v1", "bootstrapDraws": c["bootstrapDraws"],
                "confidenceLevel": c["confidenceLevel"], "adjustedConfidenceLevel": adjusted_confidence,
                "effect": None, "confidenceInterval": None, "outcome": "undetermined",
                "roundEffects": round_effects}
            if len(retained) < c["minimumRounds"]:
                reasons.append(side + ":insufficient-retained-rounds-or-excess-noise:" + metric["metricId"])
            else:
                effect, low, high = _interval(round_effects, c["randomSeed"] + index * 7 + (0 if side == "source" else 1),
                                               c["bootstrapDraws"], adjusted_confidence)
                summary.update(effect=effect, confidenceInterval=[low, high], outcome=_conclusion(metric, low, high))
            summaries.append(summary)
            (source_conclusions if side == "source" else target_conclusions).append(summary["outcome"])
    if any(item != "supported" for item in source_conclusions):
        reasons.append("source:original-conclusion-not-reproduced")
        status = "inconclusive"
    elif any(item == "contradicted" for item in target_conclusions):
        reasons.append("target:declared-conclusion-contradicted")
        status = "failed"
    elif any(item != "supported" for item in target_conclusions):
        reasons.append("target:conclusion-evidence-insufficient")
        status = "inconclusive"
    else:
        status = "verified"
    payload = {"schemaVersion": RESULT_SCHEMA, "experimentIdentity": identity(c),
        "programId": c["programId"], "status": status, "reasonCodes": sorted(set(reasons)),
        "sourceObservationIdentity": identity(source), "targetObservationIdentity": identity(target),
        "statisticalSummaries": summaries, "claimBoundary":
        "within-platform-preregistered-conclusion;not-cross-ISA-raw-counter-equality"}
    payload["resultIdentity"] = identity(payload)
    return payload


def aggregate_statistical_results(results):
    """One program/experiment is one study unit, regardless of fragment count."""
    unique = {}
    for result in results:
        if (result.get("schemaVersion") != RESULT_SCHEMA or
                result.get("resultIdentity") != identity({k: v for k, v in result.items() if k != "resultIdentity"})):
            raise ValueError("statistical result identity invalid")
        key = (result["programId"], result["experimentIdentity"])
        if key in unique and unique[key] != result["resultIdentity"]:
            raise ValueError("conflicting results for the same program/experiment")
        unique[key] = result["resultIdentity"]
    value = {"schemaVersion": "riscv2x86.l3-statistical-group.v1", "experimentSampleCount": len(unique),
             "experimentResultIdentities": [unique[key] for key in sorted(unique)]}
    value["groupIdentity"] = identity(value)
    return value
