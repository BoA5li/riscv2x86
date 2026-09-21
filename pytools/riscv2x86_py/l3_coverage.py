"""L3 coverage over authoritative requirements and closed evidence only."""
from __future__ import annotations

from collections import Counter
from typing import Mapping, Sequence

from .l3_intent_requirements import parse_l3_requirement_manifest
from .l3_experiment_runner import EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA


DEFINITIONS = {
    "intentClassification": {"unit": "fragment", "denominator": "independently recognized corpus fragments",
                             "numerator": "fragments with complete authoritative L3 classification"},
    "eligibility": {"unit": "fragment", "denominator": "independently recognized corpus fragments",
                    "numerator": "eligible L3 fragments; other classes reported separately"},
    "attempted": {"unit": "eligible fragment", "denominator": "L3 eligible fragments",
                  "numerator": "fragments for which an experiment provider was invoked"},
    "completeExecution": {"unit": "eligible fragment", "denominator": "L3 eligible fragments",
                          "numerator": "fragments with all required properties compared with complete verified or failed evidence"},
    "architecturalIntentVerified": {"unit": "fragment", "denominator": "all independently recognized corpus fragments",
                                      "numerator": "closed L3 architectural-intent verified fragments"},
    "diagnosticVerified": {"unit": "eligible fragment", "denominator": "L3 eligible fragments",
                           "numerator": "closed target-experiment diagnostic verified fragments"},
    "inconclusive": {"unit": "eligible fragment", "denominator": "L3 eligible fragments",
                     "numerator": "attempted experiments without complete comparison evidence"},
    "notRun": {"unit": "eligible fragment", "denominator": "L3 eligible fragments",
                 "numerator": "eligible fragments with no experiment provider invocation"},
}


def summarize_l3_case(evaluation: Mapping[str, object], fragments: Sequence[Mapping[str, object]]) -> dict[str, object]:
    linkage = evaluation.get("translationEvaluationLink")
    raw = linkage.get("l3Requirements") if isinstance(linkage, Mapping) else None
    requirements = parse_l3_requirement_manifest(raw).requirements if isinstance(raw, Mapping) else ()
    findings = linkage.get("findings", []) if isinstance(linkage, Mapping) else []
    identified = {x.get("fragmentId") for x in findings
                  if isinstance(x, Mapping) and isinstance(x.get("fragmentId"), str)}
    # A missing manifest never becomes an implicit 'not applicable' classification.
    identified.update(x["fragmentId"] for x in requirements)
    results = {x["fragmentId"]: x for x in fragments}
    if len(results) != len(fragments):
        raise ValueError("L3 closed fragment results have duplicate identities")
    invocations: dict[str, set[str]] = {}
    binding_kinds = Counter()
    platform_adapters = 0
    missing = Counter()
    contract_versions = set()
    for attempt in evaluation.get("attempts", []):
        if not isinstance(attempt, Mapping):
            continue
        validation = attempt.get("validation")
        for layer in validation.get("layers", []) if isinstance(validation, Mapping) else []:
            if not isinstance(layer, Mapping) or layer.get("level") != "L3":
                continue
            import json
            try:
                detail = json.loads(layer.get("detail", ""))
            except (ValueError, TypeError):
                continue
            if not isinstance(detail, Mapping):
                continue
            fragment_id = attempt.get("fragmentId")
            if detail.get("providerInvoked") is True and isinstance(fragment_id, str):
                invocations.setdefault(fragment_id, set()).add(str(detail.get("executionIdentity", "")))
                binding_kinds[str(detail.get("providerKind", "unknown"))] += 1
                if detail.get("contractSchemaVersion") == EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA:
                    platform_adapters += 1
                if isinstance(detail.get("contractSchemaVersion"), str):
                    contract_versions.add(detail["contractSchemaVersion"])
            for reason in detail.get("reasonCodes", []) if isinstance(detail.get("reasonCodes"), list) else []:
                if isinstance(reason, str) and reason.startswith("l3.capability."):
                    missing[reason] += 1
    eligibility = Counter(x["eligibilityStatus"] for x in requirements)
    counts = Counter()
    for requirement in requirements:
        if requirement["eligibilityStatus"] != "eligible":
            continue
        fid = requirement["fragmentId"]
        result = results.get(fid)
        # A validated closed source/target report also proves a direct legacy
        # experiment runner was invoked, even without the registry marker.
        attempted = fid in invocations or bool(result is not None and
            result["requirementIdentity"] == requirement["requirementIdentity"] and
            result["dimensionResults"])
        if attempted:
            counts["attempted"] += 1
        else:
            counts["notRun"] += 1
        if result is None or result["requirementIdentity"] != requirement["requirementIdentity"]:
            if attempted:
                counts["inconclusive"] += 1
            continue
        dimensions = result["dimensionResults"]
        expected = {x["propertyId"] for x in requirement["requiredProperties"]}
        complete = (set(dimensions) == expected and not result["uncoveredEffects"] and
                    all(x["status"] in {"verified", "failed"} and
                        x["evidenceIdentity"] for x in dimensions.values()))
        if complete:
            counts["completeExecution"] += 1
        elif attempted:
            counts["inconclusive"] += 1
        if complete and result["status"] == "verified":
            if result["claimScope"] == "architectural_intent":
                counts["architecturalIntentVerified"] += 1
            elif result["claimScope"] == "target_experiment_diagnostic":
                counts["diagnosticVerified"] += 1
    counts["intentClassification"] = sum(x["eligibilityStatus"] != "inconclusive" for x in requirements)
    counts["eligibility"] = eligibility["eligible"]
    return {"recognizedFragmentCount": len(identified),
            "requirementManifestIdentity": (raw.get("manifestIdentity", "") if isinstance(raw, Mapping) else ""),
            "eligibilityCounts": dict(sorted(eligibility.items())),
            "counts": {key: counts[key] for key in DEFINITIONS},
            "providerInvocationCounts": dict(sorted(binding_kinds.items())),
            "platformAdapterInvocationCount": platform_adapters,
            "missingCapabilityCounts": dict(sorted(missing.items())),
            "contractSchemaVersions": sorted(contract_versions)}


def merge_l3_coverage(cases: Sequence[Mapping[str, object]]) -> dict[str, object]:
    counts = Counter(); eligibility = Counter(); kinds = Counter(); missing = Counter()
    versions = set(); recognized = 0
    platform_adapters = 0
    for case in cases:
        value = case.get("l3Coverage", {})
        if not isinstance(value, Mapping):
            continue
        recognized += int(value.get("recognizedFragmentCount", 0))
        counts.update(value.get("counts", {})); eligibility.update(value.get("eligibilityCounts", {}))
        kinds.update(value.get("providerInvocationCounts", {}))
        missing.update(value.get("missingCapabilityCounts", {}))
        versions.update(value.get("contractSchemaVersions", []))
        platform_adapters += int(value.get("platformAdapterInvocationCount", 0))
    return {"recognizedFragmentCount": recognized,
            "eligibilityCounts": dict(sorted(eligibility.items())),
            "counts": {key: counts[key] for key in DEFINITIONS},
            "providerInvocationCounts": dict(sorted(kinds.items())),
            "automaticProviderCoverage": kinds["automatic"],
            "explicitContractCoverage": kinds["explicit"],
            "platformAdapterCoverage": platform_adapters,
            "missingCapabilityCounts": dict(sorted(missing.items())),
            "contractSchemaVersions": sorted(versions),
            "metricDefinitions": {name: dict(definition, bootstrapCluster="program/entry or independent campaign")
                                  for name, definition in DEFINITIONS.items()}}
