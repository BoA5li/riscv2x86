"""User-facing, fail-closed orchestration for a directory of evaluations."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
from typing import Mapping

from .evaluation import (
    EVALUATION_RESULT_SCHEMA,
    evaluation_request_from_dict,
    persist_evaluation_result,
    run_evaluation,
)
from .l2_dimensions import L2Dimension


BATCH_CASE_SCHEMA = "riscv2x86.batch-evaluation-case.v1"
BATCH_RESULT_SCHEMA = "riscv2x86.batch-evaluation-result.v4"
BATCH_TEMPLATE_SCHEMA = "riscv2x86.batch-evaluation-template.v1"
BATCH_DESCRIPTOR_NAME = "riscv2x86-evaluation.json"
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]+")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _identity(value: object) -> str:
    return "sha256:" + sha256(_canonical(value)).hexdigest()


def _replace_tokens(value: object, variables: Mapping[str, str]) -> object:
    if isinstance(value, str):
        for name, replacement in variables.items():
            value = value.replace("@" + name + "@", replacement)
        return value
    if isinstance(value, list):
        return [_replace_tokens(item, variables) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _replace_tokens(item, variables) for key, item in value.items()}
    return value


def _resolve_contract_path(value: object, base: Path, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(label + " must be a non-empty path")
    path = Path(value)
    return str(path.resolve() if path.is_absolute() else (base / path).resolve())


def _load_case(path: Path, batch_output: Path) -> dict[str, object]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    expected = {"schemaVersion", "caseId", "category", "request"}
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise ValueError(f"{path}: batch case fields are incomplete or unknown")
    if raw.get("schemaVersion") != BATCH_CASE_SCHEMA:
        raise ValueError(f"{path}: batch case schema is unsupported")
    case_id, category = raw.get("caseId"), raw.get("category")
    if not isinstance(case_id, str) or _IDENTIFIER.fullmatch(case_id) is None:
        raise ValueError(f"{path}: caseId must be a filesystem-safe identifier")
    if not isinstance(category, str) or not category:
        raise ValueError(f"{path}: category must be a non-empty string")
    request = raw.get("request")
    if not isinstance(request, Mapping):
        raise ValueError(f"{path}: request must be an evaluation request object")
    case_dir = path.parent.resolve()
    resolved = _replace_tokens(request, {
        "CASE_DIR": str(case_dir), "BATCH_OUTPUT": str(batch_output),
    })
    assert isinstance(resolved, dict)
    for name in ("sourceRoot", "validationPlan", "targetEnvironment"):
        resolved[name] = _resolve_contract_path(resolved.get(name), case_dir, name)
    # Strictly validate before any case is executed.  Paths intentionally relative
    # to the per-case work tree (report/archive) remain relative.
    evaluation_request_from_dict(resolved)
    return {
        "caseId": case_id, "category": category,
        "descriptor": str(path.resolve()), "request": resolved,
        "descriptorIdentity": _identity(raw),
    }


def _template_cases(root: Path, template_path: Path, output: Path) -> tuple[dict[str, object], ...]:
    if not root.is_dir():
        raise ValueError("request-template mode requires a directory input")
    raw = json.loads(template_path.read_text(encoding="utf-8"))
    if (not isinstance(raw, Mapping)
            or set(raw) != {"schemaVersion", "category", "request"}
            or raw.get("schemaVersion") != BATCH_TEMPLATE_SCHEMA):
        raise ValueError("batch request template schema or fields are invalid")
    category, template = raw.get("category"), raw.get("request")
    if not isinstance(category, str) or not category or not isinstance(template, Mapping):
        raise ValueError("batch request template payload is malformed")
    sources = sorted(root.rglob("*.c"))
    if not sources:
        raise ValueError("request-template mode found no .c programs")
    result = []
    for source in sources:
        relative = source.relative_to(root).as_posix()
        stem = relative[:-2]
        case_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", stem.replace("/", "--")).strip("-")
        if not case_id:
            raise ValueError("could not derive a safe caseId from " + relative)
        resolved = _replace_tokens(template, {
            "CASE_ID": case_id, "CASE_DIR": str(source.parent.resolve()),
            "INPUT_ROOT": str(root), "SOURCE_RELATIVE_PATH": relative,
            "BATCH_OUTPUT": str(output),
        })
        assert isinstance(resolved, dict)
        # Directory mode owns the source inventory: these two fields cannot
        # accidentally point at a different program than the discovered file.
        resolved["sourceRoot"] = str(root)
        resolved["sourceRelativePath"] = relative
        resolved["targetRelativePath"] = relative
        for name in ("validationPlan", "targetEnvironment"):
            resolved[name] = _resolve_contract_path(
                resolved.get(name), template_path.parent.resolve(), name,
            )
        evaluation_request_from_dict(resolved)
        result.append({
            "caseId": case_id, "category": category,
            "descriptor": str(template_path.resolve()), "request": resolved,
            "descriptorIdentity": _identity({
                "template": raw,
                "relativeSource": relative,
                "sourceDigest": "sha256:" + sha256(source.read_bytes()).hexdigest(),
            }),
        })
    return tuple(result)


def discover_batch_cases(
    input_path: str | Path, batch_output: str | Path, *,
    request_template: str | Path | None = None,
) -> tuple[dict[str, object], ...]:
    root = Path(input_path).resolve(); output = Path(batch_output).resolve()
    if not root.exists():
        raise ValueError("batch input does not exist")
    if request_template is not None:
        template_path = Path(request_template).resolve()
        if not template_path.is_file():
            raise ValueError("batch request template does not exist")
        cases = _template_cases(root, template_path, output)
    else:
        paths = [root] if root.is_file() else sorted(root.rglob(BATCH_DESCRIPTOR_NAME))
        if not paths:
            raise ValueError(f"no {BATCH_DESCRIPTOR_NAME} descriptors found")
        cases = tuple(_load_case(path, output) for path in paths)
    ids = [str(item["caseId"]) for item in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("batch caseId values must be unique")
    return tuple(sorted(cases, key=lambda item: str(item["caseId"])))


def _orchestration_failure(case: Mapping[str, object], exc: Exception) -> dict[str, object]:
    payload = {
        "schemaVersion": EVALUATION_RESULT_SCHEMA,
        "evaluationIdentity": "", "requestIdentity": "",
        "status": "inconclusive",
        "reasonCodes": ["batch.evaluation-orchestration-error"],
        "candidateManifestId": "", "attempts": [], "commands": [],
        "replayArtifact": "", "detail": f"{type(exc).__name__}: {exc}",
        "caseId": case["caseId"],
    }
    return payload


def _run_case(case: Mapping[str, object], output: Path) -> dict[str, object]:
    case_id = str(case["caseId"]); case_root = output / "cases" / case_id
    case_root.mkdir(parents=True, exist_ok=False)
    shutil.copy2(str(case["descriptor"]), case_root / "case-descriptor.json")
    request_path = case_root / "evaluation-request.json"
    request_value = case["request"]
    request_path.write_text(
        json.dumps(request_value, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    try:
        request = evaluation_request_from_dict(request_value)  # type: ignore[arg-type]
        result = run_evaluation(request, work_directory=case_root / "work")
    except Exception as exc:
        result = _orchestration_failure(case, exc)
    result_path = case_root / "evaluation-result.json"
    persist_evaluation_result(result, result_path)
    level_statuses: dict[str, list[str]] = {}
    for attempt in result.get("attempts", []):
        validation = attempt.get("validation") if isinstance(attempt, Mapping) else None
        layers = validation.get("layers", []) if isinstance(validation, Mapping) else []
        for layer in layers:
            if isinstance(layer, Mapping) and isinstance(layer.get("level"), str):
                level_statuses.setdefault(str(layer["level"]), []).append(str(layer.get("status", "inconclusive")))
    program_levels = {}
    for level, statuses in sorted(level_statuses.items()):
        program_levels[level] = ("failed" if "failed" in statuses else
                                 "inconclusive" if "inconclusive" in statuses else
                                 "unsupported" if "unsupported" in statuses else
                                 "needs_route" if "needs_route" in statuses else
                                 "not_run" if "not_run" in statuses else
                                 "verified" if all(x == "verified" for x in statuses)
                                 else "inconclusive")
    for level in ("L0", "L1", "L2", "L3"):
        program_levels.setdefault(level, "not_run")
    outcomes = sorted({
        str(item.get("translationOutcome", "unknown"))
        for item in result.get("attempts", []) if isinstance(item, Mapping)
    })
    emitted = {"emitted", "strengthened", "functional_fallback"}
    command_status = {
        str(item.get("phase")): str(item.get("status"))
        for item in result.get("commands", []) if isinstance(item, Mapping)
    }
    if command_status.get("source-build") == "failed":
        disposition = "source_build_failed"
    elif command_status.get("source-build") == "inconclusive":
        disposition = "source_build_inconclusive"
    elif not any(item in emitted for item in outcomes):
        disposition = "translation_no_candidate"
    elif command_status.get("target-build") == "failed":
        disposition = "target_build_failed"
    elif command_status.get("target-build") == "inconclusive":
        disposition = "target_build_inconclusive"
    else:
        disposition = "candidate_evaluated"
    linkage = result.get("translationEvaluationLink")
    validation_groups = (
        linkage.get("validationGroups", []) if isinstance(linkage, Mapping) else []
    )
    for group in validation_groups:
        if (isinstance(group, Mapping) and group.get("level") in {"L1", "L2"}
                and group.get("status") in {
                    "verified", "failed", "inconclusive", "not_run", "not_applicable"
                }):
            program_levels[str(group["level"])] = str(group["status"])
    l2_group = next((
        item for item in validation_groups
        if isinstance(item, Mapping) and item.get("level") == "L2"
    ), {})
    l2_manifest = linkage.get("l2Requirements") if isinstance(linkage, Mapping) else None
    manifest_dispositions = (
        dict(l2_manifest.get("dispositionCounts", {}))
        if isinstance(l2_manifest, Mapping) else {}
    )
    l2_dimensions = (
        dict(l2_manifest.get("requiredDimensionCounts", {}))
        if isinstance(l2_manifest, Mapping) else {}
    )
    l2_execution_samples = (
        list(linkage.get("programExecutionEvidence", []))
        if isinstance(linkage, Mapping)
        and isinstance(linkage.get("programExecutionEvidence"), list) else []
    )
    l2_dispositions = _l2_disposition_counts(l2_group, manifest_dispositions)
    coverage = _l2_coverage_diagnostics(result, case_root)
    l3_campaigns = []
    l3_statistical = []
    l3_specialized = []
    l3_fragments = []
    for attempt in result.get("attempts", []):
        validation = attempt.get("validation") if isinstance(attempt, Mapping) else None
        for layer in validation.get("layers", []) if isinstance(validation, Mapping) else []:
            if not isinstance(layer, Mapping) or layer.get("level") != "L3":
                continue
            try:
                detail = json.loads(layer.get("detail", ""))
                if isinstance(detail, Mapping) and isinstance(detail.get("providerDetail"), str):
                    detail = json.loads(detail["providerDetail"])
            except (TypeError, json.JSONDecodeError):
                continue
            fragment_result = detail.get("fragmentResult") if isinstance(detail, Mapping) else None
            if isinstance(fragment_result, Mapping):
                from .l3_evidence_closure import parse_fragment, parse_dimension
                reports = detail.get("platformReports")
                if isinstance(reports, Mapping) and set(reports) == {"source", "target"}:
                    try:
                        fragment = parse_fragment(fragment_result)
                        for result_dimension in fragment["dimensionResults"].values():
                            parse_dimension(result_dimension, source_report=reports["source"],
                                            target_report=reports["target"])
                        l3_fragments.append(dict(fragment))
                    except (ValueError, TypeError, KeyError):
                        program_levels["L3"] = "inconclusive"
            item = (detail if isinstance(detail, Mapping) and
                    detail.get("schemaVersion") == "riscv2x86.l3-concurrency-campaign-result.v1"
                    else detail.get("campaignResult") if isinstance(detail, Mapping) else None)
            if isinstance(item, Mapping) and item.get("schemaVersion") == "riscv2x86.l3-concurrency-campaign-result.v1":
                l3_campaigns.append(dict(item))
            statistical_item = (detail if isinstance(detail, Mapping) and
                detail.get("schemaVersion") == "riscv2x86.l3-statistical-experiment-result.v1" else
                detail.get("statisticalResult") if isinstance(detail, Mapping) else None)
            if (isinstance(statistical_item, Mapping) and
                    statistical_item.get("schemaVersion") == "riscv2x86.l3-statistical-experiment-result.v1"):
                l3_statistical.append(dict(statistical_item))
            specialized_item = (detail if isinstance(detail, Mapping) and
                detail.get("schemaVersion") == "riscv2x86.l3-specialized-result.v1" else
                detail.get("specializedResult") if isinstance(detail, Mapping) else None)
            if (isinstance(specialized_item, Mapping) and
                    specialized_item.get("schemaVersion") == "riscv2x86.l3-specialized-result.v1"):
                l3_specialized.append(dict(specialized_item))
    l3_programs = []
    sidecars = list((case_root / "work").rglob("*.l3-requirements.json"))
    if program_levels["L3"] == "verified" and not l3_fragments:
        program_levels["L3"] = "inconclusive"
    if l3_fragments and len(sidecars) != 1:
        program_levels["L3"] = "inconclusive"
    if len(sidecars) == 1:
        from .l3_intent_requirements import parse_l3_requirement_manifest
        from .l3_evidence_closure import close_program
        manifest = parse_l3_requirement_manifest(json.loads(sidecars[0].read_text(encoding="utf-8")))
        grouped = {}
        for item in manifest.requirements:
            if item["eligibilityStatus"] == "eligible":
                grouped.setdefault(item["programId"], []).append(item)
        for program_id, required in sorted(grouped.items()):
            members = [x for x in l3_fragments if x["programId"] == program_id]
            scopes = {x["claimScope"] for x in members}
            scope = ("target_experiment_diagnostic" if any(x["translationOutcome"] == "functional_fallback"
                     for x in required) else "architectural_intent")
            if scopes - {scope}:
                program_levels["L3"] = "inconclusive"
                continue
            group = close_program(program_id, sorted({x["fragmentId"] for x in required}), members,
                                  claim_scope=scope)
            l3_programs.append(group)
            program_levels["L3"] = ("diagnostic_verified" if group["status"] == "verified" and
                                    scope == "target_experiment_diagnostic" else group["status"])
    from .l3_coverage import summarize_l3_case
    try:
        l3_coverage = summarize_l3_case(result, l3_fragments)
    except (ValueError, TypeError, KeyError) as exc:
        l3_coverage = {"error": "l3.coverage.evidence-invalid: " + str(exc)}
        program_levels["L3"] = "inconclusive"
    return {
        "caseId": case_id, "category": case["category"],
        "descriptorIdentity": case["descriptorIdentity"],
        "status": result["status"], "reasonCodes": result.get("reasonCodes", []),
        "evaluationIdentity": result.get("evaluationIdentity", ""),
        "resultPath": result_path.relative_to(output).as_posix(),
        "attempts": result.get("attempts", []),
        "translationOutcomes": outcomes,
        "evaluationDisposition": disposition,
        "programValidationLevels": program_levels,
        "l2RequiredMemberCount": len(l2_group.get("requiredMemberAttemptIds", []))
        if isinstance(l2_group, Mapping) else 0,
        "l2VerifiedMemberCount": sum(
            1 for item in l2_group.get("memberResults", [])
            if isinstance(item, Mapping) and item.get("required") is True
            and item.get("status") == "verified"
        ) if isinstance(l2_group, Mapping) else 0,
        "l2ProgramExecutionSampleCount": int(l2_group.get("executionSampleCount", 0))
        if isinstance(l2_group, Mapping) else 0,
        "l2ProgramExecutionSamples": l2_execution_samples,
        "l3ConcurrencyCampaignResults": l3_campaigns,
        "l3StatisticalExperimentResults": l3_statistical,
        "l3SpecializedExperimentResults": l3_specialized,
        "l3FragmentResults": l3_fragments,
        "l3ProgramResults": l3_programs,
        "l3Coverage": l3_coverage,
        "l2PrivilegedFragmentClaimCounts": _privileged_claim_counts(result.get("attempts", [])),
        "l2RequirementDispositionCounts": l2_dispositions,
        "l2RequiredDimensionCounts": l2_dimensions,
        "l2CoverageDiagnostics": coverage,
    }


def _l2_coverage_diagnostics(result: Mapping[str, object], case_root: Path) -> dict[str, object]:
    """Explain L2 coverage at the fragment-dimension unit.

    Resolved plans establish provider selection; closed dimension results establish
    whether authority, observations, relations, and comparison evidence formed.
    """
    provider_counts = {kind: Counter() for kind in
                       ("automatic", "explicit", "runtime_adapter")}
    missing_capabilities: Counter[str] = Counter()
    authority: Counter[str] = Counter()
    observations: Counter[str] = Counter()
    relations: Counter[str] = Counter()
    dimension_results: dict[tuple[str, str], Mapping[str, object]] = {}
    seen_bindings: dict[tuple[str, str], tuple[str, str, tuple[str, ...]]] = {}
    for attempt in result.get("attempts", []):
        validation = attempt.get("validation") if isinstance(attempt, Mapping) else None
        for layer in validation.get("layers", []) if isinstance(validation, Mapping) else []:
            if not isinstance(layer, Mapping) or layer.get("level") != "L2":
                continue
            try:
                detail = json.loads(str(layer.get("detail", "")))
            except json.JSONDecodeError:
                continue
            raw = detail.get("dimensionResults") if isinstance(detail, Mapping) else None
            fragment_id = detail.get("fragmentId") if isinstance(detail, Mapping) else None
            if isinstance(fragment_id, str) and isinstance(raw, Mapping):
                for dimension, value in raw.items():
                    if isinstance(dimension, str) and isinstance(value, Mapping):
                        dimension_results[(fragment_id, dimension)] = value
    plan_count = 0
    for path in sorted(case_root.rglob("*-l2-resolved-plan.json")):
        try:
            plan = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            missing_capabilities["invalid_execution_plan"] += 1
            continue
        if not isinstance(plan, Mapping) or not isinstance(plan.get("bindings"), list):
            missing_capabilities["invalid_execution_plan"] += 1
            continue
        plan_count += 1
        fragment_id = str(plan.get("fragmentId", ""))
        for binding in plan["bindings"]:
            if not isinstance(binding, Mapping):
                missing_capabilities["invalid_binding"] += 1
                continue
            dimension = str(binding.get("dimension", ""))
            status = str(binding.get("bindingStatus", "inconclusive"))
            kind = str(binding.get("bindingKind", ""))
            raw_missing = binding.get("missingCapabilities")
            missing_tuple = tuple(sorted(item for item in raw_missing
                                         if isinstance(item, str) and item)) \
                if isinstance(raw_missing, list) else ()
            binding_key = (fragment_id, dimension)
            signature = (status, kind, missing_tuple)
            previous = seen_bindings.get(binding_key)
            if previous is not None:
                if previous != signature:
                    missing_capabilities["ambiguous_binding_plan"] += 1
                continue
            seen_bindings[binding_key] = signature
            result_item = dimension_results.get((fragment_id, dimension))
            outcome = (str(result_item.get("status", "inconclusive"))
                       if isinstance(result_item, Mapping) else status)
            if kind in provider_counts:
                provider_counts[kind][outcome] += 1
            else:
                missing_capabilities["provider_unbound"] += 1
            for capability in missing_tuple:
                missing_capabilities[capability] += 1
            if result_item is None:
                authority["not_materialized"] += 1
                observations["not_produced"] += 1
                relations["not_approved"] += 1
                continue
            authority_id = result_item.get("authorityIdentity")
            authority["complete" if isinstance(authority_id, str) and
                      re.fullmatch(r"sha256:[0-9a-f]{64}", authority_id)
                      else "incomplete"] += 1
            source_id, target_id = (result_item.get("sourceObservationIdentity"),
                                    result_item.get("targetObservationIdentity"))
            source_ok = isinstance(source_id, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", source_id)
            target_ok = isinstance(target_id, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", target_id)
            observations["complete" if source_ok and target_ok else
                         "missing_source" if not source_ok and target_ok else
                         "missing_target" if source_ok and not target_ok else
                         "not_produced"] += 1
            relation_id = result_item.get("effectRelationIdentity")
            relations["approved" if isinstance(relation_id, str) and
                      re.fullmatch(r"sha256:[0-9a-f]{64}", relation_id)
                      else "not_approved"] += 1
    if plan_count == 0:
        missing_capabilities["resolved_plan_missing"] += 1
    return {
        "unit": "fragment-dimension",
        "automaticProviderCoverage": dict(sorted(provider_counts["automatic"].items())),
        "explicitHarnessCoverage": dict(sorted(provider_counts["explicit"].items())),
        "runtimeAdapterCoverage": dict(sorted(provider_counts["runtime_adapter"].items())),
        "missingCapabilityCounts": dict(sorted(missing_capabilities.items())),
        "authorityMaterializationCounts": dict(sorted(authority.items())),
        "observationProductionCounts": dict(sorted(observations.items())),
        "relationApprovalCounts": dict(sorted(relations.items())),
    }


def _merge_l2_coverage(items: object) -> dict[str, object]:
    fields = ("automaticProviderCoverage", "explicitHarnessCoverage",
              "runtimeAdapterCoverage", "missingCapabilityCounts",
              "authorityMaterializationCounts", "observationProductionCounts",
              "relationApprovalCounts")
    totals = {field: Counter() for field in fields}
    for item in items if isinstance(items, list) else []:
        coverage = item.get("l2CoverageDiagnostics") if isinstance(item, Mapping) else None
        if not isinstance(coverage, Mapping):
            continue
        for field in fields:
            raw = coverage.get(field)
            if isinstance(raw, Mapping):
                totals[field].update({str(key): int(value) for key, value in raw.items()
                                      if isinstance(value, int) and not isinstance(value, bool)})
    return {field: dict(sorted(totals[field].items())) for field in fields}


def _l2_disposition_counts(
    l2_group: object, manifest_dispositions: Mapping[str, object],
) -> dict[str, int]:
    """Return post-execution dispositions when closed member results exist.

    Requirement manifests describe the pre-execution state and commonly carry
    ``not_run``.  They are only a fallback for cases where no final required
    member result was formed.
    """
    member_results = (
        l2_group.get("memberResults", []) if isinstance(l2_group, Mapping) else []
    )
    final = Counter(
        str(item.get("status")) for item in member_results
        if isinstance(item, Mapping) and item.get("required") is True
        and item.get("status") in {
            "verified", "failed", "inconclusive", "not_run", "not_applicable",
        }
    )
    if final:
        return dict(final)
    return {
        str(key): int(value) for key, value in manifest_dispositions.items()
        if isinstance(value, int) and not isinstance(value, bool)
    }


def _write_csv(output: Path, cases: list[dict[str, object]]) -> None:
    with (output / "batch-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("case_id", "category", "status", "translation_outcomes",
                         "evaluation_disposition",
                         "l0", "l1", "l2", "l3", "evaluation_identity", "reason_codes"))
        for item in cases:
            levels = item.get("programValidationLevels", {})
            writer.writerow((
                item["caseId"], item["category"], item["status"],
                ";".join(item.get("translationOutcomes", [])),
                item["evaluationDisposition"],
                *(levels.get(level, "not_run") for level in ("L0", "L1", "L2", "L3")),
                item["evaluationIdentity"], ";".join(item["reasonCodes"]),
            ))


def _privileged_claim_counts(attempts: object) -> dict[str, int]:
    counts: Counter[str] = Counter()
    if not isinstance(attempts, list):
        return {}
    for attempt in attempts:
        validation = attempt.get("validation") if isinstance(attempt, Mapping) else None
        layers = validation.get("layers", []) if isinstance(validation, Mapping) else []
        for layer in layers:
            if not isinstance(layer, Mapping) or layer.get("level") != "L2":
                continue
            detail = layer.get("detail")
            try:
                payload = json.loads(detail) if isinstance(detail, str) else None
            except json.JSONDecodeError:
                payload = None
            candidates = []
            if isinstance(payload, Mapping):
                if payload.get("schemaVersion") == "riscv2x86.l2-privileged-result.v2":
                    candidates.append(payload)
                dimensions = payload.get("dimensions")
                privileged = (dimensions.get(L2Dimension.PRIVILEGED_STATE.value)
                              if isinstance(dimensions, Mapping) else None)
                nested = privileged.get("detail") if isinstance(privileged, Mapping) else None
                try:
                    nested_payload = json.loads(nested) if isinstance(nested, str) else None
                except json.JSONDecodeError:
                    nested_payload = None
                if (isinstance(nested_payload, Mapping)
                        and nested_payload.get("schemaVersion") == "riscv2x86.l2-privileged-result.v2"):
                    candidates.append(nested_payload)
            for item in candidates:
                claim = item.get("claimBoundary")
                if isinstance(claim, str) and claim:
                    counts[claim] += 1
    return dict(sorted(counts.items()))


def run_batch_evaluation(
    input_path: str | Path, output_directory: str | Path, *, jobs: int = 1,
    request_template: str | Path | None = None,
) -> dict[str, object]:
    if isinstance(jobs, bool) or not isinstance(jobs, int) or jobs < 1:
        raise ValueError("jobs must be a positive integer")
    output = Path(output_directory).resolve()
    if output.exists():
        raise ValueError("batch output exists; refusing to overwrite")
    # Parse and validate the entire inventory before creating an output that could
    # be mistaken for a completed corpus run.
    cases = discover_batch_cases(input_path, output, request_template=request_template)
    output.mkdir(parents=True); (output / "cases").mkdir()
    completed: list[dict[str, object]] = []
    try:
        if jobs == 1:
            completed = [_run_case(case, output) for case in cases]
        else:
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = {executor.submit(_run_case, case, output): case for case in cases}
                for future in as_completed(futures):
                    completed.append(future.result())
        completed.sort(key=lambda item: str(item["caseId"]))
        statuses = Counter(str(item["status"]) for item in completed)
        category_statuses = Counter(
            (str(item["category"]), str(item["status"])) for item in completed
        )
        reasons = Counter(
            str(reason) for item in completed for reason in item["reasonCodes"]
        )
        translation_outcomes = Counter(
            str(attempt.get("translationOutcome", "unknown"))
            for item in completed for attempt in item["attempts"]
            if isinstance(attempt, Mapping)
        )
        evaluation_dispositions = Counter(
            str(item["evaluationDisposition"]) for item in completed
        )
        program_level_counts = Counter(
            (level, status) for item in completed
            for level, status in item.get("programValidationLevels", {}).items()
        )
        l2_requirement_dispositions = Counter()
        l2_required_dimensions = Counter()
        l2_privileged_claims = Counter()
        l2_execution_sample_keys: set[tuple[str, str, str]] = set()
        l3_campaign_results = []
        l3_statistical_results = []
        l3_specialized_results = []
        for item in completed:
            l3_campaign_results.extend(item.get("l3ConcurrencyCampaignResults", []))
            l3_statistical_results.extend(item.get("l3StatisticalExperimentResults", []))
            l3_specialized_results.extend(item.get("l3SpecializedExperimentResults", []))
            l2_requirement_dispositions.update(item.get("l2RequirementDispositionCounts", {}))
            l2_required_dimensions.update(item.get("l2RequiredDimensionCounts", {}))
            l2_privileged_claims.update(item.get("l2PrivilegedFragmentClaimCounts", {}))
            for evidence in item.get("l2ProgramExecutionSamples", []):
                if isinstance(evidence, Mapping):
                    key = tuple(str(evidence.get(name, "")) for name in (
                        "programId", "executionIdentity", "sampleSetIdentity",
                    ))
                    if all(key):
                        l2_execution_sample_keys.add(key)
        payload: dict[str, object] = {
            "schemaVersion": BATCH_RESULT_SCHEMA,
            "batchIdentity": "", "caseCount": len(completed),
            "statusCounts": dict(sorted(statuses.items())),
            "categoryStatusCounts": {
                category: {
                    status: count
                    for (item_category, status), count in sorted(category_statuses.items())
                    if item_category == category
                }
                for category in sorted({key[0] for key in category_statuses})
            },
            "translationOutcomeCounts": dict(sorted(translation_outcomes.items())),
            "evaluationDispositionCounts": dict(sorted(evaluation_dispositions.items())),
            "programValidationCounts": {
                level: {status: count for (item_level, status), count in sorted(program_level_counts.items())
                        if item_level == level}
                for level in sorted({item[0] for item in program_level_counts})
            },
            "programValidationDenominators": {
                level: len(completed) for level in ("L0", "L1", "L2", "L3")
            },
            "programValidationApplicableDenominators": {
                level: sum(
                    1 for item in completed
                    if item.get("programValidationLevels", {}).get(level)
                    not in {"not_applicable"}
                )
                for level in ("L0", "L1", "L2", "L3")
            },
            "l2MemberCounts": {
                "required": sum(int(item.get("l2RequiredMemberCount", 0)) for item in completed),
                "verified": sum(int(item.get("l2VerifiedMemberCount", 0)) for item in completed),
            },
            "l2ProgramExecutionSampleCount": len(l2_execution_sample_keys),
            "l3ConcurrencyCampaignSampleCount": 0,
            "l3StatisticalExperimentSampleCount": 0,
            "l3SpecializedExperimentSampleCount": 0,
            "l3ArchitecturalIntentVerifiedProgramCount": sum(
                1 for item in completed for result in item.get("l3ProgramResults", [])
                if result["claimScope"] == "architectural_intent" and result["status"] == "verified"),
            "l3TargetDiagnosticVerifiedProgramCount": sum(
                1 for item in completed for result in item.get("l3ProgramResults", [])
                if result["claimScope"] == "target_experiment_diagnostic" and result["status"] == "verified"),
            "l2PrivilegedFragmentClaimCounts": dict(sorted(l2_privileged_claims.items())),
            "l2RequirementDispositionCounts": dict(sorted(l2_requirement_dispositions.items())),
            "l2RequiredDimensionCounts": dict(sorted(l2_required_dimensions.items())),
            "l2RequirementDenominator": sum(l2_requirement_dispositions.values()),
            "l2CoverageDiagnostics": _merge_l2_coverage(completed),
            "l2CoverageMetricDefinitions": {
                "providerCoverageUnit": "required fragment-dimension binding",
                "authorityMaterializationUnit": "required fragment-dimension",
                "observationProductionUnit": "required fragment-dimension",
                "relationApprovalUnit": "required fragment-dimension",
                "missingCapabilityUnit": "unresolved fragment-dimension capability",
            },
            "statisticalUnits": {"translationCoverage": "fragment",
                                 "l2RequirementCoverage": "fragment",
                                 "validationRates": "program",
                                 "bootstrapCluster": "program"},
            "reasonCodeCounts": dict(sorted(reasons.items())),
            "cases": [{key: value for key, value in item.items() if key != "attempts"}
                      for item in completed],
        }
        if l3_campaign_results:
            from .l3_concurrency_campaign import aggregate_campaign_results
            group = aggregate_campaign_results(l3_campaign_results)
            payload["l3ConcurrencyCampaignSampleCount"] = group["campaignSampleCount"]
            payload["l3ConcurrencyCampaignGroupIdentity"] = group["groupIdentity"]
        if l3_statistical_results:
            from .l3_statistical_experiment import aggregate_statistical_results
            group = aggregate_statistical_results(l3_statistical_results)
            payload["l3StatisticalExperimentSampleCount"] = group["experimentSampleCount"]
            payload["l3StatisticalExperimentGroupIdentity"] = group["groupIdentity"]
        if l3_specialized_results:
            from .l3_specialized_experiment import aggregate_specialized_results
            group = aggregate_specialized_results(l3_specialized_results)
            payload["l3SpecializedExperimentSampleCount"] = group["experimentSampleCount"]
            payload["l3SpecializedExperimentGroupIdentity"] = group["groupIdentity"]
        payload["statisticalUnits"]["l3ConcurrencyCampaign"] = "unique programId + campaignIdentity"
        payload["statisticalUnits"]["l3StatisticalExperiment"] = "unique programId + experimentIdentity; within-program paired experiment rounds"
        payload["statisticalUnits"]["l3SpecializedExperiment"] = "unique programId + registered experimentIdentity"
        from .l3_coverage import merge_l3_coverage
        payload["l3Coverage"] = merge_l3_coverage(completed)
        payload["statisticalUnits"]["l3Intent"] = "independent recognized fragment"
        payload["statisticalUnits"]["l3Experiment"] = "program/entry or independent campaign"
        identity_value = dict(payload); identity_value.pop("batchIdentity")
        payload["batchIdentity"] = _identity(identity_value)
        (output / "batch-evaluation.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        _write_csv(output, completed)
        return payload
    except Exception:
        (output / "BATCH_RUN_INCOMPLETE").write_text(
            "batch orchestration did not complete\n", encoding="utf-8",
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-batch-evaluate")
    parser.add_argument("--input", required=True,
                        help=f"A {BATCH_DESCRIPTOR_NAME} file or directory tree")
    parser.add_argument("--output-directory", required=True)
    parser.add_argument(
        "--request-template",
        help="Shared request template; when set, every .c below --input is a program",
    )
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    try:
        result = run_batch_evaluation(
            args.input, args.output_directory, jobs=args.jobs,
            request_template=args.request_template,
        )
    except Exception as exc:
        print(json.dumps({"status": "inconclusive", "reasonCode": "batch.configuration-error",
                          "detail": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2
    print(json.dumps({"batchIdentity": result["batchIdentity"],
                      "caseCount": result["caseCount"],
                      "statusCounts": result["statusCounts"]}, sort_keys=True))
    statuses = result["statusCounts"]
    return 0 if isinstance(statuses, Mapping) and set(statuses).issubset({"verified"}) else 1


if __name__ == "__main__":
    raise SystemExit(main())
