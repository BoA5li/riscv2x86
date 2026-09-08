"""Fail-closed corpus aggregation for reproducible paper metrics."""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from hashlib import sha256
import io
import json
from pathlib import Path
import random
import re
import shutil
from typing import Mapping, Sequence

from .evaluation import EVALUATION_RESULT_SCHEMA, LEGACY_EVALUATION_RESULT_SCHEMA
from .schema import TranslationOutcome
from .validation_status import ValidationStatus


CORPUS_MANIFEST_SCHEMA = "riscv2x86.corpus-manifest.v1"
CORPUS_EVALUATION_SCHEMA = "riscv2x86.corpus-evaluation.v1"
AGGREGATION_POLICY = "riscv2x86.corpus-denominators.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_EMITTED = {"emitted", "strengthened", "functional_fallback"}
_DENOMINATORS = {
    "corpusEntryCount": "all declared corpus entries",
    "translationAttemptCount": "all manifest-declared expected attempts",
    "translationSuccessRate": "emitted attempts / all manifest-declared expected attempts",
    "validationVerifiedRate": "verified attempts / all manifest-declared expected attempts",
    "conditionalCorrectnessRate": "verified emitted attempts / evaluated emitted attempts",
    "inconclusiveRate": "inconclusive attempts / all manifest-declared expected attempts",
    "failureRate": "failed, invalid, or missing attempts / all manifest-declared expected attempts",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _text(value: Mapping[str, object], name: str, *, empty: bool = False) -> str:
    item = value.get(name)
    if not isinstance(item, str) or (not empty and not item):
        raise ValueError("corpus manifest " + name + " must be a string")
    return item


def _canonical_strings(value: object, label: str, *, empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an array of non-empty strings")
    result = tuple(value)
    if result != tuple(sorted(set(result))) or (not empty and not result):
        raise ValueError(label + " must be unique and canonically sorted")
    return result


@dataclass(frozen=True)
class BootstrapSpec:
    seed: int
    resamples: int
    confidence_level: float

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or self.seed < 0:
            raise ValueError("bootstrap seed is invalid")
        if isinstance(self.resamples, bool) or self.resamples < 100:
            raise ValueError("bootstrap requires at least 100 resamples")
        if not 0.5 < self.confidence_level < 1.0:
            raise ValueError("bootstrap confidence level is invalid")


@dataclass(frozen=True)
class CorpusEntry:
    entry_id: str
    category: str
    subcategory: str
    source_identity: str
    evaluation_result: str
    expected_attempt_ids: tuple[str, ...]
    expected_environment_id: str
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        if not all((self.entry_id, self.category, self.source_identity,
                    self.evaluation_result, self.expected_environment_id)):
            raise ValueError("corpus entry identity is incomplete")
        if _SHA256.fullmatch(self.source_identity) is None:
            raise ValueError("corpus source identity must be sha256")
        result_path = Path(self.evaluation_result)
        if result_path.is_absolute() or ".." in result_path.parts:
            raise ValueError("corpus evaluation result must be a safe relative path")
        if not self.expected_attempt_ids or any(
            _SHA256.fullmatch(item) is None for item in self.expected_attempt_ids
        ):
            raise ValueError("corpus expected attempt identities are invalid")
        if self.expected_attempt_ids != tuple(sorted(set(self.expected_attempt_ids))):
            raise ValueError("corpus expected attempt identities are not canonical")
        if self.tags != tuple(sorted(set(self.tags))):
            raise ValueError("corpus tags are not canonical")


@dataclass(frozen=True)
class CorpusManifest:
    corpus_id: str
    corpus_version: str
    description: str
    bootstrap: BootstrapSpec
    entries: tuple[CorpusEntry, ...]
    schema_version: str = CORPUS_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != CORPUS_MANIFEST_SCHEMA or not self.corpus_id or not self.corpus_version:
            raise ValueError("corpus manifest identity/schema is invalid")
        if not self.entries:
            raise ValueError("corpus manifest must declare entries")
        keys = tuple(item.entry_id for item in self.entries)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("corpus entries must be unique and canonically sorted")


def corpus_manifest_from_dict(value: Mapping[str, object]) -> CorpusManifest:
    fields = {"schemaVersion", "corpusId", "corpusVersion", "description",
              "aggregationPolicy", "denominatorDefinitions", "bootstrap", "entries"}
    if set(value) != fields or value.get("schemaVersion") != CORPUS_MANIFEST_SCHEMA:
        raise ValueError("corpus manifest schema or fields are invalid")
    if value.get("aggregationPolicy") != AGGREGATION_POLICY:
        raise ValueError("corpus aggregation policy is unsupported")
    if value.get("denominatorDefinitions") != _DENOMINATORS:
        raise ValueError("corpus denominator definitions do not match the frozen policy")
    raw_bootstrap = value.get("bootstrap")
    if not isinstance(raw_bootstrap, Mapping) or set(raw_bootstrap) != {
        "seed", "resamples", "confidenceLevel",
    }:
        raise ValueError("corpus bootstrap contract is malformed")
    seed, resamples, confidence = (raw_bootstrap.get("seed"), raw_bootstrap.get("resamples"),
                                   raw_bootstrap.get("confidenceLevel"))
    if (isinstance(seed, bool) or not isinstance(seed, int) or isinstance(resamples, bool)
            or not isinstance(resamples, int) or isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))):
        raise ValueError("corpus bootstrap values have invalid JSON types")
    raw_entries = value.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("corpus entries must be an array")
    entries = []
    entry_fields = {"entryId", "category", "subcategory", "sourceIdentity",
                    "evaluationResult", "expectedAttemptIds", "expectedEnvironmentId", "tags"}
    for raw in raw_entries:
        if not isinstance(raw, Mapping) or set(raw) != entry_fields:
            raise ValueError("corpus entry fields are invalid")
        entries.append(CorpusEntry(
            _text(raw, "entryId"), _text(raw, "category"),
            _text(raw, "subcategory", empty=True), _text(raw, "sourceIdentity"),
            _text(raw, "evaluationResult"),
            _canonical_strings(raw.get("expectedAttemptIds"), "expectedAttemptIds", empty=False),
            _text(raw, "expectedEnvironmentId"),
            _canonical_strings(raw.get("tags"), "tags"),
        ))
    return CorpusManifest(
        _text(value, "corpusId"), _text(value, "corpusVersion"),
        _text(value, "description", empty=True),
        BootstrapSpec(seed, resamples, float(confidence)), tuple(entries),
        _text(value, "schemaVersion"),
    )


def load_corpus_manifest(path: str | Path) -> CorpusManifest:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("corpus manifest root must be an object")
    return corpus_manifest_from_dict(value)


def _load_evaluation(path: Path) -> Mapping[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    fields = {"schemaVersion", "requestIdentity", "status", "reasonCodes",
              "candidateManifestId", "attempts", "commands", "replayArtifact",
              "evaluationIdentity", "validationPlan", "targetEnvironment",
              "sourceProgramArtifact", "targetProgramArtifact", "comparisonPolicy"}
    attribution_fields = {"validationUnit", "validationGroupId", "selectedAttemptIds",
                          "environmentProvenance"}
    if not isinstance(value, Mapping):
        raise ValueError("evaluation result fields are incomplete or unknown")
    schema = value.get("schemaVersion")
    valid_shape = ((schema == LEGACY_EVALUATION_RESULT_SCHEMA and set(value) == fields)
                   or (schema == EVALUATION_RESULT_SCHEMA and set(value) == fields | attribution_fields))
    if not valid_shape:
        raise ValueError("evaluation result schema or fields are unsupported")
    identity = value.get("evaluationIdentity")
    if not isinstance(identity, str) or _SHA256.fullmatch(identity) is None:
        raise ValueError("evaluation identity is invalid")
    payload = dict(value)
    payload.pop("evaluationIdentity")
    payload.pop("replayArtifact")
    if _digest(_canonical(payload)) != identity:
        raise ValueError("evaluation identity does not match content")
    attempts = value.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("evaluation attempts are invalid")
    seen = set()
    attempt_fields = {"findingId", "fragmentId", "attemptArtifactId", "translationOutcome",
                      "status", "validation", "translationArtifact", "reasonCodes", "replayArtifacts"}
    for attempt in attempts:
        if not isinstance(attempt, Mapping) or set(attempt) != attempt_fields:
            raise ValueError("evaluation attempt is malformed")
        ident = attempt.get("attemptArtifactId")
        if not isinstance(ident, str) or _SHA256.fullmatch(ident) is None or ident in seen:
            raise ValueError("evaluation attempt identity is invalid or duplicated")
        seen.add(ident)
        TranslationOutcome(str(attempt.get("translationOutcome")))
        ValidationStatus(str(attempt.get("status")))
        reasons = attempt.get("reasonCodes")
        if not isinstance(reasons, list) or not all(isinstance(item, str) and item for item in reasons):
            raise ValueError("evaluation attempt reason codes are invalid")
        validation = attempt.get("validation")
        if validation is not None:
            if not isinstance(validation, Mapping) or not isinstance(validation.get("layers"), list):
                raise ValueError("evaluation validation layers are malformed")
            for layer in validation["layers"]:
                if (not isinstance(layer, Mapping) or set(layer) !=
                        {"level", "status", "evidenceIdentity", "detail"}):
                    raise ValueError("evaluation validation layer is malformed")
                ValidationStatus(str(layer.get("status")))
    return value


def _synthetic(entry: CorpusEntry, attempt_id: str, state: str, reason: str) -> dict[str, object]:
    return {"entryId": entry.entry_id, "category": entry.category,
            "subcategory": entry.subcategory, "attemptArtifactId": attempt_id,
            "translationOutcome": "unknown", "status": state,
            "reasonCodes": [reason], "verifiedLevels": [],
            "environmentId": entry.expected_environment_id, "evaluationIdentity": ""}


def _records(manifest: CorpusManifest, base: Path):
    records = []
    integrity_errors = []
    environments: dict[str, dict[str, str]] = {}
    for entry in manifest.entries:
        path = (base / entry.evaluation_result).resolve()
        if not path.is_file():
            integrity_errors.append({"entryId": entry.entry_id,
                                     "reasonCode": "aggregation.evaluation-missing",
                                     "path": entry.evaluation_result})
            records.extend(_synthetic(entry, ident, "missing", "aggregation.evaluation-missing")
                           for ident in entry.expected_attempt_ids)
            continue
        try:
            evaluation = _load_evaluation(path)
            environment = evaluation.get("targetEnvironment")
            environment_id = entry.expected_environment_id
            if environment is None:
                integrity_errors.append({"entryId": entry.entry_id,
                                         "reasonCode": "aggregation.environment-metadata-missing"})
            elif not isinstance(environment, Mapping):
                raise ValueError("evaluation target environment is malformed")
            else:
                environment_id = environment.get("environmentId")
                if environment_id != entry.expected_environment_id:
                    raise ValueError("evaluation environment identity does not match corpus manifest")
                environments[str(environment_id)] = {
                    "environmentId": str(environment_id),
                    "sourceIsa": str(environment.get("sourceIsa", "")),
                    "sourceAbi": str(environment.get("sourceAbi", "")),
                    "targetIsa": str(environment.get("targetIsa", "")),
                    "targetAbi": str(environment.get("targetAbi", "")),
                    "runtimeIdentity": str(environment.get("runtimeIdentity", "")),
                    "loaderIdentity": str(environment.get("loaderIdentity", "")),
                }
            attempts = {item["attemptArtifactId"]: item for item in evaluation["attempts"]}
            expected = set(entry.expected_attempt_ids)
            unexpected = sorted(set(attempts) - expected)
            missing = sorted(expected - set(attempts))
            if unexpected:
                integrity_errors.append({"entryId": entry.entry_id,
                                         "reasonCode": "aggregation.unexpected-attempts",
                                         "attemptIds": unexpected})
            if missing:
                integrity_errors.append({"entryId": entry.entry_id,
                                         "reasonCode": "aggregation.expected-attempts-missing",
                                         "attemptIds": missing})
            for ident in entry.expected_attempt_ids:
                attempt = attempts.get(ident)
                if attempt is None:
                    records.append(_synthetic(entry, ident, "missing",
                                              "aggregation.expected-attempt-missing"))
                    continue
                validation = attempt.get("validation")
                levels = [] if not isinstance(validation, Mapping) else [
                    item["level"] for item in validation["layers"]
                    if item["status"] == "verified"
                ]
                records.append({
                    "entryId": entry.entry_id, "category": entry.category,
                    "subcategory": entry.subcategory, "attemptArtifactId": ident,
                    "translationOutcome": attempt["translationOutcome"],
                    "status": attempt["status"],
                    "reasonCodes": sorted(set(attempt["reasonCodes"])),
                    "verifiedLevels": levels, "environmentId": str(environment_id),
                    "evaluationIdentity": evaluation["evaluationIdentity"],
                })
        except (OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
            integrity_errors.append({"entryId": entry.entry_id,
                                     "reasonCode": "aggregation.evaluation-invalid",
                                     "detail": f"{type(exc).__name__}: {exc}"})
            records.extend(_synthetic(entry, ident, "invalid", "aggregation.evaluation-invalid")
                           for ident in entry.expected_attempt_ids)
    return records, integrity_errors, environments


def _percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires samples")
    position = probability * (len(ordered) - 1)
    lower, upper = int(position), min(int(position) + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _bootstrap(values: Sequence[int], spec: BootstrapSpec, salt: str) -> dict[str, object]:
    if not values:
        return {"estimate": None, "lower": None, "upper": None,
                "confidenceLevel": spec.confidence_level, "resamples": spec.resamples}
    estimate = sum(values) / len(values)
    seed = int(sha256((str(spec.seed) + ":" + salt).encode()).hexdigest()[:16], 16)
    generator = random.Random(seed)
    samples = [sum(values[generator.randrange(len(values))] for _ in values) / len(values)
               for _ in range(spec.resamples)]
    alpha = (1.0 - spec.confidence_level) / 2.0
    return {"estimate": estimate, "lower": _percentile(samples, alpha),
            "upper": _percentile(samples, 1.0 - alpha),
            "confidenceLevel": spec.confidence_level, "resamples": spec.resamples}


def _summary(records: Sequence[Mapping[str, object]], spec: BootstrapSpec,
             scope: str, category: str, subcategory: str) -> dict[str, object]:
    total = len(records)
    emitted = [item for item in records if item["translationOutcome"] in _EMITTED]
    evaluated_emitted = [item for item in emitted if item["status"] in {"verified", "failed", "inconclusive"}]
    verified = [item for item in records if item["status"] == "verified"]
    verified_emitted = [item for item in evaluated_emitted if item["status"] == "verified"]
    inconclusive = [item for item in records if item["status"] == "inconclusive"]
    failed = [item for item in records if item["status"] in {"failed", "invalid", "missing"}]
    vectors = {
        "translationSuccessRate": [int(item["translationOutcome"] in _EMITTED) for item in records],
        "validationVerifiedRate": [int(item["status"] == "verified") for item in records],
        "conditionalCorrectnessRate": [int(item["status"] == "verified") for item in evaluated_emitted],
        "inconclusiveRate": [int(item["status"] == "inconclusive") for item in records],
        "failureRate": [int(item["status"] in {"failed", "invalid", "missing"}) for item in records],
    }
    return {
        "scope": scope, "category": category, "subcategory": subcategory,
        "declaredAttempts": total, "emittedAttempts": len(emitted),
        "evaluatedEmittedAttempts": len(evaluated_emitted),
        "verifiedAttempts": len(verified), "verifiedEmittedAttempts": len(verified_emitted),
        "inconclusiveAttempts": len(inconclusive), "failedInvalidMissingAttempts": len(failed),
        "metrics": {name: _bootstrap(values, spec, scope + ":" + category + ":" + subcategory + ":" + name)
                    for name, values in vectors.items()},
    }


def aggregate_corpus(manifest: CorpusManifest, *, manifest_directory: str | Path) -> dict[str, object]:
    records, errors, environments = _records(manifest, Path(manifest_directory).resolve())
    summaries = [_summary(records, manifest.bootstrap, "all", "all", "all")]
    category_names = sorted(set(str(item["category"]) for item in records))
    for category in category_names:
        selected = [item for item in records if item["category"] == category]
        summaries.append(_summary(selected, manifest.bootstrap, "category", category, "all"))
    subcategories = sorted(set((str(item["category"]), str(item["subcategory"]))
                               for item in records if item["subcategory"]))
    for category, subcategory in subcategories:
        selected = [item for item in records if item["category"] == category
                    and item["subcategory"] == subcategory]
        summaries.append(_summary(selected, manifest.bootstrap, "subcategory", category, subcategory))
    reasons: dict[tuple[str, str], int] = {}
    for item in records:
        codes = item["reasonCodes"] or (["aggregation.no-reason-code"] if item["status"] != "verified" else [])
        for code in codes:
            key = (str(item["category"]), str(code))
            reasons[key] = reasons.get(key, 0) + 1
    environment_rows = []
    for environment_id in sorted(set(str(item["environmentId"]) for item in records)):
        selected = [item for item in records if item["environmentId"] == environment_id]
        row = dict(environments.get(environment_id, {
            "environmentId": environment_id, "sourceIsa": "", "sourceAbi": "",
            "targetIsa": "", "targetAbi": "", "runtimeIdentity": "",
            "loaderIdentity": "",
        }))
        row.update({
            "declaredAttempts": len(selected),
            "verifiedAttempts": sum(item["status"] == "verified" for item in selected),
            "failedAttempts": sum(item["status"] == "failed" for item in selected),
            "inconclusiveAttempts": sum(item["status"] == "inconclusive" for item in selected),
            "missingInvalidAttempts": sum(item["status"] in {"missing", "invalid"} for item in selected),
        })
        environment_rows.append(row)
    payload: dict[str, object] = {
        "schemaVersion": CORPUS_EVALUATION_SCHEMA,
        "aggregationPolicy": AGGREGATION_POLICY,
        "corpusId": manifest.corpus_id, "corpusVersion": manifest.corpus_version,
        "denominatorDefinitions": _DENOMINATORS,
        "bootstrap": {"seed": manifest.bootstrap.seed, "resamples": manifest.bootstrap.resamples,
                      "confidenceLevel": manifest.bootstrap.confidence_level},
        "integrityStatus": "failed" if errors else "verified",
        "integrityErrors": errors, "records": records, "summaries": summaries,
        "reasonBreakdown": [{"category": key[0], "reasonCode": key[1], "count": count,
                             "fractionOfDeclaredAttempts": (count / len(records) if records else None)}
                            for key, count in sorted(reasons.items())],
        "environments": environment_rows,
    }
    payload["aggregationIdentity"] = _digest(_canonical(payload))
    return payload


def _format(value: object) -> str:
    return "" if value is None else f"{float(value):.6f}"


def render_outputs(result: Mapping[str, object]) -> dict[str, str]:
    summary_buffer = io.StringIO(newline="")
    fields = ["scope", "category", "subcategory", "declaredAttempts", "emittedAttempts",
              "evaluatedEmittedAttempts", "verifiedAttempts", "verifiedEmittedAttempts",
              "inconclusiveAttempts", "failedInvalidMissingAttempts", "metric", "estimate",
              "ciLower", "ciUpper", "confidenceLevel", "resamples"]
    writer = csv.DictWriter(summary_buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for summary in result["summaries"]:
        for name, metric in summary["metrics"].items():
            row = {key: summary[key] for key in fields[:10]}
            row.update({"metric": name, "estimate": _format(metric["estimate"]),
                        "ciLower": _format(metric["lower"]), "ciUpper": _format(metric["upper"]),
                        "confidenceLevel": metric["confidenceLevel"], "resamples": metric["resamples"]})
            writer.writerow(row)
    failure_buffer = io.StringIO(newline="")
    failure_writer = csv.DictWriter(failure_buffer, fieldnames=["category", "reasonCode", "count",
                                                                  "fractionOfDeclaredAttempts"],
                                    lineterminator="\n")
    failure_writer.writeheader(); failure_writer.writerows(result["reasonBreakdown"])
    environment_buffer = io.StringIO(newline="")
    environment_fields = ["environmentId", "sourceIsa", "sourceAbi", "targetIsa", "targetAbi",
                          "runtimeIdentity", "loaderIdentity", "declaredAttempts",
                          "verifiedAttempts", "failedAttempts", "inconclusiveAttempts",
                          "missingInvalidAttempts"]
    environment_writer = csv.DictWriter(environment_buffer, fieldnames=environment_fields, lineterminator="\n")
    environment_writer.writeheader(); environment_writer.writerows(result["environments"])
    md = ["# Corpus evaluation tables", "", f"Aggregation identity: `{result['aggregationIdentity']}`",
          "", f"Integrity status: **{result['integrityStatus']}**", "", "## Denominator definitions", "",
          "| Metric | Definition |", "|---|---|"]
    md.extend(f"| {key} | {value} |" for key, value in result["denominatorDefinitions"].items())
    md.extend(["", "## Aggregate and per-category metrics", "",
               "| Scope | Category | Subcategory | Metric | Estimate | Bootstrap CI | N |",
               "|---|---|---|---|---:|---:|---:|"])
    for summary in result["summaries"]:
        for name, metric in summary["metrics"].items():
            ci = "n/a" if metric["lower"] is None else f"[{metric['lower']:.4f}, {metric['upper']:.4f}]"
            md.append(f"| {summary['scope']} | {summary['category']} | {summary['subcategory']} | "
                      f"{name} | {_format(metric['estimate']) or 'n/a'} | {ci} | {summary['declaredAttempts']} |")
    md.extend(["", "## Failure and inconclusive reasons", "",
               "| Category | Reason code | Count | Fraction of declared attempts |",
               "|---|---|---:|---:|"])
    md.extend(f"| {item['category']} | `{item['reasonCode']}` | {item['count']} | "
              f"{_format(item['fractionOfDeclaredAttempts'])} |"
              for item in result["reasonBreakdown"])
    if result["integrityErrors"]:
        md.extend(["", "## Corpus integrity errors", "", "```json",
                   json.dumps(result["integrityErrors"], indent=2, sort_keys=True), "```"])
    return {
        "corpus-evaluation.json": json.dumps(result, indent=2, sort_keys=True) + "\n",
        "corpus-summary.csv": summary_buffer.getvalue(),
        "failure-breakdown.csv": failure_buffer.getvalue(),
        "environment-matrix.csv": environment_buffer.getvalue(),
        "paper-tables.md": "\n".join(md) + "\n",
    }


def write_outputs(outputs: Mapping[str, str], output_directory: str | Path) -> None:
    destination = Path(output_directory).resolve()
    if destination.exists():
        raise ValueError("aggregation output directory exists; refusing to overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".aggregate.tmp")
    if temporary.exists():
        raise ValueError("aggregation temporary directory exists; refusing to overwrite")
    temporary.mkdir()
    try:
        for name, content in outputs.items():
            (temporary / name).write_text(content, encoding="utf-8")
        temporary.replace(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-evaluation-aggregate")
    parser.add_argument("--corpus-manifest", required=True)
    parser.add_argument("--output-directory", required=True)
    args = parser.parse_args()
    manifest_path = Path(args.corpus_manifest).resolve()
    manifest = load_corpus_manifest(manifest_path)
    result = aggregate_corpus(manifest, manifest_directory=manifest_path.parent)
    write_outputs(render_outputs(result), args.output_directory)
    print(json.dumps({"aggregationIdentity": result["aggregationIdentity"],
                      "integrityStatus": result["integrityStatus"],
                      "declaredAttempts": result["summaries"][0]["declaredAttempts"]}, sort_keys=True))
    return 0 if result["integrityStatus"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
