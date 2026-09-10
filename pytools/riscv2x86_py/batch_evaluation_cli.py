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


BATCH_CASE_SCHEMA = "riscv2x86.batch-evaluation-case.v1"
BATCH_RESULT_SCHEMA = "riscv2x86.batch-evaluation-result.v1"
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
                                 "inconclusive" if "inconclusive" in statuses else "verified")
    return {
        "caseId": case_id, "category": case["category"],
        "descriptorIdentity": case["descriptorIdentity"],
        "status": result["status"], "reasonCodes": result.get("reasonCodes", []),
        "evaluationIdentity": result.get("evaluationIdentity", ""),
        "resultPath": result_path.relative_to(output).as_posix(),
        "attempts": result.get("attempts", []),
        "programValidationLevels": program_levels,
    }


def _write_csv(output: Path, cases: list[dict[str, object]]) -> None:
    with (output / "batch-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("case_id", "category", "status", "evaluation_identity", "reason_codes"))
        for item in cases:
            writer.writerow((item["caseId"], item["category"], item["status"],
                             item["evaluationIdentity"], ";".join(item["reasonCodes"])))


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
        program_level_counts = Counter(
            (level, status) for item in completed
            for level, status in item.get("programValidationLevels", {}).items()
        )
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
            "programValidationCounts": {
                level: {status: count for (item_level, status), count in sorted(program_level_counts.items())
                        if item_level == level}
                for level in sorted({item[0] for item in program_level_counts})
            },
            "statisticalUnits": {"translationCoverage": "fragment",
                                 "validationRates": "program",
                                 "bootstrapCluster": "program"},
            "reasonCodeCounts": dict(sorted(reasons.items())),
            "cases": [{key: value for key, value in item.items() if key != "attempts"}
                      for item in completed],
        }
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
