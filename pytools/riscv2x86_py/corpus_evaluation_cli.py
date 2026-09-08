"""Execute declared real-corpus evaluations and emit a paper manifest/report."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
from typing import Mapping

from .evaluation import evaluation_request_from_dict, persist_evaluation_result, run_evaluation
from .paper_evaluation import (
    PAPER_CORPUS_SCHEMA, PAPER_EXECUTION_SCHEMA, PAPER_POLICY,
    aggregate_paper_corpus, paper_manifest_from_dict, render_paper_outputs,
    write_paper_outputs, _tree_identity,
)
from .translation_attempt import save_translation_attempt_archive


def _safe(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(label + " must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(label + " must be a safe relative path")
    return path


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None:
        raise ValueError(label + " must be a filesystem-safe identifier")
    return value


def run_corpus_execution(plan_path: str | Path, output_directory: str | Path) -> dict[str, object]:
    plan_file = Path(plan_path).resolve(); raw = json.loads(plan_file.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or set(raw) != {"schemaVersion", "corpus", "evaluations"}:
        raise ValueError("corpus execution plan fields are invalid")
    if raw.get("schemaVersion") != PAPER_EXECUTION_SCHEMA:
        raise ValueError("corpus execution plan schema is unsupported")
    corpus = raw.get("corpus"); evaluations = raw.get("evaluations")
    if not isinstance(corpus, Mapping) or not isinstance(evaluations, list):
        raise ValueError("corpus execution plan payload is malformed")
    output = Path(output_directory).resolve()
    if output.exists():
        raise ValueError("corpus execution output exists; refusing to overwrite")
    output.mkdir(parents=True); requests = output / "requests"; results = output / "results"
    requests.mkdir(); results.mkdir()
    seen = set(); completed = []; execution_facts = {}
    try:
        for raw_evaluation in evaluations:
            if not isinstance(raw_evaluation, Mapping) or set(raw_evaluation) != {
                "evaluationId", "request", "workDirectory", "resultPath",
            }:
                raise ValueError("corpus evaluation declaration is malformed")
            evaluation_id = _identifier(raw_evaluation["evaluationId"], "evaluationId")
            if evaluation_id in seen:
                raise ValueError("corpus evaluation identity is missing or duplicated")
            seen.add(evaluation_id)
            request_value = raw_evaluation["request"]
            if not isinstance(request_value, Mapping):
                raise ValueError("generated evaluation request must be an object")
            request = evaluation_request_from_dict(request_value)
            request_path = requests / (evaluation_id + ".json")
            request_path.write_text(json.dumps(request_value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            work = output / _safe(raw_evaluation["workDirectory"], "workDirectory")
            result_path = output / _safe(raw_evaluation["resultPath"], "resultPath")
            try:
                result = run_evaluation(request, work_directory=work)
                persist_evaluation_result(result, result_path)
                status = str(result["status"]); detail = ""
            except Exception as exc:
                status = "inconclusive"; detail = f"{type(exc).__name__}: {exc}"
                error_path = result_path.with_suffix(result_path.suffix + ".error.json")
                error_path.parent.mkdir(parents=True, exist_ok=True)
                error_path.write_text(json.dumps({
                    "schemaVersion": "riscv2x86.corpus-evaluation-error.v1",
                    "evaluationId": evaluation_id, "status": status,
                    "reasonCode": "paper.evaluation-orchestration-error", "detail": detail,
                }, indent=2, sort_keys=True) + "\n")
            completed.append({"evaluationId": evaluation_id, "status": status,
                              "request": request_path.relative_to(output).as_posix(),
                              "result": result_path.relative_to(output).as_posix(), "detail": detail})
            execution_facts[evaluation_id] = (request, work, result_path)
        if set(corpus) != {"corpusId", "corpusVersion", "bootstrap", "programs"}:
            raise ValueError("execution corpus fields are invalid")
        raw_programs = corpus.get("programs")
        if not isinstance(raw_programs, list):
            raise ValueError("execution corpus programs must be an array")
        manifest_programs = []
        source_evidence = output / "source-evidence"; source_evidence.mkdir()
        archive_evidence = output / "attempt-evidence"; archive_evidence.mkdir()
        for raw_program in raw_programs:
            if not isinstance(raw_program, Mapping) or set(raw_program) != {
                "programId", "category", "oracleFragments", "validations",
            }:
                raise ValueError("execution program fields are invalid")
            raw_validations = raw_program["validations"]
            if not isinstance(raw_validations, list) or not raw_validations:
                raise ValueError("execution program requires validation units")
            first_id = raw_validations[0].get("evaluationId") if isinstance(raw_validations[0], Mapping) else None
            if first_id not in execution_facts:
                raise ValueError("execution program has no matching evaluation")
            request, work, _result_path = execution_facts[first_id]
            program_id = _identifier(raw_program["programId"], "programId")
            source_copy = source_evidence / program_id
            shutil.copytree(Path(request.source_root).resolve(), source_copy, symlinks=False)
            archive_copy = archive_evidence / (program_id + ".json")
            archive_path = None
            for declaration in raw_validations:
                evaluation_id = declaration.get("evaluationId") if isinstance(declaration, Mapping) else None
                if evaluation_id not in execution_facts:
                    continue
                candidate_request, candidate_work, _candidate_result = execution_facts[evaluation_id]
                candidate = Path(candidate_request.attempt_archive)
                candidate = candidate.resolve() if candidate.is_absolute() else (candidate_work / candidate).resolve()
                if candidate.is_file():
                    archive_path = candidate; break
            if archive_path is None:
                save_translation_attempt_archive((), archive_copy)
            else:
                shutil.copy2(archive_path, archive_copy)
            validations = []
            for declaration in raw_validations:
                expected = {"evaluationId", "unit", "groupId", "oracleFragmentIds", "expectedEnvironmentId"}
                if not isinstance(declaration, Mapping) or set(declaration) != expected:
                    raise ValueError("execution validation declaration is malformed")
                evaluation_id = declaration["evaluationId"]
                if evaluation_id not in execution_facts:
                    raise ValueError("execution validation was not run")
                validations.append({**declaration,
                                    "evaluationResult": execution_facts[evaluation_id][2].relative_to(output).as_posix()})
            manifest_programs.append({"programId": program_id, "category": raw_program["category"],
                                      "sourceIdentity": _tree_identity(source_copy),
                                      "sourceRoot": source_copy.relative_to(output).as_posix(),
                                      "attemptArchive": archive_copy.relative_to(output).as_posix(),
                                      "oracleFragments": raw_program["oracleFragments"],
                                      "validations": validations})
        manifest_value = {"schemaVersion": PAPER_CORPUS_SCHEMA, "metricPolicy": PAPER_POLICY,
                          "corpusId": corpus["corpusId"], "corpusVersion": corpus["corpusVersion"],
                          "bootstrap": corpus["bootstrap"], "programs": manifest_programs}
        manifest = paper_manifest_from_dict(manifest_value)
        declared = {item.evaluation_id for program in manifest.programs for item in program.validations}
        if declared != seen:
            raise ValueError("executed and paper-manifest validation IDs differ")
        manifest_path = output / "paper-corpus-manifest.json"
        manifest_path.write_text(json.dumps(manifest_value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report = aggregate_paper_corpus(manifest, manifest_directory=output)
        write_paper_outputs(render_paper_outputs(report), output / "paper-report")
        run_summary = {"schemaVersion": "riscv2x86.paper-corpus-run.v1",
                       "integrityStatus": report["integrityStatus"], "evaluations": completed,
                       "manifest": "paper-corpus-manifest.json",
                       "reportIdentity": report["reportIdentity"]}
        (output / "corpus-run.json").write_text(json.dumps(run_summary, indent=2, sort_keys=True) + "\n")
        return run_summary
    except Exception:
        # Unlike a single failed evaluation, an invalid orchestration must not leave a
        # directory that looks like a complete corpus run.
        (output / "CORPUS_RUN_INCOMPLETE").write_text("execution did not complete\n")
        raise


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-corpus-evaluate")
    parser.add_argument("--execution-plan", required=True); parser.add_argument("--output-directory", required=True)
    args = parser.parse_args()
    result = run_corpus_execution(args.execution_plan, args.output_directory)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["integrityStatus"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
