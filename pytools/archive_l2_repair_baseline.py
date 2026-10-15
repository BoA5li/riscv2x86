#!/usr/bin/env python3
"""Freeze and verify one generated-suite L2 repair baseline.

The archive is evidence, not a production decision input.  It records the
exact repository/toolchain provenance and copies only the artifacts required
to distinguish the scalar authority-join failure from the fence staging
failure.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
from typing import Iterator


def identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


def load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: JSON root must be an object")
    return value


def objects(value: object) -> Iterator[dict[str, object]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


def run(argv: list[str], cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                            check=False)
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(argv)} failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result.stdout.strip()


def copy_required(source: Path, target: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"required baseline artifact is missing: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def dimension_rows(batch: dict[str, object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in objects(batch):
        dimension = item.get("dimension")
        status = item.get("status")
        if not isinstance(dimension, str) or not isinstance(status, str):
            continue
        row = {
            key: item.get(key)
            for key in (
                "fragmentId", "dimension", "required", "status", "reasonCode",
                "reasonCodes", "authorityIdentity", "effectRelationIdentity",
                "executionIdentity", "sourceObservationIdentity",
                "targetObservationIdentity",
            )
            if key in item
        }
        key = json.dumps(row, sort_keys=True, separators=(",", ":"))
        if key not in seen:
            seen.add(key)
            rows.append(row)
    return sorted(rows, key=lambda item: (
        str(item.get("fragmentId", "")), str(item.get("dimension", "")),
        str(item.get("status", "")), json.dumps(item, sort_keys=True),
    ))


def case_has_reason(path: Path, reason: str) -> bool:
    return reason in set(strings(json.loads(path.read_text(encoding="utf-8"))))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict-out", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--baseline", type=Path,
        default=Path("experiment/baselines/phase43-l2-before-authority-v3.json"),
    )
    parser.add_argument("--frontend", required=True, type=Path)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()

    repo = Path.cwd().resolve()
    strict = args.strict_out.resolve()
    output = args.output.resolve()
    baseline_path = args.baseline.resolve()
    frontend = args.frontend.resolve()

    if output.exists():
        raise FileExistsError(f"baseline output already exists: {output}")
    if not strict.is_dir():
        raise FileNotFoundError(f"strict output is unavailable: {strict}")
    if not frontend.is_file():
        raise FileNotFoundError(f"frontend is unavailable: {frontend}")

    baseline = load_object(baseline_path)
    expected = baseline.get("expected")
    if not isinstance(expected, dict):
        raise ValueError("baseline expected contract is missing")

    batch_path = strict / "batch-evaluation.json"
    batch = load_object(batch_path)
    if batch.get("caseCount") != baseline["source"]["caseCount"]:
        raise ValueError("generated-suite case count does not match baseline")

    cases_root = strict / "cases"
    reason = str(expected["scalarMismatchReason"])
    actual_scalar_cases = []
    for result in sorted(cases_root.glob("*/evaluation-result.json")):
        if case_has_reason(result, reason):
            actual_scalar_cases.append(result.parent.name)
    expected_scalar_cases = sorted(str(item) for item in
                                   expected["scalarMismatchCases"])
    if actual_scalar_cases != expected_scalar_cases:
        raise ValueError(
            "scalar mismatch case set differs from baseline: "
            f"expected={expected_scalar_cases}, actual={actual_scalar_cases}"
        )

    fence_case = str(expected["fenceCase"])
    fence_root = cases_root / fence_case
    fence_result = load_object(fence_root / "evaluation-result.json")
    if fence_result.get("status") != expected["fenceProgramStatus"]:
        raise ValueError("fence program status differs from baseline")
    if not case_has_reason(fence_root / "evaluation-result.json",
                           str(expected["fenceOrchestrationReason"])):
        raise ValueError("fence orchestration reason differs from baseline")
    failure = fence_result.get("orchestrationFailure")
    if (not isinstance(failure, dict)
            or failure.get("exceptionType") != expected["fenceExceptionType"]
            or not str(failure.get("detail", "")).endswith(
                str(expected["fenceMissingArtifactSuffix"]) + "'")):
        raise ValueError("fence structured failure differs from baseline")

    representative = str(expected["representativeOperandAuthorityCase"])
    matches = sorted((cases_root / representative).rglob("operand-authority.json"))
    if len(matches) != 1:
        raise ValueError(
            "representative operand authority must resolve uniquely; "
            f"found {len(matches)}"
        )

    head = run(["git", "rev-parse", "HEAD"], repo)
    branch = run(["git", "branch", "--show-current"], repo)
    clang_version = run([args.clang, "--version"], repo).splitlines()[0]
    frontend_stat = frontend.stat()
    provenance = {
        "schemaVersion": "riscv2x86.l2-baseline-provenance.v1",
        "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
        "repository": str(repo),
        "gitHead": head,
        "gitBranch": branch,
        "pythonPackage": run([
            "python3", "-c",
            "import riscv2x86_py; print(riscv2x86_py.__file__)",
        ], repo),
        "clangCommand": args.clang,
        "clangVersion": clang_version,
        "frontend": {
            "path": str(frontend),
            "size": frontend_stat.st_size,
            "modifiedNs": frontend_stat.st_mtime_ns,
            "sha256": "sha256:" + sha256(frontend.read_bytes()).hexdigest(),
        },
        "strictOutput": str(strict),
        "batchIdentity": batch.get("batchIdentity"),
        "baselineContractIdentity": identity(baseline),
    }
    major = int(baseline["source"]["requiredClang"]["majorVersion"])
    if f"clang version {major}." not in clang_version:
        raise ValueError(
            f"baseline requires clang {major}, got: {clang_version}"
        )

    output.mkdir(parents=True)
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    copy_required(batch_path, output / "batch-evaluation.json")
    (output / "scalar-dimension-results.json").write_text(
        json.dumps(dimension_rows(batch), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    copy_required(matches[0], output / "representative-operand-authority.json")

    translation = fence_root / "work" / "translation-work"
    copy_required(fence_root / "evaluation-result.json",
                  output / "case_006" / "evaluation-result.json")
    for name in (
        "translated_report.json",
        "translated_report.json.attempts.json",
        "frontend.stderr",
        "backend.stderr",
    ):
        copy_required(translation / name, output / "case_006" / name)

    verification = {
        "schemaVersion": "riscv2x86.l2-baseline-verification.v1",
        "baselineId": baseline["baselineId"],
        "baselineContractIdentity": identity(baseline),
        "batchIdentity": batch.get("batchIdentity"),
        "scalarMismatchCount": len(actual_scalar_cases),
        "scalarMismatchCases": actual_scalar_cases,
        "scalarAndFenceFailuresIndependent":
            fence_case not in set(actual_scalar_cases),
        "fenceCase": fence_case,
        "fenceOrchestrationReason": expected["fenceOrchestrationReason"],
        "complete": True,
    }
    verification["verificationIdentity"] = identity(verification)
    (output / "baseline-verification.json").write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
