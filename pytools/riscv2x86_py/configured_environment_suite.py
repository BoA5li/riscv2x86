"""Run strict and explicitly configured environment experiments separately.

The manifest is an experiment authority index, not a source of semantics.  It
only binds already complete, route-specific sidecars to content-addressed
sources and validates them with the production loaders before execution.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from typing import Mapping, Sequence

from .csr_environment_contract import load_csr_environment_contract
from .instruction_stream_sync_contracts import load_instruction_stream_sync_registry
from .privileged_environment import load_privileged_environment_manifest


CONFIGURED_ENVIRONMENT_SUITE_SCHEMA = \
    "riscv2x86.configured-environment-suite.v1"
CONFIGURED_ENVIRONMENT_REPORT_SCHEMA = \
    "riscv2x86.configured-environment-comparison.v1"

_ROUTES = {
    "privileged": (".privileged-environment.json", "--privileged-config-directory"),
    "instruction_stream_sync": (
        ".instruction-stream-sync.json", "--instruction-stream-sync-directory"),
    "csr": (".csr-environment.json", "--csr-environment-contract-directory"),
}


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _load_json(path: Path) -> Mapping[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError(str(path) + " must contain a JSON object")
    return value


def validate_configured_environment_suite(
    manifest_path: str | Path,
) -> tuple[Path, dict[str, Path], tuple[dict[str, str], ...]]:
    manifest_path = Path(manifest_path).resolve()
    value = _load_json(manifest_path)
    if set(value) != {"schemaVersion", "sourceRoot", "cases", "manifestIdentity"}:
        raise ValueError("configured environment manifest fields are incomplete or unknown")
    if value.get("schemaVersion") != CONFIGURED_ENVIRONMENT_SUITE_SCHEMA:
        raise ValueError("configured environment manifest schema is unsupported")
    payload = {key: item for key, item in value.items() if key != "manifestIdentity"}
    if value.get("manifestIdentity") != _identity(payload):
        raise ValueError("configured environment manifest identity mismatch")
    raw_root = Path(str(value.get("sourceRoot") or ""))
    source_root = (manifest_path.parent / raw_root).resolve()
    if not source_root.is_dir():
        raise ValueError("configured environment sourceRoot is unavailable")
    raw_cases = value.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("configured environment cases must be non-empty")
    roots: dict[str, Path] = {}
    cases: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw_cases:
        if not isinstance(item, Mapping) or set(item) != {
                "sourceRelativePath", "sourceDigest", "fragmentId", "route", "sidecar"}:
            raise ValueError("configured environment case fields are incomplete or unknown")
        relative = str(item.get("sourceRelativePath") or "")
        route = str(item.get("route") or "")
        fragment = str(item.get("fragmentId") or "")
        digest = str(item.get("sourceDigest") or "")
        if route not in _ROUTES or not relative or not fragment:
            raise ValueError("configured environment case identity is invalid")
        source = (source_root / relative).resolve()
        try:
            source.relative_to(source_root)
        except ValueError as exc:
            raise ValueError("configured source escapes sourceRoot") from exc
        if not source.is_file() or "sha256:" + sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError("configured environment source digest mismatch: " + relative)
        sidecar = (manifest_path.parent / str(item.get("sidecar") or "")).resolve()
        if not sidecar.is_file():
            raise ValueError("configured environment sidecar is unavailable: " + relative)
        suffix, _ = _ROUTES[route]
        expected = relative + suffix
        if sidecar.name != Path(expected).name:
            raise ValueError("configured environment sidecar name does not bind its source")
        root = sidecar
        for _part in Path(expected).parts:
            root = root.parent
        prior = roots.setdefault(route, root)
        if prior != root:
            raise ValueError("one route must use one content-addressed sidecar root")
        if route == "privileged":
            loaded = load_privileged_environment_manifest(sidecar, source=source)
        elif route == "instruction_stream_sync":
            loaded = load_instruction_stream_sync_registry(sidecar, source_path=source)
            if not loaded.binds_fragment(fragment):
                raise ValueError("instruction-stream sidecar does not bind configured fragment")
        else:
            loaded = load_csr_environment_contract(sidecar, source=source)
        if getattr(loaded, "fragment_id", fragment) != fragment:
            raise ValueError("configured environment sidecar fragment mismatch")
        key = (relative, route)
        if key in seen:
            raise ValueError("duplicate configured environment route binding")
        seen.add(key)
        cases.append({"sourceRelativePath": relative, "sourceDigest": digest,
                      "fragmentId": fragment, "route": route,
                      "sidecar": str(sidecar)})
    return source_root, roots, tuple(sorted(cases, key=lambda x: (x["sourceRelativePath"], x["route"])))


def _batch_command(source_root: Path, frontend: Path, output: Path,
                   roots: Mapping[str, Path], timeout: int) -> list[str]:
    command = [sys.executable, "-m", "riscv2x86_py.automatic_batch_cli",
               "--input", str(source_root), "--frontend", str(frontend),
               "--output-directory", str(output), "--jobs", "1",
               "--timeout-seconds", str(timeout)]
    for route in sorted(roots):
        command.extend((_ROUTES[route][1], str(roots[route])))
    return command


def run_configured_environment_suite(
    manifest: str | Path, *, frontend: str | Path, output_root: str | Path,
    timeout_seconds: int = 120,
) -> dict[str, object]:
    source_root, roots, cases = validate_configured_environment_suite(manifest)
    frontend = Path(frontend).resolve()
    if not frontend.is_file():
        raise ValueError("frontend is unavailable")
    output_root = Path(output_root).resolve(); output_root.mkdir(parents=True, exist_ok=True)
    runs = {}
    case_statuses: dict[str, dict[str, str]] = {}
    for name, configured_roots in (("strict", {}), ("configured", roots)):
        output = output_root / name
        command = _batch_command(source_root, frontend, output, configured_roots,
                                 timeout_seconds)
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        batch_path = output / "batch-evaluation.json"
        if not batch_path.is_file():
            raise ValueError(name + " experiment did not produce batch-evaluation.json: "
                             + completed.stderr.strip())
        batch = _load_json(batch_path)
        raw_cases = batch.get("cases")
        if not isinstance(raw_cases, list):
            raise ValueError(name + " batch result has no case records")
        statuses = {}
        for item in raw_cases:
            if not isinstance(item, Mapping):
                raise ValueError(name + " batch result contains a malformed case")
            case_id, status = item.get("caseId"), item.get("status")
            if not isinstance(case_id, str) or not isinstance(status, str):
                raise ValueError(name + " batch case identity/status is invalid")
            statuses[case_id] = status
        case_statuses[name] = statuses
        runs[name] = {"exitCode": completed.returncode,
                      "batchIdentity": batch.get("batchIdentity", ""),
                      "statusCounts": batch.get("statusCounts", {}),
                      "outputDirectory": str(output)}
    all_case_ids = sorted(set(case_statuses["strict"]) | set(case_statuses["configured"]))
    comparison = [{"caseId": case_id,
                   "strictStatus": case_statuses["strict"].get(case_id, "missing"),
                   "configuredStatus": case_statuses["configured"].get(case_id, "missing"),
                   "changed": (case_statuses["strict"].get(case_id)
                               != case_statuses["configured"].get(case_id))}
                  for case_id in all_case_ids]
    report = {"schemaVersion": CONFIGURED_ENVIRONMENT_REPORT_SCHEMA,
              "manifestIdentity": _load_json(Path(manifest).resolve())["manifestIdentity"],
              "caseBindings": list(cases), "runs": runs,
              "caseStatusComparison": comparison}
    report["reportIdentity"] = _identity(report)
    (output_root / "configured-environment-comparison.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser("riscv2x86-configured-environment-suite")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        report = run_configured_environment_suite(
            args.manifest, frontend=args.frontend, output_root=args.output_root,
            timeout_seconds=args.timeout_seconds)
    except Exception as exc:
        print(json.dumps({"status": "inconclusive",
                          "reasonCode": "configured-environment.configuration-error",
                          "detail": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
