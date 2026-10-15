"""One-command target-aware frontend/backend translation used by auto runs."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import json
from hashlib import sha256

from .l2_eligibility import classify_l2_requirements
from .l3_intent_requirements import classify_l3_requirements
from .automatic_batch_cli import inspect_entry_points
from .automatic_l2_authority import materialize_automatic_l2_authority
from .schema import load_report
from .translation_attempt import terminal_attempt_from_finding, save_translation_attempt_archive
from .translation_attempt import load_translation_attempt_archive
from .requirement_staging import atomic_json, write_requirement_staging
from .privileged_environment import (
    EnvironmentRelationKind,
    PrivilegedEnvironmentError,
    load_privileged_environment_manifest,
    validate_privileged_environment_pipeline_authority,
)
from .instruction_stream_sync_contracts import load_instruction_stream_sync_registry
from .csr_environment_contract import load_csr_environment_contract
from .atomic_authority import COMPILER_FRAGMENT_AUTHORITY_SCHEMA
from .compiler_fragment_closure import close_compiler_fragment_candidate


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _inject_atomic_authority(raw_report: Path, source: Path, sidecar: Path) -> None:
    """Bind content-addressed atomic authority to its exact frontend fragment."""
    report = json.loads(raw_report.read_text(encoding="utf-8"))
    binding = json.loads(sidecar.read_text(encoding="utf-8"))
    digest = "sha256:" + sha256(source.read_bytes()).hexdigest()
    required = {"schemaVersion", "sourceDigest", "bundles", "manifestIdentity"}
    if (not isinstance(binding, dict) or set(binding) != required or
            binding["schemaVersion"] != "riscv2x86.atomic-authority-binding.v1" or
            binding["sourceDigest"] != digest or
            binding["manifestIdentity"] != _identity({
                key: value for key, value in binding.items() if key != "manifestIdentity"
            }) or not isinstance(binding["bundles"], list)):
        raise ValueError("atomic authority binding is stale or malformed")
    bundles = {}
    for bundle in binding["bundles"]:
        if not isinstance(bundle, dict) or not isinstance(bundle.get("fragmentId"), str):
            raise ValueError("atomic authority bundle is malformed")
        fragment_id = bundle["fragmentId"]
        if fragment_id in bundles:
            raise ValueError("duplicate atomic authority fragment binding")
        bundles[fragment_id] = bundle
    findings = report if isinstance(report, list) else report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("frontend report has no findings")
    seen = set()
    for finding in findings:
        fragment = finding.get("fragment") if isinstance(finding, dict) else None
        fragment_id = fragment.get("fragmentId") if isinstance(fragment, dict) else None
        if fragment_id in bundles:
            fragment["atomicAuthorityBundle"] = bundles[fragment_id]
            finding["sourceDigest"] = digest
            seen.add(fragment_id)
    if seen != set(bundles):
        raise ValueError("atomic authority references a nonexistent frontend fragment")
    raw_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def _inject_compiler_fragment_authority(
    raw_report: Path, source: Path, functions: tuple[dict[str, object], ...],
) -> None:
    """Bind Clang AST fragment/object facts to exact frontend fragments.

    This payload does not assert an atomic operation.  Phase 5 may consume it
    only after the decoder independently reports a typed AMO operation.
    """
    report = json.loads(raw_report.read_text(encoding="utf-8"))
    findings = report if isinstance(report, list) else report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("frontend report has no findings")
    candidates: dict[tuple[str, int, int], list[dict[str, object]]] = {}
    for function in functions:
        boundary = function.get("l2OperandBoundary")
        if not isinstance(boundary, dict):
            continue
        for candidate in boundary.get("fragmentCandidates", []):
            key = candidate.get("fragmentBindingKey") if isinstance(candidate, dict) else None
            if not isinstance(key, dict):
                continue
            match = (str(Path(str(key.get("sourceFile") or "")).resolve()),
                     int(key.get("beginOffset", -1)), int(key.get("endOffset", -1)))
            payload = {
                "schemaVersion": COMPILER_FRAGMENT_AUTHORITY_SCHEMA,
                "sourceDigest": str(function.get("sourceDigest") or ""),
                "fragmentId": "", "targetTriple": "riscv64-linux-gnu",
                "functionIdentity": str(function.get("functionId") or ""),
                "fragmentBindingKey": key, "candidate": candidate,
                "memoryObjectBindings": boundary.get("memoryObjectBindings", {}),
            }
            candidates.setdefault(match, []).append(payload)
    for finding in findings:
        fragment = finding.get("fragment") if isinstance(finding, dict) else None
        if not isinstance(fragment, dict):
            continue
        match = (str(Path(str(fragment.get("fileName") or source)).resolve()),
                 int(fragment.get("beginOffset", -1)), int(fragment.get("endOffset", -1)))
        matched = candidates.get(match, [])
        if len(matched) > 1:
            raise ValueError("compiler fragment authority binding is ambiguous")
        if len(matched) != 1:
            continue
        payload = dict(matched[0])
        payload["fragmentId"] = str(fragment.get("fragmentId") or fragment.get("id") or "")
        payload["candidate"] = close_compiler_fragment_candidate(
            payload["candidate"], fragment,
            source_digest=str(payload["sourceDigest"]),
            function_identity=str(payload["functionIdentity"]),
        )
        payload["authorityIdentity"] = _identity(payload)
        fragment["compilerFragmentAuthority"] = payload
        finding["sourceDigest"] = payload["sourceDigest"]
    raw_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def _inject_csr_authority(raw_report: Path, source: Path, sidecar: Path) -> None:
    """Bind frontend CSR/operand facts to the exact source and fragments."""
    report = json.loads(raw_report.read_text(encoding="utf-8"))
    binding = json.loads(sidecar.read_text(encoding="utf-8"))
    digest = "sha256:" + sha256(source.read_bytes()).hexdigest()
    required = {"schemaVersion", "sourceDigest", "bundles", "manifestIdentity"}
    if (not isinstance(binding, dict) or set(binding) != required or
            binding["schemaVersion"] != "riscv2x86.csr-authority-binding.v1" or
            binding["sourceDigest"] != digest or
            binding["manifestIdentity"] != _identity({
                key: value for key, value in binding.items() if key != "manifestIdentity"
            }) or not isinstance(binding["bundles"], list)):
        raise ValueError("CSR authority binding is stale or malformed")
    bundles = {}
    for bundle in binding["bundles"]:
        if not isinstance(bundle, dict) or not isinstance(bundle.get("fragmentId"), str):
            raise ValueError("CSR authority bundle is malformed")
        if bundle["fragmentId"] in bundles:
            raise ValueError("duplicate CSR authority fragment binding")
        bundles[bundle["fragmentId"]] = bundle
    findings = report if isinstance(report, list) else report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("frontend report has no findings")
    seen = set()
    for finding in findings:
        fragment = finding.get("fragment") if isinstance(finding, dict) else None
        fragment_id = fragment.get("fragmentId") if isinstance(fragment, dict) else None
        if fragment_id in bundles:
            fragment["csrAuthorityBundle"] = bundles[fragment_id]
            finding["sourceDigest"] = digest
            seen.add(fragment_id)
    if seen != set(bundles):
        raise ValueError("CSR authority references a nonexistent frontend fragment")
    raw_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-automatic-translation")
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--validation-plan")
    parser.add_argument("--allow-functional-fallbacks", action="store_true")
    parser.add_argument("--atomic-authority-sidecar")
    parser.add_argument("--csr-authority-sidecar")
    parser.add_argument("--csr-environment-contract")
    parser.add_argument("--privileged-environment-sidecar")
    parser.add_argument("--instruction-stream-sync-registry")
    args = parser.parse_args()
    report = Path(args.report).resolve(); report.parent.mkdir(parents=True, exist_ok=True)
    if any(Path(str(report) + suffix).exists() for suffix in (
            "", ".attempts.json", ".requirement-staging.json",
            ".l2-requirements.json", ".l3-requirements.json")):
        print("Translation output already exists; use a fresh work directory", file=sys.stderr)
        return 2
    raw = report.with_name("raw_report.json")
    sysroot_result = subprocess.run(("riscv64-linux-gnu-gcc", "-print-sysroot"),
                                    text=True, capture_output=True, check=False)
    if sysroot_result.returncode:
        print(sysroot_result.stderr, file=sys.stderr); return 2
    sysroot = sysroot_result.stdout.strip()
    if sysroot == "/" and Path("/usr/riscv64-linux-gnu/include").is_dir():
        sysroot = "/usr/riscv64-linux-gnu"
    front = subprocess.run((args.frontend, "--analysis-only", "-o", str(report.with_name("dummy")),
                            "--src-root", str(Path(args.source_root).resolve()),
                            "--report-json", str(raw), str(Path(args.source).resolve()), "--",
                            "--target=riscv64-linux-gnu", "--sysroot=" + sysroot,
                            "-std=gnu11", "-march=rv64gc", "-mabi=lp64d"),
                           text=True, capture_output=True, check=False)
    (report.parent / "frontend.stdout").write_text(front.stdout, encoding="utf-8")
    (report.parent / "frontend.stderr").write_text(front.stderr, encoding="utf-8")
    if front.returncode or not raw.is_file():
        print(front.stderr, file=sys.stderr); return front.returncode or 2
    try:
        _, compiler_functions = inspect_entry_points(Path(args.source).resolve())
        _inject_compiler_fragment_authority(raw, Path(args.source).resolve(),
                                            compiler_functions)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Compiler fragment authority binding failed: " + str(exc), file=sys.stderr)
        return 2
    if args.atomic_authority_sidecar:
        try:
            _inject_atomic_authority(raw, Path(args.source).resolve(),
                                     Path(args.atomic_authority_sidecar).resolve())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("Atomic authority binding failed: " + str(exc), file=sys.stderr)
            return 2
    if args.csr_authority_sidecar:
        try:
            _inject_csr_authority(raw, Path(args.source).resolve(),
                                  Path(args.csr_authority_sidecar).resolve())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("CSR authority binding failed: " + str(exc), file=sys.stderr)
            return 2
    if args.csr_environment_contract:
        try:
            csr_environment = load_csr_environment_contract(
                args.csr_environment_contract, source=args.source,
            )
            raw_value = json.loads(raw.read_text(encoding="utf-8"))
            raw_findings = (raw_value if isinstance(raw_value, list)
                            else raw_value.get("findings", []))
            fragment_ids = {
                str(item.get("fragment", {}).get("fragmentId") or
                    item.get("fragment", {}).get("id"))
                for item in raw_findings if isinstance(item, dict)
            }
            if csr_environment.fragment_id not in fragment_ids:
                raise ValueError("CSR environment contract references a nonexistent frontend fragment")
            if (csr_environment.relation_kind == "functional-monotonic-observation"
                    and not args.allow_functional_fallbacks):
                raise ValueError("functional CSR relation requires --allow-functional-fallbacks")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("CSR environment binding failed: " + str(exc), file=sys.stderr)
            return 2
    backend = [sys.executable, "-m", "riscv2x86_py.cli", "--in", str(raw),
               "--out", str(report), "--xlen", "64", "--skip-verify"]
    if args.privileged_environment_sidecar:
        try:
            environment = load_privileged_environment_manifest(
                args.privileged_environment_sidecar, source=args.source,
            )
            validate_privileged_environment_pipeline_authority(environment)
            raw_value = json.loads(raw.read_text(encoding="utf-8"))
            raw_findings = (raw_value if isinstance(raw_value, list)
                            else raw_value.get("findings", []))
            fragment_ids = {
                str(item.get("fragment", {}).get("fragmentId") or
                    item.get("fragment", {}).get("id"))
                for item in raw_findings if isinstance(item, dict)
            }
            if environment.fragment_id not in fragment_ids:
                raise PrivilegedEnvironmentError(
                    "PRIV_ENV_FRAGMENT_ID_MISMATCH",
                    "configured fragment is absent from the frontend report",
                )
            if (environment.relation is EnvironmentRelationKind.FUNCTIONAL
                    and not args.allow_functional_fallbacks):
                raise PrivilegedEnvironmentError(
                    "PRIV_ENV_FUNCTIONAL_POLICY_DISABLED",
                    "functional route requires --allow-functional-fallbacks",
                )
            backend.extend(("--privileged-execution-sidecar", str(environment.execution_sidecar)))
            if environment.runtime_registry is not None:
                backend.extend(("--privileged-runtime-registry",
                                str(environment.runtime_registry)))
            if environment.functional_registry is not None:
                backend.extend(("--privileged-functional-registry", str(environment.functional_registry)))
            if environment.observability_sidecar is not None:
                backend.extend(("--privileged-observability-sidecar", str(environment.observability_sidecar)))
            if environment.ignored_state_sidecar is not None:
                backend.extend(("--privileged-ignored-state-declarations", str(environment.ignored_state_sidecar)))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("Privileged environment binding failed: " + str(exc), file=sys.stderr)
            return 2
    if args.allow_functional_fallbacks:
        backend.append("--allow-functional-fallbacks")
    if args.csr_environment_contract:
        backend.extend(("--csr-environment-contract",
                        str(Path(args.csr_environment_contract).resolve())))
    if args.instruction_stream_sync_registry:
        try:
            load_instruction_stream_sync_registry(
                args.instruction_stream_sync_registry, source_path=args.source,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("Instruction-stream synchronization binding failed: " + str(exc),
                  file=sys.stderr)
            return 2
        backend.extend(("--instruction-stream-sync-registry",
                        str(Path(args.instruction_stream_sync_registry).resolve())))
    back = subprocess.run(backend, text=True, capture_output=True, check=False)
    (report.parent / "backend.stdout").write_text(back.stdout, encoding="utf-8")
    (report.parent / "backend.stderr").write_text(back.stderr, encoding="utf-8")
    if back.returncode:
        print(back.stderr, file=sys.stderr)
    # Positive backend exit codes include semantic terminal/withheld outcomes.
    # Classify authenticated artifacts before deciding the command exit code.
    if back.returncode >= 0 and report.is_file():
        try:
            load_translation_attempt_archive(str(report) + ".attempts.json")
            translated = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(translated, dict):
                raise ValueError("translated report root must be an object")
            materialize_automatic_l2_authority(
                translated, tuple(item for item in compiler_functions
                                  if isinstance(item, dict)),
                args.frontend,
            )
            atomic_json(report, translated)
            # Authority changes attempt and candidate identities, so the
            # archive must be regenerated before candidate staging.
            findings = load_report(str(report))
            save_translation_attempt_archive(
                tuple(terminal_attempt_from_finding(item, index)
                      for index, item in enumerate(findings)),
                str(report) + ".attempts.json",
            )
            manifest = classify_l2_requirements(translated)
            atomic_json(str(report) + ".l2-requirements.json", manifest)
            l3 = classify_l3_requirements(translated)
            atomic_json(str(report) + ".l3-requirements.json", l3.to_dict())
            write_requirement_staging(report, returncode=back.returncode,
                                      validation_plan=args.validation_plan)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("Requirement classification failed: " + str(exc), file=sys.stderr)
            return 2
    elif back.returncode == 0:
        print("Translation completed without a translated report", file=sys.stderr)
        return 2
    return back.returncode


if __name__ == "__main__":
    raise SystemExit(main())
