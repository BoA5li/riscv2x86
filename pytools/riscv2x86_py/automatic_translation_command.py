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
from .requirement_staging import atomic_json, write_requirement_staging, write_requirement_failure
from .privileged_environment import (
    EnvironmentRelationKind,
    PrivilegedEnvironmentError,
    load_privileged_environment_manifest,
    validate_privileged_environment_pipeline_authority,
)
from .instruction_stream_sync_contracts import load_instruction_stream_sync_registry
from .csr_environment_contract import load_csr_environment_contract
from .atomic_authority import COMPILER_FRAGMENT_AUTHORITY_SCHEMA
from .compiler_fragment_closure import close_compiler_fragment_candidate, CompilerOperandClosureError
from .translation_preflight import write_preflight_failure, PreflightToolFailure
from .l2_fragment_execution import resolve_compiler_fragment_candidate


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
    joins = []
    for finding in findings:
        fragment = finding.get("fragment") if isinstance(finding, dict) else None
        if not isinstance(fragment, dict):
            continue
        fragment_id = str(fragment.get("fragmentId") or fragment.get("id") or "")
        matches = []
        for function in functions:
            boundary = function.get("l2OperandBoundary", {})
            candidates = boundary.get("fragmentCandidates", [])
            candidate, reason = resolve_compiler_fragment_candidate(
                fragment, candidates, function)
            if "AMBIGUOUS" in reason:
                raise ValueError(reason + ": " + fragment_id)
            if candidate is not None:
                matches.append((function, candidate))
        if len(matches) > 1:
            raise ValueError("compiler fragment authority binding is ambiguous: " + fragment_id)
        if not matches:
            record = {"fragmentId": fragment_id, "disposition": "missing",
                      "reasonCode": "L2_FRAGMENT_CANDIDATE_IDENTITY_NOT_FOUND"}
            fragment["compilerFragmentJoin"] = record
            joins.append(record)
            continue
        function, candidate = matches[0]
        try:
            closed = close_compiler_fragment_candidate(
                candidate, fragment, source_digest=str(function["sourceDigest"]),
                function_identity=str(function["functionId"]))
        except ValueError as exc:
            if isinstance(exc, CompilerOperandClosureError):
                if not exc.incomplete:
                    raise
            elif candidate.get("compilerStructureComplete") is True:
                raise
            record = {"fragmentId": fragment_id, "disposition": "rejected",
                      "reasonCode": getattr(exc, "reason_code", "COMPILER_FRAGMENT_CLOSURE_REJECTED"),
                      "detail": str(exc), "diagnostics": getattr(exc, "diagnostics", {})}
            fragment["compilerFragmentJoin"] = record
            joins.append(record)
            continue
        payload = {
            "schemaVersion": COMPILER_FRAGMENT_AUTHORITY_SCHEMA,
            "sourceDigest": function["sourceDigest"], "fragmentId": fragment_id,
            "targetTriple": "riscv64-linux-gnu", "functionIdentity": function["functionId"],
            "fragmentBindingKey": candidate["fragmentBindingKey"], "candidate": closed,
            "memoryObjectBindings": function["l2OperandBoundary"].get("memoryObjectBindings", {}),
        }
        payload["authorityIdentity"] = _identity(payload)
        fragment["compilerFragmentAuthority"] = payload
        fragment["compilerFragmentBinding"] = {
            "candidateIdentity": candidate["candidateIdentity"]}
        finding["sourceDigest"] = payload["sourceDigest"]
        record = {"fragmentId": fragment_id, "disposition": "matched",
                  "candidateIdentity": candidate["candidateIdentity"],
                  "closureIdentity": closed["closureIdentity"]}
        fragment["compilerFragmentJoin"] = record
        joins.append(record)
    atomic_json(raw_report.with_name("compiler-fragment-joins.json"), {
        "schemaVersion": "riscv2x86.compiler-fragment-joins.v1", "joins": joins})
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
    def preflight_failure(stage, exc, reason="evaluation.translation-preflight-failed", code=2):
        command = [sys.executable, "-m", "riscv2x86_py.automatic_translation_command", *sys.argv[1:]]
        write_preflight_failure(report, args.source, command, stage=stage,
                                reason_code=reason, exc=exc, returncode=code)
        print(stage + ": " + str(exc), file=sys.stderr)
        return code

    if any(Path(str(report) + suffix).exists() for suffix in (
            "", ".attempts.json", ".requirement-staging.json", ".requirement-failure.json",
            ".l2-requirements.json", ".l3-requirements.json", ".preflight.json")):
        if Path(str(report) + ".preflight.json").exists():
            print("Preflight artifact already exists; use a fresh work directory", file=sys.stderr)
            return 2
        return preflight_failure("output_freshness", FileExistsError(
            "Translation output already exists; use a fresh work directory"))
    raw = report.with_name("raw_report.json")
    if any(report.with_name(name).exists() for name in (
            "raw_report.json", "frontend-report.json", "compiler-candidates.json",
            "compiler-fragment-joins.json")):
        return preflight_failure("output_freshness", FileExistsError(
            "Compiler input artifacts already exist; use a fresh work directory"))

    try:
        sysroot_result = subprocess.run(("riscv64-linux-gnu-gcc", "-print-sysroot"),
                                        text=True, capture_output=True, check=False)
    except OSError as exc:
        return preflight_failure("sysroot_inspection", exc)
    if sysroot_result.returncode:
        return preflight_failure("sysroot_inspection", PreflightToolFailure(sysroot_result))
    sysroot = sysroot_result.stdout.strip()
    if sysroot == "/" and Path("/usr/riscv64-linux-gnu/include").is_dir():
        sysroot = "/usr/riscv64-linux-gnu"
    try:
        front = subprocess.run((args.frontend, "--analysis-only", "-o", str(report.with_name("dummy")),
                            "--src-root", str(Path(args.source_root).resolve()),
                            "--report-json", str(raw), str(Path(args.source).resolve()), "--",
                            "--target=riscv64-linux-gnu", "--sysroot=" + sysroot,
                            "-std=gnu11", "-march=rv64gc", "-mabi=lp64d"),
                               text=True, capture_output=True, check=False)
    except OSError as exc:
        return preflight_failure("frontend_execution", exc)
    (report.parent / "frontend.stdout").write_text(front.stdout, encoding="utf-8")
    (report.parent / "frontend.stderr").write_text(front.stderr, encoding="utf-8")
    if front.returncode or not raw.is_file():
        # Nonzero frontend is a failed command; do not infer source validity by stderr text.
        return preflight_failure("frontend_execution", PreflightToolFailure(front),
                                 "evaluation.translation-frontend-crashed" if front.returncode < 0
                                 else "evaluation.translation-frontend-failed",
                                 front.returncode if front.returncode > 0 else 2)
    preflight_stage = "compiler_inspection"
    try:
        # Preserve both independent compiler inputs before any enrichment.
        atomic_json(raw.with_name("frontend-report.json"),
                    json.loads(raw.read_text(encoding="utf-8")))
        _, compiler_functions = inspect_entry_points(Path(args.source).resolve())
        snapshot = {
            "schemaVersion": "riscv2x86.compiler-candidates.v1",
            "sourceDigest": "sha256:" + sha256(Path(args.source).read_bytes()).hexdigest(),
            "frontendReportIdentity": _identity(json.loads(raw.read_text(encoding="utf-8"))),
            "functions": list(compiler_functions),
        }
        snapshot["manifestIdentity"] = _identity(snapshot)
        atomic_json(raw.with_name("compiler-candidates.json"), snapshot)
        preflight_stage = "compiler_fragment_closure"
        _inject_compiler_fragment_authority(raw, Path(args.source).resolve(),
                                            compiler_functions)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return preflight_failure(preflight_stage, exc,
                                 getattr(exc, "reason_code", "evaluation.translation-compiler-authority-invalid"))
    if args.atomic_authority_sidecar:
        try:
            _inject_atomic_authority(raw, Path(args.source).resolve(),
                                     Path(args.atomic_authority_sidecar).resolve())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return preflight_failure("atomic_authority_binding", exc)
    if args.csr_authority_sidecar:
        try:
            _inject_csr_authority(raw, Path(args.source).resolve(),
                                  Path(args.csr_authority_sidecar).resolve())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return preflight_failure("csr_authority_binding", exc)
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
            return preflight_failure("csr_environment_binding", exc)
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
            return preflight_failure("privileged_environment_binding", exc)
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
            return preflight_failure("instruction_stream_sync_binding", exc)
        backend.extend(("--instruction-stream-sync-registry",
                        str(Path(args.instruction_stream_sync_registry).resolve())))
    try:
        back = subprocess.run(backend, text=True, capture_output=True, check=False)
    except OSError as exc:
        return preflight_failure("backend_launch", exc, "evaluation.translation-backend-launch-failed")
    (report.parent / "backend.stdout").write_text(back.stdout, encoding="utf-8")
    (report.parent / "backend.stderr").write_text(back.stderr, encoding="utf-8")
    if back.returncode:
        print(back.stderr, file=sys.stderr)
    # Positive backend exit codes include semantic terminal/withheld outcomes.
    # Classify authenticated artifacts before deciding the command exit code.
    if back.returncode >= 0 and report.is_file():
        failure_stage = "authority_materialization"
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
            failure_stage = "requirement_classification"
            manifest = classify_l2_requirements(translated)
            atomic_json(str(report) + ".l2-requirements.json", manifest)
            l3 = classify_l3_requirements(translated)
            atomic_json(str(report) + ".l3-requirements.json", l3.to_dict())
            failure_stage = "requirement_staging"
            write_requirement_staging(report, returncode=back.returncode,
                                      validation_plan=args.validation_plan)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            try:
                write_requirement_failure(report, exc, failure_stage)
            except (OSError, ValueError) as diagnostic_error:
                print("Requirement failure diagnostic could not be saved: " +
                      str(diagnostic_error), file=sys.stderr)
            print("Requirement classification failed: " + str(exc), file=sys.stderr)
            return 2
    elif back.returncode == 0:
        print("Translation completed without a translated report", file=sys.stderr)
        return 2
    return back.returncode


if __name__ == "__main__":
    raise SystemExit(main())
