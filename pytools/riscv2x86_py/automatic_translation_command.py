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
    parser.add_argument("--allow-functional-fallbacks", action="store_true")
    parser.add_argument("--atomic-authority-sidecar")
    parser.add_argument("--csr-authority-sidecar")
    args = parser.parse_args()
    report = Path(args.report).resolve(); report.parent.mkdir(parents=True, exist_ok=True)
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
    backend = [sys.executable, "-m", "riscv2x86_py.cli", "--in", str(raw),
               "--out", str(report), "--xlen", "64", "--skip-verify"]
    if args.allow_functional_fallbacks:
        backend.append("--allow-functional-fallbacks")
    back = subprocess.run(backend, text=True, capture_output=True, check=False)
    (report.parent / "backend.stdout").write_text(back.stdout, encoding="utf-8")
    (report.parent / "backend.stderr").write_text(back.stderr, encoding="utf-8")
    if back.returncode:
        print(back.stderr, file=sys.stderr)
    elif report.is_file():
        try:
            translated = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(translated, dict):
                raise ValueError("translated report root must be an object")
            _, functions = inspect_entry_points(Path(args.source).resolve())
            materialize_automatic_l2_authority(
                translated, tuple(item for item in functions if isinstance(item, dict)),
                args.frontend,
            )
            report.write_text(
                json.dumps(translated, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            # Authority changes attempt and candidate identities, so the
            # archive must be regenerated before candidate staging.
            findings = load_report(str(report))
            save_translation_attempt_archive(
                tuple(terminal_attempt_from_finding(item, index)
                      for index, item in enumerate(findings)),
                str(report) + ".attempts.json",
            )
            manifest = classify_l2_requirements(translated)
            report.with_name(report.name + ".l2-requirements.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8",
            )
            l3 = classify_l3_requirements(translated)
            report.with_name(report.name + ".l3-requirements.json").write_text(
                json.dumps(l3.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8",
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("Requirement classification failed: " + str(exc), file=sys.stderr)
            return 2
    return back.returncode


if __name__ == "__main__":
    raise SystemExit(main())
