"""One-command target-aware frontend/backend translation used by auto runs."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import json

from .l2_eligibility import classify_l2_requirements


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-automatic-translation")
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--allow-functional-fallbacks", action="store_true")
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
            manifest = classify_l2_requirements(translated)
            report.with_name(report.name + ".l2-requirements.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8",
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("L2 requirement classification failed: " + str(exc), file=sys.stderr)
            return 2
    return back.returncode


if __name__ == "__main__":
    raise SystemExit(main())
