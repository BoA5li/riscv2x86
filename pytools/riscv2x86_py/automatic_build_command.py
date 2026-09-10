"""Deterministic canonical target build used by automatic evaluation."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--kind", choices=("executable", "shared_library"), required=True)
    args = parser.parse_args()
    output = Path(args.output); obj = output.with_name(output.name + ".o")
    flags = ["-Wall", "-Wextra", "-O0"]
    if args.kind == "shared_library":
        flags.append("-fPIC")
    flags.append("-Werror")
    compiled = subprocess.run(("gcc", "-c", *flags, args.target, "-o", str(obj)), check=False)
    if compiled.returncode:
        return compiled.returncode
    mode = ("-shared",) if args.kind == "shared_library" else ()
    return subprocess.run(("gcc", *mode, str(obj), "-o", str(output)), check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
