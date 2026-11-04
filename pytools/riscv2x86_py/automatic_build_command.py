"""Deterministic canonical target build used by automatic evaluation."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from .runtime_dependency_binding import dependencies_from_translated_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--kind", choices=("object", "executable", "shared_library"), required=True)
    parser.add_argument("--translated-report")
    parser.add_argument("--repository-root")
    parser.add_argument("--project-build-contract")
    parser.add_argument("--project-side",choices=("source","target"),default="target")
    args = parser.parse_args()
    if args.kind=='object' and not args.project_build_contract:
        parser.error('object output requires an explicit project build contract')
    output = Path(args.output)
    obj = output.with_name(output.name + ".o")
    report = (Path(args.translated_report) if args.translated_report else
              Path.cwd() / "translation-work" / "translated_report.json")
    try:
        dependencies = dependencies_from_translated_report(
            report, root=args.repository_root,
        )
    except (OSError, ValueError) as exc:
        print("runtime dependency resolution failed: " + str(exc), file=__import__("sys").stderr)
        return 2
    if args.project_build_contract:
        from .project_build_contract import load
        from .project_artifact_build import build
        try:
            contract=load(args.project_build_contract)
            build(contract,args.project_side,args.target,output,args.kind,
                  include_directories=dependencies.include_directories,
                  libraries=dependencies.library_paths)
            return 0
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            print('project build failed: '+str(exc),file=__import__('sys').stderr)
            return 2
    flags = ["-Wall", "-Wextra", "-O0", "-fno-lto"]
    if args.kind == "shared_library":
        flags.append("-fPIC")
    flags.extend("-I" + item for item in dependencies.include_directories)
    flags.append("-Werror")
    compiled = subprocess.run(("gcc", "-c", *flags, args.target, "-o", str(obj)), check=False)
    if compiled.returncode:
        return compiled.returncode
    mode = ("-shared",) if args.kind == "shared_library" else ()
    return subprocess.run(
        ("gcc", "-fno-lto", *mode, str(obj), *dependencies.library_paths, "-o", str(output)),
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
