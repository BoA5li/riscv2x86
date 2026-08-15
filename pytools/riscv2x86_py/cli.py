from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ghidra_pythonrun_bridge import (
    GhidraPythonRunError,
    load_riscv_register_resolver_via_pythonrun,
)
from .pipeline import run
from .abi_sidecar import load_abi_call_sidecar, load_target_abi_wrapper_registry


def main() -> int:
    ap = argparse.ArgumentParser("riscv2x86-py")

    ap.add_argument(
        "--in",
        dest="inp",
        required=False,
        help="Input report.json from the C++ classifier",
    )

    ap.add_argument(
        "--out",
        required=False,
        help="Output translated report.json",
    )

    ap.add_argument(
        "--xlen",
        type=int,
        choices=[32, 64],
        default=64,
        help="RISC-V XLEN; default: 64",
    )

    ap.add_argument(
        "--ghidra-install-dir",
        default=None,
        help=(
            "Ghidra installation directory. "
            "If omitted, the pythonRun bridge uses its configured/default path."
        ),
    )

    ap.add_argument(
        "--ghidra-language-id",
        default=None,
        help=(
            "Optional explicit Ghidra RISC-V Language ID. "
            "For example: RISCV:LE:64:default."
        ),
    )

    ap.add_argument(
        "--skip-verify",
        action="store_true",
        help=(
            "Skip Phase 8 verification. "
            "Output findings will be marked not_verified."
        ),
    )
    ap.add_argument(
        "--allow-functional-fallbacks",
        action="store_true",
        help=(
            "Allow only explicitly registered functional-equivalence "
            "fallbacks when strict architecture-semantic equivalence is "
            "unavailable. Default: fail closed."
        ),
    )
    ap.add_argument(
        "--abi-call-sidecar",
        default=None,
        help="Versioned Phase-4 ABI call-sidecar JSON, keyed by fragmentId.",
    )
    ap.add_argument(
        "--abi-wrapper-registry",
        default=None,
        help="Versioned target ABI wrapper-registry JSON.",
    )

    args = ap.parse_args()

    # Make package shadowing immediately observable in launcher logs.  The
    # path is diagnostic provenance only and is not used by any translation
    # decision.
    print("[riscv2x86-py] backend module:", Path(__file__).resolve())

    if not args.inp:
        ap.error("--in is required")

    if not args.out:
        ap.error("--out is required")

    try:
        # 使用已经由 integration test 覆盖的 Ghidra support/pythonRun 路径。
        resolver = load_riscv_register_resolver_via_pythonrun(
            xlen=args.xlen,
            ghidra_install_dir=args.ghidra_install_dir,
            language_id=args.ghidra_language_id,
        )
    except GhidraPythonRunError as exc:
        print(
            "[riscv2x86-py] cannot initialize Ghidra "
            "support/pythonRun register resolver:\n"
            f"{exc}",
            file=sys.stderr,
        )
        return 2

    try:
        abi_call_sidecar = (
            None if args.abi_call_sidecar is None
            else load_abi_call_sidecar(args.abi_call_sidecar)
        )
        abi_wrapper_registry = (
            None if args.abi_wrapper_registry is None
            else load_target_abi_wrapper_registry(args.abi_wrapper_registry)
        )
        stats = run(
            args.inp,
            args.out,
            xlen=args.xlen,
            language=None,
            register_name_resolver=resolver,
            verify_enabled=not args.skip_verify,
            abi_call_sidecar=abi_call_sidecar,
            abi_wrapper_registry=abi_wrapper_registry,
            allow_functional_fallbacks=args.allow_functional_fallbacks,
        )
    except Exception as exc:
        print(
            "[riscv2x86-py] translation pipeline failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    print("[riscv2x86-py] done:")
    print(json.dumps(stats, ensure_ascii=False, indent=2))

    return 0 if stats.get("failed", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
