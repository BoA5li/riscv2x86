#!/usr/bin/env python3
"""Run the production L0 matrix against real RV64 and x86-64 toolchains."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile

from riscv2x86_py.l0_artifact_manifest import (
    ExpectedArtifact,
    ExpectedElf,
    L0_ARTIFACT_MANIFEST_SCHEMA,
)
from riscv2x86_py.l0_build_matrix import (
    L0BuildMatrix,
    _inspect_elf,
    _run,
    run_l0_build_matrix,
)
from riscv2x86_py.translation_validation import ProgramArtifact, TranslationArtifact
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


COMPILERS = ("gcc", "clang")
OPTIMIZATIONS = ("-O0", "-O2", "-O3")
SANITIZERS = ("none", "asan", "ubsan")
SOURCE_COMPILER = "riscv64-linux-gnu-gcc"
SOURCE_FLAGS = ("-march=rv64gc", "-mabi=lp64d")
TARGET_FLAGS = ("-Wall",)


def _cell_id(compiler: str, optimization: str, sanitizer: str) -> str:
    return f"{compiler}-{optimization[1:]}-{sanitizer}"


def _target_cell_flags(
    optimization: str, sanitizer: str, link_kind: str,
) -> tuple[str, ...]:
    flags = (*TARGET_FLAGS, optimization)
    if sanitizer == "asan":
        flags += ("-fsanitize=address",)
    elif sanitizer == "ubsan":
        flags += ("-fsanitize=undefined",)
    if link_kind == "shared_library":
        flags += ("-fPIC",)
    return (*flags, "-Werror")


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _run_checked(argv: tuple[str, ...], cwd: Path) -> str:
    completed = subprocess.run(
        argv, cwd=cwd, text=True, capture_output=True, check=False, timeout=60,
    )
    if completed.returncode:
        raise RuntimeError(
            "command failed: " + " ".join(argv) + "\n" + completed.stderr
        )
    return completed.stdout.strip()


def _elf(path: Path, cwd: Path) -> ExpectedElf:
    result, detail = _inspect_elf(path, cwd, _run, 60)
    if result is None:
        raise RuntimeError("ELF inspection failed for %s: %s" % (path, detail))
    return result


def _elf_dict(value: ExpectedElf) -> dict[str, object]:
    return {
        "class": value.elf_class,
        "endian": value.endian,
        "type": value.elf_type,
        "machine": value.machine,
        "osAbi": value.os_abi,
        "abiVersion": value.abi_version,
        "abiFlags": value.abi_flags,
        "interpreter": value.interpreter,
        "needed": list(value.needed),
        "runpath": list(value.runpath),
        "soname": value.soname,
        "undefinedSymbols": list(value.undefined_symbols),
        "relocationTypes": list(value.relocation_types),
    }


def _artifact_dict(value: ExpectedArtifact) -> dict[str, object]:
    return {
        "artifactDigest": value.artifact_digest,
        "objectDigest": value.object_digest,
        "artifactKind": value.artifact_kind,
        "compilerIdentity": value.compiler_identity,
        "compilerTriple": value.compiler_triple,
        "flags": list(value.flags),
        "runtimeLibraries": list(value.runtime_libraries),
        "elf": _elf_dict(value.elf),
        "objectElf": _elf_dict(value.object_elf),
    }


def _translation() -> TranslationArtifact:
    return TranslationArtifact(
        "ci-fragment", "ci-source-model", "ci-plan", "ci-constraints",
        "ci-proof", PreservationMode.ARCHITECTURE_EQUIVALENT,
        "ci-shell-facts", "ci-runtime", "v1", "ci-recipe", (),
        "integer", "c",
    )


def _prepare_reference_artifacts(
    root: Path, link_kind: str, translation: TranslationArtifact,
) -> tuple[L0BuildMatrix, ProgramArtifact, ProgramArtifact]:
    source = root / "source.c"
    target = root / "target.c"
    work = root / "build"
    work.mkdir()
    source.write_text("int rv64_source_probe(int x){return x+1;}\n", encoding="utf-8")
    target.write_text(
        "int translated_probe(int x){return x+1;}\n"
        "int main(void){return translated_probe(1)==2?0:1;}\n",
        encoding="utf-8",
    )

    source_output = root / "source.o"
    source_build_flags = (*SOURCE_FLAGS, "-Werror")
    _run_checked(
        (SOURCE_COMPILER, *source_build_flags, "-c", str(source),
         "-o", str(source_output)),
        work,
    )
    source_elf = _elf(source_output, work)
    source_expected = ExpectedArtifact(
        _digest(source_output), _digest(source_output), "object", SOURCE_COMPILER,
        _run_checked((SOURCE_COMPILER, "-dumpmachine"), work),
        source_build_flags, (), source_elf, source_elf,
    )

    suffix = ".so" if link_kind == "shared_library" else ".exe"
    target_output = root / ("target" + suffix)
    targets: dict[str, ExpectedArtifact] = {}
    for compiler in COMPILERS:
        triple = _run_checked((compiler, "-dumpmachine"), work)
        for optimization in OPTIMIZATIONS:
            for sanitizer in SANITIZERS:
                ident = _cell_id(compiler, optimization, sanitizer)
                flags = _target_cell_flags(optimization, sanitizer, link_kind)
                obj = work / (ident + ".o")
                output = target_output if ident == "gcc-O0-none" else work / (ident + suffix)
                _run_checked((compiler, "-c", *flags, str(target), "-o", str(obj)), work)
                sanitizer_flags = () if sanitizer == "none" else (
                    "-fsanitize=" + {"asan": "address", "ubsan": "undefined"}[sanitizer],
                )
                link_mode = ("-shared",) if link_kind == "shared_library" else ()
                _run_checked(
                    (compiler, *sanitizer_flags, *link_mode, str(obj), "-o", str(output)),
                    work,
                )
                targets[ident] = ExpectedArtifact(
                    _digest(output), _digest(obj), link_kind, compiler, triple,
                    flags, (), _elf(output, work), _elf(obj, work),
                )

    manifest_path = root / "manifest.json"
    manifest = {
        "schemaVersion": L0_ARTIFACT_MANIFEST_SCHEMA,
        "translationIdentity": translation.identity,
        "planIdentity": translation.translation_plan_id,
        "proofIdentity": translation.proof_identity,
        "runtimeContractId": translation.runtime_contract_id,
        "runtimeContractVersion": translation.runtime_contract_version,
        "recipeIdentity": translation.recipe_id,
        "runtimeHeaders": ["stdint.h"],
        "includeDirectories": [],
        "libraryDirectories": [],
        "libraries": [],
        "source": _artifact_dict(source_expected),
        "targets": {
            name: _artifact_dict(value) for name, value in sorted(targets.items())
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    matrix = L0BuildMatrix(
        str(source), SOURCE_COMPILER, SOURCE_FLAGS, str(target), COMPILERS,
        TARGET_FLAGS, OPTIMIZATIONS, SANITIZERS, str(work), str(manifest_path),
        _digest(manifest_path), runtime_headers=("stdint.h",),
        link_kind=link_kind, runtime_timeout_seconds=60,
    )
    return (
        matrix,
        ProgramArtifact("source", str(source_output), "object", _digest(source_output)),
        ProgramArtifact("target", str(target_output), link_kind, _digest(target_output)),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--link-kind", choices=("executable", "shared_library"), required=True,
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="riscv2x86-real-l0-") as directory:
        root = Path(directory)
        translation = _translation()
        matrix, source, target = _prepare_reference_artifacts(
            root, args.link_kind, translation,
        )
        result = run_l0_build_matrix(
            matrix, translation, source, target,
            target_environment={
                "sourceIsa": "rv64gc", "sourceAbi": "lp64d",
                "targetIsa": "x86_64", "targetAbi": "sysv_amd64",
            },
        )
        cells = json.loads(result.detail)
        if result.status is not ValidationStatus.VERIFIED:
            raise RuntimeError(json.dumps(cells, indent=2, sort_keys=True))
        expected_ids = {
            _cell_id(compiler, optimization, sanitizer)
            for compiler in COMPILERS
            for optimization in OPTIMIZATIONS
            for sanitizer in SANITIZERS
        }
        actual_ids = {cell["id"] for cell in cells if cell["id"] != "source-rv64"}
        if actual_ids != expected_ids or len(cells) != 19:
            raise RuntimeError("real L0 result does not contain the complete 18-cell matrix")
        if any(cell["status"] != "verified" for cell in cells):
            raise RuntimeError("real L0 matrix contains a non-verified cell")
        print(
            json.dumps({
                "linkKind": args.link_kind,
                "status": result.status.value,
                "evidenceIdentity": result.evidence_identity,
                "verifiedCells": len(cells),
            }, sort_keys=True)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
