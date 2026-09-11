"""Production builder for the expected, per-cell L0 artifact manifest."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess

from .l0_artifact_manifest import ExpectedArtifact, ExpectedElf, L0_ARTIFACT_MANIFEST_SCHEMA
from .l0_build_matrix import L0BuildMatrix, _inspect_elf, _run
from .runtime_dependency_binding import resolve_runtime_contracts
from .translation_validation import ProgramArtifact, TranslationArtifact

COMPILERS = ("gcc", "clang")
OPTIMIZATIONS = ("-O0", "-O2", "-O3")
SANITIZERS = ("none", "asan", "ubsan")


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _checked(argv: tuple[str, ...], cwd: Path, timeout: int) -> str:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("L0 reference command failed: " + " ".join(argv) + "\n" + result.stderr)
    return result.stdout.strip()


def _elf(path: Path, cwd: Path, timeout: int) -> ExpectedElf:
    value, detail = _inspect_elf(path, cwd, _run, timeout)
    if value is None:
        raise RuntimeError("L0 ELF inspection failed: " + detail)
    return value


def _elf_dict(value: ExpectedElf) -> dict[str, object]:
    return {"class": value.elf_class, "endian": value.endian, "type": value.elf_type,
            "machine": value.machine, "osAbi": value.os_abi, "abiVersion": value.abi_version,
            "abiFlags": value.abi_flags, "interpreter": value.interpreter,
            "needed": list(value.needed), "runpath": list(value.runpath), "soname": value.soname,
            "undefinedSymbols": list(value.undefined_symbols),
            "relocationTypes": list(value.relocation_types)}


def _artifact_dict(value: ExpectedArtifact) -> dict[str, object]:
    return {"artifactDigest": value.artifact_digest, "objectDigest": value.object_digest,
            "artifactKind": value.artifact_kind, "compilerIdentity": value.compiler_identity,
            "compilerTriple": value.compiler_triple, "flags": list(value.flags),
            "runtimeLibraries": list(value.runtime_libraries), "elf": _elf_dict(value.elf),
            "objectElf": _elf_dict(value.object_elf)}


def build_l0_reference_manifest(
    *, source_path: Path, target_path: Path, output_directory: Path,
    translation: TranslationArtifact, link_kind: str, timeout: int = 60,
) -> tuple[L0BuildMatrix, ProgramArtifact, ProgramArtifact]:
    """Build all declared cells first, then freeze their hashes as the oracle."""
    output_directory.mkdir(parents=True, exist_ok=False)
    dependencies = resolve_runtime_contracts((translation.runtime_contract_id,))
    includes = tuple("-I" + item for item in dependencies.include_directories)
    libdirs = tuple("-L" + item for item in dependencies.library_directories)
    libs = tuple("-l" + item for item in dependencies.libraries)
    source_compiler = "riscv64-linux-gnu-gcc"
    source_flags = ("-march=rv64gc", "-mabi=lp64d")
    target_flags = ("-Wall", "-Wextra")
    source_obj = output_directory / "source.rv64.o"
    source_full_flags = (*source_flags, "-Werror")
    _checked((source_compiler, *source_full_flags, "-c", str(source_path), "-o", str(source_obj)),
             output_directory, timeout)
    source_elf = _elf(source_obj, output_directory, timeout)
    source_expected = ExpectedArtifact(
        _digest(source_obj), _digest(source_obj), "object", source_compiler,
        _checked((source_compiler, "-dumpmachine"), output_directory, timeout),
        source_full_flags, (), source_elf, source_elf,
    )
    suffix = ".so" if link_kind == "shared_library" else ".exe"
    canonical_target = output_directory / ("target" + suffix)
    targets: dict[str, ExpectedArtifact] = {}
    for compiler in COMPILERS:
        triple = _checked((compiler, "-dumpmachine"), output_directory, timeout)
        for optimization in OPTIMIZATIONS:
            for sanitizer in SANITIZERS:
                ident = f"{compiler}-{optimization[1:]}-{sanitizer}"
                flags = (*target_flags, optimization)
                if sanitizer != "none":
                    flags += ("-fsanitize=" + {"asan": "address", "ubsan": "undefined"}[sanitizer],)
                if link_kind == "shared_library":
                    flags += ("-fPIC",)
                flags += ("-Werror",)
                obj = output_directory / (ident + ".o")
                out = canonical_target if ident == "gcc-O0-none" else output_directory / (ident + suffix)
                _checked((compiler, "-c", *flags, *includes, str(target_path), "-o", str(obj)), output_directory, timeout)
                sanitizer_flags = (() if sanitizer == "none" else
                                   ("-fsanitize=" + {"asan": "address", "ubsan": "undefined"}[sanitizer],))
                mode = ("-shared",) if link_kind == "shared_library" else ()
                _checked((compiler, *sanitizer_flags, *mode, str(obj), *libdirs, *libs,
                          "-o", str(out)), output_directory, timeout)
                targets[ident] = ExpectedArtifact(
                    _digest(out), _digest(obj), link_kind, compiler, triple, flags,
                    dependencies.libraries, _elf(out, output_directory, timeout),
                    _elf(obj, output_directory, timeout),
                )
    manifest_path = output_directory / "l0-artifact-manifest.json"
    manifest = {"schemaVersion": L0_ARTIFACT_MANIFEST_SCHEMA,
                "translationIdentity": translation.identity,
                "planIdentity": translation.translation_plan_id,
                "proofIdentity": translation.proof_identity,
                "runtimeContractId": translation.runtime_contract_id,
                "runtimeContractVersion": translation.runtime_contract_version,
                "recipeIdentity": translation.recipe_id,
                "runtimeHeaders": list(dependencies.headers),
                "includeDirectories": list(dependencies.include_directories),
                "libraryDirectories": list(dependencies.library_directories),
                "libraries": list(dependencies.libraries),
                "source": _artifact_dict(source_expected),
                "targets": {key: _artifact_dict(value) for key, value in sorted(targets.items())}}
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                             encoding="utf-8")
    matrix = L0BuildMatrix(
        str(source_path), source_compiler, source_flags, str(target_path), COMPILERS,
        target_flags, OPTIMIZATIONS, SANITIZERS, str(output_directory / "verify"),
        str(manifest_path), _digest(manifest_path),
        runtime_headers=dependencies.headers,
        include_directories=dependencies.include_directories,
        library_directories=dependencies.library_directories,
        libraries=dependencies.libraries,
        link_kind=link_kind, runtime_timeout_seconds=timeout,
    )
    return (matrix,
            ProgramArtifact("source", str(source_obj), "object", _digest(source_obj)),
            ProgramArtifact("target", str(canonical_target), link_kind, _digest(canonical_target)))
