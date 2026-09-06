"""Fail-closed L0 source/target build, link, ABI and runtime-load matrix.

This is deliberately a command runner, rather than a record that a caller may
mark as built.  A missing compiler, ELF inspector, loader, or sanitizer support
is inconclusive; it is never a successful matrix cell.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
from typing import Callable, Mapping, Sequence

from .translation_validation import (
    ProgramArtifact, ValidationLayerResult, ValidationLevel,
)
from .validation_status import ValidationStatus


L0_BUILD_MATRIX_SCHEMA = "riscv2x86.l0-build-matrix.v1"
_OPTIMIZATIONS = ("-O0", "-O2", "-O3")
_SANITIZERS = ("none", "asan", "ubsan")
_COMPILERS = ("gcc", "clang")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], Path], CommandResult]


def _run(argv: Sequence[str], cwd: Path) -> CommandResult:
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class L0BuildMatrix:
    source_path: str
    source_compiler: str
    source_flags: tuple[str, ...]
    target_path: str
    target_compilers: tuple[str, ...]
    target_flags: tuple[str, ...]
    optimizations: tuple[str, ...]
    sanitizers: tuple[str, ...]
    work_directory: str
    translation_manifest_path: str
    translation_manifest_digest: str
    runtime_headers: tuple[str, ...] = ()
    include_directories: tuple[str, ...] = ()
    library_directories: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    link_kind: str = "executable"
    warnings_as_errors: bool = True

    def __post_init__(self) -> None:
        if not all((self.source_path, self.source_compiler, self.target_path,
                    self.work_directory, self.translation_manifest_path,
                    self.translation_manifest_digest)):
            raise ValueError("L0 build matrix identity is incomplete")
        if not set(_COMPILERS).issubset(self.target_compilers):
            raise ValueError("initial L0 matrix requires GCC and Clang")
        if not set(_OPTIMIZATIONS).issubset(self.optimizations):
            raise ValueError("initial L0 matrix requires -O0/-O2/-O3")
        if not set(_SANITIZERS).issubset(self.sanitizers):
            raise ValueError("initial L0 matrix requires none/asan/ubsan")
        if self.link_kind not in {"executable", "shared_library"}:
            raise ValueError("L0 link kind is unsupported")


def load_l0_build_matrix(data: Mapping[str, object]) -> L0BuildMatrix:
    if data.get("schemaVersion") != L0_BUILD_MATRIX_SCHEMA:
        raise ValueError("L0 build matrix schema version is unsupported")
    def values(name: str) -> tuple[str, ...]:
        value = data.get(name, ())
        if not isinstance(value, list):
            raise ValueError("L0 build matrix %s must be an array" % name)
        return tuple(map(str, value))
    warning = data.get("warningPolicy", {})
    if not isinstance(warning, Mapping):
        raise ValueError("L0 warning policy must be an object")
    return L0BuildMatrix(
        source_path=str(data.get("sourcePath", "")), source_compiler=str(data.get("sourceCompiler", "")),
        source_flags=values("sourceFlags"), target_path=str(data.get("targetPath", "")),
        target_compilers=values("targetCompilers"), target_flags=values("targetFlags"),
        optimizations=values("optimizations"), sanitizers=values("sanitizers"),
        work_directory=str(data.get("workDirectory", "")),
        translation_manifest_path=str(data.get("translationManifestPath", "")),
        translation_manifest_digest=str(data.get("translationManifestDigest", "")),
        runtime_headers=values("runtimeHeaders"), include_directories=values("includeDirectories"),
        library_directories=values("libraryDirectories"), libraries=values("libraries"),
        link_kind=str(data.get("linkKind", "executable")),
        warnings_as_errors=bool(warning.get("warningsAsErrors", True)),
    )


def _tool(name: str) -> bool:
    return bool(shutil.which(name))


def _status(cells: list[dict[str, object]]) -> ValidationStatus:
    statuses = {str(cell["status"]) for cell in cells}
    if "failed" in statuses:
        return ValidationStatus.FAILED
    if "inconclusive" in statuses:
        return ValidationStatus.INCONCLUSIVE
    return ValidationStatus.VERIFIED


def _cell_id(compiler: str, optimization: str, sanitizer: str) -> str:
    return "%s-%s-%s" % (compiler, optimization[1:], sanitizer)


def _inspect_elf(path: Path, expected_machine: str, cwd: Path, runner: CommandRunner, tool_available: Callable[[str], bool]) -> CommandResult | None:
    if not tool_available("readelf"):
        return None
    result = runner(("readelf", "-h", str(path)), cwd)
    if result.returncode or "ELF" not in result.stdout or expected_machine not in result.stdout:
        return CommandResult(1, result.stdout, result.stderr or "ELF ABI/machine mismatch")
    return result


def _unsupported_sanitizer(text: str) -> bool:
    lowered = text.lower()
    return "unrecognized" in lowered or "unsupported option" in lowered or "cannot find" in lowered and "asan" in lowered


def run_l0_build_matrix(
    matrix: L0BuildMatrix, source_program_artifact: ProgramArtifact,
    target_program_artifact: ProgramArtifact, *, command_runner: CommandRunner = _run,
    tool_available: Callable[[str], bool] = _tool,
) -> ValidationLayerResult:
    """Build the RV64 source and every x86-64 target matrix cell.

    The supplied ProgramArtifact digests are expected hashes, not decorative
    metadata.  The source is an RV64 object; the designated primary target is
    GCC/-O0/no-sanitizer and must be the linked artifact path supplied to the
    validation entry point.
    """
    cells: list[dict[str, object]] = []
    cwd = Path(matrix.work_directory)
    cwd.mkdir(parents=True, exist_ok=True)
    manifest = Path(matrix.translation_manifest_path)
    if not manifest.is_file() or _digest(manifest) != matrix.translation_manifest_digest:
        cells.append({"id": "manifest", "status": "failed", "detail": "translation manifest hash mismatch"})
    elif source_program_artifact.artifact_kind != "object" or target_program_artifact.artifact_kind != matrix.link_kind:
        cells.append({"id": "artifact-kind", "status": "failed", "detail": "artifact kind does not match L0 build contract"})
    elif not tool_available(matrix.source_compiler) or not tool_available("readelf"):
        cells.append({"id": "source-rv64", "status": "inconclusive", "detail": "source compiler or readelf unavailable"})
    else:
        source_out = Path(source_program_artifact.artifact_path)
        source_out.parent.mkdir(parents=True, exist_ok=True)
        source_flags = (*matrix.source_flags, "-Werror") if matrix.warnings_as_errors else matrix.source_flags
        source = command_runner((matrix.source_compiler, *source_flags, "-c", matrix.source_path, "-o", str(source_out)), cwd)
        elf = _inspect_elf(source_out, "RISC-V", cwd, command_runner, tool_available) if source.returncode == 0 and source_out.is_file() else CommandResult(1, "", "source build did not produce object")
        ok = (source.returncode == 0 and elf is not None and elf.returncode == 0
              and _digest(source_out) == source_program_artifact.artifact_digest
              and (not matrix.warnings_as_errors or "warning:" not in source.stderr))
        cells.append({"id": "source-rv64", "status": "verified" if ok else "failed", "detail": source.stderr or (elf.stderr if elf else "readelf unavailable")})

    includes = tuple("-I" + item for item in matrix.include_directories)
    libdirs = tuple("-L" + item for item in matrix.library_directories)
    libs = tuple("-l" + item for item in matrix.libraries)
    for compiler in matrix.target_compilers:
        for optimization in matrix.optimizations:
            for sanitizer in matrix.sanitizers:
                ident = _cell_id(compiler, optimization, sanitizer)
                if not tool_available(compiler) or not tool_available("readelf") or not tool_available("ldd"):
                    cells.append({"id": ident, "status": "inconclusive", "detail": "target compiler, readelf, or loader unavailable"})
                    continue
                sanitizer_flags = () if sanitizer == "none" else ("-fsanitize=" + sanitizer,)
                common = (*matrix.target_flags, optimization, *sanitizer_flags, *includes)
                if matrix.warnings_as_errors:
                    common += ("-Werror",)
                syntax = command_runner((compiler, "-fsyntax-only", *common, matrix.target_path), cwd)
                if syntax.returncode:
                    cells.append({"id": ident, "status": "inconclusive" if sanitizer != "none" and _unsupported_sanitizer(syntax.stderr) else "failed", "detail": syntax.stderr})
                    continue
                header_probe = cwd / ("l0-headers-" + ident + ".c")
                header_probe.write_text("".join('#include <%s>\n' % h for h in matrix.runtime_headers) + "int main(void){return 0;}\n", encoding="utf-8")
                headers = command_runner((compiler, "-fsyntax-only", *common, str(header_probe)), cwd)
                if headers.returncode:
                    cells.append({"id": ident, "status": "failed", "detail": "runtime header resolution: " + headers.stderr})
                    continue
                obj = cwd / (ident + ".o")
                built = command_runner((compiler, "-c", *common, matrix.target_path, "-o", str(obj)), cwd)
                output = Path(target_program_artifact.artifact_path) if ident == "gcc-O0-none" else cwd / (ident + (".so" if matrix.link_kind == "shared_library" else ".exe"))
                output.parent.mkdir(parents=True, exist_ok=True)
                link_flags = ("-shared",) if matrix.link_kind == "shared_library" else ()
                linked = command_runner((compiler, *sanitizer_flags, *link_flags, str(obj), "-o", str(output), *libdirs, *libs), cwd)
                elf = _inspect_elf(output, "X86-64", cwd, command_runner, tool_available) if linked.returncode == 0 and output.is_file() else CommandResult(1, "", "target link did not produce artifact")
                load = command_runner(("ldd", str(output)), cwd) if elf is not None and elf.returncode == 0 else CommandResult(1, "", "not loadable")
                warning_text = syntax.stderr + headers.stderr + built.stderr + linked.stderr
                bad = built.returncode or linked.returncode or elf is None or elf.returncode or load.returncode or "not found" in load.stdout or (matrix.warnings_as_errors and "warning:" in warning_text)
                unsupported = sanitizer != "none" and _unsupported_sanitizer(warning_text)
                digest_bad = ident == "gcc-O0-none" and (not output.is_file() or _digest(output) != target_program_artifact.artifact_digest)
                cells.append({"id": ident, "status": "inconclusive" if unsupported else "failed" if bad or digest_bad else "verified", "detail": warning_text or load.stderr, "artifactDigest": _digest(output) if output.is_file() else ""})

    status = _status(cells)
    evidence = "sha256:" + sha256(json.dumps({"schemaVersion": L0_BUILD_MATRIX_SCHEMA, "manifest": matrix.translation_manifest_digest, "cells": cells}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ValidationLayerResult(ValidationLevel.L0, status, evidence, json.dumps(cells, sort_keys=True))


def build_l0_validator(matrix: L0BuildMatrix) -> Callable[..., ValidationLayerResult]:
    def validator(**kwargs: object) -> ValidationLayerResult:
        if kwargs.get("level") is not ValidationLevel.L0:
            return ValidationLayerResult(ValidationLevel.L0, ValidationStatus.FAILED, detail="L0 validator invoked for wrong level")
        return run_l0_build_matrix(matrix, kwargs["source_program_artifact"], kwargs["target_program_artifact"])
    return validator
