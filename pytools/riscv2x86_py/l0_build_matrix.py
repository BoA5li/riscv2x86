"""Executable L0 RV64/x86-64 build, link, ABI, dependency and load matrix."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable, Mapping, Sequence

from .l0_artifact_manifest import ExpectedArtifact, ExpectedElf, load_l0_artifact_manifest
from .translation_validation import ProgramArtifact, TranslationArtifact, ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus

L0_BUILD_MATRIX_SCHEMA = "riscv2x86.l0-build-matrix.v2"
L0_ELF_ABI_POLICY_VERSION = "riscv2x86.l0-elf-abi-policy.v1"
_OPTIMIZATIONS = ("-O0", "-O2", "-O3")
_SANITIZERS = ("none", "asan", "ubsan")
_COMPILERS = ("gcc", "clang")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SANITIZER_FINDINGS = ("addresssanitizer", "undefinedbehaviorsanitizer", "runtime error:", "ubsan:")
_SANITIZER_FLAGS = {"asan": "address", "ubsan": "undefined"}
_SOURCE_ISA = "rv64gc"
_SOURCE_ABI = "lp64d"
_TARGET_ISA = "x86_64"
_TARGET_ABI = "sysv_amd64"


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


CommandRunner = Callable[[Sequence[str], Path, int], CommandResult]


def _run(argv: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
    try:
        completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                                   check=False, timeout=timeout)
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(124, str(exc.stdout or ""), str(exc.stderr or ""), True)


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
    runtime_timeout_seconds: int = 10

    def __post_init__(self) -> None:
        if not all((self.source_path, self.source_compiler, self.target_path, self.work_directory,
                    self.translation_manifest_path, self.translation_manifest_digest)):
            raise ValueError("L0 matrix identity is incomplete")
        if not _SHA256.fullmatch(self.translation_manifest_digest): raise ValueError("manifest digest is invalid")
        for actual, required, label in ((self.target_compilers, _COMPILERS, "compilers"),
                                        (self.optimizations, _OPTIMIZATIONS, "optimizations"),
                                        (self.sanitizers, _SANITIZERS, "sanitizers")):
            if tuple(actual) != tuple(required): raise ValueError("L0 matrix requires exact ordered " + label)
        if self.link_kind not in {"executable", "shared_library"}: raise ValueError("unsupported link kind")
        if not isinstance(self.warnings_as_errors, bool) or self.runtime_timeout_seconds <= 0:
            raise ValueError("warning policy/runtime timeout is invalid")


def load_l0_build_matrix(data: Mapping[str, object]) -> L0BuildMatrix:
    expected = {"schemaVersion", "sourcePath", "sourceCompiler", "sourceFlags", "targetPath",
                "targetCompilers", "targetFlags", "optimizations", "sanitizers", "workDirectory",
                "translationManifestPath", "translationManifestDigest", "runtimeHeaders",
                "includeDirectories", "libraryDirectories", "libraries", "linkKind", "warningPolicy",
                "runtimeTimeoutSeconds"}
    optional = {"runtimeHeaders", "includeDirectories", "libraryDirectories", "libraries",
                "linkKind", "warningPolicy", "runtimeTimeoutSeconds"}
    if not set(data).issubset(expected) or not expected - optional <= set(data):
        raise ValueError("L0 matrix fields are incomplete or unknown")
    if data.get("schemaVersion") != L0_BUILD_MATRIX_SCHEMA: raise ValueError("unsupported L0 matrix schema")
    def string(name: str, default: str = "") -> str:
        value = data.get(name, default)
        if not isinstance(value, str): raise ValueError(name + " must be a string")
        return value
    def values(name: str) -> tuple[str, ...]:
        value = data.get(name, [])
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ValueError(name + " must be an array of strings")
        return tuple(value)
    warning = data.get("warningPolicy", {"warningsAsErrors": True})
    if not isinstance(warning, Mapping) or set(warning) != {"warningsAsErrors"}:
        raise ValueError("warningPolicy is malformed")
    warnings_as_errors = warning.get("warningsAsErrors")
    if not isinstance(warnings_as_errors, bool): raise ValueError("warningsAsErrors must be boolean")
    timeout = data.get("runtimeTimeoutSeconds", 10)
    if isinstance(timeout, bool) or not isinstance(timeout, int): raise ValueError("runtime timeout must be integer")
    return L0BuildMatrix(string("sourcePath"), string("sourceCompiler"), values("sourceFlags"),
                         string("targetPath"), values("targetCompilers"), values("targetFlags"),
                         values("optimizations"), values("sanitizers"), string("workDirectory"),
                         string("translationManifestPath"), string("translationManifestDigest"),
                         values("runtimeHeaders"), values("includeDirectories"), values("libraryDirectories"),
                         values("libraries"), string("linkKind", "executable"), warnings_as_errors, timeout)


def _cell_id(compiler: str, optimization: str, sanitizer: str) -> str:
    return f"{compiler}-{optimization[1:]}-{sanitizer}"


def _status(cells: list[dict[str, object]]) -> ValidationStatus:
    statuses = {cell["status"] for cell in cells}
    return (ValidationStatus.FAILED if "failed" in statuses else
            ValidationStatus.INCONCLUSIVE if "inconclusive" in statuses else ValidationStatus.VERIFIED)


def _unsupported_sanitizer(text: str, sanitizer: str) -> bool:
    value = text.lower()
    names = (sanitizer, "lib" + sanitizer, _SANITIZER_FLAGS.get(sanitizer, sanitizer))
    unavailable = ("unsupported option", "unrecognized command-line option", "unknown argument",
                   "cannot find", "unable to find library", "library not found", "not supported")
    return any(marker in value for marker in unavailable) and any(name in value for name in names)


def _sanitizer_finding(result: CommandResult) -> bool:
    text = (result.stdout + "\n" + result.stderr).lower()
    return any(marker in text for marker in _SANITIZER_FINDINGS)


def _readelf(path: Path, option: str, cwd: Path, runner: CommandRunner, timeout: int) -> CommandResult:
    return runner(("readelf", option, str(path)), cwd, timeout)


def _match(pattern: str, text: str, label: str) -> str:
    found = re.search(pattern, text, re.MULTILINE)
    if not found: raise ValueError("readelf output lacks " + label)
    return found.group(1).strip()


def _inspect_elf(path: Path, cwd: Path, runner: CommandRunner, timeout: int) -> tuple[ExpectedElf | None, str]:
    header = _readelf(path, "-hW", cwd, runner, timeout)
    program = _readelf(path, "-lW", cwd, runner, timeout)
    dynamic = _readelf(path, "-dW", cwd, runner, timeout)
    symbols = _readelf(path, "-sW", cwd, runner, timeout)
    relocations = _readelf(path, "-rW", cwd, runner, timeout)
    if any(x.timed_out or x.returncode for x in (header, program, dynamic, symbols, relocations)):
        return None, "readelf header/program/dynamic/symbol/relocation inspection failed"
    try:
        elf_class = _match(r"Class:\s*(ELF\d+)", header.stdout, "class")
        data = _match(r"Data:\s*([^\n]+)", header.stdout, "data").lower()
        endian = "little" if "little endian" in data else "big" if "big endian" in data else ""
        raw_type = _match(r"Type:\s*([A-Z]+)", header.stdout, "type")
        machine = _match(r"Machine:\s*([^\n]+)", header.stdout, "machine")
        os_abi = _match(r"OS/ABI:\s*([^\n]+)", header.stdout, "OS/ABI")
        abi_version = _match(r"ABI Version:\s*([^\n]+)", header.stdout, "ABI version")
        flags = _match(r"Flags:\s*([^\n]+)", header.stdout, "flags")
        interpreter_match = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", program.stdout)
        needed = tuple(sorted(set(re.findall(r"Shared library: \[([^\]]+)\]", dynamic.stdout))))
        runpath = tuple(sorted(set(re.findall(r"(?:RUNPATH|RPATH).*Library (?:run)?path: \[([^\]]*)\]", dynamic.stdout))))
        soname_match = re.search(r"SONAME.*Library soname: \[([^\]]+)\]", dynamic.stdout)
        undefined_names = []
        for line in symbols.stdout.splitlines():
            parts = line.split()
            if "UND" in parts and parts.index("UND") + 1 < len(parts):
                undefined_names.append(parts[parts.index("UND") + 1].split("@", 1)[0])
        undefined = tuple(sorted(set(undefined_names)))
        reloc = tuple(sorted(set(re.findall(r"\b(R_[A-Z0-9_]+)\b", relocations.stdout))))
        return ExpectedElf(elf_class, endian, raw_type, machine, os_abi, abi_version, flags,
                           interpreter_match.group(1) if interpreter_match else "", needed, runpath,
                           soname_match.group(1) if soname_match else "", undefined, reloc), ""
    except ValueError as exc:
        return None, str(exc)


def _elf_matches(actual: ExpectedElf, expected: ExpectedElf) -> bool:
    return actual == expected


def _numeric_elf_flags(value: str) -> int | None:
    match = re.match(r"\s*0x([0-9a-fA-F]+)", value)
    return None if match is None else int(match.group(1), 16)


def _machine_is_x86_64(value: str) -> bool:
    normalized = value.strip().lower().replace("_", "-")
    return normalized in {
        "advanced micro devices x86-64", "amd x86-64", "x86-64",
    }


def _common_elf64_error(elf: ExpectedElf) -> str:
    if elf.elf_class != "ELF64":
        return "ELF class must be ELF64"
    if elf.endian != "little":
        return "ELF data encoding must be little-endian"
    if elf.os_abi not in {"UNIX - System V", "UNIX - GNU"}:
        return "ELF OS/ABI is incompatible with the supported Linux/System-V ABI"
    if elf.abi_version != "0":
        return "ELF ABI version must be zero"
    return ""


def _source_elf_abi_error(elf: ExpectedElf) -> str:
    reason = _common_elf64_error(elf)
    if reason:
        return reason
    if elf.elf_type != "REL" or elf.machine.strip() != "RISC-V":
        return "RV64 source artifact must be an EM_RISCV relocatable object"
    flags = _numeric_elf_flags(elf.abi_flags)
    if flags is None:
        return "RV64 ELF e_flags are not parseable"
    if flags & 0x6 != 0x4:
        return "RV64 ELF does not declare the LP64D double-float ABI"
    if flags & 0x1 == 0:
        return "RV64GC ELF does not declare the compressed-instruction extension"
    if flags & 0x8:
        return "RV64 ELF incorrectly declares the RV32E ABI"
    if elf.interpreter or elf.needed or elf.soname:
        return "RV64 source object unexpectedly contains dynamic-link metadata"
    if any(not item.startswith("R_RISCV_") for item in elf.relocation_types):
        return "RV64 source object contains a non-RISC-V relocation"
    return ""


def _target_elf_abi_error(elf: ExpectedElf, *, artifact_kind: str) -> str:
    reason = _common_elf64_error(elf)
    if reason:
        return reason
    if not _machine_is_x86_64(elf.machine):
        return "target artifact must use the x86-64 ELF machine"
    flags = _numeric_elf_flags(elf.abi_flags)
    if flags != 0:
        return "x86-64 ELF e_flags must be zero"
    if any(not item.startswith("R_X86_64_") for item in elf.relocation_types):
        return "target artifact contains a non-x86-64 relocation"
    if artifact_kind == "object":
        if elf.elf_type != "REL":
            return "x86-64 object must have ELF type ET_REL"
        if elf.interpreter or elf.needed or elf.soname:
            return "x86-64 object unexpectedly contains dynamic-link metadata"
    elif artifact_kind == "executable":
        if elf.elf_type not in {"EXEC", "DYN"}:
            return "x86-64 executable must have ELF type ET_EXEC or PIE ET_DYN"
        if elf.elf_type == "DYN" and not elf.interpreter:
            return "x86-64 PIE executable lacks a dynamic interpreter"
        if elf.soname:
            return "x86-64 executable must not declare a shared-library SONAME"
    elif artifact_kind == "shared_library":
        if elf.elf_type != "DYN":
            return "x86-64 shared library must have ELF type ET_DYN"
        if elf.interpreter:
            return "x86-64 shared library must not declare a program interpreter"
    else:
        return "unsupported target artifact kind"
    return ""


def _environment_abi_error(environment: Mapping[str, object] | None) -> str:
    if environment is None:
        return ""
    required = {
        "sourceIsa": _SOURCE_ISA, "sourceAbi": _SOURCE_ABI,
        "targetIsa": _TARGET_ISA, "targetAbi": _TARGET_ABI,
    }
    if any(environment.get(name) != value for name, value in required.items()):
        return "L0 environment is outside the fixed RV64GC/LP64D to x86-64/SysV ABI policy"
    return ""


def _source_triple_error(value: str) -> str:
    normalized = value.strip().lower()
    return "" if "riscv64" in normalized and "riscv32" not in normalized else (
        "source compiler triple is not RV64"
    )


def _target_triple_error(value: str) -> str:
    normalized = value.strip().lower()
    return "" if "x86_64" in normalized or "amd64" in normalized else (
        "target compiler triple is not x86-64"
    )


def _flags(matrix: L0BuildMatrix, optimization: str, sanitizer: str) -> tuple[str, ...]:
    flags = (*matrix.target_flags, optimization)
    if sanitizer != "none": flags += ("-fsanitize=" + _SANITIZER_FLAGS[sanitizer],)
    if matrix.link_kind == "shared_library": flags += ("-fPIC",)
    if matrix.warnings_as_errors: flags += ("-Werror",)
    return flags


def _runtime_load(output: Path, compiler: str, sanitizer_flags: tuple[str, ...], matrix: L0BuildMatrix,
                  ident: str, cwd: Path, runner: CommandRunner) -> CommandResult:
    if matrix.link_kind == "executable":
        return runner(("env", "LD_BIND_NOW=1", str(output)), cwd, matrix.runtime_timeout_seconds)
    harness = cwd / ("dlopen-" + ident + ".c")
    harness.write_text("#include <dlfcn.h>\nint main(int c,char**v){void*h=dlopen(v[1],RTLD_NOW);"
                       "if(!h)return 111;return dlclose(h)?112:0;}\n", encoding="utf-8")
    binary = cwd / ("dlopen-" + ident)
    built = runner((compiler, *sanitizer_flags, str(harness), "-ldl", "-o", str(binary)),
                   cwd, matrix.runtime_timeout_seconds)
    if built.returncode or built.timed_out: return built
    return runner((str(binary), str(output)), cwd, matrix.runtime_timeout_seconds)


def _load_manifest(matrix: L0BuildMatrix):
    return load_l0_artifact_manifest(
        matrix.translation_manifest_path, matrix.translation_manifest_digest,
    )


def _check_manifest_binding(manifest, matrix: L0BuildMatrix, translation: TranslationArtifact,
                            source: ProgramArtifact, target: ProgramArtifact) -> str:
    expected_cells = tuple(_cell_id(c, o, s) for c in matrix.target_compilers
                           for o in matrix.optimizations for s in matrix.sanitizers)
    if tuple(manifest.targets) != tuple(sorted(expected_cells)) or set(manifest.targets) != set(expected_cells):
        return "manifest must declare exactly all 18 target cells"
    checks = ((manifest.translation_identity, translation.identity),
              (manifest.plan_identity, translation.translation_plan_id),
              (manifest.proof_identity, translation.proof_identity),
              (manifest.runtime_contract_id, translation.runtime_contract_id),
              (manifest.runtime_contract_version, translation.runtime_contract_version),
              (manifest.recipe_identity, translation.recipe_id),
              (manifest.runtime_headers, matrix.runtime_headers),
              (manifest.include_directories, matrix.include_directories),
              (manifest.library_directories, matrix.library_directories),
              (manifest.libraries, matrix.libraries),
              (manifest.source.artifact_digest, source.artifact_digest),
              (manifest.source.object_digest, source.artifact_digest),
              (manifest.source.artifact_kind, source.artifact_kind),
              (manifest.targets["gcc-O0-none"].artifact_digest, target.artifact_digest),
              (manifest.targets["gcc-O0-none"].artifact_kind, target.artifact_kind))
    return "" if all(a == b for a, b in checks) else "manifest translation/artifact binding mismatch"


def _cell(status: str, ident: str, detail: str, **facts: object) -> dict[str, object]:
    return {"id": ident, "status": status, "detail": detail, **facts}


def run_l0_build_matrix(
    matrix: L0BuildMatrix, translation_artifact: TranslationArtifact,
    source_program_artifact: ProgramArtifact, target_program_artifact: ProgramArtifact, *,
    target_environment: Mapping[str, object] | None = None,
    command_runner: CommandRunner = _run, tool_available: Callable[[str], bool] = lambda name: bool(shutil.which(name)),
) -> ValidationLayerResult:
    cells: list[dict[str, object]] = []
    cwd = Path(matrix.work_directory)
    cwd.mkdir(parents=True, exist_ok=True)
    try:
        manifest = _load_manifest(matrix)
        binding_error = _check_manifest_binding(manifest, matrix, translation_artifact,
                                                source_program_artifact, target_program_artifact)
        if binding_error: raise ValueError(binding_error)
    except ValueError as exc:
        cells.append(_cell("failed", "manifest", str(exc)))
        return _finish(matrix, cells)

    environment_error = _environment_abi_error(target_environment)
    if environment_error:
        cells.append(_cell("failed", "elf-abi-policy", environment_error))
        return _finish(matrix, cells)

    required_tools = {matrix.source_compiler, "readelf", *matrix.target_compilers}
    missing = sorted(tool for tool in required_tools if not tool_available(tool))
    if missing:
        cells.append(_cell("inconclusive", "tools", "unavailable tools: " + ",".join(missing)))
        return _finish(matrix, cells)

    source_out = Path(source_program_artifact.artifact_path)
    source_out.parent.mkdir(parents=True, exist_ok=True)
    source_flags = (*matrix.source_flags, *(("-Werror",) if matrix.warnings_as_errors else ()))
    triple = command_runner((matrix.source_compiler, "-dumpmachine"), cwd, matrix.runtime_timeout_seconds)
    built = command_runner((matrix.source_compiler, *source_flags, "-c", matrix.source_path,
                            "-o", str(source_out)), cwd, matrix.runtime_timeout_seconds)
    source_elf, elf_detail = _inspect_elf(source_out, cwd, command_runner, matrix.runtime_timeout_seconds) \
        if not built.returncode and source_out.is_file() else (None, "source object missing")
    source_policy_error = "" if source_elf is None else _source_elf_abi_error(source_elf)
    source_triple_error = _source_triple_error(triple.stdout) if not triple.returncode else ""
    source_bad = (triple.returncode or triple.timed_out or built.returncode or built.timed_out or source_elf is None or
                  bool(source_policy_error) or bool(source_triple_error) or
                  triple.stdout.strip() != manifest.source.compiler_triple or manifest.source.compiler_identity != matrix.source_compiler or
                  manifest.source.flags != source_flags or not source_out.is_file() or
                  _digest(source_out) != manifest.source.artifact_digest or
                  manifest.source.object_elf != manifest.source.elf or
                  source_elf is not None and not _elf_matches(source_elf, manifest.source.elf) or
                  matrix.warnings_as_errors and "warning:" in built.stderr.lower())
    cells.append(_cell("failed" if source_bad else "verified", "source-rv64",
                       built.stderr or source_policy_error or source_triple_error or elf_detail,
                       artifactDigest=_digest(source_out) if source_out.is_file() else "",
                       compilerTriple=triple.stdout.strip()))

    includes = tuple("-I" + item for item in matrix.include_directories)
    libdirs = tuple("-L" + item for item in matrix.library_directories)
    libs = tuple("-l" + item for item in matrix.libraries)
    for compiler in matrix.target_compilers:
        compiler_triple = command_runner((compiler, "-dumpmachine"), cwd, matrix.runtime_timeout_seconds)
        for optimization in matrix.optimizations:
            for sanitizer in matrix.sanitizers:
                ident = _cell_id(compiler, optimization, sanitizer)
                expected = manifest.targets[ident]
                sanitizer_flags = () if sanitizer == "none" else ("-fsanitize=" + _SANITIZER_FLAGS[sanitizer],)
                flags = _flags(matrix, optimization, sanitizer)
                if compiler_triple.returncode or compiler_triple.timed_out:
                    cells.append(_cell("inconclusive", ident, "compiler triple unavailable")); continue
                triple_policy_error = _target_triple_error(compiler_triple.stdout)
                if triple_policy_error:
                    cells.append(_cell("failed", ident, triple_policy_error)); continue
                if (expected.compiler_identity != compiler or expected.compiler_triple != compiler_triple.stdout.strip() or
                        expected.flags != flags or expected.runtime_libraries != matrix.libraries or
                        expected.artifact_kind != matrix.link_kind):
                    cells.append(_cell("failed", ident, "manifest toolchain/flags/runtime declaration mismatch")); continue
                common = (*flags, *includes)
                syntax = command_runner((compiler, "-fsyntax-only", *common, matrix.target_path), cwd,
                                        matrix.runtime_timeout_seconds)
                if syntax.returncode or syntax.timed_out:
                    status = "inconclusive" if sanitizer != "none" and _unsupported_sanitizer(syntax.stderr, sanitizer) else "failed"
                    cells.append(_cell(status, ident, "target syntax: " + syntax.stderr)); continue
                header = cwd / ("headers-" + ident + ".c")
                header.write_text("".join(f"#include <{name}>\n" for name in matrix.runtime_headers) +
                                  "int main(void){return 0;}\n", encoding="utf-8")
                header_result = command_runner((compiler, "-fsyntax-only", *common, str(header)), cwd,
                                               matrix.runtime_timeout_seconds)
                if header_result.returncode or header_result.timed_out:
                    cells.append(_cell("failed", ident, "runtime header resolution: " + header_result.stderr)); continue
                obj = cwd / (ident + ".o")
                object_result = command_runner((compiler, "-c", *common, matrix.target_path, "-o", str(obj)), cwd,
                                               matrix.runtime_timeout_seconds)
                output = (Path(target_program_artifact.artifact_path) if ident == "gcc-O0-none" else
                          cwd / (ident + (".so" if matrix.link_kind == "shared_library" else ".exe")))
                output.parent.mkdir(parents=True, exist_ok=True)
                link_mode = ("-shared",) if matrix.link_kind == "shared_library" else ()
                link_result = command_runner((compiler, *sanitizer_flags, *link_mode, str(obj), "-o", str(output),
                                              *libdirs, *libs), cwd, matrix.runtime_timeout_seconds)
                text = syntax.stderr + header_result.stderr + object_result.stderr + link_result.stderr
                if object_result.returncode or link_result.returncode or object_result.timed_out or link_result.timed_out:
                    status = "inconclusive" if sanitizer != "none" and _unsupported_sanitizer(text, sanitizer) else "failed"
                    cells.append(_cell(status, ident, "compile/link: " + text)); continue
                object_elf, object_detail = _inspect_elf(obj, cwd, command_runner, matrix.runtime_timeout_seconds)
                object_policy_error = "" if object_elf is None else _target_elf_abi_error(
                    object_elf, artifact_kind="object",
                )
                if (not obj.is_file() or _digest(obj) != expected.object_digest or object_elf is None or
                        bool(object_policy_error) or not _elf_matches(object_elf, expected.object_elf)):
                    cells.append(_cell("failed", ident, "object ELF/ABI/relocation mismatch: " +
                                       (object_policy_error or object_detail))); continue
                actual_elf, elf_detail = _inspect_elf(output, cwd, command_runner, matrix.runtime_timeout_seconds)
                final_policy_error = "" if actual_elf is None else _target_elf_abi_error(
                    actual_elf, artifact_kind=matrix.link_kind,
                )
                if actual_elf is None or final_policy_error or not _elf_matches(actual_elf, expected.elf):
                    cells.append(_cell("failed", ident, "ELF/ABI/dependency mismatch: " +
                                       (final_policy_error or elf_detail))); continue
                if not output.is_file() or _digest(output) != expected.artifact_digest:
                    cells.append(_cell("failed", ident, "cell artifact digest mismatch")); continue
                if matrix.warnings_as_errors and "warning:" in text.lower():
                    cells.append(_cell("failed", ident, "compiler warning under Werror policy")); continue
                runtime = _runtime_load(output, compiler, sanitizer_flags, matrix, ident, cwd, command_runner)
                if runtime.timed_out:
                    cells.append(_cell("failed", ident, "runtime-load timed out")); continue
                if runtime.returncode < 0:
                    cells.append(_cell("failed", ident, "runtime-load terminated by signal")); continue
                if _sanitizer_finding(runtime):
                    cells.append(_cell("failed", ident, "sanitizer runtime finding: " + runtime.stderr)); continue
                if runtime.returncode:
                    cells.append(_cell("failed", ident, "runtime-load exit code %d: %s" % (runtime.returncode, runtime.stderr))); continue
                cells.append(_cell("verified", ident, runtime.stderr,
                                   artifactDigest=_digest(output), compilerTriple=compiler_triple.stdout.strip(),
                                   runtimeExitCode=runtime.returncode))
    return _finish(matrix, cells)


def _finish(matrix: L0BuildMatrix, cells: list[dict[str, object]]) -> ValidationLayerResult:
    payload = {
        "schemaVersion": L0_BUILD_MATRIX_SCHEMA,
        "elfAbiPolicyVersion": L0_ELF_ABI_POLICY_VERSION,
        "manifest": matrix.translation_manifest_digest,
        "cells": cells,
    }
    evidence = "sha256:" + sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ValidationLayerResult(ValidationLevel.L0, _status(cells), evidence, json.dumps(cells, sort_keys=True))


def build_l0_validator(matrix: L0BuildMatrix) -> Callable[..., ValidationLayerResult]:
    def validator(**kwargs: object) -> ValidationLayerResult:
        if kwargs.get("level") is not ValidationLevel.L0:
            return ValidationLayerResult(ValidationLevel.L0, ValidationStatus.FAILED,
                                         detail="L0 validator invoked for wrong level")
        return run_l0_build_matrix(matrix, kwargs["translation_artifact"],
                                   kwargs["source_program_artifact"], kwargs["target_program_artifact"],
                                   target_environment=kwargs.get("target_environment"))
    setattr(validator, "l0_matrix", matrix)
    return validator
