from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from riscv2x86_py.l0_artifact_manifest import L0_ARTIFACT_MANIFEST_SCHEMA
from riscv2x86_py.l0_build_matrix import (
    CommandResult, L0BuildMatrix, L0_BUILD_MATRIX_SCHEMA,
    L0_ELF_ABI_POLICY_VERSION,
    load_l0_build_matrix, run_l0_build_matrix,
)
from riscv2x86_py.translation_validation import ProgramArtifact, TranslationArtifact
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _digest(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _translation():
    return TranslationArtifact("fragment-1", "source-model", "plan-1", "constraint-1", "proof-1",
                               PreservationMode.ARCHITECTURE_EQUIVALENT, "shell-1", "runtime-1", "v1",
                               "recipe-1", (), "integer", "c")


def _elf(machine, kind, *, dynamic=False):
    return {"class": "ELF64", "endian": "little", "type": kind, "machine": machine,
            "osAbi": "UNIX - System V", "abiVersion": "0",
            "abiFlags": "0x5, RVC, double-float ABI" if machine == "RISC-V" else "0x0",
            "interpreter": "/lib64/ld-linux-x86-64.so.2" if dynamic else "",
            "needed": ["libc.so.6"] if dynamic else [], "runpath": [], "soname": "",
            "undefinedSymbols": ["puts"] if machine == "Advanced Micro Devices X86-64" else [],
            "relocationTypes": ["R_X86_64_PC32"] if kind == "REL" and machine.startswith("Advanced") else []}


def _flags(optimization, sanitizer, shared=False):
    result = ["-Wall", optimization]
    if sanitizer != "none": result.append("-fsanitize=" + {"asan": "address", "ubsan": "undefined"}[sanitizer])
    if shared: result.append("-fPIC")
    result.append("-Werror")
    return result


def _setup(root: Path, *, shared=False):
    root.mkdir(parents=True, exist_ok=True)
    source, target = root / "source.c", root / "target.c"
    source.write_text("int x;", encoding="utf-8")
    target.write_text("int main(void){return 0;}", encoding="utf-8")
    translation = _translation()
    kind = "shared_library" if shared else "executable"
    suffix = ".so" if shared else ".exe"
    targets = {}
    for compiler in ("gcc", "clang"):
        for opt in ("-O0", "-O2", "-O3"):
            for sanitizer in ("none", "asan", "ubsan"):
                ident = f"{compiler}-{opt[1:]}-{sanitizer}"
                targets[ident] = {
                    "artifactDigest": _digest_bytes(("linked:" + ident).encode()),
                    "objectDigest": _digest_bytes(("object:" + ident).encode()),
                    "artifactKind": kind, "compilerIdentity": compiler,
                    "compilerTriple": "x86_64-linux-gnu", "flags": _flags(opt, sanitizer, shared),
                    "runtimeLibraries": [],
                    "elf": _elf("Advanced Micro Devices X86-64", "DYN" if shared else "EXEC", dynamic=not shared),
                    "objectElf": _elf("Advanced Micro Devices X86-64", "REL"),
                }
    source_expected = {"artifactDigest": _digest_bytes(b"source-object"),
                       "objectDigest": _digest_bytes(b"source-object"), "artifactKind": "object",
                       "compilerIdentity": "riscv64-linux-gnu-gcc", "compilerTriple": "riscv64-linux-gnu",
                       "flags": ["-march=rv64gc", "-mabi=lp64d", "-Werror"], "runtimeLibraries": [],
                       "elf": _elf("RISC-V", "REL"), "objectElf": _elf("RISC-V", "REL")}
    manifest_data = {"schemaVersion": L0_ARTIFACT_MANIFEST_SCHEMA,
                     "translationIdentity": translation.identity, "planIdentity": "plan-1",
                     "proofIdentity": "proof-1", "runtimeContractId": "runtime-1",
                     "runtimeContractVersion": "v1", "recipeIdentity": "recipe-1",
                     "runtimeHeaders": ["stdint.h"], "includeDirectories": [],
                     "libraryDirectories": [], "libraries": [],
                     "source": source_expected, "targets": dict(sorted(targets.items()))}
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps(manifest_data, sort_keys=True), encoding="utf-8")
    source_out, target_out = root / "source.o", root / ("target" + suffix)
    matrix = L0BuildMatrix(str(source), "riscv64-linux-gnu-gcc", ("-march=rv64gc", "-mabi=lp64d"),
                           str(target), ("gcc", "clang"), ("-Wall",), ("-O0", "-O2", "-O3"),
                           ("none", "asan", "ubsan"), str(root / "build"), str(manifest), _digest(manifest),
                           runtime_headers=("stdint.h",), link_kind=kind)
    programs = (ProgramArtifact("source", str(source_out), "object", _digest_bytes(b"source-object")),
                ProgramArtifact("target", str(target_out), kind, _digest_bytes(b"linked:gcc-O0-none")))
    return matrix, translation, programs, manifest_data


def _readelf(argv):
    path, option = argv[-1], argv[1]
    source = path.endswith("source.o")
    obj = path.endswith(".o")
    machine = "RISC-V" if source else "Advanced Micro Devices X86-64"
    kind = "REL" if obj else "DYN" if path.endswith(".so") else "EXEC"
    if option == "-hW":
        flags = "0x5, RVC, double-float ABI" if source else "0x0"
        return CommandResult(0, f"Class: ELF64\nData: 2's complement, little endian\nType: {kind}\nMachine: {machine}\nOS/ABI: UNIX - System V\nABI Version: 0\nFlags: {flags}\n")
    if option == "-lW":
        return CommandResult(0, "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n" if not obj and not path.endswith(".so") else "")
    if option == "-dW":
        return CommandResult(0, "Shared library: [libc.so.6]\n" if not obj and not path.endswith(".so") else "")
    if option == "-sW":
        return CommandResult(0, "  1: 0 0 NOTYPE GLOBAL DEFAULT UND puts\n" if not source else "")
    return CommandResult(0, "R_X86_64_PC32\n" if obj and not source else "")


def _fake_runner(commands, *, fault=None):
    def run(argv, cwd, timeout):
        commands.append(tuple(argv))
        if argv[0] == "readelf":
            result = _readelf(argv)
            if fault == "abi" and argv[1] == "-hW" and not argv[-1].endswith("source.o"):
                return CommandResult(0, result.stdout.replace("ELF64", "ELF32"))
            if fault == "target-elf32-consistent" and argv[1] == "-hW" and not argv[-1].endswith("source.o"):
                return CommandResult(0, result.stdout.replace("ELF64", "ELF32"))
            if fault == "target-machine-riscv-consistent" and argv[1] == "-hW" and not argv[-1].endswith("source.o"):
                return CommandResult(0, result.stdout.replace(
                    "Advanced Micro Devices X86-64", "RISC-V",
                ))
            if fault == "source-soft-float" and argv[1] == "-hW" and argv[-1].endswith("source.o"):
                return CommandResult(0, result.stdout.replace(
                    "0x5, RVC, double-float ABI", "0x1, RVC, soft-float ABI",
                ))
            if fault == "dependency" and argv[1] == "-dW" and "libc.so.6" in result.stdout:
                return CommandResult(0, result.stdout.replace("libc.so.6", "libstale.so"))
            return result
        if len(argv) > 1 and argv[1] == "-dumpmachine":
            if fault == "target-triple-aarch64" and not argv[0].startswith("riscv64"):
                return CommandResult(0, "aarch64-linux-gnu\n")
            return CommandResult(0, "riscv64-linux-gnu\n" if argv[0].startswith("riscv64") else "x86_64-linux-gnu\n")
        if fault == "ubsan-unavailable" and "-fsanitize=undefined" in argv:
            return CommandResult(1, stderr="ld: cannot find -lubsan")
        warning = "warning: conversion changed value" if fault == "warning" and "-fsyntax-only" in argv else ""
        if "-o" in argv:
            output = Path(argv[argv.index("-o") + 1]); output.parent.mkdir(parents=True, exist_ok=True)
            if output.name == "source.o": content = b"source-object"
            elif output.suffix == ".o": content = ("object:" + output.stem).encode()
            elif output.name.startswith("dlopen-"): content = b"harness"
            else:
                obj = next((Path(x) for x in argv if str(x).endswith(".o")), None)
                content = ("linked:" + obj.stem).encode()
            output.write_bytes(content)
        if argv[0] == "env" or Path(argv[0]).name.startswith("dlopen-"):
            if fault == "timeout": return CommandResult(124, timed_out=True)
            if fault == "signal": return CommandResult(-11)
            if fault == "asan": return CommandResult(0, stderr="ERROR: AddressSanitizer: heap-buffer-overflow")
            if fault == "ubsan": return CommandResult(0, stderr="runtime error: signed integer overflow")
        return CommandResult(0, stderr=warning)
    return run


def _run(tmp_path, *, fault=None, shared=False, manifest_mutation=None,
         target_environment=None):
    matrix, translation, programs, manifest = _setup(tmp_path, shared=shared)
    if manifest_mutation:
        manifest_mutation(manifest)
        Path(matrix.translation_manifest_path).write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        matrix = L0BuildMatrix(**{**matrix.__dict__, "translation_manifest_digest": _digest(Path(matrix.translation_manifest_path))})
    commands = []
    result = run_l0_build_matrix(matrix, translation, *programs,
                                 target_environment=target_environment,
                                 command_runner=_fake_runner(commands, fault=fault), tool_available=lambda _: True)
    return result, commands


def test_all_18_cells_build_inspect_and_really_execute(tmp_path):
    result, commands = _run(tmp_path)
    assert result.status is ValidationStatus.VERIFIED
    assert len([x for x in commands if x and x[0] == "env"]) == 18
    assert len([x for x in commands if x and x[0] == "readelf" and x[1] == "-rW"]) == 37
    assert L0_ELF_ABI_POLICY_VERSION == "riscv2x86.l0-elf-abi-policy.v1"


def test_shared_library_uses_pic_and_dlopen_now_harness(tmp_path):
    result, commands = _run(tmp_path, shared=True)
    assert result.status is ValidationStatus.VERIFIED
    assert len([x for x in commands if x and Path(x[0]).name.startswith("dlopen-")]) == 18
    assert all("-fPIC" in x for x in commands if "-c" in x and not x[0].startswith("riscv64"))


@pytest.mark.parametrize("fault,expected", [
    ("asan", ValidationStatus.FAILED), ("ubsan", ValidationStatus.FAILED),
    ("timeout", ValidationStatus.FAILED),
    ("signal", ValidationStatus.FAILED), ("abi", ValidationStatus.FAILED),
    ("dependency", ValidationStatus.FAILED), ("warning", ValidationStatus.FAILED),
    ("ubsan-unavailable", ValidationStatus.INCONCLUSIVE),
])
def test_runtime_sanitizer_abi_and_tool_classification(tmp_path, fault, expected):
    result, _ = _run(tmp_path, fault=fault)
    assert result.status is expected


def test_manifest_requires_every_cell_digest_and_translation_identity(tmp_path):
    result, commands = _run(tmp_path, manifest_mutation=lambda m: m["targets"]["clang-O3-ubsan"].update(
        artifactDigest=_digest_bytes(b"stale")))
    assert result.status is ValidationStatus.FAILED
    assert "clang-O3-ubsan" in result.detail
    assert commands
    result, commands = _run(tmp_path / "second", manifest_mutation=lambda m: m.update(translationIdentity=_digest_bytes(b"wrong")))
    assert result.status is ValidationStatus.FAILED
    assert commands == []


def test_manifest_cannot_authorize_consistently_wrong_target_elf_class(tmp_path):
    def declare_elf32(manifest):
        for cell in manifest["targets"].values():
            cell["elf"]["class"] = "ELF32"
            cell["objectElf"]["class"] = "ELF32"

    result, _ = _run(
        tmp_path, fault="target-elf32-consistent",
        manifest_mutation=declare_elf32,
    )
    assert result.status is ValidationStatus.FAILED
    assert "ELF class must be ELF64" in result.detail


def test_manifest_cannot_authorize_consistently_wrong_target_machine(tmp_path):
    def declare_riscv_target(manifest):
        for cell in manifest["targets"].values():
            cell["elf"]["machine"] = "RISC-V"
            cell["objectElf"]["machine"] = "RISC-V"

    result, _ = _run(
        tmp_path, fault="target-machine-riscv-consistent",
        manifest_mutation=declare_riscv_target,
    )
    assert result.status is ValidationStatus.FAILED
    assert "target artifact must use the x86-64 ELF machine" in result.detail


def test_manifest_cannot_authorize_wrong_rv64_float_abi(tmp_path):
    def declare_soft_float(manifest):
        manifest["source"]["elf"]["abiFlags"] = "0x1, RVC, soft-float ABI"
        manifest["source"]["objectElf"]["abiFlags"] = "0x1, RVC, soft-float ABI"

    result, _ = _run(
        tmp_path, fault="source-soft-float",
        manifest_mutation=declare_soft_float,
    )
    assert result.status is ValidationStatus.FAILED
    assert "LP64D double-float ABI" in result.detail


def test_manifest_cannot_authorize_non_x86_64_compiler_triple(tmp_path):
    def declare_aarch64(manifest):
        for cell in manifest["targets"].values():
            cell["compilerTriple"] = "aarch64-linux-gnu"

    result, _ = _run(
        tmp_path, fault="target-triple-aarch64",
        manifest_mutation=declare_aarch64,
    )
    assert result.status is ValidationStatus.FAILED
    assert "target compiler triple is not x86-64" in result.detail


def test_environment_cannot_override_fixed_l0_isa_abi_policy(tmp_path):
    result, commands = _run(tmp_path, target_environment={
        "sourceIsa": "rv32gc", "sourceAbi": "ilp32d",
        "targetIsa": "x86_64", "targetAbi": "sysv_amd64",
    })
    assert result.status is ValidationStatus.FAILED
    assert "fixed RV64GC/LP64D to x86-64/SysV ABI policy" in result.detail
    assert commands == []


def test_loader_rejects_string_boolean_and_allows_omitted_optional_arrays():
    required = {"schemaVersion": L0_BUILD_MATRIX_SCHEMA, "sourcePath": "s.c", "sourceCompiler": "cc",
                "sourceFlags": [], "targetPath": "t.c", "targetCompilers": ["gcc", "clang"],
                "targetFlags": [], "optimizations": ["-O0", "-O2", "-O3"],
                "sanitizers": ["none", "asan", "ubsan"], "workDirectory": "build",
                "translationManifestPath": "manifest.json", "translationManifestDigest": _digest_bytes(b"m")}
    parsed = load_l0_build_matrix(required)
    assert parsed.runtime_headers == () and parsed.warnings_as_errors
    invalid = deepcopy(required); invalid["warningPolicy"] = {"warningsAsErrors": "false"}
    with pytest.raises(ValueError): load_l0_build_matrix(invalid)


def test_missing_required_tool_is_inconclusive_without_running_commands(tmp_path):
    matrix, translation, programs, _ = _setup(tmp_path)
    commands = []
    result = run_l0_build_matrix(matrix, translation, *programs,
                                 command_runner=_fake_runner(commands), tool_available=lambda name: name != "clang")
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert commands == []
