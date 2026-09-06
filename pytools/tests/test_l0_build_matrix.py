from hashlib import sha256
from pathlib import Path

from riscv2x86_py.l0_build_matrix import (
    CommandResult, L0BuildMatrix, run_l0_build_matrix,
)
from riscv2x86_py.translation_validation import ProgramArtifact
from riscv2x86_py.validation_status import ValidationStatus


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _matrix(root: Path, manifest: Path) -> L0BuildMatrix:
    return L0BuildMatrix(
        source_path=str(root / "source.c"), source_compiler="gcc", source_flags=("--target=riscv64",),
        target_path=str(root / "target.c"), target_compilers=("gcc", "clang"),
        target_flags=("-Wall",), optimizations=("-O0", "-O2", "-O3"),
        sanitizers=("none", "asan", "ubsan"), work_directory=str(root / "build"),
        translation_manifest_path=str(manifest), translation_manifest_digest=_digest(manifest),
        runtime_headers=("stdint.h",), link_kind="executable",
    )


def test_l0_build_matrix_runs_source_and_complete_target_matrix(tmp_path: Path) -> None:
    source, target, manifest = tmp_path / "source.c", tmp_path / "target.c", tmp_path / "manifest.json"
    source.write_text("int x;", encoding="utf-8")
    target.write_text("int main(void) { return 0; }", encoding="utf-8")
    manifest.write_text("{}", encoding="utf-8")
    source_out, target_out = tmp_path / "source.o", tmp_path / "target.exe"
    source_out.write_bytes(b"source-object")
    target_out.write_bytes(b"target-executable")
    commands: list[tuple[str, ...]] = []

    def fake(argv: tuple[str, ...], cwd: Path) -> CommandResult:
        commands.append(argv)
        if argv[0] == "readelf":
            return CommandResult(0, "ELF64 Machine: RISC-V" if argv[-1].endswith("source.o") else "ELF64 Machine: X86-64")
        if argv[0] == "ldd":
            return CommandResult(0, "linux-vdso.so.1")
        if "-o" in argv:
            output = Path(argv[argv.index("-o") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            if output == source_out:
                output.write_bytes(b"source-object")
            elif output == target_out:
                output.write_bytes(b"target-executable")
            else:
                output.write_bytes(b"matrix-output")
        return CommandResult(0)

    result = run_l0_build_matrix(
        _matrix(tmp_path, manifest),
        ProgramArtifact("source", str(source_out), "object", _digest(source_out)),
        ProgramArtifact("target", str(target_out), "executable", _digest(target_out)),
        command_runner=fake, tool_available=lambda _name: True,
    )
    assert result.status is ValidationStatus.VERIFIED
    assert len([c for c in commands if "-fsyntax-only" in c]) == 36  # source + header probe per 18 cells
    assert "gcc-O0-none" in result.detail
    assert result.evidence_identity.startswith("sha256:")


def test_l0_manifest_hash_mismatch_fails_before_build(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    matrix = _matrix(tmp_path, manifest)
    object_path, output_path = tmp_path / "a.o", tmp_path / "a.exe"
    object_path.write_bytes(b"a")
    output_path.write_bytes(b"b")
    matrix = L0BuildMatrix(**{**matrix.__dict__, "translation_manifest_digest": "sha256:wrong"})
    result = run_l0_build_matrix(
        matrix, ProgramArtifact("s", str(object_path), "object", _digest(object_path)),
        ProgramArtifact("t", str(output_path), "executable", _digest(output_path)),
    )
    assert result.status is ValidationStatus.FAILED
    assert "translation manifest hash mismatch" in result.detail
