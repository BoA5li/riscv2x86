import shutil
import subprocess
from pathlib import Path

import pytest


CLANG = shutil.which("clang")
LLVM_READOBJ = shutil.which("llvm-readobj")
LLVM_DWARFDUMP = shutil.which("llvm-dwarfdump")


pytestmark = pytest.mark.skipif(
    CLANG is None,
    reason="clang is not installed",
)


def run(command, *, cwd):
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )


def test_simple_c_program_builds_and_runs(tmp_path):
    source = tmp_path / "add.c"
    executable = tmp_path / "add"

    source.write_text(
        """
        #include <stdint.h>

        static int64_t translated_add(
            int64_t a,
            int64_t b
        ) {
            return a + b;
        }

        int main(void) {
            return translated_add(20, 22) == 42
                ? 0
                : 1;
        }
        """,
        encoding="utf-8",
    )

    build = run(
        [
            CLANG,
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(executable),
        ],
        cwd=tmp_path,
    )

    assert build.returncode == 0, build.stderr

    execution = run(
        [str(executable)],
        cwd=tmp_path,
    )

    assert execution.returncode == 0


def test_invalid_inline_asm_fails_build(tmp_path):
    source = tmp_path / "invalid_asm.c"
    obj = tmp_path / "invalid_asm.o"

    source.write_text(
        """
        void translated(void) {
            __asm__ volatile(
                "this_is_not_a_real_instruction"
            );
        }
        """,
        encoding="utf-8",
    )

    build = run(
        [
            CLANG,
            "-c",
            str(source),
            "-o",
            str(obj),
        ],
        cwd=tmp_path,
    )

    assert build.returncode != 0


def test_standalone_assembly_builds_and_links(tmp_path):
    source = tmp_path / "translated.S"
    harness = tmp_path / "main.c"
    asm_obj = tmp_path / "translated.o"
    main_obj = tmp_path / "main.o"
    executable = tmp_path / "program"

    source.write_text(
        """
        .text
        .globl translated_add
        .type translated_add, @function
        translated_add:
            .cfi_startproc
            lea (%rdi,%rsi), %rax
            ret
            .cfi_endproc
        .size translated_add, .-translated_add
        """,
        encoding="utf-8",
    )

    harness.write_text(
        """
        long translated_add(long, long);

        int main(void) {
            return translated_add(20, 22) == 42
                ? 0
                : 1;
        }
        """,
        encoding="utf-8",
    )

    for command in [
        [
            CLANG,
            "-c",
            str(source),
            "-o",
            str(asm_obj),
        ],
        [
            CLANG,
            "-c",
            str(harness),
            "-o",
            str(main_obj),
        ],
        [
            CLANG,
            str(asm_obj),
            str(main_obj),
            "-o",
            str(executable),
        ],
    ]:
        result = run(command, cwd=tmp_path)
        assert result.returncode == 0, result.stderr

    execution = run(
        [str(executable)],
        cwd=tmp_path,
    )

    assert execution.returncode == 0


@pytest.mark.skipif(
    LLVM_DWARFDUMP is None,
    reason="llvm-dwarfdump is not installed",
)
def test_assembly_contains_eh_frame(tmp_path):
    source = tmp_path / "translated.S"
    obj = tmp_path / "translated.o"

    source.write_text(
        """
        .text
        .globl translated
        .type translated, @function
        translated:
            .cfi_startproc
            push %rbp
            .cfi_def_cfa_offset 16
            .cfi_offset %rbp, -16
            mov %rsp, %rbp
            .cfi_def_cfa_register %rbp
            pop %rbp
            .cfi_def_cfa %rsp, 8
            ret
            .cfi_endproc
        .size translated, .-translated
        """,
        encoding="utf-8",
    )

    build = run(
        [
            CLANG,
            "-c",
            "-g",
            str(source),
            "-o",
            str(obj),
        ],
        cwd=tmp_path,
    )

    assert build.returncode == 0, build.stderr

    dump = run(
        [
            LLVM_DWARFDUMP,
            "--eh-frame",
            str(obj),
        ],
        cwd=tmp_path,
    )

    assert dump.returncode == 0, dump.stderr
    assert "translated" in dump.stdout or "FDE" in dump.stdout


@pytest.mark.skipif(
    LLVM_READOBJ is None,
    reason="llvm-readobj is not installed",
)
def test_pic_object_relocations_can_be_inspected(tmp_path):
    source = tmp_path / "pic.c"
    obj = tmp_path / "pic.o"

    source.write_text(
        """
        extern int external_value;

        int translated(void) {
            return external_value;
        }
        """,
        encoding="utf-8",
    )

    build = run(
        [
            CLANG,
            "-fPIC",
            "-c",
            str(source),
            "-o",
            str(obj),
        ],
        cwd=tmp_path,
    )

    assert build.returncode == 0, build.stderr

    inspect_result = run(
        [
            LLVM_READOBJ,
            "--relocations",
            str(obj),
        ],
        cwd=tmp_path,
    )

    assert inspect_result.returncode == 0
    assert "Relocations" in inspect_result.stdout