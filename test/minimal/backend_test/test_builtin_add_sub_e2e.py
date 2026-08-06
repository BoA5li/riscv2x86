#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
完整 RISC-V inline asm -> x86 replacement 翻译链路测试。

链路：

  C source
    -> C++ classifier --analysis-only
    -> raw_report.json
    -> Python backend
    -> translated_report.json
    -> C++ SourceRewriter --apply
    -> translated C source
    -> host C compiler
    -> runtime semantic test

执行示例：

  RISCV2X86_FRONTEND=./build/riscv2x86 \
  RISCV2X86_PYTHON=python3 \
  python3 tests/test_rv_add_sub_full_pipeline.py

如 Python package 不在默认 PYTHONPATH 中：

  PYTHONPATH=/path/to/backend \
  RISCV2X86_FRONTEND=./build/riscv2x86 \
  python3 tests/test_rv_add_sub_full_pipeline.py

如 Ghidra bridge 需要显式指定安装路径：

  GHIDRA_INSTALL_DIR=/opt/ghidra \
  RISCV2X86_FRONTEND=./build/riscv2x86 \
  python3 tests/test_rv_add_sub_full_pipeline.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


FRONTEND = os.environ.get("RISCV2X86_FRONTEND", "")
PYTHON = os.environ.get("RISCV2X86_PYTHON", sys.executable)
CC = os.environ.get("RISCV2X86_CC", "cc")

# Python 后端模块名；如项目实际包名不同，可通过环境变量覆盖。
BACKEND_MODULE = os.environ.get(
    "RISCV2X86_BACKEND_MODULE",
    "riscv2x86_py.cli",
)

GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "")
GHIDRA_LANGUAGE_ID = os.environ.get("GHIDRA_LANGUAGE_ID", "")


class TestFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise TestFailure(message)


def run(cmd: list[str], *, cwd: Path | None = None,
        expected_rc: int = 0) -> subprocess.CompletedProcess[str]:
    print("\n[cmd]")
    print(" ".join(cmd))

    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    print("\n[stdout]")
    print(result.stdout)

    print("\n[stderr]")
    print(result.stderr)

    if result.returncode != expected_rc:
        fail(
            f"command failed\n"
            f"return code: {result.returncode}\n"
            f"expected: {expected_rc}\n"
            f"command: {' '.join(cmd)}\n"
        )

    return result


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"cannot parse JSON file {path}: {type(exc).__name__}: {exc}")


def get_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings")
    assert_true(isinstance(findings, list), "report has no findings array")
    return findings


def find_add_sub_finding(report: dict[str, Any]) -> dict[str, Any]:
    for finding in get_findings(report):
        fragment = finding.get("fragment") or {}
        asm_text = (
            fragment.get("asmText")
            or fragment.get("rawAsmText")
            or ""
        )

        if (
            "add %0, %1, %2" in asm_text
            and "sub %0, %0, %2" in asm_text
        ):
            return finding

    fail("cannot find expected RISC-V add/sub asm finding")


def assert_range_matches_raw_source(
    source_file: Path,
    finding: dict[str, Any],
    *,
    stage_name: str,
) -> None:
    begin = finding.get("rewriteBeginOffset")
    end = finding.get("rewriteEndOffset")
    raw_source_text = finding.get("rawSourceText")

    assert_true(
        isinstance(begin, int) and isinstance(end, int),
        f"{stage_name}: rewrite range is missing or invalid",
    )

    assert_true(
        isinstance(raw_source_text, str) and raw_source_text != "",
        f"{stage_name}: rawSourceText is missing",
    )

    source_bytes = source_file.read_bytes()

    assert_true(
        0 <= begin <= end <= len(source_bytes),
        f"{stage_name}: rewrite range [{begin}, {end}) "
        f"is outside source file size {len(source_bytes)}",
    )

    actual = source_bytes[begin:end].decode("utf-8")

    assert_true(
        actual == raw_source_text,
        f"{stage_name}: rewrite range does not match rawSourceText\n"
        f"range: [{begin}, {end})\n"
        f"expected:\n{raw_source_text}\n"
        f"actual:\n{actual}\n",
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def main() -> int:
    if not FRONTEND:
        print(
            "error: RISCV2X86_FRONTEND is not set.\n"
            "example:\n"
            "  RISCV2X86_FRONTEND=./build/riscv2x86 "
            "python3 tests/test_rv_add_sub_full_pipeline.py",
            file=sys.stderr,
        )
        return 2

    if not Path(FRONTEND).exists():
        print(
            f"error: frontend binary does not exist: {FRONTEND}",
            file=sys.stderr,
        )
        return 2

    if shutil.which(PYTHON) is None and not Path(PYTHON).exists():
        print(
            f"error: Python executable not found: {PYTHON}",
            file=sys.stderr,
        )
        return 2

    if shutil.which(CC) is None:
        print(
            f"error: host C compiler not found: {CC}",
            file=sys.stderr,
        )
        return 2

    root = Path(tempfile.mkdtemp(prefix="riscv2x86-full-pipeline-"))

    input_root = root / "input"
    output_root = root / "output"

    source_file = input_root / "rv_add_sub.c"
    raw_report = root / "raw_report.json"
    translated_report = root / "translated_report.json"

    try:
        # --------------------------------------------------------------
        # 输入程序。
        #
        # RISC-V 语义：
        #
        #   result = a + b
        #   result = result - b
        #
        # 所以：
        #
        #   result == a
        # --------------------------------------------------------------
        source = """\
typedef long long i64;

i64 rv_add_sub(i64 a, i64 b) {
    i64 result;

    __asm__(
        "add %0, %1, %2\\n\\t"
        "sub %0, %0, %2"
        : "=r"(result)
        : "r"(a), "r"(b)
    );

    return result;
}
"""

        write_text(source_file, source)

        # --------------------------------------------------------------
        # Phase 1:
        # C++ frontend analysis-only。
        #
        # 此阶段的预期结果是 NeedsAsmTranslation。
        # 不要求 C++ RuleEngine builtin rule 命中。
        # --------------------------------------------------------------
        run([
            FRONTEND,
            "--analysis-only",
            "-o", str(root / "dummy_out"),
            "--src-root", str(input_root),
            "--report-json", str(raw_report),
            str(source_file),
            "--",
            "-std=gnu11",
        ])

        assert_true(
            raw_report.exists(),
            "frontend analysis-only did not produce raw_report.json",
        )

        raw = load_json(raw_report)
        raw_finding = find_add_sub_finding(raw)

        assert_true(
            raw_finding.get("category") == "NeedsAsmTranslation",
            "frontend raw report must keep add/sub finding as "
            "NeedsAsmTranslation before Python backend translation",
        )

        assert_true(
            raw_finding.get("suggestedReplacement", "") == "",
            "frontend raw report unexpectedly already has replacement",
        )

        assert_range_matches_raw_source(
            source_file,
            raw_finding,
            stage_name="raw frontend report",
        )

        # --------------------------------------------------------------
        # Phase 2:
        # Python backend:
        #
        # JSON -> assemble -> lift -> structured p-code IR -> CFG
        #      -> translate -> verify -> translated_report.json
        # --------------------------------------------------------------
        backend_cmd = [
            PYTHON,
            "-m",
            BACKEND_MODULE,
            "--in", str(raw_report),
            "--out", str(translated_report),
            "--xlen", "64",
        ]
        """
        if GHIDRA_INSTALL_DIR:
            backend_cmd.extend([
                "--ghidra-install-dir",
                GHIDRA_INSTALL_DIR,
            ])

        if GHIDRA_LANGUAGE_ID:
            backend_cmd.extend([
                "--ghidra-language-id",
                GHIDRA_LANGUAGE_ID,
            ])
        """

        run(backend_cmd)

        assert_true(
            translated_report.exists(),
            "Python backend did not produce translated_report.json",
        )

        translated = load_json(translated_report)
        translated_finding = find_add_sub_finding(translated)

        # 后端不应破坏前端定位信息。
        assert_range_matches_raw_source(
            source_file,
            translated_finding,
            stage_name="translated backend report",
        )

        # 后端应生成可应用 replacement。
        assert_true(
            translated_finding.get("category") == "ReplaceableByRule",
            "Python backend did not produce ReplaceableByRule result.\n"
            f"actual category: {translated_finding.get('category')}\n"
            f"ruleName: {translated_finding.get('ruleName')}\n"
            f"verificationStatus: "
            f"{translated_finding.get('verificationStatus')}\n"
            f"verificationDetail: "
            f"{translated_finding.get('verificationDetail')}\n"
            f"notes: {translated_finding.get('notes')}\n",
        )

        rule_name = translated_finding.get("ruleName") or ""
        replacement = translated_finding.get("suggestedReplacement") or ""
        verification_status = (
            translated_finding.get("verificationStatus") or ""
        )

        assert_true(
            rule_name in {
                "phase6.lower_to_x86_inline_asm",
                "phase6.lower_to_c",
            },
            "unexpected translation ruleName.\n"
            f"actual ruleName: {rule_name}\n"
            "expected phase6.lower_to_x86_inline_asm or phase6.lower_to_c",
        )

        assert_true(
            replacement.strip() != "",
            "translated report has empty suggestedReplacement",
        )

        assert_true(
            verification_status in {"verified", "build_only"},
            "translation did not reach an accepted verification state.\n"
            f"verificationStatus: {verification_status}\n"
            f"verificationDetail: "
            f"{translated_finding.get('verificationDetail')}",
        )

        print("\n[translation result]")
        print(f"ruleName: {rule_name}")
        print(f"verificationStatus: {verification_status}")
        print("replacement:")
        print(replacement)

        # --------------------------------------------------------------
        # Phase 3:
        # C++ frontend SourceRewriter --apply。
        #
        # 这一步验证：
        #
        # translated_report.json -> loadReportJSON -> SourceRewriter
        # --------------------------------------------------------------
        run([
            FRONTEND,
            "--src-root", str(input_root),
            "-o", str(output_root),
            "--apply",
            "--report", str(translated_report),
        ])

        rewritten_file = output_root / "rv_add_sub.c"

        assert_true(
            rewritten_file.exists(),
            "SourceRewriter did not produce output/rv_add_sub.c",
        )

        rewritten = rewritten_file.read_text(encoding="utf-8")

        assert_true(
            "add %0, %1, %2" not in rewritten,
            "rewritten output still contains original RISC-V add instruction",
        )

        assert_true(
            "sub %0, %0, %2" not in rewritten,
            "rewritten output still contains original RISC-V sub instruction",
        )

        assert_true(
            replacement in rewritten,
            "rewritten source does not contain backend replacement",
        )

        # --------------------------------------------------------------
        # Phase 4:
        # 编译检查。
        #
        # 如果 Python backend 输出 x86 GNU inline asm，
        # 此处使用宿主 x86 compiler 编译。
        # --------------------------------------------------------------
        run([
            CC,
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            str(rewritten_file),
        ])

        # --------------------------------------------------------------
        # Phase 5:
        # 运行时语义检查。
        #
        # 原 RISC-V asm 的数学语义：
        #
        #   rv_add_sub(a, b) == a
        # --------------------------------------------------------------
        driver_file = root / "driver.c"
        executable = root / "rv_add_sub_runtime_test"

        driver = """\
#include <stdio.h>

typedef long long i64;

i64 rv_add_sub(i64 a, i64 b);

static int check(i64 a, i64 b) {
    i64 actual = rv_add_sub(a, b);
    i64 expected = a;

    if (actual != expected) {
        fprintf(
            stderr,
            "FAIL: rv_add_sub(%lld, %lld) = %lld, expected %lld\\n",
            a,
            b,
            actual,
            expected
        );
        return 1;
    }

    return 0;
}

int main(void) {
    if (check(0, 0)) return 1;
    if (check(1, 0)) return 1;
    if (check(0, 1)) return 1;
    if (check(1, 2)) return 1;
    if (check(7, 11)) return 1;
    if (check(-1, 1)) return 1;
    if (check(-7, 11)) return 1;
    if (check(1234567, -765432)) return 1;

    puts("PASS: full RISC-V -> x86 translation pipeline");
    return 0;
}
"""

        write_text(driver_file, driver)

        run([
            CC,
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(rewritten_file),
            str(driver_file),
            "-o",
            str(executable),
        ])

        runtime_result = run([str(executable)])

        assert_true(
            "PASS: full RISC-V -> x86 translation pipeline"
            in runtime_result.stdout,
            "runtime semantic test did not report PASS",
        )

        print("\nPASS: full frontend -> backend -> apply -> compile -> runtime pipeline")
        print(f"test directory: {root}")
        return 0

    except TestFailure as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        print(
            f"test directory retained for debugging: {root}",
            file=sys.stderr,
        )
        return 1

    except Exception as exc:
        print(
            f"\nUNEXPECTED ERROR: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(
            f"test directory retained for debugging: {root}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())