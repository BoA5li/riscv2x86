#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
riscv2x86 writeback / end-to-end integration tests.

Usage:
  RISCV2X86_BIN=/path/to/riscv2x86 python3 tests/test_writeback.py

Optional:
  python3 tests/test_writeback.py --strict-safety

Default mode:
  - Core writeback and report-driven full-chain tests must PASS.
  - Known current safety gaps are marked XFAIL:
      * stale-source report replay is not rejected
      * macro-expanded findings are not skipped

--strict-safety:
  - XFAIL cases become mandatory PASS cases.
  - Use after implementing rawSourceText validation and macro protection.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional


BIN = os.environ.get("RISCV2X86_BIN", "")


class TestFailure(Exception):
    pass


@dataclass
class TestResult:
    name: str
    status: str
    detail: str = ""


def fail(msg: str):
    raise TestFailure(msg)


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def assert_true(cond: bool, msg: str):
    if not cond:
        fail(msg)


def assert_contains(text: str, expected: str, msg: str = ""):
    if expected not in text:
        fail(msg or f"expected substring not found:\n{expected}\n--- actual ---\n{text}")


def assert_not_contains(text: str, unexpected: str, msg: str = ""):
    if unexpected in text:
        fail(msg or f"unexpected substring found:\n{unexpected}\n--- actual ---\n{text}")


def run(cmd: List[str], cwd: Optional[Path] = None, expect_rc: Optional[int] = 0):
    print("[cmd]", " ".join(str(x) for x in cmd))
    p = subprocess.run(
        [str(x) for x in cmd],
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    print("[stdout]")
    print(p.stdout)
    print("[stderr]")
    print(p.stderr)

    if expect_rc is not None and p.returncode != expect_rc:
        fail(
            f"command returned {p.returncode}, expected {expect_rc}\n"
            f"command: {' '.join(str(x) for x in cmd)}\n"
            f"stdout:\n{p.stdout}\n"
            f"stderr:\n{p.stderr}"
        )

    return p


def make_finding(
    source_file: Path,
    source_text: str,
    raw: str,
    replacement: str,
    *,
    category: str = "ReplaceableByRule",
    rule_name: str = "phase6.lower_to_c.test",
    from_macro_expansion: bool = False,
    begin_override: Optional[int] = None,
    end_override: Optional[int] = None,
) -> Dict:
    """
    以 byte offset 构造 finding。
    测试源文件保持 ASCII，以避免 Python 字符下标与 Clang byte offset 差异。
    """
    src_bytes = source_text.encode("utf-8")
    raw_bytes = raw.encode("utf-8")

    begin = src_bytes.find(raw_bytes)
    if begin < 0:
        fail(f"cannot locate raw text in source:\n{raw}")

    end = begin + len(raw_bytes)

    if begin_override is not None:
        begin = begin_override
    if end_override is not None:
        end = end_override

    return {
        "category": category,
        "file": str(source_file),
        "fileName": str(source_file),
        "line": 1,
        "column": 1,
        "description": "test finding",
        "rule": rule_name,
        "ruleName": rule_name,
        "replacement": replacement,
        "suggestedReplacement": replacement,
        "subjectKind": "AsmFragment",
        "symbolName": "",
        "hasRewriteRange": True,
        "rewriteBeginOffset": begin,
        "rewriteEndOffset": end,
        "rawSourceText": raw,
        "fromMacroExpansion": from_macro_expansion,
        "macroName": "TEST_MACRO" if from_macro_expansion else "",
        "arguments": [],
    }


def write_report(path: Path, findings: List[Dict]):
    path.write_text(
        json.dumps({"findings": findings}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def apply_report(src_root: Path, out_root: Path, report: Path):
    return run([
        BIN,
        "--src-root", str(src_root),
        "-o", str(out_root),
        "--apply",
        "--report", str(report),
    ])


def output_file(src_root: Path, out_root: Path, source_file: Path) -> Path:
    return out_root / source_file.relative_to(src_root)


def prepare_case(root: Path, name: str):
    case = root / name
    src = case / "src"
    out = case / "out"
    report = case / "report.json"

    src.mkdir(parents=True, exist_ok=True)
    return case, src, out, report


# ---------------------------------------------------------------------------
# 1. deterministic writeback tests
# ---------------------------------------------------------------------------

def test_single_rewrite(root: Path):
    _, src, out, report = prepare_case(root, "single_rewrite")

    source_file = src / "main.c"
    source = (
        "#include <stdio.h>\n"
        "\n"
        "void test(void) {\n"
        "    unsigned long x;\n"
        "    asm volatile(\"rdcycle %0\" : \"=r\"(x));\n"
        "    printf(\"%lu\\n\", x);\n"
        "}\n"
    )
    raw = 'asm volatile("rdcycle %0" : "=r"(x));'
    replacement = "x = read_cycle_counter();"

    write_text(source_file, source)
    write_report(report, [make_finding(source_file, source, raw, replacement)])

    p = apply_report(src, out, report)
    result = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(p.stdout, "applied 1 rewrites", "single rewrite count must be 1")
    assert_not_contains(result, raw, "original asm must be removed")
    assert_contains(result, replacement, "replacement must be present")
    assert_contains(
        result,
        "lowered from RISC-V asm to C",
        "phase6 replacement annotation must be present",
    )


def test_multiple_non_overlapping_rewrites(root: Path):
    _, src, out, report = prepare_case(root, "multiple_non_overlapping")

    source_file = src / "main.c"
    source = (
        "void test(void) {\n"
        "    unsigned long a;\n"
        "    unsigned long b;\n"
        "    asm volatile(\"rdcycle %0\" : \"=r\"(a));\n"
        "    asm volatile(\"rdtime %0\" : \"=r\"(b));\n"
        "}\n"
    )

    raw1 = 'asm volatile("rdcycle %0" : "=r"(a));'
    raw2 = 'asm volatile("rdtime %0" : "=r"(b));'

    repl1 = "a = read_cycle_counter();"
    repl2 = "b = read_time_counter();"

    write_text(source_file, source)
    write_report(report, [
        make_finding(source_file, source, raw1, repl1),
        make_finding(source_file, source, raw2, repl2),
    ])

    p = apply_report(src, out, report)
    result = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(p.stdout, "applied 2 rewrites", "two rewrites must be applied")
    assert_not_contains(result, raw1)
    assert_not_contains(result, raw2)
    assert_contains(result, repl1)
    assert_contains(result, repl2)


def test_multi_file_rewrite(root: Path):
    _, src, out, report = prepare_case(root, "multi_file")

    file_a = src / "a.c"
    file_b = src / "subdir" / "b.c"

    source_a = (
        "void a(void) {\n"
        "    asm volatile(\"nop\");\n"
        "}\n"
    )
    source_b = (
        "void b(void) {\n"
        "    asm volatile(\"fence\");\n"
        "}\n"
    )

    raw_a = 'asm volatile("nop");'
    raw_b = 'asm volatile("fence");'

    repl_a = "compiler_barrier();"
    repl_b = "memory_fence();"

    write_text(file_a, source_a)
    write_text(file_b, source_b)

    write_report(report, [
        make_finding(file_a, source_a, raw_a, repl_a),
        make_finding(file_b, source_b, raw_b, repl_b),
    ])

    p = apply_report(src, out, report)

    result_a = output_file(src, out, file_a).read_text(encoding="utf-8")
    result_b = output_file(src, out, file_b).read_text(encoding="utf-8")

    assert_contains(p.stdout, "applied 2 rewrites")
    assert_contains(result_a, repl_a)
    assert_contains(result_b, repl_b)
    assert_true((out / "subdir" / "b.c").exists(), "nested directory must be copied")


def test_overlapping_edits_rejected(root: Path):
    _, src, out, report = prepare_case(root, "overlap")

    source_file = src / "main.c"
    source = (
        "void test(void) {\n"
        "    asm volatile(\"nop\");\n"
        "}\n"
    )
    raw = 'asm volatile("nop");'

    write_text(source_file, source)

    original = source.encode("utf-8")
    begin = original.find(raw.encode("utf-8"))
    end = begin + len(raw.encode("utf-8"))

    f1 = make_finding(
        source_file, source, raw, "first_replacement();",
        begin_override=begin,
        end_override=end,
    )

    # 人工制造重叠区间：[begin+3, end)
    f2 = make_finding(
        source_file, source, raw, "second_replacement();",
        begin_override=begin + 3,
        end_override=end,
    )

    write_report(report, [f1, f2])

    p = apply_report(src, out, report)
    result = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(p.stderr, "overlapping edits", "overlapping edits must be diagnosed")
    assert_contains(result, raw, "overlap case must not modify file")
    assert_not_contains(result, "first_replacement();")
    assert_not_contains(result, "second_replacement();")


def test_out_of_range_edit_rejected(root: Path):
    _, src, out, report = prepare_case(root, "out_of_range")

    source_file = src / "main.c"
    source = "void test(void) { asm volatile(\"nop\"); }\n"
    raw = 'asm volatile("nop");'

    write_text(source_file, source)

    bad = make_finding(
        source_file,
        source,
        raw,
        "should_not_appear();",
        begin_override=100000,
        end_override=100100,
    )
    write_report(report, [bad])

    p = apply_report(src, out, report)
    result = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(p.stderr, "offset out of range", "out-of-range edit must be diagnosed")
    assert_contains(result, raw, "source must remain unchanged")
    assert_not_contains(result, "should_not_appear();")


def test_stdint_include_insertion(root: Path):
    _, src, out, report = prepare_case(root, "stdint_include")

    source_file = src / "main.c"
    source = (
        "#include <stdio.h>\n"
        "\n"
        "void test(void) {\n"
        "    asm volatile(\"nop\");\n"
        "}\n"
    )

    raw = 'asm volatile("nop");'
    replacement = "uint64_t x = 0;"

    write_text(source_file, source)
    write_report(report, [
        make_finding(source_file, source, raw, replacement)
    ])

    apply_report(src, out, report)
    result = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(result, "#include <stdint.h>", "stdint include must be inserted")
    assert_true(
        result.index("#include <stdio.h>") < result.index("#include <stdint.h>"),
        "stdint include should be after existing include block",
    )
    assert_contains(result, replacement)


# ---------------------------------------------------------------------------
# 2. safety tests: currently expected to fail before code improvements
# ---------------------------------------------------------------------------

def test_stale_report_must_not_modify_changed_source(root: Path):
    """
    正确行为：
      生成 report 后源文件发生变化，旧 offset 不应继续被盲目使用。
      应报告 source text mismatch，并拒绝修改该文件。

    当前给出的 Rewriter.cpp 没有比较 rawSourceText，
    因而此测试在当前实现中预期失败（XFAIL）。
    """
    _, src, out, report = prepare_case(root, "stale_source")

    source_file = src / "main.c"
    original_source = (
        "void test(void) {\n"
        "    asm volatile(\"nop\");\n"
        "}\n"
    )
    raw = 'asm volatile("nop");'
    replacement = "replacement_should_not_be_written();"

    write_text(source_file, original_source)
    write_report(report, [
        make_finding(source_file, original_source, raw, replacement)
    ])

    # 报告生成后，输入源文件发生变化，所有后续 offset 均偏移。
    changed_source = (
        "/* source changed after report generation */\n"
        + original_source
    )
    write_text(source_file, changed_source)

    p = apply_report(src, out, report)
    result = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(
        p.stderr,
        "source text mismatch",
        "stale report must be rejected by rawSourceText validation",
    )
    assert_contains(
        result,
        raw,
        "changed source must remain unmodified when report is stale",
    )
    assert_not_contains(result, replacement)


def test_macro_expansion_must_be_skipped(root: Path):
    """
    正确行为：
      fromMacroExpansion == true 的 finding 应默认跳过，
      除非已明确支持 spelling-location 级别的宏定义改写。

    当前给出的 Rewriter.cpp 不检查 fromMacroExpansion，
    因而此测试在当前实现中预期失败（XFAIL）。
    """
    _, src, out, report = prepare_case(root, "macro_expansion")

    source_file = src / "main.c"
    source = (
        "#define READ_NOP() asm volatile(\"nop\")\n"
        "\n"
        "void test(void) {\n"
        "    READ_NOP();\n"
        "}\n"
    )

    raw = "READ_NOP();"
    replacement = "replacement_should_not_be_written();"

    write_text(source_file, source)
    write_report(report, [
        make_finding(
            source_file,
            source,
            raw,
            replacement,
            from_macro_expansion=True,
        )
    ])

    p = apply_report(src, out, report)
    result = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(
        p.stderr,
        "skip macro-expanded finding",
        "macro-expanded finding must be explicitly skipped",
    )
    assert_contains(result, raw, "macro invocation must remain unchanged")
    assert_not_contains(result, replacement)


# ---------------------------------------------------------------------------
# 3. analysis -> report -> simulated translation -> apply
# ---------------------------------------------------------------------------

def find_rewritable_finding(report_obj: Dict, source_path: Path, source_bytes: bytes) -> Dict:
    """
    从 --analysis-only 的报告中选择一个带有效 rewrite range 的 finding。

    注意：
    这里不要求该 finding 当前被分类为 ReplaceableByRule；
    测试目标是验证：
        AST analysis -> report range -> translation result -> apply
    所以脚本会模拟 translator 将 category/rule/replacement 填入。
    """
    source_path_str = str(source_path)

    for f in report_obj.get("findings", []):
        file_name = f.get("fileName") or f.get("file") or ""

        # 报告路径可能是绝对路径，也可能是相对路径。
        same_file = False
        try:
            same_file = Path(file_name).resolve() == source_path.resolve()
        except Exception:
            same_file = (file_name == source_path_str)

        if not same_file:
            continue

        begin = f.get("rewriteBeginOffset", 0)
        end = f.get("rewriteEndOffset", 0)

        if not f.get("hasRewriteRange", False):
            continue

        if not isinstance(begin, int) or not isinstance(end, int):
            continue

        if begin < 0 or end <= begin or end > len(source_bytes):
            continue

        return f

    fail(
        "analysis report contains no finding with a valid rewrite range for "
        f"{source_path}"
    )


def test_analysis_translate_apply_chain(root: Path):
    """
    全流程但不做语义 verify：

      输入源文件
        -> --analysis-only
        -> 读取 report.json
        -> 模拟外部 translator 填入 replacement
        -> --apply
        -> 验证 replacement 出现在输出副本中

    该测试依赖 Classifier 能识别 GNU inline asm。
    """
    case, src, out, report = prepare_case(root, "analysis_translate_apply")

    source_file = src / "main.c"
    source = (
        "void test(void) {\n"
        "    asm volatile(\"nop\");\n"
        "}\n"
    )
    write_text(source_file, source)

    # Step 1: 真实执行 AST 分析，生成 report。
    p1 = run([
        BIN,
        "--src-root", str(src),
        "-o", str(out),
        "--analysis-only",
        "--report-json", str(report),
        str(source_file),
        "--",
        "-std=gnu11",
    ])

    assert_true(report.exists(), "analysis-only must generate report.json")

    report_obj = json.loads(report.read_text(encoding="utf-8"))
    assert_true(
        len(report_obj.get("findings", [])) > 0,
        "analysis report must contain at least one finding",
    )

    # Step 2: 验证 classifier 产生的 byte range 确实指向 source 中的原文。
    source_bytes = read_bytes(source_file)
    finding = find_rewritable_finding(report_obj, source_file, source_bytes)

    begin = finding["rewriteBeginOffset"]
    end = finding["rewriteEndOffset"]
    actual_raw = source_bytes[begin:end].decode("utf-8")

    reported_raw = finding.get("rawSourceText", "")
    if reported_raw:
        assert_true(
            actual_raw == reported_raw,
            "classifier range/rawSourceText mismatch:\n"
            f"range=[{begin},{end})\n"
            f"reported raw={reported_raw!r}\n"
            f"actual raw={actual_raw!r}",
        )

    # Step 3: 模拟 translate 阶段。
    #
    # 为避免依赖特定内建 rule，此处由测试脚本模拟外部 translator：
    # 将该 finding 变成可写回 replacement。
    replacement = "/* translated by integration test */ compiler_barrier();"

    finding["category"] = "ReplaceableByRule"
    finding["rule"] = "phase6.lower_to_c.integration_test"
    finding["ruleName"] = "phase6.lower_to_c.integration_test"
    finding["replacement"] = replacement
    finding["suggestedReplacement"] = replacement
    finding["hasRewriteRange"] = True

    # 以实际 range 文本回填 rawSourceText，避免报告生成端差异影响本测试。
    finding["rawSourceText"] = actual_raw

    translated_report = case / "translated_report.json"
    translated_report.write_text(
        json.dumps(report_obj, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Step 4: 通过 --apply 走 ReportLoad + SourceRewriter。
    p2 = apply_report(src, out, translated_report)

    rewritten = output_file(src, out, source_file).read_text(encoding="utf-8")

    assert_contains(p2.stdout, "applied 1 rewrites")
    assert_contains(rewritten, replacement)
    assert_not_contains(
        rewritten,
        actual_raw,
        "original finding source text must be replaced",
    )


# ---------------------------------------------------------------------------
# test runner
# ---------------------------------------------------------------------------

def run_test(
    name: str,
    fn: Callable[[Path], None],
    root: Path,
    *,
    xfail: bool = False,
    strict_safety: bool = False,
) -> TestResult:
    try:
        fn(root)

        if xfail and not strict_safety:
            return TestResult(
                name,
                "XPASS",
                "known safety-gap test unexpectedly passed; update test expectation",
            )

        return TestResult(name, "PASS")

    except TestFailure as e:
        if xfail and not strict_safety:
            return TestResult(name, "XFAIL", str(e))
        return TestResult(name, "FAIL", str(e))

    except Exception as e:
        if xfail and not strict_safety:
            return TestResult(name, "XFAIL", f"unexpected exception: {e}")
        return TestResult(name, "FAIL", f"unexpected exception: {e}")


def main():
    global BIN

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict-safety",
        action="store_true",
        help=(
            "require stale-source and macro-expansion safety tests to pass; "
            "use after corresponding Rewriter protections are implemented"
        ),
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="keep temporary test directory",
    )
    args = parser.parse_args()

    if not BIN:
        print(
            "error: RISCV2X86_BIN is not set.\n"
            "example:\n"
            "  RISCV2X86_BIN=./build/riscv2x86 python3 tests/test_writeback.py",
            file=sys.stderr,
        )
        return 2

    bin_path = Path(BIN)
    if not bin_path.exists():
        print(f"error: RISCV2X86_BIN does not exist: {BIN}", file=sys.stderr)
        return 2

    BIN = str(bin_path.resolve())

    temp_dir = Path(tempfile.mkdtemp(prefix="riscv2x86-writeback-test-"))
    print(f"[test root] {temp_dir}")

    tests = [
        ("single_rewrite", test_single_rewrite, False),
        ("multiple_non_overlapping_rewrites", test_multiple_non_overlapping_rewrites, False),
        ("multi_file_rewrite", test_multi_file_rewrite, False),
        ("overlapping_edits_rejected", test_overlapping_edits_rejected, False),
        ("out_of_range_edit_rejected", test_out_of_range_edit_rejected, False),
        ("stdint_include_insertion", test_stdint_include_insertion, False),

        # 当前 Rewriter.cpp 尚未具备这些保护，因此默认 XFAIL。
        ("stale_report_must_not_modify_changed_source",
         test_stale_report_must_not_modify_changed_source, True),
        ("macro_expansion_must_be_skipped",
         test_macro_expansion_must_be_skipped, True),

        # 真实执行：analysis -> report -> simulated translation -> --apply
        ("analysis_translate_apply_chain", test_analysis_translate_apply_chain, False),
    ]

    results: List[TestResult] = []

    try:
        for name, fn, xfail in tests:
            print("\n" + "=" * 78)
            print(f"[test] {name}")
            print("=" * 78)

            result = run_test(
                name,
                fn,
                temp_dir,
                xfail=xfail,
                strict_safety=args.strict_safety,
            )
            results.append(result)
            print(f"[result] {result.status}: {result.name}")
            if result.detail:
                print(result.detail)

    finally:
        if args.keep_temp:
            print(f"[keep-temp] test data retained at: {temp_dir}")
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)

    failed = False

    for r in results:
        print(f"{r.status:6} {r.name}")
        if r.status == "FAIL":
            failed = True

        # XPASS 表示“原本标记为已知缺口的测试意外通过”。
        # 这通常是好事，但也意味着应更新测试状态。
        if r.status == "XPASS":
            print("       note: safety feature may already be implemented; "
                  "consider removing XFAIL marking.")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())