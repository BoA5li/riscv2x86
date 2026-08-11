#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
通用 riscv2x86 翻译调用框架。

流程：

    输入 C 文件
      -> C++ frontend --analysis-only
      -> raw_report.json
      -> Python backend
      -> translated_report.json
      -> C++ frontend --apply
      -> 改写后的 C 文件
      -> C 语法检查
      -> C 对象文件编译检查

示例：

    python3 tools/riscv2x86_translate.py \
      --frontend ./build/riscv2x86 \
      --input /path/to/input/foo.c \
      --output-dir /path/to/output \
      --cflag=-std=gnu11

如果需要指定源码根目录：

    python3 tools/riscv2x86_translate.py \
      --frontend ./build/riscv2x86 \
      --src-root /path/to/project \
      --input /path/to/project/src/foo.c \
      --output-dir /path/to/output \
      --cflag=-std=gnu11 \
      --cflag=-I/path/to/project/include

如果 Python backend 不在默认模块路径中：

    PYTHONPATH=/path/to/backend \
    python3 tools/riscv2x86_translate.py \
      --frontend ./build/riscv2x86 \
      --input example.c \
      --output-dir output

默认严格模式：
    translated_report.json 中存在未翻译的 NeedsAsmTranslation /
    Unsupported finding 时，框架返回失败。

允许部分 finding 未翻译：

    python3 tools/riscv2x86_translate.py \
      --frontend ./build/riscv2x86 \
      --input example.c \
      --output-dir output \
      --allow-untranslated
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


class TranslationError(RuntimeError):
    """框架执行失败。"""


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    expected_rc: int = 0,
) -> subprocess.CompletedProcess[str]:
    """执行命令，打印 stdout/stderr，并检查退出码。"""
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
        raise TranslationError(
            "command failed\n"
            f"return code: {result.returncode}\n"
            f"expected: {expected_rc}\n"
            f"command: {' '.join(cmd)}"
        )

    return result


def load_json(path: Path) -> dict[str, Any]:
    """读取 JSON 报告。"""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TranslationError(
            f"cannot parse JSON report {path}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise TranslationError(f"invalid report root in {path}: expected object")

    return value


def get_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """获取报告 findings 数组。"""
    findings = report.get("findings")

    if not isinstance(findings, list):
        raise TranslationError("report has no valid findings array")

    result: list[dict[str, Any]] = []

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise TranslationError(
                f"report finding at index {index} is not an object"
            )
        result.append(finding)

    return result


def finding_label(finding: dict[str, Any]) -> str:
    """生成用于日志和错误信息的通用 finding 标识。"""
    file_name = finding.get("fileName") or finding.get("file") or "<unknown-file>"
    line = finding.get("line")
    column = finding.get("column")
    category = finding.get("category") or "<unknown-category>"
    subject_kind = finding.get("subjectKind") or "<unknown-subject>"

    location = str(file_name)

    if isinstance(line, int):
        location += f":{line}"

        if isinstance(column, int):
            location += f":{column}"

    return f"[{category}] {location} ({subject_kind})"


def summarize_report(report: dict[str, Any], *, title: str) -> None:
    """输出报告摘要。"""
    findings = get_findings(report)

    categories: dict[str, int] = {}

    for finding in findings:
        category = str(finding.get("category") or "<missing>")
        categories[category] = categories.get(category, 0) + 1

    print(f"\n[{title}]")
    print(f"total findings: {len(findings)}")

    for category in sorted(categories):
        print(f"  {category}: {categories[category]}")


def validate_translated_report(
    report: dict[str, Any],
    *,
    allow_untranslated: bool,
) -> int:
    """
    验证 Python backend 输出。

    返回值：
        可写回 replacement 数量。零表示本次输入没有需要改写的
        架构相关内容，或 Phase 6E 已明确选择 KEEP；这仍是成功结果。

    不依赖 asmText、rawAsmText 或任何具体汇编文本。
    """
    findings = get_findings(report)

    replaceable_count = 0
    untranslated: list[dict[str, Any]] = []
    invalid_replaceable: list[dict[str, Any]] = []

    for finding in findings:
        category = finding.get("category")

        if category == "ReplaceableByRule":
            replacement = finding.get("suggestedReplacement")
            # Phase 6E's KEEP is an explicit, structured decision.  It is
            # deliberately not a textual rewrite: C++ --apply copies the
            # source tree and leaves the original fragment in place.  Do not
            # confuse that approved no-op with an incomplete translation.
            if (
                finding.get("translationKind") == "keep"
                and (replacement is None or replacement == "")
            ):
                continue
            begin = finding.get("rewriteBeginOffset")
            end = finding.get("rewriteEndOffset")

            if not isinstance(replacement, str) or not replacement.strip():
                invalid_replaceable.append(finding)
                continue

            if not isinstance(begin, int) or not isinstance(end, int):
                invalid_replaceable.append(finding)
                continue

            if begin < 0 or end < begin:
                invalid_replaceable.append(finding)
                continue

            rule_name = str(finding.get("ruleName") or finding.get("rule") or "")
            phase6_artifact = finding.get("approvalArtifact")
            public_artifact = finding.get("publicApprovalArtifact")
            if rule_name.startswith("phase6."):
                if not isinstance(phase6_artifact, dict) or phase6_artifact.get("proofStatus") != "approved":
                    invalid_replaceable.append(finding)
                    continue
            elif rule_name.startswith("phase2.public."):
                if (
                    not isinstance(public_artifact, dict)
                    or public_artifact.get("artifactVersion") != "phase2-public-approval-v1"
                    or public_artifact.get("approvalStatus") != "approved"
                    or not isinstance(public_artifact.get("semanticContractId"), str)
                    or not isinstance(public_artifact.get("compilerFamily"), str)
                    or not isinstance(public_artifact.get("compilerVersion"), str)
                    or not isinstance(public_artifact.get("requiredHeaders"), list)
                    or not isinstance(public_artifact.get("requiredTargetFeatures"), list)
                    or rule_name != "phase2.public." + public_artifact["semanticContractId"]
                ):
                    invalid_replaceable.append(finding)
                    continue
            else:
                # No legacy direct-rewrite escape hatch remains.
                invalid_replaceable.append(finding)
                continue

            replaceable_count += 1
            continue

        # 已有规则处理、或不需要改写的 finding，可以继续。
        if category in {
            "AlreadyRule",
            "Ignored",
            "NoFinding",
        }:
            continue

        # 这些 category 表示后端没有产生可写回替换。
        if category in {
            "NeedsAsmTranslation",
            "Unsupported",
            "TranslationFailed",
            "NeedsRoute",
            "DeferredNonFragment",
        }:
            untranslated.append(finding)

    if invalid_replaceable:
        detail = "\n".join(
            f"  - {finding_label(finding)}"
            for finding in invalid_replaceable
        )
        raise TranslationError(
            "translated report contains invalid ReplaceableByRule finding(s):\n"
            f"{detail}\n"
            "A replaceable finding must have a non-empty suggestedReplacement "
            "and a valid rewrite range."
        )

    if not allow_untranslated and untranslated:
        detail = "\n".join(
            f"  - {finding_label(finding)}"
            for finding in untranslated
        )
        raise TranslationError(
            "translation is incomplete; untranslated finding(s) remain:\n"
            f"{detail}\n"
            "Use --allow-untranslated only when partial translation is intended."
        )

    return replaceable_count


def get_output_source_path(
    *,
    source_file: Path,
    src_root: Path,
    output_root: Path,
) -> Path:
    """
    根据 SourceRewriter 的 src-root 相对路径规则，预测写回后的输出文件路径。
    """
    try:
        relative = source_file.relative_to(src_root)
    except ValueError as exc:
        raise TranslationError(
            f"input source is outside src-root:\n"
            f"  source:   {source_file}\n"
            f"  src-root: {src_root}"
        ) from exc

    return output_root / relative


def ensure_tool_exists(command_or_path: str, tool_name: str) -> None:
    """检查可执行工具是否存在。"""
    path = Path(command_or_path)

    if path.exists():
        if not path.is_file():
            raise TranslationError(
                f"{tool_name} path exists but is not a file: {command_or_path}"
            )
        return

    if shutil.which(command_or_path) is None:
        raise TranslationError(
            f"{tool_name} executable not found: {command_or_path}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run riscv2x86 C++ frontend, Python backend, C++ rewrite, "
            "syntax validation, and object compilation."
        )
    )

    parser.add_argument(
        "--frontend",
        default=os.environ.get("RISCV2X86_FRONTEND", ""),
        help=(
            "Path to riscv2x86 C++ frontend binary. "
            "Default: RISCV2X86_FRONTEND"
        ),
    )

    parser.add_argument(
        "--python",
        default=os.environ.get("RISCV2X86_PYTHON", sys.executable),
        help=(
            "Python executable for backend. "
            "Default: RISCV2X86_PYTHON or current Python."
        ),
    )

    parser.add_argument(
        "--backend-module",
        default=os.environ.get(
            "RISCV2X86_BACKEND_MODULE",
            "riscv2x86_py.cli",
        ),
        help=(
            "Python backend module used with python -m. "
            "Default: riscv2x86_py.cli"
        ),
    )

    parser.add_argument(
        "--cc",
        default=os.environ.get("RISCV2X86_CC", "cc"),
        help="Host C compiler. Default: RISCV2X86_CC or cc.",
    )

    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Input C source file to translate.",
    )

    parser.add_argument(
        "--src-root",
        type=Path,
        default=None,
        help=(
            "Source root passed to C++ frontend. "
            "Default: parent directory of --input."
        ),
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory where rewritten C source files are written.",
    )

    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help=(
            "Directory for raw_report.json and translated_report.json. "
            "Default: a newly-created temporary directory."
        ),
    )

    parser.add_argument(
        "--xlen",
        choices=("32", "64"),
        default="64",
        help="RISC-V XLEN forwarded to Python backend. Default: 64.",
    )

    parser.add_argument(
        "--cflag",
        action="append",
        default=[],
        help=(
            "Extra C compiler / frontend source argument. "
            "May be specified multiple times, e.g. "
            "--cflag=-std=gnu11 --cflag=-I/path/include"
        ),
    )

    parser.add_argument(
        "--ghidra-install-dir",
        default=os.environ.get("GHIDRA_INSTALL_DIR", ""),
        help="Optional Ghidra installation directory.",
    )

    parser.add_argument(
        "--ghidra-language-id",
        default=os.environ.get("GHIDRA_LANGUAGE_ID", ""),
        help="Optional Ghidra language ID.",
    )

    parser.add_argument(
        "--allow-untranslated",
        action="store_true",
        help=(
            "Allow untranslated findings in translated_report.json. "
            "Default behavior is strict: untranslated inline asm causes failure."
        ),
    )

    parser.add_argument(
        "--keep-work-dir",
        action="store_true",
        help="Keep automatically created temporary work directory.",
    )

    return parser.parse_args()

def main() -> int:
    args = parse_args()

    if not args.frontend:
        print(
            "error: --frontend or RISCV2X86_FRONTEND must be specified",
            file=sys.stderr,
        )
        return 2

    try:
        ensure_tool_exists(args.frontend, "riscv2x86 frontend")
        ensure_tool_exists(args.python, "Python")
        ensure_tool_exists(args.cc, "C compiler")

        source_file = args.input.resolve()
        output_root = args.output_dir.resolve()

        if not source_file.exists():
            raise TranslationError(f"input source does not exist: {source_file}")

        if not source_file.is_file():
            raise TranslationError(f"input path is not a file: {source_file}")

        if source_file.suffix.lower() != ".c":
            raise TranslationError(
                f"input source is not a .c file: {source_file}"
            )

        # ========== 第一步：优先初始化 work_dir，修复变量前置引用 ==========
        created_temp_work_dir = False
        if args.work_dir is None:
            work_dir = Path(
                tempfile.mkdtemp(prefix="riscv2x86-translate-")
            ).resolve()
            created_temp_work_dir = True
        else:
            work_dir = args.work_dir.resolve()
            work_dir.mkdir(parents=True, exist_ok=True)

        raw_report = work_dir / "raw_report.json"
        translated_report = work_dir / "translated_report.json"
        object_file = work_dir / f"{source_file.stem}.o"

        # ========== 第二步：处理 src-root 隔离逻辑（此时 work_dir 已存在） ==========
        isolate_src_file: Path
        if args.src_root is not None:
            src_root = args.src_root.resolve()
            isolate_src_file = source_file
        else:
            # 自动隔离模式：拷贝源码到独立临时目录
            isolate_src_dir = work_dir / "isolate_single_src"
            isolate_src_dir.mkdir(parents=True, exist_ok=True)
            isolate_src_file = isolate_src_dir / source_file.name
            shutil.copy2(source_file, isolate_src_file)
            src_root = isolate_src_dir.resolve()

        if not src_root.exists() or not src_root.is_dir():
            raise TranslationError(
                f"src-root does not exist or is not a directory: {src_root}"
            )

        # 使用【隔离后的文件】计算输出路径
        rewritten_file = get_output_source_path(
            source_file=isolate_src_file,
            src_root=src_root,
            output_root=output_root,
        )

        print("[configuration]")
        print(f"frontend:       {args.frontend}")
        print(f"python:         {args.python}")
        print(f"backend module: {args.backend_module}")
        print(f"compiler:       {args.cc}")
        print(f"input:          {source_file}")
        print(f"isolate file:   {isolate_src_file}")
        print(f"src-root:       {src_root}")
        print(f"output-dir:     {output_root}")
        print(f"rewritten file: {rewritten_file}")
        print(f"work-dir:       {work_dir}")
        print(f"xlen:           {args.xlen}")

        # --------------------------------------------------------------
        # Phase 1: C++ frontend analysis-only 传入隔离后的文件，不是原始文件
        # --------------------------------------------------------------
        frontend_analysis_cmd = [
            args.frontend,
            "--analysis-only",
            "-o", str(work_dir / "analysis_dummy_output"),
            "--src-root", str(src_root),
            "--report-json", str(raw_report),
            str(isolate_src_file),   # 修复：使用隔离文件分析
            "--",
            *args.cflag,
        ]

        run(frontend_analysis_cmd)

        if not raw_report.exists():
            raise TranslationError(
                f"C++ frontend did not produce raw report: {raw_report}"
            )

        raw = load_json(raw_report)
        summarize_report(raw, title="raw frontend report")

        # --------------------------------------------------------------
        # Phase 2: Python backend translation
        # --------------------------------------------------------------
        backend_cmd = [
            args.python,
            "-m",
            args.backend_module,
            "--in", str(raw_report),
            "--out", str(translated_report),
            "--xlen", args.xlen,
        ]

        if args.ghidra_install_dir:
            backend_cmd.extend([
                "--ghidra-install-dir",
                args.ghidra_install_dir,
            ])

        if args.ghidra_language_id:
            backend_cmd.extend([
                "--ghidra-language-id",
                args.ghidra_language_id,
            ])

        run(backend_cmd)

        if not translated_report.exists():
            raise TranslationError(
                "Python backend did not produce translated report: "
                f"{translated_report}"
            )

        translated = load_json(translated_report)
        summarize_report(translated, title="translated backend report")

        replaceable_count = validate_translated_report(
            translated,
            allow_untranslated=args.allow_untranslated,
        )

        print(
            f"\n[translation validation]\n"
            f"applicable replacements: {replaceable_count}"
        )

        # --------------------------------------------------------------
        # Phase 3: C++ SourceRewriter --apply
        # --------------------------------------------------------------
        output_root.mkdir(parents=True, exist_ok=True)

        apply_cmd = [
            args.frontend,
            "--src-root", str(src_root),
            "-o", str(output_root),
            "--apply",
            "--report", str(translated_report),
        ]

        run(apply_cmd)

        if not rewritten_file.exists():
            raise TranslationError(
                "C++ SourceRewriter did not produce expected output file:\n"
                f"  expected: {rewritten_file}\n"
                f"  src-root: {src_root}\n"
                f"  input:    {isolate_src_file}\n"
                f"  output:   {output_root}"
            )

        # --------------------------------------------------------------
        # Phase 4: C syntax validation
        #
        # -I src_root 用于让改写后源文件仍可查找原工程头文件。
        # -I source_file.parent 额外处理输入源同目录头文件。
        # 用户的 --cflag 仍会原样透传。
        # --------------------------------------------------------------
        include_flags = [
            f"-I{output_root}",
            f"-I{src_root}",
            f"-I{source_file.parent}",
        ]

        syntax_check_cmd = [
            args.cc,
            "-fsyntax-only",
            *args.cflag,
            *include_flags,
            str(rewritten_file),
        ]

        run(syntax_check_cmd)

        # --------------------------------------------------------------
        # Phase 5: object compilation validation
        #
        # 使用 -c，不要求用户提供 main()，也不要求解决链接依赖。
        # 这一步可验证改写文件确实能被 host compiler 编译成目标文件。
        # --------------------------------------------------------------
        compile_cmd = [
            args.cc,
            "-c",
            *args.cflag,
            *include_flags,
            str(rewritten_file),
            "-o", str(object_file),
        ]

        run(compile_cmd)

        if not object_file.exists():
            raise TranslationError(
                f"compiler returned success but object file is missing: {object_file}"
            )

        print("\nSUCCESS: translation pipeline completed")
        print(f"input source:      {source_file}")
        print(f"rewritten source:  {rewritten_file}")
        print(f"raw report:        {raw_report}")
        print(f"translated report: {translated_report}")
        print(f"compiled object:   {object_file}")

        if created_temp_work_dir and not args.keep_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)
            print("temporary work directory removed")
        else:
            print(f"work directory retained: {work_dir}")

        return 0

    except TranslationError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(
            f"\nUNEXPECTED ERROR: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
