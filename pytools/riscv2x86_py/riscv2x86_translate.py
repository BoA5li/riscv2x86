#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
通用 riscv2x86 翻译调用框架。

流程：

    输入 C 文件或目录中的 C 文件集合
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

目录批处理：

    --input /path/to/source-tree

会递归处理其中的 ``.c`` 文件（按路径稳定排序）。单个文件失败不会阻断
其余文件；所有结果都会记录于 ``batch_summary.json``，并在结束时集中报告。
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
from typing import Any, Iterable


class TranslationError(RuntimeError):
    """框架执行失败。"""


_SOURCE_SUFFIXES = frozenset({".c"})


def _path_is_within(path: Path, root: Path) -> bool:
    """Return whether resolved ``path`` is rooted at resolved ``root``."""
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def discover_input_sources(
    input_dir: Path,
    *,
    excluded_roots: Iterable[Path] = (),
) -> tuple[Path, ...]:
    """Find supported program sources in deterministic order.

    Directory mode intentionally accepts only the same source language as
    single-file mode (``.c``).  Generated output and work trees located below
    the input directory are excluded so a repeated batch run cannot translate
    its own generated files.
    """
    root = input_dir.resolve()
    exclusions = tuple(item.resolve() for item in excluded_roots)
    sources: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        resolved = path.resolve()
        if any(_path_is_within(resolved, excluded) for excluded in exclusions):
            continue
        sources.append(resolved)
    return tuple(sources)


def _copy_source_tree_for_batch(
    source_root: Path,
    staging_root: Path,
    *,
    excluded_roots: Iterable[Path],
) -> None:
    """Copy a stable batch input tree without generated subtrees."""
    root = source_root.resolve()
    exclusions = tuple(item.resolve() for item in excluded_roots)

    def ignore(directory: str, names: list[str]) -> set[str]:
        base = Path(directory)
        return {
            name for name in names
            if any(_path_is_within(base / name, excluded) for excluded in exclusions)
        }

    shutil.copytree(root, staging_root, ignore=ignore)


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
                if phase6_artifact.get("replacementKind") == "helper_call" and not all(
                    isinstance(phase6_artifact.get(key), str) and phase6_artifact[key]
                    for key in ("helperRuntimeContractId", "helperSemanticVersion", "helperRequiredHeader", "helperRuntimeLibrary", "helperRuntimeManifestVersion")
                ):
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
        help="Input C source file or directory tree to translate.",
    )

    parser.add_argument(
        "--src-root",
        type=Path,
        default=None,
        help=(
            "Source root passed to C++ frontend. "
            "Default: parent of a file input, or the input directory itself."
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

def translate_one(
    args: argparse.Namespace,
    *,
    source_file: Path,
    src_root: Path,
    output_root: Path,
    work_dir: Path,
) -> dict[str, str]:
    """Translate exactly one already-resolved C source file.

    Batch mode calls this function independently for each file.  It has no
    recovery policy of its own: callers decide whether a per-file failure is
    terminal (single-file mode) or collected (directory mode).
    """
    source_file = source_file.resolve()
    src_root = src_root.resolve()
    output_root = output_root.resolve()
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    if not source_file.exists() or not source_file.is_file():
        raise TranslationError(f"input source is not a file: {source_file}")
    if source_file.suffix.lower() not in _SOURCE_SUFFIXES:
        raise TranslationError(f"input source is not a .c file: {source_file}")
    if not src_root.exists() or not src_root.is_dir():
        raise TranslationError(f"src-root does not exist or is not a directory: {src_root}")

    raw_report = work_dir / "raw_report.json"
    translated_report = work_dir / "translated_report.json"
    object_file = work_dir / f"{source_file.stem}.o"

    rewritten_file = get_output_source_path(
        source_file=source_file,
        src_root=src_root,
        output_root=output_root,
    )

    print("[configuration]")
    print(f"frontend:       {args.frontend}")
    print(f"python:         {args.python}")
    print(f"backend module: {args.backend_module}")
    print(f"compiler:       {args.cc}")
    print(f"input:          {source_file}")
    print(f"src-root:       {src_root}")
    print(f"output-dir:     {output_root}")
    print(f"rewritten file: {rewritten_file}")
    print(f"work-dir:       {work_dir}")
    print(f"xlen:           {args.xlen}")

    frontend_analysis_cmd = [
            args.frontend,
            "--analysis-only",
            "-o", str(work_dir / "analysis_dummy_output"),
            "--src-root", str(src_root),
            "--report-json", str(raw_report),
            str(source_file),
            "--",
            *args.cflag,
    ]

    run(frontend_analysis_cmd)

    if not raw_report.exists():
        raise TranslationError(f"C++ frontend did not produce raw report: {raw_report}")

    raw = load_json(raw_report)
    summarize_report(raw, title="raw frontend report")

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
        raise TranslationError("Python backend did not produce translated report: " f"{translated_report}")

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
                f"  input:    {source_file}\n"
                f"  output:   {output_root}"
        )

    include_flags = [
            f"-I{output_root}",
            f"-I{src_root}",
            f"-I{source_file.parent}",
            f"-I{Path(__file__).resolve().parents[2] / 'runtime' / 'include'}",
    ]

    syntax_check_cmd = [
            args.cc,
            "-fsyntax-only",
            *args.cflag,
            *include_flags,
            str(rewritten_file),
    ]

    run(syntax_check_cmd)

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
        raise TranslationError(f"compiler returned success but object file is missing: {object_file}")

    print("\nSUCCESS: translation pipeline completed")
    print(f"input source:      {source_file}")
    print(f"rewritten source:  {rewritten_file}")
    print(f"raw report:        {raw_report}")
    print(f"translated report: {translated_report}")
    print(f"compiled object:   {object_file}")
    return {
        "input": str(source_file),
        "rewritten": str(rewritten_file),
        "raw_report": str(raw_report),
        "translated_report": str(translated_report),
        "object": str(object_file),
    }


def _single_source_context(args: argparse.Namespace, source_file: Path, work_dir: Path) -> tuple[Path, Path]:
    """Preserve the historical isolated single-file behavior."""
    if args.src_root is not None:
        return source_file, args.src_root.resolve()
    isolate_src_dir = work_dir / "isolate_single_src"
    isolate_src_dir.mkdir(parents=True, exist_ok=True)
    isolated = isolate_src_dir / source_file.name
    shutil.copy2(source_file, isolated)
    return isolated, isolate_src_dir.resolve()


def _write_batch_summary(work_dir: Path, results: list[dict[str, str]]) -> Path:
    path = work_dir / "batch_summary.json"
    path.write_text(json.dumps({"results": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main() -> int:
    args = parse_args()
    if not args.frontend:
        print("error: --frontend or RISCV2X86_FRONTEND must be specified", file=sys.stderr)
        return 2
    created_temp_work_dir = False
    try:
        ensure_tool_exists(args.frontend, "riscv2x86 frontend")
        ensure_tool_exists(args.python, "Python")
        ensure_tool_exists(args.cc, "C compiler")
        input_path = args.input.resolve()
        output_root = args.output_dir.resolve()
        if not input_path.exists():
            raise TranslationError(f"input path does not exist: {input_path}")
        if args.work_dir is None:
            work_dir = Path(tempfile.mkdtemp(prefix="riscv2x86-translate-")).resolve()
            created_temp_work_dir = True
        else:
            work_dir = args.work_dir.resolve()
            work_dir.mkdir(parents=True, exist_ok=True)

        if input_path.is_file():
            if input_path.suffix.lower() not in _SOURCE_SUFFIXES:
                raise TranslationError(f"input source is not a .c file: {input_path}")
            isolated_source, src_root = _single_source_context(args, input_path, work_dir)
            translate_one(args, source_file=isolated_source, src_root=src_root, output_root=output_root, work_dir=work_dir)
            if created_temp_work_dir and not args.keep_work_dir:
                shutil.rmtree(work_dir, ignore_errors=True)
                print("temporary work directory removed")
            else:
                print(f"work directory retained: {work_dir}")
            return 0

        if not input_path.is_dir():
            raise TranslationError(f"input path is neither a file nor a directory: {input_path}")
        source_root = args.src_root.resolve() if args.src_root is not None else input_path
        if not source_root.is_dir() or not _path_is_within(input_path, source_root):
            raise TranslationError("directory input must be inside --src-root, and src-root must be a directory")
        if output_root == input_path:
            raise TranslationError("--output-dir must not be the same directory as a directory input")
        if _path_is_within(work_dir, source_root):
            raise TranslationError("--work-dir must not be inside a directory input/src-root")
        sources = discover_input_sources(input_path, excluded_roots=(output_root, work_dir))
        if not sources:
            raise TranslationError(f"no .c source files found below input directory: {input_path}")

        staging_root = work_dir / "batch_source_tree"
        _copy_source_tree_for_batch(source_root, staging_root, excluded_roots=(output_root, work_dir))
        results: list[dict[str, str]] = []
        for ordinal, source in enumerate(sources):
            relative = source.relative_to(source_root)
            staged_source = staging_root / relative
            item_work_dir = work_dir / "files" / f"{ordinal:04d}" / relative.parent / relative.stem
            print(f"\n{'=' * 72}\n[BATCH {ordinal + 1}/{len(sources)}] {relative}\n{'=' * 72}")
            try:
                artifact = translate_one(args, source_file=staged_source, src_root=staging_root, output_root=output_root, work_dir=item_work_dir)
                # --apply copies the full staged tree on every iteration.
                # Feed the successful rewritten file back into the staging
                # tree so subsequent copies retain earlier translations.
                shutil.copy2(Path(artifact["rewritten"]), staged_source)
                results.append({"input": str(source), "status": "success", **artifact})
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                print(f"\n[BATCH FAILURE] {relative}: {message}", file=sys.stderr)
                results.append({"input": str(source), "status": "failed", "error": message})
        summary = _write_batch_summary(work_dir, results)
        failed = [item for item in results if item["status"] == "failed"]
        print(f"\n[BATCH SUMMARY]\ntotal files: {len(results)}\nsucceeded:   {len(results) - len(failed)}\nfailed:      {len(failed)}\nsummary:     {summary}")
        if failed:
            print("\n[BATCH FAILURES]", file=sys.stderr)
            for item in failed:
                print(f"  - {item['input']}: {item['error']}", file=sys.stderr)
            print(f"work directory retained: {work_dir}")
            return 1
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
