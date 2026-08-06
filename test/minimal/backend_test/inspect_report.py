#!/usr/bin/env python3
import sys
from pathlib import Path

from riscv2x86_py.schema import load_report

# 固定报告根目录
REPORT_BASE = Path("/root/src/poc_trans/path_b/riscv2x86/test/minimal/output")


def main() -> int:
    target_path: Path

    if len(sys.argv) == 1:
        # 无入参，默认读取主报告
        target_path = REPORT_BASE / "report.json"
    elif len(sys.argv) == 2:
        arg = sys.argv[1]
        arg_path = Path(arg)
        if arg_path.is_absolute():
            # 传入绝对路径则直接使用
            target_path = arg_path
        else:
            # 仅传文件名，拼接基准目录
            target_path = REPORT_BASE / arg
    else:
        print(f"Usage: {sys.argv[0]} [report_filename.json]")
        print(f"Default base dir: {REPORT_BASE}")
        return 2

    if not target_path.exists():
        print(f"Error: File not found -> {target_path}")
        return 1

    findings = load_report(str(target_path))

    print(f"Loaded findings: {len(findings)}")

    for index, finding in enumerate(findings):
        print(f"\n=== Finding #{index} ===")
        print(f"category: {finding.category}")
        print(f"file: {finding.fileName}:{finding.line}:{finding.column}")

        fragment = finding.fragment
        if fragment is None:
            print("fragment: <none>")
            continue

        print(f"id: {fragment.id}")
        print(f"kind: {fragment.kind}")
        print(f"rawAsmText: {fragment.rawAsmText!r}")
        print(f"volatile: {fragment.isVolatile}")
        print(f"clobbers: {fragment.clobbers}")
        print(f"gotoLabels: {fragment.gotoLabels}")
        print(f"offset: [{fragment.beginOffset}, {fragment.endOffset})")
        print(f"function: {fragment.enclosingFunction}")

        print("outputs:")
        for op in fragment.outputs:
            print(
                f"  constraint={op.constraint!r}, "
                f"expr={op.exprText!r}, "
                f"name={op.symbolicName!r}, "
                f"isOutput={op.isOutput}, "
                f"isTied={op.isTied}, "
                f"isEarlyClobber={op.isEarlyClobber}"
            )

        print("inputs:")
        for op in fragment.inputs:
            print(
                f"  constraint={op.constraint!r}, "
                f"expr={op.exprText!r}, "
                f"name={op.symbolicName!r}, "
                f"isOutput={op.isOutput}, "
                f"isTied={op.isTied}, "
                f"isEarlyClobber={op.isEarlyClobber}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())