"""Directory-input launcher regressions without invoking translator tools."""
from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from riscv2x86_py import riscv2x86_translate as launcher


def _args(input_path: Path, output_dir: Path, work_dir: Path) -> Namespace:
    return Namespace(
        frontend="frontend", python="python", cc="cc",
        backend_module="riscv2x86_py.cli", input=input_path, src_root=None,
        output_dir=output_dir, work_dir=work_dir, xlen="64", cflag=[],
        ghidra_install_dir="", ghidra_language_id="",
        allow_untranslated=False, keep_work_dir=True,
    )


def test_directory_discovery_is_sorted_and_excludes_generated_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "z.c").write_text("int z;\n")
    (source / "nested" / "a.c").write_text("int a;\n")
    (source / "nested" / "skip.h").write_text("#pragma once\n")
    output = source / "translated"
    output.mkdir()
    (output / "old.c").write_text("int generated;\n")

    files = launcher.discover_input_sources(source, excluded_roots=(output,))

    assert [item.relative_to(source).as_posix() for item in files] == [
        "nested/a.c", "z.c",
    ]


def test_directory_mode_continues_after_failure_and_preserves_prior_staging(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.c").write_text("int original_a;\n")
    (source / "b.c").write_text("int original_b;\n")
    output, work = tmp_path / "output", tmp_path / "work"
    args = _args(source, output, work)
    seen: list[str] = []

    monkeypatch.setattr(launcher, "parse_args", lambda: args)
    monkeypatch.setattr(launcher, "ensure_tool_exists", lambda *_: None)

    def fake_translate_one(_args, *, source_file, src_root, output_root, work_dir):
        relative = source_file.relative_to(src_root)
        if relative.as_posix() == "a.c":
            rewritten = output_root / relative
            rewritten.parent.mkdir(parents=True, exist_ok=True)
            rewritten.write_text("int translated_a;\n")
            return {"input": str(source_file), "rewritten": str(rewritten), "raw_report": "raw", "translated_report": "translated", "object": "object"}
        seen.append((src_root / "a.c").read_text())
        raise launcher.TranslationError("intentional b failure")

    monkeypatch.setattr(launcher, "translate_one", fake_translate_one)

    assert launcher.main() == 1
    assert seen == ["int translated_a;\n"]
    summary = launcher.load_json(work / "batch_summary.json")
    assert [item["status"] for item in summary["results"]] == ["success", "failed"]
