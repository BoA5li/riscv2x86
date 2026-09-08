"""Launcher strictness tests for generic-C/no-op translations."""
from __future__ import annotations

import os
from argparse import Namespace

import pytest

from riscv2x86_py.riscv2x86_translate import (
    TranslationError,
    backend_module_environment,
    source_frontend_flags,
    target_compiler_flags,
    validate_translated_report,
)


def test_empty_report_is_a_successful_generic_c_noop() -> None:
    assert validate_translated_report({"findings": []}, allow_untranslated=False) == 0


def test_explicit_phase6_keep_is_a_successful_noop() -> None:
    report = {
        "findings": [{
            "category": "ReplaceableByRule",
            "translationKind": "keep",
            "suggestedReplacement": "",
        }]
    }
    assert validate_translated_report(report, allow_untranslated=False) == 0


def test_untranslated_architecture_finding_remains_strictly_rejected() -> None:
    with pytest.raises(TranslationError, match="translation is incomplete"):
        validate_translated_report(
            {"findings": [{"category": "NeedsAsmTranslation"}]},
            allow_untranslated=False,
        )


def test_actionable_replacement_still_requires_text_and_range() -> None:
    with pytest.raises(TranslationError, match="invalid ReplaceableByRule"):
        validate_translated_report(
            {"findings": [{"category": "ReplaceableByRule", "suggestedReplacement": ""}]},
            allow_untranslated=False,
        )


def test_backend_module_environment_prefers_the_launcher_checkout() -> None:
    """A stale installed package must not shadow the checked-out backend."""
    environment = backend_module_environment({"PYTHONPATH": "/tmp/old-backend"})
    first = environment["PYTHONPATH"].split(os.pathsep, 1)[0]
    assert first.endswith("/pytools")
    assert "/tmp/old-backend" in environment["PYTHONPATH"]


def _flag_args(**overrides) -> Namespace:
    values = {
        "xlen": "64", "cflag": ["-std=gnu11", "-march=rv64gc", "-mabi=lp64d"],
        "frontend_cflag": [], "target_cflag": ["-Wall"], "source_target": "",
        "source_sysroot": "", "source_cc": "",
    }
    values.update(overrides)
    return Namespace(**values)


def test_source_frontend_flags_add_riscv_target_and_discovered_sysroot(monkeypatch) -> None:
    monkeypatch.setattr(
        "riscv2x86_py.riscv2x86_translate._discover_source_sysroot",
        lambda compiler, target: "/opt/rv64-sysroot",
    )
    flags = source_frontend_flags(_flag_args())
    assert flags[:2] == (
        "--target=riscv64-linux-gnu", "--sysroot=/opt/rv64-sysroot",
    )
    assert "-march=rv64gc" in flags and "-mabi=lp64d" in flags


def test_explicit_source_target_and_sysroot_are_not_duplicated(monkeypatch) -> None:
    monkeypatch.setattr(
        "riscv2x86_py.riscv2x86_translate._discover_source_sysroot",
        lambda compiler, target: (_ for _ in ()).throw(AssertionError("must not discover")),
    )
    flags = source_frontend_flags(_flag_args(cflag=[
        "--target=riscv64-unknown-linux-gnu", "--sysroot=/custom", "-std=gnu11",
    ]))
    assert flags.count("--target=riscv64-unknown-linux-gnu") == 1
    assert flags.count("--sysroot=/custom") == 1


def test_source_architecture_flags_do_not_leak_into_x86_compilation() -> None:
    flags = target_compiler_flags(_flag_args())
    assert flags == ("-std=gnu11", "-Wall")
