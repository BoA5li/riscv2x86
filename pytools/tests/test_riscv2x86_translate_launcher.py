"""Launcher strictness tests for generic-C/no-op translations."""
from __future__ import annotations

import os

import pytest

from riscv2x86_py.riscv2x86_translate import (
    TranslationError,
    backend_module_environment,
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
