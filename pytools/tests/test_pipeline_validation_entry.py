from riscv2x86_py.pipeline import _run_unified_phase8_validation
from riscv2x86_py.pipeline_validation_context import WritebackValidationInput
from riscv2x86_py.translation_validation import (
    TranslationValidationResult, ValidationLevel, ValidationProfile,
)
from riscv2x86_py.validation_status import ValidationStatus


def _invoke(runner):
    return _run_unified_phase8_validation(
        runner, finding=object(), lift_result=object(), ir_summary=object(),
        translation_result=object(),
    )


def test_pipeline_has_no_legacy_verifier_fallback():
    writeback_input, status, detail = _invoke(None)
    assert writeback_input is None
    assert status is ValidationStatus.INCONCLUSIVE
    assert "legacy verify() cannot authorize writeback" in detail


def test_pipeline_rejects_non_protocol_validation_result():
    writeback_input, status, detail = _invoke(lambda **_kwargs: "verified")
    assert writeback_input is None
    assert status is ValidationStatus.FAILED
    assert "invalid result" in detail


def test_pipeline_accepts_only_structured_unified_validation_result():
    calls = []

    def runner(**kwargs):
        calls.append(set(kwargs))
        validation = TranslationValidationResult(
            ValidationStatus.VERIFIED, ValidationProfile.ARCHITECTURAL,
            (ValidationLevel.L0, ValidationLevel.L1, ValidationLevel.L2), (),
            (), "sha256:" + "1" * 64,
        )
        return WritebackValidationInput(
            validation, object(), "sha256:" + "2" * 64,
            object(), object(), object(),
        )

    writeback_input, status, detail = _invoke(runner)
    assert isinstance(writeback_input, WritebackValidationInput)
    assert status is ValidationStatus.VERIFIED
    assert detail == ""
    assert calls == [{
        "finding", "lift_result", "ir_summary", "translation_result",
    }]
