from riscv2x86_py.schema import (
    AsmFragment,
    Finding,
    PublicationOutcome,
    TranslationOutcome,
    ValidationOutcome,
    load_report,
    make_translation_attempt_artifact,
    save_report,
    update_translation_attempt_outcomes,
)
from riscv2x86_py.translation_validation import (
    TranslationValidationResult,
    ValidationProfile,
)
from riscv2x86_py.validation_status import (
    ValidationStatus,
    WritebackAdmission,
)


def _finding() -> Finding:
    return Finding(
        fragment=AsmFragment(id="fragment:e0", rawAsmText="add %0,%1,%2"),
        rawSourceText='asm("add %0,%1,%2");',
        category="ReplaceableByRule",
        approvalArtifact={"preservationMode": "architecture_equivalent"},
    )


def test_failed_validation_withholds_public_text_but_retains_candidate(tmp_path):
    finding = _finding()
    candidate = 'asm volatile("addq %2,%0" : "=r"(out) : "0"(lhs), "r"(rhs) : "cc");'
    finding.translationOutcome = TranslationOutcome.EMITTED.value
    finding.validationOutcome = ValidationStatus.NOT_VERIFIED.value
    finding.publicationOutcome = PublicationOutcome.PENDING.value
    finding.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id="fragment:e0", candidate_kind="x86_inline_asm",
        candidate_route="phase6f_rendered", candidate_replacement=candidate,
        candidate_rule_name="phase6.lower_to_x86_inline_asm",
        translation_outcome=TranslationOutcome.EMITTED,
    )
    finding.validationOutcome = ValidationStatus.FAILED.value
    finding.publicationOutcome = PublicationOutcome.WITHHELD.value
    finding.translationAttemptArtifact = update_translation_attempt_outcomes(
        finding.translationAttemptArtifact,
        validation_outcome=ValidationStatus.FAILED.value,
        publication_outcome=PublicationOutcome.WITHHELD,
        reason_codes=("validation.layer-not-verified:L1",),
    )
    # This is the existing fail-closed apply behavior.
    finding.suggestedReplacement = ""
    finding.ruleName = ""

    assert finding.translationOutcome == TranslationOutcome.EMITTED.value
    assert finding.validationOutcome == ValidationStatus.FAILED.value
    assert finding.publicationOutcome == PublicationOutcome.WITHHELD.value
    assert finding.suggestedReplacement == ""
    assert finding.translationAttemptArtifact["candidateReplacement"] == candidate
    assert finding.translationAttemptArtifact["translationOutcome"] == "emitted"
    assert finding.translationAttemptArtifact["validationOutcome"] == "failed"
    assert finding.translationAttemptArtifact["publicationOutcome"] == "withheld"

    report = tmp_path / "report.json"
    save_report([finding], str(report))
    restored = load_report(str(report))[0]
    assert restored.suggestedReplacement == ""
    assert restored.translationAttemptArtifact["candidateReplacement"] == candidate
    assert restored.translationAttemptArtifact["attemptIdentity"].startswith("sha256:")


def test_validation_and_publication_outcomes_are_independent():
    validation = TranslationValidationResult(
        status=ValidationStatus.VERIFIED,
        profile=ValidationProfile.ARCHITECTURAL,
        completed_levels=(), layer_results=(), reason_codes=(),
        validation_identity="sha256:" + "1" * 64,
    )
    rejected = WritebackAdmission(
        False, ValidationStatus.VERIFIED, "validation.manifest-mismatch",
    )

    assert validation.validation_outcome is ValidationOutcome.VERIFIED
    assert validation.to_dict()["validationOutcome"] == "verified"
    assert rejected.publication_outcome is PublicationOutcome.WITHHELD


def test_functional_fallback_is_a_translation_outcome_not_a_validation_status():
    finding = _finding()
    finding.approvalArtifact["preservationMode"] = "functional_equivalence_only"
    finding.translationOutcome = TranslationOutcome.FUNCTIONAL_FALLBACK.value
    finding.validationOutcome = ValidationStatus.NOT_VERIFIED.value
    finding.publicationOutcome = PublicationOutcome.PENDING.value
    finding.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id="fragment:e0", candidate_kind="functional_c",
        candidate_route="registered_fallback",
        candidate_replacement="out = lhs + rhs;",
        candidate_rule_name="phase6.functional.registered",
        translation_outcome=TranslationOutcome.FUNCTIONAL_FALLBACK,
    )

    assert finding.translationOutcome == TranslationOutcome.FUNCTIONAL_FALLBACK.value
    assert finding.validationOutcome == ValidationStatus.NOT_VERIFIED.value
    assert finding.publicationOutcome == PublicationOutcome.PENDING.value
