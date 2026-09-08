import pytest

from riscv2x86_py.schema import (
    AsmFragment, Finding, PublicationOutcome, TranslationOutcome,
    ValidationOutcome, make_translation_attempt_artifact,
)
from riscv2x86_py.translation_attempt import (
    TranslationAttemptArchive, load_translation_attempt_archive,
    save_translation_attempt_archive, terminal_attempt_from_finding,
    translation_attempt_archive_from_dict, translation_attempt_from_dict,
)


def _finding(outcome: TranslationOutcome, *, index: int = 0) -> Finding:
    emitted = outcome in {
        TranslationOutcome.EMITTED, TranslationOutcome.STRENGTHENED,
        TranslationOutcome.FUNCTIONAL_FALLBACK,
    }
    candidate = "out = lhs + rhs;" if emitted else ""
    finding = Finding(
        fragment=AsmFragment(id=f"fragment:{index}", rawAsmText="add %0,%1,%2"),
        translationOutcome=outcome.value,
        validationOutcome=(
            ValidationOutcome.FAILED.value if emitted
            else ValidationOutcome.NOT_RUN.value
        ),
        publicationOutcome=(
            PublicationOutcome.WITHHELD.value if emitted
            else PublicationOutcome.NOT_REQUESTED.value
        ),
        approvalArtifact={
            "sourceModelId": "source:model", "preservationDecisionId": "preserve:1",
            "planId": "plan:1", "constraintsId": "constraints:1",
            "proofStatus": "approved", "targetEnvironmentId": "target:1",
            "targetCatalogVersion": "catalog:1", "rendererId": "renderer:1",
            "rendererVersion": "1", "rendererContractId": "renderer-contract:1",
            "rendererRegistryId": "renderer-registry:1",
            "rendererRegistryVersion": "1",
        } if emitted else {},
    )
    finding.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id=f"fragment:{index}",
        candidate_kind="c" if emitted else outcome.value,
        candidate_route="phase6f_rendered" if emitted else "",
        candidate_replacement=candidate,
        candidate_rule_name="phase6.lower_to_c" if emitted else "",
        translation_outcome=outcome,
        validation_outcome=finding.validationOutcome,
        publication_outcome=finding.publicationOutcome,
        reason_codes=("evaluation.example",),
    )
    return finding


@pytest.mark.parametrize("outcome", tuple(TranslationOutcome))
def test_every_terminal_translation_outcome_is_archived(outcome):
    finding = _finding(outcome)
    attempt = terminal_attempt_from_finding(finding, 0)
    restored = translation_attempt_from_dict(attempt.to_dict())

    assert restored.translation_outcome is outcome
    assert restored.artifact_id == attempt.artifact_id
    assert restored.candidate_replacement == (
        "out = lhs + rhs;" if outcome in {
            TranslationOutcome.EMITTED, TranslationOutcome.STRENGTHENED,
            TranslationOutcome.FUNCTIONAL_FALLBACK,
        } else ""
    )


def test_emitted_attempt_binds_plan_proof_and_renderer():
    attempt = terminal_attempt_from_finding(_finding(TranslationOutcome.EMITTED), 0)
    assert attempt.binding_complete
    assert attempt.plan_id == "plan:1"
    assert attempt.constraints_id == "constraints:1"
    assert attempt.proof_status == "approved"
    assert attempt.proof_binding_identity.startswith("sha256:")
    assert attempt.renderer_contract_id == "renderer-contract:1"


def test_archive_round_trip_is_content_addressed(tmp_path):
    attempts = tuple(
        terminal_attempt_from_finding(_finding(outcome, index=index), index)
        for index, outcome in enumerate((
            TranslationOutcome.EMITTED, TranslationOutcome.UNSUPPORTED,
            TranslationOutcome.NEEDS_ROUTE, TranslationOutcome.KEEP,
            TranslationOutcome.FAILED,
        ))
    )
    path = tmp_path / "attempts.json"
    archive = save_translation_attempt_archive(attempts, path)
    restored = load_translation_attempt_archive(path)

    assert restored.archive_id == archive.archive_id
    assert len(restored.attempts) == 5
    assert len({item.finding_id for item in restored.attempts}) == 5


def test_archive_rejects_duplicate_finding_attempt():
    attempt = terminal_attempt_from_finding(_finding(TranslationOutcome.UNSUPPORTED), 0)
    with pytest.raises(ValueError, match="more than one attempt"):
        TranslationAttemptArchive((attempt, attempt))


def test_empty_generic_c_report_has_a_valid_empty_archive(tmp_path):
    path = tmp_path / "attempts.json"
    archive = save_translation_attempt_archive((), path)
    assert archive.attempts == ()
    assert load_translation_attempt_archive(path).archive_id == archive.archive_id


def test_parser_rejects_candidate_or_artifact_tampering():
    attempt = terminal_attempt_from_finding(_finding(TranslationOutcome.EMITTED), 0)
    payload = attempt.to_dict()
    payload["candidateReplacement"] = "tampered();"
    with pytest.raises(ValueError, match="candidate replacement digest"):
        translation_attempt_from_dict(payload)

    archive = TranslationAttemptArchive((attempt,)).to_dict()
    archive["archiveId"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="archive ID"):
        translation_attempt_archive_from_dict(archive)


def test_parser_rejects_noncanonical_reason_codes():
    attempt = terminal_attempt_from_finding(_finding(TranslationOutcome.EMITTED), 0)
    payload = attempt.to_dict()
    payload["reasonCodes"] = ["z", "a", "a"]
    with pytest.raises(ValueError, match="canonically sorted"):
        translation_attempt_from_dict(payload)
