import json
from pathlib import Path

import pytest

from riscv2x86_py.candidate_materialization import (
    load_candidate_artifact_manifest, materialize_candidate_tree,
    verify_candidate_artifact_manifest,
)
from riscv2x86_py.schema import (
    AsmFragment, Finding, PublicationOutcome, TranslationOutcome,
    ValidationOutcome, make_translation_attempt_artifact, save_report,
)
from riscv2x86_py.translation_attempt import (
    save_translation_attempt_archive, terminal_attempt_from_finding,
)


SOURCE = b"int f(int lhs, int rhs) { int out; asm(\"add %0,%1,%2\"); return out; }\n"
ASM = b'asm("add %0,%1,%2")'
CANDIDATE = "out = lhs + rhs;"


def _artifacts(tmp_path: Path, *, outcome=TranslationOutcome.EMITTED):
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "test.c"
    source_file.write_bytes(SOURCE)
    begin = SOURCE.index(ASM)
    end = begin + len(ASM)
    emitted = outcome in {
        TranslationOutcome.EMITTED, TranslationOutcome.STRENGTHENED,
        TranslationOutcome.FUNCTIONAL_FALLBACK,
    }
    candidate = CANDIDATE if emitted else ""
    finding = Finding(
        fileName="test.c", hasRewriteRange=True,
        rewriteBeginOffset=begin, rewriteEndOffset=end,
        rawSourceText=ASM.decode(), suggestedReplacement="",
        fragment=AsmFragment(
            id="fragment:0", fileName="test.c", beginOffset=begin,
            endOffset=end, rawAsmText="add %0,%1,%2",
        ),
        translationOutcome=outcome.value,
        validationOutcome=(ValidationOutcome.FAILED.value if emitted else ValidationOutcome.NOT_RUN.value),
        publicationOutcome=(PublicationOutcome.WITHHELD.value if emitted else PublicationOutcome.NOT_REQUESTED.value),
        approvalArtifact={
            "sourceModelId": "source:model", "preservationDecisionId": "preserve:1",
            "planId": "plan:1", "constraintsId": "constraints:1",
            "proofStatus": "approved", "targetEnvironmentId": "target:1",
            "targetCatalogVersion": "catalog:1", "rendererId": "renderer:1",
            "rendererVersion": "1", "rendererContractId": "renderer-contract:1",
            "rendererRegistryId": "renderer-registry:1", "rendererRegistryVersion": "1",
            "requiredHeaders": ["stdint.h"],
        } if emitted else {},
    )
    finding.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id="fragment:0", candidate_kind="c" if emitted else outcome.value,
        candidate_route="phase6f_rendered" if emitted else "",
        candidate_replacement=candidate,
        candidate_rule_name="phase6.lower_to_c" if emitted else "",
        translation_outcome=outcome,
        validation_outcome=finding.validationOutcome,
        publication_outcome=finding.publicationOutcome,
        reason_codes=("evaluation.example",),
    )
    report = tmp_path / "translated.json"
    archive = tmp_path / "attempts.json"
    save_report([finding], str(report))
    save_translation_attempt_archive((terminal_attempt_from_finding(finding, 0),), archive)
    return source, source_file, report, archive


def _materialize(tmp_path: Path, **kwargs):
    source, source_file, report, archive = _artifacts(tmp_path, **kwargs)
    staging = tmp_path / "staging"
    manifest_path = tmp_path / "candidate-manifest.json"
    manifest = materialize_candidate_tree(
        source_root=source, staging_root=staging, translated_report=report,
        attempt_archive=archive, manifest_output=manifest_path,
    )
    return source, source_file, report, archive, staging, manifest_path, manifest


def test_withheld_candidate_is_materialized_and_content_bound(tmp_path):
    source, source_file, report, archive, staging, manifest_path, manifest = _materialize(tmp_path)

    assert source_file.read_bytes() == SOURCE
    target = (staging / "test.c").read_text()
    assert '#include <stdint.h>\n' in target
    assert CANDIDATE in target
    assert "asm(" not in target
    assert len(manifest.edits) == 1
    assert manifest.source_tree_digest != manifest.target_tree_digest
    assert manifest.edits[0].attempt_artifact_id.startswith("sha256:")
    assert manifest.edits[0].binding_complete

    restored = load_candidate_artifact_manifest(manifest_path)
    assert restored.manifest_id == manifest.manifest_id
    verify_candidate_artifact_manifest(
        restored, source_root=source, staging_root=staging,
        translated_report=report, attempt_archive=archive,
    )


def test_non_emitted_attempt_is_archived_without_candidate_edit(tmp_path):
    source, source_file, report, archive, staging, _path, manifest = _materialize(
        tmp_path, outcome=TranslationOutcome.UNSUPPORTED,
    )
    assert (staging / "test.c").read_bytes() == source_file.read_bytes()
    assert manifest.edits == ()
    assert manifest.source_tree_digest == manifest.target_tree_digest
    verify_candidate_artifact_manifest(
        manifest, source_root=source, staging_root=staging,
        translated_report=report, attempt_archive=archive,
    )


def test_stale_source_fails_closed_and_removes_partial_outputs(tmp_path):
    source, source_file, report, archive = _artifacts(tmp_path)
    source_file.write_bytes(SOURCE.replace(b"add", b"sub"))
    staging = tmp_path / "staging"
    manifest = tmp_path / "candidate-manifest.json"
    with pytest.raises(ValueError, match="source slice is stale"):
        materialize_candidate_tree(
            source_root=source, staging_root=staging, translated_report=report,
            attempt_archive=archive, manifest_output=manifest,
        )
    assert not staging.exists()
    assert not manifest.exists()


def test_existing_or_overlapping_staging_tree_is_never_overwritten(tmp_path):
    source, _source_file, report, archive = _artifacts(tmp_path)
    manifest = tmp_path / "candidate-manifest.json"
    staging = tmp_path / "existing"
    staging.mkdir()
    sentinel = staging / "keep"
    sentinel.write_text("do not overwrite")
    with pytest.raises(ValueError, match="already exists"):
        materialize_candidate_tree(
            source_root=source, staging_root=staging, translated_report=report,
            attempt_archive=archive, manifest_output=manifest,
        )
    assert sentinel.read_text() == "do not overwrite"

    with pytest.raises(ValueError, match="must not overlap"):
        materialize_candidate_tree(
            source_root=source, staging_root=source / "nested",
            translated_report=report, attempt_archive=archive,
            manifest_output=manifest,
        )


def test_second_hash_verification_rejects_target_tampering(tmp_path):
    source, _source_file, report, archive, staging, manifest_path, manifest = _materialize(tmp_path)
    (staging / "test.c").write_text("tampered\n")
    with pytest.raises(ValueError, match="target tree binding mismatch"):
        verify_candidate_artifact_manifest(
            manifest, source_root=source, staging_root=staging,
            translated_report=report, attempt_archive=archive,
        )


def test_manifest_parser_rejects_identity_tampering(tmp_path):
    *_rest, manifest_path, _manifest = _materialize(tmp_path)
    payload = json.loads(manifest_path.read_text())
    payload["targetTreeDigest"] = "sha256:" + "0" * 64
    manifest_path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="manifest ID"):
        load_candidate_artifact_manifest(manifest_path)


def test_selected_candidate_materialization_is_explicit_and_fail_closed(tmp_path):
    source, _source_file, report, archive = _artifacts(tmp_path)
    archived = json.loads(archive.read_text())
    attempt_id = archived["attempts"][0]["artifactId"]
    manifest = materialize_candidate_tree(
        source_root=source, staging_root=tmp_path / "selected",
        translated_report=report, attempt_archive=archive,
        manifest_output=tmp_path / "selected.json",
        selected_attempt_ids=(attempt_id,),
    )
    assert [item.attempt_artifact_id for item in manifest.edits] == [attempt_id]

    with pytest.raises(ValueError, match="absent"):
        materialize_candidate_tree(
            source_root=source, staging_root=tmp_path / "unknown",
            translated_report=report, attempt_archive=archive,
            manifest_output=tmp_path / "unknown.json",
            selected_attempt_ids=("sha256:" + "f" * 64,),
        )
