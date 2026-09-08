from hashlib import sha256
import json
from pathlib import Path

import pytest

from riscv2x86_py.candidate_materialization import materialize_candidate_tree
from riscv2x86_py.evaluation import persist_evaluation_result
from riscv2x86_py.schema import (
    AsmFragment, Finding, PublicationOutcome, TranslationOutcome,
    ValidationOutcome, make_translation_attempt_artifact, save_report,
)
from riscv2x86_py.translation_attempt import (
    save_translation_attempt_archive, terminal_attempt_from_finding,
)
from riscv2x86_py.translation_validation import (
    ProgramArtifact, TargetEnvironment, TranslationArtifact,
    ValidationLayerResult, ValidationLevel, ValidationPlan, ValidationProfile,
    _result as rebuild_validation_result,
)
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus
from riscv2x86_py.writeback_promotion import promote_evaluated_staging


SOURCE = b'int f(int a){int out; asm("addi %0,%1,1"); return out;}\n'
ASM = b'asm("addi %0,%1,1")'


def _sha(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _setup(tmp_path: Path, *, evaluation_status="verified"):
    source = tmp_path / "source"
    source.mkdir(parents=True)
    (source / "case.c").write_bytes(SOURCE)
    begin, end = SOURCE.index(ASM), SOURCE.index(ASM) + len(ASM)
    approval = {
        "sourceModelId": "source-model", "preservationDecisionId": "preservation",
        "planId": "translation-plan", "constraintsId": "constraints",
        "proofStatus": "approved", "targetEnvironmentId": "environment",
        "targetCatalogVersion": "catalog", "rendererId": "renderer",
        "rendererVersion": "1", "rendererContractId": "renderer-contract",
        "rendererRegistryId": "renderer-registry", "rendererRegistryVersion": "1",
    }
    finding = Finding(
        fileName="case.c", hasRewriteRange=True, rewriteBeginOffset=begin,
        rewriteEndOffset=end, rawSourceText=ASM.decode(), suggestedReplacement="",
        fragment=AsmFragment(id="fragment:0", fileName="case.c", beginOffset=begin,
                             endOffset=end, rawAsmText="addi %0,%1,1"),
        translationOutcome="emitted", validationOutcome="verified",
        publicationOutcome=PublicationOutcome.WITHHELD.value,
        approvalArtifact=approval,
    )
    finding.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id="fragment:0", candidate_kind="c", candidate_route="phase6f_rendered",
        candidate_replacement="out = a + 1;", candidate_rule_name="integer.addi",
        translation_outcome=TranslationOutcome.EMITTED,
        validation_outcome=ValidationOutcome.VERIFIED,
        publication_outcome=PublicationOutcome.WITHHELD,
    )
    report, archive_path = tmp_path / "report.json", tmp_path / "attempts.json"
    save_report([finding], str(report))
    attempt = terminal_attempt_from_finding(finding, 0)
    save_translation_attempt_archive((attempt,), archive_path)
    staging, manifest_path = tmp_path / "staging", tmp_path / "candidate-manifest.json"
    manifest = materialize_candidate_tree(
        source_root=source, staging_root=staging, translated_report=report,
        attempt_archive=archive_path, manifest_output=manifest_path,
    )
    translation_dict = {
        "fragment_id": "fragment:0", "source_model_identity": "source-model",
        "translation_plan_id": "translation-plan", "constraint_id": "constraints",
        "proof_identity": _sha(b"proof"),
        "preservation_mode": "architecture_equivalent",
        "shell_facts_identity": _sha(b"shell"),
        "runtime_contract_id": "runtime", "runtime_contract_version": "v1",
        "recipe_id": "recipe", "ignored_source_state": [],
        "semantic_class": "integer", "target_route": "c",
    }
    translation = TranslationArtifact(
        "fragment:0", "source-model", "translation-plan", "constraints",
        _sha(b"proof"), PreservationMode.ARCHITECTURE_EQUIVALENT,
        _sha(b"shell"), "runtime", "v1", "recipe", (), "integer", "c",
    )
    plan = ValidationPlan("evaluation-plan", ValidationProfile.ARCHITECTURAL,
                          "qemu", "native", 7, 10, "registry-v1")
    environment = TargetEnvironment(
        "environment", "rv64gc", "lp64d", "x86_64", "sysv_amd64",
        ("qemu",), ("native",), ("none",), "runtime", "loader",
    )
    source_program = ProgramArtifact("source", "/tmp/source.o", "object", _sha(b"source"), "build-source")
    target_program = ProgramArtifact("target", "/tmp/target", "executable", _sha(b"target"), "build-target")
    layers = tuple(ValidationLayerResult(
        ValidationLevel(level), ValidationStatus.VERIFIED,
        _sha(("evidence:" + level).encode()), "",
    ) for level in ("L0", "L1", "L2"))
    validation = rebuild_validation_result(
        status=ValidationStatus.VERIFIED, plan=plan, layers=layers, reasons=(),
        translation_artifact=translation, source_program_artifact=source_program,
        target_program_artifact=target_program,
        target_environment=environment.to_dict(),
        comparison_policy="riscv2x86.comparison-policy.none.v1",
    ).to_dict()
    attempt_result = {
        "findingId": attempt.finding_id, "fragmentId": attempt.fragment_id,
        "attemptArtifactId": attempt.artifact_id, "translationOutcome": "emitted",
        "status": evaluation_status, "validation": validation,
        "translationArtifact": translation_dict, "reasonCodes": [], "replayArtifacts": [],
    }
    payload = {
        "schemaVersion": "riscv2x86.evaluation-result.v1",
        "requestIdentity": _sha(b"request"), "status": evaluation_status,
        "reasonCodes": [], "candidateManifestId": manifest.manifest_id,
        "attempts": [attempt_result], "commands": [],
        "replayArtifact": "replay/evaluation-replay.json",
        "validationPlan": {
            "schemaVersion": plan.schema_version, "planId": plan.plan_id,
            "profile": plan.profile.value, "sourceRunner": plan.source_runner,
            "targetRunner": plan.target_runner, "seed": plan.seed,
            "timeoutSeconds": plan.timeout_seconds,
            "runtimeRegistryVersion": plan.runtime_registry_version,
            "experimentContractId": plan.experiment_contract_id,
        },
        "targetEnvironment": environment.to_dict(),
        "sourceProgramArtifact": {
            "artifact_id": source_program.artifact_id, "artifact_path": source_program.artifact_path,
            "artifact_kind": source_program.artifact_kind,
            "artifact_digest": source_program.artifact_digest,
            "build_identity": source_program.build_identity,
        },
        "targetProgramArtifact": {
            "artifact_id": target_program.artifact_id, "artifact_path": target_program.artifact_path,
            "artifact_kind": target_program.artifact_kind,
            "artifact_digest": target_program.artifact_digest,
            "build_identity": target_program.build_identity,
        },
        "comparisonPolicy": "riscv2x86.comparison-policy.none.v1",
    }
    identity_payload = dict(payload)
    identity_payload.pop("replayArtifact")
    payload["evaluationIdentity"] = _sha(_canonical(identity_payload))
    evaluation_path = tmp_path / "evaluation-result.json"
    persist_evaluation_result(payload, evaluation_path)
    return source, staging, report, archive_path, manifest_path, evaluation_path, payload


def test_verified_evaluation_is_atomically_promoted(tmp_path):
    source, staging, report, archive, manifest, evaluation, _payload = _setup(tmp_path)
    final = tmp_path / "final"
    result = promote_evaluated_staging(
        evaluation_result=evaluation, candidate_manifest=manifest,
        source_root=source, staging_root=staging, translated_report=report,
        attempt_archive=archive, final_output=final,
    )
    assert result["promoted"]
    assert result["reasonCode"] == ""
    assert (final / "case.c").read_bytes() == (staging / "case.c").read_bytes()
    assert (source / "case.c").read_bytes() == SOURCE
    assert staging.is_dir() and evaluation.is_file()
    assert not list(tmp_path.glob("final.promotion-*"))


def test_rejected_evaluation_preserves_staging_and_evidence(tmp_path):
    source, staging, report, archive, manifest, evaluation, _payload = _setup(
        tmp_path, evaluation_status="failed",
    )
    before = (staging / "case.c").read_bytes()
    final = tmp_path / "final"
    result = promote_evaluated_staging(
        evaluation_result=evaluation, candidate_manifest=manifest,
        source_root=source, staging_root=staging, translated_report=report,
        attempt_archive=archive, final_output=final,
    )
    assert not result["promoted"]
    assert result["reasonCode"] == "promotion.evaluation-not-verified"
    assert not final.exists()
    assert (staging / "case.c").read_bytes() == before
    assert evaluation.is_file()


def test_tampered_evaluation_or_staging_cannot_be_promoted(tmp_path):
    source, staging, report, archive, manifest, evaluation, payload = _setup(tmp_path)
    payload["attempts"][0]["status"] = "failed"
    evaluation.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="identity does not match"):
        promote_evaluated_staging(
            evaluation_result=evaluation, candidate_manifest=manifest,
            source_root=source, staging_root=staging, translated_report=report,
            attempt_archive=archive, final_output=tmp_path / "final",
        )
    assert staging.is_dir()

    # Restore a valid evaluation, then mutate staging after its manifest was signed.
    source, staging, report, archive, manifest, evaluation, _ = _setup(tmp_path / "second")
    (staging / "case.c").write_text("tampered\n")
    with pytest.raises(ValueError, match="target tree binding mismatch"):
        promote_evaluated_staging(
            evaluation_result=evaluation, candidate_manifest=manifest,
            source_root=source, staging_root=staging, translated_report=report,
            attempt_archive=archive, final_output=tmp_path / "second-final",
        )
    assert evaluation.is_file() and staging.is_dir()


def test_existing_final_output_is_not_overwritten(tmp_path):
    source, staging, report, archive, manifest, evaluation, _ = _setup(tmp_path)
    final = tmp_path / "final"
    final.mkdir()
    marker = final / "owner-data"
    marker.write_text("keep")
    result = promote_evaluated_staging(
        evaluation_result=evaluation, candidate_manifest=manifest,
        source_root=source, staging_root=staging, translated_report=report,
        attempt_archive=archive, final_output=final,
    )
    assert not result["promoted"]
    assert result["reasonCode"] == "promotion.final-output-exists"
    assert marker.read_text() == "keep"


def test_fabricated_validation_identity_is_rejected_even_with_rehashed_evaluation(tmp_path):
    source, staging, report, archive, manifest, evaluation, payload = _setup(tmp_path)
    payload["attempts"][0]["validation"]["validationIdentity"] = _sha(b"fabricated")
    identity_payload = dict(payload)
    identity_payload.pop("evaluationIdentity")
    identity_payload.pop("replayArtifact")
    payload["evaluationIdentity"] = _sha(_canonical(identity_payload))
    evaluation.write_text(json.dumps(payload))
    final = tmp_path / "final"
    result = promote_evaluated_staging(
        evaluation_result=evaluation, candidate_manifest=manifest,
        source_root=source, staging_root=staging, translated_report=report,
        attempt_archive=archive, final_output=final,
    )
    assert not result["promoted"]
    assert result["reasonCode"] == "promotion.validation-identity-binding-invalid"
    assert not final.exists() and staging.is_dir() and evaluation.is_file()
