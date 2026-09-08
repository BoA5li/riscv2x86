import json
from dataclasses import replace
from pathlib import Path
import sys

import pytest

from riscv2x86_py.evaluation import (
    EVALUATION_REQUEST_SCHEMA, evaluation_request_from_dict,
    persist_evaluation_result, run_evaluation,
)
from riscv2x86_py.schema import (
    AsmFragment, Finding, PublicationOutcome, TranslationOutcome,
    ValidationOutcome, make_translation_attempt_artifact, save_report,
)
from riscv2x86_py.translation_attempt import (
    save_translation_attempt_archive, terminal_attempt_from_finding,
)
from riscv2x86_py.translation_validation import (
    TARGET_ENVIRONMENT_SCHEMA, TRANSLATION_VALIDATION_VERSION,
    VALIDATION_PLAN_SCHEMA, TranslationValidationResult, ValidationProfile,
)
from riscv2x86_py.validation_runtime_registry import VALIDATION_RUNTIME_REGISTRY_SCHEMA
from riscv2x86_py.validation_status import ValidationStatus


SOURCE = b'int f(int a){int out; asm("addi %0,%1,1"); return out;}\n'
ASM = b'asm("addi %0,%1,1")'


def _setup(tmp_path: Path, *, target_build_success=True):
    source = tmp_path / "source"
    source.mkdir()
    (source / "case.c").write_bytes(SOURCE)
    begin, end = SOURCE.index(ASM), SOURCE.index(ASM) + len(ASM)
    finding = Finding(
        fileName="case.c", hasRewriteRange=True, rewriteBeginOffset=begin,
        rewriteEndOffset=end, rawSourceText=ASM.decode(), suggestedReplacement="",
        fragment=AsmFragment(id="fragment:0", fileName="case.c", beginOffset=begin,
                             endOffset=end, rawAsmText="addi %0,%1,1"),
        translationOutcome=TranslationOutcome.EMITTED.value,
        validationOutcome=ValidationOutcome.FAILED.value,
        publicationOutcome=PublicationOutcome.WITHHELD.value,
    )
    finding.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id="fragment:0", candidate_kind="c", candidate_route="phase6f_rendered",
        candidate_replacement="out = a + 1;", candidate_rule_name="integer.addi",
        translation_outcome=TranslationOutcome.EMITTED,
        validation_outcome=ValidationOutcome.FAILED,
        publication_outcome=PublicationOutcome.WITHHELD,
        reason_codes=("publication.validation-failed",),
    )
    report, archive = tmp_path / "report.json", tmp_path / "attempts.json"
    save_report([finding], str(report))
    attempt = terminal_attempt_from_finding(finding, 0)
    save_translation_attempt_archive((attempt,), archive)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schemaVersion": VALIDATION_PLAN_SCHEMA, "planId": "evaluation-plan-v1",
        "profile": "architectural", "sourceRunner": "qemu", "targetRunner": "native",
        "seed": 7, "timeoutSeconds": 10, "runtimeRegistryVersion": "evaluation-registry-v1",
        "experimentContractId": "",
    }))
    environment = tmp_path / "environment.json"
    environment.write_text(json.dumps({
        "schemaVersion": TARGET_ENVIRONMENT_SCHEMA, "environmentId": "test-env",
        "sourceIsa": "rv64gc", "sourceAbi": "lp64d", "targetIsa": "x86_64",
        "targetAbi": "sysv_amd64", "sourceRunnerCapabilities": ["qemu"],
        "targetRunnerCapabilities": ["native"], "sanitizerCapabilities": ["none"],
        "runtimeIdentity": "runtime-v1", "loaderIdentity": "loader-v1",
    }))
    pycopy = "from pathlib import Path;Path(r'${OUTPUT}').write_bytes(Path(r'${SOURCE_PATH}').read_bytes())"
    if not target_build_success:
        target_command = ["definitely-unavailable-e3-compiler", "${TARGET_PATH}"]
    else:
        target_command = ["python", "-c", pycopy.replace("SOURCE_PATH", "TARGET_PATH")]
    request = evaluation_request_from_dict({
        "schemaVersion": EVALUATION_REQUEST_SCHEMA, "sourceRoot": str(source),
        "sourceRelativePath": "case.c", "targetRelativePath": "case.c",
        "translatedReport": str(report), "attemptArchive": str(archive),
        "validationPlan": str(plan), "targetEnvironment": str(environment),
        "runtimeRegistryTemplate": {
            "schemaVersion": VALIDATION_RUNTIME_REGISTRY_SCHEMA,
            "version": "evaluation-registry-v1", "validators": {},
        },
        "translationArtifacts": {attempt.finding_id: {
            "fragment_id": "fragment:0", "source_model_identity": "source-model-v1",
            "translation_plan_id": "translation-plan-v1", "constraint_id": "constraint-v1",
            "proof_identity": "sha256:" + "1" * 64,
            "preservation_mode": "architecture_equivalent",
            "shell_facts_identity": "sha256:" + "2" * 64,
            "runtime_contract_id": "runtime-contract", "runtime_contract_version": "v1",
            "recipe_id": "recipe-v1", "ignored_source_state": [],
            "semantic_class": "integer", "target_route": "c",
        }},
        "sourceBuild": {"artifactId": "source", "artifactKind": "object",
                        "outputRelativePath": "build/source.o",
                        "command": ["python", "-c", pycopy]},
        "targetBuild": {"artifactId": "target", "artifactKind": "executable",
                        "outputRelativePath": "build/target", "command": target_command},
        "translationCommand": [],
        "comparisonPolicy": "riscv2x86.comparison-policy.none.v1",
    })
    return request, source, attempt


def test_end_to_end_materializes_and_builds_without_prebuilt_target(tmp_path):
    request, source, attempt = _setup(tmp_path)
    work = tmp_path / "evaluation"
    result = run_evaluation(request, work_directory=work)

    assert (source / "case.c").read_bytes() == SOURCE
    assert not (tmp_path / "target").exists()
    assert "out = a + 1;" in (work / "candidate-staging" / "case.c").read_text()
    assert (work / "build" / "target").is_file()
    assert result["status"] == "inconclusive"  # L0 runner intentionally absent.
    assert result["candidateManifestId"].startswith("sha256:")
    assert result["attempts"][0]["attemptArtifactId"] == attempt.artifact_id
    assert result["attempts"][0]["reasonCodes"] == ["validation.layer-runner-missing:L0"]
    assert (work / result["replayArtifact"]).is_file()


def test_unavailable_build_tool_is_persisted_as_inconclusive(tmp_path):
    request, _source, attempt = _setup(tmp_path, target_build_success=False)
    work = tmp_path / "evaluation"
    result = run_evaluation(request, work_directory=work)
    output = tmp_path / "evaluation-result.json"
    persist_evaluation_result(result, output)
    restored = json.loads(output.read_text())

    assert restored["status"] == "inconclusive"
    assert restored["reasonCodes"] == ["evaluation.build-not-verified"]
    assert restored["attempts"][0]["attemptArtifactId"] == attempt.artifact_id
    assert restored["attempts"][0]["validation"] is None
    assert restored["commands"][-1]["status"] == "inconclusive"
    assert (work / "replay" / "evaluation-replay.json").is_file()


def test_translation_command_produces_report_and_archive_in_one_run(tmp_path):
    request, _source, _attempt = _setup(tmp_path)
    report_seed, archive_seed = tmp_path / "report-seed.json", tmp_path / "archive-seed.json"
    Path(request.translated_report).replace(report_seed)
    Path(request.attempt_archive).replace(archive_seed)
    script = (
        "from pathlib import Path;"
        f"Path(r'${{TRANSLATED_REPORT}}').write_bytes(Path(r'{report_seed}').read_bytes());"
        f"Path(r'${{ATTEMPT_ARCHIVE}}').write_bytes(Path(r'{archive_seed}').read_bytes())"
    )
    request = replace(
        request, translated_report="translated-report.json", attempt_archive="attempts.json",
        translation_command=(sys.executable, "-c", script),
    )
    work = tmp_path / "evaluation"
    result = run_evaluation(request, work_directory=work)

    assert result["commands"][0]["phase"] == "translation"
    assert result["commands"][0]["status"] == "verified"
    assert (work / "translated-report.json").is_file()
    assert (work / "attempts.json").is_file()
    assert (work / "candidate-staging" / "case.c").is_file()
    assert (work / "build" / "target").is_file()


def test_request_schema_and_work_tree_are_fail_closed(tmp_path):
    request, source, _attempt = _setup(tmp_path)
    malformed = dict(request.__dict__)
    assert request.source_relative_path == "case.c"
    with pytest.raises(ValueError, match="safe relative"):
        evaluation_request_from_dict({
            "schemaVersion": EVALUATION_REQUEST_SCHEMA, "sourceRoot": str(source),
            "sourceRelativePath": "../escape.c", "targetRelativePath": "case.c",
            "translatedReport": "r", "attemptArchive": "a", "validationPlan": "p",
            "targetEnvironment": "e", "runtimeRegistryTemplate": {},
            "translationArtifacts": {},
            "sourceBuild": {"artifactId": "s", "artifactKind": "object",
                            "outputRelativePath": "s.o", "command": ["cc"]},
            "targetBuild": {"artifactId": "t", "artifactKind": "executable",
                            "outputRelativePath": "t", "command": ["cc"]},
            "translationCommand": [], "comparisonPolicy": "policy",
        })
    with pytest.raises(ValueError, match="already exists"):
        existing = tmp_path / "existing"
        existing.mkdir()
        run_evaluation(request, work_directory=existing)
    nested = source / "must-not-be-created"
    with pytest.raises(ValueError, match="must not overlap"):
        run_evaluation(request, work_directory=nested)
    assert not nested.exists()
