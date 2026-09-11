import json
from dataclasses import replace
from pathlib import Path
import sys

import pytest

from riscv2x86_py.evaluation import (
    EVALUATION_REQUEST_SCHEMA, evaluation_request_from_dict,
    persist_evaluation_result, run_evaluation,
)
from riscv2x86_py.corpus_evaluation_cli import run_corpus_execution
from riscv2x86_py.paper_evaluation import PAPER_EXECUTION_SCHEMA
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
        target_command = [
            sys.executable,
            "-c",
            pycopy.replace("SOURCE_PATH", "TARGET_PATH"),
        ]
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
                        "command": [sys.executable, "-c", pycopy]},
        "targetBuild": {"artifactId": "target", "artifactKind": "executable",
                        "outputRelativePath": "build/target", "command": target_command},
        "translationCommand": [],
        "comparisonPolicy": "riscv2x86.comparison-policy.none.v1",
        "validationUnit": "program", "validationGroupId": "", "selectedAttemptIds": [],
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
    linkage = result["translationEvaluationLink"]
    assert linkage["schemaVersion"] == "riscv2x86.translation-evaluation-link.v1"
    assert linkage["translatedReportDigest"].startswith("sha256:")
    assert linkage["attemptArchiveDigest"].startswith("sha256:")
    joined = linkage["findings"][0]
    assert joined["findingId"] == attempt.finding_id
    assert joined["translationOutcome"] == "emitted"
    assert joined["finalEvaluationStatus"] == "inconclusive"
    assert joined["completedLevels"] == []
    assert joined["levelStatus"] == {
        "L0": "inconclusive", "L1": "not_run", "L2": "not_run", "L3": "not_run",
    }


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
            "validationUnit": "program", "validationGroupId": "", "selectedAttemptIds": [],
        })
    with pytest.raises(ValueError, match="already exists"):
        existing = tmp_path / "existing"
        existing.mkdir()
        run_evaluation(request, work_directory=existing)
    nested = source / "must-not-be-created"
    with pytest.raises(ValueError, match="must not overlap"):
        run_evaluation(request, work_directory=nested)
    assert not nested.exists()


def test_single_candidate_evaluation_records_attribution_and_provenance(tmp_path):
    request, _source, attempt = _setup(tmp_path)
    request = replace(
        request, validation_unit="single_candidate", validation_group_id="fragment-group-0",
        selected_attempt_ids=(attempt.artifact_id,),
    )
    result = run_evaluation(request, work_directory=tmp_path / "single-evaluation")

    assert result["validationUnit"] == "single_candidate"
    assert result["validationGroupId"] == "fragment-group-0"
    assert result["selectedAttemptIds"] == [attempt.artifact_id]
    assert result["environmentProvenance"]["schemaVersion"] == "riscv2x86.environment-provenance.v1"
    assert result["environmentProvenance"]["kernel"]
    assert result["environmentProvenance"]["sourceBuildCommand"]


def test_grouping_contract_rejects_ambiguous_or_noncanonical_selection(tmp_path):
    request, _source, attempt = _setup(tmp_path)
    with pytest.raises(ValueError, match="exactly one"):
        replace(request, validation_unit="single_candidate", validation_group_id="g",
                selected_attempt_ids=())
    with pytest.raises(ValueError, match="unique and sorted"):
        replace(request, validation_unit="group", validation_group_id="g",
                selected_attempt_ids=(attempt.artifact_id, attempt.artifact_id))


def test_corpus_runner_generates_requests_manifest_evidence_and_report(tmp_path):
    request, source, attempt = _setup(tmp_path)
    request = replace(request, validation_unit="single_candidate", validation_group_id="g0",
                      selected_attempt_ids=(attempt.artifact_id,))
    request_value = {
        "schemaVersion": request.schema_version, "sourceRoot": request.source_root,
        "sourceRelativePath": request.source_relative_path, "targetRelativePath": request.target_relative_path,
        "translatedReport": request.translated_report, "attemptArchive": request.attempt_archive,
        "validationPlan": request.validation_plan, "targetEnvironment": request.target_environment,
        "runtimeRegistryTemplate": request.runtime_registry_template,
        "translationArtifacts": request.translation_artifacts,
        "sourceBuild": {"artifactId": request.source_build.artifact_id,
                        "artifactKind": request.source_build.artifact_kind,
                        "outputRelativePath": request.source_build.output_relative_path,
                        "command": list(request.source_build.command)},
        "targetBuild": {"artifactId": request.target_build.artifact_id,
                        "artifactKind": request.target_build.artifact_kind,
                        "outputRelativePath": request.target_build.output_relative_path,
                        "command": list(request.target_build.command)},
        "translationCommand": list(request.translation_command),
        "comparisonPolicy": request.comparison_policy, "validationUnit": request.validation_unit,
        "validationGroupId": request.validation_group_id,
        "selectedAttemptIds": list(request.selected_attempt_ids),
    }
    begin, end = SOURCE.index(ASM), SOURCE.index(ASM) + len(ASM)
    oracle_facts = {"fragmentId": "fragment:0", "relativePath": "case.c",
                    "beginOffset": begin, "endOffset": end,
                    "sourceSliceDigest": "sha256:" + __import__("hashlib").sha256(ASM).hexdigest(),
                    "category": "integer", "subcategory": "scalar",
                    "requiredDimensions": ["operand", "shell"]}
    oracle_id = "sha256:" + __import__("hashlib").sha256(json.dumps(
        oracle_facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    plan = {
        "schemaVersion": PAPER_EXECUTION_SCHEMA,
        "corpus": {"corpusId": "pilot", "corpusVersion": "1",
                   "bootstrap": {"seed": 7, "resamples": 100, "confidenceLevel": 0.95},
                   "programs": [{"programId": "program-0", "category": "integer",
                                 "oracleFragments": [{"oracleFragmentId": oracle_id, **oracle_facts}],
                                 "validations": [{"evaluationId": "eval-0", "unit": "single_candidate",
                                     "groupId": "g0", "oracleFragmentIds": [oracle_id],
                                     "expectedEnvironmentId": "test-env"}]}]},
        "evaluations": [{"evaluationId": "eval-0", "request": request_value,
                         "workDirectory": "work/eval-0", "resultPath": "results/eval-0.json"}],
    }
    plan_path = tmp_path / "corpus-plan.json"; plan_path.write_text(json.dumps(plan))
    output = tmp_path / "corpus-run"
    result = run_corpus_execution(plan_path, output)

    assert result["integrityStatus"] == "verified"
    assert (output / "requests/eval-0.json").is_file()
    assert (output / "paper-corpus-manifest.json").is_file()
    assert (output / "source-evidence/program-0/case.c").read_bytes() == (source / "case.c").read_bytes()
    assert (output / "attempt-evidence/program-0.json").is_file()
    assert (output / "paper-report/paper-evaluation.json").is_file()
