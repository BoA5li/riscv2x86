"""Tests for the user-facing multi-program evaluation orchestrator."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys

import pytest

from riscv2x86_py.batch_evaluation_cli import (
    BATCH_CASE_SCHEMA, BATCH_DESCRIPTOR_NAME, BATCH_TEMPLATE_SCHEMA,
    _l2_coverage_diagnostics, _l2_disposition_counts, _merge_l2_coverage,
    discover_batch_cases,
    run_batch_evaluation,
)
from tests.test_evaluation_runner import _setup
from riscv2x86_py.schema import TranslationOutcome


def _request_value(request) -> dict[str, object]:
    return {
        "schemaVersion": request.schema_version,
        "sourceRoot": request.source_root,
        "sourceRelativePath": request.source_relative_path,
        "targetRelativePath": request.target_relative_path,
        "translatedReport": request.translated_report,
        "attemptArchive": request.attempt_archive,
        "validationPlan": request.validation_plan,
        "targetEnvironment": request.target_environment,
        "runtimeRegistryTemplate": request.runtime_registry_template,
        "translationArtifacts": request.translation_artifacts,
        "sourceBuild": {
            "artifactId": request.source_build.artifact_id,
            "artifactKind": request.source_build.artifact_kind,
            "outputRelativePath": request.source_build.output_relative_path,
            "command": list(request.source_build.command),
        },
        "targetBuild": {
            "artifactId": request.target_build.artifact_id,
            "artifactKind": request.target_build.artifact_kind,
            "outputRelativePath": request.target_build.output_relative_path,
            "command": list(request.target_build.command),
        },
        "translationCommand": list(request.translation_command),
        "comparisonPolicy": request.comparison_policy,
        "validationUnit": request.validation_unit,
        "validationGroupId": request.validation_group_id,
        "selectedAttemptIds": list(request.selected_attempt_ids),
    }


def _descriptor(directory: Path, case_id: str, request, *, category="integer") -> Path:
    directory.mkdir(parents=True)
    path = directory / BATCH_DESCRIPTOR_NAME
    path.write_text(json.dumps({
        "schemaVersion": BATCH_CASE_SCHEMA, "caseId": case_id,
        "category": category, "request": _request_value(request),
    }), encoding="utf-8")
    return path


def _fixture(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    return _setup(root)


def test_batch_runs_all_cases_and_persists_summary(tmp_path):
    request, _source, _attempt = _fixture(tmp_path)
    corpus = tmp_path / "corpus"
    _descriptor(corpus / "add", "add-001", request)
    unavailable = replace(
        request,
        target_build=replace(request.target_build,
                             command=("definitely-unavailable-batch-compiler", "${TARGET_PATH}")),
    )
    _descriptor(corpus / "shift", "shift-001", unavailable)

    output = tmp_path / "run"
    result = run_batch_evaluation(corpus, output, jobs=2)

    assert result["caseCount"] == 2
    assert result["statusCounts"] == {"inconclusive": 2}
    assert result["programValidationDenominators"] == {
        "L0": 2, "L1": 2, "L2": 2, "L3": 2,
    }
    assert result["programValidationApplicableDenominators"] == {
        "L0": 2, "L1": 2, "L2": 2, "L3": 2,
    }
    assert result["l2MemberCounts"] == {"required": 0, "verified": 0}
    assert result["l2ProgramExecutionSampleCount"] == 0
    assert result["l2PrivilegedFragmentClaimCounts"] == {}
    assert result["programValidationCounts"]["L2"] == {"not_run": 2}
    assert result["programValidationCounts"]["L3"] == {"not_run": 2}
    assert result["l2RequirementDispositionCounts"] == {}
    assert result["l2RequiredDimensionCounts"] == {}
    assert result["l2RequirementDenominator"] == 0
    assert result["l2CoverageDiagnostics"] == {
        "automaticProviderCoverage": {}, "explicitHarnessCoverage": {},
        "runtimeAdapterCoverage": {},
        "missingCapabilityCounts": {"resolved_plan_missing": 2},
        "authorityMaterializationCounts": {},
        "observationProductionCounts": {}, "relationApprovalCounts": {},
    }
    assert result["l2CoverageMetricDefinitions"]["providerCoverageUnit"] == (
        "required fragment-dimension binding")
    assert [item["caseId"] for item in result["cases"]] == ["add-001", "shift-001"]
    assert (output / "cases/add-001/evaluation-result.json").is_file()
    assert (output / "cases/shift-001/evaluation-result.json").is_file()
    assert (output / "batch-evaluation.json").is_file()
    assert (output / "batch-summary.csv").is_file()
    header = (output / "batch-summary.csv").read_text().splitlines()[0]
    assert header == ("case_id,category,status,translation_outcomes,evaluation_disposition,"
                      "l0,l1,l2,l3,evaluation_identity,reason_codes")


def test_final_l2_member_disposition_replaces_manifest_not_run():
    manifest = {"not_run": 1}
    group = {
        "memberResults": [
            {"fragmentId": "fragment:0", "required": True, "status": "verified"},
            {"fragmentId": "diagnostic:0", "required": False, "status": "failed"},
        ],
    }

    assert _l2_disposition_counts(group, manifest) == {"verified": 1}
    assert _l2_disposition_counts({}, manifest) == {"not_run": 1}


def test_l2_coverage_diagnostics_separate_provider_and_evidence_failures(tmp_path):
    identity = lambda char: "sha256:" + char * 64
    case_root = tmp_path / "case"; replay = case_root / "work/replay"; replay.mkdir(parents=True)
    plan = {
        "fragmentId": "fragment:renamed:0",
        "bindings": [
            {"dimension": "logical_operands", "bindingStatus": "resolved",
             "bindingKind": "automatic", "missingCapabilities": []},
            {"dimension": "control_flow", "bindingStatus": "resolved",
             "bindingKind": "explicit", "missingCapabilities": []},
            {"dimension": "memory_effects", "bindingStatus": "not_run",
             "bindingKind": "", "missingCapabilities": ["object_relative_memory_observation"]},
        ],
    }
    (replay / "one-l2-resolved-plan.json").write_text(json.dumps(plan))
    # A replay/archive copy of the same plan is not another coverage sample.
    (replay / "two-l2-resolved-plan.json").write_text(json.dumps(plan))
    detail = {
        "fragmentId": "fragment:renamed:0",
        "dimensionResults": {
            "logical_operands": {"status": "verified", "authorityIdentity": identity("a"),
                "sourceObservationIdentity": identity("b"),
                "targetObservationIdentity": identity("c"),
                "effectRelationIdentity": identity("d")},
            "control_flow": {"status": "failed", "authorityIdentity": identity("a"),
                "sourceObservationIdentity": identity("e"),
                "targetObservationIdentity": identity("f"),
                "effectRelationIdentity": identity("d")},
            "memory_effects": {"status": "not_run", "authorityIdentity": "",
                "sourceObservationIdentity": "", "targetObservationIdentity": "",
                "effectRelationIdentity": ""},
        },
    }
    result = {"attempts": [{"validation": {"layers": [
        {"level": "L2", "detail": json.dumps(detail)}]}}]}
    coverage = _l2_coverage_diagnostics(result, case_root)
    assert coverage["automaticProviderCoverage"] == {"verified": 1}
    assert coverage["explicitHarnessCoverage"] == {"failed": 1}
    assert coverage["runtimeAdapterCoverage"] == {}
    assert coverage["missingCapabilityCounts"] == {
        "object_relative_memory_observation": 1, "provider_unbound": 1}
    assert coverage["authorityMaterializationCounts"] == {
        "complete": 2, "incomplete": 1}
    assert coverage["observationProductionCounts"] == {
        "complete": 2, "not_produced": 1}
    assert coverage["relationApprovalCounts"] == {"approved": 2, "not_approved": 1}


def test_l2_coverage_aggregation_preserves_nonverified_round2_categories():
    fields = {
        "automaticProviderCoverage": {"verified": 9, "inconclusive": 1},
        "explicitHarnessCoverage": {"verified": 2},
        "runtimeAdapterCoverage": {"verified": 1, "not_run": 1},
        "missingCapabilityCounts": {"instruction_visibility": 1},
        "authorityMaterializationCounts": {"complete": 12, "incomplete": 2},
        "observationProductionCounts": {"complete": 12, "not_produced": 2},
        "relationApprovalCounts": {"approved": 12, "not_approved": 2},
    }
    merged = _merge_l2_coverage([
        {"l2CoverageDiagnostics": fields},
        {"l2CoverageDiagnostics": {
            **fields, "missingCapabilityCounts": {"privileged_state_observation": 1}}},
    ])
    assert merged["automaticProviderCoverage"] == {"inconclusive": 2, "verified": 18}
    assert merged["missingCapabilityCounts"] == {
        "instruction_visibility": 1, "privileged_state_observation": 1}
    assert merged["relationApprovalCounts"] == {"approved": 24, "not_approved": 4}


def test_batch_separates_no_candidate_from_target_build_failure(tmp_path):
    needs_route, _source, _attempt = _setup(
        tmp_path / "route-fixture", translation_outcome=TranslationOutcome.NEEDS_ROUTE,
    )
    failed, _source, _attempt = _setup(tmp_path / "build-fixture")
    failed = replace(
        failed,
        target_build=replace(
            failed.target_build,
            command=(sys.executable, "-c", "raise SystemExit(1)"),
        ),
    )
    corpus = tmp_path / "corpus"
    _descriptor(corpus / "route", "route", needs_route)
    _descriptor(corpus / "build", "build", failed)

    result = run_batch_evaluation(corpus, tmp_path / "run")

    assert result["statusCounts"] == {"failed": 1, "needs_route": 1}
    assert result["evaluationDispositionCounts"] == {
        "target_build_failed": 1,
        "translation_no_candidate": 1,
    }
    assert result["translationOutcomeCounts"] == {"emitted": 1, "needs_route": 1}


def test_case_orchestration_failure_does_not_drop_other_results(tmp_path):
    request, _source, _attempt = _fixture(tmp_path)
    corpus = tmp_path / "corpus"
    _descriptor(corpus / "good", "good", request)
    broken = replace(request, translated_report="missing-report.json")
    _descriptor(corpus / "broken", "broken", broken)

    output = tmp_path / "run"
    result = run_batch_evaluation(corpus, output)
    by_id = {item["caseId"]: item for item in result["cases"]}

    assert set(by_id) == {"broken", "good"}
    assert by_id["broken"]["reasonCodes"] == ["batch.evaluation-orchestration-error"]
    assert (output / "cases/good/evaluation-result.json").is_file()


def test_duplicate_case_ids_fail_before_output_is_created(tmp_path):
    request, _source, _attempt = _fixture(tmp_path)
    corpus = tmp_path / "corpus"
    _descriptor(corpus / "one", "same", request)
    _descriptor(corpus / "two", "same", request)
    output = tmp_path / "run"

    with pytest.raises(ValueError, match="unique"):
        discover_batch_cases(corpus, output)
    assert not output.exists()


def test_case_tokens_and_relative_contract_paths_are_resolved(tmp_path):
    request, source, _attempt = _fixture(tmp_path)
    case_dir = tmp_path / "corpus" / "case"
    value = _request_value(request)
    value["sourceRoot"] = "@CASE_DIR@/source"
    value["validationPlan"] = "plan.json"
    value["targetEnvironment"] = "environment.json"
    case_dir.mkdir(parents=True)
    (case_dir / "source").symlink_to(source, target_is_directory=True)
    Path(request.validation_plan).replace(case_dir / "plan.json")
    Path(request.target_environment).replace(case_dir / "environment.json")
    (case_dir / BATCH_DESCRIPTOR_NAME).write_text(json.dumps({
        "schemaVersion": BATCH_CASE_SCHEMA, "caseId": "tokens",
        "category": "integer", "request": value,
    }), encoding="utf-8")

    case = discover_batch_cases(case_dir, tmp_path / "run")[0]
    assert case["request"]["sourceRoot"] == str((case_dir / "source").resolve())
    assert case["request"]["validationPlan"] == str((case_dir / "plan.json").resolve())


def test_template_mode_discovers_every_c_program_and_derives_stable_ids(tmp_path):
    request, _source, _attempt = _fixture(tmp_path)
    sources = tmp_path / "sources"
    (sources / "integer").mkdir(parents=True)
    (sources / "integer/add.c").write_text("int main(void){return 0;}\n")
    (sources / "shift.c").write_text("int main(void){return 0;}\n")
    config = tmp_path / "config"; config.mkdir()
    template_request = _request_value(request)
    template_request["sourceRoot"] = "@INPUT_ROOT@"
    template_request["sourceRelativePath"] = "@SOURCE_RELATIVE_PATH@"
    template_request["targetRelativePath"] = "@SOURCE_RELATIVE_PATH@"
    template_request["validationPlan"] = str(Path(request.validation_plan).resolve())
    template_request["targetEnvironment"] = str(Path(request.target_environment).resolve())
    template_request["sourceBuild"]["artifactId"] = "source-@CASE_ID@"
    template = config / "template.json"
    template.write_text(json.dumps({
        "schemaVersion": BATCH_TEMPLATE_SCHEMA, "category": "mixed",
        "request": template_request,
    }))

    cases = discover_batch_cases(
        sources, tmp_path / "run", request_template=template,
    )

    assert [item["caseId"] for item in cases] == ["integer--add", "shift"]
    assert [item["request"]["sourceRelativePath"] for item in cases] == [
        "integer/add.c", "shift.c",
    ]
    assert cases[0]["request"]["sourceBuild"]["artifactId"] == "source-integer--add"
