from hashlib import sha256
import json
from pathlib import Path

import pytest

from riscv2x86_py.evaluation import EVALUATION_RESULT_SCHEMA, LEGACY_EVALUATION_RESULT_SCHEMA

from riscv2x86_py.evaluation_aggregate import (
    AGGREGATION_POLICY, CORPUS_MANIFEST_SCHEMA, _DENOMINATORS,
    aggregate_corpus, corpus_manifest_from_dict, load_corpus_manifest,
    render_outputs, write_outputs,
)


def _sha(text: str) -> str:
    return "sha256:" + sha256(text.encode()).hexdigest()


def _evaluation(path: Path, attempt_id: str, *, outcome="emitted", status="verified",
                reason_codes=(), environment="env-a", attributed=False):
    validation = None
    if status in {"verified", "failed", "inconclusive"}:
        validation = {
            "schemaVersion": "riscv2x86.translation-validation.v2",
            "status": status, "validationOutcome": status, "profile": "architectural",
            "completedLevels": (["L0", "L1", "L2"] if status == "verified" else ["L0"]),
            "layers": ([
                {"level": level, "status": "verified", "evidenceIdentity": _sha(level), "detail": ""}
                for level in ("L0", "L1", "L2")
            ] if status == "verified" else [
                {"level": "L0", "status": "verified", "evidenceIdentity": _sha("L0"), "detail": ""},
                {"level": "L1", "status": status, "evidenceIdentity": _sha("L1"), "detail": "mismatch"},
            ]),
            "reasonCodes": list(reason_codes), "validationIdentity": _sha("validation:" + attempt_id),
        }
    attempt = {
        "findingId": "finding:0:fragment", "fragmentId": "fragment",
        "attemptArtifactId": attempt_id, "translationOutcome": outcome,
        "status": status, "validation": validation, "translationArtifact": None,
        "reasonCodes": list(reason_codes), "replayArtifacts": [],
    }
    value = {
        "schemaVersion": EVALUATION_RESULT_SCHEMA if attributed else LEGACY_EVALUATION_RESULT_SCHEMA,
        "requestIdentity": _sha("request:" + attempt_id), "status": status,
        "reasonCodes": list(reason_codes), "candidateManifestId": _sha("candidate:" + attempt_id),
        "attempts": [attempt], "commands": [], "replayArtifact": "replay/evaluation-replay.json",
        "validationPlan": {},
        "targetEnvironment": {
            "environmentId": environment, "sourceIsa": "rv64gc", "sourceAbi": "lp64d",
            "targetIsa": "x86_64", "targetAbi": "sysv_amd64",
            "runtimeIdentity": "runtime-v1", "loaderIdentity": "loader-v1",
        },
        "sourceProgramArtifact": {}, "targetProgramArtifact": {},
        "comparisonPolicy": "riscv2x86.comparison-policy.architectural.v1",
    }
    if attributed:
        value.update({"validationUnit": "program", "validationGroupId": "",
                      "selectedAttemptIds": [],
                      "environmentProvenance": {"schemaVersion": "riscv2x86.environment-provenance.v1"}})
    identity_payload = dict(value)
    identity_payload.pop("replayArtifact")
    value["evaluationIdentity"] = "sha256:" + sha256(json.dumps(
        identity_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    path.write_text(json.dumps(value), encoding="utf-8")


def _manifest(entries, *, resamples=200):
    return {
        "schemaVersion": CORPUS_MANIFEST_SCHEMA, "corpusId": "paper-corpus",
        "corpusVersion": "2026.09", "description": "test corpus",
        "aggregationPolicy": AGGREGATION_POLICY,
        "denominatorDefinitions": _DENOMINATORS,
        "bootstrap": {"seed": 20260908, "resamples": resamples, "confidenceLevel": 0.95},
        "entries": entries,
    }


def _entry(name, attempt_id, result, category="integer", environment="env-a"):
    return {"entryId": name, "category": category, "subcategory": "scalar",
            "sourceIdentity": _sha("source:" + name), "evaluationResult": result,
            "expectedAttemptIds": [attempt_id], "expectedEnvironmentId": environment,
            "tags": ["rv64gc"]}


def test_aggregate_uses_declared_denominators_and_is_reproducible(tmp_path):
    verified_id, failed_id = _sha("attempt-v"), _sha("attempt-f")
    _evaluation(tmp_path / "verified.json", verified_id)
    _evaluation(tmp_path / "failed.json", failed_id, status="failed",
                reason_codes=("validation.layer-not-verified:L1",))
    manifest = corpus_manifest_from_dict(_manifest([
        _entry("entry-a", verified_id, "verified.json"),
        _entry("entry-b", failed_id, "failed.json"),
    ]))
    first = aggregate_corpus(manifest, manifest_directory=tmp_path)
    second = aggregate_corpus(manifest, manifest_directory=tmp_path)
    overall = first["summaries"][0]

    assert first["aggregationIdentity"] == second["aggregationIdentity"]
    assert first["integrityStatus"] == "verified"
    assert overall["declaredAttempts"] == 2
    assert overall["verifiedAttempts"] == 1
    assert overall["metrics"]["validationVerifiedRate"]["estimate"] == 0.5
    assert first["reasonBreakdown"] == [{
        "category": "integer", "reasonCode": "validation.layer-not-verified:L1", "count": 1,
        "fractionOfDeclaredAttempts": 0.5,
    }]


def test_missing_evaluation_is_not_silently_skipped(tmp_path):
    attempt_id = _sha("missing-attempt")
    manifest = corpus_manifest_from_dict(_manifest([
        _entry("entry-a", attempt_id, "does-not-exist.json"),
    ]))
    result = aggregate_corpus(manifest, manifest_directory=tmp_path)
    overall = result["summaries"][0]

    assert result["integrityStatus"] == "failed"
    assert overall["declaredAttempts"] == 1
    assert overall["failedInvalidMissingAttempts"] == 1
    assert overall["metrics"]["failureRate"]["estimate"] == 1.0
    assert result["records"][0]["status"] == "missing"
    assert result["records"][0]["reasonCodes"] == ["aggregation.evaluation-missing"]


def test_invalid_or_incomplete_evaluation_accounts_for_every_expected_attempt(tmp_path):
    first, second = _sha("one"), _sha("two")
    (tmp_path / "broken.json").write_text("{}")
    manifest = corpus_manifest_from_dict(_manifest([
        {**_entry("entry-a", first, "broken.json"), "expectedAttemptIds": sorted([first, second])},
    ]))
    result = aggregate_corpus(manifest, manifest_directory=tmp_path)
    assert len(result["records"]) == 2
    assert all(item["status"] == "invalid" for item in result["records"])
    assert result["summaries"][0]["declaredAttempts"] == 2


def test_all_five_outputs_are_emitted_with_explicit_denominators(tmp_path):
    attempt_id = _sha("attempt")
    _evaluation(tmp_path / "evaluation.json", attempt_id)
    manifest = corpus_manifest_from_dict(_manifest([
        _entry("entry-a", attempt_id, "evaluation.json"),
    ]))
    outputs = render_outputs(aggregate_corpus(manifest, manifest_directory=tmp_path))
    destination = tmp_path / "out"
    write_outputs(outputs, destination)

    assert set(outputs) == {"corpus-evaluation.json", "corpus-summary.csv",
                            "failure-breakdown.csv", "environment-matrix.csv", "paper-tables.md"}
    assert all((destination / name).is_file() for name in outputs)
    assert "conditionalCorrectnessRate" in (destination / "corpus-summary.csv").read_text()
    assert "Denominator definitions" in (destination / "paper-tables.md").read_text()


def test_manifest_rejects_changed_denominators_and_noncanonical_entries(tmp_path):
    attempt_id = _sha("attempt")
    value = _manifest([_entry("entry-a", attempt_id, "evaluation.json")])
    value["denominatorDefinitions"] = {**_DENOMINATORS, "failureRate": "successful only"}
    with pytest.raises(ValueError, match="denominator definitions"):
        corpus_manifest_from_dict(value)

    value = _manifest([_entry("z", attempt_id, "z.json"),
                       _entry("a", _sha("other"), "a.json")])
    with pytest.raises(ValueError, match="canonically sorted"):
        corpus_manifest_from_dict(value)


def test_unexpected_attempt_is_reported_and_cannot_change_declared_denominator(tmp_path):
    expected, unexpected = _sha("expected"), _sha("unexpected")
    _evaluation(tmp_path / "evaluation.json", unexpected)
    manifest = corpus_manifest_from_dict(_manifest([
        _entry("entry-a", expected, "evaluation.json"),
    ]))
    result = aggregate_corpus(manifest, manifest_directory=tmp_path)
    codes = {item["reasonCode"] for item in result["integrityErrors"]}
    assert result["integrityStatus"] == "failed"
    assert codes == {"aggregation.unexpected-attempts", "aggregation.expected-attempts-missing"}
    assert result["summaries"][0]["declaredAttempts"] == 1
    assert result["records"][0]["attemptArtifactId"] == expected
    assert result["records"][0]["status"] == "missing"


def test_e5_aggregator_accepts_e7_attribution_extension(tmp_path):
    attempt_id = _sha("attributed")
    _evaluation(tmp_path / "evaluation.json", attempt_id, attributed=True)
    manifest = corpus_manifest_from_dict(_manifest([
        _entry("entry-a", attempt_id, "evaluation.json"),
    ]))
    assert aggregate_corpus(manifest, manifest_directory=tmp_path)["integrityStatus"] == "verified"
