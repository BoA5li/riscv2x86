from hashlib import sha256
import json
from pathlib import Path

import pytest

from riscv2x86_py.evaluation import EVALUATION_RESULT_SCHEMA
from riscv2x86_py.l2_dimensions import (
    L2ClaimScope, L2DimensionStatus, parse_l2_dimension,
)
from riscv2x86_py.l2_results import L2DimensionResult, L2FragmentResult

from riscv2x86_py.paper_evaluation import (
    PAPER_CORPUS_SCHEMA, PAPER_POLICY, Bootstrap, _cluster_metric, _validation_maps,
    aggregate_paper_corpus,
    paper_manifest_from_dict, render_paper_outputs,
)
from riscv2x86_py.schema import PublicationOutcome, TranslationOutcome, ValidationOutcome
from riscv2x86_py.translation_attempt import (
    TranslationAttempt, load_translation_attempt_archive, save_translation_attempt_archive,
)


def _digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _tree(root: Path) -> str:
    files = [{"path": path.relative_to(root).as_posix(), "digest": _digest(path.read_bytes())}
             for path in sorted(root.rglob("*")) if path.is_file()]
    return _digest(json.dumps({"files": files}, sort_keys=True, separators=(",", ":")).encode())


def test_paper_maps_do_not_accept_legacy_untyped_l2_success():
    evaluation = {"attempts": [{
        "fragmentId": "fragment:1",
        "validation": {"layers": [{
            "level": "L2", "status": "verified",
            "evidenceIdentity": _digest(b"legacy-layer"),
            "detail": json.dumps({
                "schemaVersion": "riscv2x86.validation-dimensions.v1",
                "dimensions": {"logical_operands": {
                    "status": "verified", "evidenceIdentity": _digest(b"legacy"),
                }},
            }),
        }]},
    }]}
    levels, dimensions, scopes, execution = _validation_maps(evaluation, {"fragment:1"})
    assert levels["L2"] == "inconclusive"
    assert dimensions == {}
    assert scopes == {}
    assert execution == {}


def _attempt(fragment: str, *, emitted: bool) -> TranslationAttempt:
    replacement = "out = lhs + rhs;" if emitted else ""
    return TranslationAttempt(
        finding_id="finding:" + fragment[-1] + ":" + fragment,
        fragment_id=fragment, candidate_kind="c" if emitted else "unsupported",
        candidate_route="route" if emitted else "", candidate_replacement=replacement,
        candidate_replacement_digest=_digest(replacement.encode()),
        candidate_rule_name="rule" if emitted else "",
        translation_outcome=TranslationOutcome.EMITTED if emitted else TranslationOutcome.UNSUPPORTED,
        validation_outcome=ValidationOutcome.NOT_RUN,
        publication_outcome=PublicationOutcome.WITHHELD if emitted else PublicationOutcome.NOT_REQUESTED,
        reason_codes=(), source_model_id="model" if emitted else "",
        preservation_decision_id="decision" if emitted else "", plan_id="plan" if emitted else "",
        constraints_id="constraints" if emitted else "", proof_status="approved" if emitted else "",
        proof_binding_identity=_digest(b"proof") if emitted else "",
        target_environment_id="env" if emitted else "", renderer_id="renderer" if emitted else "",
        renderer_version="1" if emitted else "", renderer_contract_id="contract" if emitted else "",
        renderer_registry_id="registry" if emitted else "", renderer_registry_version="1" if emitted else "",
        binding_complete=emitted,
    )


def _evaluation(path: Path, attempt: TranslationAttempt, *, unit="single_candidate", group="g0",
                dimensions=("logical_operands", "shell_semantics"),
                claim_scope=L2ClaimScope.ARCHITECTURAL):
    layers = [{"level": level, "status": "verified", "evidenceIdentity": _digest(level.encode()), "detail": ""}
              for level in ("L0", "L1", "L2")]
    dimension_results = tuple(L2DimensionResult.create(
        dimension=parse_l2_dimension(name), status=L2DimensionStatus.VERIFIED,
        claim_scope=claim_scope,
        authority_identity=_digest((name + "-authority").encode()),
        source_observation_identity=_digest((name + "-source").encode()),
        target_observation_identity=_digest((name + "-target").encode()),
        effect_relation_identity=_digest((name + "-relation").encode()),
        execution_identity=_digest((name + "-execution").encode()),
        relation_kind=("runtime_mediated" if claim_scope is
                       L2ClaimScope.APPROVED_FUNCTIONAL_RELATION else "exact"),
        verified_properties=(("declared-return-relation",) if claim_scope is
                             L2ClaimScope.APPROVED_FUNCTIONAL_RELATION else ()),
        not_claimed_properties=(("architectural-state-equivalence",) if claim_scope is
                                L2ClaimScope.APPROVED_FUNCTIONAL_RELATION else ()),
    ) for name in dimensions)
    fragment_result = L2FragmentResult.close(
        fragment_id=attempt.fragment_id, requirement_identity=_digest(b"requirement"),
        required_dimensions=tuple(parse_l2_dimension(name) for name in dimensions),
        dimension_results=dimension_results,
    )
    layers[-1]["detail"] = json.dumps(
        fragment_result.to_dict(), sort_keys=True, separators=(",", ":"),
    )
    layers[-1]["evidenceIdentity"] = fragment_result.evidence_identity
    value = {
        "schemaVersion": EVALUATION_RESULT_SCHEMA, "requestIdentity": _digest(b"request"),
        "status": "verified", "reasonCodes": [], "candidateManifestId": _digest(b"candidate"),
        "attempts": [{"findingId": attempt.finding_id, "fragmentId": attempt.fragment_id,
                      "attemptArtifactId": attempt.artifact_id, "translationOutcome": "emitted",
                      "status": "verified", "validation": {"layers": layers},
                      "translationArtifact": {}, "reasonCodes": [], "replayArtifacts": []}],
        "commands": [], "replayArtifact": "replay/evaluation-replay.json", "validationPlan": {},
        "targetEnvironment": {"environmentId": "env"}, "sourceProgramArtifact": {},
        "targetProgramArtifact": {}, "comparisonPolicy": "policy", "validationUnit": unit,
        "validationGroupId": group, "selectedAttemptIds": [attempt.artifact_id],
        "environmentProvenance": {"schemaVersion": "riscv2x86.environment-provenance.v1",
                                  "kernel": "k", "platform": "linux", "machine": "x86_64",
                                  "cpuModel": "cpu", "microcode": "microcode",
                                  "toolVersions": {"cc": "cc 1"},
                                  "runnerVersions": {"source": "qemu 1", "target": "native"},
                                  "sourceBuildCommand": ["rvcc"], "targetBuildCommand": ["cc"],
                                  "runtimeIdentity": "runtime", "loaderIdentity": "loader",
                                  "containerImageDigest": "sha256:" + "c" * 64},
    }
    identity_payload = dict(value); identity_payload.pop("replayArtifact")
    value["evaluationIdentity"] = _digest(json.dumps(
        identity_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode())
    path.write_text(json.dumps(value))


def _manifest(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    content = b"asm-one\nasm-two\n"; (source / "case.c").write_bytes(content)
    emitted, unsupported = _attempt("fragment:0", emitted=True), _attempt("fragment:1", emitted=False)
    save_translation_attempt_archive((emitted, unsupported), tmp_path / "attempts.json")
    _evaluation(tmp_path / "result.json", emitted)
    oracle = []
    for index, text in enumerate((b"asm-one", b"asm-two")):
        begin = content.index(text)
        facts = {"fragmentId": "fragment:" + str(index), "relativePath": "case.c",
                 "beginOffset": begin, "endOffset": begin + len(text),
                 "sourceSliceDigest": _digest(text), "category": "integer",
                 "subcategory": "scalar",
                 "requiredDimensions": ["logical_operands", "shell_semantics"]}
        oracle.append({"oracleFragmentId": _digest(json.dumps(
            facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()), **facts})
    oracle.sort(key=lambda item: item["oracleFragmentId"])
    selected = next(item for item in oracle if item["fragmentId"] == "fragment:0")
    return {
        "schemaVersion": PAPER_CORPUS_SCHEMA, "metricPolicy": PAPER_POLICY,
        "corpusId": "paper", "corpusVersion": "1",
        "bootstrap": {"seed": 7, "resamples": 200, "confidenceLevel": 0.95},
        "programs": [{"programId": "program-0", "category": "integer",
                      "sourceIdentity": _tree(source), "sourceRoot": "source",
                      "attemptArchive": "attempts.json", "oracleFragments": oracle,
                      "validations": [{"evaluationId": "eval-0", "evaluationResult": "result.json",
                                       "unit": "single_candidate", "groupId": "g0",
                                       "oracleFragmentIds": [selected["oracleFragmentId"]],
                                       "expectedEnvironmentId": "env"}]}],
    }


def test_paper_metrics_use_oracle_denominators_and_program_cluster_bootstrap(tmp_path):
    manifest = paper_manifest_from_dict(_manifest(tmp_path))
    result = aggregate_paper_corpus(manifest, manifest_directory=tmp_path)
    assert result["integrityStatus"] == "verified"
    assert result["metrics"]["recognitionCoverage"]["estimate"] == 1.0
    assert result["metrics"]["l3IntentClassificationCoverage"]["denominator"] == 2
    assert result["metrics"]["l3IntentClassificationCoverage"]["numerator"] == 0
    assert result["metrics"]["l3UnconditionalArchitecturalIntentVerifiedRate"]["denominator"] == 2
    assert result["metrics"]["l3UnconditionalArchitecturalIntentVerifiedRate"]["numerator"] == 0
    assert result["metricDefinitions"]["l3NotRunRate"]["denominator"] == "L3 eligible fragments"
    assert result["metrics"]["l3UnconditionalArchitecturalIntentVerifiedRate"]["clusters"] == 1
    assert result["metrics"]["modelingCoverage"]["estimate"] == 0.5
    assert result["metrics"]["candidateCoverage"]["estimate"] == 0.5
    assert result["metrics"]["l2VerifiedRate"]["estimate"] == 1.0
    assert result["metrics"]["l2EligibilityCoverage"]["denominator"] == 2
    assert result["metrics"]["l2EligibilityCoverage"]["numerator"] == 1
    assert result["metrics"]["l2AttemptedCoverage"]["denominator"] == 1
    assert result["metrics"]["l2AttemptedCoverage"]["numerator"] == 1
    assert result["metrics"]["l2CompleteExecutionCoverage"]["numerator"] == 1
    assert result["metrics"]["l2UnconditionalArchitecturalVerifiedRate"]["denominator"] == 2
    assert result["metrics"]["l2UnconditionalArchitecturalVerifiedRate"]["numerator"] == 1
    assert result["dimensionMetrics"]["shell_semantics"]["estimate"] == 0.5
    assert result["metrics"]["candidateCoverage"]["clusters"] == 1
    assert result["translationOutcomeBreakdown"] == {"emitted": 1, "unsupported": 1}
    assert result["statisticalUnit"]["bootstrap"] == "program-or-entry-cluster"
    assert all(item["denominator"] for item in result["metricDefinitions"].values())
    assert set(result["metrics"]) == set(result["metricDefinitions"])
    markdown = render_paper_outputs(result)["paper-tables.md"]
    assert "## Metric denominators" in markdown
    assert "all corpus oracle fragments" in markdown
    assert set(render_paper_outputs(result)) == {"paper-evaluation.json", "paper-metrics.csv",
                                                  "translation-outcomes.csv",
                                                  "failure-breakdown.csv",
                                                  "environment-provenance.json", "paper-tables.md"}


def test_oracle_is_independent_and_source_tampering_fails_integrity(tmp_path):
    value = _manifest(tmp_path); manifest = paper_manifest_from_dict(value)
    (tmp_path / "source/case.c").write_text("changed")
    result = aggregate_paper_corpus(manifest, manifest_directory=tmp_path)
    assert result["integrityStatus"] == "failed"
    assert "paper.oracle-source-invalid" in {item["reasonCode"] for item in result["integrityErrors"]}


def test_program_result_cannot_be_attributed_as_single_candidate(tmp_path):
    value = _manifest(tmp_path)
    result_path = tmp_path / "result.json"
    emitted = load_translation_attempt_archive(tmp_path / "attempts.json").attempts[0]
    _evaluation(result_path, emitted, unit="program", group="")
    result = aggregate_paper_corpus(paper_manifest_from_dict(value), manifest_directory=tmp_path)
    assert result["integrityStatus"] == "failed"
    assert "paper.evaluation-invalid" in {item["reasonCode"] for item in result["integrityErrors"]}


def test_manifest_rejects_duplicate_or_noncanonical_oracle_units(tmp_path):
    value = _manifest(tmp_path)
    validation = value["programs"][0]["validations"][0]
    validation["oracleFragmentIds"] = sorted(
        item["oracleFragmentId"] for item in value["programs"][0]["oracleFragments"]
    )
    with pytest.raises(ValueError, match="exactly one"):
        paper_manifest_from_dict(value)


def test_bootstrap_resamples_program_clusters_not_fragments():
    rows = [{"programId": "p0", "ok": True}, {"programId": "p0", "ok": False},
            {"programId": "p1", "ok": True}]
    metric = _cluster_metric(rows, lambda row: row["ok"], lambda _row: True,
                             Bootstrap(11, 200, 0.95), "cluster-contract")
    assert metric["numerator"] == 2
    assert metric["denominator"] == 3
    assert metric["clusters"] == 2
    assert metric["bootstrapUnit"] == "program"


def test_ten_fragments_from_one_program_are_one_bootstrap_cluster():
    rows = [{"programId": "p0", "ok": index < 7} for index in range(10)]
    metric = _cluster_metric(rows, lambda row: row["ok"], lambda _row: True,
                             Bootstrap(17, 200, 0.95), "ten-fragment-cluster")
    assert metric["numerator"] == 7
    assert metric["denominator"] == 10
    assert metric["clusters"] == 1


def test_generic_l2_success_does_not_invent_missing_dimension_evidence(tmp_path):
    value = _manifest(tmp_path)
    attempt = load_translation_attempt_archive(tmp_path / "attempts.json").attempts[0]
    _evaluation(tmp_path / "result.json", attempt, dimensions=("logical_operands",))
    result = aggregate_paper_corpus(paper_manifest_from_dict(value), manifest_directory=tmp_path)
    assert result["metrics"]["l2VerifiedRate"]["estimate"] == 0.0
    assert result["dimensionMetrics"]["logical_operands"]["estimate"] == 0.5
    assert result["dimensionMetrics"]["shell_semantics"]["estimate"] == 0.0


def test_functional_relation_is_excluded_from_architectural_l2_numerator(tmp_path):
    value = _manifest(tmp_path)
    attempt = load_translation_attempt_archive(tmp_path / "attempts.json").attempts[0]
    _evaluation(
        tmp_path / "result.json", attempt,
        claim_scope=L2ClaimScope.APPROVED_FUNCTIONAL_RELATION,
    )
    result = aggregate_paper_corpus(
        paper_manifest_from_dict(value), manifest_directory=tmp_path,
    )
    assert result["metrics"]["l2VerifiedRate"]["numerator"] == 0
    assert result["metrics"]["l2UnconditionalArchitecturalVerifiedRate"]["numerator"] == 0
    assert result["metrics"]["l2ApprovedFunctionalRelationVerifiedRate"]["numerator"] == 1
    assert result["dimensionMetrics"]["logical_operands"]["numerator"] == 0
    assert result["l2DimensionSummaries"]["logical_operands"]["verifiedFunctionalRelation"] == 1


@pytest.mark.parametrize("dimension", ["operand", "operands", "effects", "shell", "unknown"])
def test_paper_oracle_rejects_noncanonical_l2_dimension_names(tmp_path, dimension):
    value = _manifest(tmp_path)
    oracle = value["programs"][0]["oracleFragments"][0]
    oracle["requiredDimensions"] = [dimension]
    with pytest.raises(ValueError, match="unsupported"):
        paper_manifest_from_dict(value)
