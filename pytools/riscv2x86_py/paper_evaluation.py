"""Paper-grade corpus oracle, attribution and cluster-bootstrap reporting."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import argparse
import csv
import io
import json
from pathlib import Path
import random
import shutil
from typing import Mapping, Sequence

from .translation_attempt import load_translation_attempt_archive
from .evaluation import EVALUATION_RESULT_SCHEMA
from .l2_dimensions import L2ClaimScope, L2Dimension
from .l2_results import L2FragmentResult, L2_FRAGMENT_RESULT_SCHEMA
from .l2_program_results import ProgramExecutionEvidence


PAPER_CORPUS_SCHEMA = "riscv2x86.paper-corpus-manifest.v1"
PAPER_REPORT_SCHEMA = "riscv2x86.paper-evaluation-report.v4"
PAPER_EXECUTION_SCHEMA = "riscv2x86.paper-corpus-execution.v1"
PAPER_POLICY = "riscv2x86.paper-metrics.v2"
_SHA_PREFIX = "sha256:"
_COVERAGE = ("recognition", "modeling", "routing", "candidate", "proof", "rendering")
_LEVELS = ("L0", "L1", "L2", "L3")
_DIMENSION_LEVEL = {dimension.value: "L2" for dimension in L2Dimension}
_DIMENSION_LEVEL["experiment_contract"] = "L3"
_EMITTED = {"emitted", "strengthened", "functional_fallback"}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: bytes) -> str:
    return _SHA_PREFIX + sha256(value).hexdigest()


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith(_SHA_PREFIX):
        raise ValueError(label + " must be a sha256 identity")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise ValueError(label + " must be a sha256 identity") from exc
    return value


def _text(value: object, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError(label + " must be a string")
    return value


def _relative(value: object, label: str) -> str:
    text = _text(value, label)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(label + " must be a safe relative path")
    return path.as_posix()


def _ordered(value: object, label: str, *, allowed: set[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an array of non-empty strings")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ValueError(label + " must be unique and canonically sorted")
    if allowed is not None and not set(result).issubset(allowed):
        raise ValueError(label + " contains unsupported values")
    return result


@dataclass(frozen=True)
class Bootstrap:
    seed: int
    resamples: int
    confidence_level: float

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ValueError("bootstrap seed is invalid")
        if isinstance(self.resamples, bool) or not isinstance(self.resamples, int) or self.resamples < 100:
            raise ValueError("bootstrap resamples are invalid")
        if not 0.5 < self.confidence_level < 1.0:
            raise ValueError("bootstrap confidence level is invalid")


@dataclass(frozen=True)
class OracleFragment:
    oracle_fragment_id: str
    fragment_id: str
    relative_path: str
    begin_offset: int
    end_offset: int
    source_slice_digest: str
    category: str
    subcategory: str
    required_dimensions: tuple[str, ...]

    def __post_init__(self) -> None:
        _sha(self.oracle_fragment_id, "oracle fragment identity")
        _sha(self.source_slice_digest, "oracle source slice")
        _relative(self.relative_path, "oracle relative path")
        if (isinstance(self.begin_offset, bool) or not isinstance(self.begin_offset, int)
                or isinstance(self.end_offset, bool) or not isinstance(self.end_offset, int)
                or self.begin_offset < 0 or self.end_offset <= self.begin_offset):
            raise ValueError("oracle fragment range is invalid")
        if not self.fragment_id or not self.category:
            raise ValueError("oracle fragment facts are incomplete")
        if self.required_dimensions != tuple(sorted(set(self.required_dimensions))):
            raise ValueError("oracle dimensions are not canonical")
        if not set(self.required_dimensions).issubset(_DIMENSION_LEVEL):
            raise ValueError("oracle dimension is unsupported")
        identity_payload = {
            "fragmentId": self.fragment_id, "relativePath": self.relative_path,
            "beginOffset": self.begin_offset, "endOffset": self.end_offset,
            "sourceSliceDigest": self.source_slice_digest, "category": self.category,
            "subcategory": self.subcategory, "requiredDimensions": list(self.required_dimensions),
        }
        if self.oracle_fragment_id != _digest(_canonical(identity_payload)):
            raise ValueError("oracle fragment identity does not match authoritative facts")


@dataclass(frozen=True)
class ValidationUnit:
    evaluation_id: str
    evaluation_result: str
    unit: str
    group_id: str
    oracle_fragment_ids: tuple[str, ...]
    expected_environment_id: str

    def __post_init__(self) -> None:
        _relative(self.evaluation_result, "evaluation result")
        if self.unit not in {"program", "single_candidate", "group"}:
            raise ValueError("validation unit is unsupported")
        if (not self.evaluation_id or not self.expected_environment_id
                or (self.unit != "program" and not self.group_id)):
            raise ValueError("validation unit identity is incomplete")
        if self.unit == "program" and self.group_id:
            raise ValueError("program validation cannot claim a candidate group")
        if self.oracle_fragment_ids != tuple(sorted(set(self.oracle_fragment_ids))):
            raise ValueError("validation unit oracle IDs are not canonical")
        if self.unit == "single_candidate" and len(self.oracle_fragment_ids) != 1:
            raise ValueError("single-candidate unit requires exactly one oracle fragment")
        if self.unit != "program" and not self.oracle_fragment_ids:
            raise ValueError("candidate/group unit requires oracle fragments")


@dataclass(frozen=True)
class ProgramOracle:
    program_id: str
    category: str
    source_identity: str
    source_root: str
    attempt_archive: str
    fragments: tuple[OracleFragment, ...]
    validations: tuple[ValidationUnit, ...]

    def __post_init__(self) -> None:
        _sha(self.source_identity, "program source identity")
        _relative(self.source_root, "program source root")
        _relative(self.attempt_archive, "program attempt archive")
        if not self.program_id or not self.category or not self.fragments:
            raise ValueError("program oracle is incomplete")
        fragment_ids = tuple(item.oracle_fragment_id for item in self.fragments)
        if fragment_ids != tuple(sorted(set(fragment_ids))):
            raise ValueError("program oracle fragments are not canonical")
        logical_ids = tuple(item.fragment_id for item in self.fragments)
        if len(set(logical_ids)) != len(logical_ids):
            raise ValueError("program oracle logical fragment IDs are duplicated")
        evaluation_ids = tuple(item.evaluation_id for item in self.validations)
        if evaluation_ids != tuple(sorted(set(evaluation_ids))):
            raise ValueError("program validation units are not canonical")
        known = set(fragment_ids)
        for validation in self.validations:
            if validation.unit == "program":
                if validation.oracle_fragment_ids and set(validation.oracle_fragment_ids) != known:
                    raise ValueError("program validation must cover all oracle fragments")
            elif not set(validation.oracle_fragment_ids).issubset(known):
                raise ValueError("validation unit references an unknown oracle fragment")


@dataclass(frozen=True)
class PaperCorpusManifest:
    corpus_id: str
    corpus_version: str
    bootstrap: Bootstrap
    programs: tuple[ProgramOracle, ...]

    def __post_init__(self) -> None:
        ids = tuple(item.program_id for item in self.programs)
        if not self.corpus_id or not self.corpus_version or not ids:
            raise ValueError("paper corpus identity is incomplete")
        if ids != tuple(sorted(set(ids))):
            raise ValueError("paper corpus programs are not canonical")
        source_ids = [item.source_identity for item in self.programs]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("paper corpus source programs are duplicated")
        oracle_ids = [fragment.oracle_fragment_id for program in self.programs for fragment in program.fragments]
        if len(oracle_ids) != len(set(oracle_ids)):
            raise ValueError("paper corpus oracle identities are duplicated")
        evaluations = [item for program in self.programs for item in program.validations]
        evaluation_ids = [item.evaluation_id for item in evaluations]
        result_paths = [item.evaluation_result for item in evaluations]
        if len(evaluation_ids) != len(set(evaluation_ids)) or len(result_paths) != len(set(result_paths)):
            raise ValueError("paper corpus validation evidence is duplicated")


def paper_manifest_from_dict(value: Mapping[str, object]) -> PaperCorpusManifest:
    fields = {"schemaVersion", "metricPolicy", "corpusId", "corpusVersion", "bootstrap", "programs"}
    if set(value) != fields or value.get("schemaVersion") != PAPER_CORPUS_SCHEMA:
        raise ValueError("paper corpus schema or fields are invalid")
    if value.get("metricPolicy") != PAPER_POLICY:
        raise ValueError("paper metric policy is unsupported")
    raw_bootstrap = value.get("bootstrap")
    if not isinstance(raw_bootstrap, Mapping) or set(raw_bootstrap) != {"seed", "resamples", "confidenceLevel"}:
        raise ValueError("paper bootstrap contract is malformed")
    bootstrap = Bootstrap(raw_bootstrap["seed"], raw_bootstrap["resamples"], raw_bootstrap["confidenceLevel"])
    raw_programs = value.get("programs")
    if not isinstance(raw_programs, list):
        raise ValueError("paper programs must be an array")
    programs = []
    for raw_program in raw_programs:
        program_fields = {"programId", "category", "sourceIdentity", "sourceRoot", "attemptArchive",
                          "oracleFragments", "validations"}
        if not isinstance(raw_program, Mapping) or set(raw_program) != program_fields:
            raise ValueError("paper program fields are invalid")
        raw_fragments, raw_validations = raw_program["oracleFragments"], raw_program["validations"]
        if not isinstance(raw_fragments, list) or not isinstance(raw_validations, list):
            raise ValueError("paper fragments/validations must be arrays")
        fragments = []
        for raw in raw_fragments:
            expected = {"oracleFragmentId", "fragmentId", "relativePath", "beginOffset", "endOffset", "sourceSliceDigest",
                        "category", "subcategory", "requiredDimensions"}
            if not isinstance(raw, Mapping) or set(raw) != expected:
                raise ValueError("oracle fragment fields are invalid")
            fragments.append(OracleFragment(
                _text(raw["oracleFragmentId"], "oracleFragmentId"), _text(raw["fragmentId"], "fragmentId"),
                _relative(raw["relativePath"], "relativePath"), raw["beginOffset"], raw["endOffset"],
                _text(raw["sourceSliceDigest"], "sourceSliceDigest"),
                _text(raw["category"], "fragment category"), _text(raw["subcategory"], "fragment subcategory", empty=True),
                _ordered(raw["requiredDimensions"], "requiredDimensions", allowed=set(_DIMENSION_LEVEL)),
            ))
        validations = []
        for raw in raw_validations:
            expected = {"evaluationId", "evaluationResult", "unit", "groupId",
                        "oracleFragmentIds", "expectedEnvironmentId"}
            if not isinstance(raw, Mapping) or set(raw) != expected:
                raise ValueError("validation unit fields are invalid")
            validations.append(ValidationUnit(
                _text(raw["evaluationId"], "evaluationId"), _relative(raw["evaluationResult"], "evaluationResult"),
                _text(raw["unit"], "unit"), _text(raw["groupId"], "groupId"),
                _ordered(raw["oracleFragmentIds"], "oracleFragmentIds"),
                _text(raw["expectedEnvironmentId"], "expectedEnvironmentId"),
            ))
        programs.append(ProgramOracle(
            _text(raw_program["programId"], "programId"), _text(raw_program["category"], "category"),
            _text(raw_program["sourceIdentity"], "sourceIdentity"),
            _relative(raw_program["sourceRoot"], "sourceRoot"),
            _relative(raw_program["attemptArchive"], "attemptArchive"),
            tuple(fragments), tuple(validations),
        ))
    return PaperCorpusManifest(
        _text(value["corpusId"], "corpusId"), _text(value["corpusVersion"], "corpusVersion"),
        bootstrap, tuple(programs),
    )


def load_paper_manifest(path: str | Path) -> PaperCorpusManifest:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("paper corpus manifest root must be an object")
    return paper_manifest_from_dict(value)


def _load_evaluation(path: Path) -> Mapping[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or value.get("schemaVersion") != EVALUATION_RESULT_SCHEMA:
        raise ValueError("paper evaluation result schema is unsupported")
    identity = value.get("evaluationIdentity")
    _sha(identity, "evaluation identity")
    payload = dict(value); payload.pop("evaluationIdentity"); payload.pop("replayArtifact")
    if _digest(_canonical(payload)) != identity:
        raise ValueError("evaluation identity does not match content")
    if not isinstance(value.get("attempts"), list) or not isinstance(value.get("targetEnvironment"), Mapping):
        raise ValueError("evaluation attempts/environment are missing")
    return value


def _tree_identity(root: Path) -> str:
    if not root.is_dir():
        raise ValueError("oracle source root is unavailable")
    files = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError("oracle source tree contains a symbolic link")
        if path.is_file():
            files.append({"path": path.relative_to(root).as_posix(), "digest": _digest(path.read_bytes())})
    return _digest(_canonical({"files": files}))


def _validation_maps(
    evaluation: Mapping[str, object], selected_fragment_ids: set[str],
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, dict[str, bool]]]:
    attempts = [item for item in evaluation["attempts"] if isinstance(item, Mapping)
                and (not selected_fragment_ids or item.get("fragmentId") in selected_fragment_ids)]
    if not attempts:
        return {}, {}, {}, {}
    maps = []
    dimension_maps = []
    scope_maps = []
    execution_maps = []
    for attempt in attempts:
        validation = attempt.get("validation")
        if not isinstance(validation, Mapping) or not isinstance(validation.get("layers"), list):
            maps.append({})
            dimension_maps.append({}); scope_maps.append({}); execution_maps.append({}); continue
        layer_map = {}; dimensions = {}; scopes = {}; execution = {}
        for item in validation["layers"]:
            if not isinstance(item, Mapping):
                continue
            item_status = str(item.get("status"))
            if item_status == "verified":
                try:
                    _sha(item.get("evidenceIdentity"), "layer evidence identity")
                except ValueError:
                    item_status = "inconclusive"
            layer_map[str(item.get("level"))] = item_status
            detail = item.get("detail")
            typed_l2 = False
            if isinstance(detail, str) and detail.startswith("{"):
                payload = json.loads(detail)
                if item.get("level") == "L3" and item_status == "verified":
                    from .l3_evidence_closure import parse_fragment
                    raw = payload.get("fragmentResult")
                    if raw is None and isinstance(payload.get("providerDetail"), str):
                        try:
                            raw = json.loads(payload["providerDetail"]).get("fragmentResult")
                        except (ValueError, AttributeError):
                            raw = None
                    try:
                        closed = parse_fragment(raw)
                        if closed["status"] != "verified":
                            raise ValueError("L3 fragment has incomplete properties")
                        reports = payload.get("platformReports")
                        if reports is None and isinstance(payload.get("providerDetail"), str):
                            reports = json.loads(payload["providerDetail"]).get("platformReports")
                        if not isinstance(reports, Mapping) or set(reports) != {"source", "target"}:
                            raise ValueError("L3 source/target reports unavailable")
                        from .l3_evidence_closure import parse_dimension
                        for dimension in closed["dimensionResults"].values():
                            parse_dimension(dimension, source_report=reports["source"],
                                            target_report=reports["target"])
                        layer_map["L3"] = ("verified" if closed["claimScope"] == "architectural_intent"
                                           else "diagnostic_verified")
                    except (ValueError, KeyError, TypeError):
                        layer_map["L3"] = "inconclusive"
                if (item.get("level") == "L2"
                        and payload.get("schemaVersion") == L2_FRAGMENT_RESULT_SCHEMA):
                    fragment_result = L2FragmentResult.from_dict(payload)
                    typed_l2 = True
                    if item.get("evidenceIdentity") != fragment_result.evidence_identity:
                        item_status = "inconclusive"
                        layer_map["L2"] = item_status
                    for result in fragment_result.dimension_results:
                        dimensions[result.dimension.value] = result.status.value
                        scopes[result.dimension.value] = result.claim_scope.value
                        execution[result.dimension.value] = {
                            "attempted": result.status.value not in {"not_run", "not_applicable"},
                            "complete": (result.status.value in {"verified", "failed"}
                                         and bool(result.evidence_identity)),
                        }
                elif (item.get("level") != "L2"
                      and payload.get("schemaVersion") == "riscv2x86.validation-dimensions.v1"):
                    raw_dimensions = payload.get("dimensions")
                    if not isinstance(raw_dimensions, Mapping):
                        raise ValueError("validation dimension evidence must be an object")
                    names = list(raw_dimensions)
                    if names != sorted(set(names)):
                        raise ValueError("L2 dimension evidence is not canonical")
                    for name, dimension_result in raw_dimensions.items():
                        if name == "experiment_contract":
                            dimension = name
                        else:
                            raise ValueError("validation dimension is unsupported for its level")
                        if not isinstance(dimension_result, Mapping):
                            raise ValueError("L2 dimension result is malformed")
                        status = str(dimension_result.get("status"))
                        if status == "verified":
                            try:
                                _sha(dimension_result.get("evidenceIdentity"),
                                     "dimension evidence identity")
                            except ValueError:
                                status = "inconclusive"
                        dimensions[dimension] = status
            if item.get("level") == "L2" and not typed_l2:
                layer_map["L2"] = "inconclusive"
            if item.get("level") == "L3" and item_status == "verified" and not (
                    isinstance(detail, str) and detail.startswith("{")):
                layer_map["L3"] = "inconclusive"
        maps.append(layer_map); dimension_maps.append(dimensions); scope_maps.append(scopes)
        execution_maps.append(execution)
    result = {}
    for level in _LEVELS:
        if not any(level in item for item in maps):
            continue
        statuses = [item.get(level, "inconclusive") for item in maps]
        result[level] = ("failed" if "failed" in statuses else
                         "inconclusive" if "inconclusive" in statuses else
                         "diagnostic_verified" if "diagnostic_verified" in statuses else "verified")
    dimension_result = {}
    for dimension in sorted(set(name for item in dimension_maps for name in item)):
        statuses = [item.get(dimension, "inconclusive") for item in dimension_maps]
        dimension_result[dimension] = ("failed" if "failed" in statuses else
                                       "inconclusive" if "inconclusive" in statuses else "verified")
    scope_result = {}
    for dimension in sorted(set(name for item in scope_maps for name in item)):
        values = {item.get(dimension, L2ClaimScope.NONE.value) for item in scope_maps}
        scope_result[dimension] = (
            L2ClaimScope.ARCHITECTURAL.value
            if values == {L2ClaimScope.ARCHITECTURAL.value}
            else L2ClaimScope.DIAGNOSTIC_ONLY.value
            if L2ClaimScope.DIAGNOSTIC_ONLY.value in values
            else L2ClaimScope.APPROVED_FUNCTIONAL_RELATION.value
            if L2ClaimScope.APPROVED_FUNCTIONAL_RELATION.value in values
            else L2ClaimScope.NONE.value
        )
    execution_result = {}
    for dimension in sorted(set(name for item in execution_maps for name in item)):
        values = [item.get(dimension, {"attempted": False, "complete": False})
                  for item in execution_maps]
        execution_result[dimension] = {
            "attempted": any(item["attempted"] for item in values),
            "complete": all(item["complete"] for item in values),
        }
    return result, dimension_result, scope_result, execution_result


def _stage_facts(attempt: object | None) -> dict[str, bool]:
    if attempt is None:
        return {name: False for name in _COVERAGE}
    emitted = attempt.translation_outcome.value in _EMITTED
    return {
        "recognition": True,
        "modeling": bool(attempt.source_model_id),
        "routing": bool(attempt.candidate_route and attempt.plan_id),
        "candidate": bool(emitted and attempt.candidate_replacement),
        "proof": bool(attempt.proof_status == "approved" and attempt.proof_binding_identity),
        "rendering": bool(emitted and attempt.renderer_id and attempt.renderer_version),
    }


def _percentile(values: Sequence[float], p: float) -> float:
    ordered = sorted(values); position = p * (len(ordered) - 1)
    lower = int(position); upper = min(lower + 1, len(ordered) - 1); fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _cluster_metric(rows: Sequence[Mapping[str, object]], predicate, denominator,
                    bootstrap: Bootstrap, salt: str) -> dict[str, object]:
    clusters: dict[str, tuple[int, int]] = {}
    for row in rows:
        if not denominator(row):
            continue
        key = str(row["programId"]); yes, total = clusters.get(key, (0, 0))
        clusters[key] = (yes + int(predicate(row)), total + 1)
    numerator = sum(item[0] for item in clusters.values()); total = sum(item[1] for item in clusters.values())
    if not total:
        return {"estimate": None, "lower": None, "upper": None, "numerator": 0,
                "denominator": 0, "clusters": 0, "confidenceLevel": bootstrap.confidence_level,
                "resamples": bootstrap.resamples, "bootstrapUnit": "program"}
    generator = random.Random(int(sha256(f"{bootstrap.seed}:{salt}".encode()).hexdigest()[:16], 16))
    values = list(clusters.values()); samples = []
    for _ in range(bootstrap.resamples):
        sample = [values[generator.randrange(len(values))] for _ in values]
        sample_total = sum(item[1] for item in sample)
        samples.append(sum(item[0] for item in sample) / sample_total)
    alpha = (1 - bootstrap.confidence_level) / 2
    return {"estimate": numerator / total, "lower": _percentile(samples, alpha),
            "upper": _percentile(samples, 1 - alpha), "numerator": numerator,
            "denominator": total, "clusters": len(clusters),
            "confidenceLevel": bootstrap.confidence_level, "resamples": bootstrap.resamples,
            "bootstrapUnit": "program"}


def aggregate_paper_corpus(manifest: PaperCorpusManifest, *, manifest_directory: str | Path) -> dict[str, object]:
    base = Path(manifest_directory).resolve(); fragments = []; units = []; errors = []; environments = {}
    fragment_validation: dict[str, dict[str, object]] = {}
    eligibility_classification: dict[str, str] = {}
    seen_oracles: set[str] = set()
    l2_execution_sample_keys: set[tuple[str, str, str]] = set()
    for program in manifest.programs:
        source_root = base / program.source_root
        try:
            if _tree_identity(source_root) != program.source_identity:
                raise ValueError("oracle source tree identity mismatch")
            for oracle in program.fragments:
                source = (source_root / oracle.relative_path).resolve()
                if source_root.resolve() not in source.parents or not source.is_file():
                    raise ValueError("oracle fragment source path is unavailable")
                content = source.read_bytes()
                if oracle.end_offset > len(content) or _digest(content[oracle.begin_offset:oracle.end_offset]) != oracle.source_slice_digest:
                    raise ValueError("oracle fragment source slice mismatch")
        except Exception as exc:
            errors.append({"programId": program.program_id, "reasonCode": "paper.oracle-source-invalid",
                           "detail": f"{type(exc).__name__}: {exc}"})
        try:
            archive = load_translation_attempt_archive(base / program.attempt_archive)
            archive_fragment_ids = [item.fragment_id for item in archive.attempts]
            if len(set(archive_fragment_ids)) != len(archive_fragment_ids):
                raise ValueError("attempt archive fragment identities are duplicated")
            by_fragment = {item.fragment_id: item for item in archive.attempts}
            unexpected = sorted(set(by_fragment) - {item.fragment_id for item in program.fragments})
            if unexpected:
                errors.append({"programId": program.program_id,
                               "reasonCode": "paper.unexpected-recognized-fragments",
                               "fragmentIds": unexpected})
        except Exception as exc:
            errors.append({"programId": program.program_id, "reasonCode": "paper.attempt-archive-invalid",
                           "detail": f"{type(exc).__name__}: {exc}"})
            by_fragment = {}
        for oracle in program.fragments:
            if oracle.oracle_fragment_id in seen_oracles:
                errors.append({"programId": program.program_id, "reasonCode": "paper.oracle-identity-duplicated",
                               "oracleFragmentId": oracle.oracle_fragment_id})
            seen_oracles.add(oracle.oracle_fragment_id)
            attempt = by_fragment.get(oracle.fragment_id); stages = _stage_facts(attempt)
            fragments.append({"programId": program.program_id, "oracleFragmentId": oracle.oracle_fragment_id,
                              "fragmentId": oracle.fragment_id, "category": oracle.category,
                              "subcategory": oracle.subcategory, "requiredDimensions": list(oracle.required_dimensions),
                              "attemptArtifactId": "" if attempt is None else attempt.artifact_id,
                              "translationOutcome": "missing" if attempt is None else attempt.translation_outcome.value,
                              "reasonCodes": (["paper.expected-fragment-not-recognized"] if attempt is None
                                              else list(attempt.reason_codes)),
                              **stages})
        for declaration in program.validations:
            path = base / declaration.evaluation_result
            try:
                evaluation = _load_evaluation(path)
                environment = evaluation["targetEnvironment"]
                if environment.get("environmentId") != declaration.expected_environment_id:
                    raise ValueError("evaluation environment does not match oracle")
                actual_unit = str(evaluation.get("validationUnit", "program"))
                actual_group = str(evaluation.get("validationGroupId", ""))
                if actual_unit != declaration.unit or (declaration.unit != "program" and actual_group != declaration.group_id):
                    raise ValueError("evaluation attribution does not match validation unit")
                selected = {item.fragment_id for item in program.fragments
                            if item.oracle_fragment_id in declaration.oracle_fragment_ids}
                expected_attempts = sorted(by_fragment[item].artifact_id for item in selected if item in by_fragment)
                actual_attempts = evaluation.get("selectedAttemptIds", [])
                if declaration.unit == "program":
                    if actual_attempts:
                        raise ValueError("program validation selected individual attempts")
                elif actual_attempts != expected_attempts:
                    raise ValueError("evaluation selected attempts do not match oracle group")
                layers, dimension_statuses, dimension_scopes, dimension_execution = _validation_maps(
                    evaluation, selected,
                )
                linkage = evaluation.get("translationEvaluationLink")
                if isinstance(linkage, Mapping) and isinstance(linkage.get("l2Requirements"), Mapping):
                    from .l2_eligibility import validate_l2_requirement_manifest
                    requirement_manifest = linkage["l2Requirements"]
                    validate_l2_requirement_manifest(requirement_manifest)
                    for requirement in requirement_manifest["requirements"]:
                        eligibility_classification[str(requirement["fragmentId"])] = str(
                            requirement["eligibilityStatus"]
                        )
                raw_execution_evidence = (
                    linkage.get("programExecutionEvidence", [])
                    if isinstance(linkage, Mapping) else []
                )
                if not isinstance(raw_execution_evidence, list):
                    raise ValueError("L2 program execution evidence must be an array")
                for raw_evidence in raw_execution_evidence:
                    if not isinstance(raw_evidence, Mapping):
                        raise ValueError("L2 program execution evidence entry is invalid")
                    evidence = ProgramExecutionEvidence.from_dict(raw_evidence)
                    l2_execution_sample_keys.add(evidence.deduplication_key)
                provenance = evaluation.get("environmentProvenance")
                if not isinstance(provenance, Mapping):
                    raise ValueError("evaluation environment provenance is missing")
                provenance_fields = {"schemaVersion", "kernel", "platform", "machine", "cpuModel",
                                     "microcode", "toolVersions", "runnerVersions", "sourceBuildCommand",
                                     "targetBuildCommand", "runtimeIdentity", "loaderIdentity",
                                     "containerImageDigest"}
                if set(provenance) != provenance_fields or provenance.get("schemaVersion") != "riscv2x86.environment-provenance.v1":
                    raise ValueError("evaluation environment provenance fields are invalid")
                if (not isinstance(provenance.get("toolVersions"), Mapping)
                        or not isinstance(provenance.get("runnerVersions"), Mapping)
                        or not isinstance(provenance.get("sourceBuildCommand"), list)
                        or not isinstance(provenance.get("targetBuildCommand"), list)
                        or any(not isinstance(provenance.get(name), str) or not provenance.get(name)
                               for name in ("kernel", "platform", "machine", "cpuModel", "microcode",
                                            "runtimeIdentity", "loaderIdentity", "containerImageDigest"))):
                    raise ValueError("evaluation environment provenance is incomplete")
                environments[declaration.expected_environment_id] = dict(provenance)
                status = str(evaluation.get("status")); reason_codes = evaluation.get("reasonCodes", [])
                if not isinstance(reason_codes, list):
                    raise ValueError("evaluation reason codes are malformed")
            except Exception as exc:
                errors.append({"programId": program.program_id, "evaluationId": declaration.evaluation_id,
                               "reasonCode": "paper.evaluation-invalid",
                               "detail": f"{type(exc).__name__}: {exc}"})
                layers = {}; dimension_statuses = {}; dimension_scopes = {}; dimension_execution = {}
                status = "invalid"; reason_codes = ["paper.evaluation-invalid"]
            required_dimensions = sorted(set(
                dimension for fragment in program.fragments
                if not declaration.oracle_fragment_ids or fragment.oracle_fragment_id in declaration.oracle_fragment_ids
                for dimension in fragment.required_dimensions
            ))
            units.append({"programId": program.program_id, "category": program.category,
                          "evaluationId": declaration.evaluation_id,
                          "unit": declaration.unit, "groupId": declaration.group_id,
                          "oracleFragmentIds": list(declaration.oracle_fragment_ids), "status": status,
                          "layers": layers, "requiredDimensions": required_dimensions,
                          "dimensions": {name: dimension_statuses.get(name, "inconclusive")
                                         for name in required_dimensions},
                          "dimensionClaimScopes": {
                              name: dimension_scopes.get(name, L2ClaimScope.NONE.value)
                              for name in required_dimensions
                          },
                          "reasonCodes": sorted(set(str(item) for item in reason_codes if str(item))),
                          "environmentId": declaration.expected_environment_id})
            covered_oracles = (
                declaration.oracle_fragment_ids or
                tuple(item.oracle_fragment_id for item in program.fragments)
            )
            for oracle_id in covered_oracles:
                fragment_validation[oracle_id] = {
                    "layers": dict(layers), "dimensions": dict(dimension_statuses),
                    "scopes": dict(dimension_scopes), "execution": dict(dimension_execution),
                }
    for fragment in fragments:
        required = tuple(fragment["requiredDimensions"])
        classifier_status = eligibility_classification.get(str(fragment["fragmentId"]), "")
        # Typed L2 evidence is itself bound to a requirement identity, and thus
        # proves classification for older evaluation fixtures without linkage.
        classified = bool(fragment["recognition"] and (
            classifier_status or fragment["oracleFragmentId"] in fragment_validation
        ))
        eligible = classified and (
            classifier_status == "eligible" if classifier_status else bool(required)
        )
        validation = fragment_validation.get(str(fragment["oracleFragmentId"]), {})
        layers = validation.get("layers", {}) if isinstance(validation, Mapping) else {}
        statuses = validation.get("dimensions", {}) if isinstance(validation, Mapping) else {}
        scopes = validation.get("scopes", {}) if isinstance(validation, Mapping) else {}
        execution = validation.get("execution", {}) if isinstance(validation, Mapping) else {}
        dimension_records = {}
        for dimension in required:
            execution_record = execution.get(dimension, {}) if isinstance(execution, Mapping) else {}
            dimension_records[dimension] = {
                "status": statuses.get(dimension, "not_run") if isinstance(statuses, Mapping) else "not_run",
                "claimScope": scopes.get(dimension, L2ClaimScope.NONE.value)
                if isinstance(scopes, Mapping) else L2ClaimScope.NONE.value,
                "attempted": bool(execution_record.get("attempted", False))
                if isinstance(execution_record, Mapping) else False,
                "complete": bool(execution_record.get("complete", False))
                if isinstance(execution_record, Mapping) else False,
            }
        attempted = any(item["attempted"] for item in dimension_records.values())
        complete = bool(required) and all(item["complete"] for item in dimension_records.values())
        architectural = complete and all(
            item["status"] == "verified" and
            item["claimScope"] == L2ClaimScope.ARCHITECTURAL.value
            for item in dimension_records.values()
        )
        functional = complete and all(
            item["status"] == "verified" and
            item["claimScope"] == L2ClaimScope.APPROVED_FUNCTIONAL_RELATION.value
            for item in dimension_records.values()
        )
        diagnostic = any(
            item["status"] == "verified" and
            item["claimScope"] == L2ClaimScope.DIAGNOSTIC_ONLY.value
            for item in dimension_records.values()
        )
        fragment.update({
            "l2EligibilityClassified": classified,
            "l2EligibilityStatus": (classifier_status if classified and classifier_status
                                    else "eligible" if eligible else
                                    "not_applicable" if classified else "unclassified"),
            "l2Eligible": eligible, "l2Attempted": attempted,
            "l2CompleteExecution": complete,
            "l2ArchitecturalVerified": architectural,
            "l2FunctionalRelationVerified": functional,
            "l2DiagnosticPassed": diagnostic,
            "l2Layers": dict(layers) if isinstance(layers, Mapping) else {},
            "l2DimensionRecords": dimension_records,
        })
    metrics = {}
    for name in _COVERAGE:
        metrics[name + "Coverage"] = _cluster_metric(
            fragments, lambda row, key=name: bool(row[key]), lambda _row: True,
            manifest.bootstrap, name,
        )
    for index, level in enumerate(_LEVELS):
        applies = lambda row, level=level: level in row["layers"]
        verified = (lambda row, level=level: row["layers"].get(level) == "verified"
                    and (level != "L2" or all(
                        row["dimensions"].get(dimension) == "verified"
                        and row["dimensionClaimScopes"].get(dimension) == L2ClaimScope.ARCHITECTURAL.value
                        for dimension in row["requiredDimensions"])))
        metrics[level.lower() + "VerifiedRate"] = _cluster_metric(
            units, verified, applies,
            manifest.bootstrap, level + ":unconditional",
        )
        previous = _LEVELS[:index]
        conditional = lambda row, level=level, previous=previous: (
            level in row["layers"] and all(row["layers"].get(item) == "verified" for item in previous)
        )
        metrics[level.lower() + "ConditionalVerifiedRate"] = _cluster_metric(
            units, verified, conditional,
            manifest.bootstrap, level + ":conditional",
        )
    metrics["l3TargetExperimentDiagnosticRate"] = _cluster_metric(
        units, lambda row: row["layers"].get("L3") == "diagnostic_verified",
        lambda row: "L3" in row["layers"], manifest.bootstrap,
        "L3:target-experiment-diagnostic",
    )
    metrics["l2EligibilityCoverage"] = _cluster_metric(
        fragments, lambda row: row["l2EligibilityClassified"], lambda _row: True,
        manifest.bootstrap, "L2:eligibility-coverage",
    )
    metrics["l2AttemptedCoverage"] = _cluster_metric(
        fragments, lambda row: row["l2Attempted"], lambda row: row["l2Eligible"],
        manifest.bootstrap, "L2:attempted-coverage",
    )
    metrics["l2CompleteExecutionCoverage"] = _cluster_metric(
        fragments, lambda row: row["l2CompleteExecution"], lambda row: row["l2Eligible"],
        manifest.bootstrap, "L2:complete-execution-coverage",
    )
    metrics["l2UnconditionalArchitecturalVerifiedRate"] = _cluster_metric(
        fragments, lambda row: row["l2ArchitecturalVerified"], lambda _row: True,
        manifest.bootstrap, "L2:unconditional-architectural",
    )
    metrics["l2ConditionalArchitecturalVerifiedRate"] = _cluster_metric(
        fragments, lambda row: row["l2ArchitecturalVerified"],
        lambda row: (row["l2Eligible"] and row["l2CompleteExecution"] and
                     row["l2Layers"].get("L0") == "verified" and
                     row["l2Layers"].get("L1") == "verified"),
        manifest.bootstrap, "L2:conditional-architectural",
    )
    metrics["l2VerifiedAmongEligible"] = _cluster_metric(
        fragments, lambda row: row["l2ArchitecturalVerified"],
        lambda row: row["l2Eligible"], manifest.bootstrap, "L2:among-eligible",
    )
    metrics["l2InconclusiveRate"] = _cluster_metric(
        fragments,
        lambda row: row["l2Attempted"] and not row["l2CompleteExecution"],
        lambda row: row["l2Eligible"], manifest.bootstrap, "L2:inconclusive",
    )
    metrics["needsRouteOrUnsupportedRate"] = _cluster_metric(
        fragments, lambda row: row["translationOutcome"] in {"needs_route", "unsupported"},
        lambda _row: True, manifest.bootstrap, "translation:needs-route-unsupported",
    )
    dimensions = {}
    for dimension, level in _DIMENSION_LEVEL.items():
        if level == "L2":
            dimensions[dimension] = _cluster_metric(
                fragments, lambda row, dimension=dimension: (
                    row["l2DimensionRecords"].get(dimension, {}).get("status") == "verified" and
                    row["l2DimensionRecords"].get(dimension, {}).get("claimScope") ==
                        L2ClaimScope.ARCHITECTURAL.value),
                lambda row, dimension=dimension: dimension in row["requiredDimensions"],
                manifest.bootstrap, "dimension:" + dimension,
            )
        else:
            dimensions[dimension] = _cluster_metric(
                units, lambda row, dimension=dimension: row["dimensions"].get(dimension) == "verified",
                lambda row, dimension=dimension: dimension in row["requiredDimensions"],
                manifest.bootstrap, "dimension:" + dimension,
            )
    l2_dimension_summaries = {}
    for dimension in (item.value for item in L2Dimension):
        records = [fragment["l2DimensionRecords"][dimension]
                   for fragment in fragments
                   if dimension in fragment["requiredDimensions"]]
        l2_dimension_summaries[dimension] = {
            "dimension": dimension,
            "required": len(records),
            "attempted": sum(bool(item["attempted"]) for item in records),
            "verifiedArchitectural": sum(
                item["status"] == "verified" and
                item["claimScope"] == L2ClaimScope.ARCHITECTURAL.value
                for item in records),
            "verifiedFunctionalRelation": sum(
                item["status"] == "verified" and
                item["claimScope"] == L2ClaimScope.APPROVED_FUNCTIONAL_RELATION.value
                for item in records),
            "diagnosticPassed": sum(
                item["status"] == "verified" and
                item["claimScope"] == L2ClaimScope.DIAGNOSTIC_ONLY.value
                for item in records),
            "failed": sum(item["status"] == "failed" for item in records),
            "inconclusive": sum(item["status"] == "inconclusive" for item in records),
            "notRun": sum(item["status"] == "not_run" for item in records),
            "notApplicable": sum(item["status"] == "not_applicable" for item in records),
        }
    metrics["l2ApprovedFunctionalRelationVerifiedRate"] = _cluster_metric(
        units,
        lambda row: bool(row["requiredDimensions"]) and all(
            row["dimensions"].get(dimension) == "verified" and
            row["dimensionClaimScopes"].get(dimension) ==
                L2ClaimScope.APPROVED_FUNCTIONAL_RELATION.value
            for dimension in row["requiredDimensions"]),
        lambda row: "L2" in row["layers"], manifest.bootstrap,
        "L2:approved-functional-relation",
    )
    metrics["l2DiagnosticExecutionCoverage"] = _cluster_metric(
        units,
        lambda row: any(
            row["dimensions"].get(dimension) == "verified" and
            row["dimensionClaimScopes"].get(dimension) == L2ClaimScope.DIAGNOSTIC_ONLY.value
            for dimension in row["requiredDimensions"]),
        lambda row: bool(row["requiredDimensions"]), manifest.bootstrap,
        "L2:diagnostic-execution",
    )
    metrics["l2ApprovedFunctionalRelationRate"] = _cluster_metric(
        fragments, lambda row: row["l2FunctionalRelationVerified"],
        lambda row: row["l2Eligible"], manifest.bootstrap, "L2:functional-fragment",
    )
    metrics["l2DiagnosticPassedRate"] = _cluster_metric(
        fragments, lambda row: row["l2DiagnosticPassed"],
        lambda row: row["l2Eligible"], manifest.bootstrap, "L2:diagnostic-fragment",
    )
    outcomes: dict[str, int] = {}
    for row in fragments:
        outcome = str(row["translationOutcome"]); outcomes[outcome] = outcomes.get(outcome, 0) + 1
    category_summaries = []
    for category in sorted(set(str(item["category"]) for item in fragments)):
        category_fragments = [item for item in fragments if item["category"] == category]
        category_units = [item for item in units if item["category"] == category]
        coverage = {name + "Coverage": _cluster_metric(
            category_fragments, lambda row, key=name: bool(row[key]), lambda _row: True,
            manifest.bootstrap, "category:" + category + ":" + name,
        ) for name in _COVERAGE}
        validation = {}
        for index, level in enumerate(_LEVELS):
            category_verified = (lambda row, level=level:
                row["layers"].get(level) == "verified" and
                (level != "L2" or all(
                    row["dimensions"].get(dimension) == "verified" and
                    row["dimensionClaimScopes"].get(dimension) ==
                        L2ClaimScope.ARCHITECTURAL.value
                    for dimension in row["requiredDimensions"])))
            validation[level.lower() + "VerifiedRate"] = _cluster_metric(
                category_units, category_verified,
                lambda row, level=level: level in row["layers"], manifest.bootstrap,
                "category:" + category + ":" + level,
            )
            previous = _LEVELS[:index]
            validation[level.lower() + "ConditionalVerifiedRate"] = _cluster_metric(
                category_units, category_verified,
                lambda row, level=level, previous=previous: level in row["layers"] and all(
                    row["layers"].get(item) == "verified" for item in previous),
                manifest.bootstrap, "category:" + category + ":" + level + ":conditional",
            )
        breakdown: dict[str, int] = {}
        for row in category_fragments:
            outcome = str(row["translationOutcome"]); breakdown[outcome] = breakdown.get(outcome, 0) + 1
        category_summaries.append({"category": category, "coverageMetrics": coverage,
                                   "validationMetrics": validation,
                                   "translationOutcomeBreakdown": dict(sorted(breakdown.items()))})
    reasons: dict[str, int] = {}
    for row in (*fragments, *units):
        for reason in row["reasonCodes"]:
            reasons[reason] = reasons.get(reason, 0) + 1
    metric_definitions = {
        "l2EligibilityCoverage": {"unit": "fragment", "denominator": "all independent oracle expected fragments",
            "numerator": "recognized fragments with a complete eligibility classification"},
        "l2AttemptedCoverage": {"unit": "fragment", "denominator": "L2 eligible fragments",
            "numerator": "fragments for which at least one required-dimension validator was invoked"},
        "l2CompleteExecutionCoverage": {"unit": "fragment", "denominator": "L2 eligible fragments",
            "numerator": "fragments whose every required dimension has verified-or-failed comparison evidence"},
        "l2UnconditionalArchitecturalVerifiedRate": {"unit": "fragment", "denominator": "all corpus oracle fragments",
            "numerator": "architectural L2 verified fragments"},
        "l2ConditionalArchitecturalVerifiedRate": {"unit": "fragment", "denominator": "L0 and L1 verified, L2 eligible fragments with complete required-dimension results",
            "numerator": "architectural L2 verified fragments in that denominator"},
        "l2VerifiedAmongEligible": {"unit": "fragment", "denominator": "L2 eligible fragments",
            "numerator": "architectural L2 verified fragments"},
        "l2ApprovedFunctionalRelationRate": {"unit": "fragment", "denominator": "L2 eligible fragments",
            "numerator": "approved functional-relation verified fragments"},
        "l2DiagnosticPassedRate": {"unit": "fragment", "denominator": "L2 eligible fragments",
            "numerator": "fragments with at least one diagnostic-only verified required dimension"},
        "l3TargetExperimentDiagnosticRate": {"unit": "program/group",
            "denominator": "declared validation units containing L3",
            "numerator": "closed target-only experiment diagnostic units; excluded from architectural L3 verified"},
        "l2InconclusiveRate": {"unit": "fragment", "denominator": "L2 eligible fragments",
            "numerator": "attempted fragments without complete required-dimension comparison evidence"},
        "needsRouteOrUnsupportedRate": {"unit": "fragment", "denominator": "all corpus oracle fragments",
            "numerator": "needs_route or unsupported translation outcomes"},
    }
    for definition in metric_definitions.values():
        definition["bootstrapCluster"] = "program/entry"
    for name in _COVERAGE:
        metric_definitions[name + "Coverage"] = {
            "unit": "fragment", "denominator": "all corpus oracle fragments",
            "numerator": "oracle fragments completing the " + name + " stage",
            "bootstrapCluster": "program/entry",
        }
    for level in _LEVELS:
        metric_definitions.setdefault(level.lower() + "VerifiedRate", {
            "unit": "program/group", "denominator": "declared validation units containing " + level,
            "numerator": level + " verified units", "bootstrapCluster": "program/entry",
        })
        metric_definitions.setdefault(level.lower() + "ConditionalVerifiedRate", {
            "unit": "program/group", "denominator": "declared " + level +
                " units whose preceding validation layers are verified",
            "numerator": level + " verified units", "bootstrapCluster": "program/entry",
        })
    metric_definitions.setdefault("l2ApprovedFunctionalRelationVerifiedRate", {
        "unit": "program/group", "denominator": "declared validation units containing L2",
        "numerator": "units with every required dimension verified under an approved functional relation",
        "bootstrapCluster": "program/entry",
    })
    metric_definitions.setdefault("l2DiagnosticExecutionCoverage", {
        "unit": "program/group", "denominator": "declared units requiring at least one L2 dimension",
        "numerator": "units with a diagnostic-only verified required dimension",
        "bootstrapCluster": "program/entry",
    })
    result = {"schemaVersion": PAPER_REPORT_SCHEMA, "metricPolicy": PAPER_POLICY,
              "corpusId": manifest.corpus_id, "corpusVersion": manifest.corpus_version,
              "statisticalUnit": {"translationEligibilityCoverage": "oracle-fragment",
                                  "dimensionEvidence": "oracle-fragment",
                                  "programDifferential": "declared-program-or-group",
                                  "concurrency": "contract-or-campaign",
                                  "bootstrap": "program-or-entry-cluster"},
              "metricDefinitions": metric_definitions,
              "dimensionMetricDefinition": {
                  "unit": "fragment", "denominator": "oracle fragments requiring the named dimension",
                  "numerator": "verified architectural results for the named dimension",
                  "bootstrapCluster": "program/entry",
              },
              "integrityStatus": "failed" if errors else "verified", "integrityErrors": errors,
              "fragmentRecords": fragments, "validationUnitRecords": units,
              "l2ProgramExecutionSampleCount": len(l2_execution_sample_keys),
              "metrics": metrics, "dimensionMetrics": dimensions,
              "l2DimensionSummaries": l2_dimension_summaries,
              "translationOutcomeBreakdown": dict(sorted(outcomes.items())),
              "categorySummaries": category_summaries,
              "reasonCodeBreakdown": [{"reasonCode": key, "count": reasons[key]} for key in sorted(reasons)],
              "environments": [{"environmentId": key, **environments[key]} for key in sorted(environments)]}
    result["reportIdentity"] = _digest(_canonical(result))
    return result


def render_paper_outputs(result: Mapping[str, object]) -> dict[str, str]:
    metric_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(metric_buffer, fieldnames=["metric", "estimate", "lower", "upper", "numerator",
                                                             "denominator", "clusters", "bootstrapUnit"], lineterminator="\n")
    writer.writeheader()
    for namespace, values in (("", result["metrics"]), ("dimension.", result["dimensionMetrics"])):
        for name, metric in values.items():
            writer.writerow({"metric": namespace + name, **{key: metric[key] for key in
                             ("estimate", "lower", "upper", "numerator", "denominator", "clusters", "bootstrapUnit")}})
    outcome_buffer = io.StringIO(newline="")
    outcome_writer = csv.writer(outcome_buffer, lineterminator="\n"); outcome_writer.writerow(("translationOutcome", "count"))
    outcome_writer.writerows(result["translationOutcomeBreakdown"].items())
    reason_buffer = io.StringIO(newline="")
    reason_writer = csv.DictWriter(reason_buffer, fieldnames=["reasonCode", "count"], lineterminator="\n")
    reason_writer.writeheader(); reason_writer.writerows(result["reasonCodeBreakdown"])
    environment_buffer = io.StringIO(newline="")
    environment_buffer.write(json.dumps(result["environments"], indent=2, sort_keys=True) + "\n")
    md = ["# Paper evaluation report", "", f"Integrity: **{result['integrityStatus']}**", "",
          f"Report identity: `{result['reportIdentity']}`", "", "## Metrics", "",
          "| Metric | Estimate | Numerator | Denominator | Program clusters |", "|---|---:|---:|---:|---:|"]
    for namespace, values in (("", result["metrics"]), ("dimension.", result["dimensionMetrics"])):
        for name, metric in values.items():
            estimate = "n/a" if metric["estimate"] is None else f"{metric['estimate']:.6f}"
            md.append(f"| {namespace}{name} | {estimate} | {metric['numerator']} | {metric['denominator']} | {metric['clusters']} |")
    md.extend(["", "## Metric denominators", "",
               "| Metric | Unit | Numerator | Denominator | Bootstrap cluster |",
               "|---|---|---|---|---|"])
    for name, definition in result["metricDefinitions"].items():
        md.append(f"| {name} | {definition['unit']} | {definition['numerator']} | {definition['denominator']} | {definition['bootstrapCluster']} |")
    dimension_definition = result["dimensionMetricDefinition"]
    md.append(f"| dimension.* | {dimension_definition['unit']} | {dimension_definition['numerator']} | {dimension_definition['denominator']} | {dimension_definition['bootstrapCluster']} |")
    md.extend(["", "## L2 dimension dispositions", "",
               "| Dimension | Required | Attempted | Architectural | Functional | Diagnostic | Failed | Inconclusive | Not run | Not applicable |",
               "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"])
    for item in result["l2DimensionSummaries"].values():
        md.append(
            f"| {item['dimension']} | {item['required']} | {item['attempted']} | "
            f"{item['verifiedArchitectural']} | {item['verifiedFunctionalRelation']} | "
            f"{item['diagnosticPassed']} | {item['failed']} | {item['inconclusive']} | "
            f"{item['notRun']} | {item['notApplicable']} |"
        )
    return {"paper-evaluation.json": json.dumps(result, indent=2, sort_keys=True) + "\n",
            "paper-metrics.csv": metric_buffer.getvalue(), "translation-outcomes.csv": outcome_buffer.getvalue(),
            "failure-breakdown.csv": reason_buffer.getvalue(),
            "environment-provenance.json": environment_buffer.getvalue(), "paper-tables.md": "\n".join(md) + "\n"}


def write_paper_outputs(outputs: Mapping[str, str], output_directory: str | Path) -> None:
    destination = Path(output_directory).resolve()
    if destination.exists():
        raise ValueError("paper output directory exists; refusing to overwrite")
    temporary = destination.with_name(destination.name + ".tmp"); temporary.mkdir(parents=True)
    try:
        for name, content in outputs.items():
            (temporary / name).write_text(content, encoding="utf-8")
        temporary.replace(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True); raise


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-paper-evaluation")
    parser.add_argument("--corpus-manifest", required=True); parser.add_argument("--output-directory", required=True)
    args = parser.parse_args(); path = Path(args.corpus_manifest).resolve(); manifest = load_paper_manifest(path)
    result = aggregate_paper_corpus(manifest, manifest_directory=path.parent)
    write_paper_outputs(render_paper_outputs(result), args.output_directory)
    print(json.dumps({"integrityStatus": result["integrityStatus"], "reportIdentity": result["reportIdentity"]}, sort_keys=True))
    return 0 if result["integrityStatus"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
