"""Commit marker for classified translation artifacts, independent of exit code."""
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from .translation_attempt import load_translation_attempt_archive

SCHEMA = "riscv2x86.requirement-staging.v1"


class RequirementArtifactError(ValueError):
    def __init__(self, level, path, exc, *, expected_identity="", actual_identity="",
                 expected_schema="", actual_schema="", staging=None):
        super().__init__(str(exc))
        self.reason_code = "evaluation." + level + "-requirement-artifact-production-failed"
        self.detail = {
            "schemaVersion": "riscv2x86.requirement-artifact-failure.v1",
            "failureStage": "requirement_staging",
            "exceptionType": type(exc).__name__, "detail": str(exc),
            "artifactPath": str(path), "expectedIdentity": expected_identity,
            "actualIdentity": actual_identity, "expectedSchema": expected_schema,
            "actualSchema": actual_schema,
            "translationOutcome": (staging or {}).get("translationOutcome", ""),
            "publicationOutcome": (staging or {}).get("publicationDisposition", ""),
        }


def read_staged_requirements(report):
    """Single checked ingress for executable requirement artifacts."""
    from .l2_eligibility import validate_l2_requirement_manifest, L2_REQUIREMENT_MANIFEST_SCHEMA
    from .l3_intent_requirements import parse_l3_requirement_manifest, MANIFEST_SCHEMA
    report = Path(report)
    marker = Path(str(report) + ".requirement-staging.json")
    staging = {}
    path, level, expected, actual, schema, actual_schema = marker, "l2", "", "", SCHEMA, ""
    failure_path = Path(str(report) + ".requirement-failure.json")
    if not marker.exists() and failure_path.is_file():
        try:
            failure = json.loads(failure_path.read_text())
            unsigned = {k: v for k, v in failure.items() if k != "failureIdentity"}
            if (failure.get("schemaVersion") != "riscv2x86.requirement-production-failure.v1"
                    or failure.get("failureIdentity") != content_identity(unsigned)
                    or failure.get("translationReportIdentity") != content_identity(
                        json.loads(report.read_text()))):
                raise ValueError("requirement production failure identity is stale")
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            raise RequirementArtifactError("l2", failure_path, exc) from exc
        level = "l3" if failure.get("failureStage") == "l3_intent_production" else "l2"
        error = RequirementArtifactError(level, failure_path, ValueError(failure["detail"]))
        error.detail.update({key: failure[key] for key in (
            "failureStage", "exceptionType", "detail", "artifactPath", "schema", "jsonPath")})
        if "producerFailure" in failure:
            error.detail["producerFailure"] = failure["producerFailure"]
        raise error
    try:
        staging = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(staging, dict):
            raise ValueError("requirement staging root must be an object")
        actual_schema = staging.get("schemaVersion", "")
        unsigned = dict(staging); expected = unsigned.pop("stagingIdentity", "")
        actual = content_identity(unsigned)
        if actual_schema != SCHEMA or expected != actual or staging.get("complete") is not True:
            raise ValueError("requirement staging schema/completeness/identity is invalid")
        result = {}
        for level, schema, validator in (
                ("l2", L2_REQUIREMENT_MANIFEST_SCHEMA, validate_l2_requirement_manifest),
                ("l3", MANIFEST_SCHEMA, parse_l3_requirement_manifest)):
            path = Path(str(report) + "." + level + "-requirements.json")
            expected, actual, actual_schema = staging.get(level + "RequirementIdentity", ""), "", ""
            if staging.get(level + "RequirementDisposition") != "available":
                raise ValueError(level + " requirements are not available for emitted translation")
            if staging.get(level + "RequirementArtifact") != str(path.resolve()):
                raise ValueError("requirement artifact path differs from staged path")
            payload = json.loads(path.read_text(encoding="utf-8"))
            actual = content_identity(payload)
            actual_schema = payload.get("schemaVersion", "") if isinstance(payload, dict) else ""
            if not expected or actual != expected:
                raise ValueError("requirement artifact content identity mismatch")
            validator(payload)
            result[level] = payload
        level = "l2"
        path, schema = report, "translated-report"
        expected, actual_schema = staging.get("translationReportIdentity", ""), ""
        actual = content_identity(json.loads(report.read_text(encoding="utf-8")))
        if actual != expected:
            raise ValueError("staged translation report identity mismatch")
        path = Path(str(report) + ".attempts.json")
        schema = "riscv2x86.translation-attempt-archive.v2"
        expected = staging.get("attemptArchiveIdentity", "")
        actual = load_translation_attempt_archive(path).archive_id
        if actual != expected:
            raise ValueError("staged attempt archive identity mismatch")
        if staging.get("commandDisposition") != "completed":
            raise ValueError("requirements belong to an incomplete translation command")
        if staging.get("publicationDisposition") not in {
                "published", "withheld_pending_validation"}:
            raise ValueError("translation publication state does not permit evaluation")
        return result
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise RequirementArtifactError(level, path, exc, expected_identity=expected,
            actual_identity=actual, expected_schema=schema, actual_schema=actual_schema,
            staging=staging if isinstance(staging, dict) else {}) from exc


def content_identity(value):
    return "sha256:" + sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def atomic_json(path, value):
    """Read back and re-address the closed temporary file before rename."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp",
                                     dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        reread = json.loads(Path(temporary).read_text(encoding="utf-8"))
        if reread != value or content_identity(reread) != content_identity(value):
            raise ValueError("staged artifact readback differs from payload")
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_requirement_staging(report, *, returncode, validation_plan=None):
    report = Path(report)
    translated = json.loads(report.read_text(encoding="utf-8"))
    archive_path = Path(str(report) + ".attempts.json")
    archive = load_translation_attempt_archive(archive_path)
    if not archive.attempts:
        raise ValueError("requirement staging needs terminal attempts")
    outcomes = sorted({item.translation_outcome.value for item in archive.attempts})
    dispositions = {item.staging_disposition.value for item in archive.attempts}
    publication = ("withheld_pending_validation"
                   if "external_validation_pending" in dispositions else
                   "published" if dispositions == {"published"} else
                   "withheld_validation_rejected" if "validation_rejected" in dispositions
                   else "not_applicable")
    value = {"schemaVersion": SCHEMA,
             "commandDisposition": "completed" if returncode >= 0 else "crashed",
             "commandReturnCode": returncode,
             "translationOutcome": outcomes[0] if len(outcomes) == 1 else "mixed",
             "translationOutcomes": outcomes,
             "publicationDisposition": publication,
             "translationReportIdentity": content_identity(translated),
             "attemptArchiveIdentity": archive.archive_id,
             "validationPlanArtifact": str(Path(validation_plan).resolve()) if validation_plan else "",
             "validationPlanIdentity": "",
             "complete": True}
    if validation_plan:
        value["validationPlanIdentity"] = content_identity(
            json.loads(Path(validation_plan).read_text(encoding="utf-8")))
    for level in ("l2", "l3"):
        path = Path(str(report) + "." + level + "-requirements.json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        disposition = ("route_required" if outcomes == ["needs_route"] else
                       "unsupported" if outcomes == ["unsupported"] else
                       "not_applicable" if outcomes == ["failed"] else "available")
        value[level + "RequirementDisposition"] = disposition
        value[level + "RequirementArtifact"] = str(path.resolve())
        value[level + "RequirementIdentity"] = content_identity(payload)
    value["stagingIdentity"] = content_identity(value)
    atomic_json(str(report) + ".requirement-staging.json", value)
    return value


def verify_requirement_staging(report):
    report = Path(report)
    value = json.loads(Path(str(report) + ".requirement-staging.json").read_text(encoding="utf-8"))
    unsigned = dict(value); claimed = unsigned.pop("stagingIdentity", None)
    if value.get("schemaVersion") != SCHEMA or claimed != content_identity(unsigned) \
            or value.get("complete") is not True:
        raise ValueError("requirement staging manifest identity is invalid")
    if content_identity(json.loads(report.read_text(encoding="utf-8"))) != value["translationReportIdentity"]:
        raise ValueError("staged translation report identity mismatch")
    if load_translation_attempt_archive(str(report) + ".attempts.json").archive_id != value["attemptArchiveIdentity"]:
        raise ValueError("staged attempt archive identity mismatch")
    for level in ("l2", "l3"):
        path = Path(str(report) + "." + level + "-requirements.json")
        if str(path.resolve()) != value[level + "RequirementArtifact"] or content_identity(
                json.loads(path.read_text(encoding="utf-8"))) != value[level + "RequirementIdentity"]:
            raise ValueError("staged " + level + " requirement identity mismatch")
    if value["validationPlanArtifact"] and content_identity(json.loads(
            Path(value["validationPlanArtifact"]).read_text(encoding="utf-8"))) != value["validationPlanIdentity"]:
        raise ValueError("staged validation plan identity mismatch")
    return value


def write_requirement_failure(report, exc, stage):
    """Preserve the producer exception without publishing an available marker."""
    report = Path(report)
    payload = {
        "schemaVersion": "riscv2x86.requirement-production-failure.v1",
        "translationReportIdentity": content_identity(json.loads(report.read_text())),
        "failureStage": stage, "exceptionType": type(exc).__name__,
        "detail": str(exc), "artifactPath": str(report),
        "schema": "translated-report", "jsonPath": "$",
    }
    diagnostic = getattr(exc, "producer_failure", None)
    if isinstance(diagnostic, dict):
        payload.update(producerFailure=diagnostic,
            artifactPath=diagnostic["executionTranscriptPath"],
            schema="riscv2x86.l3-intent-execution-diagnostic.v1", jsonPath="$.stdout")
    atomic_json(str(report) + ".requirement-failure.json",
                {**payload, "failureIdentity": content_identity(payload)})
