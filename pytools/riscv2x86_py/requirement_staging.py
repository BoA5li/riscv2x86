"""Commit marker for classified translation artifacts, independent of exit code."""
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from .translation_attempt import load_translation_attempt_archive

SCHEMA = "riscv2x86.requirement-staging.v1"


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
