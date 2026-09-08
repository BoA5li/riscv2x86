"""Materialize archived translation candidates into an isolated source tree."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
from typing import Mapping

from .schema import Finding, TranslationOutcome, load_report
from .translation_attempt import (
    TranslationAttempt, TranslationAttemptArchive, load_translation_attempt_archive,
)


CANDIDATE_ARTIFACT_MANIFEST_SCHEMA = "riscv2x86.candidate-artifact-manifest.v1"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_EMITTED = {
    TranslationOutcome.EMITTED, TranslationOutcome.STRENGTHENED,
    TranslationOutcome.FUNCTIONAL_FALLBACK,
}


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _identity(value: Mapping[str, object]) -> str:
    return _digest_bytes(_canonical(value))


def _tree_digest(root: Path) -> str:
    entries: list[dict[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError("candidate source trees cannot contain symbolic links")
        if path.is_file():
            entries.append({
                "path": path.relative_to(root).as_posix(),
                "digest": _digest_bytes(path.read_bytes()),
            })
    return _identity({"files": entries})


def candidate_tree_digest(root: str | Path) -> str:
    """Public canonical tree hash used by evaluation-bound promotion."""
    path = Path(root).resolve()
    if not path.is_dir():
        raise ValueError("candidate tree root is unavailable")
    return _tree_digest(path)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _source_path(finding: Finding, source_root: Path) -> Path:
    raw = Path(finding.fileName or (finding.fragment.fileName if finding.fragment else ""))
    candidates = (raw, source_root / raw) if raw.is_absolute() else (source_root / raw,)
    for candidate in candidates:
        resolved = candidate.resolve()
        if _is_within(resolved, source_root) and resolved.is_file():
            return resolved
    raise ValueError("finding source file is unavailable or outside source root")


def _required_headers(finding: Finding) -> tuple[str, ...]:
    values: list[str] = []
    for artifact in (finding.publicApprovalArtifact, finding.approvalArtifact):
        if not isinstance(artifact, Mapping):
            continue
        headers = artifact.get("requiredHeaders", [])
        if isinstance(headers, list):
            values.extend(item for item in headers if isinstance(item, str) and item)
        helper = artifact.get("helperRequiredHeader")
        if isinstance(helper, str) and helper:
            values.append(helper)
    result = tuple(sorted(set(values)))
    if any(re.fullmatch(r"[A-Za-z0-9_./+-]+", item) is None for item in result):
        raise ValueError("candidate required header is unsafe")
    return result


def _insert_headers(content: bytes, headers: tuple[str, ...]) -> bytes:
    if not headers:
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("candidate source file is not UTF-8") from exc
    missing = [item for item in headers if f"#include <{item}>" not in text]
    if not missing:
        return content
    prefix = "".join(f"#include <{item}>\n" for item in missing)
    return (prefix + text).encode("utf-8")


@dataclass(frozen=True)
class CandidateEditManifest:
    finding_id: str
    attempt_artifact_id: str
    relative_path: str
    begin_offset: int
    end_offset: int
    source_slice_digest: str
    candidate_replacement_digest: str
    before_file_digest: str
    after_file_digest: str
    binding_complete: bool
    required_headers: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.finding_id or not self.relative_path:
            raise ValueError("candidate edit identity/path is incomplete")
        path = Path(self.relative_path)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("candidate edit path is unsafe")
        if self.begin_offset < 0 or self.end_offset <= self.begin_offset:
            raise ValueError("candidate edit range is invalid")
        for value in (self.attempt_artifact_id, self.source_slice_digest,
                      self.candidate_replacement_digest, self.before_file_digest,
                      self.after_file_digest):
            if _SHA256.fullmatch(value) is None:
                raise ValueError("candidate edit contains an invalid digest")
        if self.required_headers != tuple(sorted(set(self.required_headers))):
            raise ValueError("candidate edit headers are not canonical")

    def to_dict(self) -> dict[str, object]:
        return {
            "findingId": self.finding_id, "attemptArtifactId": self.attempt_artifact_id,
            "relativePath": self.relative_path, "beginOffset": self.begin_offset,
            "endOffset": self.end_offset, "sourceSliceDigest": self.source_slice_digest,
            "candidateReplacementDigest": self.candidate_replacement_digest,
            "beforeFileDigest": self.before_file_digest, "afterFileDigest": self.after_file_digest,
            "bindingComplete": self.binding_complete, "requiredHeaders": list(self.required_headers),
        }


@dataclass(frozen=True)
class CandidateArtifactManifest:
    source_root_identity: str
    staging_root_identity: str
    source_tree_digest: str
    target_tree_digest: str
    attempt_archive_id: str
    translated_report_digest: str
    edits: tuple[CandidateEditManifest, ...]
    manifest_id: str = ""
    schema_version: str = CANDIDATE_ARTIFACT_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != CANDIDATE_ARTIFACT_MANIFEST_SCHEMA:
            raise ValueError("candidate artifact manifest schema is unsupported")
        for value in (self.source_root_identity, self.staging_root_identity,
                      self.source_tree_digest, self.target_tree_digest,
                      self.attempt_archive_id, self.translated_report_digest):
            if _SHA256.fullmatch(value) is None:
                raise ValueError("candidate artifact manifest contains invalid digest")
        keys = tuple((item.relative_path, item.begin_offset, item.end_offset) for item in self.edits)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("candidate artifact edits are not canonical and unique")
        expected = _identity(self._payload(False))
        if self.manifest_id and self.manifest_id != expected:
            raise ValueError("candidate artifact manifest ID does not match content")
        object.__setattr__(self, "manifest_id", expected)

    def _payload(self, include_id: bool) -> dict[str, object]:
        result: dict[str, object] = {
            "schemaVersion": self.schema_version,
            "sourceRootIdentity": self.source_root_identity,
            "stagingRootIdentity": self.staging_root_identity,
            "sourceTreeDigest": self.source_tree_digest,
            "targetTreeDigest": self.target_tree_digest,
            "attemptArchiveId": self.attempt_archive_id,
            "translatedReportDigest": self.translated_report_digest,
            "edits": [item.to_dict() for item in self.edits],
        }
        if include_id:
            result["manifestId"] = self.manifest_id
        return result

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


def _attempts_by_index(archive: TranslationAttemptArchive, count: int) -> dict[int, TranslationAttempt]:
    result: dict[int, TranslationAttempt] = {}
    for attempt in archive.attempts:
        match = re.fullmatch(r"finding:(\d+):.*", attempt.finding_id)
        if match is None:
            raise ValueError("attempt finding identity cannot be joined to report")
        index = int(match.group(1))
        if index >= count or index in result:
            raise ValueError("attempt archive/report finding coverage is invalid")
        result[index] = attempt
    if set(result) != set(range(count)):
        raise ValueError("attempt archive does not cover every report finding exactly once")
    return result


def materialize_candidate_tree(
    *, source_root: str | Path, staging_root: str | Path,
    translated_report: str | Path, attempt_archive: str | Path,
    manifest_output: str | Path,
) -> CandidateArtifactManifest:
    source = Path(source_root).resolve()
    staging = Path(staging_root).resolve()
    report_path = Path(translated_report).resolve()
    archive_path = Path(attempt_archive).resolve()
    destination = Path(manifest_output).resolve()
    if not source.is_dir():
        raise ValueError("candidate source root is not a directory")
    if source == staging or _is_within(staging, source) or _is_within(source, staging):
        raise ValueError("source and staging trees must not overlap")
    if staging.exists():
        raise ValueError("candidate staging root already exists; refusing to overwrite")
    if destination.exists():
        raise ValueError("candidate manifest already exists; refusing to overwrite")
    findings = load_report(str(report_path))
    archive = load_translation_attempt_archive(archive_path)
    attempts = _attempts_by_index(archive, len(findings))
    source_digest = _tree_digest(source)
    shutil.copytree(source, staging, symlinks=False)
    edit_manifests: list[CandidateEditManifest] = []
    edits_by_path: dict[Path, list[tuple[int, int, Finding, TranslationAttempt]]] = {}
    try:
        for index, finding in enumerate(findings):
            attempt = attempts[index]
            if attempt.translation_outcome not in _EMITTED:
                continue
            if attempt.fragment_id != str(getattr(finding.fragment, "id", "") or attempt.fragment_id):
                raise ValueError("attempt/report fragment identity mismatch")
            embedded = finding.translationAttemptArtifact
            if not isinstance(embedded, Mapping):
                raise ValueError("report translation attempt artifact is malformed")
            if (embedded.get("candidateReplacementDigest") != attempt.candidate_replacement_digest
                    or embedded.get("translationOutcome") != attempt.translation_outcome.value):
                raise ValueError("attempt archive is not bound to translated report")
            begin = finding.rewriteBeginOffset
            end = finding.rewriteEndOffset
            if end <= begin and finding.fragment is not None:
                begin, end = finding.fragment.beginOffset, finding.fragment.endOffset
            if end <= begin or begin < 0:
                raise ValueError("candidate finding has no valid rewrite range")
            path = _source_path(finding, source)
            edits_by_path.setdefault(path, []).append((begin, end, finding, attempt))

        for source_path, edits in sorted(edits_by_path.items(), key=lambda item: item[0].as_posix()):
            edits.sort(key=lambda item: (item[0], item[1]))
            for previous, current in zip(edits, edits[1:]):
                if previous[1] > current[0]:
                    raise ValueError("candidate edits overlap")
            relative = source_path.relative_to(source)
            target_path = staging / relative
            before = source_path.read_bytes()
            result = before
            pending: list[tuple[int, int, Finding, TranslationAttempt, str, tuple[str, ...]]] = []
            for begin, end, finding, attempt in edits:
                if end > len(before):
                    raise ValueError("candidate rewrite range exceeds source file")
                source_slice = before[begin:end]
                if not finding.rawSourceText:
                    raise ValueError("candidate finding has no authoritative source slice")
                if source_slice != finding.rawSourceText.encode("utf-8"):
                    raise ValueError("candidate source slice is stale")
                pending.append((begin, end, finding, attempt, _digest_bytes(source_slice), _required_headers(finding)))
            for begin, end, _finding, attempt, _slice_digest, _headers in reversed(pending):
                result = result[:begin] + attempt.candidate_replacement.encode("utf-8") + result[end:]
            all_headers = tuple(sorted(set(header for item in pending for header in item[5])))
            result = _insert_headers(result, all_headers)
            temporary = target_path.with_name(target_path.name + ".candidate.tmp")
            temporary.write_bytes(result)
            temporary.replace(target_path)
            after_digest = _digest_bytes(target_path.read_bytes())
            if after_digest != _digest_bytes(result):
                raise ValueError("candidate file post-write digest mismatch")
            before_digest = _digest_bytes(before)
            for begin, end, _finding, attempt, slice_digest, headers in pending:
                edit_manifests.append(CandidateEditManifest(
                    attempt.finding_id, attempt.artifact_id, relative.as_posix(), begin, end,
                    slice_digest, attempt.candidate_replacement_digest,
                    before_digest, after_digest, attempt.binding_complete, headers,
                ))
        target_digest = _tree_digest(staging)
        manifest = CandidateArtifactManifest(
            source_root_identity=_identity({"role": "source", "treeDigest": source_digest}),
            staging_root_identity=_identity({"role": "candidate-target", "treeDigest": target_digest}),
            source_tree_digest=source_digest, target_tree_digest=target_digest,
            attempt_archive_id=archive.archive_id,
            translated_report_digest=_digest_bytes(report_path.read_bytes()),
            edits=tuple(sorted(edit_manifests, key=lambda item: (item.relative_path, item.begin_offset, item.end_offset))),
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(destination)
        # Re-read both artifacts after all writes; this is the E2 second-hash gate.
        if _tree_digest(staging) != manifest.target_tree_digest:
            raise ValueError("candidate target tree changed after manifest creation")
        return manifest
    except Exception:
        # A partial tree must never masquerade as a materialized candidate.
        shutil.rmtree(staging, ignore_errors=True)
        destination.unlink(missing_ok=True)
        raise


def load_candidate_artifact_manifest(path: str | Path) -> CandidateArtifactManifest:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("candidate artifact manifest root must be an object")
    expected = {"schemaVersion", "manifestId", "sourceRootIdentity", "stagingRootIdentity",
                "sourceTreeDigest", "targetTreeDigest", "attemptArchiveId",
                "translatedReportDigest", "edits"}
    if set(value) != expected or value.get("schemaVersion") != CANDIDATE_ARTIFACT_MANIFEST_SCHEMA:
        raise ValueError("candidate artifact manifest fields are invalid")
    raw_edits = value.get("edits")
    if not isinstance(raw_edits, list):
        raise ValueError("candidate artifact manifest edits are invalid")
    edits: list[CandidateEditManifest] = []
    edit_fields = {"findingId", "attemptArtifactId", "relativePath", "beginOffset", "endOffset",
                   "sourceSliceDigest", "candidateReplacementDigest", "beforeFileDigest",
                   "afterFileDigest", "bindingComplete", "requiredHeaders"}
    for raw in raw_edits:
        if not isinstance(raw, Mapping) or set(raw) != edit_fields:
            raise ValueError("candidate edit manifest fields are invalid")
        headers = raw["requiredHeaders"]
        if not isinstance(headers, list) or tuple(headers) != tuple(sorted(set(headers))):
            raise ValueError("candidate edit headers are not canonical")
        for name in ("beginOffset", "endOffset"):
            if isinstance(raw[name], bool) or not isinstance(raw[name], int):
                raise ValueError("candidate edit offsets are invalid")
        if not isinstance(raw["bindingComplete"], bool):
            raise ValueError("candidate edit binding flag is invalid")
        edits.append(CandidateEditManifest(
            str(raw["findingId"]), str(raw["attemptArtifactId"]), str(raw["relativePath"]),
            raw["beginOffset"], raw["endOffset"], str(raw["sourceSliceDigest"]),
            str(raw["candidateReplacementDigest"]), str(raw["beforeFileDigest"]),
            str(raw["afterFileDigest"]), raw["bindingComplete"], tuple(headers),
        ))
    return CandidateArtifactManifest(
        source_root_identity=str(value["sourceRootIdentity"]),
        staging_root_identity=str(value["stagingRootIdentity"]),
        source_tree_digest=str(value["sourceTreeDigest"]),
        target_tree_digest=str(value["targetTreeDigest"]),
        attempt_archive_id=str(value["attemptArchiveId"]),
        translated_report_digest=str(value["translatedReportDigest"]),
        edits=tuple(edits), manifest_id=str(value["manifestId"]),
        schema_version=str(value["schemaVersion"]),
    )


def verify_candidate_artifact_manifest(
    manifest: CandidateArtifactManifest, *, source_root: str | Path,
    staging_root: str | Path, translated_report: str | Path,
    attempt_archive: str | Path,
) -> None:
    """Revalidate the complete E2 binding before a later build/evaluation."""
    source = Path(source_root).resolve()
    staging = Path(staging_root).resolve()
    report = Path(translated_report).resolve()
    archive = load_translation_attempt_archive(attempt_archive)
    source_digest = _tree_digest(source)
    target_digest = _tree_digest(staging)
    checks = (
        (manifest.source_tree_digest, source_digest, "source tree"),
        (manifest.target_tree_digest, target_digest, "target tree"),
        (manifest.attempt_archive_id, archive.archive_id, "attempt archive"),
        (manifest.translated_report_digest, _digest_bytes(report.read_bytes()), "translated report"),
        (manifest.source_root_identity,
         _identity({"role": "source", "treeDigest": source_digest}), "source identity"),
        (manifest.staging_root_identity,
         _identity({"role": "candidate-target", "treeDigest": target_digest}), "target identity"),
    )
    for expected, actual, label in checks:
        if expected != actual:
            raise ValueError("candidate artifact " + label + " binding mismatch")
