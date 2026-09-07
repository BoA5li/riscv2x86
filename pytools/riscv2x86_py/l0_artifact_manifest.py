"""Strict expected-artifact contract consumed by the L0 build matrix."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping


L0_ARTIFACT_MANIFEST_SCHEMA = "riscv2x86.l0-artifact-manifest.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(label + " fields are incomplete or unknown")


def _string(value: Mapping[str, object], name: str, label: str, empty: bool = False) -> str:
    item = value.get(name)
    if not isinstance(item, str) or (not empty and not item):
        raise ValueError(f"{label}.{name} must be a string")
    return item


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(label + " must be an array of strings")
    result = tuple(value)
    if tuple(sorted(set(result))) != result:
        raise ValueError(label + " must be unique and sorted")
    return result


def _ordered_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(label + " must be an array of strings")
    result = tuple(value)
    if len(set(result)) != len(result): raise ValueError(label + " must not contain duplicates")
    return result


@dataclass(frozen=True)
class ExpectedElf:
    elf_class: str
    endian: str
    elf_type: str
    machine: str
    os_abi: str
    abi_version: str
    abi_flags: str
    interpreter: str
    needed: tuple[str, ...]
    runpath: tuple[str, ...]
    soname: str
    undefined_symbols: tuple[str, ...]
    relocation_types: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.elf_class not in {"ELF32", "ELF64"} or self.endian not in {"little", "big"}:
            raise ValueError("expected ELF class/endian is invalid")
        if self.elf_type not in {"REL", "EXEC", "DYN"} or not self.machine or not self.os_abi or not self.abi_version:
            raise ValueError("expected ELF type/machine is invalid")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ExpectedElf":
        expected = {"class", "endian", "type", "machine", "osAbi", "abiVersion", "abiFlags", "interpreter",
                    "needed", "runpath", "soname", "undefinedSymbols", "relocationTypes"}
        _fields(value, expected, "expected ELF")
        return cls(_string(value, "class", "elf"), _string(value, "endian", "elf"),
                   _string(value, "type", "elf"), _string(value, "machine", "elf"),
                   _string(value, "osAbi", "elf"), _string(value, "abiVersion", "elf"),
                   _string(value, "abiFlags", "elf", True), _string(value, "interpreter", "elf", True),
                   _strings(value.get("needed"), "elf.needed"), _strings(value.get("runpath"), "elf.runpath"),
                   _string(value, "soname", "elf", True),
                   _strings(value.get("undefinedSymbols"), "elf.undefinedSymbols"),
                   _strings(value.get("relocationTypes"), "elf.relocationTypes"))


@dataclass(frozen=True)
class ExpectedArtifact:
    artifact_digest: str
    object_digest: str
    artifact_kind: str
    compiler_identity: str
    compiler_triple: str
    flags: tuple[str, ...]
    runtime_libraries: tuple[str, ...]
    elf: ExpectedElf
    object_elf: ExpectedElf

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.artifact_digest) or not _SHA256.fullmatch(self.object_digest):
            raise ValueError("expected artifact/object digest is invalid")
        if self.artifact_kind not in {"object", "executable", "shared_library"}:
            raise ValueError("expected artifact kind is invalid")
        if not self.compiler_identity or not self.compiler_triple:
            raise ValueError("expected compiler identity/triple is incomplete")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ExpectedArtifact":
        _fields(value, {"artifactDigest", "objectDigest", "artifactKind", "compilerIdentity", "compilerTriple",
                        "flags", "runtimeLibraries", "elf", "objectElf"}, "expected artifact")
        elf, object_elf = value.get("elf"), value.get("objectElf")
        if not isinstance(elf, Mapping) or not isinstance(object_elf, Mapping):
            raise ValueError("expected artifact ELF contracts must be objects")
        flags = value.get("flags")
        if not isinstance(flags, list) or not all(isinstance(x, str) for x in flags):
            raise ValueError("expected artifact flags must be an array of strings")
        return cls(_string(value, "artifactDigest", "artifact"), _string(value, "objectDigest", "artifact"),
                   _string(value, "artifactKind", "artifact"),
                   _string(value, "compilerIdentity", "artifact"), _string(value, "compilerTriple", "artifact"),
                   tuple(flags), _ordered_strings(value.get("runtimeLibraries"), "artifact.runtimeLibraries"),
                   ExpectedElf.from_dict(elf), ExpectedElf.from_dict(object_elf))


@dataclass(frozen=True)
class L0ArtifactManifest:
    translation_identity: str
    plan_identity: str
    proof_identity: str
    runtime_contract_id: str
    runtime_contract_version: str
    recipe_identity: str
    runtime_headers: tuple[str, ...]
    include_directories: tuple[str, ...]
    library_directories: tuple[str, ...]
    libraries: tuple[str, ...]
    source: ExpectedArtifact
    targets: Mapping[str, ExpectedArtifact]
    schema_version: str = L0_ARTIFACT_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L0_ARTIFACT_MANIFEST_SCHEMA:
            raise ValueError("L0 artifact manifest schema is unsupported")
        if not _SHA256.fullmatch(self.translation_identity):
            raise ValueError("translation identity must be a sha256 identity")
        if not all((self.plan_identity, self.proof_identity, self.runtime_contract_id,
                    self.runtime_contract_version, self.recipe_identity)):
            raise ValueError("L0 artifact manifest translation binding is incomplete")
        if tuple(sorted(self.targets)) != tuple(self.targets):
            raise ValueError("target manifest cells must be canonically ordered")


def l0_artifact_manifest_from_dict(value: Mapping[str, object]) -> L0ArtifactManifest:
    _fields(value, {"schemaVersion", "translationIdentity", "planIdentity", "proofIdentity",
                    "runtimeContractId", "runtimeContractVersion", "recipeIdentity", "runtimeHeaders",
                    "includeDirectories", "libraryDirectories", "libraries", "source", "targets"},
            "L0 artifact manifest")
    source, targets = value.get("source"), value.get("targets")
    if not isinstance(source, Mapping) or not isinstance(targets, Mapping):
        raise ValueError("L0 artifact manifest source/targets must be objects")
    parsed = {}
    for key, item in targets.items():
        if not isinstance(key, str) or not isinstance(item, Mapping):
            raise ValueError("target manifest cell is malformed")
        parsed[key] = ExpectedArtifact.from_dict(item)
    return L0ArtifactManifest(
        _string(value, "translationIdentity", "manifest"), _string(value, "planIdentity", "manifest"),
        _string(value, "proofIdentity", "manifest"), _string(value, "runtimeContractId", "manifest"),
        _string(value, "runtimeContractVersion", "manifest"), _string(value, "recipeIdentity", "manifest"),
        _ordered_strings(value.get("runtimeHeaders"), "manifest.runtimeHeaders"),
        _ordered_strings(value.get("includeDirectories"), "manifest.includeDirectories"),
        _ordered_strings(value.get("libraryDirectories"), "manifest.libraryDirectories"),
        _ordered_strings(value.get("libraries"), "manifest.libraries"),
        ExpectedArtifact.from_dict(source), parsed, _string(value, "schemaVersion", "manifest"),
    )


def load_l0_artifact_manifest(
    path: str | Path, expected_digest: str,
) -> L0ArtifactManifest:
    """Load the exact manifest whose digest was admitted by the caller."""
    manifest_path = Path(path)
    if not _SHA256.fullmatch(expected_digest):
        raise ValueError("translation manifest digest is invalid")
    try:
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise ValueError("translation manifest is unavailable") from exc
    actual_digest = "sha256:" + sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        raise ValueError("translation manifest hash mismatch")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("translation manifest is not valid JSON") from exc
    if not isinstance(raw, Mapping):
        raise ValueError("translation manifest must be an object")
    return l0_artifact_manifest_from_dict(raw)
