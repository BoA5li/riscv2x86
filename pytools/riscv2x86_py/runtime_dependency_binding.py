"""Closed, content-checked binding from translation approvals to shipped runtimes."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterable, Mapping

from .helper_runtime_manifest import get_runtime_helper_contract

_EMITTED = {"emitted", "strengthened", "functional_fallback"}
_NO_RUNTIME = {"", "riscv2x86.runtime.none"}


@dataclass(frozen=True)
class RuntimeBuildDependencies:
    contract_ids: tuple[str, ...] = ()
    headers: tuple[str, ...] = ()
    include_directories: tuple[str, ...] = ()
    library_directories: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    library_paths: tuple[str, ...] = ()


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _string_array(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(label + " must be an array of non-empty strings")
    if value != sorted(set(value)):
        raise ValueError(label + " must be unique and canonical")
    return tuple(value)


def resolve_runtime_contracts(
    contract_ids: Iterable[str], *, root: str | Path | None = None,
) -> RuntimeBuildDependencies:
    base = repository_root() if root is None else Path(root).resolve()
    include = base / "runtime" / "include"
    library_dir = base / "build"
    headers: set[str] = set()
    libraries: set[str] = set()
    resolved_ids: set[str] = set()
    for contract_id in contract_ids:
        if contract_id in _NO_RUNTIME:
            continue
        contract = get_runtime_helper_contract(contract_id)
        if contract is None:
            raise ValueError("unregistered runtime contract: " + contract_id)
        header = include / contract.required_header
        library_name = contract.runtime_library
        archive = library_dir / (library_name + ("" if library_name.endswith(".a") else ".a"))
        if not header.is_file():
            raise ValueError("registered runtime header is unavailable: " + str(header))
        if not archive.is_file():
            raise ValueError("registered runtime library is unavailable: " + str(archive))
        resolved_ids.add(contract_id)
        headers.add(contract.required_header)
        libraries.add(library_name.removeprefix("lib").removesuffix(".a"))
    ordered_libraries = tuple(sorted(libraries))
    return RuntimeBuildDependencies(
        tuple(sorted(resolved_ids)), tuple(sorted(headers)),
        (str(include),) if headers else (),
        (str(library_dir),) if libraries else (),
        ordered_libraries,
        tuple(str(library_dir / ("lib" + name + ".a")) for name in ordered_libraries),
    )


def dependencies_from_translated_report(
    report_path: str | Path, *, root: str | Path | None = None,
) -> RuntimeBuildDependencies:
    raw = json.loads(Path(report_path).read_text(encoding="utf-8"))
    findings = raw.get("findings") if isinstance(raw, Mapping) else None
    if not isinstance(findings, list):
        raise ValueError("translated report findings are malformed")
    contract_ids: set[str] = set()
    declarations: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise ValueError("translated report finding is malformed")
        if finding.get("translationOutcome") not in _EMITTED:
            continue
        approval = finding.get("approvalArtifact")
        if not isinstance(approval, Mapping):
            raise ValueError("emitted finding lacks approval artifact")
        contract_id = approval.get("runtimeContractId") or approval.get("helperRuntimeContractId") or ""
        if not isinstance(contract_id, str):
            raise ValueError("runtime contract id must be a string")
        if contract_id in _NO_RUNTIME:
            continue
        canonical_present = ("requiredHeaders" in approval or "requiredLibraries" in approval)
        legacy_present = ("helperRequiredHeader" in approval or "helperRuntimeLibrary" in approval)
        if canonical_present:
            headers = _string_array(approval.get("requiredHeaders"), "requiredHeaders")
            libraries = _string_array(approval.get("requiredLibraries"), "requiredLibraries")
        elif legacy_present:
            legacy_header = approval.get("helperRequiredHeader")
            legacy_library = approval.get("helperRuntimeLibrary")
            if (not isinstance(legacy_header, str) or not legacy_header
                    or not isinstance(legacy_library, str) or not legacy_library):
                raise ValueError("legacy helper runtime dependency binding is incomplete")
            headers, libraries = (legacy_header,), (legacy_library,)
        else:
            raise ValueError("runtime-bearing approval lacks dependency declarations")
        if legacy_present:
            legacy_header = approval.get("helperRequiredHeader")
            legacy_library = approval.get("helperRuntimeLibrary")
            if (not isinstance(legacy_header, str) or not legacy_header
                    or not isinstance(legacy_library, str) or not legacy_library):
                raise ValueError("legacy helper runtime dependency binding is incomplete")
            if headers != (legacy_header,) or libraries != (legacy_library,):
                raise ValueError("canonical/legacy runtime dependency declarations conflict")
        contract_ids.add(contract_id)
        declarations.append((contract_id, headers, libraries))
    resolved = resolve_runtime_contracts(contract_ids, root=root)
    for contract_id, headers, libraries in declarations:
        contract = get_runtime_helper_contract(contract_id)
        assert contract is not None
        if contract.required_header not in headers or contract.runtime_library not in libraries:
            raise ValueError("approval/runtime registry dependency mismatch: " + contract_id)
    return resolved
