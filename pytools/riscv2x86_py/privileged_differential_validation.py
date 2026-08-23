"""Phase-8 differential and engineering validation for privileged routes.

Runners (emulator, VMM, or native target runtime) produce typed observations.
This module compares those observations; it never infers semantics from logs,
assembly text, or target disassembly.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from typing import Mapping, Sequence


PRIVILEGED_DIFFERENTIAL_VALIDATION_VERSION = (
    "privileged-differential-validation.v1"
)


class DifferentialPreservationMode(str, Enum):
    STRICT = "architecture_equivalent"
    FUNCTIONAL = "functional_equivalence_only"


@dataclass(frozen=True)
class PrivilegedMachineObservation:
    runner_id: str
    runtime_version: str
    initial_state_id: str
    csr_state: tuple[tuple[str, str], ...]
    privilege_mode: str
    trap_state: tuple[tuple[str, str], ...]
    continuation_id: str
    memory_state: tuple[tuple[str, str], ...]
    interrupt_state: tuple[tuple[str, str], ...]
    address_translation_state: tuple[tuple[str, str], ...]
    termination_class: str
    observable_effects: tuple[tuple[str, str], ...]
    external_events: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "runner_id", "runtime_version", "initial_state_id",
            "privilege_mode", "continuation_id", "termination_class",
        ):
            if not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        for name in (
            "csr_state", "trap_state", "memory_state", "interrupt_state",
            "address_translation_state", "observable_effects",
        ):
            values = getattr(self, name)
            if tuple(sorted(values)) != values or len(dict(values)) != len(values):
                raise ValueError(f"{name} must be unique and stably sorted")
        if tuple(sorted(set(self.external_events))) != self.external_events:
            raise ValueError("external events must be unique and sorted")


@dataclass(frozen=True)
class EngineeringValidationRecord:
    compiler: str
    optimization: str
    sanitizer: str
    compile_succeeded: bool
    link_succeeded: bool
    runtime_manifest_valid: bool
    final_report_valid: bool
    writeback_valid: bool
    runtime_contract_version: str
    observed_runtime_version: str
    proof_identity: str

    @property
    def complete(self) -> bool:
        return all((
            self.compile_succeeded, self.link_succeeded,
            self.runtime_manifest_valid, self.final_report_valid,
            self.writeback_valid,
            self.runtime_contract_version == self.observed_runtime_version,
            self.proof_identity.startswith("sha256:"),
        ))


@dataclass(frozen=True)
class PrivilegedDifferentialValidationResult:
    approved: bool
    preservation_mode: DifferentialPreservationMode
    compared_effect_ids: tuple[str, ...]
    ignored_state_ids: tuple[str, ...]
    mismatch_codes: tuple[str, ...]
    proof_identity: str
    validation_identity: str
    engineering_matrix_complete: bool


def _manifest_value(manifest: Mapping[str, object], name: str):
    return manifest.get(name)


def _stable_identity(payload: Mapping[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(raw.encode("utf-8")).hexdigest()


def _engineering_reasons(
    records: Sequence[EngineeringValidationRecord],
) -> tuple[list[str], bool]:
    reasons: list[str] = []
    cells = {(x.compiler, x.optimization, x.sanitizer) for x in records}
    required = {
        (compiler, optimization, sanitizer)
        for compiler in ("gcc", "clang")
        for optimization in ("-O0", "-O2", "-O3")
        for sanitizer in ("none", "asan", "ubsan")
    }
    if not required <= cells:
        reasons.append("phase8.privileged.engineering-matrix-incomplete")
    if any(not item.compile_succeeded for item in records):
        reasons.append("phase8.privileged.compile-failed")
    if any(not item.link_succeeded for item in records):
        reasons.append("phase8.privileged.link-failed")
    if any(
        item.runtime_contract_version != item.observed_runtime_version
        for item in records
    ):
        reasons.append("phase8.privileged.runtime-version-mismatch")
    if any(not item.runtime_manifest_valid for item in records):
        reasons.append("phase8.privileged.runtime-manifest-invalid")
    if any(not item.final_report_valid for item in records):
        reasons.append("phase8.privileged.final-report-invalid")
    if any(not item.writeback_valid for item in records):
        reasons.append("phase8.privileged.writeback-invalid")
    if any(not item.proof_identity.startswith("sha256:") for item in records):
        reasons.append("phase8.privileged.proof-identity-invalid")
    return reasons, bool(records) and required <= cells and all(x.complete for x in records)


def validate_privileged_differential(
    *,
    source: PrivilegedMachineObservation,
    target: PrivilegedMachineObservation,
    manifest: Mapping[str, object],
    engineering_records: Sequence[EngineeringValidationRecord],
) -> PrivilegedDifferentialValidationResult:
    """Validate one strict or fallback source/target execution pair."""
    mode = DifferentialPreservationMode(str(
        _manifest_value(manifest, "preservationMode")
    ))
    reasons: list[str] = []
    if source.initial_state_id != target.initial_state_id:
        reasons.append("phase8.privileged.initial-state-mismatch")
    if _manifest_value(manifest, "proofStatus") not in {
        "approved", "functional_approved",
    }:
        reasons.append("phase8.privileged.manifest-not-approved")
    proof_identity = str(
        (manifest.get("proof") or {}).get("identity", "")
        if isinstance(manifest.get("proof"), Mapping) else ""
    )
    if not proof_identity.startswith("sha256:"):
        reasons.append("phase8.privileged.proof-identity-invalid")

    ignored = tuple(sorted(str(x) for x in manifest.get("ignoredSourceState", ())))
    compared: list[str] = []
    if mode is DifferentialPreservationMode.STRICT:
        relations = {
            "csr": source.csr_state == target.csr_state,
            "privilege-mode": source.privilege_mode == target.privilege_mode,
            "trap": source.trap_state == target.trap_state,
            "continuation": source.continuation_id == target.continuation_id,
            "memory": source.memory_state == target.memory_state,
            "interrupt": source.interrupt_state == target.interrupt_state,
            "mmu-tlb": (
                source.address_translation_state
                == target.address_translation_state
            ),
            "termination": (
                source.termination_class == target.termination_class
            ),
        }
        compared.extend(relations)
        reasons.extend(
            "phase8.privileged.strict-" + name + "-mismatch"
            for name, equal in relations.items() if not equal
        )
        if ignored:
            reasons.append("phase8.privileged.strict-ignored-state-forbidden")
        if manifest.get("architectureSemanticsPreserved") is not True:
            reasons.append("phase8.privileged.strict-conclusion-invalid")
    else:
        observable = tuple(sorted(
            str(x) for x in manifest.get("observableEffectsProved", ())
        ))
        source_effects = dict(source.observable_effects)
        target_effects = dict(target.observable_effects)
        for effect_id in observable:
            compared.append(effect_id)
            if effect_id not in source_effects or effect_id not in target_effects:
                reasons.append(
                    "phase8.privileged.observable-effect-missing:" + effect_id
                )
            elif source_effects[effect_id] != target_effects[effect_id]:
                reasons.append(
                    "phase8.privileged.observable-effect-mismatch:" + effect_id
                )
        if not ignored:
            reasons.append("phase8.privileged.ignored-state-manifest-missing")
        if set(ignored) & set(observable):
            reasons.append("phase8.privileged.ignored-state-escape")
        if (
            manifest.get("architectureSemanticsPreserved") is not False
            or manifest.get("microarchitectureSemanticsPreserved") is not False
        ):
            reasons.append("phase8.privileged.fallback-conclusion-invalid")

    engineering_reasons, engineering_complete = _engineering_reasons(
        engineering_records
    )
    reasons.extend(engineering_reasons)
    unique_reasons = tuple(sorted(set(reasons)))
    payload = {
        "version": PRIVILEGED_DIFFERENTIAL_VALIDATION_VERSION,
        "mode": mode.value,
        "sourceRunner": source.runner_id,
        "sourceRuntime": source.runtime_version,
        "targetRunner": target.runner_id,
        "targetRuntime": target.runtime_version,
        "compared": sorted(compared),
        "ignored": list(ignored),
        "reasons": list(unique_reasons),
        "proofIdentity": proof_identity,
        "engineering": [item.__dict__ for item in engineering_records],
    }
    return PrivilegedDifferentialValidationResult(
        approved=not unique_reasons,
        preservation_mode=mode,
        compared_effect_ids=tuple(sorted(set(compared))),
        ignored_state_ids=ignored,
        mismatch_codes=unique_reasons,
        proof_identity=proof_identity,
        validation_identity=_stable_identity(payload),
        engineering_matrix_complete=engineering_complete,
    )
