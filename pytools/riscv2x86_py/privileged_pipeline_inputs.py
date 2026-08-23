"""CLI/pipeline ingress for privileged translation authority inputs.

This module only parses and validates versioned Phase-4 declarations and
versioned target registries.  It never derives privileged semantics from
assembly text.  Phase 5 remains responsible for joining these declarations
with canonical p-code and CFG facts.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterable, Mapping

from .functional_observability import (
    IgnoredPrivilegedStateKind,
    IgnoredStateDeclaration,
)
from .privileged_execution_sidecar import (
    PrivilegedExecutionSidecar,
    SourceExecutionProfile,
    TargetExecutionMode,
    load_privileged_execution_sidecar,
)
from .privileged_functional_contracts import (
    PRIVILEGED_FUNCTIONAL_REGISTRY_SCHEMA,
    PrivilegedFunctionalFallbackContract,
    PrivilegedFunctionalFallbackPolicy,
    PrivilegedFunctionalFallbackRegistry,
)
from .privileged_runtime_contracts import (
    PRIVILEGED_RUNTIME_REGISTRY_SCHEMA,
    PrivilegedRuntimeContract,
    PrivilegedRuntimeRegistry,
)


PRIVILEGED_OBSERVABILITY_SIDECAR_SCHEMA = (
    "riscv2x86.privileged-observability-sidecar.v1"
)
PRIVILEGED_IGNORED_STATE_SIDECAR_SCHEMA = (
    "riscv2x86.privileged-ignored-state-declarations.v1"
)


def _object(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    return value


def _text(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} must be a non-empty string")
    return value.strip()


def _optional_text(value: object, what: str) -> str | None:
    return None if value is None else _text(value, what)


def _boolean(value: object, what: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{what} must be a boolean")
    return value


def _strings(value: object, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{what} must be an array")
    result = tuple(_text(item, what) for item in value)
    if len(result) != len(set(result)):
        raise ValueError(f"{what} must not contain duplicates")
    return tuple(sorted(result))


def _indexes(value: object, what: str) -> tuple[int, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in value
    ):
        raise ValueError(f"{what} must contain non-negative integers")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise ValueError(f"{what} must not contain duplicates")
    return result


def _load_json(path: str | Path) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class PrivilegedObservabilityDeclaration:
    fragment_id: str
    source_execution_profile: SourceExecutionProfile
    observable_contract_id: str
    declared_ignored_state_ids: tuple[str, ...]
    complete: bool
    provenance: str

    def __post_init__(self) -> None:
        for name in ("fragment_id", "observable_contract_id", "provenance"):
            if not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if tuple(sorted(set(self.declared_ignored_state_ids))) != (
            self.declared_ignored_state_ids
        ):
            raise ValueError("declared ignored-state ids must be unique and sorted")


@dataclass(frozen=True)
class PrivilegedObservabilitySidecar:
    schema_version: str
    declarations: tuple[PrivilegedObservabilityDeclaration, ...]
    provenance: str

    def __post_init__(self) -> None:
        if self.schema_version != PRIVILEGED_OBSERVABILITY_SIDECAR_SCHEMA:
            raise ValueError("unsupported privileged observability schemaVersion")
        ids = tuple(item.fragment_id for item in self.declarations)
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate privileged observability fragmentId")

    def declaration_for(
        self, fragment_id: str
    ) -> PrivilegedObservabilityDeclaration | None:
        return next(
            (item for item in self.declarations if item.fragment_id == fragment_id),
            None,
        )


@dataclass(frozen=True)
class FragmentIgnoredStateDeclarations:
    fragment_id: str
    declarations: tuple[IgnoredStateDeclaration, ...]
    complete: bool
    provenance: str

    def __post_init__(self) -> None:
        ids = tuple(item.state_id for item in self.declarations)
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate ignored privileged stateId")


@dataclass(frozen=True)
class PrivilegedIgnoredStateSidecar:
    schema_version: str
    entries: tuple[FragmentIgnoredStateDeclarations, ...]
    provenance: str

    def __post_init__(self) -> None:
        if self.schema_version != PRIVILEGED_IGNORED_STATE_SIDECAR_SCHEMA:
            raise ValueError("unsupported privileged ignored-state schemaVersion")
        ids = tuple(item.fragment_id for item in self.entries)
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate ignored-state fragmentId")

    def declarations_for(
        self, fragment_id: str
    ) -> tuple[IgnoredStateDeclaration, ...]:
        item = next(
            (entry for entry in self.entries if entry.fragment_id == fragment_id),
            None,
        )
        return () if item is None else item.declarations


@dataclass(frozen=True)
class PrivilegedPipelineInputs:
    execution_sidecar: PrivilegedExecutionSidecar | None
    runtime_registry: PrivilegedRuntimeRegistry | None
    functional_registry: PrivilegedFunctionalFallbackRegistry | None
    observability_sidecar: PrivilegedObservabilitySidecar | None
    ignored_state_declarations: PrivilegedIgnoredStateSidecar | None
    preservation_policy: PrivilegedFunctionalFallbackPolicy

    def __post_init__(self) -> None:
        if not isinstance(
            self.preservation_policy, PrivilegedFunctionalFallbackPolicy
        ):
            raise TypeError("privileged preservation policy must be typed")
        if self.preservation_policy.enabled and self.functional_registry is None:
            # The flag changes policy only.  Absence of a registry remains a
            # normal fail-closed state rather than fabricating any contract.
            return

    def validate_fragment_membership(
        self, fragment_ids: Iterable[str]
    ) -> tuple[str, ...]:
        known = frozenset(fragment_ids)
        reasons: list[str] = []
        sources = (
            (
                "execution",
                () if self.execution_sidecar is None else
                tuple(x.fragment_id for x in self.execution_sidecar.facts_by_fragment_id),
            ),
            (
                "observability",
                () if self.observability_sidecar is None else
                tuple(x.fragment_id for x in self.observability_sidecar.declarations),
            ),
            (
                "ignored-state",
                () if self.ignored_state_declarations is None else
                tuple(x.fragment_id for x in self.ignored_state_declarations.entries),
            ),
        )
        for source_name, ids in sources:
            for fragment_id in ids:
                if fragment_id not in known:
                    reasons.append(
                        "privileged-ingress."
                        + source_name
                        + "-fragment-not-in-translation-unit:"
                        + fragment_id
                    )
        return tuple(sorted(reasons))


def privileged_observability_sidecar_from_dict(
    value: object,
) -> PrivilegedObservabilitySidecar:
    data = _object(value, "privileged observability sidecar")
    if data.get("schemaVersion") != PRIVILEGED_OBSERVABILITY_SIDECAR_SCHEMA:
        raise ValueError("unsupported privileged observability schemaVersion")
    provenance = _text(data.get("provenance"), "provenance")
    raw = data.get("fragments")
    if not isinstance(raw, list):
        raise ValueError("privileged observability fragments must be an array")
    result = []
    for item in raw:
        entry = _object(item, "privileged observability declaration")
        result.append(PrivilegedObservabilityDeclaration(
            fragment_id=_text(entry.get("fragmentId"), "fragmentId"),
            source_execution_profile=SourceExecutionProfile(
                entry.get("sourceExecutionProfile")
            ),
            observable_contract_id=_text(
                entry.get("observableContractId"), "observableContractId"
            ),
            declared_ignored_state_ids=_strings(
                entry.get("declaredIgnoredStateIds", []),
                "declaredIgnoredStateIds",
            ),
            complete=_boolean(entry.get("complete"), "complete", False),
            provenance=_text(entry.get("provenance", provenance), "provenance"),
        ))
    return PrivilegedObservabilitySidecar(
        PRIVILEGED_OBSERVABILITY_SIDECAR_SCHEMA,
        tuple(sorted(result, key=lambda item: item.fragment_id)),
        provenance,
    )


def privileged_ignored_state_sidecar_from_dict(
    value: object,
) -> PrivilegedIgnoredStateSidecar:
    data = _object(value, "privileged ignored-state sidecar")
    if data.get("schemaVersion") != PRIVILEGED_IGNORED_STATE_SIDECAR_SCHEMA:
        raise ValueError("unsupported privileged ignored-state schemaVersion")
    provenance = _text(data.get("provenance"), "provenance")
    raw = data.get("fragments")
    if not isinstance(raw, list):
        raise ValueError("ignored-state fragments must be an array")
    entries = []
    for item in raw:
        entry = _object(item, "ignored-state fragment")
        declarations = []
        raw_declarations = entry.get("declarations")
        if not isinstance(raw_declarations, list):
            raise ValueError("ignored-state declarations must be an array")
        entry_provenance = _text(
            entry.get("provenance", provenance), "provenance"
        )
        for declaration in raw_declarations:
            declared = _object(declaration, "ignored-state declaration")
            declarations.append(IgnoredStateDeclaration(
                state_id=_text(declared.get("stateId"), "stateId"),
                kind=IgnoredPrivilegedStateKind(declared.get("kind")),
                justification=_text(
                    declared.get("justification"), "justification"
                ),
                provenance=_text(
                    declared.get("provenance", entry_provenance), "provenance"
                ),
                complete=_boolean(
                    declared.get("complete"), "declaration.complete", False
                ),
            ))
        entries.append(FragmentIgnoredStateDeclarations(
            fragment_id=_text(entry.get("fragmentId"), "fragmentId"),
            declarations=tuple(sorted(
                declarations, key=lambda declaration: declaration.state_id
            )),
            complete=_boolean(entry.get("complete"), "complete", False),
            provenance=entry_provenance,
        ))
    return PrivilegedIgnoredStateSidecar(
        PRIVILEGED_IGNORED_STATE_SIDECAR_SCHEMA,
        tuple(sorted(entries, key=lambda item: item.fragment_id)),
        provenance,
    )


def _runtime_contract(value: object) -> PrivilegedRuntimeContract:
    item = _object(value, "privileged runtime contract")
    return PrivilegedRuntimeContract(
        contract_id=_text(item.get("contractId"), "contractId"),
        semantic_version=_text(item.get("semanticVersion"), "semanticVersion"),
        source_privileged_identity=_text(
            item.get("sourcePrivilegedIdentity"), "sourcePrivilegedIdentity"
        ),
        target_environment_id=_text(
            item.get("targetEnvironmentId"), "targetEnvironmentId"
        ),
        runtime_symbol=_text(item.get("runtimeSymbol"), "runtimeSymbol"),
        required_target_capability=_text(
            item.get("requiredTargetCapability"), "requiredTargetCapability"
        ),
        required_headers=_strings(item.get("requiredHeaders", []), "requiredHeaders"),
        required_library=_optional_text(
            item.get("requiredLibrary"), "requiredLibrary"
        ),
        argument_operand_indexes=_indexes(
            item.get("argumentOperandIndexes", []), "argumentOperandIndexes"
        ),
        result_operand_indexes=_indexes(
            item.get("resultOperandIndexes", []), "resultOperandIndexes"
        ),
        **{
            name: _boolean(item.get(json_name), json_name, default)
            for name, json_name, default in (
                ("preserves_architectural_state", "preservesArchitecturalState", True),
                ("preserves_shell", "preservesShell", True),
                ("preserves_volatile_execution", "preservesVolatileExecution", True),
                ("preserves_compiler_memory_ordering", "preservesCompilerMemoryOrdering", True),
                ("preserves_cc_clobber", "preservesCcClobber", True),
                ("preserves_memory_effects", "preservesMemoryEffects", True),
                ("preserves_trap_behavior", "preservesTrapBehavior", True),
                ("preserves_control_flow", "preservesControlFlow", True),
                ("preserves_microarchitecture_intent", "preservesMicroarchitectureIntent", False),
                ("abi_isolated", "abiIsolated", True),
                ("may_return", "mayReturn", True),
                ("may_unwind", "mayUnwind", False),
                ("complete", "complete", True),
            )
        },
    )


def privileged_runtime_registry_from_dict(
    value: object,
) -> PrivilegedRuntimeRegistry:
    data = _object(value, "privileged runtime registry")
    if data.get("schemaVersion") != PRIVILEGED_RUNTIME_REGISTRY_SCHEMA:
        raise ValueError("unsupported privileged runtime registry schemaVersion")
    version = _text(data.get("version"), "version")
    raw = data.get("contracts")
    if not isinstance(raw, list):
        raise ValueError("privileged runtime contracts must be an array")
    return PrivilegedRuntimeRegistry(
        version=version, contracts=tuple(_runtime_contract(item) for item in raw)
    )


def _functional_contract(value: object) -> PrivilegedFunctionalFallbackContract:
    item = _object(value, "privileged functional contract")
    return PrivilegedFunctionalFallbackContract(
        contract_id=_text(item.get("contractId"), "contractId"),
        semantic_version=_text(item.get("semanticVersion"), "semanticVersion"),
        source_privileged_identity=_text(
            item.get("sourcePrivilegedIdentity"), "sourcePrivilegedIdentity"
        ),
        source_observability_identity=_text(
            item.get("sourceObservabilityIdentity"), "sourceObservabilityIdentity"
        ),
        target_environment_id=_text(
            item.get("targetEnvironmentId"), "targetEnvironmentId"
        ),
        implementation_id=_text(item.get("implementationId"), "implementationId"),
        required_target_capability=_text(
            item.get("requiredTargetCapability"), "requiredTargetCapability"
        ),
        required_headers=_strings(item.get("requiredHeaders", []), "requiredHeaders"),
        required_library=_optional_text(
            item.get("requiredLibrary"), "requiredLibrary"
        ),
        argument_operand_indexes=_indexes(
            item.get("argumentOperandIndexes", []), "argumentOperandIndexes"
        ),
        result_operand_indexes=_indexes(
            item.get("resultOperandIndexes", []), "resultOperandIndexes"
        ),
        ignored_state_ids=_strings(
            item.get("ignoredStateIds", []), "ignoredStateIds"
        ),
        required_value_source_ids=_strings(
            item.get("requiredValueSourceIds", []), "requiredValueSourceIds"
        ),
        **{
            name: _boolean(item.get(json_name), json_name, default)
            for name, json_name, default in (
                ("preserves_outputs", "preservesOutputs", True),
                ("preserves_memory", "preservesMemory", True),
                ("preserves_errors", "preservesErrors", True),
                ("preserves_termination", "preservesTermination", True),
                ("preserves_traps", "preservesTraps", True),
                ("preserves_shell", "preservesShell", True),
                ("preserves_volatile_execution", "preservesVolatileExecution", True),
                ("preserves_compiler_memory_ordering", "preservesCompilerMemoryOrdering", True),
                ("preserves_cc_clobber", "preservesCcClobber", True),
                ("functional_equivalence_only", "functionalEquivalenceOnly", True),
                ("may_return", "mayReturn", True),
                ("may_unwind", "mayUnwind", False),
                ("complete", "complete", True),
            )
        },
    )


def privileged_functional_registry_from_dict(
    value: object,
) -> PrivilegedFunctionalFallbackRegistry:
    data = _object(value, "privileged functional registry")
    if data.get("schemaVersion") != PRIVILEGED_FUNCTIONAL_REGISTRY_SCHEMA:
        raise ValueError("unsupported privileged functional registry schemaVersion")
    version = _text(data.get("version"), "version")
    raw = data.get("contracts")
    if not isinstance(raw, list):
        raise ValueError("privileged functional contracts must be an array")
    return PrivilegedFunctionalFallbackRegistry(
        version=version,
        contracts=tuple(_functional_contract(item) for item in raw),
    )


def load_privileged_runtime_registry(
    path: str | Path,
) -> PrivilegedRuntimeRegistry:
    return privileged_runtime_registry_from_dict(_load_json(path))


def load_privileged_functional_registry(
    path: str | Path,
) -> PrivilegedFunctionalFallbackRegistry:
    return privileged_functional_registry_from_dict(_load_json(path))


def load_privileged_observability_sidecar(
    path: str | Path,
) -> PrivilegedObservabilitySidecar:
    return privileged_observability_sidecar_from_dict(_load_json(path))


def load_privileged_ignored_state_sidecar(
    path: str | Path,
) -> PrivilegedIgnoredStateSidecar:
    return privileged_ignored_state_sidecar_from_dict(_load_json(path))


def load_privileged_pipeline_inputs(
    *,
    execution_sidecar_path: str | Path | None,
    runtime_registry_path: str | Path | None,
    functional_registry_path: str | Path | None,
    observability_sidecar_path: str | Path | None,
    ignored_state_declarations_path: str | Path | None,
    allow_functional_fallbacks: bool,
) -> PrivilegedPipelineInputs:
    return PrivilegedPipelineInputs(
        execution_sidecar=(
            None if execution_sidecar_path is None
            else load_privileged_execution_sidecar(execution_sidecar_path)
        ),
        runtime_registry=(
            None if runtime_registry_path is None
            else load_privileged_runtime_registry(runtime_registry_path)
        ),
        functional_registry=(
            None if functional_registry_path is None
            else load_privileged_functional_registry(functional_registry_path)
        ),
        observability_sidecar=(
            None if observability_sidecar_path is None
            else load_privileged_observability_sidecar(observability_sidecar_path)
        ),
        ignored_state_declarations=(
            None if ignored_state_declarations_path is None
            else load_privileged_ignored_state_sidecar(
                ignored_state_declarations_path
            )
        ),
        preservation_policy=PrivilegedFunctionalFallbackPolicy(
            enabled=allow_functional_fallbacks
        ),
    )
