"""Versioned target contracts for strict privileged-state adaptation.

The registry is an authority supplied by the target deployment.  It does not
infer a runtime symbol from a CSR name, mnemonic, or source text.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Iterable, Mapping

from .privileged_state_adapter import SourcePrivilegedSemanticModel


PRIVILEGED_RUNTIME_REGISTRY_SCHEMA = (
    "riscv2x86.privileged-runtime-registry.v2"
)
PRIVILEGED_EFFECT_MAPPING_SCHEMA = "riscv2x86.privileged-effect-mapping.v1"


def source_effect_id(kind: str, block_address: int, operation_index: int) -> str:
    if not isinstance(kind, str) or not kind.strip():
        raise TypeError("effect kind must be a non-empty string")
    return f"{kind.strip()}@0x{block_address:x}:{operation_index}"


@dataclass(frozen=True)
class TargetCsrStateMapping:
    source_effect_id: str
    source_csr_id: str
    source_field_ids: tuple[str, ...]
    target_state_object_id: str
    target_operation_id: str
    old_new_state_relation_id: str
    access_trap_mapping_id: str | None
    complete: bool = True


@dataclass(frozen=True)
class TargetTrapMapping:
    source_effect_id: str
    cause_mapping_id: str
    tval_mapping_id: str
    handler_mapping_id: str
    continuation_mapping_id: str
    target_error_or_result_mapping_id: str
    complete: bool = True


@dataclass(frozen=True)
class TargetInterruptMapping:
    source_effect_id: str
    target_event_state_id: str
    enable_pending_relation_id: str
    delegation_priority_relation_id: str
    wait_wakeup_relation_id: str | None
    complete: bool = True


@dataclass(frozen=True)
class TargetAddressTranslationMapping:
    source_effect_id: str
    target_address_space_id: str
    root_mode_relation_id: str
    scope_relation_id: str
    synchronization_relation_id: str
    shootdown_relation_id: str
    complete: bool = True


@dataclass(frozen=True)
class TargetVirtualizationMapping:
    source_effect_id: str
    target_virtualization_state_id: str
    state_relation_id: str
    complete: bool = True


@dataclass(frozen=True)
class TargetDebugMapping:
    source_effect_id: str
    target_debug_state_id: str
    state_relation_id: str
    complete: bool = True


@dataclass(frozen=True)
class TargetObservableEffectMapping:
    source_observable_id: str
    target_observable_id: str
    relation_id: str
    complete: bool = True


@dataclass(frozen=True)
class TargetPrivilegedShellConstraint:
    preserves_volatile: bool
    preserves_memory_clobber: bool
    preserves_cc_clobber: bool
    complete: bool


@dataclass(frozen=True)
class TargetPrivilegedMemoryConstraint:
    preserves_memory_effects: bool
    preserves_compiler_ordering: bool
    complete: bool


@dataclass(frozen=True)
class TargetPrivilegedControlFlowConstraint:
    preserves_traps: bool
    preserves_control_flow: bool
    may_return: bool
    may_unwind: bool
    complete: bool


def _validate_mappings(values: tuple[object, ...], name: str) -> None:
    ids = tuple(getattr(item, "source_effect_id", None) for item in values)
    if any(not isinstance(item, str) or not item for item in ids):
        raise TypeError(f"{name} require source effect identities")
    if len(set(ids)) != len(ids):
        raise ValueError(f"{name} contain duplicate source effect mappings")
    if tuple(sorted(ids)) != ids:
        raise ValueError(f"{name} must use stable source-effect sorting")
    if any(getattr(item, "complete", None) is not True for item in values):
        raise ValueError(f"{name} must be complete")


def target_environment_identity(environment: object) -> str:
    architecture = getattr(getattr(environment, "architecture", None), "value", None)
    abi = getattr(getattr(environment, "abi", None), "value", None)
    dialect = getattr(getattr(environment, "asm_dialect", None), "value", None)
    if not all(isinstance(value, str) and value for value in (architecture, abi, dialect)):
        raise TypeError("target environment identity is incomplete")
    return f"{architecture}:{abi}:{dialect}"


def privileged_source_identity(model: SourcePrivilegedSemanticModel) -> str:
    """Bind a strict contract only to architecture-relevant source facts."""
    if not isinstance(model, SourcePrivilegedSemanticModel):
        raise TypeError("privileged source identity requires the Phase-6A model")
    payload = repr((
        model.state,
        model.semantic_classes,
        model.read_only_counter,
        model.requires_whole_function_lowering,
        model.strict_translation_eligible,
        model.strict_reason_codes,
    ))
    return "sha256:" + sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PrivilegedRuntimeContract:
    contract_id: str
    semantic_version: str
    source_privileged_identity: str
    target_environment_id: str
    runtime_symbol: str
    required_target_capability: str
    source_execution_profile: str = "riscv_user_process"
    target_execution_mode: str = "x86_user_process"
    renderer_contract_id: str = "privileged-runtime-call.v1"
    runtime_contract_set_id: str = "default-privileged-runtime-set"
    effect_mapping_schema: str = PRIVILEGED_EFFECT_MAPPING_SCHEMA
    csr_mappings: tuple[TargetCsrStateMapping, ...] = ()
    trap_mappings: tuple[TargetTrapMapping, ...] = ()
    interrupt_mappings: tuple[TargetInterruptMapping, ...] = ()
    address_translation_mappings: tuple[TargetAddressTranslationMapping, ...] = ()
    virtualization_mappings: tuple[TargetVirtualizationMapping, ...] = ()
    debug_mappings: tuple[TargetDebugMapping, ...] = ()
    observable_effect_mappings: tuple[TargetObservableEffectMapping, ...] = ()
    required_headers: tuple[str, ...] = ()
    required_library: str | None = None
    argument_operand_indexes: tuple[int, ...] = ()
    result_operand_indexes: tuple[int, ...] = ()
    preserves_architectural_state: bool = True
    preserves_shell: bool = True
    preserves_volatile_execution: bool = True
    preserves_compiler_memory_ordering: bool = True
    preserves_cc_clobber: bool = True
    preserves_memory_effects: bool = True
    preserves_trap_behavior: bool = True
    preserves_control_flow: bool = True
    preserves_microarchitecture_intent: bool = False
    abi_isolated: bool = True
    may_return: bool = True
    may_unwind: bool = False
    complete: bool = True

    def __post_init__(self) -> None:
        for name in (
            "contract_id", "semantic_version", "source_privileged_identity",
            "target_environment_id", "runtime_symbol",
            "required_target_capability",
            "source_execution_profile", "target_execution_mode",
            "renderer_contract_id", "runtime_contract_set_id", "effect_mapping_schema",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise TypeError(f"{name} must be a non-empty stripped string")
        if tuple(sorted(set(self.required_headers))) != self.required_headers:
            raise ValueError("required headers must be unique and sorted")
        for name in ("argument_operand_indexes", "result_operand_indexes"):
            values = getattr(self, name)
            if any(isinstance(item, bool) or not isinstance(item, int) or item < 0
                   for item in values):
                raise TypeError(f"{name} must contain non-negative integers")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicates")
        for name in (
            "csr_mappings", "trap_mappings", "interrupt_mappings",
            "address_translation_mappings", "virtualization_mappings",
            "debug_mappings",
        ):
            _validate_mappings(getattr(self, name), name)
        for name in (
            "preserves_architectural_state", "preserves_shell",
            "preserves_volatile_execution",
            "preserves_compiler_memory_ordering", "preserves_cc_clobber",
            "preserves_memory_effects", "preserves_trap_behavior",
            "preserves_control_flow", "preserves_microarchitecture_intent",
            "abi_isolated", "may_return", "may_unwind", "complete",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")

    @property
    def semantic_contract_id(self) -> str:
        return f"privileged-runtime.{self.contract_id}@{self.semantic_version}"


class PrivilegedRuntimeRegistry:
    def __init__(
        self,
        *,
        version: str,
        contracts: Iterable[PrivilegedRuntimeContract] = (),
    ) -> None:
        if not isinstance(version, str) or not version.strip():
            raise TypeError("privileged runtime registry requires a version")
        entries = tuple(contracts)
        by_key: dict[tuple[str, str], PrivilegedRuntimeContract] = {}
        ids: set[tuple[str, str]] = set()
        for contract in entries:
            if not isinstance(contract, PrivilegedRuntimeContract):
                raise TypeError("registry entries must be privileged contracts")
            identity = (contract.contract_id, contract.semantic_version)
            if identity in ids:
                raise ValueError("duplicate privileged runtime contract identity")
            ids.add(identity)
            key = (
                contract.source_privileged_identity,
                contract.target_environment_id,
            )
            if key in by_key:
                raise ValueError("ambiguous privileged runtime source/target key")
            by_key[key] = contract
        self.version = version.strip()
        self.schema_version = PRIVILEGED_RUNTIME_REGISTRY_SCHEMA
        self._contracts: Mapping[tuple[str, str], PrivilegedRuntimeContract] = (
            MappingProxyType(by_key)
        )

    def resolve(
        self,
        source: SourcePrivilegedSemanticModel,
        target_environment: object,
    ) -> PrivilegedRuntimeContract | None:
        return self._contracts.get((
            privileged_source_identity(source),
            target_environment_identity(target_environment),
        ))

    @property
    def semantic_contract_ids(self) -> frozenset[str]:
        return frozenset(
            contract.semantic_contract_id
            for contract in self._contracts.values()
        )

    @property
    def required_target_capabilities(self) -> frozenset[str]:
        return frozenset(
            contract.required_target_capability
            for contract in self._contracts.values()
        )


EMPTY_PRIVILEGED_RUNTIME_REGISTRY = PrivilegedRuntimeRegistry(
    version="privileged-runtime-registry.empty.v1"
)


@dataclass(frozen=True)
class TargetPrivilegedRuntimeConstraint:
    runtime_contract: PrivilegedRuntimeContract
    source_privileged_identity: str
    target_environment_id: str
    registry_version: str
    contract_id: str
    contract_version: str
    source_execution_profile: str
    target_execution_mode: str
    csr_mappings: tuple[TargetCsrStateMapping, ...]
    trap_mappings: tuple[TargetTrapMapping, ...]
    interrupt_mappings: tuple[TargetInterruptMapping, ...]
    address_translation_mappings: tuple[TargetAddressTranslationMapping, ...]
    virtualization_mappings: tuple[TargetVirtualizationMapping, ...]
    debug_mappings: tuple[TargetDebugMapping, ...]
    shell_constraint: TargetPrivilegedShellConstraint
    memory_constraint: TargetPrivilegedMemoryConstraint
    control_flow_constraint: TargetPrivilegedControlFlowConstraint
    ignored_source_state: tuple[str, ...]
    observable_effect_mappings: tuple[TargetObservableEffectMapping, ...]
    runtime_symbol_or_intrinsic: str
    required_headers: tuple[str, ...]
    required_libraries: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    functional_fallback: bool
    complete: bool
    forbids_generic_helper_fallback: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.runtime_contract, PrivilegedRuntimeContract):
            raise TypeError("runtime contract must be typed")
        for name in (
            "source_privileged_identity", "target_environment_id",
            "registry_version",
            "contract_id", "contract_version", "source_execution_profile",
            "target_execution_mode", "runtime_symbol_or_intrinsic",
        ):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise TypeError(f"{name} must be non-empty")
        if self.forbids_generic_helper_fallback is not True:
            raise ValueError("privileged constraint must forbid generic helper fallback")
        if self.functional_fallback:
            raise ValueError("strict privileged constraint cannot be a fallback")
        if not self.complete:
            raise ValueError("privileged effect mapping constraint must be complete")
        for name in (
            "csr_mappings", "trap_mappings", "interrupt_mappings",
            "address_translation_mappings", "virtualization_mappings",
            "debug_mappings",
        ):
            _validate_mappings(getattr(self, name), name)
        if self.ignored_source_state:
            raise ValueError("strict mapping cannot ignore source state")
