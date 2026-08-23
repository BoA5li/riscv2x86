"""Versioned target contracts for strict privileged-state adaptation.

The registry is an authority supplied by the target deployment.  It does not
infer a runtime symbol from a CSR name, mnemonic, or source text.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from types import MappingProxyType
from typing import Iterable, Mapping
import re

from .privileged_state_adapter import SourcePrivilegedSemanticModel


PRIVILEGED_RUNTIME_REGISTRY_SCHEMA = (
    "riscv2x86.privileged-runtime-registry.v2"
)
PRIVILEGED_EFFECT_MAPPING_SCHEMA = "riscv2x86.privileged-effect-mapping.v1"
PRIVILEGED_MAPPING_REGISTRY_SCHEMA = "riscv2x86.privileged-mapping-registry.v1"


class PrivilegedMappingRegistryKind(str, Enum):
    STATE = "state"
    TRAP = "trap"
    INTERRUPT = "interrupt"
    MMU = "mmu"


@dataclass(frozen=True)
class VersionedPrivilegedMappingRegistry:
    registry_id: str
    semantic_version: str
    kind: PrivilegedMappingRegistryKind
    mappings: tuple[object, ...]
    complete: bool = True

    def __post_init__(self) -> None:
        for name in ("registry_id", "semantic_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise TypeError(f"{name} must be a non-empty stripped string")
        if not isinstance(self.kind, PrivilegedMappingRegistryKind):
            raise TypeError("mapping registry kind must be typed")
        _validate_mappings(self.mappings, f"{self.kind.value} mapping registry")
        if not self.complete:
            raise ValueError("mapping registry must be complete")

    @property
    def versioned_id(self) -> str:
        return f"{self.registry_id}@{self.semantic_version}"


class PrivilegedMappingRegistrySet:
    def __init__(self, *, version: str, registries: Iterable[VersionedPrivilegedMappingRegistry] = ()):
        if not isinstance(version, str) or not version.strip():
            raise TypeError("mapping registry set requires a version")
        by_id = {}
        for registry in tuple(registries):
            if not isinstance(registry, VersionedPrivilegedMappingRegistry):
                raise TypeError("mapping registry entries must be typed")
            if registry.versioned_id in by_id:
                raise ValueError("duplicate versioned privileged mapping registry")
            by_id[registry.versioned_id] = registry
        self.version = version.strip()
        self.schema_version = PRIVILEGED_MAPPING_REGISTRY_SCHEMA
        self._registries = MappingProxyType(by_id)

    def resolve(self, versioned_id: str, kind: PrivilegedMappingRegistryKind):
        registry = self._registries.get(versioned_id)
        return registry if registry is not None and registry.kind is kind else None


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


def source_semantic_contract_identity(model: SourcePrivilegedSemanticModel) -> tuple[str, str]:
    state = model.state
    if state is None or not state.effect_model_version:
        raise TypeError("source privileged semantic contract is incomplete")
    return "riscv2x86.source-privileged-state", state.effect_model_version


def isa_extension_profile_identity(model: SourcePrivilegedSemanticModel) -> str:
    state = model.state
    if state is None:
        raise TypeError("source privileged state is missing")
    return "extensions:" + ",".join(state.source_isa_extensions)


def target_runtime_identity(model: SourcePrivilegedSemanticModel) -> tuple[str, str]:
    state = model.state
    raw = None if state is None else state.target_runtime_contract_set_id
    if not isinstance(raw, str) or not raw:
        return "default-privileged-runtime-set", "unknown"
    match = re.fullmatch(r"(.+)-v([A-Za-z0-9_.-]+)", raw)
    return (match.group(1), match.group(2)) if match else (raw, "unknown")


@dataclass(frozen=True)
class PrivilegedRuntimeContract:
    contract_id: str
    semantic_version: str
    source_privileged_identity: str
    target_environment_id: str
    runtime_symbol: str
    required_target_capability: str
    supported_source_profiles: tuple[str, ...] = ("riscv_user_process",)
    supported_target_modes: tuple[str, ...] = ("x86_user_process",)
    supported_semantic_classes: tuple[str, ...] = ("counter_observation",)
    source_semantic_contract_id: str = "riscv2x86.source-privileged-state"
    source_semantic_version: str = "privileged-effect-model.v2"
    privilege_spec_version: str = "unknown"
    isa_extension_profile_id: str = "extensions:"
    runtime_identity: str = "default-privileged-runtime-set"
    runtime_contract_version: str = "1"
    state_mapping_registry_id: str = "state.empty@1"
    trap_mapping_registry_id: str = "trap.empty@1"
    interrupt_mapping_registry_id: str = "interrupt.empty@1"
    mmu_mapping_registry_id: str = "mmu.empty@1"
    callable_identifier: str = "privileged_runtime_callable"
    abi_contract_id: str = "c-abi.v1"
    memory_effect_contract_id: str = "memory-effect.exact.v1"
    control_flow_effect_contract_id: str = "control-flow.exact.v1"
    unwind_policy_id: str = "nounwind.v1"
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
    required_libraries: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
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
            "source_semantic_contract_id", "source_semantic_version",
            "privilege_spec_version", "isa_extension_profile_id",
            "runtime_identity", "runtime_contract_version",
            "state_mapping_registry_id", "trap_mapping_registry_id",
            "interrupt_mapping_registry_id", "mmu_mapping_registry_id",
            "callable_identifier", "abi_contract_id", "memory_effect_contract_id",
            "control_flow_effect_contract_id", "unwind_policy_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise TypeError(f"{name} must be a non-empty stripped string")
        if tuple(sorted(set(self.required_headers))) != self.required_headers:
            raise ValueError("required headers must be unique and sorted")
        for name in ("required_libraries", "required_capabilities"):
            values = getattr(self, name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{name} must be unique and sorted")
        if self.required_library is not None and self.required_library not in self.required_libraries:
            raise ValueError("legacy required_library must be present in required_libraries")
        if self.required_target_capability not in self.required_capabilities:
            raise ValueError("legacy target capability must be present in required_capabilities")
        for name in ("supported_source_profiles", "supported_target_modes", "supported_semantic_classes"):
            values = getattr(self, name)
            if not values or tuple(sorted(set(values))) != values:
                raise ValueError(f"{name} must be non-empty, unique, and sorted")
        if self.source_execution_profile not in self.supported_source_profiles:
            raise ValueError("source execution profile is outside contract support")
        if self.target_execution_mode not in self.supported_target_modes:
            raise ValueError("target execution mode is outside contract support")
        if self.callable_identifier != self.runtime_symbol:
            raise ValueError("callable identifier must exactly bind runtime symbol")
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
        mapping_registries: PrivilegedMappingRegistrySet | None = None,
    ) -> None:
        if not isinstance(version, str) or not version.strip():
            raise TypeError("privileged runtime registry requires a version")
        entries = tuple(contracts)
        if not isinstance(mapping_registries, PrivilegedMappingRegistrySet):
            if entries:
                raise TypeError("privileged contracts require versioned mapping registries")
            mapping_registries = PrivilegedMappingRegistrySet(version="empty.v1")
        by_key: dict[tuple[str, ...], PrivilegedRuntimeContract] = {}
        ids: set[tuple[str, str]] = set()
        for contract in entries:
            if not isinstance(contract, PrivilegedRuntimeContract):
                raise TypeError("registry entries must be privileged contracts")
            identity = (contract.contract_id, contract.semantic_version)
            if identity in ids:
                raise ValueError("duplicate privileged runtime contract identity")
            ids.add(identity)
            resolved = self._resolve_contract_mapping_registries(contract, mapping_registries)
            if resolved is None:
                raise ValueError("privileged contract mapping registry is missing or mismatched")
            state_registry, trap_registry, interrupt_registry, mmu_registry = resolved
            if tuple(state_registry.mappings) != tuple((*contract.csr_mappings, *contract.virtualization_mappings, *contract.debug_mappings)):
                raise ValueError("state mapping registry does not match contract snapshot")
            if tuple(trap_registry.mappings) != contract.trap_mappings:
                raise ValueError("trap mapping registry does not match contract snapshot")
            if tuple(interrupt_registry.mappings) != contract.interrupt_mappings:
                raise ValueError("interrupt mapping registry does not match contract snapshot")
            if tuple(mmu_registry.mappings) != contract.address_translation_mappings:
                raise ValueError("MMU mapping registry does not match contract snapshot")
            if len(contract.supported_semantic_classes) != 1:
                raise ValueError("registry-v2 contracts bind exactly one privileged semantic class")
            key = self._contract_key(contract)
            if key in by_key:
                raise ValueError("ambiguous privileged runtime source/target key")
            by_key[key] = contract
        self.version = version.strip()
        self.schema_version = PRIVILEGED_RUNTIME_REGISTRY_SCHEMA
        self.mapping_registries = mapping_registries
        self._contracts: Mapping[tuple[str, ...], PrivilegedRuntimeContract] = (
            MappingProxyType(by_key)
        )

    @staticmethod
    def _resolve_contract_mapping_registries(contract, registries):
        values = (
            registries.resolve(contract.state_mapping_registry_id, PrivilegedMappingRegistryKind.STATE),
            registries.resolve(contract.trap_mapping_registry_id, PrivilegedMappingRegistryKind.TRAP),
            registries.resolve(contract.interrupt_mapping_registry_id, PrivilegedMappingRegistryKind.INTERRUPT),
            registries.resolve(contract.mmu_mapping_registry_id, PrivilegedMappingRegistryKind.MMU),
        )
        return None if any(item is None for item in values) else values

    @staticmethod
    def _contract_key(contract):
        return (
            contract.supported_source_profiles[0], contract.supported_target_modes[0],
            contract.supported_semantic_classes[0], contract.source_semantic_contract_id,
            contract.source_semantic_version, contract.privilege_spec_version,
            contract.isa_extension_profile_id, contract.target_environment_id,
            contract.runtime_identity, contract.runtime_contract_version,
        )

    def resolve(
        self,
        source: SourcePrivilegedSemanticModel,
        target_environment: object,
    ) -> PrivilegedRuntimeContract | None:
        if source.state is None or len(source.semantic_classes) != 1:
            return None
        source_contract_id, source_contract_version = source_semantic_contract_identity(source)
        runtime_identity, runtime_version = target_runtime_identity(source)
        key = (
            source.state.execution_profile.value, source.state.target_execution_mode.value,
            source.semantic_classes[0].value, source_contract_id, source_contract_version,
            source.state.source_privilege_spec_version or "unknown",
            isa_extension_profile_identity(source), target_environment_identity(target_environment),
            runtime_identity, runtime_version,
        )
        contract = self._contracts.get(key)
        return contract if contract is not None and contract.source_privileged_identity == privileged_source_identity(source) else None

    @property
    def semantic_contract_ids(self) -> frozenset[str]:
        return frozenset(
            contract.semantic_contract_id
            for contract in self._contracts.values()
        )

    @property
    def required_target_capabilities(self) -> frozenset[str]:
        return frozenset(item for contract in self._contracts.values()
                         for item in contract.required_capabilities)


EMPTY_PRIVILEGED_RUNTIME_REGISTRY = PrivilegedRuntimeRegistry(
    version="privileged-runtime-registry.empty.v2",
    mapping_registries=PrivilegedMappingRegistrySet(version="empty.v1"),
)


@dataclass(frozen=True)
class TargetPrivilegedRuntimeConstraint:
    runtime_contract: PrivilegedRuntimeContract
    source_privileged_identity: str
    target_environment_id: str
    registry_version: str
    mapping_registry_version: str
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
            "mapping_registry_version",
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
