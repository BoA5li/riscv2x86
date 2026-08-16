"""Versioned contracts for explicitly permitted privileged functional fallbacks.

These contracts deliberately claim functional equivalence only.  They are
separate from :mod:`privileged_runtime_contracts`, whose contracts preserve
the complete architectural privileged state.  Neither a command-line flag nor
a CSR name is sufficient to resolve a fallback: the registry key binds the
complete Phase-6A privileged and observability identities to one target
environment.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Iterable, Mapping

from .functional_observability import FunctionalObservabilityContract
from .privileged_runtime_contracts import (
    privileged_source_identity,
    target_environment_identity,
)
from .privileged_state_adapter import SourcePrivilegedSemanticModel


PRIVILEGED_FUNCTIONAL_REGISTRY_SCHEMA = (
    "riscv2x86.privileged-functional-fallback-registry.v1"
)
PRIVILEGED_FUNCTIONAL_POLICY_SCHEMA = (
    "riscv2x86.privileged-functional-fallback-policy.v1"
)


def functional_observability_identity(
    contract: FunctionalObservabilityContract,
) -> str:
    if not isinstance(contract, FunctionalObservabilityContract):
        raise TypeError("functional observability identity requires a typed contract")
    return "sha256:" + sha256(repr(contract).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PrivilegedFunctionalFallbackPolicy:
    enabled: bool = False
    policy_id: str = "privileged-functional-fallback"
    policy_version: str = "1"
    schema_version: str = PRIVILEGED_FUNCTIONAL_POLICY_SCHEMA

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("functional fallback policy enabled must be bool")
        for name in ("policy_id", "policy_version", "schema_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise TypeError(f"{name} must be a non-empty stripped string")

    @property
    def identity(self) -> str:
        return f"{self.schema_version}:{self.policy_id}@{self.policy_version}:enabled={self.enabled}"


@dataclass(frozen=True)
class PrivilegedFunctionalFallbackContract:
    contract_id: str
    semantic_version: str
    source_privileged_identity: str
    source_observability_identity: str
    target_environment_id: str
    implementation_id: str
    required_target_capability: str
    required_headers: tuple[str, ...] = ()
    required_library: str | None = None
    preserves_outputs: bool = True
    preserves_memory: bool = True
    preserves_errors: bool = True
    preserves_termination: bool = True
    preserves_traps: bool = True
    preserves_shell: bool = True
    preserves_volatile_execution: bool = True
    preserves_compiler_memory_ordering: bool = True
    preserves_cc_clobber: bool = True
    ignored_state_ids: tuple[str, ...] = ()
    required_value_source_ids: tuple[str, ...] = ()
    functional_equivalence_only: bool = True
    may_return: bool = True
    may_unwind: bool = False
    complete: bool = True

    def __post_init__(self) -> None:
        for name in (
            "contract_id", "semantic_version", "source_privileged_identity",
            "source_observability_identity", "target_environment_id",
            "implementation_id", "required_target_capability",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise TypeError(f"{name} must be a non-empty stripped string")
        for name in ("required_headers", "ignored_state_ids", "required_value_source_ids"):
            value = getattr(self, name)
            if tuple(sorted(set(value))) != value:
                raise ValueError(f"{name} must be unique and sorted")
        for name in (
            "preserves_outputs", "preserves_memory", "preserves_errors",
            "preserves_termination", "preserves_traps", "preserves_shell",
            "preserves_volatile_execution", "preserves_compiler_memory_ordering",
            "preserves_cc_clobber", "functional_equivalence_only", "may_return",
            "may_unwind", "complete",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")
        if self.functional_equivalence_only is not True:
            raise ValueError("functional fallback contract must not claim architecture equivalence")

    @property
    def semantic_contract_id(self) -> str:
        return f"privileged-functional.{self.contract_id}@{self.semantic_version}"


class PrivilegedFunctionalFallbackRegistry:
    def __init__(
        self,
        *,
        version: str,
        contracts: Iterable[PrivilegedFunctionalFallbackContract] = (),
    ) -> None:
        if not isinstance(version, str) or not version.strip():
            raise TypeError("privileged functional registry requires a version")
        by_key: dict[tuple[str, str, str], PrivilegedFunctionalFallbackContract] = {}
        identities: set[tuple[str, str]] = set()
        for contract in tuple(contracts):
            if not isinstance(contract, PrivilegedFunctionalFallbackContract):
                raise TypeError("registry entries must be typed functional contracts")
            identity = (contract.contract_id, contract.semantic_version)
            if identity in identities:
                raise ValueError("duplicate privileged functional contract identity")
            identities.add(identity)
            key = (
                contract.source_privileged_identity,
                contract.source_observability_identity,
                contract.target_environment_id,
            )
            if key in by_key:
                raise ValueError("ambiguous privileged functional source/target key")
            by_key[key] = contract
        self.version = version.strip()
        self.schema_version = PRIVILEGED_FUNCTIONAL_REGISTRY_SCHEMA
        self._contracts: Mapping[
            tuple[str, str, str], PrivilegedFunctionalFallbackContract
        ] = MappingProxyType(by_key)

    def resolve(
        self,
        source: SourcePrivilegedSemanticModel,
        target_environment: object,
    ) -> PrivilegedFunctionalFallbackContract | None:
        if source.observability is None:
            return None
        return self._contracts.get((
            privileged_source_identity(source),
            functional_observability_identity(source.observability),
            target_environment_identity(target_environment),
        ))

    @property
    def semantic_contract_ids(self) -> frozenset[str]:
        return frozenset(item.semantic_contract_id for item in self._contracts.values())


EMPTY_PRIVILEGED_FUNCTIONAL_FALLBACK_REGISTRY = (
    PrivilegedFunctionalFallbackRegistry(
        version="privileged-functional-registry.empty.v1"
    )
)


@dataclass(frozen=True)
class TargetPrivilegedFunctionalFallbackConstraint:
    fallback_contract: PrivilegedFunctionalFallbackContract
    source_privileged_identity: str
    source_observability_identity: str
    target_environment_id: str
    registry_version: str
    policy_identity: str
    forbids_generic_helper_fallback: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.fallback_contract, PrivilegedFunctionalFallbackContract):
            raise TypeError("fallback contract must be typed")
        for name in (
            "source_privileged_identity", "source_observability_identity",
            "target_environment_id", "registry_version", "policy_identity",
        ):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise TypeError(f"{name} must be non-empty")
        if self.forbids_generic_helper_fallback is not True:
            raise ValueError("privileged functional route must forbid generic helper fallback")
