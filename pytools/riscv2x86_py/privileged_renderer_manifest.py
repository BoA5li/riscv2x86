"""Registered Phase-6F recipes for proved privileged lowering plans.

The manifest is deployment authority.  It binds an already registered
privileged semantic contract to one C runtime call or compiler builtin; it
never contains inline assembly and is never populated from source mnemonics.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from types import MappingProxyType
from typing import Iterable, Mapping

from .plan_types import TargetLoweringKind


PRIVILEGED_RENDERER_MANIFEST_SCHEMA = (
    "riscv2x86.privileged-renderer-manifest.v1"
)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PRIVILEGED_KINDS = frozenset({
    TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER,
    TargetLoweringKind.SYSCALL_OR_SERVICE_ABI_ADAPTER,
    TargetLoweringKind.PRIVILEGED_EVENT_ADAPTER,
    TargetLoweringKind.MMU_RUNTIME_ADAPTER,
    TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER,
    TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK,
})


class PrivilegedRecipeKind(str, Enum):
    RUNTIME_CALL = "runtime_call"
    COMPILER_BUILTIN = "compiler_builtin"


@dataclass(frozen=True)
class PrivilegedRendererManifestEntry:
    semantic_contract_id: str
    plan_kind: TargetLoweringKind
    renderer_contract_id: str
    recipe_kind: PrivilegedRecipeKind
    callable_identifier: str
    argument_operand_indexes: tuple[int, ...]
    result_operand_indexes: tuple[int, ...]
    required_headers: tuple[str, ...]
    required_libraries: tuple[str, ...]
    required_target_capability: str
    target_environment_id: str
    source_registry_version: str
    complete: bool = True

    def __post_init__(self) -> None:
        for name in (
            "semantic_contract_id", "renderer_contract_id",
            "callable_identifier", "required_target_capability",
            "target_environment_id", "source_registry_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise TypeError(f"{name} must be a non-empty stripped string")
        if self.plan_kind not in _PRIVILEGED_KINDS:
            raise ValueError("privileged renderer entry has an invalid plan kind")
        if not isinstance(self.recipe_kind, PrivilegedRecipeKind):
            raise TypeError("recipe_kind must be PrivilegedRecipeKind")
        if _IDENTIFIER.fullmatch(self.callable_identifier) is None:
            raise ValueError("callable_identifier must be one C identifier")
        for name in ("argument_operand_indexes", "result_operand_indexes"):
            values = getattr(self, name)
            if any(isinstance(item, bool) or not isinstance(item, int) or item < 0
                   for item in values):
                raise TypeError(f"{name} must contain non-negative integers")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicates")
        if len(self.result_operand_indexes) > 1:
            raise ValueError("v1 privileged renderer supports at most one result")
        for name in ("required_headers", "required_libraries"):
            values = getattr(self, name)
            if tuple(sorted(set(values))) != values or any(
                not isinstance(item, str) or not item.strip() for item in values
            ):
                raise ValueError(f"{name} must contain sorted unique names")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be bool")


class PrivilegedRendererManifest:
    def __init__(
        self,
        *,
        manifest_id: str,
        version: str,
        entries: Iterable[PrivilegedRendererManifestEntry] = (),
    ) -> None:
        for name, value in (("manifest_id", manifest_id), ("version", version)):
            if not isinstance(value, str) or not value.strip():
                raise TypeError(f"{name} must be non-empty")
        by_id: dict[str, PrivilegedRendererManifestEntry] = {}
        for entry in tuple(entries):
            if not isinstance(entry, PrivilegedRendererManifestEntry):
                raise TypeError("manifest entries must be typed")
            if entry.semantic_contract_id in by_id:
                raise ValueError("duplicate privileged renderer semantic contract")
            by_id[entry.semantic_contract_id] = entry
        self.manifest_id = manifest_id.strip()
        self.version = version.strip()
        self.schema_version = PRIVILEGED_RENDERER_MANIFEST_SCHEMA
        self._entries: Mapping[str, PrivilegedRendererManifestEntry] = (
            MappingProxyType(by_id)
        )

    @property
    def entries(self) -> tuple[PrivilegedRendererManifestEntry, ...]:
        return tuple(self._entries[key] for key in sorted(self._entries))


EMPTY_PRIVILEGED_RENDERER_MANIFEST = PrivilegedRendererManifest(
    manifest_id="riscv2x86.privileged-renderers.empty",
    version="1",
)
