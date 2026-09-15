"""Requirement-driven L2 validator provider resolution.

Planning is deliberately separate from execution.  A resolver consumes one
validated fragment requirement and an explicit provider catalogue; it never
drops a required dimension merely because a provider is unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from .l2_dimensions import (
    L2Dimension, L2EligibilityStatus,
    parse_l2_dimension, parse_l2_dimensions,
)
from .l2_semantic_profile import L2PatternKind


L2_REQUIREMENT_DRIVEN_REGISTRY_SCHEMA = "riscv2x86.l2-requirement-driven-registry.v2"
L2_RESOLVED_EXECUTION_PLAN_SCHEMA = "riscv2x86.l2-resolved-execution-plan.v2"
L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA = "riscv2x86.explicit-l2-providers.v1"
_BINDING_KINDS = ("explicit", "automatic", "runtime_adapter")
_PRIORITY = {name: index for index, name in enumerate(_BINDING_KINDS)}
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class L2BindingStatus(str, Enum):
    RESOLVED = "resolved"
    NOT_RUN = "not_run"
    INCONCLUSIVE = "inconclusive"


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


@dataclass(frozen=True)
class L2ValidatorProvider:
    provider_id: str
    dimensions: tuple[L2Dimension, ...]
    binding_kind: str
    validator_type: str
    config: Mapping[str, object]
    fragment_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.provider_id or not self.validator_type:
            raise ValueError("L2 validator provider identity/type is missing")
        if not self.dimensions:
            raise ValueError("L2 validator provider dimensions are missing")
        if self.binding_kind not in _PRIORITY:
            raise ValueError("L2 validator provider binding kind is unsupported")
        if tuple(sorted(set(self.fragment_ids))) != self.fragment_ids:
            raise ValueError("L2 validator provider fragment IDs must be unique and sorted")

    def applies_to(self, fragment_id: str) -> bool:
        return not self.fragment_ids or fragment_id in self.fragment_ids


@dataclass(frozen=True)
class L2RuntimeCapabilities:
    providers: tuple[L2ValidatorProvider, ...]

    def __post_init__(self) -> None:
        ids = tuple(provider.provider_id for provider in self.providers)
        if len(ids) != len(set(ids)):
            raise ValueError("L2 validator provider IDs must be unique")


@dataclass(frozen=True)
class ExplicitL2Bindings:
    providers: tuple[L2ValidatorProvider, ...] = ()

    def __post_init__(self) -> None:
        if any(provider.binding_kind != "explicit" for provider in self.providers):
            raise ValueError("explicit L2 bindings may only contain explicit providers")


@dataclass(frozen=True)
class L2FragmentRequirement:
    fragment_id: str
    requirement_identity: str
    required_dimensions: tuple[L2Dimension, ...]
    eligibility_status: L2EligibilityStatus
    semantic_profile_identity: str = ""
    pattern_kind: str = "unknown"
    required_capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.required_capabilities != tuple(sorted(set(self.required_capabilities))):
            raise ValueError("L2 requirement capabilities must be unique and sorted")
        try:
            kind = L2PatternKind(self.pattern_kind)
        except ValueError as exc:
            raise ValueError("L2 requirement pattern kind is unsupported") from exc
        if self.eligibility_status is L2EligibilityStatus.ELIGIBLE and (
                _SHA256.fullmatch(self.semantic_profile_identity) is None
                or kind is L2PatternKind.UNKNOWN or not self.required_capabilities):
            raise ValueError("eligible L2 requirement has no complete semantic profile")


@dataclass(frozen=True)
class L2ResolvedBinding:
    dimension: L2Dimension
    binding_status: L2BindingStatus
    provider_id: str = ""
    binding_kind: str = ""
    validator_type: str = ""
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "validatorType": self.validator_type,
            "providerId": self.provider_id,
            "bindingKind": self.binding_kind,
            "bindingStatus": self.binding_status.value,
            "reasonCodes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class L2ResolvedExecutionPlan:
    fragment_id: str
    requirement_identity: str
    execution_profile: str
    eligibility_status: L2EligibilityStatus
    bindings: tuple[L2ResolvedBinding, ...]
    semantic_profile_identity: str = ""
    pattern_kind: str = "unknown"
    required_capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        L2PatternKind(self.pattern_kind)
        if self.required_capabilities != tuple(sorted(set(self.required_capabilities))):
            raise ValueError("L2 resolved plan capabilities must be unique and sorted")
        if self.eligibility_status is L2EligibilityStatus.ELIGIBLE and (
                _SHA256.fullmatch(self.semantic_profile_identity) is None
                or self.pattern_kind == L2PatternKind.UNKNOWN.value
                or not self.required_capabilities):
            raise ValueError("eligible L2 resolved plan has no complete semantic profile")

    def to_dict(self) -> dict[str, object]:
        payload = {
            "schemaVersion": L2_RESOLVED_EXECUTION_PLAN_SCHEMA,
            "fragmentId": self.fragment_id,
            "requirementIdentity": self.requirement_identity,
            "executionProfile": self.execution_profile,
            "eligibilityStatus": self.eligibility_status.value,
            "semanticProfileIdentity": self.semantic_profile_identity,
            "patternKind": self.pattern_kind,
            "requiredCapabilities": list(self.required_capabilities),
            "bindings": [binding.to_dict() for binding in self.bindings],
        }
        payload["planIdentity"] = _identity(payload)
        return payload

    @property
    def complete(self) -> bool:
        return (self.eligibility_status is L2EligibilityStatus.ELIGIBLE
                and bool(self.bindings) and all(
            binding.binding_status is L2BindingStatus.RESOLVED
            and bool(binding.provider_id) for binding in self.bindings
        ))


class L2ValidatorResolver:
    """Resolve every required dimension without changing the requirement."""

    def resolve(
        self, requirement: L2FragmentRequirement,
        capabilities: L2RuntimeCapabilities,
        explicit_bindings: ExplicitL2Bindings = ExplicitL2Bindings(),
        *, execution_profile: str,
    ) -> L2ResolvedExecutionPlan:
        providers = explicit_bindings.providers + capabilities.providers
        bindings: list[L2ResolvedBinding] = []
        for dimension in requirement.required_dimensions:
            candidates = [
                provider for provider in providers
                if dimension in provider.dimensions
                and provider.applies_to(requirement.fragment_id)
            ]
            if not candidates:
                bindings.append(L2ResolvedBinding(
                    dimension, L2BindingStatus.NOT_RUN,
                    reason_codes=("l2.binding.provider-missing",),
                ))
                continue
            best_priority = min(_PRIORITY[item.binding_kind] for item in candidates)
            best = sorted(
                (item for item in candidates
                 if _PRIORITY[item.binding_kind] == best_priority),
                key=lambda item: item.provider_id,
            )
            if len(best) != 1:
                bindings.append(L2ResolvedBinding(
                    dimension, L2BindingStatus.INCONCLUSIVE,
                    reason_codes=("l2.binding.provider-ambiguous",),
                ))
                continue
            provider = best[0]
            bindings.append(L2ResolvedBinding(
                dimension, L2BindingStatus.RESOLVED,
                provider.provider_id, provider.binding_kind,
                provider.validator_type,
            ))
        return L2ResolvedExecutionPlan(
            requirement.fragment_id, requirement.requirement_identity,
            execution_profile, requirement.eligibility_status, tuple(bindings),
            requirement.semantic_profile_identity, requirement.pattern_kind,
            requirement.required_capabilities,
        )


def fragment_requirement_from_dict(value: Mapping[str, object]) -> L2FragmentRequirement:
    dimensions = value.get("requiredDimensions")
    if not isinstance(dimensions, list):
        raise ValueError("L2 fragment requirement dimensions are missing")
    fragment_id = value.get("fragmentId")
    requirement_identity = value.get("requirementIdentity")
    if (not isinstance(fragment_id, str) or not fragment_id
            or not isinstance(requirement_identity, str)
            or _SHA256.fullmatch(requirement_identity) is None):
        raise ValueError("L2 fragment requirement identities are invalid")
    parsed_dimensions = parse_l2_dimensions(dimensions)
    eligibility = L2EligibilityStatus(str(value.get("eligibilityStatus")))
    if eligibility is L2EligibilityStatus.ELIGIBLE and not parsed_dimensions:
        raise ValueError("eligible L2 fragment requirement has no dimensions")
    profile_identity = value.get("semanticProfileIdentity")
    pattern_kind = value.get("patternKind")
    capabilities = value.get("requiredCapabilities")
    if (not isinstance(profile_identity, str)
            or (profile_identity and _SHA256.fullmatch(profile_identity) is None)
            or not isinstance(pattern_kind, str) or not pattern_kind
            or not isinstance(capabilities, list)
            or capabilities != sorted(set(capabilities))
            or not all(isinstance(item, str) and item for item in capabilities)):
        raise ValueError("L2 fragment requirement semantic profile binding is invalid")
    try:
        L2PatternKind(pattern_kind)
    except ValueError as exc:
        raise ValueError("L2 fragment requirement pattern kind is unsupported") from exc
    return L2FragmentRequirement(
        fragment_id, requirement_identity, parsed_dimensions, eligibility,
        profile_identity, pattern_kind, tuple(capabilities),
    )


def provider_from_dict(value: Mapping[str, object]) -> L2ValidatorProvider:
    expected = {"providerId", "dimensions", "bindingKind", "validatorType", "config", "fragmentIds"}
    if set(value) != expected:
        raise ValueError("L2 validator provider fields are incomplete or unknown")
    dimensions, fragment_ids, config = value.get("dimensions"), value.get("fragmentIds"), value.get("config")
    if not isinstance(dimensions, list) or not isinstance(fragment_ids, list) or not isinstance(config, Mapping):
        raise ValueError("L2 validator provider dimensions/fragments/config are invalid")
    if not all(isinstance(item, str) and item for item in fragment_ids):
        raise ValueError("L2 validator provider fragment IDs are invalid")
    return L2ValidatorProvider(
        str(value.get("providerId") or ""), parse_l2_dimensions(dimensions),
        str(value.get("bindingKind") or ""), str(value.get("validatorType") or ""),
        config, tuple(fragment_ids),
    )


def resolve_fragment_execution_plan(
    manifest: Mapping[str, object], providers: Sequence[L2ValidatorProvider],
    fragment_id: str, *, execution_profile: str,
) -> L2ResolvedExecutionPlan | None:
    """Resolve one strict manifest member; return ``None`` when it is absent."""
    raw_requirements = manifest.get("requirements")
    if not isinstance(raw_requirements, list):
        raise ValueError("L2 requirement manifest requirements must be an array")
    matches = [fragment_requirement_from_dict(item) for item in raw_requirements
               if isinstance(item, Mapping) and item.get("fragmentId") == fragment_id]
    if len(matches) > 1:
        raise ValueError("L2 requirement manifest contains duplicate fragment IDs")
    if not matches:
        return None
    explicit = ExplicitL2Bindings(tuple(item for item in providers
                                        if item.binding_kind == "explicit"))
    capabilities = L2RuntimeCapabilities(tuple(item for item in providers
                                               if item.binding_kind != "explicit"))
    return L2ValidatorResolver().resolve(
        matches[0], capabilities, explicit, execution_profile=execution_profile,
    )


def validate_resolved_execution_plan(value: Mapping[str, object]) -> None:
    expected = {"schemaVersion", "fragmentId", "requirementIdentity", "executionProfile",
                "eligibilityStatus", "semanticProfileIdentity", "patternKind",
                "requiredCapabilities", "bindings", "planIdentity"}
    if set(value) != expected or value.get("schemaVersion") != L2_RESOLVED_EXECUTION_PLAN_SCHEMA:
        raise ValueError("L2 resolved execution plan schema or fields are invalid")
    payload = dict(value); identity = payload.pop("planIdentity")
    if not isinstance(identity, str) or identity != _identity(payload):
        raise ValueError("L2 resolved execution plan identity does not match content")
    if (not isinstance(value.get("fragmentId"), str) or not value.get("fragmentId")
            or not isinstance(value.get("requirementIdentity"), str)
            or _SHA256.fullmatch(str(value.get("requirementIdentity"))) is None
            or not isinstance(value.get("executionProfile"), str)
            or not value.get("executionProfile")):
        raise ValueError("L2 resolved execution plan identities/profile are invalid")
    L2EligibilityStatus(str(value.get("eligibilityStatus")))
    profile_identity = value.get("semanticProfileIdentity")
    capabilities = value.get("requiredCapabilities")
    if (not isinstance(profile_identity, str)
            or (profile_identity and _SHA256.fullmatch(profile_identity) is None)
            or not isinstance(value.get("patternKind"), str)
            or not value.get("patternKind")
            or not isinstance(capabilities, list)
            or capabilities != sorted(set(capabilities))
            or not all(isinstance(item, str) and item for item in capabilities)):
        raise ValueError("L2 resolved execution plan semantic profile is invalid")
    try:
        L2PatternKind(str(value.get("patternKind")))
    except ValueError as exc:
        raise ValueError("L2 resolved execution plan pattern kind is unsupported") from exc
    raw = value.get("bindings")
    if not isinstance(raw, list):
        raise ValueError("L2 resolved execution plan bindings must be an array")
    dimensions = []
    for binding in raw:
        fields = {"dimension", "validatorType", "providerId", "bindingKind", "bindingStatus", "reasonCodes"}
        if not isinstance(binding, Mapping) or set(binding) != fields:
            raise ValueError("L2 resolved execution binding is malformed")
        dimensions.append(parse_l2_dimension(binding.get("dimension")))
        status = L2BindingStatus(str(binding.get("bindingStatus")))
        provider_id, validator_type = binding.get("providerId"), binding.get("validatorType")
        binding_kind, reasons = binding.get("bindingKind"), binding.get("reasonCodes")
        if (not isinstance(provider_id, str) or not isinstance(validator_type, str)
                or not isinstance(binding_kind, str) or not isinstance(reasons, list)
                or not all(isinstance(item, str) and item for item in reasons)):
            raise ValueError("L2 resolved execution binding fields are invalid")
        if status is L2BindingStatus.RESOLVED:
            if not provider_id or not validator_type or binding_kind not in _PRIORITY or reasons:
                raise ValueError("resolved L2 binding is incomplete")
        elif provider_id or validator_type or binding_kind or not reasons:
            raise ValueError("unresolved L2 binding carries invalid provider data")
    parse_l2_dimensions([item.value for item in dimensions])


def write_resolved_execution_plan(path: str | Path, plan: L2ResolvedExecutionPlan) -> None:
    value = plan.to_dict()
    validate_resolved_execution_plan(value)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
