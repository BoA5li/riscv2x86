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
from .l2_semantic_profile import L2FragmentSemanticProfile, L2PatternKind


L2_REQUIREMENT_DRIVEN_REGISTRY_SCHEMA = "riscv2x86.l2-requirement-driven-registry.v3"
L2_RESOLVED_EXECUTION_PLAN_SCHEMA = "riscv2x86.l2-resolved-execution-plan.v3"
L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA = "riscv2x86.explicit-l2-providers.v2"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class L2BindingStatus(str, Enum):
    RESOLVED = "resolved"
    NOT_RUN = "not_run"
    INCONCLUSIVE = "inconclusive"


class L2BindingKind(str, Enum):
    EXPLICIT = "explicit"
    AUTOMATIC = "automatic"
    RUNTIME_ADAPTER = "runtime_adapter"


_PRIORITY = {kind: index for index, kind in enumerate(L2BindingKind)}


class L2ProviderMatchStatus(str, Enum):
    MATCHED = "matched"
    NOT_MATCHED = "not_matched"


_DIMENSION_CAPABILITY = {
    L2Dimension.LOGICAL_OPERANDS: "logical_operand_observation",
    L2Dimension.MEMORY_EFFECTS: "object_relative_memory_observation",
    L2Dimension.CONTROL_FLOW: "control_flow_observation",
    L2Dimension.SHELL_SEMANTICS: "shell_observation",
    L2Dimension.PRIVILEGED_STATE: "privileged_state_observation",
    L2Dimension.TRAP_SEMANTICS: "privileged_state_observation",
    L2Dimension.ATOMIC_MEMORY_ORDER: "atomic_outcome_observation",
}


def _dimension_capability(dimension: L2Dimension, pattern: L2PatternKind) -> str:
    if dimension is L2Dimension.MEMORY_EFFECTS:
        if pattern is L2PatternKind.FENCE:
            return "ordering_observation"
        if pattern is L2PatternKind.INSTRUCTION_VISIBILITY_FENCE:
            return "instruction_visibility"
    return _DIMENSION_CAPABILITY[dimension]


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


@dataclass(frozen=True)
class L2ProviderMatch:
    match_status: L2ProviderMatchStatus
    matched_capabilities: tuple[str, ...] = ()
    missing_capabilities: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for values in (self.matched_capabilities, self.missing_capabilities,
                       self.reason_codes):
            if values != tuple(sorted(set(values))):
                raise ValueError("L2 provider match values must be unique and sorted")
        if self.match_status is L2ProviderMatchStatus.MATCHED and (
                self.missing_capabilities or self.reason_codes):
            raise ValueError("matched L2 provider carries mismatch diagnostics")

    def to_dict(self) -> dict[str, object]:
        return {"matchStatus": self.match_status.value,
                "matchedCapabilities": list(self.matched_capabilities),
                "missingCapabilities": list(self.missing_capabilities),
                "reasonCodes": list(self.reason_codes)}


@dataclass(frozen=True)
class L2ValidatorProvider:
    provider_id: str
    supported_dimensions: tuple[L2Dimension, ...]
    supported_patterns: tuple[L2PatternKind, ...]
    required_capabilities: tuple[str, ...]
    execution_profiles: tuple[str, ...]
    binding_kind: L2BindingKind
    validator_type: str
    config_schema_version: str
    config: Mapping[str, object]
    fragment_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.provider_id or not self.validator_type:
            raise ValueError("L2 validator provider identity/type is missing")
        if not isinstance(self.binding_kind, L2BindingKind):
            raise ValueError("L2 validator provider binding kind is unsupported")
        if not self.supported_dimensions or not self.supported_patterns:
            raise ValueError("L2 validator provider dimensions are missing")
        if (self.supported_dimensions != tuple(sorted(set(self.supported_dimensions),
                                                      key=lambda item: item.value))
                or self.supported_patterns != tuple(sorted(set(self.supported_patterns),
                                                           key=lambda item: item.value))):
            raise ValueError("L2 provider dimensions/patterns must be unique and sorted")
        for values, label in ((self.required_capabilities, "capabilities"),
                              (self.execution_profiles, "execution profiles"),
                              (self.fragment_ids, "fragment IDs")):
            if values != tuple(sorted(set(values))) or any(not item for item in values):
                raise ValueError(f"L2 validator provider {label} must be unique and sorted")
        if not self.required_capabilities or not self.execution_profiles:
            raise ValueError("L2 validator provider applicability contract is incomplete")
        if (not self.config_schema_version
                or self.config.get("schemaVersion") != self.config_schema_version):
            raise ValueError("L2 validator provider config schema binding is invalid")

    def applies_to(self, fragment_id: str) -> bool:
        return not self.fragment_ids or fragment_id in self.fragment_ids

    @property
    def dimensions(self) -> tuple[L2Dimension, ...]:
        """Compatibility read-only name for existing reporting callers."""
        return self.supported_dimensions

    def supports(
        self, requirement: "L2FragmentRequirement",
        profile: L2FragmentSemanticProfile,
        environment: "L2RuntimeCapabilities", *, dimension: L2Dimension,
    ) -> L2ProviderMatch:
        reasons: set[str] = set()
        if dimension not in self.supported_dimensions:
            reasons.add("l2.provider.dimension-unsupported")
        if profile.pattern_kind not in self.supported_patterns:
            reasons.add("l2.provider.pattern-unsupported")
        if not self.applies_to(requirement.fragment_id):
            reasons.add("l2.provider.fragment-not-bound")
        if profile.execution_profile not in self.execution_profiles:
            reasons.add("l2.provider.execution-profile-unsupported")
        if profile.execution_profile not in environment.execution_profiles:
            reasons.add("l2.environment.execution-profile-unavailable")
        capability = _dimension_capability(dimension, profile.pattern_kind)
        declared = set(self.required_capabilities)
        if capability not in declared:
            reasons.add("l2.provider.dimension-capability-undeclared")
        available = set(environment.available_capabilities)
        missing = declared - available
        if missing:
            reasons.add("l2.environment.capability-missing")
        if (profile.profile_identity != requirement.semantic_profile_identity
                or profile.pattern_kind.value != requirement.pattern_kind
                or profile.required_capabilities != requirement.required_capabilities):
            reasons.add("l2.provider.semantic-profile-binding-mismatch")
        return L2ProviderMatch(
            L2ProviderMatchStatus.MATCHED if not reasons else L2ProviderMatchStatus.NOT_MATCHED,
            tuple(sorted(declared & available)), tuple(sorted(missing)), tuple(sorted(reasons)),
        )


@dataclass(frozen=True)
class L2RuntimeCapabilities:
    providers: tuple[L2ValidatorProvider, ...]
    available_capabilities: tuple[str, ...]
    execution_profiles: tuple[str, ...]

    def __post_init__(self) -> None:
        ids = tuple(provider.provider_id for provider in self.providers)
        if len(ids) != len(set(ids)):
            raise ValueError("L2 validator provider IDs must be unique")
        if (self.available_capabilities != tuple(sorted(set(self.available_capabilities)))
                or self.execution_profiles != tuple(sorted(set(self.execution_profiles)))
                or any(not item for item in self.available_capabilities)
                or any(not item for item in self.execution_profiles)
                or not self.execution_profiles):
            raise ValueError("L2 runtime capabilities/profiles are non-canonical")


@dataclass(frozen=True)
class ExplicitL2Bindings:
    providers: tuple[L2ValidatorProvider, ...] = ()

    def __post_init__(self) -> None:
        if any(provider.binding_kind is not L2BindingKind.EXPLICIT for provider in self.providers):
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
    matched_capabilities: tuple[str, ...] = ()
    missing_capabilities: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "validatorType": self.validator_type,
            "providerId": self.provider_id,
            "bindingKind": self.binding_kind,
            "bindingStatus": self.binding_status.value,
            "matchedCapabilities": list(self.matched_capabilities),
            "missingCapabilities": list(self.missing_capabilities),
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
        *, execution_profile: str, profile: L2FragmentSemanticProfile,
    ) -> L2ResolvedExecutionPlan:
        if execution_profile != profile.execution_profile:
            raise ValueError("L2 resolver execution/profile identity mismatch")
        providers = explicit_bindings.providers + capabilities.providers
        provider_ids = tuple(item.provider_id for item in providers)
        if len(provider_ids) != len(set(provider_ids)):
            raise ValueError("L2 provider catalogue contains duplicate provider IDs")
        bindings: list[L2ResolvedBinding] = []
        for dimension in requirement.required_dimensions:
            matches = [(provider, provider.supports(
                requirement, profile, capabilities, dimension=dimension,
            )) for provider in providers]
            candidates = [(provider, match) for provider, match in matches
                          if match.match_status is L2ProviderMatchStatus.MATCHED]
            if not candidates:
                relevant = [match for provider, match in matches
                            if dimension in provider.supported_dimensions]
                missing = tuple(sorted({item for match in relevant
                                        for item in match.missing_capabilities}))
                reasons = tuple(sorted({item for match in relevant
                                        for item in match.reason_codes}))
                bindings.append(L2ResolvedBinding(
                    dimension, L2BindingStatus.NOT_RUN,
                    missing_capabilities=missing,
                    reason_codes=reasons or ("l2.binding.provider-missing",),
                ))
                continue
            best_priority = min(_PRIORITY[item.binding_kind] for item, _match in candidates)
            best = sorted(
                ((item, match) for item, match in candidates
                 if _PRIORITY[item.binding_kind] == best_priority),
                key=lambda pair: pair[0].provider_id,
            )
            if len(best) != 1:
                bindings.append(L2ResolvedBinding(
                    dimension, L2BindingStatus.INCONCLUSIVE,
                    reason_codes=("l2.binding.provider-ambiguous",),
                ))
                continue
            provider, match = best[0]
            bindings.append(L2ResolvedBinding(
                dimension, L2BindingStatus.RESOLVED,
                provider.provider_id, provider.binding_kind.value,
                provider.validator_type, match.matched_capabilities,
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
    expected = {"providerId", "supportedDimensions", "supportedPatterns",
                "requiredCapabilities", "executionProfiles", "bindingKind",
                "validatorType", "configSchemaVersion", "config", "fragmentIds"}
    if set(value) != expected:
        raise ValueError("L2 validator provider fields are incomplete or unknown")
    dimensions = value.get("supportedDimensions")
    patterns = value.get("supportedPatterns")
    required = value.get("requiredCapabilities")
    profiles = value.get("executionProfiles")
    fragment_ids, config = value.get("fragmentIds"), value.get("config")
    if (not isinstance(dimensions, list) or not isinstance(patterns, list)
            or not isinstance(required, list) or not isinstance(profiles, list)
            or not isinstance(fragment_ids, list) or not isinstance(config, Mapping)):
        raise ValueError("L2 validator provider dimensions/fragments/config are invalid")
    if not all(isinstance(item, str) and item for values in
               (patterns, required, profiles, fragment_ids) for item in values):
        raise ValueError("L2 validator provider applicability values are invalid")
    if patterns != sorted(set(patterns)):
        raise ValueError("L2 validator provider patterns are non-canonical")
    try:
        parsed_patterns = tuple(sorted((L2PatternKind(item) for item in patterns),
                                       key=lambda item: item.value))
        binding_kind = L2BindingKind(str(value.get("bindingKind")))
    except ValueError as exc:
        raise ValueError("L2 validator provider pattern/binding kind is invalid") from exc
    return L2ValidatorProvider(
        str(value.get("providerId") or ""), parse_l2_dimensions(dimensions),
        parsed_patterns, tuple(required), tuple(profiles), binding_kind,
        str(value.get("validatorType") or ""),
        str(value.get("configSchemaVersion") or ""), config, tuple(fragment_ids),
    )


def resolve_fragment_execution_plan(
    manifest: Mapping[str, object], providers: Sequence[L2ValidatorProvider],
    fragment_id: str, *, execution_profile: str,
    profile: L2FragmentSemanticProfile,
    available_capabilities: Sequence[str],
    environment_execution_profiles: Sequence[str],
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
                                        if item.binding_kind is L2BindingKind.EXPLICIT))
    capabilities = L2RuntimeCapabilities(tuple(item for item in providers
                                               if item.binding_kind is not L2BindingKind.EXPLICIT),
                                         tuple(available_capabilities),
                                         tuple(environment_execution_profiles))
    return L2ValidatorResolver().resolve(
        matches[0], capabilities, explicit, execution_profile=execution_profile,
        profile=profile,
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
        fields = {"dimension", "validatorType", "providerId", "bindingKind", "bindingStatus",
                  "matchedCapabilities", "missingCapabilities", "reasonCodes"}
        if not isinstance(binding, Mapping) or set(binding) != fields:
            raise ValueError("L2 resolved execution binding is malformed")
        dimensions.append(parse_l2_dimension(binding.get("dimension")))
        status = L2BindingStatus(str(binding.get("bindingStatus")))
        provider_id, validator_type = binding.get("providerId"), binding.get("validatorType")
        binding_kind, reasons = binding.get("bindingKind"), binding.get("reasonCodes")
        matched, missing = binding.get("matchedCapabilities"), binding.get("missingCapabilities")
        if (not isinstance(provider_id, str) or not isinstance(validator_type, str)
                or not isinstance(binding_kind, str) or not isinstance(reasons, list)
                or not isinstance(matched, list) or not isinstance(missing, list)
                or matched != sorted(set(matched)) or missing != sorted(set(missing))
                or reasons != sorted(set(reasons))
                or not all(isinstance(item, str) and item for item in matched + missing)
                or not all(isinstance(item, str) and item for item in reasons)):
            raise ValueError("L2 resolved execution binding fields are invalid")
        if status is L2BindingStatus.RESOLVED:
            if (not provider_id or not validator_type
                    or binding_kind not in {item.value for item in L2BindingKind}
                    or reasons or missing or not matched):
                raise ValueError("resolved L2 binding is incomplete")
        elif provider_id or validator_type or binding_kind or matched or not reasons:
            raise ValueError("unresolved L2 binding carries invalid provider data")
    parse_l2_dimensions([item.value for item in dimensions])


def write_resolved_execution_plan(path: str | Path, plan: L2ResolvedExecutionPlan) -> None:
    value = plan.to_dict()
    validate_resolved_execution_plan(value)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
