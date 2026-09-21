"""Capability-driven L3 provider selection; planning is not verification."""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
from typing import Callable, Mapping

from .l3_intent_requirements import (
    L3IntentKind, parse_l3_intent_profile, parse_l3_requirement_manifest, _hash,
)
from .l3_experiment_runner import (
    EXPERIMENT_CONTRACT_BOUND_SCHEMA, EXPERIMENT_CONTRACT_TRACE_SCHEMA,
    EXPERIMENT_CONTRACT_CAMPAIGN_SCHEMA, load_experiment_contract,
    EXPERIMENT_CONTRACT_STATISTICAL_SCHEMA,
    EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA,
)
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus

PROVIDER_SCHEMA = "riscv2x86.l3-validator-provider.v1"
REGISTRY_SCHEMA = "riscv2x86.l3-capability-provider-registry.v1"
PLAN_SCHEMA = "riscv2x86.l3-resolved-execution-plan.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_BINDINGS = {"explicit", "automatic"}


def _sha(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(name + " is not a sha256 identity")
    return value


def _canonical(value: object, name: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if (not isinstance(value, list) or (nonempty and not value)
            or any(not isinstance(x, str) or not x for x in value)
            or value != sorted(set(value))):
        raise ValueError(name + " must be sorted and unique strings")
    return tuple(value)


@dataclass(frozen=True)
class L3ValidatorProvider:
    provider_id: str
    binding_kind: str
    validator_type: str
    config: Mapping[str, object]
    experiment_classes: tuple[str, ...]
    property_dimensions: tuple[str, ...]
    source_capabilities: tuple[str, ...]
    target_capabilities: tuple[str, ...]
    execution_profiles: tuple[str, ...]
    contract_schemas: tuple[str, ...]
    fragment_ids: tuple[str, ...]
    profile_ids: tuple[str, ...]

    @property
    def identity(self) -> str:
        return _hash(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion": PROVIDER_SCHEMA, "providerId": self.provider_id,
                "bindingKind": self.binding_kind, "validatorType": self.validator_type,
                "config": dict(self.config), "experimentClasses": list(self.experiment_classes),
                "propertyDimensions": list(self.property_dimensions),
                "sourceCapabilities": list(self.source_capabilities),
                "targetCapabilities": list(self.target_capabilities),
                "executionProfiles": list(self.execution_profiles),
                "contractSchemas": list(self.contract_schemas),
                "fragmentIds": list(self.fragment_ids), "profileIdentities": list(self.profile_ids)}


def provider_from_dict(value: Mapping[str, object]) -> L3ValidatorProvider:
    fields = {"schemaVersion", "providerId", "bindingKind", "validatorType", "config",
              "experimentClasses", "propertyDimensions", "sourceCapabilities",
              "targetCapabilities", "executionProfiles", "contractSchemas",
              "fragmentIds", "profileIdentities"}
    if not isinstance(value, Mapping) or set(value) != fields or value["schemaVersion"] != PROVIDER_SCHEMA:
        raise ValueError("L3 provider schema/fields invalid")
    provider_id, kind, validator_type = (value[name] for name in ("providerId", "bindingKind", "validatorType"))
    if (not isinstance(provider_id, str) or not provider_id or kind not in _BINDINGS
            or not isinstance(validator_type, str) or not validator_type
            or not isinstance(value["config"], Mapping)):
        raise ValueError("L3 provider binding/config invalid")
    classes = _canonical(value["experimentClasses"], "experimentClasses", nonempty=True)
    dimensions = _canonical(value["propertyDimensions"], "propertyDimensions", nonempty=True)
    source = _canonical(value["sourceCapabilities"], "sourceCapabilities")
    target = _canonical(value["targetCapabilities"], "targetCapabilities")
    profiles = _canonical(value["executionProfiles"], "executionProfiles", nonempty=True)
    schemas = _canonical(value["contractSchemas"], "contractSchemas", nonempty=True)
    fragments = _canonical(value["fragmentIds"], "fragmentIds")
    profile_ids = _canonical(value["profileIdentities"], "profileIdentities")
    for item in profile_ids:
        _sha(item, "profile identity")
    if kind == "explicit" and not (fragments or profile_ids):
        raise ValueError("explicit L3 provider needs fragment/profile identity")
    if kind == "automatic" and (fragments or profile_ids):
        raise ValueError("automatic L3 provider cannot silently use exact bindings")
    if "side_channel_speculation" in dimensions and kind != "explicit":
        raise ValueError("specialized L3 properties require exact explicit provider binding")
    return L3ValidatorProvider(provider_id, kind, validator_type, dict(value["config"]),
                               classes, dimensions, source, target, profiles, schemas,
                               fragments, profile_ids)


def _binary_fingerprints(command: tuple[str, ...]) -> tuple[Mapping[str, str], ...]:
    paths = []
    executable = shutil.which(command[0]) or command[0]
    for candidate in (executable, *command[1:]):
        path = Path(candidate)
        if path.is_file():
            paths.append({"path": str(path.resolve()),
                          "digest": "sha256:" + sha256(path.read_bytes()).hexdigest()})
    if not paths or paths[0]["path"] != str(Path(executable).resolve()):
        raise OSError("L3 runner executable is unavailable")
    return tuple(paths)


def _provider_inputs(provider: L3ValidatorProvider) -> tuple[Path, str, tuple[str, ...], tuple[str, ...]]:
    config = provider.config
    path = config.get("contractPath")
    digest = config.get("contractDigest")
    source = config.get("sourceCommand")
    target = config.get("targetCommand")
    if (not isinstance(path, str) or not path or not isinstance(digest, str)
            or not _SHA.fullmatch(digest)
            or not isinstance(source, list) or not source
            or not isinstance(target, list) or not target
            or any(not isinstance(x, str) or not x for x in source + target)):
        raise ValueError("L3 provider contract/runner configuration incomplete")
    return Path(path), digest, tuple(source), tuple(target)


def _contract_covers_properties(contract: object, profile: object) -> bool:
    """A provider declaration cannot substitute for an approved experiment contract."""
    classes = set(contract.experiment_classes)
    dimensions = {item.dimension for item in profile.required_properties}
    if "access_pattern" in dimensions and ("memory_access" not in classes
                                           or not contract.required_access_pattern):
        return False
    if "control_flow" in dimensions and ("control_flow" not in classes
                                         or not contract.required_control_flow):
        return False
    if "synchronization" in dimensions and (not contract.required_sync_semantics or
            contract.payload["schemaVersion"] == EXPERIMENT_CONTRACT_CAMPAIGN_SCHEMA and
            not contract.payload.get("campaignContract")):
        return False
    if "performance_trend" in dimensions and ("statistical" not in classes or
            not contract.metrics and contract.payload["schemaVersion"] != EXPERIMENT_CONTRACT_STATISTICAL_SCHEMA):
        return False
    if "side_channel_speculation" in dimensions:
        return (contract.payload["schemaVersion"] == EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA and
                "side_channel_speculation" in classes and bool(contract.payload.get("specializedExperiment")) and
                {"cross-ISA-hardware-equivalence", "identical-cache-or-timing-parameters"} <=
                set(profile.not_claimed_properties))
    return bool(dimensions)


def _result(requirement: Mapping[str, object], *, status: str, reason_codes: set[str],
            provider: L3ValidatorProvider | None = None, contract_identity: str = "",
            source_binaries: tuple[Mapping[str, str], ...] = (),
            target_binaries: tuple[Mapping[str, str], ...] = (),
            source_artifact_digest: str = "", target_artifact_digest: str = "",
            environment_identity: str = "") -> dict[str, object]:
    payload = {"schemaVersion": PLAN_SCHEMA, "fragmentId": requirement["fragmentId"],
               "programId": requirement["programId"],
               "profileIdentity": requirement["profileIdentity"],
               "requirementIdentity": requirement["requirementIdentity"],
               "bindingStatus": status, "reasonCodes": sorted(reason_codes),
               "providerId": "" if provider is None else provider.provider_id,
               "providerIdentity": "" if provider is None else provider.identity,
               "validatorType": "" if provider is None else provider.validator_type,
               "contractIdentity": contract_identity,
               "sourceRunnerBinaries": list(source_binaries),
               "targetRunnerBinaries": list(target_binaries),
               "sourceArtifactDigest": source_artifact_digest,
               "targetArtifactDigest": target_artifact_digest,
               "environmentIdentity": environment_identity}
    payload["executionIdentity"] = _hash(payload)
    return payload


def resolve_l3_execution_plan(
    requirement: Mapping[str, object], intent: Mapping[str, object],
    providers: tuple[L3ValidatorProvider, ...], *, execution_profile: str,
    source_capabilities: tuple[str, ...], target_capabilities: tuple[str, ...],
    environment_identity: str, source_artifact_digest: str, target_artifact_digest: str,
    validator_types: set[str], translation_plan_id: str = "",
    experiment_contract_id: str = "",
) -> dict[str, object]:
    """Resolve one fragment; never lower requirements to satisfy a provider."""
    profile = parse_l3_intent_profile(intent, fragment_id=str(requirement["fragmentId"]))
    if requirement["profileIdentity"] != profile.profile_identity:
        return _result(requirement, status="inconclusive", reason_codes={"l3.profile.stale"})
    if (requirement["programId"] != profile.program_id
            or requirement["proofIdentity"] != profile.proof_identity
            or requirement["approvedTargetRelationIdentity"] != profile.approved_target_relation_identity
            or requirement["experimentClasses"] != list(profile.experiment_classes)
            or requirement["requiredProperties"] != [x.to_dict() for x in profile.required_properties]
            or (requirement["eligibilityStatus"] == "eligible" and (
                not profile.complete or profile.intent_kind in {L3IntentKind.NONE, L3IntentKind.UNKNOWN}
                or requirement["translationOutcome"] not in
                {"emitted", "strengthened", "functional_fallback"}))):
        return _result(requirement, status="inconclusive", reason_codes={"l3.requirement.profile-mismatch"})
    if requirement["eligibilityStatus"] != "eligible":
        return _result(requirement, status="not_run", reason_codes={"l3.requirement.not-eligible"})
    _sha(environment_identity, "environment identity")
    _sha(source_artifact_digest, "source artifact digest")
    _sha(target_artifact_digest, "target artifact digest")
    reasons: set[str] = set()
    explicit_contract_errors: set[str] = set()
    matches = []
    for provider in providers:
        if provider.validator_type not in validator_types:
            reasons.add("l3.provider.unregistered")
            continue
        if ("side_channel_speculation" in {item.dimension for item in profile.required_properties} and
                provider.binding_kind != "explicit"):
            reasons.add("l3.specialized.explicit-provider-required")
            continue
        if provider.binding_kind == "explicit" and (provider.fragment_ids or provider.profile_ids):
            if (profile.fragment_id not in provider.fragment_ids
                    and profile.profile_identity not in provider.profile_ids):
                continue
        if (not set(profile.experiment_classes) <= set(provider.experiment_classes)
                or not {item.dimension for item in profile.required_properties} <=
                set(provider.property_dimensions)):
            reasons.add("l3.provider.applicability-mismatch")
            continue
        if execution_profile not in provider.execution_profiles:
            reasons.add("l3.provider.execution-profile-mismatch")
            continue
        missing_source = ((set(profile.source_capabilities) | set(provider.source_capabilities))
                          - set(source_capabilities))
        missing_target = ((set(profile.target_capabilities) | set(provider.target_capabilities))
                          - set(target_capabilities))
        if missing_source or missing_target:
            reasons.update("l3.capability.source-missing:" + x for x in missing_source)
            reasons.update("l3.capability.target-missing:" + x for x in missing_target)
            continue
        try:
            path, digest, source_command, target_command = _provider_inputs(provider)
            if "sha256:" + sha256(path.read_bytes()).hexdigest() != digest:
                reasons.add("l3.contract.stale")
                if provider.binding_kind == "explicit":
                    explicit_contract_errors.add("l3.contract.stale")
                continue
            contract = load_experiment_contract(path)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            reasons.add("l3.contract.unavailable-or-invalid")
            if provider.binding_kind == "explicit":
                explicit_contract_errors.add("l3.contract.unavailable-or-invalid")
            continue
        if contract.payload["schemaVersion"] not in provider.contract_schemas:
            reasons.add("l3.contract.version-mismatch")
            if provider.binding_kind == "explicit":
                explicit_contract_errors.add("l3.contract.version-mismatch")
            continue
        if (contract.payload["schemaVersion"] not in {EXPERIMENT_CONTRACT_BOUND_SCHEMA,
                                                       EXPERIMENT_CONTRACT_TRACE_SCHEMA,
                                                       EXPERIMENT_CONTRACT_CAMPAIGN_SCHEMA,
                                                       EXPERIMENT_CONTRACT_STATISTICAL_SCHEMA}
                                                       | {EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA}
                or contract.intent_profile_identity != profile.profile_identity
                or contract.requirement_identity != requirement["requirementIdentity"]
                or contract.approved_target_relation_identity != profile.approved_target_relation_identity
                or contract.proof_identity != profile.proof_identity
                or contract.program_id != profile.program_id
                or (translation_plan_id and contract.translation_plan_id != translation_plan_id)
                or (experiment_contract_id and contract.experiment_id != experiment_contract_id)):
            reasons.add("l3.contract.binding-mismatch")
            if provider.binding_kind == "explicit":
                explicit_contract_errors.add("l3.contract.binding-mismatch")
            continue
        if contract.payload["schemaVersion"] == EXPERIMENT_CONTRACT_SPECIALIZED_SCHEMA:
            from .l3_specialized_experiment import mechanism_route_status
            specialized = contract.payload["specializedExperiment"]
            if (provider.binding_kind != "explicit" or
                    provider.config.get("schemaVersion") != "riscv2x86.l3-experiment-runner.v2"):
                reasons.add("l3.specialized.explicit-runner-not-configured")
                continue
            if (specialized["fragmentId"] != profile.fragment_id or
                    specialized["profileIdentity"] != profile.profile_identity or
                    specialized["sourceArtifactDigest"] != source_artifact_digest or
                    specialized["targetArtifactDigest"] != target_artifact_digest or
                    specialized["targetEnvironmentIdentity"] != environment_identity):
                reasons.add("l3.specialized.profile-artifact-or-environment-stale")
                continue
            route_reasons = mechanism_route_status(
                specialized, provider.config.get("specializedMechanismRegistry"),
                {"source": source_capabilities, "target": target_capabilities})
            if route_reasons:
                reasons.update(route_reasons)
                continue
        if not _contract_covers_properties(contract, profile):
            reasons.add("l3.contract.properties-uncovered")
            if provider.binding_kind == "explicit":
                explicit_contract_errors.add("l3.contract.properties-uncovered")
            continue
        try:
            source_bins = _binary_fingerprints(source_command)
            target_bins = _binary_fingerprints(target_command)
        except OSError:
            reasons.add("l3.runner.unavailable")
            if provider.binding_kind == "explicit":
                explicit_contract_errors.add("l3.runner.unavailable")
            continue
        priority = (0 if profile.fragment_id in provider.fragment_ids else
                    1 if profile.profile_identity in provider.profile_ids else 2)
        matches.append((priority, provider, contract.identity, source_bins, target_bins))
    if explicit_contract_errors:
        return _result(requirement, status="inconclusive", reason_codes=explicit_contract_errors)
    if not matches:
        if ("side_channel_speculation" in {item.dimension for item in profile.required_properties} and
                not explicit_contract_errors and not any(r.startswith("l3.capability.") or
                                                        r.startswith("l3.runner.") or
                                                        r.endswith("-capability-missing") or
                                                        r.endswith("-environment-stale") for r in reasons)):
            return _result(requirement, status="needs_route",
                           reason_codes=reasons or {"l3.specialized.approved-target-mechanism-missing"})
        return _result(requirement, status="inconclusive",
                       reason_codes=reasons or {"l3.provider.missing"})
    best = min(item[0] for item in matches)
    selected = [item for item in matches if item[0] == best]
    if len(selected) != 1:
        return _result(requirement, status="inconclusive",
                       reason_codes={"l3.provider.ambiguous"})
    _, provider, contract_id, source_bins, target_bins = selected[0]
    return _result(requirement, status="resolved", reason_codes=set(), provider=provider,
                   contract_identity=contract_id, source_binaries=source_bins,
                   target_binaries=target_bins, source_artifact_digest=source_artifact_digest,
                   target_artifact_digest=target_artifact_digest,
                   environment_identity=environment_identity)


def build_l3_capability_registry_validator(
    config: Mapping[str, object], factories: Mapping[str, Callable[[Mapping[str, object]], Callable]],
) -> Callable:
    fields = {"schemaVersion", "providers", "executionProfile", "sourceCapabilities",
              "targetCapabilities", "environmentId"}
    if not isinstance(config, Mapping) or set(config) != fields or config["schemaVersion"] != REGISTRY_SCHEMA:
        raise ValueError("L3 capability registry schema invalid")
    providers_raw = config["providers"]
    if not isinstance(providers_raw, list):
        raise ValueError("L3 providers must be an array")
    providers = tuple(provider_from_dict(item) for item in providers_raw)
    ids = tuple(item.provider_id for item in providers)
    if ids != tuple(sorted(set(ids))):
        raise ValueError("L3 provider IDs must be sorted and unique")
    source = _canonical(config["sourceCapabilities"], "sourceCapabilities")
    target = _canonical(config["targetCapabilities"], "targetCapabilities")
    execution = config["executionProfile"]
    environment_id = config["environmentId"]
    if not isinstance(execution, str) or not execution or not isinstance(environment_id, str) or not environment_id:
        raise ValueError("L3 execution/environment identity missing")

    def validate(**kwargs: object) -> ValidationLayerResult:
        artifact = kwargs.get("translation_artifact")
        environment = kwargs.get("target_environment")
        if (not isinstance(environment, Mapping) or environment.get("environmentId") != environment_id):
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                         detail="l3.environment.identity-mismatch")
        try:
            manifest = parse_l3_requirement_manifest(kwargs.get("l3_requirement_manifest"))
            fragment_id = getattr(artifact, "fragment_id", "")
            items = [x for x in manifest.requirements if x["fragmentId"] == fragment_id]
            if len(items) != 1:
                raise ValueError("l3.requirement.fragment-ambiguous-or-missing")
            profile_raw = kwargs.get("l3_intent_profile")
            profile = parse_l3_intent_profile(profile_raw, fragment_id=fragment_id)
            requirement = items[0]
            if (requirement["proofIdentity"] != getattr(artifact, "proof_identity", "")
                    or requirement["programId"] != profile.program_id):
                raise ValueError("l3.requirement.proof-or-program-mismatch")
            source_artifact = kwargs["source_program_artifact"]
            target_artifact = kwargs["target_program_artifact"]
            plan = resolve_l3_execution_plan(
                requirement, profile.to_dict(), providers, execution_profile=execution,
                source_capabilities=source, target_capabilities=target,
                environment_identity=_hash(environment),
                source_artifact_digest=source_artifact.artifact_digest,
                target_artifact_digest=target_artifact.artifact_digest,
                validator_types=set(factories) - {"l3-capability-provider-registry"},
                translation_plan_id=getattr(artifact, "translation_plan_id", ""),
                experiment_contract_id=("" if getattr(kwargs.get("validation_plan"),
                    "experiment_contract_id", "") == "resolved-per-fragment" else
                    getattr(kwargs.get("validation_plan"), "experiment_contract_id", "")),
            )
            directory = kwargs.get("l3_plan_directory")
            if directory is not None:
                root = Path(directory)
                root.mkdir(parents=True, exist_ok=True)
                (root / (plan["executionIdentity"].replace(":", "-") + ".json")).write_text(
                    json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if plan["bindingStatus"] != "resolved":
                status = (ValidationStatus.NEEDS_ROUTE if plan["bindingStatus"] == "needs_route"
                          else ValidationStatus.INCONCLUSIVE)
                return ValidationLayerResult(ValidationLevel.L3, status,
                                             detail=json.dumps(plan, sort_keys=True))
            provider = next(x for x in providers if x.provider_id == plan["providerId"])
            # Pin executable and any command-local files immediately before the
            # runner starts. The runner separately checks the contract digest.
            path, digest, source_command, target_command = _provider_inputs(provider)
            if ("sha256:" + sha256(path.read_bytes()).hexdigest() != digest
                    or list(_binary_fingerprints(source_command)) != plan["sourceRunnerBinaries"]
                    or list(_binary_fingerprints(target_command)) != plan["targetRunnerBinaries"]):
                return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                             detail="l3.runner.stale")
            from .l3_experiment_runner import load_experiment_contract
            contract = load_experiment_contract(path)
            selected_kwargs = dict(kwargs)
            original_plan = kwargs.get("validation_plan")
            if getattr(original_plan, "experiment_contract_id", "") == "resolved-per-fragment":
                selected_kwargs["validation_plan"] = replace(
                    original_plan, experiment_contract_id=contract.experiment_id)
            result = factories[provider.validator_type](provider.config)(**selected_kwargs)
            if ("sha256:" + sha256(path.read_bytes()).hexdigest() != digest
                    or list(_binary_fingerprints(source_command)) != plan["sourceRunnerBinaries"]
                    or list(_binary_fingerprints(target_command)) != plan["targetRunnerBinaries"]):
                return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                             detail="l3.runner-or-contract.changed-during-execution")
            if (not isinstance(result, ValidationLayerResult) or result.level is not ValidationLevel.L3):
                return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                             detail="l3.provider.protocol-error")
            if result.status is ValidationStatus.VERIFIED:
                _sha(result.evidence_identity, "L3 provider evidence identity")
                from .l3_evidence_closure import parse_fragment
                try:
                    provider_detail = json.loads(result.detail)
                    fragment = parse_fragment(provider_detail["fragmentResult"])
                    reports = provider_detail["platformReports"]
                    if not isinstance(reports, Mapping) or set(reports) != {"source", "target"}:
                        raise ValueError("L3 provider source/target report bodies missing")
                    from .l3_evidence_closure import parse_dimension
                    for dimension in fragment["dimensionResults"].values():
                        parse_dimension(dimension, source_report=reports["source"],
                                        target_report=reports["target"])
                    if (fragment["status"] != "verified" or fragment["fragmentId"] != fragment_id or
                            fragment["requirementIdentity"] != requirement["requirementIdentity"] or
                            fragment["profileIdentity"] != requirement["profileIdentity"] or
                            any(x["contractIdentity"] != plan["contractIdentity"] or
                                x["sourceArtifactIdentity"] != plan["sourceArtifactDigest"] or
                                x["targetArtifactIdentity"] != plan["targetArtifactDigest"]
                                for x in fragment["dimensionResults"].values())):
                        raise ValueError("L3 provider dimension closure does not match execution plan")
                except (ValueError, KeyError, TypeError) as exc:
                    return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                                 detail="l3.provider.evidence-closure-invalid: " + str(exc))
                return ValidationLayerResult(
                    ValidationLevel.L3, ValidationStatus.VERIFIED,
                    _hash({"executionIdentity": plan["executionIdentity"],
                           "providerEvidenceIdentity": result.evidence_identity}),
                    json.dumps({"executionIdentity": plan["executionIdentity"],
                                "providerEvidenceIdentity": result.evidence_identity,
                                "providerId": provider.provider_id,
                                "providerKind": provider.binding_kind,
                                "providerInvoked": True,
                                "contractSchemaVersion": contract.payload["schemaVersion"],
                                "fragmentResult": fragment,
                                "providerDetail": result.detail}, sort_keys=True))
            return ValidationLayerResult(
                ValidationLevel.L3, result.status, result.evidence_identity,
                json.dumps({"executionIdentity": plan["executionIdentity"],
                            "providerId": provider.provider_id,
                            "providerKind": provider.binding_kind,
                            "providerInvoked": True,
                            "contractSchemaVersion": contract.payload["schemaVersion"],
                            "providerDetail": result.detail}, sort_keys=True))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
                                         detail="l3.provider.resolution-unavailable: " + str(exc))

    return validate
