"""Content-bound environment authority for explicit ECALL/WFI routes.

The manifest is deliberately an envelope over the existing execution and
runtime registries.  It does not synthesize architectural facts from an
instruction name and it never turns a functional adapter into an
architectural contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping


PRIVILEGED_ENVIRONMENT_SCHEMA = "riscv2x86.privileged-environment.v1"


class EnvironmentRelationKind(str, Enum):
    ARCHITECTURAL = "architectural_equivalence"
    FUNCTIONAL = "functional_fallback"


class EnvironmentOperationKind(str, Enum):
    ECALL = "ecall"
    WFI = "wfi"


class PrivilegedEnvironmentError(ValueError):
    def __init__(self, reason_code: str, detail: str):
        self.reason_code = reason_code
        super().__init__(reason_code + ": " + detail)


def _text(value: object, code: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise PrivilegedEnvironmentError(code, name + " is missing or invalid")
    return value


def _strings(value: object, code: str, name: str) -> tuple[str, ...]:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) or not item.strip() for item in value)):
        raise PrivilegedEnvironmentError(code, name + " is missing or invalid")
    result = tuple(value)
    if tuple(sorted(set(result))) != result:
        raise PrivilegedEnvironmentError(code, name + " must be sorted and unique")
    return result


@dataclass(frozen=True)
class PrivilegedEnvironmentManifest:
    source_digest: str
    fragment_id: str
    operation: EnvironmentOperationKind
    relation: EnvironmentRelationKind
    runtime_set_identity: str
    runtime_set_version: str
    runtime_adapter_identity: str
    source_profile: Mapping[str, object]
    target_profile: Mapping[str, object]
    route_contract: Mapping[str, object]
    execution_sidecar: Path
    runtime_registry: Path | None
    functional_registry: Path | None
    observability_sidecar: Path | None
    ignored_state_sidecar: Path | None


_COMMON_SOURCE = {
    "privilegeSpecVersion": "PRIV_ENV_PRIVILEGE_SPEC_VERSION_MISSING",
    "initialPrivilegeMode": "PRIV_ENV_INITIAL_PRIVILEGE_MODE_MISSING",
    "isaExtensions": "PRIV_ENV_ISA_EXTENSIONS_MISSING",
    "interruptModel": "PRIV_ENV_INTERRUPT_MODEL_MISSING",
    "delegationModel": "PRIV_ENV_DELEGATION_MODEL_MISSING",
    "virtualizationModel": "PRIV_ENV_VIRTUALIZATION_MODEL_MISSING",
    "addressSpaceIdentity": "PRIV_ENV_ADDRESS_SPACE_IDENTITY_MISSING",
    "csrAccessPolicy": "PRIV_ENV_CSR_ACCESS_POLICY_MISSING",
}
_ECALL = {
    "trapHandlerIdentity": "PRIV_ENV_ECALL_TRAP_HANDLER_MISSING",
    "sourceAbi": "PRIV_ENV_ECALL_SOURCE_ABI_MISSING",
    "serviceIdentity": "PRIV_ENV_ECALL_SERVICE_IDENTITY_MISSING",
    "callNumberSource": "PRIV_ENV_ECALL_CALL_NUMBER_SOURCE_MISSING",
    "argumentMapping": "PRIV_ENV_ECALL_ARGUMENT_MAPPING_MISSING",
    "resultMapping": "PRIV_ENV_ECALL_RESULT_MAPPING_MISSING",
    "errorRepresentation": "PRIV_ENV_ECALL_ERROR_REPRESENTATION_MISSING",
    "memoryEffects": "PRIV_ENV_ECALL_MEMORY_EFFECTS_MISSING",
    "clobbers": "PRIV_ENV_ECALL_CLOBBERS_MISSING",
    "continuation": "PRIV_ENV_ECALL_CONTINUATION_MISSING",
    "addressSpaceRelation": "PRIV_ENV_ECALL_ADDRESS_SPACE_RELATION_MISSING",
}
_WFI = {
    "interruptEnableState": "PRIV_ENV_WFI_INTERRUPT_ENABLE_MISSING",
    "pendingInterruptModel": "PRIV_ENV_WFI_PENDING_INTERRUPT_MISSING",
    "delegationRelation": "PRIV_ENV_WFI_DELEGATION_MISSING",
    "virtualizationRelation": "PRIV_ENV_WFI_VIRTUALIZATION_MISSING",
    "trapWakeupContinuation": "PRIV_ENV_WFI_WAKEUP_CONTINUATION_MISSING",
    "spuriousWakeupPolicy": "PRIV_ENV_WFI_SPURIOUS_WAKEUP_POLICY_MISSING",
    "targetWaitAdapter": "PRIV_ENV_WFI_TARGET_ADAPTER_MISSING",
    "schedulerRuntimeInteraction": "PRIV_ENV_WFI_SCHEDULER_INTERACTION_MISSING",
}


def _require_fields(value: Mapping[str, object], fields: Mapping[str, str]) -> None:
    for name, code in fields.items():
        item = value.get(name)
        if item is None or item == "" or item == [] or item == {}:
            raise PrivilegedEnvironmentError(code, name + " is required")


def _resolve_file(root: Path, value: object, code: str, name: str) -> Path:
    raw = Path(_text(value, code, name))
    if raw.is_absolute():
        raise PrivilegedEnvironmentError(code, name + " must be relative")
    result = (root / raw).resolve()
    try:
        result.relative_to(root.resolve())
    except ValueError as exc:
        raise PrivilegedEnvironmentError(code, name + " escapes the environment directory") from exc
    if not result.is_file():
        raise PrivilegedEnvironmentError(code, name + " is unavailable")
    return result


def load_privileged_environment_manifest(
    path: str | Path, *, source: str | Path,
) -> PrivilegedEnvironmentManifest:
    manifest_path = Path(path).resolve()
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrivilegedEnvironmentError("PRIV_ENV_MANIFEST_UNREADABLE", str(exc)) from exc
    if not isinstance(value, Mapping):
        raise PrivilegedEnvironmentError("PRIV_ENV_MANIFEST_MALFORMED", "root must be an object")
    if value.get("schemaVersion") != PRIVILEGED_ENVIRONMENT_SCHEMA:
        raise PrivilegedEnvironmentError("PRIV_ENV_SCHEMA_UNSUPPORTED", "schemaVersion is unsupported")
    source_digest = _text(value.get("sourceDigest"), "PRIV_ENV_SOURCE_DIGEST_MISSING", "sourceDigest")
    actual_digest = "sha256:" + sha256(Path(source).read_bytes()).hexdigest()
    if source_digest != actual_digest:
        raise PrivilegedEnvironmentError("PRIV_ENV_SOURCE_DIGEST_MISMATCH", "manifest is stale or belongs to another source")
    fragment_id = _text(value.get("fragmentId"), "PRIV_ENV_FRAGMENT_ID_MISSING", "fragmentId")
    try:
        operation = EnvironmentOperationKind(value.get("operation"))
    except ValueError as exc:
        raise PrivilegedEnvironmentError("PRIV_ENV_OPERATION_UNSUPPORTED", "operation must be ecall or wfi") from exc
    try:
        relation = EnvironmentRelationKind(value.get("relationKind"))
    except ValueError as exc:
        raise PrivilegedEnvironmentError("PRIV_ENV_RELATION_UNSUPPORTED", "relationKind is unsupported") from exc
    source_profile = value.get("sourceExecutionProfile")
    target_profile = value.get("targetProfile")
    runtime_set = value.get("runtimeContractSet")
    route = value.get("routeContract")
    inputs = value.get("pipelineInputs")
    for item, code, name in (
        (source_profile, "PRIV_ENV_SOURCE_PROFILE_MISSING", "sourceExecutionProfile"),
        (target_profile, "PRIV_ENV_TARGET_PROFILE_MISSING", "targetProfile"),
        (runtime_set, "PRIV_ENV_RUNTIME_SET_MISSING", "runtimeContractSet"),
        (route, "PRIV_ENV_ROUTE_CONTRACT_MISSING", "routeContract"),
        (inputs, "PRIV_ENV_PIPELINE_INPUTS_MISSING", "pipelineInputs"),
    ):
        if not isinstance(item, Mapping):
            raise PrivilegedEnvironmentError(code, name + " must be an object")
    _require_fields(source_profile, _COMMON_SOURCE)
    _require_fields(target_profile, {
        "os": "PRIV_ENV_TARGET_OS_MISSING", "abi": "PRIV_ENV_TARGET_ABI_MISSING",
        "cpuProfile": "PRIV_ENV_TARGET_CPU_PROFILE_MISSING",
    })
    _require_fields(route, _ECALL if operation is EnvironmentOperationKind.ECALL else _WFI)
    adapter = _text(route.get("runtimeAdapterIdentity"), "PRIV_ENV_RUNTIME_ADAPTER_MISSING", "runtimeAdapterIdentity")
    if route.get("targetMechanism") == "direct-x86-syscall":
        raise PrivilegedEnvironmentError(
            "PRIV_ENV_ECALL_DIRECT_SYSCALL_FORBIDDEN",
            "ECALL requires a registered runtime adapter; direct x86 syscall is not assumed equivalent",
        )
    preserved = _strings(route.get("preservedSemantics"), "PRIV_ENV_PRESERVED_SEMANTICS_MISSING", "preservedSemantics")
    not_preserved_raw = route.get("notPreservedSemantics", [])
    if not isinstance(not_preserved_raw, list) or any(not isinstance(x, str) or not x for x in not_preserved_raw):
        raise PrivilegedEnvironmentError("PRIV_ENV_NOT_PRESERVED_SEMANTICS_INVALID", "notPreservedSemantics is invalid")
    not_preserved = tuple(sorted(set(not_preserved_raw)))
    if relation is EnvironmentRelationKind.ARCHITECTURAL and not_preserved:
        raise PrivilegedEnvironmentError("PRIV_ENV_ARCHITECTURAL_RELATION_INCOMPLETE", "architectural route cannot omit semantics")
    if relation is EnvironmentRelationKind.FUNCTIONAL:
        if operation is not EnvironmentOperationKind.WFI:
            raise PrivilegedEnvironmentError("PRIV_ENV_FUNCTIONAL_ROUTE_UNSUPPORTED", "only an explicitly modeled WFI wait-intent fallback is supported")
        required_preserved = "waiting_intent"
        required_lost = {"architectural_interrupt_wakeup", "architectural_state_transition"}
        if required_preserved not in preserved or not required_lost.issubset(not_preserved):
            raise PrivilegedEnvironmentError("PRIV_ENV_WFI_FUNCTIONAL_BOUNDARY_INCOMPLETE", "functional WFI must state preserved wait intent and unpreserved architectural wakeup/state")
        if route.get("targetMechanism") not in {"pause", "yield", "sleep", "registered-runtime-adapter"}:
            raise PrivilegedEnvironmentError("PRIV_ENV_WFI_FUNCTIONAL_MECHANISM_UNSUPPORTED", "functional WFI mechanism is not approved")
    root = manifest_path.parent
    def optional_path(name: str) -> Path | None:
        return None if inputs.get(name) is None else _resolve_file(root, inputs[name], "PRIV_ENV_PIPELINE_INPUT_UNAVAILABLE", name)
    return PrivilegedEnvironmentManifest(
        source_digest, fragment_id, operation, relation,
        _text(runtime_set.get("identity"), "PRIV_ENV_RUNTIME_SET_IDENTITY_MISSING", "runtimeContractSet.identity"),
        _text(runtime_set.get("version"), "PRIV_ENV_RUNTIME_SET_VERSION_MISSING", "runtimeContractSet.version"),
        adapter, dict(source_profile), dict(target_profile), dict(route),
        _resolve_file(root, inputs.get("executionSidecar"), "PRIV_ENV_EXECUTION_SIDECAR_MISSING", "executionSidecar"),
        (_resolve_file(root, inputs.get("runtimeRegistry"),
                       "PRIV_ENV_RUNTIME_REGISTRY_MISSING", "runtimeRegistry")
         if relation is EnvironmentRelationKind.ARCHITECTURAL
         else optional_path("runtimeRegistry")),
        optional_path("functionalRegistry"), optional_path("observabilitySidecar"),
        optional_path("ignoredStateDeclarations"),
    )


def validate_privileged_environment_pipeline_authority(
    manifest: PrivilegedEnvironmentManifest,
) -> None:
    """Cross-check the envelope against the authoritative pipeline inputs."""
    from .privileged_execution_sidecar import load_privileged_execution_sidecar
    from .privileged_pipeline_inputs import load_privileged_runtime_registry
    from .privileged_runtime_contracts import PrivilegedEnvironmentRouteKind

    execution = load_privileged_execution_sidecar(manifest.execution_sidecar)
    facts = execution.facts_for(manifest.fragment_id)
    if facts is None:
        raise PrivilegedEnvironmentError(
            "PRIV_ENV_EXECUTION_FRAGMENT_MISMATCH",
            "execution sidecar does not bind the configured fragment",
        )
    if not facts.complete:
        detail = ",".join(facts.missing_fact_codes) or "execution facts incomplete"
        raise PrivilegedEnvironmentError("PRIV_ENV_EXECUTION_FACTS_INCOMPLETE", detail)
    expected = manifest.source_profile
    comparisons = (
        (facts.source_privilege_spec_version, expected.get("privilegeSpecVersion"),
         "PRIV_ENV_PRIVILEGE_SPEC_MISMATCH"),
        (facts.initial_privilege_mode.value, expected.get("initialPrivilegeMode"),
         "PRIV_ENV_PRIVILEGE_MODE_MISMATCH"),
        (list(facts.source_isa_extensions), expected.get("isaExtensions"),
         "PRIV_ENV_ISA_EXTENSIONS_MISMATCH"),
        (facts.interrupt_model_id, expected.get("interruptModel"),
         "PRIV_ENV_INTERRUPT_MODEL_MISMATCH"),
        (facts.delegation_model_id, expected.get("delegationModel"),
         "PRIV_ENV_DELEGATION_MODEL_MISMATCH"),
        (facts.virtual_memory_model_id, expected.get("virtualizationModel"),
         "PRIV_ENV_VIRTUALIZATION_MODEL_MISMATCH"),
        (facts.address_space_identity, expected.get("addressSpaceIdentity"),
         "PRIV_ENV_ADDRESS_SPACE_MISMATCH"),
        (facts.csr_access_policy_id, expected.get("csrAccessPolicy"),
         "PRIV_ENV_CSR_POLICY_MISMATCH"),
        (facts.target_runtime_contract_set_id,
         manifest.runtime_set_identity + "-v" + manifest.runtime_set_version,
         "PRIV_ENV_RUNTIME_SET_MISMATCH"),
        (facts.os_or_runtime_identity, manifest.target_profile.get("os"),
         "PRIV_ENV_TARGET_OS_MISMATCH"),
        (facts.target_cpu_feature_profile_id, manifest.target_profile.get("cpuProfile"),
         "PRIV_ENV_TARGET_CPU_PROFILE_MISMATCH"),
    )
    for actual, configured, code in comparisons:
        if actual != configured:
            raise PrivilegedEnvironmentError(code, "environment envelope disagrees with execution authority")

    if manifest.relation is EnvironmentRelationKind.FUNCTIONAL:
        if not all((manifest.functional_registry, manifest.observability_sidecar,
                    manifest.ignored_state_sidecar)):
            raise PrivilegedEnvironmentError(
                "PRIV_ENV_FUNCTIONAL_AUTHORITIES_MISSING",
                "functional route requires registry, observability, and ignored-state authorities",
            )
        return
    if manifest.runtime_registry is None:
        raise PrivilegedEnvironmentError(
            "PRIV_ENV_RUNTIME_REGISTRY_MISSING",
            "architectural route requires a strict runtime registry",
        )
    registry = load_privileged_runtime_registry(manifest.runtime_registry)
    expected_route = PrivilegedEnvironmentRouteKind(manifest.operation.value)
    contracts = tuple(registry._contracts.values())
    matching = tuple(
        item for item in contracts
        if item.environment_route_kind is expected_route
        and item.runtime_symbol == manifest.runtime_adapter_identity
        and item.runtime_identity == manifest.runtime_set_identity
        and item.runtime_contract_version == manifest.runtime_set_version
    )
    if len(matching) != 1:
        raise PrivilegedEnvironmentError(
            "PRIV_ENV_RUNTIME_CONTRACT_NOT_REGISTERED",
            "exactly one route/runtime adapter contract must be registered",
        )
