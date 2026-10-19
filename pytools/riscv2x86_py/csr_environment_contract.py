"""Content-bound production contract for CSR runtime translation routes.

The file format intentionally contains both the Phase-6C target mapping and
the Phase-6F renderer recipe.  Loading never derives either item from a CSR
name, an asm template, or a p-code shape.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping

from .csr_effect_constraints import CsrTargetMapping
from .csr_runtime_registry import CounterObservationContract
from .csr_structured_renderer import CsrRuntimeRecipe
from .csr_translation_pipeline import CsrRendererRegistry, CsrRuntimeRegistry


CSR_ENVIRONMENT_CONTRACT_SCHEMA = "riscv2x86.csr-environment-contract.v1"


class CsrEnvironmentContractError(ValueError):
    def __init__(self, reason_code: str, detail: str):
        self.reason_code = reason_code
        super().__init__(reason_code + ": " + detail)


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CsrEnvironmentContract:
    source_digest: str
    fragment_id: str
    relation_kind: str
    runtime_registry: CsrRuntimeRegistry
    renderer_registry: CsrRendererRegistry


def _object(value: object, code: str, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CsrEnvironmentContractError(code, name + " must be an object")
    return value


def _text(value: object, code: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise CsrEnvironmentContractError(code, name + " is missing or invalid")
    return value


def _strings(value: object, code: str, name: str) -> tuple[str, ...]:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) or not item.strip() for item in value)):
        raise CsrEnvironmentContractError(code, name + " is missing or invalid")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise CsrEnvironmentContractError(code, name + " must be sorted and unique")
    return result


def _positive_int(value: object, code: str, name: str, *, allow_zero: bool = False) -> int:
    if (isinstance(value, bool) or not isinstance(value, int)
            or value < (0 if allow_zero else 1)):
        raise CsrEnvironmentContractError(code, name + " is invalid")
    return value


def load_csr_environment_contract(
    path: str | Path, *, source: str | Path | None = None,
) -> CsrEnvironmentContract:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CsrEnvironmentContractError("CSR_ENV_CONTRACT_UNREADABLE", str(exc)) from exc
    root = _object(value, "CSR_ENV_CONTRACT_MALFORMED", "contract")
    expected_root = {
        "schemaVersion", "sourceDigest", "fragmentId", "relationKind",
        "runtimeRegistry", "rendererRegistry", "contractIdentity",
    }
    if set(root) != expected_root:
        raise CsrEnvironmentContractError(
            "CSR_ENV_CONTRACT_FIELDS_INVALID", "contract fields are incomplete or unknown"
        )
    if root.get("schemaVersion") != CSR_ENVIRONMENT_CONTRACT_SCHEMA:
        raise CsrEnvironmentContractError("CSR_ENV_SCHEMA_UNSUPPORTED", "schemaVersion is unsupported")
    if root.get("contractIdentity") != _identity({
            key: item for key, item in root.items() if key != "contractIdentity"
    }):
        raise CsrEnvironmentContractError(
            "CSR_ENV_CONTRACT_IDENTITY_MISMATCH", "contract content identity is invalid"
        )
    digest = _text(root.get("sourceDigest"), "CSR_ENV_SOURCE_DIGEST_MISSING", "sourceDigest")
    if source is not None:
        actual = "sha256:" + sha256(Path(source).read_bytes()).hexdigest()
        if digest != actual:
            raise CsrEnvironmentContractError(
                "CSR_ENV_SOURCE_DIGEST_MISMATCH", "contract is stale or belongs to another source"
            )
    fragment_id = _text(root.get("fragmentId"), "CSR_ENV_FRAGMENT_ID_MISSING", "fragmentId")
    relation = _text(root.get("relationKind"), "CSR_ENV_RELATION_MISSING", "relationKind")
    if relation not in {"architectural-equivalence", "functional-monotonic-observation"}:
        raise CsrEnvironmentContractError("CSR_ENV_RELATION_UNSUPPORTED", "relationKind is unsupported")

    runtime = _object(root.get("runtimeRegistry"), "CSR_ENV_RUNTIME_REGISTRY_MISSING", "runtimeRegistry")
    expected_runtime = {
        "registryVersion", "runtimeVersion", "executionProfile", "shellTransportable",
        "externalStateComplete", "mapping", "counterContract",
    }
    if set(runtime) != expected_runtime:
        raise CsrEnvironmentContractError("CSR_ENV_RUNTIME_FIELDS_INVALID", "runtime registry fields are incomplete or unknown")
    mapping = _object(runtime.get("mapping"), "CSR_ENV_MAPPING_MISSING", "mapping")
    expected_mapping = {
        "sourceEffectId", "sourceCsrId", "targetStateObjectId", "targetOperationId",
        "stateLifetimeId", "readResultMapping", "writeValueMapping", "fieldMappings",
        "oldNewStateRelationId", "accessPolicyMappingId", "deniedAccessTrapMappingId",
        "sideEffectMappingIds", "orderingRelationId",
    }
    if set(mapping) != expected_mapping:
        raise CsrEnvironmentContractError("CSR_ENV_MAPPING_FIELDS_INVALID", "mapping fields are incomplete or unknown")
    counter = _object(runtime.get("counterContract"), "CSR_ENV_COUNTER_CONTRACT_MISSING", "counterContract")
    expected_counter = {
        "contractId", "relationKind", "sourceEpoch", "targetEpoch", "frequencyHz",
        "scaleNumerator", "scaleDenominator", "monotonicity", "wraparoundBits", "scope",
        "migrationBehavior", "serialization", "targetObservationMechanism", "errorBoundTicks",
        "availabilityPolicy", "trapPolicy", "complete",
    }
    if set(counter) != expected_counter or counter.get("relationKind") != relation:
        raise CsrEnvironmentContractError("CSR_ENV_COUNTER_RELATION_MISMATCH", "counter contract is incomplete or disagrees with route relation")
    counter_contract = CounterObservationContract(
        _text(counter.get("contractId"), "CSR_ENV_COUNTER_ID_MISSING", "counterContract.contractId"),
        relation,
        _text(counter.get("sourceEpoch"), "CSR_ENV_COUNTER_EPOCH_MISSING", "sourceEpoch"),
        _text(counter.get("targetEpoch"), "CSR_ENV_COUNTER_EPOCH_MISSING", "targetEpoch"),
        (None if counter.get("frequencyHz") is None else
         _positive_int(counter.get("frequencyHz"), "CSR_ENV_COUNTER_FREQUENCY_INVALID", "frequencyHz")),
        _positive_int(counter.get("scaleNumerator"), "CSR_ENV_COUNTER_SCALE_INVALID", "scaleNumerator"),
        _positive_int(counter.get("scaleDenominator"), "CSR_ENV_COUNTER_SCALE_INVALID", "scaleDenominator"),
        _text(counter.get("monotonicity"), "CSR_ENV_COUNTER_MONOTONICITY_MISSING", "monotonicity"),
        _positive_int(counter.get("wraparoundBits"), "CSR_ENV_COUNTER_WRAPAROUND_INVALID", "wraparoundBits"),
        _text(counter.get("scope"), "CSR_ENV_COUNTER_SCOPE_MISSING", "scope"),
        _text(counter.get("migrationBehavior"), "CSR_ENV_COUNTER_MIGRATION_MISSING", "migrationBehavior"),
        _text(counter.get("serialization"), "CSR_ENV_COUNTER_SERIALIZATION_MISSING", "serialization"),
        _text(counter.get("targetObservationMechanism"), "CSR_ENV_COUNTER_MECHANISM_MISSING", "targetObservationMechanism"),
        _positive_int(counter.get("errorBoundTicks"), "CSR_ENV_COUNTER_ERROR_BOUND_INVALID", "errorBoundTicks", allow_zero=True),
        _text(counter.get("availabilityPolicy"), "CSR_ENV_COUNTER_AVAILABILITY_MISSING", "availabilityPolicy"),
        _text(counter.get("trapPolicy"), "CSR_ENV_COUNTER_TRAP_POLICY_MISSING", "trapPolicy"),
        counter.get("complete") is True,
    )
    if not counter_contract.complete:
        raise CsrEnvironmentContractError("CSR_ENV_COUNTER_CONTRACT_INCOMPLETE", "counter contract is not complete")
    runtime_version = _text(runtime.get("runtimeVersion"), "CSR_ENV_RUNTIME_VERSION_MISSING", "runtimeVersion")
    execution_profile = _text(runtime.get("executionProfile"), "CSR_ENV_EXECUTION_PROFILE_MISSING", "executionProfile")
    target_operation = _text(mapping.get("targetOperationId"), "CSR_ENV_TARGET_OPERATION_MISSING", "targetOperationId")
    target_mapping = CsrTargetMapping(
        _text(mapping.get("sourceEffectId"), "CSR_ENV_SOURCE_EFFECT_MISSING", "sourceEffectId"),
        _text(mapping.get("sourceCsrId"), "CSR_ENV_SOURCE_CSR_MISSING", "sourceCsrId"),
        _text(mapping.get("targetStateObjectId"), "CSR_ENV_TARGET_STATE_MISSING", "targetStateObjectId"),
        target_operation, runtime_version, execution_profile,
        _text(mapping.get("stateLifetimeId"), "CSR_ENV_STATE_LIFETIME_MISSING", "stateLifetimeId"),
        read_result_mapping=mapping.get("readResultMapping"),
        write_value_mapping=mapping.get("writeValueMapping"),
        field_mappings=_strings(mapping.get("fieldMappings"), "CSR_ENV_FIELD_MAPPING_MISSING", "fieldMappings"),
        old_new_state_relation_id=_text(mapping.get("oldNewStateRelationId"), "CSR_ENV_STATE_RELATION_MISSING", "oldNewStateRelationId"),
        access_policy_mapping_id=_text(mapping.get("accessPolicyMappingId"), "CSR_ENV_ACCESS_POLICY_MISSING", "accessPolicyMappingId"),
        denied_access_trap_mapping_id=mapping.get("deniedAccessTrapMappingId"),
        side_effect_mapping_ids=tuple(mapping.get("sideEffectMappingIds") or ()),
        ordering_relation_id=_text(mapping.get("orderingRelationId"), "CSR_ENV_ORDERING_RELATION_MISSING", "orderingRelationId"),
        counter_contract_identity=counter_contract.contract_id,
        counter_relation_kind=counter_contract.relation_kind,
        counter_contract=counter_contract,
    )
    runtime_registry = CsrRuntimeRegistry(
        _text(runtime.get("registryVersion"), "CSR_ENV_REGISTRY_VERSION_MISSING", "registryVersion"),
        runtime_version, execution_profile, (target_mapping,),
        runtime.get("shellTransportable") is True,
        runtime.get("externalStateComplete") is True,
        source_digest=digest, fragment_id=fragment_id,
    )
    if not runtime_registry.shell_transportable or not runtime_registry.external_state_complete:
        raise CsrEnvironmentContractError("CSR_ENV_RUNTIME_AUTHORITY_INCOMPLETE", "shell or external-state authority is incomplete")

    renderer = _object(root.get("rendererRegistry"), "CSR_ENV_RENDERER_REGISTRY_MISSING", "rendererRegistry")
    if set(renderer) != {"registryVersion", "targetOperationId", "recipe"}:
        raise CsrEnvironmentContractError("CSR_ENV_RENDERER_FIELDS_INVALID", "renderer fields are incomplete or unknown")
    if renderer.get("targetOperationId") != target_operation:
        raise CsrEnvironmentContractError("CSR_ENV_RENDERER_OPERATION_MISMATCH", "renderer is bound to a different target operation")
    recipe = _object(renderer.get("recipe"), "CSR_ENV_RECIPE_MISSING", "recipe")
    expected_recipe = {
        "recipeId", "callableIdentifier", "csrToken", "contextExpression",
        "inputExpression", "outputExpression", "requiredHeader", "requiredLibrary",
        "runtimeVersion", "trapResultPolicy", "approved",
    }
    if set(recipe) != expected_recipe or recipe.get("runtimeVersion") != runtime_version:
        raise CsrEnvironmentContractError("CSR_ENV_RECIPE_FIELDS_INVALID", "recipe is incomplete or uses another runtime version")
    recipe_value = CsrRuntimeRecipe(
        _text(recipe.get("recipeId"), "CSR_ENV_RECIPE_ID_MISSING", "recipeId"),
        _text(recipe.get("callableIdentifier"), "CSR_ENV_CALLABLE_MISSING", "callableIdentifier"),
        _text(recipe.get("csrToken"), "CSR_ENV_CSR_TOKEN_MISSING", "csrToken"),
        _text(recipe.get("contextExpression"), "CSR_ENV_CONTEXT_EXPRESSION_MISSING", "contextExpression"),
        recipe.get("inputExpression"), recipe.get("outputExpression"),
        _text(recipe.get("requiredHeader"), "CSR_ENV_HEADER_MISSING", "requiredHeader"),
        _text(recipe.get("requiredLibrary"), "CSR_ENV_LIBRARY_MISSING", "requiredLibrary"),
        runtime_version,
        _text(recipe.get("trapResultPolicy"), "CSR_ENV_TRAP_RESULT_POLICY_MISSING", "trapResultPolicy"),
        recipe.get("approved") is True,
    )
    if not recipe_value.approved:
        raise CsrEnvironmentContractError("CSR_ENV_RECIPE_NOT_APPROVED", "renderer recipe is not approved")
    renderer_registry = CsrRendererRegistry(
        _text(renderer.get("registryVersion"), "CSR_ENV_RENDERER_VERSION_MISSING", "rendererRegistry.registryVersion"),
        {target_operation: recipe_value}, {recipe_value.recipe_id: runtime_version},
    )
    return CsrEnvironmentContract(digest, fragment_id, relation, runtime_registry, renderer_registry)
