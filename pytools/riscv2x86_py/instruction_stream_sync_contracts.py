"""Independent contracts for instruction-stream synchronization."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from hashlib import sha256
import re
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping

INSTRUCTION_STREAM_SYNC_REGISTRY_SCHEMA = "riscv2x86.instruction-stream-sync-registry.v2"
INSTRUCTION_STREAM_SYNC_REGISTRY_VERSION = "instruction-stream-sync-registry-v2"
NOOP_ELISION_CONTRACT_ID = "instruction-stream-sync.noop-proven.v2"
RUNTIME_LOCAL_SYNC_CONTRACT_ID = "instruction-stream-sync.runtime-adapter.v2"


class InstructionStreamSyncScope(str, Enum):
    LOCAL_HART = "local_hart"
    MULTI_HART = "multi_hart"


class InstructionStreamSyncLoweringKind(str, Enum):
    RUNTIME_HELPER = "runtime_helper"
    CACHE_MAINTENANCE_API = "cache_maintenance_api"
    PROVEN_NOOP = "proven_noop"


@dataclass(frozen=True)
class ModifiedCodeRange:
    object_identity: str
    offset_bytes: int
    length_bytes: int
    address_space_identity: str

    def __post_init__(self) -> None:
        for name in ("object_identity", "address_space_identity"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise TypeError(f"{name} must be non-empty")
        if (isinstance(self.offset_bytes, bool) or not isinstance(self.offset_bytes, int)
                or self.offset_bytes < 0 or isinstance(self.length_bytes, bool)
                or not isinstance(self.length_bytes, int) or self.length_bytes <= 0):
            raise ValueError("modified code range must be finite and non-empty")


@dataclass(frozen=True)
class InstructionStreamSyncContract:
    contract_id: str
    semantic_version: str
    source_fragment_id: str
    target_environment_id: str
    lowering_kind: InstructionStreamSyncLoweringKind
    modified_code_range: ModifiedCodeRange
    data_write_publication_relation_id: str
    instruction_fetch_visibility_relation_id: str
    required_scope: InstructionStreamSyncScope
    cache_coherence_model_id: str
    cross_core_invalidation_relation_id: str | None
    target_cpu_profile_id: str
    runtime_adapter_identity: str
    completion_acknowledgement_relation_id: str
    helper_symbol: str | None = None
    required_header: str = ""
    runtime_library: str = ""
    proves_data_write_publication: bool = True
    proves_instruction_fetch_visibility: bool = True
    proves_completion_acknowledgement: bool = True
    proves_required_scope: bool = True
    preserves_compiler_memory_ordering: bool = True
    preserves_volatile_execution: bool = True
    preserves_cc_clobber: bool = True
    environment_noop_guarantee_id: str | None = None
    complete: bool = True

    def __post_init__(self) -> None:
        for name in ("contract_id", "semantic_version", "source_fragment_id",
                     "target_environment_id", "data_write_publication_relation_id",
                     "instruction_fetch_visibility_relation_id", "cache_coherence_model_id",
                     "target_cpu_profile_id", "runtime_adapter_identity",
                     "completion_acknowledgement_relation_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise TypeError(f"{name} must be a non-empty stripped string")
        if not isinstance(self.lowering_kind, InstructionStreamSyncLoweringKind):
            raise TypeError("lowering kind must be typed")
        if not isinstance(self.required_scope, InstructionStreamSyncScope):
            raise TypeError("instruction-stream scope must be typed")
        if not isinstance(self.modified_code_range, ModifiedCodeRange):
            raise TypeError("modified code range must be typed")
        for name in ("proves_data_write_publication", "proves_instruction_fetch_visibility",
                     "proves_completion_acknowledgement", "proves_required_scope",
                     "preserves_compiler_memory_ordering", "preserves_volatile_execution",
                     "preserves_cc_clobber", "complete"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")
        if (self.cross_core_invalidation_relation_id is not None
                and (not isinstance(self.cross_core_invalidation_relation_id, str)
                     or not self.cross_core_invalidation_relation_id.strip())):
            raise ValueError("cross-core invalidation relation must be non-empty when present")
        if self.lowering_kind is InstructionStreamSyncLoweringKind.PROVEN_NOOP:
            if not self.environment_noop_guarantee_id:
                raise ValueError("no-op route requires a positive environment guarantee")
            if self.helper_symbol or self.required_header or self.runtime_library:
                raise ValueError("no-op route cannot carry helper dependencies")
        elif not all((self.helper_symbol, self.required_header, self.runtime_library)):
            raise ValueError("executable instruction-stream route requires registered helper/API")
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.helper_symbol or "") is None:
            raise ValueError("instruction-stream helper symbol must be a C identifier")

    @property
    def semantic_contract_id(self) -> str:
        return f"{self.contract_id}@{self.semantic_version}"


class InstructionStreamSyncRegistry:
    def __init__(self, *, version: str, source_digest: str = "sha256:direct-test-authority",
                 contracts: Iterable[InstructionStreamSyncContract] = ()) -> None:
        if not isinstance(version, str) or not version.strip():
            raise TypeError("instruction-stream registry version must be non-empty")
        by_key = {}
        for contract in tuple(contracts):
            if not isinstance(contract, InstructionStreamSyncContract):
                raise TypeError("instruction-stream registry entries must be typed")
            key = (contract.source_fragment_id, contract.target_environment_id)
            if key in by_key:
                raise ValueError("ambiguous instruction-stream contract binding")
            by_key[key] = contract
        self.version = version
        if not isinstance(source_digest, str) or not source_digest.startswith("sha256:"):
            raise ValueError("instruction-stream registry requires a source digest")
        self.source_digest = source_digest
        self.schema_version = INSTRUCTION_STREAM_SYNC_REGISTRY_SCHEMA
        self._contracts = MappingProxyType(by_key)

    def resolve(self, fragment_id: str, target_environment_id: str):
        return self._contracts.get((fragment_id, target_environment_id))


@dataclass(frozen=True)
class InstructionStreamSyncProof:
    approved: bool
    reason_code: str
    contract: InstructionStreamSyncContract | None
    obligations: tuple[str, ...] = ()


def prove_instruction_stream_sync(
    contract: InstructionStreamSyncContract | None, *, target_cpu_profile_id: str | None = None,
) -> InstructionStreamSyncProof:
    """Phase-6D proof gate for the independent synchronization route."""
    if contract is None:
        return InstructionStreamSyncProof(False, "ISS_RUNTIME_CONTRACT_MISSING", None)
    if (target_cpu_profile_id is not None
            and contract.target_cpu_profile_id != target_cpu_profile_id):
        return InstructionStreamSyncProof(False, "ISS_TARGET_CPU_PROFILE_MISMATCH", contract)
    checks = (
        (contract.complete, "ISS_RUNTIME_CONTRACT_INCOMPLETE"),
        (contract.proves_data_write_publication, "ISS_DATA_WRITE_PUBLICATION_UNPROVEN"),
        (contract.proves_instruction_fetch_visibility, "ISS_INSTRUCTION_FETCH_VISIBILITY_UNPROVEN"),
        (contract.proves_required_scope, "ISS_REQUIRED_SCOPE_UNPROVEN"),
        (contract.proves_completion_acknowledgement, "ISS_COMPLETION_ACK_UNPROVEN"),
        (contract.preserves_compiler_memory_ordering, "ISS_COMPILER_MEMORY_ORDERING_UNPROVEN"),
        (contract.preserves_volatile_execution, "ISS_VOLATILE_EXECUTION_UNPROVEN"),
        (contract.preserves_cc_clobber, "ISS_CC_CLOBBER_UNPROVEN"),
    )
    for approved, reason in checks:
        if not approved:
            return InstructionStreamSyncProof(False, reason, contract)
    if (contract.required_scope is InstructionStreamSyncScope.MULTI_HART
            and not contract.cross_core_invalidation_relation_id):
        return InstructionStreamSyncProof(False, "ISS_CROSS_CORE_INVALIDATION_UNPROVEN", contract)
    if (contract.lowering_kind is InstructionStreamSyncLoweringKind.PROVEN_NOOP
            and not contract.environment_noop_guarantee_id):
        return InstructionStreamSyncProof(False, "ISS_NOOP_ENVIRONMENT_GUARANTEE_MISSING", contract)
    if contract.lowering_kind is not InstructionStreamSyncLoweringKind.PROVEN_NOOP:
        from .helper_runtime_manifest import get_runtime_helper_contract
        runtime = get_runtime_helper_contract(contract.runtime_adapter_identity)
        if runtime is None:
            return InstructionStreamSyncProof(False, "ISS_RUNTIME_ADAPTER_UNREGISTERED", contract)
        if (runtime.helper_symbol != contract.helper_symbol
                or runtime.required_header != contract.required_header
                or runtime.runtime_library != contract.runtime_library):
            return InstructionStreamSyncProof(False, "ISS_RUNTIME_ADAPTER_BINDING_MISMATCH", contract)
        if (contract.required_scope is InstructionStreamSyncScope.MULTI_HART
                and (runtime.semantic_family.endswith(".local")
                     or runtime.barrier_effect.endswith("_local"))):
            return InstructionStreamSyncProof(False, "ISS_RUNTIME_ADAPTER_SCOPE_MISMATCH", contract)
    return InstructionStreamSyncProof(True, "ISS_PROOF_APPROVED", contract, tuple(sorted((
        "cache-coherence.model", "code-range.identity-and-bounds",
        "completion.acknowledgement", "cross-core.invalidation-if-required",
        "data-write.publication", "instruction-fetch.visibility",
        "runtime-adapter.identity", "scope.local-or-multi-hart", "target-cpu.profile",
    ))))


def instruction_stream_environment_id(environment: object) -> str:
    return "phase6:" + ":".join((environment.architecture.value, environment.abi.value,
        environment.asm_dialect.value, environment.compiler_family, environment.compiler_version,
        environment.target_cpu_profile_id))


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(name + " must be a non-empty string")
    return value.strip()


def instruction_stream_sync_registry_from_dict(value: object) -> InstructionStreamSyncRegistry:
    if not isinstance(value, Mapping) or value.get("schemaVersion") != INSTRUCTION_STREAM_SYNC_REGISTRY_SCHEMA:
        raise ValueError("unsupported instruction-stream synchronization registry schema")
    if set(value) != {"schemaVersion", "version", "sourceDigest", "contracts"}:
        raise ValueError("instruction-stream registry fields are incomplete or unknown")
    raw = value.get("contracts")
    if not isinstance(raw, list):
        raise ValueError("instruction-stream contracts must be an array")
    contracts = []
    for item in raw:
        if not isinstance(item, Mapping) or not isinstance(item.get("modifiedCodeRange"), Mapping):
            raise ValueError("instruction-stream contract or code range is malformed")
        expected = {
            "contractId", "semanticVersion", "sourceFragmentId", "targetEnvironmentId",
            "loweringKind", "modifiedCodeRange", "dataWritePublicationRelationId",
            "instructionFetchVisibilityRelationId", "requiredScope",
            "cacheCoherenceModelId", "crossCoreInvalidationRelationId",
            "targetCpuProfileId", "runtimeAdapterIdentity",
            "completionAcknowledgementRelationId", "helperSymbol", "requiredHeader",
            "runtimeLibrary", "provesDataWritePublication",
            "provesInstructionFetchVisibility", "provesCompletionAcknowledgement",
            "provesRequiredScope", "environmentNoopGuaranteeId", "complete",
            "preservesCompilerMemoryOrdering", "preservesVolatileExecution",
            "preservesCcClobber",
        }
        if set(item) != expected:
            raise ValueError("instruction-stream contract fields are incomplete or unknown")
        code_range = item["modifiedCodeRange"]
        if set(code_range) != {"objectIdentity", "offsetBytes", "lengthBytes", "addressSpaceIdentity"}:
            raise ValueError("modified code range fields are incomplete or unknown")
        contracts.append(InstructionStreamSyncContract(
            contract_id=_text(item.get("contractId"), "contractId"),
            semantic_version=_text(item.get("semanticVersion"), "semanticVersion"),
            source_fragment_id=_text(item.get("sourceFragmentId"), "sourceFragmentId"),
            target_environment_id=_text(item.get("targetEnvironmentId"), "targetEnvironmentId"),
            lowering_kind=InstructionStreamSyncLoweringKind(item.get("loweringKind")),
            modified_code_range=ModifiedCodeRange(_text(code_range.get("objectIdentity"), "objectIdentity"),
                code_range.get("offsetBytes"), code_range.get("lengthBytes"),
                _text(code_range.get("addressSpaceIdentity"), "addressSpaceIdentity")),
            data_write_publication_relation_id=_text(item.get("dataWritePublicationRelationId"), "dataWritePublicationRelationId"),
            instruction_fetch_visibility_relation_id=_text(item.get("instructionFetchVisibilityRelationId"), "instructionFetchVisibilityRelationId"),
            required_scope=InstructionStreamSyncScope(item.get("requiredScope")),
            cache_coherence_model_id=_text(item.get("cacheCoherenceModelId"), "cacheCoherenceModelId"),
            cross_core_invalidation_relation_id=item.get("crossCoreInvalidationRelationId"),
            target_cpu_profile_id=_text(item.get("targetCpuProfileId"), "targetCpuProfileId"),
            runtime_adapter_identity=_text(item.get("runtimeAdapterIdentity"), "runtimeAdapterIdentity"),
            completion_acknowledgement_relation_id=_text(item.get("completionAcknowledgementRelationId"), "completionAcknowledgementRelationId"),
            helper_symbol=item.get("helperSymbol"), required_header=item.get("requiredHeader", ""),
            runtime_library=item.get("runtimeLibrary", ""),
            proves_data_write_publication=item.get("provesDataWritePublication", False),
            proves_instruction_fetch_visibility=item.get("provesInstructionFetchVisibility", False),
            proves_completion_acknowledgement=item.get("provesCompletionAcknowledgement", False),
            proves_required_scope=item.get("provesRequiredScope", False),
            preserves_compiler_memory_ordering=item.get("preservesCompilerMemoryOrdering", False),
            preserves_volatile_execution=item.get("preservesVolatileExecution", False),
            preserves_cc_clobber=item.get("preservesCcClobber", False),
            environment_noop_guarantee_id=item.get("environmentNoopGuaranteeId"),
            complete=item.get("complete", False),
        ))
    return InstructionStreamSyncRegistry(
        version=_text(value.get("version"), "version"),
        source_digest=_text(value.get("sourceDigest"), "sourceDigest"),
        contracts=contracts,
    )


def load_instruction_stream_sync_registry(
    path: str | Path, *, source_path: str | Path | None = None,
) -> InstructionStreamSyncRegistry:
    registry = instruction_stream_sync_registry_from_dict(
        json.loads(Path(path).read_text(encoding="utf-8"))
    )
    if source_path is not None:
        actual = "sha256:" + sha256(Path(source_path).read_bytes()).hexdigest()
        if registry.source_digest != actual:
            raise ValueError("instruction-stream registry source digest mismatch")
    return registry
