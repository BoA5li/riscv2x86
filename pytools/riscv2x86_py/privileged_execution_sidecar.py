"""Versioned Phase-4 authority facts for privileged execution environments.

V1 remains readable for compatibility, but cannot claim a complete privileged
execution environment because it does not describe delegation, interrupts,
virtual memory, trap handling, address-space identity, or runtime versions.
V2 adds typed submodels for those facts.  Neither schema derives facts from
assembly text, disassembly, symbols, paths, or instruction-name similarity.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path


PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V1 = (
    "riscv2x86.privileged-execution-sidecar.v1"
)
PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2 = (
    "riscv2x86.privileged-execution-sidecar.v2"
)
# Compatibility alias: callers creating legacy fixtures keep producing V1.
PRIVILEGED_EXECUTION_SIDECAR_SCHEMA = PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V1
_SUPPORTED_SCHEMAS = frozenset({
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V1,
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2,
})


class SourceExecutionProfile(str, Enum):
    RISCV_USER_PROCESS = "riscv_user_process"
    RISCV_SUPERVISOR_KERNEL = "riscv_supervisor_kernel"
    RISCV_MACHINE_FIRMWARE = "riscv_machine_firmware"
    RISCV_HYPERVISOR = "riscv_hypervisor"


class TargetExecutionMode(str, Enum):
    X86_USER_PROCESS = "x86_user_process"
    X86_KERNEL = "x86_kernel"
    X86_HYPERVISOR = "x86_hypervisor"
    VIRTUALIZED_RUNTIME = "virtualized_runtime"
    EMULATOR = "emulator"


class SourcePrivilegeMode(str, Enum):
    U = "u"; S = "s"; M = "m"; VU = "vu"; VS = "vs"; HS = "hs"


class UnknownCsrAccessDisposition(str, Enum):
    DENY = "deny"
    TRAP = "trap"
    ENVIRONMENT_DEFINED = "environment_defined"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CsrAccessPolicyFacts:
    policy_id: str
    readable_csr_ids: tuple[str, ...]
    writable_csr_ids: tuple[str, ...]
    unknown_access: UnknownCsrAccessDisposition
    complete: bool

    def __post_init__(self) -> None:
        _identity(self.policy_id, "CSR access policy")
        _stable_unique(self.readable_csr_ids, "readable CSR ids")
        _stable_unique(self.writable_csr_ids, "writable CSR ids")
        if self.complete and self.unknown_access is UnknownCsrAccessDisposition.UNKNOWN:
            raise ValueError("complete CSR access policy cannot be unknown")


@dataclass(frozen=True)
class DelegationModelFacts:
    model_id: str
    exception_delegation_complete: bool
    interrupt_delegation_complete: bool
    delegated_exception_causes: tuple[str, ...]
    delegated_interrupt_causes: tuple[str, ...]
    complete: bool

    def __post_init__(self) -> None:
        _identity(self.model_id, "delegation model")
        _stable_unique(self.delegated_exception_causes, "delegated exception causes")
        _stable_unique(self.delegated_interrupt_causes, "delegated interrupt causes")


@dataclass(frozen=True)
class InterruptModelFacts:
    model_id: str
    enable_state_complete: bool
    pending_state_complete: bool
    priority_model_id: str | None
    externally_interruptible: bool | None
    complete: bool

    def __post_init__(self) -> None:
        _identity(self.model_id, "interrupt model")
        if self.complete and (
            not self.enable_state_complete
            or not self.pending_state_complete
            or self.externally_interruptible is None
        ):
            raise ValueError("complete interrupt model has unknown state")


@dataclass(frozen=True)
class VirtualMemoryModelFacts:
    model_id: str
    address_translation_enabled: bool | None
    translation_mode: str | None
    page_size_bytes: int | None
    asid_width_bits: int | None
    vmid_width_bits: int | None
    complete: bool

    def __post_init__(self) -> None:
        _identity(self.model_id, "virtual-memory model")
        for name in ("page_size_bytes", "asid_width_bits", "vmid_width_bits"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
            ):
                raise ValueError(f"{name} must be a positive integer")
        if self.complete and self.address_translation_enabled is None:
            raise ValueError("complete virtual-memory model needs enabled state")


@dataclass(frozen=True)
class TrapHandlerBindingFacts:
    binding_id: str
    handler_identity: str
    trap_abi_contract_id: str
    continuation_model_id: str
    complete: bool

    def __post_init__(self) -> None:
        for name in (
            "binding_id", "handler_identity", "trap_abi_contract_id",
            "continuation_model_id",
        ):
            _identity(getattr(self, name), name)


@dataclass(frozen=True)
class AddressSpaceIdentityFacts:
    identity: str
    process_or_guest_id: str
    lifetime_model_id: str
    shared_with_target_runtime: bool
    complete: bool

    def __post_init__(self) -> None:
        for name in ("identity", "process_or_guest_id", "lifetime_model_id"):
            _identity(getattr(self, name), name)


@dataclass(frozen=True)
class PrivilegedExecutionFacts:
    fragment_id: str
    source_execution_profile: SourceExecutionProfile
    target_execution_mode: TargetExecutionMode
    source_privilege_spec_version: str | None
    source_isa_extensions: tuple[str, ...]
    initial_privilege_mode: SourcePrivilegeMode
    csr_access_policy: CsrAccessPolicyFacts
    target_runtime_contract_set_id: str | None
    complete: bool
    missing_fact_codes: tuple[str, ...]
    provenance: str
    delegation_model: DelegationModelFacts | None = None
    interrupt_model: InterruptModelFacts | None = None
    virtual_memory_model: VirtualMemoryModelFacts | None = None
    trap_handler_binding: TrapHandlerBindingFacts | None = None
    address_space: AddressSpaceIdentityFacts | None = None
    os_or_runtime_identity: str | None = None
    kernel_or_vmm_version: str | None = None
    target_cpu_feature_profile_id: str | None = None
    schema_version: str = PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V1

    def __post_init__(self) -> None:
        _identity(self.fragment_id, "fragmentId")
        _identity(self.provenance, "provenance")
        if self.schema_version not in _SUPPORTED_SCHEMAS:
            raise ValueError("unsupported privileged execution facts schema")
        _stable_unique(self.source_isa_extensions, "source ISA extensions")
        _stable_unique(self.missing_fact_codes, "missing fact codes")
        if self.complete and self.missing_fact_codes:
            raise ValueError("complete privileged facts cannot have missing facts")
        if self.complete and self.schema_version != PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2:
            raise ValueError("only V2 privileged execution facts may be complete")
        if self.complete and not all((
            self.csr_access_policy.complete,
            self.delegation_model is not None and self.delegation_model.complete,
            self.interrupt_model is not None and self.interrupt_model.complete,
            self.virtual_memory_model is not None and self.virtual_memory_model.complete,
            self.trap_handler_binding is not None and self.trap_handler_binding.complete,
            self.address_space is not None and self.address_space.complete,
            self.os_or_runtime_identity,
            self.kernel_or_vmm_version,
            self.target_cpu_feature_profile_id,
            self.target_runtime_contract_set_id,
        )):
            raise ValueError("complete V2 privileged facts lack environment facts")

    @property
    def csr_access_policy_id(self) -> str:
        return self.csr_access_policy.policy_id

    @property
    def delegation_model_id(self) -> str | None:
        return None if self.delegation_model is None else self.delegation_model.model_id

    @property
    def interrupt_model_id(self) -> str | None:
        return None if self.interrupt_model is None else self.interrupt_model.model_id

    @property
    def virtual_memory_model_id(self) -> str | None:
        return (
            None if self.virtual_memory_model is None
            else self.virtual_memory_model.model_id
        )

    @property
    def trap_handler_binding_id(self) -> str | None:
        return (
            None if self.trap_handler_binding is None
            else self.trap_handler_binding.binding_id
        )

    @property
    def address_space_identity(self) -> str | None:
        return None if self.address_space is None else self.address_space.identity


@dataclass(frozen=True)
class PrivilegedExecutionSidecar:
    schema_version: str
    facts_by_fragment_id: tuple[PrivilegedExecutionFacts, ...]
    provenance: str
    default_source_execution_profile: SourceExecutionProfile = (
        SourceExecutionProfile.RISCV_USER_PROCESS
    )
    default_target_execution_mode: TargetExecutionMode = (
        TargetExecutionMode.X86_USER_PROCESS
    )

    def __post_init__(self) -> None:
        if self.schema_version not in _SUPPORTED_SCHEMAS:
            raise ValueError("unsupported privileged execution schemaVersion")
        _identity(self.provenance, "sidecar provenance")
        ids = tuple(item.fragment_id for item in self.facts_by_fragment_id)
        _stable_unique(ids, "privileged execution fragment ids")
        if any(item.schema_version != self.schema_version
               for item in self.facts_by_fragment_id):
            raise ValueError("fragment facts schema does not match sidecar schema")

    def facts_for(self, fragment_id: str) -> PrivilegedExecutionFacts | None:
        return next(
            (item for item in self.facts_by_fragment_id
             if item.fragment_id == fragment_id),
            None,
        )


def _identity(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{what} must be a non-empty stripped string")
    return value


def _stable_unique(values: tuple[str, ...], what: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{what} must be unique")
    if tuple(sorted(values)) != values:
        raise ValueError(f"{what} must use stable sorting")


def _obj(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    return value


def _text(value: object, what: str) -> str:
    return _identity(value, what)


def _optional_text(value: object, what: str) -> str | None:
    return None if value is None else _text(value, what)


def _strings(value: object, what: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{what} must be a string array")
    result = tuple(sorted(item.strip().lower() for item in value))
    _stable_unique(result, what)
    return result


def _bool(value: object, what: str, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{what} must be a boolean")
    return value


def _optional_bool(value: object, what: str) -> bool | None:
    if value is None:
        return None
    return _bool(value, what)


def _positive_int(value: object, what: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{what} must be a positive integer")
    return value


def _enum(enum_type, value: object, what: str):
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{what} is invalid") from exc


def _source_modes(profile: SourceExecutionProfile) -> frozenset[SourcePrivilegeMode]:
    return {
        SourceExecutionProfile.RISCV_USER_PROCESS: frozenset({SourcePrivilegeMode.U}),
        SourceExecutionProfile.RISCV_SUPERVISOR_KERNEL: frozenset({SourcePrivilegeMode.S}),
        SourceExecutionProfile.RISCV_MACHINE_FIRMWARE: frozenset({SourcePrivilegeMode.M}),
        SourceExecutionProfile.RISCV_HYPERVISOR: frozenset({
            SourcePrivilegeMode.HS, SourcePrivilegeMode.VS, SourcePrivilegeMode.VU,
        }),
    }[profile]


def _profile_target_compatible(
    source: SourceExecutionProfile, target: TargetExecutionMode
) -> bool:
    if target is TargetExecutionMode.X86_USER_PROCESS:
        return source is SourceExecutionProfile.RISCV_USER_PROCESS
    if target is TargetExecutionMode.X86_KERNEL:
        return source in {
            SourceExecutionProfile.RISCV_USER_PROCESS,
            SourceExecutionProfile.RISCV_SUPERVISOR_KERNEL,
        }
    if target is TargetExecutionMode.X86_HYPERVISOR:
        return source is SourceExecutionProfile.RISCV_HYPERVISOR
    return True  # registered virtual runtime/emulator still needs Phase-6 proof


def _csr_policy(value: object) -> CsrAccessPolicyFacts:
    data = _obj(value, "csrAccessPolicy")
    return CsrAccessPolicyFacts(
        _text(data.get("policyId"), "csrAccessPolicy.policyId"),
        _strings(data.get("readableCsrIds", []), "readableCsrIds"),
        _strings(data.get("writableCsrIds", []), "writableCsrIds"),
        _enum(
            UnknownCsrAccessDisposition,
            data.get("unknownAccess", "unknown"),
            "unknownAccess",
        ),
        _bool(data.get("complete"), "csrAccessPolicy.complete", False),
    )


def _delegation(value: object) -> DelegationModelFacts:
    data = _obj(value, "delegationModel")
    return DelegationModelFacts(
        _text(data.get("modelId"), "delegationModel.modelId"),
        _bool(data.get("exceptionDelegationComplete"),
              "exceptionDelegationComplete", False),
        _bool(data.get("interruptDelegationComplete"),
              "interruptDelegationComplete", False),
        _strings(data.get("delegatedExceptionCauses", []),
                 "delegatedExceptionCauses"),
        _strings(data.get("delegatedInterruptCauses", []),
                 "delegatedInterruptCauses"),
        _bool(data.get("complete"), "delegationModel.complete", False),
    )


def _interrupt(value: object) -> InterruptModelFacts:
    data = _obj(value, "interruptModel")
    return InterruptModelFacts(
        _text(data.get("modelId"), "interruptModel.modelId"),
        _bool(data.get("enableStateComplete"), "enableStateComplete", False),
        _bool(data.get("pendingStateComplete"), "pendingStateComplete", False),
        _optional_text(data.get("priorityModelId"), "priorityModelId"),
        _optional_bool(data.get("externallyInterruptible"),
                       "externallyInterruptible"),
        _bool(data.get("complete"), "interruptModel.complete", False),
    )


def _virtual_memory(value: object) -> VirtualMemoryModelFacts:
    data = _obj(value, "virtualMemoryModel")
    return VirtualMemoryModelFacts(
        _text(data.get("modelId"), "virtualMemoryModel.modelId"),
        _optional_bool(data.get("addressTranslationEnabled"),
                       "addressTranslationEnabled"),
        _optional_text(data.get("translationMode"), "translationMode"),
        _positive_int(data.get("pageSizeBytes"), "pageSizeBytes"),
        _positive_int(data.get("asidWidthBits"), "asidWidthBits"),
        _positive_int(data.get("vmidWidthBits"), "vmidWidthBits"),
        _bool(data.get("complete"), "virtualMemoryModel.complete", False),
    )


def _trap_handler(value: object) -> TrapHandlerBindingFacts:
    data = _obj(value, "trapHandlerBinding")
    return TrapHandlerBindingFacts(
        _text(data.get("bindingId"), "trapHandlerBinding.bindingId"),
        _text(data.get("handlerIdentity"), "handlerIdentity"),
        _text(data.get("trapAbiContractId"), "trapAbiContractId"),
        _text(data.get("continuationModelId"), "continuationModelId"),
        _bool(data.get("complete"), "trapHandlerBinding.complete", False),
    )


def _address_space(value: object) -> AddressSpaceIdentityFacts:
    data = _obj(value, "addressSpaceIdentity")
    return AddressSpaceIdentityFacts(
        _text(data.get("identity"), "addressSpaceIdentity.identity"),
        _text(data.get("processOrGuestId"), "processOrGuestId"),
        _text(data.get("lifetimeModelId"), "lifetimeModelId"),
        _bool(data.get("sharedWithTargetRuntime"),
              "sharedWithTargetRuntime", False),
        _bool(data.get("complete"), "addressSpaceIdentity.complete", False),
    )


def _fragment_facts(
    value: object, *, schema_version: str, sidecar_provenance: str,
    default_source: SourceExecutionProfile, default_target: TargetExecutionMode,
) -> PrivilegedExecutionFacts:
    data = _obj(value, "privileged execution fragment facts")
    source = _enum(
        SourceExecutionProfile,
        data.get("sourceExecutionProfile", default_source.value),
        "sourceExecutionProfile",
    )
    target = _enum(
        TargetExecutionMode,
        data.get("targetExecutionMode", default_target.value),
        "targetExecutionMode",
    )
    mode = _enum(
        SourcePrivilegeMode,
        data.get("initialPrivilegeMode", "u"),
        "initialPrivilegeMode",
    )
    policy = _csr_policy(data.get("csrAccessPolicy", {
        "policyId": "riscv.user.default-deny-privileged.v1",
        "unknownAccess": "trap",
        "complete": False,
    }))
    missing = set(_strings(data.get("missingFactCodes", []), "missingFactCodes"))
    spec = _optional_text(
        data.get("sourcePrivilegeSpecVersion"), "sourcePrivilegeSpecVersion"
    )
    extensions = _strings(data.get("sourceIsaExtensions", []),
                          "sourceIsaExtensions")
    runtime_set = _optional_text(
        data.get("targetRuntimeContractSetId"), "targetRuntimeContractSetId"
    )

    delegation = interrupt = virtual_memory = trap_handler = address_space = None
    os_identity = runtime_version = target_cpu_profile = None
    if schema_version == PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2:
        if data.get("delegationModel") is not None:
            delegation = _delegation(data["delegationModel"])
        if data.get("interruptModel") is not None:
            interrupt = _interrupt(data["interruptModel"])
        if data.get("virtualMemoryModel") is not None:
            virtual_memory = _virtual_memory(data["virtualMemoryModel"])
        if data.get("trapHandlerBinding") is not None:
            trap_handler = _trap_handler(data["trapHandlerBinding"])
        if data.get("addressSpaceIdentity") is not None:
            address_space = _address_space(data["addressSpaceIdentity"])
        os_identity = _optional_text(
            data.get("osOrRuntimeIdentity"), "osOrRuntimeIdentity"
        )
        runtime_version = _optional_text(
            data.get("kernelOrVmmVersion"), "kernelOrVmmVersion"
        )
        target_cpu_profile = _optional_text(
            data.get("targetCpuFeatureProfileId"),
            "targetCpuFeatureProfileId",
        )
    else:
        missing.add("privileged-execution.schema-v1-limited")

    if spec is None:
        missing.add("privileged-execution.privilege-spec-version-missing")
    if not extensions:
        missing.add("privileged-execution.isa-extensions-missing")
    if not policy.complete:
        missing.add("privileged-execution.csr-access-policy-incomplete")
    for value, code in (
        (delegation, "privileged-execution.delegation-model-missing"),
        (interrupt, "privileged-execution.interrupt-model-missing"),
        (virtual_memory, "privileged-execution.virtual-memory-model-missing"),
        (trap_handler, "privileged-execution.trap-handler-missing"),
        (address_space, "privileged-execution.address-space-identity-missing"),
    ):
        if value is None or not value.complete:
            missing.add(code)
    if os_identity is None or runtime_version is None:
        missing.add("privileged-execution.runtime-version-missing")
    if target_cpu_profile is None:
        missing.add("privileged-execution.target-cpu-profile-missing")
    if runtime_set is None:
        missing.add("privileged-execution.runtime-contract-set-missing")
    if mode not in _source_modes(source):
        missing.add("privileged-execution.profile-mode-mismatch")
    if not _profile_target_compatible(source, target):
        missing.add("privileged-execution.target-profile-incompatible")
        missing.add("privileged-execution.source-target-profile-incompatible")

    declared_complete = _bool(data.get("complete"), "complete", False)
    complete = (
        schema_version == PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2
        and declared_complete
        and not missing
    )
    if declared_complete and not complete:
        missing.add("privileged-execution.declared-complete-inconsistent")

    return PrivilegedExecutionFacts(
        fragment_id=_text(data.get("fragmentId"), "fragmentId"),
        source_execution_profile=source,
        target_execution_mode=target,
        source_privilege_spec_version=spec,
        source_isa_extensions=extensions,
        initial_privilege_mode=mode,
        csr_access_policy=policy,
        target_runtime_contract_set_id=runtime_set,
        complete=complete,
        missing_fact_codes=tuple(sorted(missing)),
        provenance=_text(data.get("provenance", sidecar_provenance),
                         "provenance"),
        delegation_model=delegation,
        interrupt_model=interrupt,
        virtual_memory_model=virtual_memory,
        trap_handler_binding=trap_handler,
        address_space=address_space,
        os_or_runtime_identity=os_identity,
        kernel_or_vmm_version=runtime_version,
        target_cpu_feature_profile_id=target_cpu_profile,
        schema_version=schema_version,
    )


def privileged_execution_sidecar_from_dict(
    value: object,
) -> PrivilegedExecutionSidecar:
    data = _obj(value, "privileged execution sidecar")
    schema_version = data.get("schemaVersion")
    if schema_version not in _SUPPORTED_SCHEMAS:
        raise ValueError("unsupported privileged execution schemaVersion")
    provenance = _text(data.get("provenance"), "provenance")
    default_source = _enum(
        SourceExecutionProfile,
        data.get("defaultSourceExecutionProfile",
                 SourceExecutionProfile.RISCV_USER_PROCESS.value),
        "defaultSourceExecutionProfile",
    )
    default_target = _enum(
        TargetExecutionMode,
        data.get("defaultTargetExecutionMode",
                 TargetExecutionMode.X86_USER_PROCESS.value),
        "defaultTargetExecutionMode",
    )
    fragments = data.get("fragments")
    if not isinstance(fragments, list):
        raise ValueError("privileged execution fragments must be an array")
    facts = tuple(sorted((
        _fragment_facts(
            item, schema_version=schema_version,
            sidecar_provenance=provenance,
            default_source=default_source, default_target=default_target,
        )
        for item in fragments
    ), key=lambda item: item.fragment_id))
    return PrivilegedExecutionSidecar(
        schema_version, facts, provenance, default_source, default_target
    )


def default_user_process_execution_facts(
    fragment_id: str,
    *,
    provenance: str = "phase4-default-user-process.v2",
) -> PrivilegedExecutionFacts:
    """Declare only the default user-process execution boundary.

    This object deliberately lacks all privileged environment authorities.
    Ordinary non-privileged fragments are unaffected because Phase 5 observes
    no privileged state.  A detected privileged effect remains incomplete.
    """
    reasons = (
        "privileged-execution.address-space-identity-missing",
        "privileged-execution.csr-access-policy-incomplete",
        "privileged-execution.delegation-model-missing",
        "privileged-execution.interrupt-model-missing",
        "privileged-execution.isa-extensions-missing",
        "privileged-execution.privilege-spec-version-missing",
        "privileged-execution.runtime-contract-set-missing",
        "privileged-execution.runtime-version-missing",
        "privileged-execution.target-cpu-profile-missing",
        "privileged-execution.trap-handler-missing",
        "privileged-execution.virtual-memory-model-missing",
    )
    return PrivilegedExecutionFacts(
        fragment_id=fragment_id,
        source_execution_profile=SourceExecutionProfile.RISCV_USER_PROCESS,
        target_execution_mode=TargetExecutionMode.X86_USER_PROCESS,
        source_privilege_spec_version=None,
        source_isa_extensions=(),
        initial_privilege_mode=SourcePrivilegeMode.U,
        csr_access_policy=CsrAccessPolicyFacts(
            "riscv.user.default-deny-privileged.v1", (), (),
            UnknownCsrAccessDisposition.TRAP, False,
        ),
        target_runtime_contract_set_id=None,
        complete=False,
        missing_fact_codes=reasons,
        provenance=provenance,
        schema_version=PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2,
    )


def load_privileged_execution_sidecar(
    path: str | Path,
) -> PrivilegedExecutionSidecar:
    return privileged_execution_sidecar_from_dict(
        json.loads(Path(path).read_text(encoding="utf-8"))
    )
