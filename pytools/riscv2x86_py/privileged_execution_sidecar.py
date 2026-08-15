"""Phase-4 authority ingress for privileged execution-environment facts.

This module describes where a RISC-V fragment is expected to execute.  It
does not infer privileged semantics from CSR names, instruction mnemonics,
source paths, or disassembly.  Phase 5 must join these declarations with the
canonical machine semantics before any privileged lowering can be proposed.

The absence of a sidecar defaults only the execution boundary to a RISC-V
user process targeting an x86 user process.  It never fabricates a privilege
specification version, ISA extension set, or complete CSR access policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path


PRIVILEGED_EXECUTION_SIDECAR_SCHEMA = (
    "riscv2x86.privileged-execution-sidecar.v1"
)


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
    U = "u"
    S = "s"
    M = "m"
    VU = "vu"
    VS = "vs"
    HS = "hs"


class UnknownCsrAccessDisposition(str, Enum):
    DENY = "deny"
    TRAP = "trap"
    ENVIRONMENT_DEFINED = "environment_defined"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CsrAccessPolicyFacts:
    """Authority declaration for CSR visibility at the fragment boundary."""

    policy_id: str
    readable_csr_ids: tuple[str, ...]
    writable_csr_ids: tuple[str, ...]
    unknown_access: UnknownCsrAccessDisposition
    complete: bool

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("CSR access policy requires policyId")
        _require_unique(self.readable_csr_ids, "readable CSR ids")
        _require_unique(self.writable_csr_ids, "writable CSR ids")
        if self.complete and self.unknown_access is UnknownCsrAccessDisposition.UNKNOWN:
            raise ValueError(
                "complete CSR access policy cannot use unknown disposition"
            )


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

    def __post_init__(self) -> None:
        if not self.fragment_id:
            raise ValueError("privileged execution facts require fragmentId")
        if not self.provenance:
            raise ValueError("privileged execution facts require provenance")
        _require_unique(self.source_isa_extensions, "source ISA extensions")
        _require_unique(self.missing_fact_codes, "missing fact codes")
        if tuple(sorted(self.source_isa_extensions)) != self.source_isa_extensions:
            raise ValueError("source ISA extensions must use stable sorting")
        if tuple(sorted(self.missing_fact_codes)) != self.missing_fact_codes:
            raise ValueError("missing fact codes must use stable sorting")
        if self.complete and self.missing_fact_codes:
            raise ValueError("complete privileged facts cannot have missing facts")


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
        if self.schema_version != PRIVILEGED_EXECUTION_SIDECAR_SCHEMA:
            raise ValueError("unsupported privileged execution schemaVersion")
        if not self.provenance:
            raise ValueError("privileged execution sidecar requires provenance")
        ids = tuple(item.fragment_id for item in self.facts_by_fragment_id)
        _require_unique(ids, "privileged execution fragment ids")

    def facts_for(self, fragment_id: str) -> PrivilegedExecutionFacts | None:
        return next(
            (item for item in self.facts_by_fragment_id
             if item.fragment_id == fragment_id),
            None,
        )


def _require_dict(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    return value


def _require_nonempty_string(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} must be a non-empty string")
    return value.strip()


def _require_string_array(value: object, what: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{what} must be a non-empty-string array")
    result = tuple(item.strip().lower() for item in value)
    _require_unique(result, what)
    return tuple(sorted(result))


def _require_bool(value: object, what: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{what} must be a boolean")
    return value


def _require_unique(values: tuple[str, ...], what: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{what} must be unique")


def _enum_value(enum_type, value: object, what: str):
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{what} is invalid") from exc


def _expected_source_modes(
    profile: SourceExecutionProfile,
) -> frozenset[SourcePrivilegeMode]:
    return {
        SourceExecutionProfile.RISCV_USER_PROCESS: frozenset(
            {SourcePrivilegeMode.U, SourcePrivilegeMode.VU}
        ),
        SourceExecutionProfile.RISCV_SUPERVISOR_KERNEL: frozenset(
            {SourcePrivilegeMode.S}
        ),
        SourceExecutionProfile.RISCV_MACHINE_FIRMWARE: frozenset(
            {SourcePrivilegeMode.M}
        ),
        SourceExecutionProfile.RISCV_HYPERVISOR: frozenset(
            {SourcePrivilegeMode.HS, SourcePrivilegeMode.VS}
        ),
    }[profile]


def _profile_target_compatible(
    source: SourceExecutionProfile,
    target: TargetExecutionMode,
) -> bool:
    # The only default execution pair is user -> user.  More privileged
    # targets remain declarations, not approvals: Phase 6 must still resolve
    # an exact runtime/kernel/VMM contract for them.
    return (
        target is not TargetExecutionMode.X86_USER_PROCESS
        or source is SourceExecutionProfile.RISCV_USER_PROCESS
    )


def _csr_policy(value: object) -> CsrAccessPolicyFacts:
    data = _require_dict(value, "csrAccessPolicy")
    policy_id = _require_nonempty_string(data.get("policyId"), "policyId")
    readable = _require_string_array(
        data.get("readableCsrIds", []), "readableCsrIds"
    )
    writable = _require_string_array(
        data.get("writableCsrIds", []), "writableCsrIds"
    )
    disposition = _enum_value(
        UnknownCsrAccessDisposition,
        data.get("unknownAccess", "unknown"),
        "unknownAccess",
    )
    complete = _require_bool(data.get("complete", False),
                             "csrAccessPolicy.complete")
    return CsrAccessPolicyFacts(
        policy_id, readable, writable, disposition, complete
    )


def _fragment_facts(
    value: object,
    *,
    sidecar_provenance: str,
    default_source: SourceExecutionProfile,
    default_target: TargetExecutionMode,
) -> PrivilegedExecutionFacts:
    data = _require_dict(value, "privileged execution fragment facts")
    fragment_id = _require_nonempty_string(data.get("fragmentId"), "fragmentId")
    source = _enum_value(
        SourceExecutionProfile,
        data.get("sourceExecutionProfile", default_source.value),
        "sourceExecutionProfile",
    )
    target = _enum_value(
        TargetExecutionMode,
        data.get("targetExecutionMode", default_target.value),
        "targetExecutionMode",
    )
    initial_mode = _enum_value(
        SourcePrivilegeMode,
        data.get("initialPrivilegeMode", "u"),
        "initialPrivilegeMode",
    )
    extensions = _require_string_array(
        data.get("sourceIsaExtensions", []), "sourceIsaExtensions"
    )
    missing = set(
        _require_string_array(data.get("missingFactCodes", []),
                              "missingFactCodes")
    )
    spec = data.get("sourcePrivilegeSpecVersion")
    if spec is not None:
        spec = _require_nonempty_string(spec, "sourcePrivilegeSpecVersion")
    policy = _csr_policy(data.get("csrAccessPolicy", {
        "policyId": "riscv.user.default-deny-privileged.v1",
        "readableCsrIds": [],
        "writableCsrIds": [],
        "unknownAccess": "trap",
        "complete": False,
    }))
    runtime_set = data.get("targetRuntimeContractSetId")
    if runtime_set is not None:
        runtime_set = _require_nonempty_string(
            runtime_set, "targetRuntimeContractSetId"
        )
    provenance = _require_nonempty_string(
        data.get("provenance", sidecar_provenance), "provenance"
    )

    if spec is None:
        missing.add("privileged-execution.privilege-spec-version-missing")
    if not extensions:
        missing.add("privileged-execution.isa-extensions-missing")
    if not policy.complete:
        missing.add("privileged-execution.csr-access-policy-incomplete")
    if initial_mode not in _expected_source_modes(source):
        missing.add("privileged-execution.profile-mode-mismatch")
    if not _profile_target_compatible(source, target):
        missing.add("privileged-execution.source-target-profile-incompatible")

    declared_complete = _require_bool(data.get("complete", False), "complete")
    complete = declared_complete and not missing
    if declared_complete and missing:
        missing.add("privileged-execution.declared-complete-inconsistent")
        complete = False

    return PrivilegedExecutionFacts(
        fragment_id=fragment_id,
        source_execution_profile=source,
        target_execution_mode=target,
        source_privilege_spec_version=spec,
        source_isa_extensions=extensions,
        initial_privilege_mode=initial_mode,
        csr_access_policy=policy,
        target_runtime_contract_set_id=runtime_set,
        complete=complete,
        missing_fact_codes=tuple(sorted(missing)),
        provenance=provenance,
    )


def privileged_execution_sidecar_from_dict(
    value: object,
) -> PrivilegedExecutionSidecar:
    data = _require_dict(value, "privileged execution sidecar")
    if data.get("schemaVersion") != PRIVILEGED_EXECUTION_SIDECAR_SCHEMA:
        raise ValueError("unsupported privileged execution schemaVersion")
    provenance = _require_nonempty_string(data.get("provenance"), "provenance")
    default_source = _enum_value(
        SourceExecutionProfile,
        data.get(
            "defaultSourceExecutionProfile",
            SourceExecutionProfile.RISCV_USER_PROCESS.value,
        ),
        "defaultSourceExecutionProfile",
    )
    default_target = _enum_value(
        TargetExecutionMode,
        data.get(
            "defaultTargetExecutionMode",
            TargetExecutionMode.X86_USER_PROCESS.value,
        ),
        "defaultTargetExecutionMode",
    )
    fragments = data.get("fragments")
    if not isinstance(fragments, list):
        raise ValueError("privileged execution fragments must be an array")
    facts = tuple(sorted((
        _fragment_facts(
            item,
            sidecar_provenance=provenance,
            default_source=default_source,
            default_target=default_target,
        )
        for item in fragments
    ), key=lambda item: item.fragment_id))
    return PrivilegedExecutionSidecar(
        PRIVILEGED_EXECUTION_SIDECAR_SCHEMA,
        facts,
        provenance,
        default_source,
        default_target,
    )


def default_user_process_execution_facts(
    fragment_id: str,
    *,
    provenance: str = "phase4-default-user-process.v1",
) -> PrivilegedExecutionFacts:
    """Return a conservative sidecar-absent execution boundary.

    Profiles are known, but spec/ISA/access facts are not.  Phase 5 may use
    this object to diagnose a privileged operation, never to approve it.
    """
    return PrivilegedExecutionFacts(
        fragment_id=fragment_id,
        source_execution_profile=SourceExecutionProfile.RISCV_USER_PROCESS,
        target_execution_mode=TargetExecutionMode.X86_USER_PROCESS,
        source_privilege_spec_version=None,
        source_isa_extensions=(),
        initial_privilege_mode=SourcePrivilegeMode.U,
        csr_access_policy=CsrAccessPolicyFacts(
            "riscv.user.default-deny-privileged.v1",
            (),
            (),
            UnknownCsrAccessDisposition.TRAP,
            False,
        ),
        target_runtime_contract_set_id=None,
        complete=False,
        missing_fact_codes=(
            "privileged-execution.csr-access-policy-incomplete",
            "privileged-execution.isa-extensions-missing",
            "privileged-execution.privilege-spec-version-missing",
        ),
        provenance=provenance,
    )


def load_privileged_execution_sidecar(
    path: str | Path,
) -> PrivilegedExecutionSidecar:
    return privileged_execution_sidecar_from_dict(
        json.loads(Path(path).read_text(encoding="utf-8"))
    )
