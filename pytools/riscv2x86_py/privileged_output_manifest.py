"""Phase-9 privileged translation output manifest.

The manifest is an audit product.  It serializes already-approved Phase-5/6
facts and structured rejection diagnostics; it never re-analyses assembly,
p-code, renderer text, or compiler output.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Iterable, Mapping

from .privileged_state_adapter import SourcePrivilegedSemanticModel


PRIVILEGED_OUTPUT_MANIFEST_SCHEMA = (
    "riscv2x86.privileged-output-manifest.v1"
)


class PrivilegedOutputStatus(str, Enum):
    EMITTED = "emitted"
    NEEDS_ROUTE = "needs_route"
    KEEP = "keep"
    UNSUPPORTED = "unsupported"


class PrivilegedPreservationConclusion(str, Enum):
    ARCHITECTURE_EQUIVALENT = "architecture_equivalent"
    FUNCTIONAL_EQUIVALENCE_ONLY = "functional_equivalence_only"
    NOT_PRESERVED = "not_preserved"


@dataclass(frozen=True)
class PrivilegedProofIdentity:
    identity: str
    source_model_id: str | None
    preservation_decision_id: str | None
    plan_id: str | None
    constraints_id: str | None
    target_environment_id: str | None
    target_catalog_version: str | None
    selection_policy_id: str | None
    selection_policy_version: str | None

    def __post_init__(self) -> None:
        if not self.identity.startswith("sha256:"):
            raise ValueError("privileged proof identity must be sha256")


@dataclass(frozen=True)
class PrivilegedRuntimeDependency:
    callable_identifier: str | None
    required_headers: tuple[str, ...]
    required_libraries: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("required_headers", "required_libraries"):
            values = getattr(self, name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{name} must be unique and sorted")


@dataclass(frozen=True)
class PrivilegedOutputDiagnostic:
    reason_code: str
    stage: str
    plan_id: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not self.reason_code or not self.stage:
            raise ValueError("privileged diagnostic requires reason and stage")


@dataclass(frozen=True)
class PrivilegedOutputManifest:
    fragment_id: str
    status: PrivilegedOutputStatus
    source_execution_profile: str
    target_execution_profile: str
    source_privilege_spec_version: str | None
    source_isa_extensions: tuple[str, ...]
    semantic_contract_id: str | None
    semantic_contract_version: str | None
    source_registry_version: str | None
    renderer_manifest_id: str | None
    renderer_manifest_version: str | None
    preservation_conclusion: PrivilegedPreservationConclusion
    ignored_state_ids: tuple[str, ...]
    proof: PrivilegedProofIdentity | None
    runtime_dependencies: PrivilegedRuntimeDependency
    diagnostics: tuple[PrivilegedOutputDiagnostic, ...]
    complete: bool
    schema_version: str = PRIVILEGED_OUTPUT_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if not self.fragment_id:
            raise ValueError("privileged output manifest requires fragment id")
        if self.schema_version != PRIVILEGED_OUTPUT_MANIFEST_SCHEMA:
            raise ValueError("unsupported privileged output manifest schema")
        for name in ("source_isa_extensions", "ignored_state_ids"):
            values = getattr(self, name)
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{name} must be unique and sorted")
        ordered = tuple(sorted(
            self.diagnostics,
            key=lambda item: (
                item.stage, item.plan_id or "", item.reason_code,
                item.detail or "",
            ),
        ))
        if ordered != self.diagnostics:
            raise ValueError("privileged diagnostics must use stable sorting")
        if self.status is PrivilegedOutputStatus.EMITTED:
            if not self.complete or self.proof is None:
                raise ValueError("emitted privileged manifest requires proof")
            if not self.semantic_contract_id:
                raise ValueError("emitted manifest requires semantic contract")
            if self.diagnostics:
                raise ValueError("emitted manifest cannot contain diagnostics")
        elif not self.diagnostics:
            raise ValueError("non-emitted privileged manifest needs diagnostics")
        if (
            self.preservation_conclusion
            is PrivilegedPreservationConclusion.ARCHITECTURE_EQUIVALENT
            and self.ignored_state_ids
        ):
            raise ValueError("strict manifest cannot ignore source state")

    def to_dict(self) -> dict[str, object]:
        proof = None if self.proof is None else {
            "identity": self.proof.identity,
            "sourceModelId": self.proof.source_model_id,
            "preservationDecisionId": self.proof.preservation_decision_id,
            "planId": self.proof.plan_id,
            "constraintsId": self.proof.constraints_id,
            "targetEnvironmentId": self.proof.target_environment_id,
            "targetCatalogVersion": self.proof.target_catalog_version,
            "selectionPolicyId": self.proof.selection_policy_id,
            "selectionPolicyVersion": self.proof.selection_policy_version,
        }
        return {
            "schemaVersion": self.schema_version,
            "fragmentId": self.fragment_id,
            "status": self.status.value,
            "sourceExecutionProfile": self.source_execution_profile,
            "targetExecutionProfile": self.target_execution_profile,
            "sourcePrivilegeSpecVersion": self.source_privilege_spec_version,
            "sourceIsaExtensions": list(self.source_isa_extensions),
            "semanticContractId": self.semantic_contract_id,
            "semanticContractVersion": self.semantic_contract_version,
            "sourceRegistryVersion": self.source_registry_version,
            "rendererManifestId": self.renderer_manifest_id,
            "rendererManifestVersion": self.renderer_manifest_version,
            "preservationConclusion": self.preservation_conclusion.value,
            "ignoredStateIds": list(self.ignored_state_ids),
            "proof": proof,
            "runtimeDependencies": {
                "callableIdentifier": (
                    self.runtime_dependencies.callable_identifier
                ),
                "requiredHeaders": list(
                    self.runtime_dependencies.required_headers
                ),
                "requiredLibraries": list(
                    self.runtime_dependencies.required_libraries
                ),
            },
            "diagnostics": [{
                "reasonCode": item.reason_code,
                "stage": item.stage,
                "planId": item.plan_id,
                "detail": item.detail,
            } for item in self.diagnostics],
            "complete": self.complete,
        }


def _proof_identity(artifact: Mapping[str, object]) -> PrivilegedProofIdentity:
    fields = (
        artifact.get("sourceModelId"),
        artifact.get("preservationDecisionId"),
        artifact.get("planId"),
        artifact.get("constraintsId"),
        artifact.get("targetEnvironmentId"),
        artifact.get("targetCatalogVersion"),
        artifact.get("selectionPolicyId"),
        artifact.get("selectionPolicyVersion"),
    )
    identity = "sha256:" + sha256(repr(fields).encode("utf-8")).hexdigest()
    return PrivilegedProofIdentity(
        identity=identity,
        source_model_id=_optional_string(fields[0]),
        preservation_decision_id=_optional_string(fields[1]),
        plan_id=_optional_string(fields[2]),
        constraints_id=_optional_string(fields[3]),
        target_environment_id=_optional_string(fields[4]),
        target_catalog_version=_optional_string(fields[5]),
        selection_policy_id=_optional_string(fields[6]),
        selection_policy_version=_optional_string(fields[7]),
    )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        return ()
    return tuple(sorted(set(
        item for item in value if isinstance(item, str) and item
    )))


def _diagnostics(
    *,
    reason_codes: Iterable[str],
    attempts: object,
    notes: Iterable[str],
) -> tuple[PrivilegedOutputDiagnostic, ...]:
    values: list[PrivilegedOutputDiagnostic] = []
    for code in reason_codes:
        if isinstance(code, str) and code:
            values.append(PrivilegedOutputDiagnostic(code, "translation"))
    if isinstance(attempts, (tuple, list)):
        for attempt in attempts:
            if not isinstance(attempt, Mapping):
                continue
            plan = _optional_string(attempt.get("planId"))
            stage = _optional_string(attempt.get("stage")) or "phase6"
            codes = attempt.get("reasonCodes")
            if isinstance(codes, (tuple, list)):
                for code in codes:
                    if isinstance(code, str) and code:
                        values.append(
                            PrivilegedOutputDiagnostic(code, stage, plan)
                        )
    if not values:
        for note in notes:
            if isinstance(note, str) and note:
                values.append(PrivilegedOutputDiagnostic(
                    "privileged-output.unclassified-diagnostic",
                    "translation",
                    detail=note,
                ))
    if not values:
        values.append(PrivilegedOutputDiagnostic(
            "privileged-output.no-approved-lowering",
            "translation",
        ))
    unique = {
        (item.stage, item.plan_id, item.reason_code, item.detail): item
        for item in values
    }
    return tuple(sorted(unique.values(), key=lambda item: (
        item.stage, item.plan_id or "", item.reason_code, item.detail or "",
    )))


def build_privileged_output_manifest(
    *,
    fragment_id: str,
    privileged: SourcePrivilegedSemanticModel,
    output_kind: str,
    route: str,
    approval_artifact: Mapping[str, object] | None,
    reason_codes: Iterable[str] = (),
    attempts: object = (),
    notes: Iterable[str] = (),
) -> PrivilegedOutputManifest:
    """Build one manifest from typed source facts and Phase-6 artifacts."""
    if not isinstance(privileged, SourcePrivilegedSemanticModel):
        raise TypeError("privileged output requires typed Phase-6A facts")
    state = privileged.state
    if state is None:
        raise ValueError("privileged output requires Phase-5 state")
    artifact = dict(approval_artifact or {})
    replacement_kind = _optional_string(artifact.get("replacementKind"))
    emitted = replacement_kind in {
        "privileged_runtime_adapter",
        "privileged_functional_fallback",
    } and output_kind in {"privileged_runtime", "functional_c"}
    if emitted:
        status = PrivilegedOutputStatus.EMITTED
    elif output_kind in {"needs_route", "route_required", "deferred_route"}:
        status = PrivilegedOutputStatus.NEEDS_ROUTE
    elif output_kind == "keep":
        status = PrivilegedOutputStatus.KEEP
    else:
        status = PrivilegedOutputStatus.UNSUPPORTED

    if replacement_kind == "privileged_runtime_adapter":
        conclusion = PrivilegedPreservationConclusion.ARCHITECTURE_EQUIVALENT
        ignored = ()
    elif replacement_kind == "privileged_functional_fallback":
        conclusion = (
            PrivilegedPreservationConclusion.FUNCTIONAL_EQUIVALENCE_ONLY
        )
        ignored = _strings(artifact.get("ignoredStateIds"))
    else:
        conclusion = PrivilegedPreservationConclusion.NOT_PRESERVED
        ignored = ()

    proof = _proof_identity(artifact) if emitted else None
    diagnostics = () if emitted else _diagnostics(
        reason_codes=reason_codes,
        attempts=attempts,
        notes=notes,
    )
    dependency = PrivilegedRuntimeDependency(
        callable_identifier=_optional_string(
            artifact.get("privilegedCallableIdentifier")
        ),
        required_headers=_strings(artifact.get("requiredHeaders")),
        required_libraries=_strings(artifact.get("requiredLibraries")),
    )
    return PrivilegedOutputManifest(
        fragment_id=fragment_id,
        status=status,
        source_execution_profile=state.execution_profile.value,
        target_execution_profile=state.target_execution_mode.value,
        source_privilege_spec_version=state.source_privilege_spec_version,
        source_isa_extensions=tuple(sorted(state.source_isa_extensions)),
        semantic_contract_id=_optional_string(
            artifact.get("privilegedSemanticContractId")
        ),
        semantic_contract_version=_optional_string(
            artifact.get("privilegedSemanticContractVersion")
        ),
        source_registry_version=_optional_string(
            artifact.get("privilegedSourceRegistryVersion")
        ),
        renderer_manifest_id=_optional_string(
            artifact.get("privilegedRendererManifestId")
        ),
        renderer_manifest_version=_optional_string(
            artifact.get("privilegedRendererManifestVersion")
        ),
        preservation_conclusion=conclusion,
        ignored_state_ids=ignored,
        proof=proof,
        runtime_dependencies=dependency,
        diagnostics=diagnostics,
        complete=bool(emitted and privileged.complete),
    )


def finalize_privileged_output_manifest(
    manifest: Mapping[str, object],
    *,
    verification_status: str,
    verification_detail: str,
    accepted: bool,
    stage: str = "phase8",
) -> dict[str, object]:
    """Attach final pipeline validation without discarding Phase-6 proof."""
    if manifest.get("schemaVersion") != PRIVILEGED_OUTPUT_MANIFEST_SCHEMA:
        raise ValueError("cannot finalize an unknown privileged manifest")
    if not verification_status:
        raise ValueError("privileged manifest finalization requires status")
    result = dict(manifest)
    result["verification"] = {
        "status": verification_status,
        "detail": verification_detail,
    }
    if accepted:
        return result
    result["status"] = PrivilegedOutputStatus.UNSUPPORTED.value
    result["complete"] = False
    diagnostics = [
        dict(item) for item in result.get("diagnostics", ())
        if isinstance(item, Mapping)
    ]
    diagnostics.append({
        "reasonCode": "privileged-output.validation-rejected",
        "stage": stage,
        "planId": None,
        "detail": verification_detail,
    })
    result["diagnostics"] = sorted(
        diagnostics,
        key=lambda item: (
            str(item.get("stage") or ""),
            str(item.get("planId") or ""),
            str(item.get("reasonCode") or ""),
            str(item.get("detail") or ""),
        ),
    )
    return result
