"""One-command target-aware frontend/backend translation used by auto runs."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import json
from hashlib import sha256

from .l2_eligibility import classify_l2_requirements
from .l3_intent_requirements import classify_l3_requirements
from .automatic_batch_cli import inspect_entry_points
from .automatic_l2_authority import materialize_automatic_l2_authority
from .schema import load_report
from .translation_attempt import terminal_attempt_from_finding, save_translation_attempt_archive
from .translation_attempt import load_translation_attempt_archive
from .requirement_staging import atomic_json, write_requirement_staging, write_requirement_failure
from .privileged_environment import (
    EnvironmentRelationKind,
    PrivilegedEnvironmentError,
    load_privileged_environment_manifest,
    validate_privileged_environment_pipeline_authority,
)
from .instruction_stream_sync_contracts import load_instruction_stream_sync_registry
from .csr_environment_contract import load_csr_environment_contract
from .atomic_authority import COMPILER_FRAGMENT_AUTHORITY_SCHEMA
from .compiler_fragment_closure import close_compiler_fragment_candidate, CompilerOperandClosureError
from .compiler_expression_evaluation import close_expression_evaluation
from .compiler_expression import bind_expression_operands, CompilerExpressionError
from .translation_preflight import write_preflight_failure, PreflightToolFailure
from .l2_fragment_execution import resolve_compiler_fragment_candidate


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _inject_atomic_authority(raw_report: Path, source: Path, sidecar: Path) -> None:
    """Bind content-addressed atomic authority to its exact frontend fragment."""
    report = json.loads(raw_report.read_text(encoding="utf-8"))
    binding = json.loads(sidecar.read_text(encoding="utf-8"))
    digest = "sha256:" + sha256(source.read_bytes()).hexdigest()
    required = {"schemaVersion", "sourceDigest", "bundles", "manifestIdentity"}
    if (not isinstance(binding, dict) or set(binding) != required or
            binding["schemaVersion"] != "riscv2x86.atomic-authority-binding.v1" or
            binding["sourceDigest"] != digest or
            binding["manifestIdentity"] != _identity({
                key: value for key, value in binding.items() if key != "manifestIdentity"
            }) or not isinstance(binding["bundles"], list)):
        raise ValueError("atomic authority binding is stale or malformed")
    bundles = {}
    for bundle in binding["bundles"]:
        if not isinstance(bundle, dict) or not isinstance(bundle.get("fragmentId"), str):
            raise ValueError("atomic authority bundle is malformed")
        fragment_id = bundle["fragmentId"]
        if fragment_id in bundles:
            raise ValueError("duplicate atomic authority fragment binding")
        bundles[fragment_id] = bundle
    findings = report if isinstance(report, list) else report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("frontend report has no findings")
    seen = set()
    for finding in findings:
        fragment = finding.get("fragment") if isinstance(finding, dict) else None
        fragment_id = fragment.get("fragmentId") if isinstance(fragment, dict) else None
        if fragment_id in bundles:
            fragment["atomicAuthorityBundle"] = bundles[fragment_id]
            finding["sourceDigest"] = digest
            seen.add(fragment_id)
    if seen != set(bundles):
        raise ValueError("atomic authority references a nonexistent frontend fragment")
    raw_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def _inject_compiler_fragment_authority(
    raw_report: Path, source: Path, functions: tuple[dict[str, object], ...],
) -> None:
    """Bind Clang AST fragment/object facts to exact frontend fragments.

    This payload does not assert an atomic operation.  Phase 5 may consume it
    only after the decoder independently reports a typed AMO operation.
    """
    report = json.loads(raw_report.read_text(encoding="utf-8"))
    findings = report if isinstance(report, list) else report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("frontend report has no findings")
    joins = []
    for finding in findings:
        fragment = finding.get("fragment") if isinstance(finding, dict) else None
        if not isinstance(fragment, dict):
            continue
        fragment_id = str(fragment.get("fragmentId") or fragment.get("id") or "")
        matches = []
        for function in functions:
            boundary = function.get("l2OperandBoundary", {})
            candidates = boundary.get("fragmentCandidates", [])
            candidate, reason = resolve_compiler_fragment_candidate(
                fragment, candidates, function)
            if "AMBIGUOUS" in reason:
                raise ValueError(reason + ": " + fragment_id)
            if candidate is not None:
                matches.append((function, candidate))
        if len(matches) > 1:
            raise ValueError("compiler fragment authority binding is ambiguous: " + fragment_id)
        if not matches:
            record = {"fragmentId": fragment_id, "disposition": "missing",
                      "reasonCode": "L2_FRAGMENT_CANDIDATE_IDENTITY_NOT_FOUND"}
            fragment["compilerFragmentJoin"] = record
            joins.append(record)
            continue
        function, candidate = matches[0]
        if candidate.get("compilerExpressionFacts") is not None:
            try:
                fragment["compilerExpressionJoin"] = bind_expression_operands(
                    candidate, fragment, source_digest=str(function["sourceDigest"]),
                    function_identity=str(function["functionId"]))
            except CompilerExpressionError as exc:
                fragment["compilerExpressionJoin"] = {
                    "schemaVersion": "riscv2x86.compiler-expression-join-decision.v1",
                    "fragmentId": fragment_id, "complete": False,
                    "reasonCode": exc.reason_code, "detail": str(exc),
                    "expressionFacts": candidate["compilerExpressionFacts"]}
            try:
                fragment["compilerExpressionEvaluation"] = close_expression_evaluation(
                    candidate, fragment, source_digest=str(function["sourceDigest"]),
                    function_identity=str(function["functionId"]))
            except CompilerExpressionError as exc:
                fragment["compilerExpressionEvaluation"] = {
                    "schemaVersion": "riscv2x86.compiler-evaluation-decision.v1",
                    "fragmentId": fragment_id, "complete": False,
                    "failureStage": "expression_evaluation_closure",
                    "reasonCode": exc.reason_code, "detail": str(exc)}
        try:
            closed = close_compiler_fragment_candidate(
                candidate, fragment, source_digest=str(function["sourceDigest"]),
                function_identity=str(function["functionId"]))
        except ValueError as exc:
            if isinst…93379 tokens truncated…omplete = _bool(data.get("complete"), "complete", False)
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
