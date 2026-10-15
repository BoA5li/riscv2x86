"""Bounded automatic L2-A validation for scalar GNU inline-asm fragments."""
from __future__ import annotations

from hashlib import sha256
import json
from enum import Enum
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Mapping, Sequence

from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .runtime_dependency_binding import resolve_runtime_contracts
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import PreservationMode, ValidationStatus
from .l2_authority import l2_authority_sidecar_from_dict
from .l2_internal_value import instrumentation_plan_from_dict
from .l2_fragment_execution import (
    boundary_as_legacy, fragment_boundary_from_dict,
    fragment_dependency_graph_from_dict,
    materialize_operand_observation_authority,
    operand_observation_authority_from_dict,
    program_execution_authority_from_dict,
)
from .l2_evidence_closure import (
    L2DimensionEvidence, L2EvidenceProductionDisposition,
    L2ProviderExecutionDisposition, provider_evidence_fields,
    provider_precondition_detail,
)
from .l2_dimensions import L2Dimension
from .l2_scalar_authority import (
    assess_scalar_authority_materializability,
    scalar_authority_decision_matches_assessment,
    scalar_authority_decision_from_dict,
)
from .canonical_l2_operand import canonical_l2_operand_bindings_from_dict


AUTO_L2_OPERAND_SCHEMA = "riscv2x86.auto-l2-operand-runner.v1"
AUTO_L2_AUTHORITY_SCHEMA = "riscv2x86.auto-logical-operand-authority.v1"
AUTO_L2_OBSERVATION_SCHEMA = "riscv2x86.auto-logical-operand-observation.v1"
AUTO_L2_FAILURE_SCHEMA = "riscv2x86.auto-l2-operand-failure.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENT = re.compile(r"^[A-Za-z_]\w*$")
_VALUES = (0, 1, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
           0x5A17D3E4C29B806F, 0xC4CEB9FE1A85EC53)


class L2OperandFailureStage(Enum):
    INPUT_ARTIFACT = "input_artifact"
    REPORT_LOAD = "report_load"
    AUTHORITY_JOIN = "authority_join"
    WRAPPER_MATERIALIZATION = "wrapper_materialization"
    INSTRUMENTATION = "instrumentation"
    RUNTIME_CONTRACT = "runtime_contract"
    SHARED_EXECUTION_LOAD = "shared_execution_load"
    HARNESS_BUILD = "harness_build"
    EXECUTION = "execution"
    TRACE_PARSE = "trace_parse"
    OBSERVATION_MATERIALIZATION = "observation_materialization"
    EVIDENCE_CLOSURE = "evidence_closure"


_FAILURE_REASON_BY_STAGE = {
    L2OperandFailureStage.INPUT_ARTIFACT: "L2_OPERAND_INPUT_ARTIFACT_INVALID",
    L2OperandFailureStage.REPORT_LOAD: "L2_OPERAND_REPORT_INVALID",
    L2OperandFailureStage.AUTHORITY_JOIN: "L2_OPERAND_AUTHORITY_JOIN_INVALID",
    L2OperandFailureStage.WRAPPER_MATERIALIZATION:
        "L2_OPERAND_WRAPPER_MATERIALIZATION_FAILED",
    L2OperandFailureStage.INSTRUMENTATION:
        "L2_OPERAND_INSTRUMENTATION_MATERIALIZATION_FAILED",
    L2OperandFailureStage.RUNTIME_CONTRACT:
        "L2_OPERAND_RUNTIME_CONTRACT_RESOLUTION_FAILED",
    L2OperandFailureStage.SHARED_EXECUTION_LOAD:
        "L2_OPERAND_SHARED_EXECUTION_RECORD_INVALID",
    L2OperandFailureStage.HARNESS_BUILD: "L2_OPERAND_HARNESS_BUILD_UNAVAILABLE",
    L2OperandFailureStage.EXECUTION: "L2_OPERAND_EXECUTION_LAUNCH_FAILED",
    L2OperandFailureStage.TRACE_PARSE: "L2_OPERAND_TRACE_PARSE_FAILED",
    L2OperandFailureStage.OBSERVATION_MATERIALIZATION:
        "L2_OPERAND_OBSERVATION_MATERIALIZATION_FAILED",
    L2OperandFailureStage.EVIDENCE_CLOSURE:
        "L2_OPERAND_EVIDENCE_CLOSURE_FAILED",
}


class L2OperandObservationError(ValueError):
    """A stable semantic failure raised while materializing typed observations."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code


def _failure_result(
    stage: L2OperandFailureStage, exc: BaseException, *, artifact_path: Path,
    disposition: L2ProviderExecutionDisposition,
    reason_code: str = "",
) -> ValidationLayerResult:
    """Return a fail-closed, stage-addressable provider failure."""
    detail = {
        "schemaVersion": AUTO_L2_FAILURE_SCHEMA,
        "executionDisposition": disposition.value,
        "evidenceProductionDisposition":
            L2EvidenceProductionDisposition.NOT_PRODUCED.value,
        "reasonCode": reason_code or _FAILURE_REASON_BY_STAGE[stage],
        "failureStage": stage.value,
        "exceptionType": type(exc).__name__,
        "detail": str(exc),
        "artifactPath": str(artifact_path),
    }
    return ValidationLayerResult(
        ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
        _identity(detail), json.dumps(detail, sort_keys=True),
    )


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _identity(value: object) -> str:
    return _digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode())


def _run(argv: Sequence[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                          timeout=timeout, check=False)


def _signedness(type_name: str) -> str:
    value = " ".join(type_name.split())
    if value.startswith("uint") or value.startswith("unsigned"):
        return "unsigned"
    if value.startswith("int") or value.startswith("signed") or value in {"char", "short", "long", "long long"}:
        return "signed"
    return "not_applicable"


def _width(type_name: str) -> int:
    match = re.search(r"(?:u?int)(8|16|32|64)_t", type_name)
    if match:
        return int(match.group(1))
    normalized = " ".join(type_name.split())
    if "char" in normalized: return 8
    if "short" in normalized: return 16
    if "long" in normalized: return 64
    if normalized in {"int", "unsigned", "unsigned int", "signed", "signed int"}: return 32
    return 0


def _finding(report: Mapping[str, object], fragment_id: str) -> Mapping[str, object] | None:
    findings = report.get("findings")
    if not isinstance(findings, list):
        return None
    for item in findings:
        fragment = item.get("fragment") if isinstance(item, Mapping) else None
        if isinstance(fragment, Mapping) and (fragment.get("id") or fragment.get("fragmentId")) == fragment_id:
            return item
    return None


def _authority(finding: Mapping[str, object], functions: list[object], artifact: object) -> tuple[dict[str, object] | None, str]:
    fragment = finding.get("fragment")
    if not isinstance(fragment, Mapping):
        return None, "L2_OPERAND_FRAGMENT_FACTS_MISSING"
    function_name = fragment.get("enclosingFunction")
    matches = [item for item in functions if isinstance(item, Mapping) and item.get("name") == function_name]
    if len(matches) != 1:
        return None, "L2_OPERAND_FUNCTION_BINDING_AMBIGUOUS"
    function = matches[0]
    function_boundary = function.get("l2OperandBoundary")
    approval = finding.get("approvalArtifact")
    raw_fragment_boundary = (approval.get("l2FragmentOperandBoundary")
                             if isinstance(approval, Mapping) else None)
    per_fragment = isinstance(raw_fragment_boundary, Mapping)
    raw_decision = (approval.get("l2ScalarAuthorityDecision")
                    if isinstance(approval, Mapping) else None)
    if isinstance(raw_decision, Mapping):
        fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
        try:
            stored = scalar_authority_decision_from_dict(
                raw_decision, expected_fragment_id=fragment_id)
        except ValueError:
            return None, "L2_SCALAR_AUTHORITY_DECISION_INVALID"
        decision_boundary = (raw_fragment_boundary if per_fragment
                             else function_boundary)
        recomputed = assess_scalar_authority_materializability(
            finding, function,
            decision_boundary if isinstance(decision_boundary, Mapping) else None)
        if not scalar_authority_decision_matches_assessment(stored, recomputed):
            return None, "L2_SCALAR_AUTHORITY_DECISION_STALE"
        if not stored.materializable:
            return None, stored.reason_codes[0]
    if per_fragment:
        try:
            parsed_boundary = fragment_boundary_from_dict(
                raw_fragment_boundary,
                expected_fragment_id=str(fragment.get("id") or fragment.get("fragmentId") or ""),
            )
        except ValueError:
            return None, "L2_FRAGMENT_BOUNDARY_AUTHORITY_INVALID"
        if not parsed_boundary.complete:
            return None, "L2_FRAGMENT_BOUNDARY_VALUE_FLOW_UNPROVED"
    boundary = (boundary_as_legacy(raw_fragment_boundary, function_boundary)
                if per_fragment and isinstance(function_boundary, Mapping)
                else function_boundary)
    if not isinstance(boundary, Mapping) or boundary.get("complete") is not True:
        return None, "L2_OPERAND_BOUNDARY_VALUE_FLOW_UNPROVED"
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if not isinstance(outputs, list) or not isinstance(inputs, list) or not outputs:
        return None, "L2_OPERAND_GNU_SHELL_FACTS_INCOMPLETE"
    declarations = boundary.get("declarations")
    reference_counts = boundary.get("declarationReferenceCounts")
    asm_ids = boundary.get("asmOperandDeclarationIds")
    params = boundary.get("parameterDeclarationIds")
    returned = boundary.get("returnDeclarationId")
    if (not isinstance(declarations, Mapping) or not isinstance(reference_counts, Mapping)
            or not isinstance(asm_ids, list) or not isinstance(params, list)):
        return None, "L2_OPERAND_COMPILER_SIDECAR_MALFORMED"
    if len(asm_ids) != len(outputs) + len(inputs):
        return None, "L2_OPERAND_AST_SHELL_ARITY_MISMATCH"
    output_ids, input_ids = asm_ids[:len(outputs)], asm_ids[len(outputs):]
    # Direct boundary observations need one returned output.  Composite
    # fragments instead require a proof-owned instrumentation plan below.
    read_write_ids = [output_ids[index] for index, item in enumerate(outputs)
                      if isinstance(item, Mapping) and str(item.get("constraint") or "").startswith("+")]
    raw_instrumentation = approval.get("l2InstrumentationPlan") \
        if isinstance(approval, Mapping) else None
    instrumentation = None
    if raw_instrumentation is not None:
        if not isinstance(raw_instrumentation, Mapping):
            return None, "L2_OPERAND_INSTRUMENTATION_PLAN_INVALID"
        try:
            instrumentation = instrumentation_plan_from_dict(raw_instrumentation)
        except ValueError:
            return None, "L2_OPERAND_INSTRUMENTATION_PLAN_INVALID"
        if (instrumentation.fragment_id != getattr(artifact, "fragment_id", "")
                or not instrumentation.complete
                or not instrumentation.non_interference.complete):
            return None, "L2_OPERAND_NON_INTERFERENCE_PROOF_MISSING"
    if not per_fragment:
        if ((len(outputs) != 1 or output_ids[0] != returned) and instrumentation is None):
            return None, "L2_OPERAND_INTERNAL_VALUE_REQUIRES_INSTRUMENTATION"
        if (returned not in output_ids
                or sorted(input_ids + read_write_ids) != sorted(params)):
            return None, "L2_OPERAND_INTERNAL_VALUE_REQUIRES_INSTRUMENTATION"
        for declaration_id in set(asm_ids):
            expected_references = asm_ids.count(declaration_id) + int(returned == declaration_id)
            if reference_counts.get(declaration_id) != expected_references:
                return None, "L2_OPERAND_VALUE_ESCAPES_FUNCTION_BOUNDARY_MODEL"
    if not isinstance(approval, Mapping) or approval.get("proofStatus") != "approved":
        return None, "L2_OPERAND_ARCHITECTURAL_PROOF_NOT_APPROVED"
    shell_identity = getattr(artifact, "shell_facts_identity", "")
    if not isinstance(shell_identity, str) or _SHA.fullmatch(shell_identity) is None:
        return None, "L2_OPERAND_SHELL_IDENTITY_MISSING"
    raw_canonical = approval.get("l2CanonicalOperandBindings")
    if not isinstance(raw_canonical, Mapping):
        return None, "L2_OPERAND_CANONICAL_BINDING_MISSING"
    try:
        canonical = canonical_l2_operand_bindings_from_dict(
            raw_canonical,
            expected_fragment_id=str(getattr(artifact, "fragment_id", "")),
            expected_proof_identity=str(getattr(artifact, "proof_identity", "")),
        )
    except ValueError:
        return None, "L2_OPERAND_CANONICAL_BINDING_MISMATCH"
    id_to_index = {item.operand_id: item.operand_index for item in canonical}
    facts = [{
        "operandIndex": item.operand_index,
        "operandName": item.logical_name,
        "operandId": item.operand_id,
        "declarationId": item.declaration_identity,
        "accessMode": item.access_mode,
        "widthBits": item.width_bits,
        "parameterIndex": item.parameter_index,
        "signedness": item.signedness,
        "tiedToOperandIndex": (id_to_index[item.tied_to_operand_id]
                               if item.tied_to_operand_id else None),
        "earlyClobber": item.early_clobber,
        "sourceConstraint": item.source_constraint,
        "targetContractCarriedByProof": True,
        "escaped": item.escape_kind not in {"none", "non_escaping"},
        "valueNodeIdentity": item.value_node_identity,
    } for item in canonical]
    raw_sidecar = approval.get("l2AuthoritySidecar")
    if not isinstance(raw_sidecar, Mapping):
        return None, "L2_OPERAND_AUTHORITY_SIDECAR_MISSING"
    try:
        sidecar = l2_authority_sidecar_from_dict(
            raw_sidecar, expected_fragment_id=str(getattr(artifact, "fragment_id", "")),
            expected_shell_fact_identity=shell_identity,
        )
    except ValueError:
        return None, "L2_OPERAND_AUTHORITY_SIDECAR_INVALID"
    if (not sidecar.complete
            or sidecar.authority_identity != getattr(artifact, "l2_authority_identity", "")
            or sidecar.effect_relation_set_identity
            != getattr(artifact, "effect_relation_set_identity", "")):
        return None, "L2_OPERAND_AUTHORITY_IDENTITY_MISMATCH"
    # Compiler facts above are an independent applicability check.  The
    # validator consumes the proof-bound sidecar values, never reconstructed
    # values, for comparison authority.
    # The validator consumes typed compiler authority.  Conversion to JSON is
    # only for the evidence payload; no field is reconstructed here.
    sidecar_operands = [item.to_dict() for item in sidecar.operands]
    if len(sidecar_operands) != len(facts):
        return None, "L2_OPERAND_AUTHORITY_FACT_MISSING"
    compiler_facts = {item["operandIndex"]: item for item in facts}
    if len(compiler_facts) != len(facts):
        return None, "L2_OPERAND_AUTHORITY_FACT_MISSING"
    for item in sidecar_operands:
        compiler = compiler_facts.get(item.get("operandIndex"))
        if (not isinstance(compiler, Mapping)
                or item.get("declarationId") != compiler.get("declarationId")
                or item.get("valueNodeIdentity") != compiler.get("valueNodeIdentity")
                or item.get("accessMode") != compiler.get("accessMode")
                or item.get("widthBits") != compiler.get("widthBits")
                or item.get("signedness") != compiler.get("signedness")):
            return None, "L2_OPERAND_AUTHORITY_BOUNDARY_MISMATCH"
    payload = {
        "schemaVersion": AUTO_L2_AUTHORITY_SCHEMA,
        "producer": "clang-ast-plus-frontend-gnu-shell-v1",
        "fragmentId": getattr(artifact, "fragment_id"),
        "function": function_name, "shellFactsIdentity": shell_identity,
        "sourceModelIdentity": getattr(artifact, "source_model_identity", ""),
        "proofIdentity": getattr(artifact, "proof_identity", ""),
        "operands": sidecar_operands,
        "effectRelationSetIdentity": sidecar.effect_relation_set_identity,
        "instrumentationPlan": (None if instrumentation is None
                                else instrumentation.to_dict()),
    }
    if per_fragment:
        raw_execution = approval.get("l2ProgramExecutionAuthority")
        raw_graph = approval.get("l2FragmentDependencyGraph")
        if not isinstance(raw_execution, Mapping):
            return None, "L2_PROGRAM_EXECUTION_AUTHORITY_MISSING"
        if not isinstance(raw_graph, Mapping):
            return None, "L2_FRAGMENT_DEPENDENCY_GRAPH_MISSING"
        try:
            execution = program_execution_authority_from_dict(
                raw_execution, expected_fragment_id=str(getattr(artifact, "fragment_id", "")))
            graph = fragment_dependency_graph_from_dict(
                raw_graph, expected_fragment_id=str(getattr(artifact, "fragment_id", "")))
        except ValueError:
            return None, "L2_PROGRAM_EXECUTION_AUTHORITY_INVALID"
        if (not execution.complete or not graph.complete
                or execution.dependency_graph_identity != graph.graph_identity
                or execution.execution_mode != graph.execution_mode):
            return None, "L2_PROGRAM_EXECUTION_AUTHORITY_INCOMPLETE"
        raw_observation_authority = approval.get(
            "l2OperandObservationAuthority")
        if not isinstance(raw_observation_authority, Mapping):
            return None, "L2_OPERAND_OBSERVATION_AUTHORITY_MISSING"
        if (sidecar.operand_observation_authority is None
                or sidecar.operand_observation_authority.to_dict()
                != dict(raw_observation_authority)):
            return None, "L2_OPERAND_OBSERVATION_SIDECAR_MISMATCH"
        try:
            observation_authority = operand_observation_authority_from_dict(
                raw_observation_authority,
                expected_fragment_id=parsed_boundary.fragment_id,
                expected_boundary_identity=parsed_boundary.boundary_identity,
            )
            recomputed_observation_authority = materialize_operand_observation_authority(
                parsed_boundary,
                operand_ids={int(item["operandIndex"]): str(item["operandId"])
                             for item in sidecar_operands},
                proof_identity=str(getattr(artifact, "proof_identity", "")),
                dependency_graph_identity=graph.graph_identity,
                parameter_indices={int(item["operandIndex"]):
                                   item.get("parameterIndex")
                                   for item in sidecar_operands},
                dependency_edges=graph.edges,
                instrumentation_plan_identity=(
                    instrumentation.plan_identity
                    if instrumentation is not None else ""),
                canonical_bindings=canonical,
            )
        except (KeyError, TypeError, ValueError):
            return None, "L2_OPERAND_OBSERVATION_AUTHORITY_INCOMPLETE"
        if (observation_authority.authority_identity
                != recomputed_observation_authority.authority_identity
                or observation_authority.proof_identity
                != str(getattr(artifact, "proof_identity", ""))
                or observation_authority.dependency_graph_identity
                != graph.graph_identity):
            return None, "L2_OPERAND_OBSERVATION_AUTHORITY_STALE"
        payload.update({
            "fragmentBoundaryIdentity": parsed_boundary.boundary_identity,
            "programExecutionAuthorityIdentity": execution.authority_identity,
            "programExecutionIdentity": execution.execution_identity,
            "executionMode": execution.execution_mode,
            "fragmentDependencyEdges": [item.to_dict() for item in graph.edges],
            "observationSinks": [item.to_dict()
                                 for item in parsed_boundary.observation_sinks],
            "operandObservationAuthority": observation_authority.to_dict(),
            "sourceFragmentObservationIdentity": execution.observation_identity(
                parsed_boundary.fragment_id, "logical_operands", "source"),
            "targetFragmentObservationIdentity": execution.observation_identity(
                parsed_boundary.fragment_id, "logical_operands", "target"),
            "sourceShellObservationIdentity": execution.observation_identity(
                parsed_boundary.fragment_id, "shell_semantics", "source"),
            "targetShellObservationIdentity": execution.observation_identity(
                parsed_boundary.fragment_id, "shell_semantics", "target"),
        })
    payload["authorityIdentity"] = sidecar.authority_identity
    return payload, ""


def _wrapper(function: Mapping[str, object]) -> str:
    name = str(function["name"])
    ret = " ".join(str(function["returnType"]).split())
    types = function["parameterTypes"]
    arity = function.get("arity")
    if (not _IDENT.fullmatch(name) or not isinstance(types, list)
            or isinstance(arity, bool) or not isinstance(arity, int)
            or arity != len(types) or arity > 4):
        raise ValueError("automatic L2 scalar function shape is unsupported")
    normalized_types = [" ".join(str(item).split()) for item in types]
    if (_width(ret) <= 0 or _signedness(ret) == "not_applicable"
            or any(token in ret for token in ("*", "[", "]", "(", ")"))
            or any(_width(item) <= 0 or _signedness(item) == "not_applicable"
                   or any(token in item for token in ("*", "[", "]", "(", ")"))
                   for item in normalized_types)):
        raise ValueError("automatic L2 scalar function type is unsupported")
    declarations = ", ".join(normalized_types) if normalized_types else "void"
    args = ",".join(f"({normalized_types[i]})v[i{i}]" for i in range(len(types)))
    loops = "".join(f"for(unsigned i{i}=0;i{i}<8;++i{i}){{" for i in range(len(types)))
    print_args = "".join(f'printf(";%016llx",(unsigned long long)v[i{i}]);' for i in range(len(types)))
    return "\n".join([
        "#include <stdint.h>", "#include <stdio.h>", "#include <stdarg.h>",
        "void __r2x_l2_observe(unsigned n,...){va_list a;va_start(a,n);printf(\"internal_trace\");for(unsigned i=0;i<n;++i)printf(\";%016llx\",va_arg(a,unsigned long long));printf(\"\\n\");va_end(a);}",
        f"{ret} {name}({declarations});",
        "int main(void){ static const uint64_t v[8]={0,1,UINT64_MAX,UINT64_C(0x7fffffff),UINT64_C(0x80000000),UINT64_C(0xffffffff),UINT64_C(0x5a17d3e4c29b806f),UINT64_C(0xc4ceb9fe1a85ec53)};",
        loops, f"uint64_t out=(uint64_t){name}({args});", f'printf("operand_trace={name}");{print_args}printf(";%016llx\\n",(unsigned long long)out);',
        "}" * len(types), "return 0;}",
    ]) + "\n"


def _instrumented_pair(source: Path, target: Path, report: Mapping[str, object],
                       finding: Mapping[str, object], plan: Mapping[str, object],
                       work: Path) -> tuple[Path, Path]:
    """Materialize observation variants from proof/report byte boundaries only."""
    points = plan.get("points")
    source_offset = plan.get("sourceInsertionOffset")
    if (not isinstance(points, list) or not points
            or isinstance(source_offset, bool) or not isinstance(source_offset, int)):
        raise ValueError("instrumentation plan is incomplete")
    names = []
    for point in points:
        if not isinstance(point, Mapping) or not isinstance(point.get("declarationName"), str):
            raise ValueError("instrumentation declaration binding is invalid")
        names.append(str(point["declarationName"]))
    source_bytes, target_bytes = source.read_bytes(), target.read_bytes()
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("translated findings are unavailable for target offset mapping")
    source_resolved = source.resolve()
    edits = []
    for item in findings:
        if not isinstance(item, Mapping):
            continue
        file_name = item.get("fileName") or item.get("file")
        replacement = item.get("suggestedReplacement")
        embedded_attempt = item.get("translationAttemptArtifact")
        if (not isinstance(replacement, str) or not replacement) and isinstance(
                embedded_attempt, Mapping):
            replacement = embedded_attempt.get("candidateReplacement")
        begin, end = item.get("rewriteBeginOffset"), item.get("rewriteEndOffset")
        if (not isinstance(file_name, str) or not isinstance(replacement, str)
                or not replacement or isinstance(begin, bool) or not isinstance(begin, int)
                or isinstance(end, bool) or not isinstance(end, int)):
            continue
        try:
            same_file = Path(file_name).resolve() == source_resolved
        except OSError:
            same_file = False
        if same_file:
            edits.append((begin, end, replacement.encode("utf-8")))
    edits.sort()
    if any(left[1] > right[0] for left, right in zip(edits, edits[1:])):
        raise ValueError("instrumentation target mapping has overlapping edits")
    expected = source_bytes
    for begin, end, replacement in reversed(edits):
        expected = expected[:begin] + replacement + expected[end:]
    header_prefix = b""
    if expected != target_bytes:
        # Candidate materialization may prepend proof-declared headers.  A
        # unique exact suffix preserves the byte mapping without parsing C.
        if not target_bytes.endswith(expected):
            raise ValueError("instrumentation target mapping is not content-exact")
        header_prefix = target_bytes[:-len(expected)] if expected else target_bytes
        if not header_prefix or not all(
                line.startswith(b"#include <") and line.endswith(b">")
                for line in header_prefix.rstrip(b"\n").splitlines()):
            raise ValueError("instrumentation target header mapping is unapproved")
    target_offset = len(header_prefix) + source_offset + sum(
        len(replacement) - (end - begin)
        for begin, end, replacement in edits if end <= source_offset
    )
    if source_offset > len(source_bytes) or target_offset > len(target_bytes):
        raise ValueError("instrumentation insertion boundary exceeds candidate")
    call = ("\n__r2x_l2_observe(" + str(len(names)) + "," +
            ",".join("(unsigned long long)(" + name + ")" for name in names) + ");\n").encode()
    declaration = b"#include <stdint.h>\nextern void __r2x_l2_observe(unsigned,...);\n"
    source_instrumented = declaration + source_bytes[:source_offset] + call + source_bytes[source_offset:]
    target_instrumented = declaration + target_bytes[:target_offset] + call + target_bytes[target_offset:]
    source_path, target_path = work / "source-instrumented.c", work / "target-instrumented.c"
    source_path.write_bytes(source_instrumented); target_path.write_bytes(target_instrumented)
    return source_path, target_path


def _internal_traces(text: str, width: int) -> tuple[tuple[int, ...], ...] | None:
    rows = []
    for line in text.splitlines():
        if not line.startswith("internal_trace;"):
            continue
        fields = line[len("internal_trace;"):].split(";")
        if len(fields) != width or any(re.fullmatch(r"[0-9a-f]{16}", item) is None
                                       for item in fields):
            return None
        rows.append(tuple(int(item, 16) for item in fields))
    return tuple(rows) if rows else None


def _traces(text: str, name: str, arity: int) -> tuple[tuple[int, ...], ...] | None:
    prefix = "operand_trace=" + name + ";"
    rows = []
    for line in text.splitlines():
        if line.startswith(prefix):
            fields = line[len(prefix):].split(";")
            if len(fields) != arity + 1 or any(re.fullmatch(r"[0-9a-f]{16}", item) is None for item in fields):
                return None
            rows.append(tuple(int(item, 16) for item in fields))
    expected = 8 ** arity
    return tuple(rows) if len(rows) == expected else None


def _sample_observations(rows: tuple[tuple[int, ...], ...] | None,
                         authority: Mapping[str, object],
                         internal_rows: tuple[tuple[int, ...], ...] | None = None,
                         *, trace_arity: int | None = None,
                         ) -> list[dict[str, object]]:
    if rows is None:
        return []
    facts = authority.get("operands")
    if not isinstance(facts, list) or not facts:
        raise L2OperandObservationError(
            "L2_OPERAND_OBSERVATION_FACTS_INVALID",
            "logical operand authority is absent or empty")
    observation_authority = authority.get("operandObservationAuthority")
    if not isinstance(observation_authority, Mapping):
        raise L2OperandObservationError(
            "L2_OPERAND_OBSERVATION_AUTHORITY_MISSING",
            "typed operand observation authority is missing")
    try:
        parsed = operand_observation_authority_from_dict(
            observation_authority,
            expected_fragment_id=str(authority.get("fragmentId", "")),
            expected_boundary_identity=str(
                authority.get("fragmentBoundaryIdentity", "")),
        )
    except ValueError as exc:
        raise L2OperandObservationError(
            "L2_OPERAND_OBSERVATION_AUTHORITY_INVALID", str(exc)) from exc
    bindings = {item.operand_id: item for item in parsed.bindings}
    if len(bindings) != len(parsed.bindings) or len(bindings) != len(facts):
        raise L2OperandObservationError(
            "L2_OPERAND_OBSERVATION_BINDING_SET_MISMATCH",
            "typed bindings do not bijectively cover logical operands")
    arity = trace_arity
    if arity is None:
        arity = len(rows[0]) - 1 if rows else 0
    if isinstance(arity, bool) or not isinstance(arity, int) or arity < 0:
        raise L2OperandObservationError(
            "L2_OPERAND_TRACE_ARITY_INVALID", "trace arity is invalid")
    for row in rows:
        if len(row) != arity + 1:
            raise L2OperandObservationError(
                "L2_OPERAND_TRACE_ARITY_MISMATCH",
                f"trace row has {len(row)} fields; expected {arity + 1}")
    plan = authority.get("instrumentationPlan")
    point_positions = {}
    if isinstance(plan, Mapping) and isinstance(plan.get("points"), list):
        point_positions = {item.get("operandIndex"): index
                           for index, item in enumerate(plan["points"])
                           if isinstance(item, Mapping)}
    result = []
    if internal_rows is not None and len(internal_rows) != len(rows):
        raise L2OperandObservationError(
            "L2_OPERAND_INSTRUMENTATION_SAMPLE_COUNT_MISMATCH",
            "internal trace sample count differs from boundary trace")

    def checked_binding(fact: Mapping[str, object]):
        binding = bindings.get(str(fact.get("operandId", "")))
        if (binding is None
                or binding.operand_index != fact.get("operandIndex")
                or binding.declaration_identity != fact.get("declarationId")
                or binding.value_node_identity != fact.get("valueNodeIdentity")
                or binding.access != fact.get("accessMode")
                or binding.width_bits != fact.get("widthBits")
                or binding.signedness != fact.get("signedness")):
            raise L2OperandObservationError(
                "L2_OPERAND_OBSERVATION_BINDING_MISMATCH",
                f"typed binding does not match operand {fact.get('operandId', '')}")
        return binding

    def before_value(binding, row: tuple[int, ...]):
        if binding.closure_kind == "parameter" or binding.access == "read_write":
            index = binding.parameter_index
            if index is None:
                raise L2OperandObservationError(
                    "L2_OPERAND_READ_WRITE_BEFORE_AUTHORITY_MISSING",
                    f"operand {binding.operand_id} has no before-value source")
            if index >= arity:
                raise L2OperandObservationError(
                    "L2_OPERAND_PARAMETER_INDEX_OUT_OF_RANGE",
                    f"parameter index {index} is outside trace arity {arity}")
            return f"0x{row[index]:016x}", "function_parameter"
        if binding.closure_kind == "producer":
            return None, "composite_dependency"
        raise L2OperandObservationError(
            "L2_OPERAND_INPUT_SOURCE_INVALID",
            f"operand {binding.operand_id} has no typed input source")

    def after_value(binding, sample_index: int, row: tuple[int, ...]):
        if binding.closure_kind == "instrumentation":
            position = point_positions.get(binding.operand_index)
            if not isinstance(position, int) or internal_rows is None:
                raise L2OperandObservationError(
                    "L2_OPERAND_INSTRUMENTATION_TRACE_MISSING",
                    f"operand {binding.operand_id} lacks instrumentation trace")
            if position >= len(internal_rows[sample_index]):
                raise L2OperandObservationError(
                    "L2_OPERAND_INSTRUMENTATION_TRACE_ARITY_MISMATCH",
                    f"instrumentation position {position} is outside trace row")
            return internal_rows[sample_index][position], "instrumentation"
        if binding.closure_kind == "sink":
            if binding.observation_kind != "function_return":
                raise L2OperandObservationError(
                    "L2_OPERAND_OUTPUT_SINK_NOT_RUNTIME_OBSERVABLE",
                    f"sink {binding.observation_kind} needs a registered observer")
            return row[arity], "function_return"
        if binding.closure_kind == "consumer":
            return None, "composite_dependency"
        if binding.closure_kind == "discard":
            return None, "discarded"
        raise L2OperandObservationError(
            "L2_OPERAND_OUTPUT_SINK_INVALID",
            f"operand {binding.operand_id} has no typed output sink")

    for sample_index, row in enumerate(rows):
        operands = []
        for fact in facts:
            if not isinstance(fact, Mapping):
                raise L2OperandObservationError(
                    "L2_OPERAND_OBSERVATION_FACTS_INVALID",
                    "operand fact is not an object")
            binding = checked_binding(fact)
            before = after = None
            kinds: list[str] = []
            if binding.access in {"input", "read_write"}:
                before, kind = before_value(binding, row)
                kinds.append(kind)
            if binding.access in {"output", "read_write"}:
                raw_after, kind = after_value(binding, sample_index, row)
                after = (f"0x{raw_after:016x}"
                         if isinstance(raw_after, int) else None)
                kinds.append(kind)
            operands.append({
                "operandId": binding.operand_id, "access": binding.access,
                "valueBefore": before, "valueAfter": after,
                "observationKind": "+".join(kinds),
                "widthBits": binding.width_bits,
                "signedness": binding.signedness,
                "bindingIdentity": binding.binding_identity,
                "valueNodeIdentity": binding.value_node_identity,
            })
        result.append({"sampleIndex": sample_index, "logicalOperands": operands})
    return result


def _load_shared_execution(path: Path, binding: Mapping[str, object]) -> dict[str, object] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict)
            or set(value) != {"schemaVersion", "binding", "source", "target",
                              "evidenceIdentity"}
            or value.get("schemaVersion") != "riscv2x86.l2-shared-program-execution.v1"
            or not isinstance(value.get("binding"), dict)):
        raise ValueError("shared program execution schema is invalid")
    for side in ("source", "target"):
        run = value.get(side)
        if (not isinstance(run, dict)
                or set(run) != {"returnCode", "stdout", "stderr"}
                or isinstance(run.get("returnCode"), bool)
                or not isinstance(run.get("returnCode"), int)
                or not isinstance(run.get("stdout"), str)
                or not isinstance(run.get("stderr"), str)):
            raise ValueError(f"shared program execution {side} result is invalid")
    claimed = value.get("evidenceIdentity")
    payload = {key: item for key, item in value.items() if key != "evidenceIdentity"}
    if claimed != _identity(payload):
        raise ValueError("shared program execution identity does not match content")
    if value.get("binding") != dict(binding):
        return None
    return value


def _save_shared_execution(path: Path, binding: Mapping[str, object], *,
                           source: subprocess.CompletedProcess[str],
                           target: subprocess.CompletedProcess[str]) -> None:
    payload = {
        "schemaVersion": "riscv2x86.l2-shared-program-execution.v1",
        "binding": dict(binding),
        "source": {"returnCode": source.returncode, "stdout": source.stdout,
                   "stderr": source.stderr},
        "target": {"returnCode": target.returncode, "stdout": target.stdout,
                   "stderr": target.stderr},
    }
    payload["evidenceIdentity"] = _identity(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")
        temporary = Path(stream.name)
    temporary.replace(path)


def build_auto_l2_operand_validator(config: Mapping[str, object]):
    expected = {"schemaVersion", "sourcePath", "sourceDigest", "targetPath", "targetDigest",
                "translatedReport", "functions", "workDirectory", "replayDirectory",
                "timeoutSeconds", "seed", "qemuBinary"}
    if set(config) != expected or config.get("schemaVersion") != AUTO_L2_OPERAND_SCHEMA:
        raise ValueError("automatic L2 operand config fields/schema are invalid")
    functions = config.get("functions")
    if not isinstance(functions, list):
        raise ValueError("automatic L2 operand functions must be an array")
    timeout, seed = config.get("timeoutSeconds"), config.get("seed")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0 or isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("automatic L2 operand execution parameters are invalid")

    def validate(**kwargs: object) -> ValidationLayerResult:
        if kwargs.get("level") is not ValidationLevel.L2:
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="automatic L2-A invoked for wrong level")
        if kwargs.get("comparison_policy") != ARCHITECTURAL_COMPARISON_POLICY:
            return ValidationLayerResult(
                ValidationLevel.L2,
                ValidationStatus.FAILED,
                detail=json.dumps(
                    {
                        "reasonCode": "L2_OPERAND_COMPARISON_POLICY_INVALID",
                        "expected": ARCHITECTURAL_COMPARISON_POLICY,
                        "actual": kwargs.get("comparison_policy"),
                    },
                    sort_keys=True,
                ),
            )
        artifact = kwargs.get("translation_artifact")
        if getattr(artifact, "preservation_mode", None) is not PreservationMode.ARCHITECTURE_EQUIVALENT:
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                         detail=json.dumps(provider_precondition_detail("L2_OPERAND_FUNCTIONAL_FALLBACK_NOT_ARCHITECTURAL")))
        stage = L2OperandFailureStage.INPUT_ARTIFACT
        artifact_path = Path(str(config["sourcePath"]))
        executed = False
        try:
            source, target = Path(str(config["sourcePath"])), Path(str(config["targetPath"]))
            if _digest_bytes(source.read_bytes()) != config["sourceDigest"] or _digest_bytes(target.read_bytes()) != config["targetDigest"]:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="automatic L2-A source/target digest mismatch")
            stage = L2OperandFailureStage.REPORT_LOAD
            artifact_path = Path(str(config["translatedReport"]))
            report = json.loads(artifact_path.read_text(encoding="utf-8"))
            finding = _finding(report, str(getattr(artifact, "fragment_id", ""))) if isinstance(report, Mapping) else None
            if finding is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail=json.dumps(provider_precondition_detail("L2_OPERAND_FINDING_MISSING")))
            stage = L2OperandFailureStage.AUTHORITY_JOIN
            authority, reason = _authority(finding, functions, artifact)
            if authority is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail=json.dumps(provider_precondition_detail(reason)))
            function_name = authority["function"]
            function = next(item for item in functions if isinstance(item, Mapping) and item.get("name") == function_name)
            stage = L2OperandFailureStage.WRAPPER_MATERIALIZATION
            wrapper = _wrapper(function)
            work, replay = Path(str(config["workDirectory"])), Path(str(config["replayDirectory"]))
            artifact_path = work / "operand-harness.c"
            work.mkdir(parents=True, exist_ok=True); replay.mkdir(parents=True, exist_ok=True)
            harness = work / "operand-harness.c"; harness.write_text(wrapper, encoding="utf-8")
            (replay / "operand-harness.c").write_text(wrapper, encoding="utf-8")
            (replay / "operand-authority.json").write_text(json.dumps(authority, indent=2, sort_keys=True)+"\n", encoding="utf-8")
            plan = authority.get("instrumentationPlan")
            build_source, build_target = source, target
            if isinstance(plan, Mapping):
                stage = L2OperandFailureStage.INSTRUMENTATION
                artifact_path = replay / "instrumentation-plan.json"
                build_source, build_target = _instrumented_pair(
                    source, target, report, finding, plan, work,
                )
                (replay / "instrumentation-plan.json").write_text(
                    json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                (replay / "source-instrumented.c").write_bytes(build_source.read_bytes())
                (replay / "target-instrumented.c").write_bytes(build_target.read_bytes())
            stage = L2OperandFailureStage.RUNTIME_CONTRACT
            artifact_path = replay / "operand-authority.json"
            dependencies = resolve_runtime_contracts((getattr(artifact, "runtime_contract_id"),))
            provider_id = str(kwargs.get("l2_provider_id", ""))
            if not provider_id:
                stage = L2OperandFailureStage.EVIDENCE_CLOSURE
                raise ValueError("resolved L2 operand provider identity is empty")
            authorized_execution = str(authority.get("programExecutionIdentity", ""))
            shared_binding = {
                "providerId": provider_id,
                "authorizedExecutionIdentity": authorized_execution,
                "sourceDigest": config["sourceDigest"], "targetDigest": config["targetDigest"],
                "harnessDigest": _digest_bytes(wrapper.encode()),
                "instrumentationPlanIdentity": (
                    plan.get("planIdentity", "") if isinstance(plan, Mapping) else ""),
            }
            shared_path = work.parent / ".program-executions" / (
                _identity(shared_binding).removeprefix("sha256:") + ".json")
            stage = L2OperandFailureStage.SHARED_EXECUTION_LOAD
            artifact_path = shared_path
            shared = (_load_shared_execution(shared_path, shared_binding)
                      if authorized_execution and not isinstance(plan, Mapping) else None)
            if shared is None:
                source_exe, target_exe = work / "source.rv64", work / "target.x86_64"
                stage = L2OperandFailureStage.HARNESS_BUILD
                artifact_path = harness
                left_build = _run(("riscv64-linux-gnu-gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror","-march=rv64gc","-mabi=lp64d","-static",str(harness),str(build_source),"-o",str(source_exe)),work,timeout)
                right_build = _run(("gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror",*("-I"+item for item in dependencies.include_directories),str(harness),str(build_target),*dependencies.library_paths,"-o",str(target_exe)),work,timeout)
                if left_build.returncode or right_build.returncode:
                    detail={"schemaVersion":AUTO_L2_FAILURE_SCHEMA,"executionDisposition":L2ProviderExecutionDisposition.NOT_EXECUTED.value,"evidenceProductionDisposition":L2EvidenceProductionDisposition.NOT_PRODUCED.value,"reasonCode":"L2_OPERAND_HARNESS_BUILD_UNAVAILABLE","failureStage":stage.value,"exceptionType":"CompilerExit","detail":"source or target harness compilation failed","artifactPath":str(harness),"source":left_build.stderr,"target":right_build.stderr}
                    return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,_identity(detail),json.dumps(detail,sort_keys=True))
                stage = L2OperandFailureStage.EXECUTION
                artifact_path = source_exe
                left=_run((str(config["qemuBinary"]),str(source_exe)),work,timeout)
                right=_run((str(target_exe),),work,timeout)
                executed = True
                if authorized_execution and not isinstance(plan, Mapping):
                    _save_shared_execution(shared_path, shared_binding, source=left, target=right)
                shared_reused = False
            else:
                source_run, target_run = shared.get("source"), shared.get("target")
                if not isinstance(source_run, Mapping) or not isinstance(target_run, Mapping):
                    raise ValueError("shared program execution record is malformed")
                left = subprocess.CompletedProcess(
                    (), int(source_run["returnCode"]), str(source_run["stdout"]),
                    str(source_run["stderr"]))
                right = subprocess.CompletedProcess(
                    (), int(target_run["returnCode"]), str(target_run["stdout"]),
                    str(target_run["stderr"]))
                shared_reused = True
                executed = True
            stage = L2OperandFailureStage.TRACE_PARSE
            artifact_path = replay / "operand-observation.json"
            arity=int(function["arity"]); source_rows=_traces(left.stdout,str(function_name),arity); target_rows=_traces(right.stdout,str(function_name),arity)
            point_count = len(plan.get("points", [])) if isinstance(plan, Mapping) else 0
            source_internal = _internal_traces(left.stdout, point_count) if point_count else ()
            target_internal = _internal_traces(right.stdout, point_count) if point_count else ()
            stage = L2OperandFailureStage.OBSERVATION_MATERIALIZATION
            observation={"schemaVersion":AUTO_L2_OBSERVATION_SCHEMA,"fragmentId":getattr(artifact,"fragment_id"),"attemptId":Path(str(config["workDirectory"])).name,"seed":seed,"inputDomain":"boundary-cartesian-u64-v1","harnessDigest":_digest_bytes(wrapper.encode()),"authorityIdentity":authority["authorityIdentity"],"sourceTraceDigest":_identity({"boundary":source_rows,"internal":source_internal}),"targetTraceDigest":_identity({"boundary":target_rows,"internal":target_internal}),"sampleCount":0 if source_rows is None else len(source_rows),"sourceExitCode":left.returncode,"targetExitCode":right.returncode,"sourceStderr":left.stderr,"targetStderr":right.stderr,"operandAuthority":authority["operands"],"instrumentationPlanIdentity":plan.get("planIdentity", "") if isinstance(plan, Mapping) else "","sourceInternalValues":source_internal,"targetInternalValues":target_internal,"sourceSamples":_sample_observations(source_rows,authority,source_internal or None,trace_arity=arity),"targetSamples":_sample_observations(target_rows,authority,target_internal or None,trace_arity=arity)}
            if (source_rows is None or target_rows is None
                    or (point_count and (source_internal is None or target_internal is None
                        or len(source_internal) != len(source_rows)
                        or len(target_internal) != len(target_rows)))):
                status=ValidationStatus.INCONCLUSIVE; observation["reasonCode"]="L2_OPERAND_TRACE_INCOMPLETE"
            elif left.returncode or right.returncode or left.stderr or right.stderr:
                status=ValidationStatus.FAILED; observation["reasonCode"]="L2_OPERAND_EXECUTION_FAILED"
            elif source_rows != target_rows or source_internal != target_internal:
                status=ValidationStatus.FAILED; observation["reasonCode"]="L2_OPERAND_VALUE_MISMATCH"
            else:
                status=ValidationStatus.VERIFIED; observation["reasonCode"]=""
            evidence=_identity(observation)
            (replay / "operand-observation.json").write_text(json.dumps(observation,indent=2,sort_keys=True)+"\n",encoding="utf-8")
            stage = L2OperandFailureStage.EVIDENCE_CLOSURE
            closure = provider_evidence_fields(
                artifact, provider_id=provider_id,
                harness_identity=str(observation["harnessDigest"]),
                execution_nonce={"authorizedExecutionIdentity": authorized_execution,
                                 "seed": seed, "inputDomain": observation["inputDomain"],
                                 "sharedExecutionBinding": _identity(shared_binding)},
                dimensions=(L2Dimension.LOGICAL_OPERANDS,),
                dimension_evidence={L2Dimension.LOGICAL_OPERANDS: L2DimensionEvidence(
                    str(observation["sourceTraceDigest"]),
                    str(observation["targetTraceDigest"]),
                    ("operand_binding", "value_bit_pattern", "width", "signedness"),
                )},
                authorized_execution_identity=authorized_execution,
                execution_disposition={
                    ValidationStatus.VERIFIED:
                        L2ProviderExecutionDisposition.EXECUTED_VERIFIED,
                    ValidationStatus.FAILED:
                        L2ProviderExecutionDisposition.EXECUTED_FAILED,
                    ValidationStatus.INCONCLUSIVE:
                        L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE,
                }[status])
            summary={"schemaVersion":"riscv2x86.auto-l2-operand-result.v2","status":status.value,"reasonCode":observation["reasonCode"],"fragmentId":observation["fragmentId"],"attemptId":observation["attemptId"],"sampleCount":observation["sampleCount"],"sharedProgramExecutionReused":shared_reused,**closure,"executionAuthorityIdentity":str(authority.get("programExecutionAuthorityIdentity", "")),"observationEvidenceIdentity":evidence,"replayArtifact":"operand-observation.json"}
            return ValidationLayerResult(ValidationLevel.L2,status,evidence,json.dumps(summary,sort_keys=True))
        except subprocess.TimeoutExpired as exc:
            return _failure_result(
                stage, exc, artifact_path=artifact_path,
                disposition=(L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE
                             if executed else L2ProviderExecutionDisposition.NOT_EXECUTED),
                reason_code="L2_OPERAND_RUNNER_TIMEOUT",
            )
        except (OSError, ValueError, KeyError, TypeError, StopIteration,
                json.JSONDecodeError) as exc:
            return _failure_result(
                stage, exc, artifact_path=artifact_path,
                disposition=(L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE
                             if executed else L2ProviderExecutionDisposition.NOT_EXECUTED),
                reason_code=(exc.reason_code
                             if isinstance(exc, L2OperandObservationError) else ""),
            )
    return validate
