"""Bounded automatic L2-A validation for scalar GNU inline-asm fragments."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping, Sequence

from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .runtime_dependency_binding import resolve_runtime_contracts
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import PreservationMode, ValidationStatus
from .l2_authority import l2_authority_sidecar_from_dict
from .l2_internal_value import instrumentation_plan_from_dict
from .l2_fragment_execution import (
    boundary_as_legacy, fragment_boundary_from_dict,
    program_execution_authority_from_dict,
)
from .l2_evidence_closure import (
    L2ProviderExecutionDisposition, provider_evidence_fields,
    provider_precondition_detail,
)
from .l2_scalar_authority import (
    assess_scalar_authority_materializability,
    scalar_authority_decision_matches_assessment,
    scalar_authority_decision_from_dict,
)


AUTO_L2_OPERAND_SCHEMA = "riscv2x86.auto-l2-operand-runner.v1"
AUTO_L2_AUTHORITY_SCHEMA = "riscv2x86.auto-logical-operand-authority.v1"
AUTO_L2_OBSERVATION_SCHEMA = "riscv2x86.auto-logical-operand-observation.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENT = re.compile(r"^[A-Za-z_]\w*$")
_VALUES = (0, 1, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
           0x5A17D3E4C29B806F, 0xC4CEB9FE1A85EC53)


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
    facts = []
    combined = [(item, output_ids[index], "output") for index, item in enumerate(outputs)]
    combined += [(item, input_ids[index], "input") for index, item in enumerate(inputs)]
    for index, (raw, declaration_id, role) in enumerate(combined):
        if not isinstance(raw, Mapping) or declaration_id not in declarations:
            return None, "L2_OPERAND_AUTHORITY_FACT_MISSING"
        decl = declarations[declaration_id]
        if not isinstance(decl, Mapping):
            return None, "L2_OPERAND_DECLARATION_FACT_MISSING"
        constraint = str(raw.get("constraint") or "")
        width, signedness = _width(str(decl.get("type") or "")), _signedness(str(decl.get("type") or ""))
        if width <= 0 or signedness == "not_applicable":
            return None, "L2_OPERAND_HOST_TYPE_UNSUPPORTED"
        access = "read_write" if role == "output" and constraint.startswith("+") else role
        tied = None
        if role == "input" and constraint.isdigit():
            tied = int(constraint)
        facts.append({
            "operandIndex": index, "operandName": str(raw.get("symbolicName") or decl.get("name") or f"operand{index}"),
            "operandId": f"{getattr(artifact, 'fragment_id')}:{index}:{declaration_id}",
            "declarationId": declaration_id, "accessMode": access, "widthBits": width,
            "parameterIndex": params.index(declaration_id) if declaration_id in params else None,
            "signedness": signedness, "tiedToOperandIndex": tied,
            "earlyClobber": bool(raw.get("isEarlyClobber")) or "&" in constraint,
            "sourceConstraint": constraint, "targetContractCarriedByProof": True,
            "escaped": False,
        })
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
        if not isinstance(raw_execution, Mapping):
            return None, "L2_PROGRAM_EXECUTION_AUTHORITY_MISSING"
        try:
            execution = program_execution_authority_from_dict(
                raw_execution, expected_fragment_id=str(getattr(artifact, "fragment_id", "")))
        except ValueError:
            return None, "L2_PROGRAM_EXECUTION_AUTHORITY_INVALID"
        if not execution.complete:
            return None, "L2_PROGRAM_EXECUTION_AUTHORITY_INCOMPLETE"
        payload.update({
            "fragmentBoundaryIdentity": parsed_boundary.boundary_identity,
            "programExecutionAuthorityIdentity": execution.authority_identity,
            "programExecutionIdentity": execution.execution_identity,
            "executionMode": execution.execution_mode,
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
    name, ret = str(function["name"]), str(function["returnType"])
    types = function["parameterTypes"]
    if not _IDENT.fullmatch(name) or not isinstance(types, list) or not types or len(types) > 4:
        raise ValueError("automatic L2 scalar function shape is unsupported")
    declarations = ", ".join(str(item) for item in types)
    args = ",".join(f"({types[i]})v[i{i}]" for i in range(len(types)))
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
                         ) -> list[dict[str, object]]:
    if rows is None:
        return []
    facts = authority["operands"]
    assert isinstance(facts, list)
    input_facts = [item for item in facts if item["accessMode"] == "input"]
    output_facts = [item for item in facts if item["accessMode"] in {"output", "read_write"}]
    plan = authority.get("instrumentationPlan")
    point_positions = {}
    if isinstance(plan, Mapping) and isinstance(plan.get("points"), list):
        point_positions = {item.get("operandIndex"): index
                           for index, item in enumerate(plan["points"])
                           if isinstance(item, Mapping)}
    result = []
    for sample_index, row in enumerate(rows):
        operands = []
        for fact in input_facts:
            parameter_index = fact["parameterIndex"]
            assert isinstance(parameter_index, int)
            operands.append({"operandId": fact["operandId"], "access": "input",
                             "valueBefore": f"0x{row[parameter_index]:016x}", "valueAfter": None,
                             "widthBits": fact["widthBits"], "signedness": fact["signedness"]})
        for fact in output_facts:
            parameter_index = fact["parameterIndex"]
            internal_position = point_positions.get(fact["operandIndex"])
            after = (internal_rows[sample_index][internal_position]
                     if internal_rows is not None and isinstance(internal_position, int)
                     and sample_index < len(internal_rows) else row[-1])
            operands.append({"operandId": fact["operandId"], "access": fact["accessMode"],
                             "valueBefore": (f"0x{row[parameter_index]:016x}"
                                             if isinstance(parameter_index, int) else None),
                             "valueAfter": f"0x{after:016x}",
                             "widthBits": fact["widthBits"], "signedness": fact["signedness"]})
        result.append({"sampleIndex": sample_index, "logicalOperands": operands})
    return result


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
        try:
            source, target = Path(str(config["sourcePath"])), Path(str(config["targetPath"]))
            if _digest_bytes(source.read_bytes()) != config["sourceDigest"] or _digest_bytes(target.read_bytes()) != config["targetDigest"]:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="automatic L2-A source/target digest mismatch")
            report = json.loads(Path(str(config["translatedReport"])).read_text(encoding="utf-8"))
            finding = _finding(report, str(getattr(artifact, "fragment_id", ""))) if isinstance(report, Mapping) else None
            if finding is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail=json.dumps(provider_precondition_detail("L2_OPERAND_FINDING_MISSING")))
            authority, reason = _authority(finding, functions, artifact)
            if authority is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail=json.dumps(provider_precondition_detail(reason)))
            function_name = authority["function"]
            function = next(item for item in functions if isinstance(item, Mapping) and item.get("name") == function_name)
            wrapper = _wrapper(function)
            work, replay = Path(str(config["workDirectory"])), Path(str(config["replayDirectory"]))
            work.mkdir(parents=True, exist_ok=True); replay.mkdir(parents=True, exist_ok=True)
            harness = work / "operand-harness.c"; harness.write_text(wrapper, encoding="utf-8")
            (replay / "operand-harness.c").write_text(wrapper, encoding="utf-8")
            (replay / "operand-authority.json").write_text(json.dumps(authority, indent=2, sort_keys=True)+"\n", encoding="utf-8")
            plan = authority.get("instrumentationPlan")
            build_source, build_target = source, target
            if isinstance(plan, Mapping):
                build_source, build_target = _instrumented_pair(
                    source, target, report, finding, plan, work,
                )
                (replay / "instrumentation-plan.json").write_text(
                    json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                (replay / "source-instrumented.c").write_bytes(build_source.read_bytes())
                (replay / "target-instrumented.c").write_bytes(build_target.read_bytes())
            dependencies = resolve_runtime_contracts((getattr(artifact, "runtime_contract_id"),))
            source_exe, target_exe = work / "source.rv64", work / "target.x86_64"
            left_build = _run(("riscv64-linux-gnu-gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror","-march=rv64gc","-mabi=lp64d","-static",str(harness),str(build_source),"-o",str(source_exe)),work,timeout)
            right_build = _run(("gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror",*("-I"+item for item in dependencies.include_directories),str(harness),str(build_target),*dependencies.library_paths,"-o",str(target_exe)),work,timeout)
            if left_build.returncode or right_build.returncode:
                detail={"executionDisposition":L2ProviderExecutionDisposition.NOT_EXECUTED.value,"reasonCode":"L2_OPERAND_HARNESS_BUILD_UNAVAILABLE","source":left_build.stderr,"target":right_build.stderr}
                return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,_identity(detail),json.dumps(detail,sort_keys=True))
            left=_run((str(config["qemuBinary"]),str(source_exe)),work,timeout); right=_run((str(target_exe),),work,timeout)
            arity=int(function["arity"]); source_rows=_traces(left.stdout,str(function_name),arity); target_rows=_traces(right.stdout,str(function_name),arity)
            point_count = len(plan.get("points", [])) if isinstance(plan, Mapping) else 0
            source_internal = _internal_traces(left.stdout, point_count) if point_count else ()
            target_internal = _internal_traces(right.stdout, point_count) if point_count else ()
            observation={"schemaVersion":AUTO_L2_OBSERVATION_SCHEMA,"fragmentId":getattr(artifact,"fragment_id"),"attemptId":str(config["workDirectory"]).rsplit("/",1)[-1],"seed":seed,"inputDomain":"boundary-cartesian-u64-v1","harnessDigest":_digest_bytes(wrapper.encode()),"authorityIdentity":authority["authorityIdentity"],"sourceTraceDigest":_identity({"boundary":source_rows,"internal":source_internal}),"targetTraceDigest":_identity({"boundary":target_rows,"internal":target_internal}),"sampleCount":0 if source_rows is None else len(source_rows),"sourceExitCode":left.returncode,"targetExitCode":right.returncode,"sourceStderr":left.stderr,"targetStderr":right.stderr,"operandAuthority":authority["operands"],"instrumentationPlanIdentity":plan.get("planIdentity", "") if isinstance(plan, Mapping) else "","sourceInternalValues":source_internal,"targetInternalValues":target_internal,"sourceSamples":_sample_observations(source_rows,authority,source_internal or None),"targetSamples":_sample_observations(target_rows,authority,target_internal or None)}
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
            authorized_execution = str(authority.get("programExecutionIdentity", ""))
            fragment_id = str(observation["fragmentId"])
            def observation_identity(dimension: str, side: str, fallback: object) -> str:
                if not authorized_execution:
                    return str(fallback)
                return _identity({
                    "schemaVersion": "riscv2x86.l2-fragment-observation-evidence.v1",
                    "authorizedExecutionIdentity": authorized_execution,
                    "fragmentId": fragment_id,
                    "dimension": dimension,
                    "side": side,
                })
            source_observation_identity = observation_identity(
                "logical_operands", "source", observation["sourceTraceDigest"])
            target_observation_identity = observation_identity(
                "logical_operands", "target", observation["targetTraceDigest"])
            closure = provider_evidence_fields(
                artifact, provider_id=str(kwargs.get("l2_provider_id", "")),
                harness_identity=str(observation["harnessDigest"]),
                source_observation_identity=source_observation_identity,
                target_observation_identity=target_observation_identity,
                execution_nonce={"authorizedExecutionIdentity": authorized_execution,
                                 "seed": seed, "inputDomain": observation["inputDomain"]},
                dimensions=("logical_operands", "shell_semantics"),
                execution_disposition={
                    ValidationStatus.VERIFIED:
                        L2ProviderExecutionDisposition.EXECUTED_VERIFIED,
                    ValidationStatus.FAILED:
                        L2ProviderExecutionDisposition.EXECUTED_FAILED,
                    ValidationStatus.INCONCLUSIVE:
                        L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE,
                }[status])
            summary={"schemaVersion":"riscv2x86.auto-l2-operand-result.v2","status":status.value,"reasonCode":observation["reasonCode"],"fragmentId":observation["fragmentId"],"attemptId":observation["attemptId"],"sampleCount":observation["sampleCount"],**closure,"sourceShellObservationIdentity":observation_identity("shell_semantics", "source", observation["sourceTraceDigest"]),"targetShellObservationIdentity":observation_identity("shell_semantics", "target", observation["targetTraceDigest"]),"executionAuthorityIdentity":str(authority.get("programExecutionAuthorityIdentity", "")),"observationEvidenceIdentity":evidence,"replayArtifact":"operand-observation.json"}
            return ValidationLayerResult(ValidationLevel.L2,status,evidence,json.dumps(summary,sort_keys=True))
        except subprocess.TimeoutExpired as exc:
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,detail=json.dumps({"executionDisposition":L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE.value,"reasonCode":"L2_OPERAND_RUNNER_TIMEOUT","detail":str(exc)}))
        except (OSError,ValueError,KeyError,json.JSONDecodeError) as exc:
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,detail=json.dumps({"executionDisposition":L2ProviderExecutionDisposition.NOT_EXECUTED.value,"reasonCode":"L2_OPERAND_INFRASTRUCTURE_UNAVAILABLE","detail":f"{type(exc).__name__}: {exc}"}))
    return validate
