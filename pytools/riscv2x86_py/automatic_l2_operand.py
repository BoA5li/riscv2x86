"""Bounded automatic L2-A validation for scalar GNU inline-asm fragments."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping, Sequence

from .runtime_dependency_binding import resolve_runtime_contracts
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import PreservationMode, ValidationStatus


AUTO_L2_OPERAND_SCHEMA = "riscv2x86.auto-l2-operand-runner.v1"
AUTO_L2_AUTHORITY_SCHEMA = "riscv2x86.auto-logical-operand-authority.v1"
AUTO_L2_OBSERVATION_SCHEMA = "riscv2x86.auto-logical-operand-observation.v1"
ARCHITECTURAL_COMPARISON_POLICY = (
    "riscv2x86.architectural-observation-comparison.v1"
)
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
    boundary = function.get("l2OperandBoundary")
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
    # This first automatic profile observes every input at the function boundary
    # and exactly one output at return.  Internal temporaries are never omitted.
    read_write_ids = [output_ids[index] for index, item in enumerate(outputs)
                      if isinstance(item, Mapping) and str(item.get("constraint") or "").startswith("+")]
    if (len(outputs) != 1 or output_ids[0] != returned
            or sorted(input_ids + read_write_ids) != sorted(params)):
        return None, "L2_OPERAND_INTERNAL_VALUE_REQUIRES_INSTRUMENTATION"
    for declaration_id in set(asm_ids):
        expected_references = asm_ids.count(declaration_id) + int(returned == declaration_id)
        if reference_counts.get(declaration_id) != expected_references:
            return None, "L2_OPERAND_VALUE_ESCAPES_FUNCTION_BOUNDARY_MODEL"
    approval = finding.get("approvalArtifact")
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
    payload = {
        "schemaVersion": AUTO_L2_AUTHORITY_SCHEMA,
        "producer": "clang-ast-plus-frontend-gnu-shell-v1",
        "fragmentId": getattr(artifact, "fragment_id"),
        "function": function_name, "shellFactsIdentity": shell_identity,
        "sourceModelIdentity": getattr(artifact, "source_model_identity", ""),
        "proofIdentity": getattr(artifact, "proof_identity", ""),
        "operands": facts,
    }
    payload["authorityIdentity"] = _identity(payload)
    return payload, ""


def _wrapper(function: Mapping[str, object]) -> str:
    name, ret = str(function["name"]), str(function["returnType"])
    types = function["parameterTypes"]
    if not _IDENT.fullmatch(name) or not isinstance(types, list) or not types or len(types) > 3:
        raise ValueError("automatic L2 scalar function shape is unsupported")
    declarations = ", ".join(str(item) for item in types)
    args = ",".join(f"({types[i]})v[i{i}]" for i in range(len(types)))
    loops = "".join(f"for(unsigned i{i}=0;i{i}<8;++i{i}){{" for i in range(len(types)))
    print_args = "".join(f'printf(";%016llx",(unsigned long long)v[i{i}]);' for i in range(len(types)))
    return "\n".join([
        "#include <stdint.h>", "#include <stdio.h>", f"{ret} {name}({declarations});",
        "int main(void){ static const uint64_t v[8]={0,1,UINT64_MAX,UINT64_C(0x7fffffff),UINT64_C(0x80000000),UINT64_C(0xffffffff),UINT64_C(0x5a17d3e4c29b806f),UINT64_C(0xc4ceb9fe1a85ec53)};",
        loops, f"uint64_t out=(uint64_t){name}({args});", f'printf("operand_trace={name}");{print_args}printf(";%016llx\\n",(unsigned long long)out);',
        "}" * len(types), "return 0;}",
    ]) + "\n"


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
                         authority: Mapping[str, object]) -> list[dict[str, object]]:
    if rows is None:
        return []
    facts = authority["operands"]
    assert isinstance(facts, list)
    input_facts = [item for item in facts if item["accessMode"] == "input"]
    output_facts = [item for item in facts if item["accessMode"] in {"output", "read_write"}]
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
            operands.append({"operandId": fact["operandId"], "access": fact["accessMode"],
                             "valueBefore": (f"0x{row[parameter_index]:016x}"
                                             if isinstance(parameter_index, int) else None),
                             "valueAfter": f"0x{row[-1]:016x}",
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
                                         detail=json.dumps({"reasonCode":"L2_OPERAND_FUNCTIONAL_FALLBACK_NOT_ARCHITECTURAL"}))
        try:
            source, target = Path(str(config["sourcePath"])), Path(str(config["targetPath"]))
            if _digest_bytes(source.read_bytes()) != config["sourceDigest"] or _digest_bytes(target.read_bytes()) != config["targetDigest"]:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, detail="automatic L2-A source/target digest mismatch")
            report = json.loads(Path(str(config["translatedReport"])).read_text(encoding="utf-8"))
            finding = _finding(report, str(getattr(artifact, "fragment_id", ""))) if isinstance(report, Mapping) else None
            if finding is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail=json.dumps({"reasonCode":"L2_OPERAND_FINDING_MISSING"}))
            authority, reason = _authority(finding, functions, artifact)
            if authority is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE, detail=json.dumps({"reasonCode":reason}))
            function_name = authority["function"]
            function = next(item for item in functions if isinstance(item, Mapping) and item.get("name") == function_name)
            wrapper = _wrapper(function)
            work, replay = Path(str(config["workDirectory"])), Path(str(config["replayDirectory"]))
            work.mkdir(parents=True, exist_ok=True); replay.mkdir(parents=True, exist_ok=True)
            harness = work / "operand-harness.c"; harness.write_text(wrapper, encoding="utf-8")
            (replay / "operand-harness.c").write_text(wrapper, encoding="utf-8")
            (replay / "operand-authority.json").write_text(json.dumps(authority, indent=2, sort_keys=True)+"\n", encoding="utf-8")
            dependencies = resolve_runtime_contracts((getattr(artifact, "runtime_contract_id"),))
            source_exe, target_exe = work / "source.rv64", work / "target.x86_64"
            left_build = _run(("riscv64-linux-gnu-gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror","-march=rv64gc","-mabi=lp64d","-static",str(harness),str(source),"-o",str(source_exe)),work,timeout)
            right_build = _run(("gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror",*("-I"+item for item in dependencies.include_directories),str(harness),str(target),*dependencies.library_paths,"-o",str(target_exe)),work,timeout)
            if left_build.returncode or right_build.returncode:
                detail={"reasonCode":"L2_OPERAND_HARNESS_BUILD_UNAVAILABLE","source":left_build.stderr,"target":right_build.stderr}
                return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,_identity(detail),json.dumps(detail,sort_keys=True))
            left=_run((str(config["qemuBinary"]),str(source_exe)),work,timeout); right=_run((str(target_exe),),work,timeout)
            arity=int(function["arity"]); source_rows=_traces(left.stdout,str(function_name),arity); target_rows=_traces(right.stdout,str(function_name),arity)
            observation={"schemaVersion":AUTO_L2_OBSERVATION_SCHEMA,"fragmentId":getattr(artifact,"fragment_id"),"attemptId":str(config["workDirectory"]).rsplit("/",1)[-1],"seed":seed,"inputDomain":"boundary-cartesian-u64-v1","harnessDigest":_digest_bytes(wrapper.encode()),"authorityIdentity":authority["authorityIdentity"],"sourceTraceDigest":_identity(source_rows),"targetTraceDigest":_identity(target_rows),"sampleCount":0 if source_rows is None else len(source_rows),"sourceExitCode":left.returncode,"targetExitCode":right.returncode,"sourceStderr":left.stderr,"targetStderr":right.stderr,"operandAuthority":authority["operands"],"sourceSamples":_sample_observations(source_rows,authority),"targetSamples":_sample_observations(target_rows,authority)}
            if source_rows is None or target_rows is None:
                status=ValidationStatus.INCONCLUSIVE; observation["reasonCode"]="L2_OPERAND_TRACE_INCOMPLETE"
            elif left.returncode or right.returncode or left.stderr or right.stderr:
                status=ValidationStatus.FAILED; observation["reasonCode"]="L2_OPERAND_EXECUTION_FAILED"
            elif source_rows != target_rows:
                status=ValidationStatus.FAILED; observation["reasonCode"]="L2_OPERAND_VALUE_MISMATCH"
            else:
                status=ValidationStatus.VERIFIED; observation["reasonCode"]=""
            evidence=_identity(observation)
            (replay / "operand-observation.json").write_text(json.dumps(observation,indent=2,sort_keys=True)+"\n",encoding="utf-8")
            summary={"schemaVersion":"riscv2x86.auto-l2-operand-result.v1","status":status.value,"reasonCode":observation["reasonCode"],"fragmentId":observation["fragmentId"],"attemptId":observation["attemptId"],"sampleCount":observation["sampleCount"],"authorityIdentity":authority["authorityIdentity"],"observationEvidenceIdentity":evidence,"replayArtifact":"operand-observation.json"}
            return ValidationLayerResult(ValidationLevel.L2,status,evidence,json.dumps(summary,sort_keys=True))
        except subprocess.TimeoutExpired as exc:
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,detail=json.dumps({"reasonCode":"L2_OPERAND_RUNNER_TIMEOUT","detail":str(exc)}))
        except (OSError,ValueError,KeyError,json.JSONDecodeError) as exc:
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,detail=json.dumps({"reasonCode":"L2_OPERAND_INFRASTRUCTURE_UNAVAILABLE","detail":f"{type(exc).__name__}: {exc}"}))
    return validate
