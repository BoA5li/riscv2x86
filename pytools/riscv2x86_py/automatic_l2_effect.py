"""Bounded automatic L2-B memory, control-flow, shell and fence validation."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping, Sequence

from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .automatic_validation import _branch_domain_wrapper, _memory_object_wrapper, _scalar_wrapper
from .automatic_l2_operand import _wrapper as _operand_trace_wrapper
from .runtime_dependency_binding import resolve_runtime_contracts
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import PreservationMode, ValidationStatus
from .effect_relation import approved_effect_relation_from_dict
from .l2_authority import l2_authority_sidecar_from_dict


AUTO_L2_EFFECT_SCHEMA = "riscv2x86.auto-l2-effect-runner.v1"
AUTO_L2_EFFECT_OBSERVATION_SCHEMA = "riscv2x86.auto-l2-effect-observation.v1"
_INITIAL_OBJECT = (0x1122334455667788, 0x8877665544332211,
                   0x0123456789ABCDEF, 0xFEDCBA9876543210)
_BRANCH_CASES = (
    (0, 0, 0x1111111111111111, 0x2222222222222222),
    (1, 1, 0x3333333333333333, 0x4444444444444444),
    (0, 1, 0x5555555555555555, 0xAAAAAAAAAAAAAAAA),
    (1, 0, 0x0123456789ABCDEF, 0xFEDCBA9876543210),
    (0xFFFFFFFFFFFFFFFF, 0, 0x13579BDF2468ACE0, 0x02468ACE13579BDF),
    (0, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000),
    (0x7FFFFFFF, 0x80000000, 3, 5),
    (0x80000000, 0x7FFFFFFF, 7, 11),
    (0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 13, 17),
    (0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 19, 23),
    (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 29, 31),
)


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()
    return "sha256:" + sha256(data).hexdigest()


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _run(argv: Sequence[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                          timeout=timeout, check=False)


def _finding(report: Mapping[str, object], fragment_id: str) -> Mapping[str, object] | None:
    findings = report.get("findings")
    if not isinstance(findings, list):
        return None
    matches = []
    for item in findings:
        fragment = item.get("fragment") if isinstance(item, Mapping) else None
        if isinstance(fragment, Mapping) and (fragment.get("id") or fragment.get("fragmentId")) == fragment_id:
            matches.append(item)
    return matches[0] if len(matches) == 1 else None


def _function_for(finding: Mapping[str, object], functions: list[object]) -> Mapping[str, object] | None:
    fragment = finding.get("fragment")
    name = fragment.get("enclosingFunction") if isinstance(fragment, Mapping) else None
    matches = [item for item in functions if isinstance(item, Mapping) and item.get("name") == name]
    return matches[0] if len(matches) == 1 else None


def _approved_relations(
    finding: Mapping[str, object], artifact: object,
) -> tuple[dict[str, object] | None, str]:
    """Read proof authority; never manufacture a relation from translation text."""
    approval = finding.get("approvalArtifact")
    if not isinstance(approval, Mapping):
        return None, "L2_EFFECT_AUTHORITY_MISSING"
    raw = approval.get("l2AuthoritySidecar")
    if not isinstance(raw, Mapping):
        return None, "L2_EFFECT_APPROVED_RELATION_MISSING"
    try:
        authority = l2_authority_sidecar_from_dict(
            raw, expected_fragment_id=str(getattr(artifact, "fragment_id", "")),
            expected_shell_fact_identity=str(getattr(artifact, "shell_facts_identity", "")),
        )
        if (authority.authority_identity != getattr(artifact, "l2_authority_identity", "")
                or authority.effect_relation_set_identity
                != getattr(artifact, "effect_relation_set_identity", "")):
            return None, "L2_EFFECT_AUTHORITY_IDENTITY_MISMATCH"
        if approval.get("proofIdentity") != getattr(artifact, "proof_identity", ""):
            return None, "L2_EFFECT_PROOF_IDENTITY_MISMATCH"
        relations = tuple(
            approved_effect_relation_from_dict(item)
            for item in authority.approved_effect_relations
        )
    except ValueError:
        return None, "L2_EFFECT_APPROVED_RELATION_INVALID"
    if not authority.complete or not relations:
        return None, "L2_EFFECT_APPROVED_RELATION_MISSING"
    runtime_id = str(getattr(artifact, "runtime_contract_id", ""))
    runtime_version = str(getattr(artifact, "runtime_contract_version", ""))
    contracts = tuple(authority.runtime_contracts)
    for relation in relations:
        if not relation.authority_complete:
            return None, "L2_EFFECT_APPROVED_RELATION_INCOMPLETE"
        if relation.relation_kind == "runtime_mediated":
            matches = [item for item in contracts if item.get("runtimeContractId") == runtime_id
                       and item.get("runtimeContractVersion") == runtime_version]
            if relation.runtime_contract_id != runtime_id or len(matches) != 1:
                return None, "L2_EFFECT_RUNTIME_CONTRACT_MISMATCH"
    return {
        "authorityIdentity": authority.authority_identity,
        "effectRelationSetIdentity": authority.effect_relation_set_identity,
        "relations": [item.to_dict() for item in relations],
    }, ""


# Compatibility name retained for callers; semantics are now strictly authority-driven.
_shell_relation = _approved_relations


def _memory_events(stdout: str, function: Mapping[str, object]) -> list[dict[str, object]] | None:
    name = str(function["name"])
    return_pattern = re.compile(rf"^{re.escape(name)}:return=([0-9a-f]{{16}})$")
    object_pattern = re.compile(rf"^{re.escape(name)}:object=\[([0-9a-f]{{16}}(?:,[0-9a-f]{{16}}){{3}})\]$")
    pending_return: int | None = None
    events = []
    for line in stdout.splitlines():
        match = return_pattern.fullmatch(line)
        if match:
            pending_return = int(match.group(1), 16)
            continue
        match = object_pattern.fullmatch(line)
        if not match:
            continue
        after = tuple(int(item, 16) for item in match.group(1).split(","))
        changed = [index for index, pair in enumerate(zip(_INITIAL_OBJECT, after)) if pair[0] != pair[1]]
        if changed:
            if len(changed) != 1:
                return None
            index = changed[0]
            events.append({"eventId": f"sample:{len(events)}:write", "order": len(events),
                           "eventKind": "write_memory", "objectId": f"arg:{name}:object",
                           "offset": index * 8, "size": 8, "alignment": 8,
                           "atomicity": "none", "memoryOrder": "compiler",
                           "valueBefore": f"0x{_INITIAL_OBJECT[index]:016x}",
                           "valueAfter": f"0x{after[index]:016x}",
                           "orderingPredecessors": []})
        elif pending_return is not None:
            indices = [index for index, value in enumerate(after) if value == pending_return]
            if len(indices) != 1:
                return None
            index = indices[0]
            events.append({"eventId": f"sample:{len(events)}:read", "order": len(events),
                           "eventKind": "read_memory", "objectId": f"arg:{name}:object",
                           "offset": index * 8, "size": 8, "alignment": 8,
                           "atomicity": "none", "memoryOrder": "compiler",
                           "value": f"0x{pending_return:016x}", "orderingPredecessors": []})
        else:
            return None
        pending_return = None
    return events if events else None


def _branch_events(stdout: str, function: Mapping[str, object]) -> list[dict[str, object]] | None:
    name = str(function["name"])
    pattern = re.compile(rf"^{re.escape(name)}:case=([0-9]+):return=([0-9a-f]{{16}})$")
    events = []
    for line in stdout.splitlines():
        match = pattern.fullmatch(line)
        if not match:
            continue
        case, result = int(match.group(1)), int(match.group(2), 16)
        if case >= len(_BRANCH_CASES):
            return None
        values = _BRANCH_CASES[case]
        selected = 2 if result == values[2] else 3 if result == values[3] else -1
        events.append({"eventId": f"case:{case}:branch", "order": case,
                       "eventKind": "branch", "logicalSubject": name,
                       "conditionInputs": [f"0x{values[0]:016x}", f"0x{values[1]:016x}"],
                       "branchTaken": selected == 2, "continuation": f"return-arg:{selected}",
                       "result": f"0x{result:016x}",
                       "orderingPredecessors": []})
    return events if len(events) == len(_BRANCH_CASES) else None


def _scalar_events(stdout: str, function: Mapping[str, object]) -> list[dict[str, object]] | None:
    name, arity = str(function["name"]), int(function["arity"])
    pattern = re.compile(rf"^operand_trace={re.escape(name)};"
                         + ";".join([r"([0-9a-f]{16})"] * (arity + 1)) + r"$")
    events = []
    for line in stdout.splitlines():
        match = pattern.fullmatch(line)
        if not match:
            continue
        values = [int(item, 16) for item in match.groups()]
        result = values[-1]
        continuations = [f"return-arg:{index}" for index, value in enumerate(values[:-1])
                         if value == result]
        events.append({"eventId":f"sample:{len(events)}:continuation","order":len(events),
                       "eventKind":"continuation","logicalSubject":name,
                       "inputs":[f"0x{item:016x}" for item in values[:-1]],
                       "result":f"0x{result:016x}","continuationClasses":continuations,
                       "orderingPredecessors":[]})
    return events if len(events) == 8 ** arity else None


def _fence_events(stdout: str, function: Mapping[str, object], authority: Mapping[str, object],
                  *, side: str) -> list[dict[str, object]] | None:
    name = str(function["name"])
    if stdout.splitlines().count(name + "=completed") != 1:
        return None
    relations = authority.get("relations")
    if not isinstance(relations, list) or len(relations) != 1:
        return None
    relation = approved_effect_relation_from_dict(relations[0])
    event_id = (relation.source_effect_id if side == "source"
                else relation.target_effect_ids[0])
    memory_order = ("compiler" if side == "source"
                    and relation.relation_kind == "strengthened" else "seq_cst")
    return [{"eventId": event_id, "order": 0, "eventKind": "fence",
             "logicalSubject": "compiler-and-memory-order", "memoryOrder": memory_order,
             "relationKind": relation.relation_kind,
             "runtimeContractId": relation.runtime_contract_id,
             "orderingPredecessors": []}]


def _approved_fence_matches(
    source: list[dict[str, object]], target: list[dict[str, object]],
    authority: Mapping[str, object],
) -> bool:
    relations = authority.get("relations")
    if len(source) != 1 or len(target) != 1 or not isinstance(relations, list) or len(relations) != 1:
        return False
    relation = approved_effect_relation_from_dict(relations[0])
    left, right = source[0], target[0]
    if (left.get("eventId") != relation.source_effect_id
            or right.get("eventId") not in relation.target_effect_ids
            or left.get("eventKind") != right.get("eventKind")):
        return False
    if relation.relation_kind == "exact":
        return left.get("memoryOrder") == right.get("memoryOrder")
    if relation.relation_kind == "strengthened":
        allowed = {"compiler": {"hardware", "seq_cst"}, "hardware": {"seq_cst"}}
        source_order, target_order = str(left.get("memoryOrder")), str(right.get("memoryOrder"))
        return source_order == target_order or target_order in allowed.get(source_order, set())
    return False


def _approved_effect_ids_match(
    source: list[dict[str, object]], target: list[dict[str, object]],
    authority: Mapping[str, object],
) -> bool:
    relations = authority.get("relations")
    if not isinstance(relations, list):
        return False
    approved = tuple(approved_effect_relation_from_dict(item) for item in relations)
    return ({str(item.get("eventId")) for item in source}
            == {item.source_effect_id for item in approved}
            and {str(item.get("eventId")) for item in target}
            == {target_id for item in approved for target_id in item.target_effect_ids})


def build_auto_l2_effect_validator(config: Mapping[str, object]):
    expected = {"schemaVersion", "mode", "sourcePath", "sourceDigest", "targetPath",
                "targetDigest", "translatedReport", "functions", "workDirectory",
                "replayDirectory", "timeoutSeconds", "qemuBinary"}
    if set(config) != expected or config.get("schemaVersion") != AUTO_L2_EFFECT_SCHEMA:
        raise ValueError("automatic L2 effect config fields/schema are invalid")
    if config.get("mode") not in {"memory-object-functions", "branch-domain-functions",
                                  "scalar-effect-functions", "fence-functions"}:
        raise ValueError("automatic L2 effect mode is unsupported")
    functions = config.get("functions")
    if not isinstance(functions, list) or not functions:
        raise ValueError("automatic L2 effect functions are missing")
    timeout = config.get("timeoutSeconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("automatic L2 effect timeout is invalid")

    def validate(**kwargs: object) -> ValidationLayerResult:
        if kwargs.get("level") is not ValidationLevel.L2:
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                         detail="automatic L2-B invoked for wrong level")
        if kwargs.get("comparison_policy") != ARCHITECTURAL_COMPARISON_POLICY:
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                         detail="automatic L2-B comparison policy mismatch")
        artifact = kwargs.get("translation_artifact")
        if getattr(artifact, "preservation_mode", None) is not PreservationMode.ARCHITECTURE_EQUIVALENT:
            return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                         detail=json.dumps({"reasonCode":"L2_EFFECT_FUNCTIONAL_FALLBACK_NOT_ARCHITECTURAL"}))
        try:
            source, target = Path(str(config["sourcePath"])), Path(str(config["targetPath"]))
            if _digest(source) != config["sourceDigest"] or _digest(target) != config["targetDigest"]:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                             detail="automatic L2-B source/target digest mismatch")
            report = json.loads(Path(str(config["translatedReport"])).read_text(encoding="utf-8"))
            finding = _finding(report, str(getattr(artifact, "fragment_id", ""))) if isinstance(report, Mapping) else None
            if finding is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                             detail=json.dumps({"reasonCode":"L2_EFFECT_FINDING_MISSING"}))
            function = _function_for(finding, functions)
            if function is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                             detail=json.dumps({"reasonCode":"L2_EFFECT_FUNCTION_BINDING_AMBIGUOUS"}))
            relation_authority, reason = _approved_relations(finding, artifact)
            if relation_authority is None:
                return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                             detail=json.dumps({"reasonCode":reason}))
            mode = str(config["mode"])
            approved = tuple(
                approved_effect_relation_from_dict(item)
                for item in relation_authority["relations"]
            )
            if (mode != "fence-functions"
                    and any(item.relation_kind != "exact" for item in approved)):
                return ValidationLayerResult(
                    ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                    detail=json.dumps({
                        "reasonCode": "L2_EFFECT_EXPLICIT_NORMALIZED_TRACE_REQUIRED",
                    }),
                )
            wrapper = (_memory_object_wrapper([function]) if mode == "memory-object-functions" else
                       _branch_domain_wrapper([function]) if mode == "branch-domain-functions" else
                       _operand_trace_wrapper(function) if mode == "scalar-effect-functions" else
                       _scalar_wrapper([function]))
            work, replay = Path(str(config["workDirectory"])), Path(str(config["replayDirectory"]))
            work.mkdir(parents=True, exist_ok=True); replay.mkdir(parents=True, exist_ok=True)
            harness = work / "effect-harness.c"; harness.write_text(wrapper, encoding="utf-8")
            dependencies = resolve_runtime_contracts((getattr(artifact, "runtime_contract_id"),))
            source_exe, target_exe = work / "source.rv64", work / "target.x86_64"
            left_build = _run(("riscv64-linux-gnu-gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror","-march=rv64gc","-mabi=lp64d","-static",str(harness),str(source),"-o",str(source_exe)),work,timeout)
            right_build = _run(("gcc","-std=gnu11","-O2","-Wall","-Wextra","-Werror",*("-I"+item for item in dependencies.include_directories),str(harness),str(target),*dependencies.library_paths,"-o",str(target_exe)),work,timeout)
            if left_build.returncode or right_build.returncode:
                detail={"reasonCode":"L2_EFFECT_HARNESS_BUILD_UNAVAILABLE","source":left_build.stderr,"target":right_build.stderr}
                return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,_identity(detail),json.dumps(detail,sort_keys=True))
            left=_run((str(config["qemuBinary"]),str(source_exe)),work,timeout)
            right=_run((str(target_exe),),work,timeout)
            parser = (_memory_events if mode == "memory-object-functions" else
                      _branch_events if mode == "branch-domain-functions" else
                      _scalar_events if mode == "scalar-effect-functions" else None)
            source_events = (_fence_events(left.stdout,function,relation_authority,side="source") if parser is None else parser(left.stdout,function))
            target_events = (_fence_events(right.stdout,function,relation_authority,side="target") if parser is None else parser(right.stdout,function))
            observation={"schemaVersion":AUTO_L2_EFFECT_OBSERVATION_SCHEMA,
                         "fragmentId":getattr(artifact,"fragment_id",""),
                         "attemptId":work.name,"mode":mode,"approvedRelationAuthority":relation_authority,
                         "harnessDigest":"sha256:"+sha256(wrapper.encode()).hexdigest(),
                         "source":{"exitCode":left.returncode,"stderr":left.stderr,"events":source_events},
                         "target":{"exitCode":right.returncode,"stderr":right.stderr,"events":target_events}}
            if source_events is None or target_events is None:
                status=ValidationStatus.INCONCLUSIVE; reason="L2_EFFECT_TRACE_INCOMPLETE"
            elif left.returncode or right.returncode or left.stderr or right.stderr:
                status=ValidationStatus.FAILED; reason="L2_EFFECT_EXECUTION_FAILED"
            elif not _approved_effect_ids_match(
                    source_events, target_events, relation_authority):
                status=ValidationStatus.FAILED; reason="L2_EFFECT_APPROVED_TARGET_EFFECT_MISSING"
            elif parser is None and not _approved_fence_matches(
                    source_events, target_events, relation_authority):
                status=ValidationStatus.FAILED; reason="L2_EFFECT_APPROVED_RELATION_NOT_SATISFIED"
            elif parser is not None and source_events != target_events:
                status=ValidationStatus.FAILED; reason="L2_EFFECT_TRACE_MISMATCH"
            else:
                status=ValidationStatus.VERIFIED; reason=""
            observation["reasonCode"] = reason
            evidence = _identity(observation)
            replay.mkdir(parents=True,exist_ok=True)
            (replay/"effect-harness.c").write_text(wrapper,encoding="utf-8")
            (replay/"effect-observation.json").write_text(json.dumps(observation,indent=2,sort_keys=True)+"\n",encoding="utf-8")
            summary={"schemaVersion":"riscv2x86.auto-l2-effect-result.v1","status":status.value,
                     "reasonCode":reason,"fragmentId":observation["fragmentId"],
                     "attemptId":observation["attemptId"],"mode":mode,
                     "eventCount":len(source_events or []),
                     "effectRelationSetIdentity":relation_authority["effectRelationSetIdentity"],
                     "observationEvidenceIdentity":evidence,"replayArtifact":"effect-observation.json"}
            return ValidationLayerResult(ValidationLevel.L2,status,evidence,json.dumps(summary,sort_keys=True))
        except subprocess.TimeoutExpired as exc:
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,
                                         detail=json.dumps({"reasonCode":"L2_EFFECT_RUNNER_TIMEOUT","detail":str(exc)}))
        except (OSError,ValueError,KeyError,json.JSONDecodeError) as exc:
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,
                                         detail=json.dumps({"reasonCode":"L2_EFFECT_INFRASTRUCTURE_UNAVAILABLE","detail":f"{type(exc).__name__}: {exc}"}))
    return validate
