"""Compiler/proof-produced L2 authority for bounded automatic scalar runs.

This materializer runs before candidate staging.  Validators only consume the
result and therefore never infer operand bindings or effect relations.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from .effect_relation import ApprovedEffectRelation
from .l2_authority import (
    L2AuthorityProducer,
    L2AuthoritySidecar,
    L2OperandAuthority,
    L2OrderingAuthority,
    L2SourceEffectAuthority,
    L2InternalValueAuthority,
)
from .l2_control_flow import (
    bind_control_flow_authority,
    control_flow_proof_facts_from_dict,
)
from .l2_memory_object import (
    bind_memory_object_authority,
    memory_proof_facts_from_dict,
)
from .l2_fence_ordering import (
    approved_fence_relations,
    fence_proof_facts_from_dict,
)
from .l2_internal_value import (
    bind_instrumentation_plan,
    internal_value_proof_facts_from_dict,
)
from .l2_semantic_profile import L2PatternKind, l2_fragment_semantic_profile_from_dict


_INTEGER = re.compile(r"^(?:const |volatile )*(u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)$")
_INTEGER_POINTER = re.compile(r"^(?:const |volatile )*(?:u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)(?: const| volatile)*\s*\*$")


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


def _width(type_name: str) -> int:
    name = " ".join(type_name.replace("const", "").replace("volatile", "").split())
    fixed = re.fullmatch(r"u?int(8|16|32|64)_t", name)
    if fixed:
        return int(fixed.group(1))
    return {"char": 8, "signed char": 8, "unsigned char": 8,
            "short": 16, "signed short": 16, "unsigned short": 16,
            "int": 32, "signed int": 32, "unsigned int": 32,
            "long": 64, "signed long": 64, "unsigned long": 64,
            "long long": 64, "signed long long": 64,
            "unsigned long long": 64}.get(name, 0)


def _signedness(type_name: str) -> str:
    name = " ".join(type_name.replace("const", "").replace("volatile", "").split())
    if not _INTEGER.fullmatch(type_name.strip()):
        return "not_applicable"
    return "unsigned" if name.startswith("u") or name.startswith("unsigned") else "signed"


def _shell_identity(approval: Mapping[str, object], fragment_id: str) -> str:
    existing = approval.get("shellFactsIdentity")
    if isinstance(existing, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", existing):
        return existing
    return _identity({
        "schemaVersion": "riscv2x86.shell-facts-binding.v1",
        "sourceFragmentId": fragment_id,
        "sourceModelId": str(approval.get("sourceModelId", "")),
        "constraintsId": str(approval.get("constraintsId", "")),
    })


def _scalar_authority(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    producer_digest: str,
) -> L2AuthoritySidecar | None:
    fragment = finding.get("fragment")
    approval = finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    if (approval.get("proofStatus") != "approved"
            or approval.get("architectureSemanticsPreserved") is False
            or approval.get("shellSemanticsPreserved") is False):
        return None
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    if not fragment_id or len(matches) != 1:
        return None
    function = matches[0]
    boundary = function.get("l2OperandBoundary")
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if (not isinstance(boundary, Mapping) or boundary.get("complete") is not True
            or not isinstance(outputs, list) or not outputs
            or not isinstance(inputs, list)):
        return None
    declarations = boundary.get("declarations")
    asm_ids = boundary.get("asmOperandDeclarationIds")
    params = boundary.get("parameterDeclarationIds")
    returned = boundary.get("returnDeclarationId")
    counts = boundary.get("declarationReferenceCounts")
    if (not isinstance(declarations, Mapping) or not isinstance(asm_ids, list)
            or not isinstance(params, list) or not isinstance(counts, Mapping)
            or len(asm_ids) != len(outputs) + len(inputs)):
        return None
    output_ids, input_ids = asm_ids[:len(outputs)], asm_ids[len(outputs):]
    read_write_ids = [output_ids[index] for index, item in enumerate(outputs)
                      if isinstance(item, Mapping)
                      and str(item.get("constraint", "")).startswith("+")]
    if returned not in output_ids or sorted(input_ids + read_write_ids) != sorted(params):
        return None
    expected = {item: asm_ids.count(item) + int(item == returned) for item in set(asm_ids)}
    if any(counts.get(item) != count for item, count in expected.items()):
        return None
    operands = []
    for index, (raw, declaration_id, access) in enumerate(
            [(item, output_ids[pos],
              "read_write" if isinstance(item, Mapping)
              and str(item.get("constraint", "")).startswith("+") else "output")
             for pos, item in enumerate(outputs)]
            + [(item, input_ids[pos], "input") for pos, item in enumerate(inputs)]):
        declaration = declarations.get(declaration_id)
        if not isinstance(raw, Mapping) or not isinstance(declaration, Mapping):
            return None
        type_name = str(declaration.get("type", ""))
        width, signedness = _width(type_name), _signedness(type_name)
        if not width or signedness == "not_applicable":
            return None
        constraint = str(raw.get("constraint", ""))
        operands.append(L2OperandAuthority(
            operand_id=f"{fragment_id}:{index}:{declaration_id}",
            operand_index=index,
            logical_name=str(raw.get("symbolicName") or declaration.get("name") or f"operand{index}"),
            access_mode=access,
            type_kind="integer",
            width_bits=width,
            signedness=signedness,
            tied_to_operand_id="",
            early_clobber=bool(raw.get("isEarlyClobber")) or "&" in constraint,
            fixed_register_contract="",
            escape_kind=("function_return" if declaration_id == returned else
                         "function_argument" if declaration_id in params else "non_escaping"),
            declaration_id=str(declaration_id),
            parameter_index=params.index(declaration_id) if declaration_id in params else None,
            source_constraint=constraint,
            target_contract_carried_by_proof=True,
        ))
    arity = function.get("arity")
    if isinstance(arity, bool) or not isinstance(arity, int) or not 1 <= arity <= 4:
        return None
    raw_profile = finding.get("l2SemanticProfile")
    if not isinstance(raw_profile, Mapping):
        return None
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id,
        )
    except ValueError:
        return None
    if profile.pattern_kind not in {
            L2PatternKind.SCALAR, L2PatternKind.BRANCH, L2PatternKind.JUMP,
            L2PatternKind.COMPOSITE}:
        return None
    internal_values = ()
    instrumentation_plan_identity = ""
    if profile.pattern_kind is L2PatternKind.COMPOSITE:
        raw_internal = approval.get("l2InternalValueProofFacts")
        if not isinstance(raw_internal, Mapping):
            return None
        try:
            internal_facts = internal_value_proof_facts_from_dict(raw_internal)
            if internal_facts.fragment_id != fragment_id:
                return None
            rewrite_end = finding.get("rewriteEndOffset")
            instrumentation = bind_instrumentation_plan(
                internal_facts, boundary,
                insertion_offset=(rewrite_end if isinstance(rewrite_end, int)
                                  and not isinstance(rewrite_end, bool)
                                  and rewrite_end > 0 else None),
            )
        except (KeyError, ValueError):
            return None
        internal_values = tuple(sorted((L2InternalValueAuthority(
            point.logical_value_id, point.type_contract.type_kind,
            point.type_contract.width_bits, point.type_contract.signedness,
            "operand" if output_ids[point.operand_index] == returned else "non_escaping",
            True,
        ) for point in instrumentation.points), key=lambda item: item.value_id))
        if isinstance(approval, dict):
            approval["l2InstrumentationPlan"] = instrumentation.to_dict()
        instrumentation_plan_identity = instrumentation.plan_identity
    control_flow = ()
    proof_facts = None
    if profile.pattern_kind in {L2PatternKind.BRANCH, L2PatternKind.JUMP}:
        raw_control = approval.get("l2ControlFlowProofFacts")
        if not isinstance(raw_control, Mapping):
            return None
        try:
            proof_facts = control_flow_proof_facts_from_dict(raw_control)
            if (proof_facts.fragment_id != fragment_id
                    or proof_facts.pattern_kind != profile.pattern_kind.value):
                return None
            control_flow = (bind_control_flow_authority(proof_facts, operands),)
        except (KeyError, ValueError):
            return None
    relations = []
    source_effects = []
    sample_count = 11 if profile.pattern_kind is L2PatternKind.BRANCH else 8 ** arity
    relation_prefix = ("branch" if profile.pattern_kind is L2PatternKind.BRANCH else
                       "jump" if profile.pattern_kind is L2PatternKind.JUMP else "scalar")
    event_kind = ("Branch" if profile.pattern_kind is L2PatternKind.BRANCH else
                  "ControlTransfer" if profile.pattern_kind is L2PatternKind.JUMP
                  else "continuation")
    requirements = (("branch_condition", "branch_continuation", "branch_outcome", "kind", "value")
                    if profile.pattern_kind is L2PatternKind.BRANCH else
                    ("kind", "target", "value") if profile.pattern_kind is L2PatternKind.JUMP else
                    ("branch_continuation", "kind", "value"))
    for sample in sorted(range(sample_count), key=lambda item: f"relation:{relation_prefix}:{item}"):
        event_id = (f"case:{sample}:branch" if profile.pattern_kind is L2PatternKind.BRANCH
                    else f"sample:{sample}:transfer" if profile.pattern_kind is L2PatternKind.JUMP
                    else f"sample:{sample}:continuation")
        target_id = "target:" + event_id if proof_facts is not None else event_id
        relation = ApprovedEffectRelation(
            f"relation:{relation_prefix}:{sample}", event_id, (target_id,), "exact",
            requirements, (), "", True,
        )
        relations.append(relation)
        source_effects.append(L2SourceEffectAuthority(
            event_id, event_kind,
            "condition:0" if profile.pattern_kind is L2PatternKind.BRANCH else
            "transfer:0" if profile.pattern_kind is L2PatternKind.JUMP else
            (("continuation:return|instrumentation:" + instrumentation_plan_identity)
             if instrumentation_plan_identity else "continuation:return"), True,
        ))
    shell_identity = _shell_identity(approval, fragment_id)
    return L2AuthoritySidecar(
        fragment_id,
        L2AuthorityProducer("frontend-compiler-sidecar", "automatic-fragment-authority",
                            "v4", producer_digest),
        shell_identity, tuple(operands), (), tuple(source_effects), tuple(relations),
        (), (), True, control_flow=control_flow, internal_values=internal_values,
    )


def _memory_authority(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    producer_digest: str,
) -> L2AuthoritySidecar | None:
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    if (approval.get("proofStatus") != "approved"
            or approval.get("architectureSemanticsPreserved") is False
            or approval.get("shellSemanticsPreserved") is False):
        return None
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    raw_profile, raw_facts = finding.get("l2SemanticProfile"), approval.get("l2MemoryProofFacts")
    if (not fragment_id or len(matches) != 1 or not isinstance(raw_profile, Mapping)
            or not isinstance(raw_facts, Mapping)):
        return None
    function = matches[0]
    boundary = function.get("l2OperandBoundary")
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
        facts = memory_proof_facts_from_dict(raw_facts)
    except ValueError:
        return None
    if (profile.pattern_kind not in {L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE}
            or facts.fragment_id != fragment_id or not facts.complete
            or not isinstance(boundary, Mapping) or boundary.get("complete") is not True):
        return None
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    declarations, asm_ids = boundary.get("declarations"), boundary.get("asmOperandDeclarationIds")
    params = boundary.get("parameterDeclarationIds")
    if (not isinstance(outputs, list) or not isinstance(inputs, list)
            or not isinstance(declarations, Mapping) or not isinstance(asm_ids, list)
            or not isinstance(params, list) or len(asm_ids) != len(outputs) + len(inputs)):
        return None
    raw_operands = [(item, "output") for item in outputs] + [(item, "input") for item in inputs]
    operands = []
    for index, ((raw, default_access), declaration_id) in enumerate(zip(raw_operands, asm_ids)):
        declaration = declarations.get(declaration_id)
        if not isinstance(raw, Mapping) or not isinstance(declaration, Mapping):
            return None
        type_name = str(declaration.get("type", ""))
        is_pointer = bool(_INTEGER_POINTER.fullmatch(type_name.strip()))
        width = 64 if is_pointer else _width(type_name)
        signedness = "not_applicable" if is_pointer else _signedness(type_name)
        if not width or (not is_pointer and signedness == "not_applicable"):
            return None
        access = "address" if index == facts.address_operand_index else default_access
        operands.append(L2OperandAuthority(
            f"{fragment_id}:{index}:{declaration_id}", index,
            str(raw.get("symbolicName") or declaration.get("name") or f"operand{index}"),
            access, "pointer" if is_pointer else "integer", width, signedness, "",
            bool(raw.get("isEarlyClobber")) or "&" in str(raw.get("constraint", "")), "",
            "function_argument" if declaration_id in params else
            "function_return" if default_access == "output" else "non_escaping",
            str(declaration_id), params.index(declaration_id) if declaration_id in params else None,
            str(raw.get("constraint", "")), True,
        ))
    try:
        memory_object, object_id = bind_memory_object_authority(facts, operands)
    except ValueError:
        return None
    sample_count = 8 if any(item.parameter_index is not None and
                            item.operand_index != facts.address_operand_index
                            for item in operands) else 1
    relations, effects = [], []
    event_kind = "ReadMemory" if facts.access_kind == "load" else "WriteMemory"
    requirements = ("kind", "memory_coordinates", "memory_order", "subject", "value")
    for sample in range(sample_count):
        source_id = f"sample:{sample}:memory"
        relations.append(ApprovedEffectRelation(
            f"relation:memory:{sample}", source_id, ("target:" + source_id,),
            "exact", requirements, (), "", True))
        effects.append(L2SourceEffectAuthority(source_id, event_kind, object_id, True))
    return L2AuthoritySidecar(
        fragment_id, L2AuthorityProducer("frontend-compiler-sidecar",
          "automatic-memory-authority", "v1", producer_digest),
        _shell_identity(approval, fragment_id), tuple(operands), (memory_object,),
        tuple(effects), tuple(relations), (), (), True,
    )


def _fence_authority(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    producer_digest: str,
) -> L2AuthoritySidecar | None:
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    raw_profile, raw_facts = finding.get("l2SemanticProfile"), approval.get("l2FenceProofFacts")
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    if (approval.get("proofStatus") != "approved" or not fragment_id or len(matches) != 1
            or not isinstance(raw_profile, Mapping) or not isinstance(raw_facts, Mapping)):
        return None
    function = matches[0]
    if function.get("arity") != 0 or function.get("returnType") != "void":
        return None
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
        facts = fence_proof_facts_from_dict(raw_facts)
    except ValueError:
        return None
    if (profile.pattern_kind is not L2PatternKind.FENCE or facts.fragment_id != fragment_id
            or not facts.complete
            or approval.get("rendererContractId") != facts.target_contract_id
            or approval.get("rendererVersion") != facts.target_contract_version):
        return None
    relations = approved_fence_relations(facts)
    effects = tuple(sorted((
        L2SourceEffectAuthority(facts.before_effect_id, "ReadMemory", "ordering:before", True),
        L2SourceEffectAuthority(facts.fence_effect_id, "Fence", "ordering:fence", True),
        L2SourceEffectAuthority(facts.after_effect_id, "WriteMemory", "ordering:after", True),
    ), key=lambda item: item.effect_id))
    ordering = (L2OrderingAuthority(
        "ordering:fence-domain", facts.before_effect_id, facts.after_effect_id, True),)
    return L2AuthoritySidecar(
        fragment_id, L2AuthorityProducer("translation-proof-sidecar",
          "automatic-fence-ordering-authority", "v1", producer_digest),
        _shell_identity(approval, fragment_id), (), (), effects, relations, (), (), True,
        ordering=ordering,
    )


def materialize_automatic_l2_authority(
    report: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    frontend: str | Path,
) -> int:
    """Attach complete bounded authority to approved scalar findings in-place."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("translated report findings are unavailable")
    producer_digest = "sha256:" + sha256(Path(frontend).read_bytes()).hexdigest()
    count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        sidecar = (_fence_authority(finding, functions, producer_digest)
                   or _memory_authority(finding, functions, producer_digest)
                   or _scalar_authority(finding, functions, producer_digest))
        if sidecar is None:
            continue
        approval = finding.get("approvalArtifact")
        assert isinstance(approval, dict)
        proof_payload = {
            key: approval.get(key, "") for key in (
                "sourceModelId", "preservationDecisionId", "planId", "constraintsId",
                "proofStatus", "targetEnvironmentId", "targetCatalogVersion",
            )
        }
        proof_identity = approval.get("proofIdentity")
        if not isinstance(proof_identity, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", proof_identity):
            if not all(proof_payload.values()):
                continue
            approval["proofIdentity"] = _identity(proof_payload)
        approval["shellFactsIdentity"] = sidecar.shell_fact_identity
        approval["l2AuthoritySidecar"] = sidecar.to_dict()
        count += 1
    return count
