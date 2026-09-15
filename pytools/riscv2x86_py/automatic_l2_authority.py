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
from .l2_authority import L2AuthorityProducer, L2AuthoritySidecar


_INTEGER = re.compile(r"^(?:const |volatile )*(u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)$")


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
            or not isinstance(outputs, list) or len(outputs) != 1
            or not isinstance(inputs, list)):
        return None
    declarations = boundary.get("declarations")
    asm_ids = boundary.get("asmOperandDeclarationIds")
    params = boundary.get("parameterDeclarationIds")
    returned = boundary.get("returnDeclarationId")
    counts = boundary.get("declarationReferenceCounts")
    if (not isinstance(declarations, Mapping) or not isinstance(asm_ids, list)
            or not isinstance(params, list) or not isinstance(counts, Mapping)
            or len(asm_ids) != 1 + len(inputs)):
        return None
    output_id, input_ids = asm_ids[0], asm_ids[1:]
    if output_id != returned or sorted(input_ids) != sorted(params):
        return None
    expected = {item: asm_ids.count(item) + int(item == returned) for item in set(asm_ids)}
    if any(counts.get(item) != count for item, count in expected.items()):
        return None
    operands = []
    for index, (raw, declaration_id, access) in enumerate(
            [(outputs[0], output_id, "output")]
            + [(item, input_ids[pos], "input") for pos, item in enumerate(inputs)]):
        declaration = declarations.get(declaration_id)
        if not isinstance(raw, Mapping) or not isinstance(declaration, Mapping):
            return None
        type_name = str(declaration.get("type", ""))
        width, signedness = _width(type_name), _signedness(type_name)
        if not width or signedness == "not_applicable":
            return None
        constraint = str(raw.get("constraint", ""))
        operands.append({
            "operandIndex": index,
            "operandName": str(raw.get("symbolicName") or declaration.get("name") or f"operand{index}"),
            "operandId": f"{fragment_id}:{index}:{declaration_id}",
            "declarationId": declaration_id,
            "accessMode": access,
            "widthBits": width,
            "parameterIndex": params.index(declaration_id) if declaration_id in params else None,
            "signedness": signedness,
            "tiedToOperandIndex": None,
            "earlyClobber": bool(raw.get("isEarlyClobber")) or "&" in constraint,
            "sourceConstraint": constraint,
            "targetContractCarriedByProof": True,
            "escaped": access == "output",
            "escapeKind": "function_return" if access == "output" else "none",
        })
    arity = function.get("arity")
    if isinstance(arity, bool) or not isinstance(arity, int) or not 1 <= arity <= 3:
        return None
    relations = []
    source_effects = []
    # Sidecar relations are canonicalized by relationId, not numeric sample
    # order (e.g. relation:10 sorts before relation:2).
    for sample in sorted(range(8 ** arity), key=lambda item: f"relation:scalar:{item}"):
        event_id = f"sample:{sample}:continuation"
        relation = ApprovedEffectRelation(
            f"relation:scalar:{sample}", event_id, (event_id,), "exact",
            ("branch_continuation", "kind", "value"), (), "", True,
        )
        relations.append(relation.to_dict())
        source_effects.append({"eventId": event_id, "eventKind": "continuation"})
    shell_identity = _shell_identity(approval, fragment_id)
    return L2AuthoritySidecar(
        fragment_id,
        L2AuthorityProducer("frontend-compiler-sidecar", "automatic-scalar-authority",
                            "v1", producer_digest),
        shell_identity, tuple(operands), (), tuple(source_effects), tuple(relations),
        (), (), True,
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
        sidecar = _scalar_authority(finding, functions, producer_digest)
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
