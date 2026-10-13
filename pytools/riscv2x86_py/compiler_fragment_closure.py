"""Authoritative closure of compiler AST and GNU inline-asm fragment facts.

Clang JSON AST versions do not consistently export the output/input partition
of ``GCCAsmStmt.inner``.  The C++ frontend does export that partition and the
GNU constraints.  This module performs the content-bound join once so typed
consumers never guess operand roles from assembly text or variable names.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Mapping


CLOSED_COMPILER_FRAGMENT_SCHEMA = "riscv2x86.closed-compiler-fragment.v1"


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _operand_access(operand: Mapping[str, object], *, output: bool) -> str:
    constraint = operand.get("constraint")
    if not isinstance(constraint, str) or not constraint:
        raise ValueError("frontend operand constraint is missing")
    return "read_write" if output and constraint.startswith("+") else (
        "output" if output else "input")


def close_compiler_fragment_candidate(
    candidate: Mapping[str, object], fragment: Mapping[str, object], *,
    source_digest: str, function_identity: str,
) -> dict[str, object]:
    """Join compiler carriers to frontend-owned operand roles, fail closed.

    The ordered carrier list is compiler authority.  The output/input split
    and constraints are frontend authority.  Both identities are included in
    the closure identity, and disagreement is rejected instead of repaired.
    """
    key = candidate.get("fragmentBindingKey")
    carriers = candidate.get("operandCarriers")
    nodes = candidate.get("valueNodes")
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if not isinstance(key, Mapping):
        raise ValueError("compiler fragment binding key is missing")
    if (key.get("sourceDigest") != source_digest
            or key.get("functionIdentity") != function_identity):
        raise ValueError("compiler fragment authority identity mismatch")
    if candidate.get("compilerStructureComplete") is not True:
        raise ValueError("compiler fragment structure is incomplete")
    if not isinstance(carriers, list) or not isinstance(nodes, list):
        raise ValueError("compiler fragment carriers/value nodes are missing")
    if not isinstance(outputs, list) or not isinstance(inputs, list):
        raise ValueError("frontend fragment operand partition is missing")
    frontend_operands = outputs + inputs
    if len(carriers) != len(frontend_operands):
        raise ValueError("compiler/frontend operand arity mismatch")

    node_ids = {item.get("nodeIdentity") for item in nodes
                if isinstance(item, Mapping)}
    bindings: list[dict[str, object]] = []
    for index, (carrier, operand) in enumerate(zip(carriers, frontend_operands)):
        if not isinstance(carrier, Mapping) or not isinstance(operand, Mapping):
            raise ValueError("compiler/frontend operand record is malformed")
        if carrier.get("operandIndex") != index or carrier.get("complete") is not True:
            raise ValueError("compiler operand carrier ordering is incomplete")
        declaration = carrier.get("declarationIdentity")
        value_node = carrier.get("valueNodeIdentity")
        width = carrier.get("widthBits")
        signedness = carrier.get("signedness")
        if (not isinstance(declaration, str) or not declaration
                or value_node not in node_ids
                or isinstance(width, bool) or not isinstance(width, int) or width <= 0
                or signedness not in {"signed", "unsigned"}):
            raise ValueError("compiler operand carrier is incomplete")
        bindings.append({
            "operandIndex": index,
            "declarationIdentity": declaration,
            "valueNodeIdentity": value_node,
            "access": _operand_access(operand, output=index < len(outputs)),
            "widthBits": width,
            "signedness": signedness,
            "complete": True,
        })

    uses = candidate.get("downstreamUses")
    if candidate.get("downstreamUseEnumerationComplete") is not True \
            or not isinstance(uses, list):
        raise ValueError("compiler downstream-use enumeration is incomplete")
    uses = [dict(item) for item in uses if isinstance(item, Mapping)]
    used = {item.get("valueNodeIdentity") for item in uses}
    for binding in bindings[:len(outputs)]:
        node = binding["valueNodeIdentity"]
        if node in used:
            continue
        use = {
            "valueNodeIdentity": node,
            "useNodeIdentity": _identity({
                "schemaVersion": "riscv2x86.compiler-dead-output.v1",
                "candidateIdentity": candidate.get("candidateIdentity"),
                "declarationIdentity": binding["declarationIdentity"],
                "valueNodeIdentity": node,
            }),
            "useKind": "discarded",
            "consumerFragmentIdentity": "",
            "observationSinkIdentity": "",
            "relationKind": "discarded",
            "complete": True,
        }
        uses.append(use)

    result = dict(candidate)
    result.update({
        "schemaVersion": CLOSED_COMPILER_FRAGMENT_SCHEMA,
        "sourceCandidateSchemaVersion": candidate.get("schemaVersion"),
        "operandBindings": bindings,
        "operandClassificationComplete": True,
        "downstreamUses": uses,
        "complete": True,
        "reasonCodes": [],
        "classificationReasonCodes": [],
        "closureProvenance": {
            "compilerCandidateIdentity": candidate.get("candidateIdentity"),
            "frontendFragmentIdentity": (
                fragment.get("fragmentId") or fragment.get("id")),
            "producerIdentities": [
                "clang-json-ast.compiler-value-flow.v2",
                "clang-tooling.gnu-inline-asm-fragment.v1",
            ],
        },
    })
    unsigned = dict(result)
    unsigned.pop("closureIdentity", None)
    result["closureIdentity"] = _identity(unsigned)
    return result


def validate_closed_compiler_fragment_candidate(
    candidate: Mapping[str, object],
) -> None:
    """Validate the closed payload before a typed semantic consumer uses it."""
    if candidate.get("schemaVersion") != CLOSED_COMPILER_FRAGMENT_SCHEMA:
        raise ValueError("closed compiler fragment schema is unsupported")
    declared = candidate.get("closureIdentity")
    unsigned = dict(candidate)
    unsigned.pop("closureIdentity", None)
    if not isinstance(declared, str) or declared != _identity(unsigned):
        raise ValueError("closed compiler fragment identity is invalid")
    provenance = candidate.get("closureProvenance")
    if (not isinstance(provenance, Mapping)
            or not provenance.get("compilerCandidateIdentity")
            or not provenance.get("frontendFragmentIdentity")
            or provenance.get("producerIdentities") != [
                "clang-json-ast.compiler-value-flow.v2",
                "clang-tooling.gnu-inline-asm-fragment.v1",
            ]):
        raise ValueError("closed compiler fragment provenance is incomplete")
    if (candidate.get("complete") is not True
            or candidate.get("compilerStructureComplete") is not True
            or candidate.get("operandClassificationComplete") is not True
            or candidate.get("downstreamUseEnumerationComplete") is not True):
        raise ValueError("closed compiler fragment is incomplete")
