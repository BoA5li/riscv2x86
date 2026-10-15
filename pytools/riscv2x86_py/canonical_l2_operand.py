"""Canonical compiler/proof join for every L2 logical operand.

This module is the only production location allowed to combine GNU operand
syntax with compiler declaration/value-flow authority.  Route-specific code
may refine an already-bound operand role (for example, a memory address), but
must not reconstruct declaration or value-node identities.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .l2_effect_proof import effect_proof_facts_from_dict
from .l2_fragment_execution import fragment_boundary_from_dict


_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
CANONICAL_L2_OPERAND_BINDING_SET_SCHEMA = (
    "riscv2x86.canonical-l2-operand-binding-set.v1"
)
_INTEGER = re.compile(
    r"^(?:const |volatile )*(u?int(?:8|16|32|64)_t|"
    r"unsigned(?: (?:char|short|int|long|long long))?|"
    r"signed(?: (?:char|short|int|long|long long))?|"
    r"char|short|int|long|long long)$")


def _integer_width(type_name: str) -> int:
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


def _type_authority(type_name: str) -> tuple[str, int, str]:
    stripped = type_name.strip()
    if stripped.endswith("*"):
        # The frontend carrier schema represents pointer carriers as unsigned
        # address-width bitvectors.  Preserve that typed fact at the join;
        # route-specific memory semantics still identify the operand as a
        # pointer rather than an integer value.
        return "pointer", 64, "unsigned"
    width = _integer_width(stripped)
    if width and _INTEGER.fullmatch(stripped):
        normalized = " ".join(stripped.replace("const", "")
                               .replace("volatile", "").split())
        signedness = ("unsigned" if normalized.startswith(("u", "unsigned"))
                      else "signed")
        return "integer", width, signedness
    raise ValueError("canonical operand type authority is unsupported")


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CanonicalL2OperandBinding:
    fragment_id: str
    operand_id: str
    operand_index: int
    declaration_identity: str
    value_node_identity: str
    access_mode: str
    type_kind: str
    width_bits: int
    signedness: str
    parameter_index: int | None
    source_constraint: str
    tied_to_operand_id: str
    early_clobber: bool
    escape_kind: str
    complete: bool
    logical_name: str = ""

    def __post_init__(self) -> None:
        if (not self.fragment_id or not self.operand_id
                or isinstance(self.operand_index, bool)
                or not isinstance(self.operand_index, int)
                or self.operand_index < 0 or not self.declaration_identity
                or _SHA.fullmatch(self.value_node_identity) is None
                or self.access_mode not in {"input", "output", "read_write"}
                or self.type_kind not in {"integer", "pointer"}
                or isinstance(self.width_bits, bool) or self.width_bits <= 0
                or self.signedness not in {"signed", "unsigned", "not_applicable"}
                or (self.type_kind == "integer"
                    and self.signedness == "not_applicable")
                or (self.type_kind == "pointer"
                    and self.signedness not in {"unsigned", "not_applicable"})
                or self.complete is not True):
            raise ValueError("canonical L2 operand binding is incomplete")
        if self.parameter_index is not None and (
                isinstance(self.parameter_index, bool)
                or not isinstance(self.parameter_index, int)
                or self.parameter_index < 0):
            raise ValueError("canonical operand parameter index is invalid")
        if self.tied_to_operand_id == self.operand_id:
            raise ValueError("canonical operand cannot be tied to itself")
        if self.escape_kind not in {
                "none", "function_argument", "function_return",
                "memory_object", "external", "non_escaping"}:
            raise ValueError("canonical operand escape kind is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "fragmentId": self.fragment_id, "operandId": self.operand_id,
            "operandIndex": self.operand_index,
            "declarationIdentity": self.declaration_identity,
            "valueNodeIdentity": self.value_node_identity,
            "accessMode": self.access_mode, "typeKind": self.type_kind,
            "widthBits": self.width_bits, "signedness": self.signedness,
            "parameterIndex": self.parameter_index,
            "sourceConstraint": self.source_constraint,
            "tiedToOperandId": self.tied_to_operand_id,
            "earlyClobber": self.early_clobber,
            "escapeKind": self.escape_kind, "complete": self.complete,
            "logicalName": self.logical_name,
        }


def canonical_l2_operand_binding_set(
    bindings: Sequence[CanonicalL2OperandBinding], *, proof_identity: str,
) -> dict[str, object]:
    if (not bindings or _SHA.fullmatch(proof_identity) is None
            or len({item.operand_index for item in bindings}) != len(bindings)
            or len({item.operand_id for item in bindings}) != len(bindings)):
        raise ValueError("canonical operand binding set is incomplete")
    fragment_ids = {item.fragment_id for item in bindings}
    if len(fragment_ids) != 1:
        raise ValueError("canonical operands span multiple fragments")
    value = {
        "schemaVersion": CANONICAL_L2_OPERAND_BINDING_SET_SCHEMA,
        "fragmentId": next(iter(fragment_ids)),
        "proofIdentity": proof_identity,
        "bindings": [item.to_dict() for item in
                     sorted(bindings, key=lambda item: item.operand_index)],
        "complete": True,
    }
    value["bindingSetIdentity"] = _identity(value)
    return value


def canonical_l2_operand_bindings_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
    expected_proof_identity: str = "",
) -> tuple[CanonicalL2OperandBinding, ...]:
    fields = {"schemaVersion", "fragmentId", "proofIdentity", "bindings",
              "complete", "bindingSetIdentity"}
    payload = dict(value)
    claimed = payload.pop("bindingSetIdentity", None)
    if (set(value) != fields
            or value.get("schemaVersion") !=
            CANONICAL_L2_OPERAND_BINDING_SET_SCHEMA
            or value.get("complete") is not True
            or claimed != _identity(payload)):
        raise ValueError("canonical operand binding set identity is invalid")
    fragment_id, proof_identity = value.get("fragmentId"), value.get("proofIdentity")
    if (not isinstance(fragment_id, str) or not fragment_id
            or _SHA.fullmatch(str(proof_identity)) is None
            or expected_fragment_id and fragment_id != expected_fragment_id
            or expected_proof_identity and proof_identity != expected_proof_identity):
        raise ValueError("canonical operand binding set header is invalid")
    raw = value.get("bindings")
    binding_fields = {
        "fragmentId", "operandId", "operandIndex", "declarationIdentity",
        "valueNodeIdentity", "accessMode", "typeKind", "widthBits",
        "signedness", "parameterIndex", "sourceConstraint",
        "tiedToOperandId", "earlyClobber", "escapeKind", "complete",
        "logicalName",
    }
    if not isinstance(raw, list) or not raw:
        raise ValueError("canonical operand bindings are missing")
    result = []
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != binding_fields:
            raise ValueError("canonical operand binding fields are invalid")
        if (not isinstance(item.get("earlyClobber"), bool)
                or not isinstance(item.get("complete"), bool)):
            raise ValueError("canonical operand boolean fields are invalid")
        index, width, parameter = (item.get("operandIndex"),
                                   item.get("widthBits"),
                                   item.get("parameterIndex"))
        if (isinstance(index, bool) or not isinstance(index, int)
                or isinstance(width, bool) or not isinstance(width, int)
                or parameter is not None and (
                    isinstance(parameter, bool) or not isinstance(parameter, int))):
            raise ValueError("canonical operand numeric fields are invalid")
        result.append(CanonicalL2OperandBinding(
            str(item["fragmentId"]), str(item["operandId"]), index,
            str(item["declarationIdentity"]), str(item["valueNodeIdentity"]),
            str(item["accessMode"]), str(item["typeKind"]), width,
            str(item["signedness"]), parameter,
            str(item["sourceConstraint"]), str(item["tiedToOperandId"]),
            item.get("earlyClobber") is True, str(item["escapeKind"]),
            item.get("complete") is True, str(item["logicalName"])))
    indices = tuple(item.operand_index for item in result)
    ids = {item.operand_id for item in result}
    if (indices != tuple(range(len(result))) or len(ids) != len(result)
            or any(item.fragment_id != fragment_id for item in result)
            or any(item.tied_to_operand_id and item.tied_to_operand_id not in ids
                   for item in result)):
        raise ValueError("canonical operand binding set is not closed")
    return tuple(result)


def _fragment_id(fragment: Mapping[str, object]) -> str:
    return str(fragment.get("id") or fragment.get("fragmentId") or "")


def _ordered_gnu_operands(fragment: Mapping[str, object]):
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if not isinstance(outputs, list) or not isinstance(inputs, list):
        raise ValueError("GNU operand arrays are missing")
    ordered = []
    for index, raw in enumerate(outputs + inputs):
        if not isinstance(raw, Mapping):
            raise ValueError("GNU operand is malformed")
        output = index < len(outputs)
        constraint = str(raw.get("constraint") or "")
        access = ("read_write" if output and constraint.startswith("+")
                  else "output" if output else "input")
        ordered.append((index, raw, constraint, access))
    return ordered


def _boundary_bindings(fragment_boundary: Mapping[str, object],
                       _function_boundary: Mapping[str, object],
                       fragment_id: str):
    """Return exact compiler bindings; legacy facts remain explicit input.

    The compatibility form is accepted only when it already contains a value
    node per ordered operand.  It does not synthesize or infer an identity.
    """
    if "boundaryIdentity" in fragment_boundary:
        for group in ("inputBindings", "outputBindings"):
            for raw in fragment_boundary.get(group, ()):
                if isinstance(raw, Mapping) and set(raw) != {
                        "operandIndex", "declarationIdentity", "valueNodeIdentity",
                        "access", "widthBits", "signedness", "complete"}:
                    raise ValueError("canonical compiler carrier schema is unsupported")
        parsed = fragment_boundary_from_dict(
            fragment_boundary, expected_fragment_id=fragment_id)
        if not parsed.complete:
            raise ValueError("canonical compiler boundary is incomplete")
        for edge in parsed.value_flow_edges:
            if edge.consumer_fragment_id and (
                    edge.producer_fragment_id != fragment_id
                    or edge.consumer_fragment_id == fragment_id
                    or edge.relation_kind != "fragment_operand"
                    or not edge.consumer_value_node):
                raise ValueError("canonical fragment dependency edge is invalid")
        return {item.operand_index: item for item in
                parsed.output_bindings + parsed.input_bindings}
    declarations = fragment_boundary.get("asmOperandDeclarationIds")
    nodes = fragment_boundary.get("asmOperandValueNodeIdentities")
    if (fragment_boundary.get("complete") is not True
            or not isinstance(declarations, list) or not isinstance(nodes, list)
            or len(declarations) != len(nodes)):
        raise ValueError("compiler operand boundary is incomplete")
    # A lightweight immutable view with the same attributes as OperandBinding.
    @dataclass(frozen=True)
    class _Binding:
        operand_index: int; declaration_identity: str
        value_node_identity: str; access: str
        width_bits: int; signedness: str
    result = {}
    # Access/type are checked later against the actual fragment and declaration.
    for index, (declaration, node) in enumerate(zip(declarations, nodes)):
        if not isinstance(declaration, str) or not declaration \
                or not isinstance(node, str) or _SHA.fullmatch(node) is None:
            raise ValueError("compiler operand boundary identity is invalid")
        result[index] = _Binding(index, declaration, node, "", 0, "")
    return result


def bind_canonical_l2_operands(
    fragment: Mapping[str, object], fragment_boundary: Mapping[str, object],
    function_boundary: Mapping[str, object], phase6d_proof: Mapping[str, object],
) -> tuple[CanonicalL2OperandBinding, ...]:
    """Join GNU operands to compiler facts exactly once and fail closed."""
    fragment_id = _fragment_id(fragment)
    if not fragment_id:
        raise ValueError("canonical operand fragment identity is missing")
    proof = effect_proof_facts_from_dict(phase6d_proof)
    if proof.fragment_id != fragment_id or proof.complete is not True:
        raise ValueError("canonical operand Phase 6D proof is incomplete")
    declarations = function_boundary.get("declarations")
    parameters = function_boundary.get("parameterDeclarationIds")
    returned = function_boundary.get("returnDeclarationId")
    if not isinstance(declarations, Mapping) or not isinstance(parameters, list):
        raise ValueError("canonical function boundary is incomplete")
    ordered = _ordered_gnu_operands(fragment)
    bindings = _boundary_bindings(fragment_boundary, function_boundary, fragment_id)
    if set(bindings) != set(range(len(ordered))):
        raise ValueError("canonical operand index coverage is incomplete")
    if "boundaryIdentity" not in fragment_boundary:
        # Legacy function-wide boundaries remain admissible only when their
        # declaration accounting proves the same closed function shell.  This
        # is validation of compiler identities, not a name-based fallback.
        counts = function_boundary.get("declarationReferenceCounts")
        if not isinstance(counts, Mapping):
            raise ValueError("legacy compiler declaration accounting is missing")
        output_declarations = [bindings[index].declaration_identity
                               for index, _raw, _constraint, access in ordered
                               if access in {"output", "read_write"}]
        input_declarations = [bindings[index].declaration_identity
                              for index, _raw, _constraint, access in ordered
                              if access in {"input", "read_write"}]
        if (output_declarations and returned not in output_declarations
                or sorted(input_declarations) != sorted(parameters)):
            raise ValueError("legacy compiler function boundary is not closed")
        all_declarations = [bindings[index].declaration_identity
                            for index, *_rest in ordered]
        expected = {item: all_declarations.count(item) + int(item == returned)
                    for item in set(all_declarations)}
        if any(counts.get(item) != count for item, count in expected.items()):
            raise ValueError("legacy compiler declaration accounting is stale")

    preliminary = []
    for index, raw, constraint, access in ordered:
        binding = bindings[index]
        declaration = declarations.get(binding.declaration_identity)
        if not isinstance(declaration, Mapping):
            raise ValueError("canonical operand declaration join failed")
        type_kind, width, signedness = _type_authority(str(declaration.get("type") or ""))
        # Typed fragment boundaries are authoritative and must agree with C type
        # and GNU access.  Compatibility boundaries carry no duplicate fields.
        if binding.access and binding.access != access:
            raise ValueError("canonical operand access join failed")
        if binding.width_bits and binding.width_bits != width:
            raise ValueError("canonical operand width join failed")
        if binding.signedness and binding.signedness != signedness:
            raise ValueError("canonical operand signedness join failed")
        parameter_index = (parameters.index(binding.declaration_identity)
                           if binding.declaration_identity in parameters else None)
        escape = ("function_return"
                  if binding.declaration_identity == returned and access != "input"
                  else "function_argument" if parameter_index is not None
                  else "non_escaping")
        operand_id = f"{fragment_id}:{index}:{binding.declaration_identity}"
        preliminary.append({
            "fragment_id": fragment_id, "operand_id": operand_id,
            "operand_index": index,
            "declaration_identity": binding.declaration_identity,
            "value_node_identity": binding.value_node_identity,
            "access_mode": access, "type_kind": type_kind,
            "width_bits": width, "signedness": signedness,
            "parameter_index": parameter_index,
            "source_constraint": constraint,
            "early_clobber": bool(raw.get("isEarlyClobber")) or "&" in constraint,
            "escape_kind": escape, "complete": True,
            "logical_name": str(raw.get("symbolicName")
                                or declaration.get("name") or f"operand{index}"),
        })
    ids = {item["operand_index"]: item["operand_id"] for item in preliminary}
    result = []
    for item in preliminary:
        constraint = str(item["source_constraint"])
        tie_match = re.fullmatch(r"[&%!*?]*([0-9]+)", constraint)
        tied = ""
        if tie_match:
            tied_index = int(tie_match.group(1))
            if tied_index not in ids or tied_index == item["operand_index"]:
                raise ValueError("canonical tied operand reference is invalid")
            tied = str(ids[tied_index])
        result.append(CanonicalL2OperandBinding(
            **item, tied_to_operand_id=tied))
    # No two logical operands may claim the same index, and a read-write
    # operand is one carrier.  Pre/post SSA pairs must therefore be represented
    # by a future explicit schema, never silently collapsed here.
    if len({item.operand_index for item in result}) != len(result):
        raise ValueError("canonical operand binding is ambiguous")
    return tuple(result)
