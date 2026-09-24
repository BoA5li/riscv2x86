"""Compiler-owned value nodes and downstream-use authority for L2 fragments."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping


COMPILER_VALUE_NODE_SCHEMA = "riscv2x86.compiler-value-node.v1"
COMPILER_FRAGMENT_CANDIDATE_SCHEMA = \
    "riscv2x86.compiler-fragment-boundary-candidate.v2"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACCESS = {"input", "output", "read_write"}
_SIGNEDNESS = {"signed", "unsigned"}
_USE_KINDS = {
    "function_return", "c_expression", "memory_store",
    "subsequent_asm_input", "branch_condition", "call_argument",
    "discarded", "dead", "escape_unknown",
}
_RELATIONS = {
    "identity", "integer_cast", "bit_preserving_cast",
    "pure_integer_expression", "memory_store", "function_return",
    "control_predicate", "fragment_operand", "discarded",
}


def identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CompilerValueNode:
    node_identity: str
    declaration_identity: str
    defining_ast_node_identity: str
    defining_fragment_id: str
    type_identity: str
    width_bits: int
    signedness: str
    complete: bool
    schema_version: str = COMPILER_VALUE_NODE_SCHEMA

    def __post_init__(self) -> None:
        expected = identity({
            "schemaVersion": self.schema_version,
            "declarationIdentity": self.declaration_identity,
            "definingAstNodeIdentity": self.defining_ast_node_identity,
            "definingFragmentId": self.defining_fragment_id,
            "typeIdentity": self.type_identity,
            "widthBits": self.width_bits,
            "signedness": self.signedness,
        })
        if (self.schema_version != COMPILER_VALUE_NODE_SCHEMA
                or self.node_identity != expected
                or not self.declaration_identity
                or _SHA.fullmatch(self.defining_ast_node_identity) is None
                or _SHA.fullmatch(self.type_identity) is None
                or self.width_bits not in {8, 16, 32, 64}
                or self.signedness not in _SIGNEDNESS
                or self.complete is not True):
            raise ValueError("compiler value node is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion": self.schema_version,
                "nodeIdentity": self.node_identity,
                "declarationIdentity": self.declaration_identity,
                "definingAstNodeIdentity": self.defining_ast_node_identity,
                "definingFragmentId": self.defining_fragment_id,
                "typeIdentity": self.type_identity,
                "widthBits": self.width_bits,
                "signedness": self.signedness, "complete": self.complete}


@dataclass(frozen=True)
class CompilerOperandBinding:
    operand_index: int
    declaration_identity: str
    value_node_identity: str
    access: str
    width_bits: int
    signedness: str
    complete: bool

    def __post_init__(self) -> None:
        if (isinstance(self.operand_index, bool) or self.operand_index < 0
                or not self.declaration_identity
                or _SHA.fullmatch(self.value_node_identity) is None
                or self.access not in _ACCESS or self.width_bits not in {8, 16, 32, 64}
                or self.signedness not in _SIGNEDNESS or self.complete is not True):
            raise ValueError("compiler operand binding is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"operandIndex": self.operand_index,
                "declarationIdentity": self.declaration_identity,
                "valueNodeIdentity": self.value_node_identity,
                "access": self.access, "widthBits": self.width_bits,
                "signedness": self.signedness, "complete": self.complete}


@dataclass(frozen=True)
class CompilerDownstreamUse:
    value_node_identity: str
    use_node_identity: str
    use_kind: str
    consumer_fragment_identity: str
    observation_sink_identity: str
    relation_kind: str
    complete: bool

    def __post_init__(self) -> None:
        if (_SHA.fullmatch(self.value_node_identity) is None
                or _SHA.fullmatch(self.use_node_identity) is None
                or self.use_kind not in _USE_KINDS
                or self.relation_kind not in _RELATIONS
                or (self.observation_sink_identity
                    and _SHA.fullmatch(self.observation_sink_identity) is None)
                or self.complete != (
                    self.use_kind in {"function_return", "c_expression",
                                      "subsequent_asm_input", "branch_condition",
                                      "discarded", "dead"}
                    and (bool(self.observation_sink_identity)
                         or self.use_kind in {"discarded", "dead"}))):
            raise ValueError("compiler downstream use is inconsistent")

    def to_dict(self) -> dict[str, object]:
        return {"valueNodeIdentity": self.value_node_identity,
                "useNodeIdentity": self.use_node_identity,
                "useKind": self.use_kind,
                "consumerFragmentIdentity": self.consumer_fragment_identity,
                "observationSinkIdentity": self.observation_sink_identity,
                "relationKind": self.relation_kind, "complete": self.complete}


def compiler_value_node_from_dict(value: Mapping[str, object]) -> CompilerValueNode:
    expected = {"schemaVersion", "nodeIdentity", "declarationIdentity",
                "definingAstNodeIdentity", "definingFragmentId", "typeIdentity",
                "widthBits", "signedness", "complete"}
    if set(value) != expected:
        raise ValueError("compiler value node fields are invalid")
    width = value.get("widthBits")
    if isinstance(width, bool) or not isinstance(width, int):
        raise ValueError("compiler value node width is invalid")
    return CompilerValueNode(
        str(value["nodeIdentity"]), str(value["declarationIdentity"]),
        str(value["definingAstNodeIdentity"]), str(value["definingFragmentId"]),
        str(value["typeIdentity"]), width, str(value["signedness"]),
        value.get("complete") is True, str(value["schemaVersion"]))


def compiler_operand_binding_from_dict(value: Mapping[str, object]) -> CompilerOperandBinding:
    expected = {"operandIndex", "declarationIdentity", "valueNodeIdentity",
                "access", "widthBits", "signedness", "complete"}
    if set(value) != expected:
        raise ValueError("compiler operand binding fields are invalid")
    index, width = value.get("operandIndex"), value.get("widthBits")
    if any(isinstance(item, bool) or not isinstance(item, int) for item in (index, width)):
        raise ValueError("compiler operand binding numeric fields are invalid")
    return CompilerOperandBinding(index, str(value["declarationIdentity"]),
                                  str(value["valueNodeIdentity"]), str(value["access"]),
                                  width, str(value["signedness"]),
                                  value.get("complete") is True)


def compiler_downstream_use_from_dict(value: Mapping[str, object]) -> CompilerDownstreamUse:
    expected = {"valueNodeIdentity", "useNodeIdentity", "useKind",
                "consumerFragmentIdentity", "observationSinkIdentity",
                "relationKind", "complete"}
    if set(value) != expected:
        raise ValueError("compiler downstream-use fields are invalid")
    return CompilerDownstreamUse(
        str(value["valueNodeIdentity"]), str(value["useNodeIdentity"]),
        str(value["useKind"]), str(value["consumerFragmentIdentity"]),
        str(value["observationSinkIdentity"]), str(value["relationKind"]),
        value.get("complete") is True)
