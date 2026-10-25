"""Compiler-owned per-fragment operand flow and shared execution authority."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping, Sequence
from .compiler_value_flow import (
    COMPILER_FRAGMENT_CANDIDATE_SCHEMA,
    compiler_downstream_use_from_dict, compiler_operand_binding_from_dict,
    compiler_operand_carrier_from_dict, compiler_value_node_from_dict,
)
from .compiler_static_operand import validate_static_operand, static_operands
from .l2_internal_value import internal_value_proof_facts_from_dict


FRAGMENT_OPERAND_BOUNDARY_SCHEMA = "riscv2x86.fragment-operand-boundary.v2"
FRAGMENT_DEPENDENCY_GRAPH_SCHEMA = "riscv2x86.fragment-dependency-graph.v2"
PROGRAM_EXECUTION_AUTHORITY_SCHEMA = "riscv2x86.fragment-program-execution-authority.v1"
OPERAND_OBSERVATION_AUTHORITY_SCHEMA = (
    "riscv2x86.l2-operand-observation-authority.v2"
)
STATIC_BOUNDARY_SCHEMA = "riscv2x86.fragment-operand-boundary.v3"
STATIC_OBSERVATION_SCHEMA = "riscv2x86.l2-operand-observation-authority.v3"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


def identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


@dataclass(frozen=True)
class OperandBinding:
    operand_index: int
    declaration_identity: str
    value_node_identity: str
    access: str
    width_bits: int
    complete: bool
    signedness: str = "unsigned"
    static_operand: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if (isinstance(self.operand_index, bool) or self.operand_index < 0
                or (not self.declaration_identity and self.static_operand is None) or not self.value_node_identity
                or self.access not in {"input", "output", "read_write"}
                or self.width_bits <= 0 or self.complete is not True
                or self.signedness not in {"signed", "unsigned"}
                or _SHA.fullmatch(self.value_node_identity) is None):
            raise ValueError("fragment operand binding is incomplete")
        if self.static_operand is not None:
            validate_static_operand(self.static_operand,index=self.operand_index,node=self.value_node_identity,
                width=self.width_bits,signedness=self.signedness,access=self.access,declaration=self.declaration_identity)

    def to_dict(self) -> dict[str, object]:
        return {"operandIndex": self.operand_index,
                "declarationIdentity": self.declaration_identity,
                "valueNodeIdentity": self.value_node_identity,
                "access": self.access, "widthBits": self.width_bits,
                "signedness": self.signedness, "complete": self.complete,
                **({"staticOperand":dict(self.static_operand)} if self.static_operand is not None else {})}


@dataclass(frozen=True)
class FragmentValueFlowEdge:
    producer_value_node: str
    consumer_value_node: str
    producer_fragment_id: str
    consumer_fragment_id: str
    relation_kind: str
    observation_sink_identity: str
    complete: bool

    def __post_init__(self) -> None:
        if (_SHA.fullmatch(self.producer_value_node) is None
                or (self.consumer_value_node
                    and _SHA.fullmatch(self.consumer_value_node) is None)
                or not self.producer_fragment_id
                or self.relation_kind not in {
                    "identity", "integer_cast", "bit_preserving_cast",
                    "pure_integer_expression", "memory_store", "function_return",
                    "control_predicate", "fragment_operand", "discarded"}
                or (self.observation_sink_identity
                    and _SHA.fullmatch(self.observation_sink_identity) is None)
                or self.complete is not True):
            raise ValueError("fragment value-flow edge is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"producerValueNode": self.producer_value_node,
                "consumerValueNode": self.consumer_value_node,
                "producerFragmentId": self.producer_fragment_id,
                "consumerFragmentId": self.consumer_fragment_id,
                "relationKind": self.relation_kind,
                "observationSinkIdentity": self.observation_sink_identity,
                "complete": self.complete}


@dataclass(frozen=True)
class ObservationSinkBinding:
    sink_identity: str
    value_node_identity: str
    sink_kind: str
    complete: bool

    def __post_init__(self) -> None:
        if (_SHA.fullmatch(self.sink_identity) is None
                or _SHA.fullmatch(self.value_node_identity) is None
                or self.sink_kind not in {
                    "function_return", "c_expression", "memory_store",
                    "subsequent_asm_input", "branch_condition",
                    "instrumentation"}
                or self.complete is not True):
            raise ValueError("observation sink binding is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"sinkIdentity": self.sink_identity,
                "valueNodeIdentity": self.value_node_identity,
                "sinkKind": self.sink_kind, "complete": self.complete}


@dataclass(frozen=True)
class L2OperandObservationBinding:
    """Proof-bound route from one logical operand to its observation source/sink."""

    fragment_id: str
    operand_id: str
    operand_index: int
    declaration_identity: str
    value_node_identity: str
    access: str
    closure_kind: str
    width_bits: int = 0
    signedness: str = ""
    parameter_index: int | None = None
    producer_fragment_id: str = ""
    producer_value_node_identity: str = ""
    observation_kind: str = ""
    observation_sink_identity: str = ""
    consumer_fragment_id: str = ""
    consumer_value_node_identity: str = ""
    value_flow_edge_identity: str = ""
    instrumentation_plan_identity: str = ""
    complete: bool = True
    static_operand: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if (not self.fragment_id or not self.operand_id
                or isinstance(self.operand_index, bool)
                or not isinstance(self.operand_index, int)
                or self.operand_index < 0 or (not self.declaration_identity and self.static_operand is None)
                or _SHA.fullmatch(self.value_node_identity) is None
                or self.access not in {"input", "output", "read_write"}
                or isinstance(self.width_bits, bool)
                or not isinstance(self.width_bits, int) or self.width_bits <= 0
                or self.signedness not in {"signed", "unsigned"}
                or self.closure_kind not in {
                    "parameter", "producer", "sink", "consumer", "discard",
                    "instrumentation", "compiler_constant"}
                or self.complete is not True):
            raise ValueError("operand observation binding header is invalid")
        constant = self.closure_kind == "compiler_constant"
        if constant != (self.static_operand is not None):
            raise ValueError("static observation role mismatch")
        if constant:
            validate_static_operand(self.static_operand,index=self.operand_index,node=self.value_node_identity,
                width=self.width_bits,signedness=self.signedness,access=self.access,declaration=self.declaration_identity)
            if self.observation_kind != "compiler_constant":raise ValueError("static observation kind mismatch")
        parameter = self.closure_kind == "parameter"
        producer = self.closure_kind == "producer"
        sink = self.closure_kind == "sink"
        consumer = self.closure_kind == "consumer"
        instrumentation = self.closure_kind == "instrumentation"
        if parameter != (self.parameter_index is not None
                          and self.access == "input"):
            raise ValueError("operand parameter observation authority is inconsistent")
        if self.access == "read_write" and self.parameter_index is None:
            raise ValueError("read-write operand lacks before-value authority")
        if self.access == "output" and self.parameter_index is not None:
            raise ValueError("output-only operand has foreign parameter authority")
        if self.parameter_index is not None and (
                isinstance(self.parameter_index, bool)
                or not isinstance(self.parameter_index, int)
                or self.parameter_index < 0):
            raise ValueError("operand parameter index is invalid")
        if producer != bool(self.producer_fragment_id):
            raise ValueError("operand producer authority is inconsistent")
        if producer and (_SHA.fullmatch(self.producer_value_node_identity) is None
                         or _SHA.fullmatch(self.value_flow_edge_identity) is None
                         or self.observation_kind != "composite_dependency"):
            raise ValueError("operand producer authority is invalid")
        if sink and (_SHA.fullmatch(self.observation_sink_identity) is None
                     or self.observation_kind not in {
                         "function_return", "c_expression", "memory_store",
                         "branch_condition"}):
            raise ValueError("operand observation sink authority is invalid")
        if consumer != bool(self.consumer_fragment_id):
            raise ValueError("operand observation consumer authority is inconsistent")
        if consumer and (_SHA.fullmatch(self.consumer_value_node_identity) is None
                         or _SHA.fullmatch(self.observation_sink_identity) is None
                         or _SHA.fullmatch(self.value_flow_edge_identity) is None
                         or self.observation_kind != "subsequent_asm_input"):
            raise ValueError("operand observation consumer authority is invalid")
        if instrumentation != bool(self.instrumentation_plan_identity):
            raise ValueError("operand instrumentation authority is inconsistent")
        if (instrumentation
                and _SHA.fullmatch(self.instrumentation_plan_identity) is None):
            raise ValueError("operand instrumentation plan identity is invalid")
        if instrumentation and self.observation_kind != "instrumentation":
            raise ValueError("operand instrumentation observation kind is invalid")
        if self.closure_kind == "discard" and self.observation_kind != "discarded":
            raise ValueError("discarded operand authority is invalid")
        if (not producer and (self.producer_fragment_id
                              or self.producer_value_node_identity)
                or not consumer and (self.consumer_fragment_id
                              or self.consumer_value_node_identity
                              or (self.value_flow_edge_identity and not producer))
                or not (sink or consumer) and self.observation_sink_identity
                or not instrumentation and self.instrumentation_plan_identity):
            raise ValueError("operand observation authority has foreign fields")

    @property
    def binding_identity(self) -> str:
        return identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value = {
            "fragmentId": self.fragment_id, "operandId": self.operand_id,
            "operandIndex": self.operand_index,
            "declarationIdentity": self.declaration_identity,
            "valueNodeIdentity": self.value_node_identity,
            "access": self.access, "closureKind": self.closure_kind,
            "widthBits": self.width_bits, "signedness": self.signedness,
            "parameterIndex": self.parameter_index,
            "producerFragmentId": self.producer_fragment_id,
            "producerValueNodeIdentity": self.producer_value_node_identity,
            "observationKind": self.observation_kind,
            "observationSinkIdentity": self.observation_sink_identity,
            "consumerFragmentId": self.consumer_fragment_id,
            "consumerValueNodeIdentity": self.consumer_value_node_identity,
            "valueFlowEdgeIdentity": self.value_flow_edge_identity,
            "instrumentationPlanIdentity": self.instrumentation_plan_identity,
            "complete": self.complete,
            **({"staticOperand":dict(self.static_operand)} if self.static_operand is not None else {}),
        }
        if include_identity:
            value["bindingIdentity"] = self.binding_identity
        return value


@dataclass(frozen=True)
class L2OperandObservationAuthority:
    fragment_id: str
    boundary_identity: str
    proof_identity: str
    dependency_graph_identity: str
    bindings: tuple[L2OperandObservationBinding, ...]
    complete: bool
    schema_version: str = OPERAND_OBSERVATION_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version not in {OPERAND_OBSERVATION_AUTHORITY_SCHEMA,STATIC_OBSERVATION_SCHEMA}
                or not self.fragment_id
                or _SHA.fullmatch(self.boundary_identity) is None
                or _SHA.fullmatch(self.proof_identity) is None
                or _SHA.fullmatch(self.dependency_graph_identity) is None):
            raise ValueError("operand observation authority header is invalid")
        if any(b.static_operand is not None for b in self.bindings) != (self.schema_version == STATIC_OBSERVATION_SCHEMA):
            raise ValueError("static observations require v3 authority")
        indices = tuple(item.operand_index for item in self.bindings)
        if (not self.bindings or indices != tuple(sorted(set(indices)))
                or any(item.fragment_id != self.fragment_id
                       for item in self.bindings)
                or self.complete is not True):
            raise ValueError("operand observation authority is incomplete")

    @property
    def authority_identity(self) -> str:
        return identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value = {
            "schemaVersion": self.schema_version,
            "fragmentId": self.fragment_id,
            "boundaryIdentity": self.boundary_identity,
            "proofIdentity": self.proof_identity,
            "dependencyGraphIdentity": self.dependency_graph_identity,
            "bindings": [item.to_dict() for item in self.bindings],
            "complete": self.complete,
        }
        if include_identity:
            value["authorityIdentity"] = self.authority_identity
        return value


def materialize_operand_observation_authority(
    boundary: "FragmentOperandBoundary", *, operand_ids: Mapping[int, str],
    proof_identity: str, dependency_graph_identity: str,
    parameter_indices: Mapping[int, int | None] | None = None,
    dependency_edges: Sequence["FragmentDependencyEdge"] = (),
    instrumentation_plan_identity: str = "",
    canonical_bindings: Sequence[object] | None = None,
) -> L2OperandObservationAuthority:
    """Close every scalar operand through exactly one typed source/sink route."""
    if not boundary.complete:
        raise ValueError("operand observation boundary is incomplete")
    if canonical_bindings is not None:
        canonical = {item.operand_index: item for item in canonical_bindings}
        compiler = boundary.input_bindings + boundary.output_bindings
        if (len(canonical) != len(canonical_bindings)
                or set(canonical) != {item.operand_index for item in compiler}):
            raise ValueError("canonical observation operand coverage mismatch")
        for item in compiler:
            bound = canonical[item.operand_index]
            if ((bound.fragment_id, bound.declaration_identity,
                 bound.value_node_identity, bound.access_mode,
                 bound.width_bits, bound.signedness)
                    != (boundary.fragment_id, item.declaration_identity,
                        item.value_node_identity, item.access,
                        item.width_bits, item.signedness)
                    or getattr(bound,"static_operand",None) != item.static_operand
                    or operand_ids.get(item.operand_index) != bound.operand_id
                    or (parameter_indices or {}).get(item.operand_index)
                    != bound.parameter_index):
                raise ValueError("canonical observation operand binding mismatch")
    bindings: list[L2OperandObservationBinding] = []
    parameters = parameter_indices or {}
    for input_binding in boundary.input_bindings:
        routes: list[dict[str, object]] = []
        parameter_index = parameters.get(input_binding.operand_index)
        if input_binding.static_operand is not None:
            routes.append({"closure_kind":"compiler_constant","observation_kind":"compiler_constant",
                           "static_operand":input_binding.static_operand})
        if parameter_index is not None:
            routes.append({"closure_kind": "parameter",
                           "observation_kind": "function_parameter",
                           "parameter_index": parameter_index})
        producers = [item for item in dependency_edges
                     if item.consumer_fragment_id == boundary.fragment_id
                     and item.consumer_value_node_identity
                     == input_binding.value_node_identity]
        if len(producers) == 1:
            routes.append({
                "closure_kind": "producer",
                "observation_kind": "composite_dependency",
                "producer_fragment_id": producers[0].producer_fragment_id,
                "producer_value_node_identity": producers[0].value_node_identity,
                "value_flow_edge_identity": identity(producers[0].to_dict()),
            })
        elif len(producers) > 1:
            raise ValueError("scalar input has ambiguous fragment producers")
        if len(routes) != 1:
            raise ValueError("scalar input does not have one observation source")
        operand_id = operand_ids.get(input_binding.operand_index, "")
        if not operand_id:
            raise ValueError("scalar input operand identity is missing")
        bindings.append(L2OperandObservationBinding(
            boundary.fragment_id, operand_id, input_binding.operand_index,
            input_binding.declaration_identity, input_binding.value_node_identity,
            input_binding.access, width_bits=input_binding.width_bits,
            signedness=input_binding.signedness, **routes[0]))
    for output in boundary.output_bindings:
        routes: list[dict[str, str]] = []
        sinks = [item for item in boundary.observation_sinks
                 if item.value_node_identity == output.value_node_identity
                 and item.sink_kind != "subsequent_asm_input"]
        consumers = [item for item in boundary.value_flow_edges
                     if item.producer_value_node == output.value_node_identity
                     and item.consumer_fragment_id]
        if len(sinks) == 1:
            routes.append({
                "closure_kind": "sink",
                "observation_kind": sinks[0].sink_kind,
                "observation_sink_identity": sinks[0].sink_identity,
            })
        elif len(sinks) > 1:
            raise ValueError("scalar output has ambiguous observation sinks")
        if len(consumers) == 1:
            if consumers[0].relation_kind != "fragment_operand":
                raise ValueError("scalar output consumer relation is unsupported")
            routes.append({
                "closure_kind": "consumer",
                "observation_kind": "subsequent_asm_input",
                "observation_sink_identity":
                    consumers[0].observation_sink_identity,
                "consumer_fragment_id": consumers[0].consumer_fragment_id,
                "consumer_value_node_identity": consumers[0].consumer_value_node,
                "value_flow_edge_identity": identity(FragmentDependencyEdge(
                    consumers[0].producer_fragment_id,
                    consumers[0].consumer_fragment_id,
                    consumers[0].producer_value_node,
                    consumers[0].consumer_value_node).to_dict()),
            })
        elif len(consumers) > 1:
            raise ValueError("scalar output has ambiguous fragment consumers")
        if output.value_node_identity in boundary.discarded_output_nodes:
            routes.append({"closure_kind": "discard",
                           "observation_kind": "discarded"})
        if output.value_node_identity in boundary.instrumentation_observed_nodes:
            if not instrumentation_plan_identity:
                raise ValueError("instrumented scalar output lacks plan identity")
            routes.append({
                "closure_kind": "instrumentation",
                "observation_kind": "instrumentation",
                "instrumentation_plan_identity": instrumentation_plan_identity,
            })
        if len(routes) != 1:
            raise ValueError("scalar output does not have one observation route")
        operand_id = operand_ids.get(output.operand_index, "")
        if not operand_id:
            raise ValueError("scalar output operand identity is missing")
        bindings.append(L2OperandObservationBinding(
            boundary.fragment_id, operand_id, output.operand_index,
            output.declaration_identity, output.value_node_identity,
            output.access, width_bits=output.width_bits,
            signedness=output.signedness,
            parameter_index=(parameters.get(output.operand_index)
                             if output.access == "read_write" else None),
            **routes[0]))
    if not bindings:
        raise ValueError("scalar observation authority has no operands")
    return L2OperandObservationAuthority(
        boundary.fragment_id, boundary.boundary_identity, proof_identity,
        dependency_graph_identity,
        tuple(sorted(bindings, key=lambda item: item.operand_index)), True,
        STATIC_OBSERVATION_SCHEMA if any(b.static_operand is not None for b in bindings) else OPERAND_OBSERVATION_AUTHORITY_SCHEMA)


def operand_observation_authority_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
    expected_boundary_identity: str = "",
) -> L2OperandObservationAuthority:
    fields = {
        "schemaVersion", "fragmentId", "boundaryIdentity", "proofIdentity",
        "dependencyGraphIdentity", "bindings", "complete", "authorityIdentity",
    }
    if set(value) != fields or not isinstance(value.get("bindings"), list):
        raise ValueError("operand observation authority fields are invalid")
    binding_fields = {
        "fragmentId", "operandId", "operandIndex", "declarationIdentity",
        "valueNodeIdentity", "access", "closureKind", "observationKind",
        "widthBits", "signedness", "parameterIndex", "producerFragmentId",
        "producerValueNodeIdentity",
        "observationSinkIdentity", "consumerFragmentId",
        "consumerValueNodeIdentity", "valueFlowEdgeIdentity",
        "instrumentationPlanIdentity", "complete", "bindingIdentity",
    }
    bindings = []
    for raw in value["bindings"]:
        if (not isinstance(raw, Mapping) or set(raw) != binding_fields | ({"staticOperand"} if "staticOperand" in raw else set())
                or not isinstance(raw.get("complete"), bool)):
            raise ValueError("operand observation binding fields are invalid")
        if "staticOperand" in raw and not isinstance(raw["staticOperand"],Mapping):raise ValueError("static observation binding is invalid")
        index = raw.get("operandIndex")
        if isinstance(index, bool) or not isinstance(index, int):
            raise ValueError("operand observation binding index is invalid")
        width = raw.get("widthBits")
        if isinstance(width, bool) or not isinstance(width, int):
            raise ValueError("operand observation binding width is invalid")
        binding = L2OperandObservationBinding(
            str(raw.get("fragmentId", "")), str(raw.get("operandId", "")), index,
            str(raw.get("declarationIdentity", "")),
            str(raw.get("valueNodeIdentity", "")), str(raw.get("access", "")),
            str(raw.get("closureKind", "")),
            width, str(raw.get("signedness", "")),
            raw.get("parameterIndex"),
            str(raw.get("producerFragmentId", "")),
            str(raw.get("producerValueNodeIdentity", "")),
            str(raw.get("observationKind", "")),
            str(raw.get("observationSinkIdentity", "")),
            str(raw.get("consumerFragmentId", "")),
            str(raw.get("consumerValueNodeIdentity", "")),
            str(raw.get("valueFlowEdgeIdentity", "")),
            str(raw.get("instrumentationPlanIdentity", "")),
            bool(raw.get("complete")), static_operand=raw.get("staticOperand"),
        )
        if raw.get("bindingIdentity") != binding.binding_identity:
            raise ValueError("operand observation binding identity is stale")
        bindings.append(binding)
    if not isinstance(value.get("complete"), bool):
        raise ValueError("operand observation authority completeness is invalid")
    authority = L2OperandObservationAuthority(
        str(value.get("fragmentId", "")),
        str(value.get("boundaryIdentity", "")),
        str(value.get("proofIdentity", "")),
        str(value.get("dependencyGraphIdentity", "")), tuple(bindings),
        bool(value.get("complete")), str(value.get("schemaVersion", "")),
    )
    if value.get("authorityIdentity") != authority.authority_identity:
        raise ValueError("operand observation authority identity is stale")
    if expected_fragment_id and authority.fragment_id != expected_fragment_id:
        raise ValueError("operand observation authority fragment mismatch")
    if (expected_boundary_identity
            and authority.boundary_identity != expected_boundary_identity):
        raise ValueError("operand observation authority boundary mismatch")
    return authority


@dataclass(frozen=True)
class FragmentOperandBoundary:
    program_id: str
    function_id: str
    fragment_id: str
    input_bindings: tuple[OperandBinding, ...]
    output_bindings: tuple[OperandBinding, ...]
    live_in_nodes: tuple[str, ...]
    live_out_nodes: tuple[str, ...]
    complete: bool
    reason_codes: tuple[str, ...] = ()
    value_flow_edges: tuple[FragmentValueFlowEdge, ...] = ()
    observation_sinks: tuple[ObservationSinkBinding, ...] = ()
    discarded_output_nodes: tuple[str, ...] = ()
    instrumentation_observed_nodes: tuple[str, ...] = ()
    schema_version: str = FRAGMENT_OPERAND_BOUNDARY_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version not in {FRAGMENT_OPERAND_BOUNDARY_SCHEMA,STATIC_BOUNDARY_SCHEMA}
                or not self.program_id or not self.function_id or not self.fragment_id
                or self.live_in_nodes != tuple(sorted(set(self.live_in_nodes)))
                or self.live_out_nodes != tuple(sorted(set(self.live_out_nodes)))
                or self.reason_codes != tuple(sorted(set(self.reason_codes)))
                or self.discarded_output_nodes != tuple(sorted(set(self.discarded_output_nodes)))
                or self.instrumentation_observed_nodes != tuple(sorted(set(self.instrumentation_observed_nodes)))):
            raise ValueError("fragment operand boundary identity is invalid")
        bindings = self.output_bindings + self.input_bindings
        if any(b.static_operand is not None for b in bindings) != (self.schema_version == STATIC_BOUNDARY_SCHEMA):
            raise ValueError("static operands require v3 boundary")
        indices = tuple(item.operand_index for item in bindings)
        if len(indices) != len(set(indices)):
            raise ValueError("fragment operand boundary indices are duplicated")
        if not bindings and (self.live_in_nodes or self.live_out_nodes
                             or self.value_flow_edges or self.observation_sinks
                             or self.discarded_output_nodes
                             or self.instrumentation_observed_nodes):
            raise ValueError("zero-operand boundary contains unbound value facts")
        observed = {item.value_node_identity for item in self.observation_sinks}
        consumed = {item.producer_value_node for item in self.value_flow_edges
                    if item.consumer_fragment_id}
        accounted = observed | consumed | set(self.discarded_output_nodes) \
            | set(self.instrumentation_observed_nodes)
        # An input-only fragment has a closed operand boundary when every
        # declared input is complete.  Output obligations remain universal:
        # every real output must be observed, consumed, authoritatively
        # discarded, or covered by an approved instrumentation point.  The
        # vacuous all() for an empty output set is intentional and does not
        # fabricate a source result.
        # Explicit, identity-bound empty arrays are a valid zero-operand
        # boundary. Missing enumeration is rejected by the producer/parser;
        # effect and shell completeness remain separate proof obligations.
        closed = bool(not self.reason_codes
                      and all(item.complete for item in bindings)
                      and all(item.value_node_identity in accounted
                              for item in self.output_bindings))
        if self.complete != closed:
            raise ValueError("fragment operand boundary completeness is inconsistent")

    @property
    def boundary_identity(self) -> str:
        return identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value = {"schemaVersion": self.schema_version, "programId": self.program_id,
                 "functionId": self.function_id, "fragmentId": self.fragment_id,
                 "inputBindings": [item.to_dict() for item in self.input_bindings],
                 "outputBindings": [item.to_dict() for item in self.output_bindings],
                 "liveInNodes": list(self.live_in_nodes),
                 "liveOutNodes": list(self.live_out_nodes), "complete": self.complete,
                 "reasonCodes": list(self.reason_codes),
                 "valueFlowEdges": [item.to_dict() for item in self.value_flow_edges],
                 "observationSinks": [item.to_dict() for item in self.observation_sinks],
                 "discardedOutputNodes": list(self.discarded_output_nodes),
                 "instrumentationObservedNodes": list(self.instrumentation_observed_nodes)}
        if include_identity:
            value["boundaryIdentity"] = self.boundary_identity
        return value


@dataclass(frozen=True)
class FragmentDependencyEdge:
    producer_fragment_id: str
    consumer_fragment_id: str
    value_node_identity: str
    consumer_value_node_identity: str = ""

    def __post_init__(self) -> None:
        if (not self.producer_fragment_id or not self.consumer_fragment_id
                or self.producer_fragment_id == self.consumer_fragment_id
                or _SHA.fullmatch(self.value_node_identity) is None
                or _SHA.fullmatch(self.consumer_value_node_identity) is None):
            raise ValueError("fragment dependency edge is incomplete")

    def to_dict(self) -> dict[str, str]:
        return {"producerFragmentId": self.producer_fragment_id,
                "consumerFragmentId": self.consumer_fragment_id,
                "valueNodeIdentity": self.value_node_identity,
                "consumerValueNodeIdentity": self.consumer_value_node_identity}


@dataclass(frozen=True)
class FragmentDependencyGraph:
    program_id: str
    function_id: str
    fragment_ids: tuple[str, ...]
    edges: tuple[FragmentDependencyEdge, ...]
    execution_mode: str
    complete: bool
    reason_codes: tuple[str, ...] = ()
    schema_version: str = FRAGMENT_DEPENDENCY_GRAPH_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != FRAGMENT_DEPENDENCY_GRAPH_SCHEMA
                or self.fragment_ids != tuple(sorted(set(self.fragment_ids)))
                or self.execution_mode not in {"shared_independent", "composite", "inconclusive"}
                or self.reason_codes != tuple(sorted(set(self.reason_codes)))):
            raise ValueError("fragment dependency graph is invalid")
        edge_keys = tuple((item.producer_fragment_id, item.consumer_fragment_id,
                           item.value_node_identity,
                           item.consumer_value_node_identity) for item in self.edges)
        if edge_keys != tuple(sorted(set(edge_keys))):
            raise ValueError("fragment dependency edges are not canonical")
        if self.complete != (self.execution_mode != "inconclusive" and not self.reason_codes):
            raise ValueError("fragment dependency graph completeness is inconsistent")

    @property
    def graph_identity(self) -> str:
        return identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value = {"schemaVersion": self.schema_version, "programId": self.program_id,
                 "functionId": self.function_id, "fragmentIds": list(self.fragment_ids),
                 "edges": [item.to_dict() for item in self.edges],
                 "executionMode": self.execution_mode, "complete": self.complete,
                 "reasonCodes": list(self.reason_codes)}
        if include_identity:
            value["graphIdentity"] = self.graph_identity
        return value


@dataclass(frozen=True)
class ProgramExecutionAuthority:
    program_id: str
    function_id: str
    fragment_ids: tuple[str, ...]
    dependency_graph_identity: str
    execution_mode: str
    complete: bool
    reason_codes: tuple[str, ...] = ()
    schema_version: str = PROGRAM_EXECUTION_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != PROGRAM_EXECUTION_AUTHORITY_SCHEMA
                or not self.program_id or not self.function_id
                or self.fragment_ids != tuple(sorted(set(self.fragment_ids)))
                or _SHA.fullmatch(self.dependency_graph_identity) is None
                or self.execution_mode not in {"shared_independent", "composite", "inconclusive"}
                or self.reason_codes != tuple(sorted(set(self.reason_codes)))
                or self.complete != (self.execution_mode != "inconclusive"
                                     and not self.reason_codes)):
            raise ValueError("program execution authority is invalid")

    @property
    def authority_identity(self) -> str:
        return identity(self.to_dict(include_identity=False, include_execution=False))

    @property
    def execution_identity(self) -> str:
        return identity({"schemaVersion": "riscv2x86.l2-program-execution.v2",
                         "programId": self.program_id, "functionId": self.function_id,
                         "fragmentIds": list(self.fragment_ids),
                         "dependencyGraphIdentity": self.dependency_graph_identity,
                         "executionMode": self.execution_mode}) if self.complete else ""

    def observation_identity(self, fragment_id: str, dimension: str, side: str) -> str:
        if not self.complete or fragment_id not in self.fragment_ids:
            return ""
        return identity({"schemaVersion": "riscv2x86.l2-fragment-observation.v1",
                         "executionIdentity": self.execution_identity,
                         "fragmentId": fragment_id, "dimension": dimension,
                         "side": side})

    def to_dict(self, *, include_identity: bool = True,
                include_execution: bool = True) -> dict[str, object]:
        value = {"schemaVersion": self.schema_version, "programId": self.program_id,
                 "functionId": self.function_id, "fragmentIds": list(self.fragment_ids),
                 "dependencyGraphIdentity": self.dependency_graph_identity,
                 "executionMode": self.execution_mode, "complete": self.complete,
                 "reasonCodes": list(self.reason_codes)}
        if include_identity:
            value["authorityIdentity"] = self.authority_identity
        if include_execution:
            value["executionIdentity"] = self.execution_identity
        return value


def _width(type_name: object) -> int:
    value = " ".join(str(type_name).replace("const", "").replace("volatile", "").split())
    match = re.fullmatch(r"u?int(8|16|32|64)_t", value)
    if match:
        return int(match.group(1))
    if "char" in value: return 8
    if "short" in value: return 16
    if "long" in value: return 64
    if value in {"int", "signed", "signed int", "unsigned", "unsigned int"}: return 32
    return 0


def _fragment_source_location(
    fragment: Mapping[str, object],
) -> tuple[str, int, int] | None:
    """Read the frontend-owned source coordinate without inspecting asm text."""
    raw = fragment.get("sourceLocation")
    if isinstance(raw, Mapping):
        source_file = raw.get("sourceFile")
        line, column = raw.get("line"), raw.get("column")
        if (isinstance(source_file, str) and source_file
                and isinstance(line, int) and not isinstance(line, bool)
                and isinstance(column, int) and not isinstance(column, bool)
                and line > 0 and column > 0):
            return source_file, line, column
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    match = re.fullmatch(r"(.+):(\d+):(\d+)", fragment_id)
    if match is None:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3))


def _same_source_file(left: object, right: object) -> bool:
    if not isinstance(left, str) or not left or not isinstance(right, str) or not right:
        return False
    return Path(left).resolve() == Path(right).resolve()


def resolve_compiler_fragment_candidate(
    fragment: Mapping[str, object],
    candidates: Sequence[Mapping[str, object]],
    function: Mapping[str, object],
) -> tuple[Mapping[str, object] | None, str]:
    """Resolve exactly one compiler candidate from shared structured identity."""
    binding = fragment.get("compilerFragmentBinding")
    if isinstance(binding, Mapping):
        candidate_identity = binding.get("candidateIdentity")
        direct = [item for item in candidates
                  if item.get("candidateIdentity") == candidate_identity]
        if len(direct) == 1:
            return direct[0], ""
        return (None, "L2_FRAGMENT_CANDIDATE_IDENTITY_AMBIGUOUS"
                if len(direct) > 1 else
                "L2_FRAGMENT_CANDIDATE_IDENTITY_NOT_FOUND")

    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    direct = [item for item in candidates if item.get("fragmentId") == fragment_id]
    if len(direct) == 1:
        return direct[0], ""
    if len(direct) > 1:
        return None, "L2_FRAGMENT_CANDIDATE_IDENTITY_AMBIGUOUS"

    function_id = str(function.get("functionId") or function.get("name") or "")
    source_digest = str(function.get("sourceDigest") or "")
    location = _fragment_source_location(fragment)
    if location is not None:
        source_file, line, column = location
        matches = []
        for item in candidates:
            key = item.get("fragmentBindingKey")
            if (isinstance(key, Mapping)
                    and key.get("functionIdentity") == function_id
                    and key.get("sourceDigest") == source_digest
                    and _same_source_file(key.get("sourceFile"), source_file)
                    and key.get("beginLine") == line
                    and key.get("beginColumn") == column):
                matches.append(item)
        if len(matches) == 1:
            return matches[0], ""
        if len(matches) > 1:
            return None, "L2_FRAGMENT_CANDIDATE_IDENTITY_AMBIGUOUS"

    # Compatibility for frontends which already export byte offsets.  The
    # function and digest checks prevent a range in another source/function
    # from being accepted.
    begin, end = fragment.get("beginOffset"), fragment.get("endOffset")
    if (isinstance(begin, int) and not isinstance(begin, bool)
            and isinstance(end, int) and not isinstance(end, bool)):
        matches = []
        for item in candidates:
            key = item.get("fragmentBindingKey")
            if (isinstance(key, Mapping)
                    and key.get("functionIdentity") == function_id
                    and key.get("sourceDigest") == source_digest
                    and key.get("beginOffset") == begin
                    and key.get("endOffset") == end):
                matches.append(item)
        if len(matches) == 1:
            return matches[0], ""
        if len(matches) > 1:
            return None, "L2_FRAGMENT_CANDIDATE_IDENTITY_AMBIGUOUS"
    return None, "L2_FRAGMENT_CANDIDATE_IDENTITY_NOT_FOUND"


_candidate_for = resolve_compiler_fragment_candidate

def materialize_fragment_execution_authority(
    findings: Sequence[Mapping[str, object]], function: Mapping[str, object],
    program_id: str,
) -> tuple[dict[str, FragmentOperandBoundary], FragmentDependencyGraph,
           ProgramExecutionAuthority]:
    """Join compiler asm ranges to report fragments without ordinal guessing."""
    function_id = str(function.get("functionId") or function.get("name") or "")
    raw = function.get("l2OperandBoundary")
    declarations = raw.get("declarations") if isinstance(raw, Mapping) else None
    params = raw.get("parameterDeclarationIds") if isinstance(raw, Mapping) else None
    returned = raw.get("returnDeclarationId") if isinstance(raw, Mapping) else None
    candidates = raw.get("fragmentCandidates") if isinstance(raw, Mapping) else None
    if not isinstance(declarations, Mapping): declarations = {}
    if not isinstance(params, list): params = []
    if not isinstance(candidates, list): candidates = []
    scoped = []
    for finding in findings:
        fragment = finding.get("fragment")
        if (isinstance(fragment, Mapping)
                and fragment.get("enclosingFunction") == function.get("name")):
            scoped.append((finding, fragment))
    scoped.sort(key=lambda pair: str(pair[1].get("id") or pair[1].get("fragmentId") or ""))
    resolved: dict[str, tuple[Mapping[str, object] | None, str, Mapping[str, object]]] = {}
    candidate_fragments: dict[str, set[str]] = {}
    for _finding, fragment in scoped:
        fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
        candidate, candidate_reason = resolve_compiler_fragment_candidate(
            fragment, [item for item in candidates if isinstance(item, Mapping)],
            function)
        if isinstance(candidate, Mapping) and fragment.get('compilerFragmentAuthority'):
            try:
                literals = static_operands(fragment)
                if literals:
                    closed = fragment['compilerFragmentAuthority']['candidate']
                    if closed['expressionClosureInputs']['candidate'] != candidate:
                        raise ValueError('COMPILER_STATIC_ORIGINAL_CANDIDATE_MISMATCH')
                    candidate = closed
            except (ValueError,KeyError,TypeError) as exc:
                candidate_reason = str(exc)
                candidate = None
        resolved[fragment_id] = candidate, candidate_reason, fragment
        if isinstance(candidate, Mapping) and isinstance(candidate.get("candidateIdentity"), str):
            candidate_fragments.setdefault(
                str(candidate["candidateIdentity"]), set()).add(fragment_id)

    boundaries: dict[str, FragmentOperandBoundary] = {}
    graph_edges: list[FragmentDependencyEdge] = []
    finding_by_fragment = {
        str(fragment.get("id") or fragment.get("fragmentId") or ""): finding
        for finding, fragment in scoped
    }
    for fragment_id, (candidate, candidate_reason, fragment) in resolved.items():
        outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
        reasons: set[str] = set()
        if candidate is None:
            reasons.add(candidate_reason or "L2_FRAGMENT_BOUNDARY_BINDING_MISSING")
        elif candidate.get("schemaVersion") not in {COMPILER_FRAGMENT_CANDIDATE_SCHEMA,"riscv2x86.closed-compiler-fragment.v2"}:
            reasons.add("L2_FRAGMENT_CANDIDATE_SCHEMA_UNSUPPORTED")
        elif candidate.get("complete") is not True:
            reasons.add("L2_FRAGMENT_CANDIDATE_INCOMPLETE")
        if isinstance(candidate, Mapping):
            binding_key = candidate.get("fragmentBindingKey")
            expected_candidate = (identity({
                "schemaVersion": "riscv2x86.compiler-fragment-binding-key.v2",
                **dict(binding_key),
            }) if isinstance(binding_key, Mapping) else "")
            if (not isinstance(binding_key, Mapping)
                    or binding_key.get("functionIdentity") != function_id
                    or binding_key.get("sourceDigest") != function.get("sourceDigest")
                    or not _same_source_file(
                        binding_key.get("sourceFile"), function.get("sourceFile"))
                    or candidate.get("candidateIdentity") != expected_candidate):
                reasons.add("L2_FRAGMENT_BINDING_KEY_MISMATCH")
        literals = static_operands(fragment) if candidate and candidate.get("expressionEvaluation") else {}
        if candidate and candidate.get("schemaVersion")=="riscv2x86.closed-compiler-fragment.v2" and not literals:
            reasons.add("L2_FRAGMENT_CANDIDATE_SCHEMA_UNSUPPORTED")
        raw_bindings = candidate.get("operandBindings") if candidate else None
        raw_carriers = candidate.get("operandCarriers") if candidate else None
        raw_nodes = candidate.get("valueNodes") if candidate else None
        raw_uses = candidate.get("downstreamUses") if candidate else None
        operand_authority = (raw_carriers if isinstance(raw_carriers, list)
                             else raw_bindings)
        if (not isinstance(outputs, list) or not isinstance(inputs, list)
                or not isinstance(operand_authority, list)
                or len(operand_authority)
                != len(outputs or ()) + len(inputs or ())):
            reasons.add("L2_FRAGMENT_OPERAND_ARITY_MISMATCH")
        output_bindings: list[OperandBinding] = []
        input_bindings: list[OperandBinding] = []
        node_ids: set[str] = set()
        if isinstance(raw_nodes, list):
            try:
                node_ids = {compiler_value_node_from_dict(item).node_identity
                            for item in raw_nodes if isinstance(item, Mapping) and item.get("nodeIdentity") not in {v["valueNodeIdentity"] for v in literals.values()}}
                node_ids.update(v["valueNodeIdentity"] for v in literals.values())
            except ValueError:
                reasons.add("L2_FRAGMENT_VALUE_NODE_INVALID")
        else:
            reasons.add("L2_FRAGMENT_VALUE_NODE_MISSING")
        if isinstance(operand_authority, list):
            for index, (operand, raw_operand) in enumerate(zip(
                    list(outputs or ()) + list(inputs or ()), operand_authority)):
                is_output = index < len(outputs or ())
                constraint = str(operand.get("constraint") or "") \
                    if isinstance(operand, Mapping) else ""
                expected_access = ("read_write"
                                   if is_output and constraint.startswith("+")
                                   else "output" if is_output else "input")
                try:
                    if index in literals:
                        b = raw_bindings[index]; literal = literals[index]
                        input_bindings.append(OperandBinding(index,'',b['valueNodeIdentity'],'input',
                            b['widthBits'],True,b['signedness'],literal))
                        if expected_access!='input':raise ValueError('literal output unsupported')
                        continue
                    if isinstance(raw_carriers, list):
                        parsed_carrier = compiler_operand_carrier_from_dict(
                            raw_operand)
                        parsed_index = parsed_carrier.operand_index
                        declaration_identity = (
                            parsed_carrier.declaration_identity)
                        value_node_identity = (
                            parsed_carrier.value_node_identity)
                        width_bits = parsed_carrier.width_bits
                        signedness = parsed_carrier.signedness
                        parsed_complete = parsed_carrier.complete
                    else:
                        parsed_binding = compiler_operand_binding_from_dict(
                            raw_operand)
                        parsed_index = parsed_binding.operand_index
                        declaration_identity = (
                            parsed_binding.declaration_identity)
                        value_node_identity = (
                            parsed_binding.value_node_identity)
                        width_bits = parsed_binding.width_bits
                        signedness = parsed_binding.signedness
                        parsed_complete = parsed_binding.complete
                        if parsed_binding.access != expected_access:
                            raise ValueError("operand access mismatch")
                except (TypeError, ValueError):
                    reasons.add("L2_FRAGMENT_VALUE_NODE_INVALID")
                    continue
                if (parsed_index != index
                        or value_node_identity not in node_ids):
                    reasons.add("L2_FRAGMENT_OPERAND_BINDING_MISMATCH")
                    continue
                binding = OperandBinding(
                    parsed_index, declaration_identity,
                    value_node_identity, expected_access, width_bits,
                    parsed_complete, signedness)
                (output_bindings if is_output else input_bindings).append(
                    binding)
        value_flow_edges: list[FragmentValueFlowEdge] = []
        sinks: list[ObservationSinkBinding] = []
        discarded: set[str] = set()
        instrumented: set[str] = set()
        output_node_ids = {
            item.value_node_identity for item in output_bindings
        }
        if isinstance(raw_uses, list):
            for raw_use in raw_uses:
                try:
                    use = compiler_downstream_use_from_dict(raw_use)
                except (TypeError, ValueError):
                    reasons.add("L2_FRAGMENT_DOWNSTREAM_USE_AMBIGUOUS"); continue
                # The compiler exports use facts for every ordered carrier.
                # Only frontend-classified outputs create live-out proof
                # obligations.
                if use.value_node_identity not in output_node_ids:
                    continue
                if not use.complete:
                    reasons.add("L2_FRAGMENT_DOWNSTREAM_USE_AMBIGUOUS"); continue
                consumer_fragment = ""
                consumer_node = use.use_node_identity
                if use.use_kind == "subsequent_asm_input":
                    consumer_fragments = candidate_fragments.get(
                        use.consumer_fragment_identity, set())
                    if len(consumer_fragments) != 1:
                        reasons.add("L2_FRAGMENT_CONSUMER_IDENTITY_CONFLICT"); continue
                    consumer_fragment = next(iter(consumer_fragments))
                    consumer_candidate, _reason, consumer_report_fragment = \
                        resolved.get(consumer_fragment, (None, "", {}))
                    raw_consumer_carriers = (
                        consumer_candidate.get("operandCarriers")
                        if isinstance(consumer_candidate, Mapping) else None)
                    raw_consumer_bindings = (
                        consumer_candidate.get("operandBindings")
                        if isinstance(consumer_candidate, Mapping) else None)
                    consumer_authority = (
                        raw_consumer_carriers
                        if isinstance(raw_consumer_carriers, list)
                        else raw_consumer_bindings)
                    consumer_outputs = consumer_report_fragment.get("outputs")
                    producer_decl = next((item.declaration_identity
                                          for item in output_bindings
                                          if item.value_node_identity == use.value_node_identity), "")
                    matches = []
                    if (isinstance(consumer_authority, list)
                            and isinstance(consumer_outputs, list)):
                        for item in consumer_authority:
                            try:
                                if isinstance(raw_consumer_carriers, list):
                                    parsed_consumer = compiler_operand_carrier_from_dict(item)
                                    is_input = parsed_consumer.operand_index >= len(consumer_outputs)
                                else:
                                    parsed_consumer = compiler_operand_binding_from_dict(item)
                                    is_input = parsed_consumer.access == "input"
                            except (TypeError, ValueError):
                                continue
                            if (is_input
                                    and parsed_consumer.declaration_identity == producer_decl):
                                matches.append(parsed_consumer.value_node_identity)
                    consumer_nodes = (consumer_candidate.get("valueNodes")
                                      if isinstance(consumer_candidate, Mapping) else None)
                    try:
                        consumer_literals = static_operands(consumer_report_fragment) if (
                            isinstance(consumer_candidate, Mapping) and consumer_candidate.get('expressionEvaluation')) else {}
                        static_ids = {v['valueNodeIdentity'] for v in consumer_literals.values()}
                        valid_nodes = {
                            compiler_value_node_from_dict(item).node_identity
                            for item in consumer_nodes
                            if isinstance(item, Mapping) and item.get('nodeIdentity') not in static_ids
                        } | static_ids if isinstance(consumer_nodes, list) else set()
                    except ValueError:
                        valid_nodes = set()
                    if (len(matches) != 1 or matches[0] not in valid_nodes
                            or use.relation_kind != "fragment_operand"):
                        reasons.add("L2_FRAGMENT_DOWNSTREAM_USE_AMBIGUOUS"); continue
                    consumer_node = matches[0]
                    graph_edges.append(FragmentDependencyEdge(
                        fragment_id, consumer_fragment, use.value_node_identity,
                        consumer_node))
                if use.use_kind in {"discarded", "dead"}:
                    discarded.add(use.value_node_identity)
                    continue
                edge = FragmentValueFlowEdge(
                    use.value_node_identity, consumer_node, fragment_id,
                    consumer_fragment, use.relation_kind,
                    use.observation_sink_identity, True)
                value_flow_edges.append(edge)
                sinks.append(ObservationSinkBinding(
                    use.observation_sink_identity, use.value_node_identity,
                    use.use_kind, True))
        else:
            reasons.add("L2_FRAGMENT_OBSERVATION_SINK_MISSING")
        # Enumeration completeness is not evidence that an unmentioned output
        # is dead.  The frontend must emit an explicit discarded/dead use;
        # otherwise the output remains an unproved live-out obligation.
        approval = finding_by_fragment[fragment_id].get("approvalArtifact")
        raw_internal = (approval.get("l2InternalValueProofFacts")
                        if isinstance(approval, Mapping) else None)
        if isinstance(raw_internal, Mapping):
            try:
                internal = internal_value_proof_facts_from_dict(raw_internal)
                if internal.fragment_id != fragment_id or not internal.complete:
                    raise ValueError("incomplete internal value proof")
                for point in internal.points:
                    matches = [item.value_node_identity for item in output_bindings
                               if item.operand_index == point.operand_index]
                    if len(matches) != 1:
                        raise ValueError("instrumentation operand mismatch")
                    instrumented.add(matches[0])
            except ValueError:
                reasons.add("L2_FRAGMENT_INSTRUMENTATION_PROOF_INVALID")
        accounted = ({item.value_node_identity for item in sinks}
                     | {item.producer_value_node for item in value_flow_edges
                        if item.consumer_fragment_id} | discarded | instrumented)
        if any(item.value_node_identity not in accounted for item in output_bindings):
            reasons.add("L2_FRAGMENT_LIVE_OUT_UNPROVED")
        live_out = tuple(sorted(({item.value_node_identity for item in sinks}
                                 | {item.producer_value_node for item in value_flow_edges
                                    if item.consumer_fragment_id})))
        boundaries[fragment_id] = FragmentOperandBoundary(
            program_id, function_id, fragment_id, tuple(input_bindings),
            tuple(output_bindings),
            tuple(sorted(item.value_node_identity for item in input_bindings)),
            live_out, not reasons, tuple(sorted(reasons)),
            tuple(sorted(value_flow_edges,
                         key=lambda item: (item.producer_value_node,
                                           item.consumer_value_node))),
            tuple(sorted(sinks, key=lambda item: item.sink_identity)),
            tuple(sorted(discarded)), tuple(sorted(instrumented)),
            STATIC_BOUNDARY_SCHEMA if literals else FRAGMENT_OPERAND_BOUNDARY_SCHEMA)

    edges = sorted(set(graph_edges), key=lambda item: (
        item.producer_fragment_id, item.consumer_fragment_id,
        item.value_node_identity, item.consumer_value_node_identity))
    graph_reasons = set()
    if not boundaries or any(not item.complete for item in boundaries.values()):
        graph_reasons.add("L2_FRAGMENT_BOUNDARY_INCOMPLETE")
    adjacency = {item: set() for item in boundaries}
    for edge in edges: adjacency[edge.producer_fragment_id].add(edge.consumer_fragment_id)
    visiting: set[str] = set(); visited: set[str] = set()
    def cycle(node: str) -> bool:
        if node in visiting: return True
        if node in visited: return False
        visiting.add(node)
        if any(cycle(next_node) for next_node in adjacency[node]): return True
        visiting.remove(node); visited.add(node); return False
    if any(cycle(node) for node in sorted(adjacency)):
        graph_reasons.add("L2_FRAGMENT_DEPENDENCY_CYCLE")
    mode = ("inconclusive" if graph_reasons else
            "composite" if edges else "shared_independent")
    graph = FragmentDependencyGraph(
        program_id, function_id, tuple(sorted(boundaries)), tuple(edges), mode,
        not graph_reasons, tuple(sorted(graph_reasons)))
    execution = ProgramExecutionAuthority(
        program_id, function_id, tuple(sorted(boundaries)), graph.graph_identity,
        mode, graph.complete, graph.reason_codes)
    return boundaries, graph, execution


def boundary_as_legacy(value: Mapping[str, object],
                       function_boundary: Mapping[str, object]) -> dict[str, object]:
    """Expose one fragment boundary to existing typed operand consumers."""
    inputs, outputs = value.get("inputBindings"), value.get("outputBindings")
    if not isinstance(inputs, list) or not isinstance(outputs, list):
        return {"complete": False}
    combined = outputs + inputs
    return {"schemaVersion": FRAGMENT_OPERAND_BOUNDARY_SCHEMA,
            "complete": value.get("complete") is True,
            "parameterDeclarationIds": list(function_boundary.get("parameterDeclarationIds", [])),
            "asmOperandDeclarationIds": [item.get("declarationIdentity") for item in combined],
            "asmOperandValueNodeIdentities": [item.get("valueNodeIdentity") for item in combined],
            "returnDeclarationId": function_boundary.get("returnDeclarationId", ""),
            "declarations": dict(function_boundary.get("declarations", {})),
            "declarationReferenceCounts": dict(function_boundary.get("declarationReferenceCounts", {})),
            "asmStatementEndOffset": function_boundary.get("asmStatementEndOffset", -1),
            # Object contracts remain function/harness-owned, while the value
            # nodes above are fragment-owned.  Keeping both in this adapter
            # lets typed consumers prove the join instead of falling back to
            # declaration names.
            "memoryObjectBindings": dict(function_boundary.get("memoryObjectBindings", {}))}


def fragment_boundary_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
) -> FragmentOperandBoundary:
    payload = dict(value); claimed = payload.pop("boundaryIdentity", None)
    if claimed != identity(payload):
        raise ValueError("fragment boundary identity does not match content")
    def bindings(name: str) -> tuple[OperandBinding, ...]:
        raw = value.get(name)
        if not isinstance(raw, list): raise ValueError("fragment bindings are missing")
        result = []
        for item in raw:
            if not isinstance(item, Mapping): raise ValueError("fragment binding is invalid")
            if "staticOperand" in item and not isinstance(item["staticOperand"],Mapping):raise ValueError("static fragment binding is invalid")
            result.append(OperandBinding(
                int(item.get("operandIndex", -1)), str(item.get("declarationIdentity") or ""),
                str(item.get("valueNodeIdentity") or ""), str(item.get("access") or ""),
                int(item.get("widthBits", 0)), item.get("complete") is True,
                str(item.get("signedness") or ""), item.get("staticOperand")))
        return tuple(result)
    reasons, live_in, live_out = (value.get("reasonCodes"), value.get("liveInNodes"),
                                  value.get("liveOutNodes"))
    discarded = value.get("discardedOutputNodes")
    instrumented = value.get("instrumentationObservedNodes")
    raw_edges, raw_sinks = value.get("valueFlowEdges"), value.get("observationSinks")
    if not all(isinstance(item, list) and all(isinstance(x, str) for x in item)
               for item in (reasons, live_in, live_out, discarded, instrumented)):
        raise ValueError("fragment boundary arrays are invalid")
    if not isinstance(raw_edges, list) or not isinstance(raw_sinks, list):
        raise ValueError("fragment boundary value-flow authority is missing")
    edges = []
    for item in raw_edges:
        if not isinstance(item, Mapping):
            raise ValueError("fragment value-flow edge is invalid")
        edges.append(FragmentValueFlowEdge(
            str(item.get("producerValueNode") or ""),
            str(item.get("consumerValueNode") or ""),
            str(item.get("producerFragmentId") or ""),
            str(item.get("consumerFragmentId") or ""),
            str(item.get("relationKind") or ""),
            str(item.get("observationSinkIdentity") or ""),
            item.get("complete") is True))
    sinks = []
    for item in raw_sinks:
        if not isinstance(item, Mapping):
            raise ValueError("fragment observation sink is invalid")
        sinks.append(ObservationSinkBinding(
            str(item.get("sinkIdentity") or ""),
            str(item.get("valueNodeIdentity") or ""),
            str(item.get("sinkKind") or ""), item.get("complete") is True))
    result = FragmentOperandBoundary(
        str(value.get("programId") or ""), str(value.get("functionId") or ""),
        str(value.get("fragmentId") or ""), bindings("inputBindings"),
        bindings("outputBindings"), tuple(live_in), tuple(live_out),
        value.get("complete") is True, tuple(reasons), tuple(edges), tuple(sinks),
        tuple(discarded), tuple(instrumented),
        str(value.get("schemaVersion") or ""))
    if expected_fragment_id and result.fragment_id != expected_fragment_id:
        raise ValueError("fragment boundary identity/binding mismatch")
    return result


def fragment_dependency_graph_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
) -> FragmentDependencyGraph:
    """Parse a content-addressed dependency graph without inferring edges.

    The graph is program authority.  Consumers must not reconstruct it from
    declaration names because distinct compiler value nodes may legitimately
    share one spelling.
    """
    payload = dict(value)
    claimed = payload.pop("graphIdentity", None)
    if claimed != identity(payload):
        raise ValueError("fragment dependency graph identity does not match content")
    members, raw_edges, reasons = (
        value.get("fragmentIds"), value.get("edges"), value.get("reasonCodes"))
    if (not isinstance(members, list) or not all(isinstance(item, str) for item in members)
            or not isinstance(raw_edges, list) or not isinstance(reasons, list)
            or not all(isinstance(item, str) for item in reasons)):
        raise ValueError("fragment dependency graph arrays are invalid")
    edges = []
    for item in raw_edges:
        if not isinstance(item, Mapping):
            raise ValueError("fragment dependency graph edge is invalid")
        edges.append(FragmentDependencyEdge(
            str(item.get("producerFragmentId") or ""),
            str(item.get("consumerFragmentId") or ""),
            str(item.get("valueNodeIdentity") or ""),
            str(item.get("consumerValueNodeIdentity") or ""),
        ))
    result = FragmentDependencyGraph(
        str(value.get("programId") or ""), str(value.get("functionId") or ""),
        tuple(members), tuple(edges), str(value.get("executionMode") or ""),
        value.get("complete") is True, tuple(reasons),
        str(value.get("schemaVersion") or ""),
    )
    if expected_fragment_id and expected_fragment_id not in result.fragment_ids:
        raise ValueError("fragment dependency graph does not contain fragment")
    return result


def program_execution_authority_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
) -> ProgramExecutionAuthority:
    payload = dict(value)
    claimed_execution = payload.pop("executionIdentity", None)
    claimed_authority = payload.pop("authorityIdentity", None)
    members, reasons = value.get("fragmentIds"), value.get("reasonCodes")
    if (not isinstance(members, list) or not isinstance(reasons, list)
            or not all(isinstance(item, str) for item in members + reasons)):
        raise ValueError("program execution authority arrays are invalid")
    result = ProgramExecutionAuthority(
        str(value.get("programId") or ""), str(value.get("functionId") or ""),
        tuple(members), str(value.get("dependencyGraphIdentity") or ""),
        str(value.get("executionMode") or ""), value.get("complete") is True,
        tuple(reasons), str(value.get("schemaVersion") or ""))
    if (claimed_authority != result.authority_identity
            or claimed_execution != result.execution_identity
            or (expected_fragment_id and expected_fragment_id not in result.fragment_ids)):
        raise ValueError("program execution authority identity/binding mismatch")
    return result
