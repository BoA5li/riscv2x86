"""Compiler-owned per-fragment operand flow and shared execution authority."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence


FRAGMENT_OPERAND_BOUNDARY_SCHEMA = "riscv2x86.fragment-operand-boundary.v1"
FRAGMENT_DEPENDENCY_GRAPH_SCHEMA = "riscv2x86.fragment-dependency-graph.v1"
PROGRAM_EXECUTION_AUTHORITY_SCHEMA = "riscv2x86.fragment-program-execution-authority.v1"
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

    def __post_init__(self) -> None:
        if (isinstance(self.operand_index, bool) or self.operand_index < 0
                or not self.declaration_identity or not self.value_node_identity
                or self.access not in {"input", "output", "read_write"}
                or self.width_bits <= 0 or self.complete is not True):
            raise ValueError("fragment operand binding is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"operandIndex": self.operand_index,
                "declarationIdentity": self.declaration_identity,
                "valueNodeIdentity": self.value_node_identity,
                "access": self.access, "widthBits": self.width_bits,
                "complete": self.complete}


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
    schema_version: str = FRAGMENT_OPERAND_BOUNDARY_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != FRAGMENT_OPERAND_BOUNDARY_SCHEMA
                or not self.program_id or not self.function_id or not self.fragment_id
                or self.live_in_nodes != tuple(sorted(set(self.live_in_nodes)))
                or self.live_out_nodes != tuple(sorted(set(self.live_out_nodes)))
                or self.reason_codes != tuple(sorted(set(self.reason_codes)))):
            raise ValueError("fragment operand boundary identity is invalid")
        bindings = self.output_bindings + self.input_bindings
        indices = tuple(item.operand_index for item in bindings)
        if len(indices) != len(set(indices)):
            raise ValueError("fragment operand boundary indices are duplicated")
        closed = bool(bindings and self.output_bindings and not self.reason_codes
                      and all(item.complete for item in bindings))
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
                 "reasonCodes": list(self.reason_codes)}
        if include_identity:
            value["boundaryIdentity"] = self.boundary_identity
        return value


@dataclass(frozen=True)
class FragmentDependencyEdge:
    producer_fragment_id: str
    consumer_fragment_id: str
    value_node_identity: str

    def to_dict(self) -> dict[str, str]:
        return {"producerFragmentId": self.producer_fragment_id,
                "consumerFragmentId": self.consumer_fragment_id,
                "valueNodeIdentity": self.value_node_identity}


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
                           item.value_node_identity) for item in self.edges)
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


def _candidate_for(fragment: Mapping[str, object], candidates: Sequence[Mapping[str, object]]) -> tuple[Mapping[str, object] | None, bool]:
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    direct = [item for item in candidates if item.get("fragmentId") == fragment_id]
    if len(direct) == 1:
        return direct[0], False
    if len(direct) > 1:
        return None, True
    begin, end = fragment.get("beginOffset"), fragment.get("endOffset")
    if (isinstance(begin, int) and not isinstance(begin, bool)
            and isinstance(end, int) and not isinstance(end, bool)):
        overlaps = [item for item in candidates
                    if isinstance(item.get("beginOffset"), int)
                    and isinstance(item.get("endOffset"), int)
                    and int(item["beginOffset"]) <= begin
                    and end <= int(item["endOffset"])]
        if len(overlaps) == 1:
            return overlaps[0], False
        if len(overlaps) > 1:
            return None, True
    return None, False


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
    boundaries: dict[str, FragmentOperandBoundary] = {}
    for _finding, fragment in scoped:
        fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
        outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
        candidate, ambiguous = _candidate_for(
            fragment, [item for item in candidates if isinstance(item, Mapping)])
        reasons: set[str] = set()
        asm_ids = candidate.get("asmOperandDeclarationIds") if candidate else None
        if candidate is None:
            reasons.add("L2_FRAGMENT_BOUNDARY_RANGE_AMBIGUOUS" if ambiguous
                        else "L2_FRAGMENT_BOUNDARY_BINDING_MISSING")
            asm_ids = []
        if (not isinstance(outputs, list) or not isinstance(inputs, list)
                or not isinstance(asm_ids, list)
                or len(asm_ids) != len(outputs or ()) + len(inputs or ())):
            reasons.add("L2_FRAGMENT_OPERAND_ARITY_MISMATCH")
        if not isinstance(outputs, list) or not outputs:
            reasons.add("L2_FRAGMENT_OUTPUT_BINDING_MISSING")
        output_bindings: list[OperandBinding] = []
        input_bindings: list[OperandBinding] = []
        if not reasons:
            for index, (operand, declaration_id) in enumerate(zip(
                    list(outputs or ()) + list(inputs or ()), asm_ids)):
                declaration = declarations.get(declaration_id)
                width = _width(declaration.get("type")) if isinstance(declaration, Mapping) else 0
                if not isinstance(operand, Mapping) or not declaration_id or not width:
                    reasons.add("L2_FRAGMENT_VALUE_NODE_MISSING"); continue
                is_output = index < len(outputs or ())
                constraint = str(operand.get("constraint") or "")
                access = ("read_write" if is_output and constraint.startswith("+")
                          else "output" if is_output else "input")
                binding = OperandBinding(index, str(declaration_id),
                    "decl-value:" + str(declaration_id), access, width, True)
                (output_bindings if is_output else input_bindings).append(binding)
        boundaries[fragment_id] = FragmentOperandBoundary(
            program_id, function_id, fragment_id, tuple(input_bindings),
            tuple(output_bindings),
            tuple(sorted(item.value_node_identity for item in input_bindings)), (),
            False, tuple(sorted(reasons or {"L2_FRAGMENT_LIVE_OUT_UNPROVED"})))

    # A produced value is live-out only when returned or consumed by another
    # fragment. Declaration identity, never spelling, establishes the edge.
    consumers: dict[str, list[str]] = {}
    for fragment_id, boundary in boundaries.items():
        for item in boundary.input_bindings:
            consumers.setdefault(item.declaration_identity, []).append(fragment_id)
    rebuilt: dict[str, FragmentOperandBoundary] = {}
    for fragment_id, boundary in boundaries.items():
        live_out = tuple(sorted(item.value_node_identity for item in boundary.output_bindings
                                if item.declaration_identity == returned
                                or consumers.get(item.declaration_identity)))
        reasons = set(boundary.reason_codes) - {"L2_FRAGMENT_LIVE_OUT_UNPROVED"}
        if any(item.value_node_identity not in live_out for item in boundary.output_bindings):
            reasons.add("L2_FRAGMENT_LIVE_OUT_UNPROVED")
        rebuilt[fragment_id] = FragmentOperandBoundary(
            boundary.program_id, boundary.function_id, boundary.fragment_id,
            boundary.input_bindings, boundary.output_bindings, boundary.live_in_nodes,
            live_out, not reasons, tuple(sorted(reasons)))
    boundaries = rebuilt
    edges = []
    for producer_id, boundary in boundaries.items():
        for output in boundary.output_bindings:
            for consumer_id in consumers.get(output.declaration_identity, ()):
                if consumer_id != producer_id:
                    edges.append(FragmentDependencyEdge(
                        producer_id, consumer_id, output.value_node_identity))
    edges = sorted(edges, key=lambda item: (item.producer_fragment_id,
                                            item.consumer_fragment_id,
                                            item.value_node_identity))
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
            "returnDeclarationId": function_boundary.get("returnDeclarationId", ""),
            "declarations": dict(function_boundary.get("declarations", {})),
            "declarationReferenceCounts": dict(function_boundary.get("declarationReferenceCounts", {})),
            "asmStatementEndOffset": function_boundary.get("asmStatementEndOffset", -1)}


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
            result.append(OperandBinding(
                int(item.get("operandIndex", -1)), str(item.get("declarationIdentity") or ""),
                str(item.get("valueNodeIdentity") or ""), str(item.get("access") or ""),
                int(item.get("widthBits", 0)), item.get("complete") is True))
        return tuple(result)
    reasons, live_in, live_out = (value.get("reasonCodes"), value.get("liveInNodes"),
                                  value.get("liveOutNodes"))
    if not all(isinstance(item, list) and all(isinstance(x, str) for x in item)
               for item in (reasons, live_in, live_out)):
        raise ValueError("fragment boundary arrays are invalid")
    result = FragmentOperandBoundary(
        str(value.get("programId") or ""), str(value.get("functionId") or ""),
        str(value.get("fragmentId") or ""), bindings("inputBindings"),
        bindings("outputBindings"), tuple(live_in), tuple(live_out),
        value.get("complete") is True, tuple(reasons),
        str(value.get("schemaVersion") or ""))
    if expected_fragment_id and result.fragment_id != expected_fragment_id:
        raise ValueError("fragment boundary identity/binding mismatch")
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
