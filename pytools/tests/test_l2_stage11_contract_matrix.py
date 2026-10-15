"""Independent contract oracles; no expected bindings built by production helpers."""
from copy import deepcopy

import pytest

from riscv2x86_py.canonical_l2_operand import bind_canonical_l2_operands
from riscv2x86_py.l2_authority import (
    PREVIOUS_L2_AUTHORITY_SIDECAR_SCHEMA, l2_authority_sidecar_from_dict,
    migrate_l2_authority_v2_to_v3,
)
from riscv2x86_py.l2_fragment_execution import (
    FragmentOperandBoundary, OperandBinding, ObservationSinkBinding,
    FragmentValueFlowEdge,
)
from riscv2x86_py.l2_effect_proof import identity
from tests.test_canonical_l2_operand import _proof
from tests.test_l2_typed_authority import _sidecar, _boundary


@pytest.mark.parametrize("mutation", ["empty", "non_sha", "unknown", "stale"])
def test_v3_negative_schema_matrix(mutation):
    raw = _sidecar().to_dict()
    if mutation == "unknown": raw["operands"][0]["unregisteredField"] = True
    elif mutation == "stale": raw["authorityIdentity"] = "sha256:" + "0" * 64
    else: raw["operands"][0]["valueNodeIdentity"] = "" if mutation == "empty" else "decl-value:lhs"
    with pytest.raises(ValueError):
        l2_authority_sidecar_from_dict(raw)


def test_v2_migration_rejects_ambiguous_value_nodes():
    raw = _sidecar().to_dict()
    raw["schemaVersion"] = PREVIOUS_L2_AUTHORITY_SIDECAR_SCHEMA
    raw["operands"][0].pop("valueNodeIdentity")
    raw.pop("authorityIdentity"); raw["authorityIdentity"] = identity(raw)
    boundary = _boundary()
    duplicate = deepcopy(boundary["inputBindings"][0])
    duplicate["valueNodeIdentity"] = "sha256:" + "a" * 64
    boundary["inputBindings"].append(duplicate)
    boundary.pop("boundaryIdentity"); boundary["boundaryIdentity"] = identity(boundary)
    with pytest.raises(ValueError, match="no unique"):
        migrate_l2_authority_v2_to_v3(raw, boundary)


@pytest.mark.parametrize("route", ["input-only", "output-only", "input-output", "read-write",
    "direct-return", "expression-return", "memory-sink", "control-predicate",
    "downstream-fragment", "discarded", "instrumentation"])
def test_canonical_join_access_and_sink_matrix(route):
    node = "sha256:" + "1" * 64
    incoming = "sha256:" + "2" * 64
    sink = "sha256:" + "3" * 64
    access = "read_write" if route == "read-write" else "output"
    outputs = () if route == "input-only" else (OperandBinding(0, "decl:out", node, access, 64, True),)
    inputs = ((OperandBinding(0 if route == "input-only" else 1, "decl:in", incoming, "input", 64, True),)
              if route in {"input-only", "input-output"} else ())
    sink_kind = {"expression-return": "c_expression", "memory-sink": "memory_store",
                 "control-predicate": "branch_condition"}.get(route, "function_return")
    sinks, edges, discarded, instrumented = (), (), (), ()
    if outputs:
        if route == "discarded": discarded = (node,)
        elif route == "instrumentation": instrumented = (node,)
        elif route == "downstream-fragment":
            edges = (FragmentValueFlowEdge(node, "sha256:" + "4" * 64,
                "fragment:1", "fragment:2", "fragment_operand", sink, True),)
        else: sinks = (ObservationSinkBinding(sink, node, sink_kind, True),)
    boundary = FragmentOperandBoundary("program", "function", "fragment:1", inputs, outputs,
        (incoming,) if inputs else (), (node,) if outputs else (), True,
        value_flow_edges=edges, observation_sinks=sinks,
        discarded_output_nodes=discarded, instrumentation_observed_nodes=instrumented)
    fragment = {"id": "fragment:1", "outputs": [
        {"constraint": "+r" if access == "read_write" else "=r", "symbolicName": "out"}
        for _ in outputs], "inputs": [{"constraint": "r", "symbolicName": "in"} for _ in inputs]}
    function = {"declarations": {"decl:out": {"name": "same", "type": "uint64_t"},
                                 "decl:in": {"name": "same", "type": "uint64_t"}},
                "parameterDeclarationIds": ["decl:out"] if route == "read-write" else ["decl:in"],
                "returnDeclarationId": "decl:out" if route == "direct-return" else ""}
    bound = bind_canonical_l2_operands(fragment, boundary.to_dict(), function, _proof())
    assert len(bound) == len(inputs) + len(outputs)
    assert [item.operand_index for item in bound] == list(range(len(bound)))
    if outputs:
        assert bound[0].declaration_identity == "decl:out"
        assert bound[0].value_node_identity == "sha256:" + "1" * 64
        assert bound[0].access_mode == access
    if inputs:
        assert bound[-1].declaration_identity == "decl:in"
        assert bound[-1].value_node_identity == "sha256:" + "2" * 64
    if route == "direct-return": assert bound[0].escape_kind == "function_return"
