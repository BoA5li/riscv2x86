from __future__ import annotations

from dataclasses import replace

import pytest

from riscv2x86_py.l2_fragment_execution import (
    FragmentOperandBoundary,
    FragmentValueFlowEdge,
    ObservationSinkBinding,
    OperandBinding,
    materialize_operand_observation_authority,
    operand_observation_authority_from_dict,
)


def _sha(digit: str) -> str:
    return "sha256:" + digit * 64


def _boundary(route: str) -> FragmentOperandBoundary:
    node = _sha("1")
    output = OperandBinding(0, "decl:out", node, "output", 64, True)
    edges = ()
    sinks = ()
    discarded = ()
    instrumented = ()
    if route == "sink":
        sinks = (ObservationSinkBinding(
            _sha("2"), node, "function_return", True),)
    elif route == "consumer":
        edges = (FragmentValueFlowEdge(
            node, _sha("3"), "fragment:producer", "fragment:consumer",
            "fragment_operand", _sha("4"), True),)
        # The frontend may also retain a subsequent-asm sink record.  It is
        # subordinate to the concrete fragment dependency and must not create
        # a second closure route.
        sinks = (ObservationSinkBinding(
            _sha("4"), node, "subsequent_asm_input", True),)
    elif route == "discard":
        discarded = (node,)
    elif route == "instrumentation":
        instrumented = (node,)
    else:
        raise AssertionError(route)
    return FragmentOperandBoundary(
        "program", "function", "fragment:producer", (), (output,), (),
        (node,) if route in {"sink", "consumer"} else (), True,
        value_flow_edges=edges, observation_sinks=sinks,
        discarded_output_nodes=discarded,
        instrumentation_observed_nodes=instrumented,
    )


@pytest.mark.parametrize(
    ("route", "expected"),
    (("sink", "sink"), ("consumer", "consumer"),
     ("discard", "discard"), ("instrumentation", "instrumentation")),
)
def test_each_scalar_output_has_one_content_addressed_closure(route, expected):
    authority = materialize_operand_observation_authority(
        _boundary(route), operand_ids={0: "operand:out"},
        proof_identity=_sha("5"), dependency_graph_identity=_sha("6"),
        instrumentation_plan_identity=(
            _sha("7") if route == "instrumentation" else ""),
    )
    assert authority.complete
    assert authority.bindings[0].closure_kind == expected
    encoded = authority.to_dict()
    assert encoded["authorityIdentity"].startswith("sha256:")
    assert encoded["bindings"][0]["bindingIdentity"].startswith("sha256:")
    assert operand_observation_authority_from_dict(
        encoded, expected_fragment_id="fragment:producer",
        expected_boundary_identity=_boundary(route).boundary_identity,
    ) == authority


def test_multiple_output_routes_are_rejected_as_ambiguous():
    boundary = _boundary("sink")
    boundary = replace(
        boundary,
        discarded_output_nodes=(boundary.output_bindings[0].value_node_identity,),
        complete=True,
    )
    with pytest.raises(ValueError, match="one observation route"):
        materialize_operand_observation_authority(
            boundary, operand_ids={0: "operand:out"},
            proof_identity=_sha("5"), dependency_graph_identity=_sha("6"),
        )


def test_authority_identity_detects_tampering():
    authority = materialize_operand_observation_authority(
        _boundary("sink"), operand_ids={0: "operand:out"},
        proof_identity=_sha("5"), dependency_graph_identity=_sha("6"),
    ).to_dict()
    authority["bindings"][0]["valueNodeIdentity"] = _sha("9")
    with pytest.raises(ValueError, match="identity is stale"):
        operand_observation_authority_from_dict(authority)


def test_missing_output_route_fails_closed():
    boundary = _boundary("sink")
    boundary = replace(boundary, observation_sinks=(), complete=False,
                       reason_codes=("L2_FRAGMENT_LIVE_OUT_UNPROVED",))
    with pytest.raises(ValueError, match="boundary is incomplete"):
        materialize_operand_observation_authority(
            boundary, operand_ids={0: "operand:out"},
            proof_identity=_sha("5"), dependency_graph_identity=_sha("6"),
        )
