from __future__ import annotations

from dataclasses import replace

import pytest

from riscv2x86_py.automatic_l2_operand import (
    L2OperandObservationError, _sample_observations,
)
from riscv2x86_py.l2_operand_observation_plan import CanonicalOperandObservationPlan
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


def _materializer_authority(*, access: str = "input", parameter_index=0):
    node = _sha("1")
    binding = OperandBinding(0, "decl:value", node, access, 64, True)
    boundary = FragmentOperandBoundary(
        "program", "function", "fragment", (binding,) if access == "input" else (),
        (binding,) if access != "input" else (), (),
        (node,) if access != "input" else (), True,
        observation_sinks=((ObservationSinkBinding(
            _sha("2"), node, "function_return", True),)
            if access != "input" else ()),
    )
    typed = materialize_operand_observation_authority(
        boundary, operand_ids={0: "operand:value"}, proof_identity=_sha("5"),
        dependency_graph_identity=_sha("6"),
        parameter_indices={0: parameter_index},
    )
    return CanonicalOperandObservationPlan(typed).to_dict()


def test_input_observation_consumes_typed_parameter_binding():
    samples = _sample_observations(
        ((7, 9),), _materializer_authority(), trace_arity=1)
    operand = samples[0]["logicalOperands"][0]
    assert operand["valueBefore"] == "0x0000000000000007"
    assert operand["valueAfter"] is None
    assert operand["observationKind"] == "function_parameter"
    assert operand["bindingIdentity"].startswith("sha256:")


def test_read_write_observation_materializes_before_and_after():
    samples = _sample_observations(
        ((7, 9),), _materializer_authority(access="read_write"),
        trace_arity=1)
    operand = samples[0]["logicalOperands"][0]
    assert operand["valueBefore"] == "0x0000000000000007"
    assert operand["valueAfter"] == "0x0000000000000009"
    assert operand["observationKind"] == "function_parameter+function_return"


def test_trace_arity_mismatch_has_precise_reason():
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(
            ((7,),), _materializer_authority(), trace_arity=1)
    assert caught.value.reason_code == "L2_OPERAND_TRACE_ARITY_MISMATCH"


def test_parameter_index_range_has_precise_reason():
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(
            ((7, 9),), _materializer_authority(parameter_index=1),
            trace_arity=1)
    assert caught.value.reason_code == "L2_OPERAND_PARAMETER_INDEX_OUT_OF_RANGE"


def _matrix_boundary(
    *, inputs=(), outputs=(), sink_kind="function_return", route="sink",
):
    input_bindings = tuple(
        OperandBinding(index, f"decl:in:{index}", _sha(str(index + 1)),
                       access, 64, True)
        for index, access in inputs
    )
    output_bindings = tuple(
        OperandBinding(index, f"decl:out:{index}", _sha(str(index + 1)),
                       access, 64, True)
        for index, access in outputs
    )
    sinks = ()
    edges = ()
    discarded = ()
    instrumented = ()
    if output_bindings and route == "sink":
        sinks = tuple(ObservationSinkBinding(
            _sha(str(8 - position)), item.value_node_identity,
            sink_kind, True,
        ) for position, item in enumerate(output_bindings))
    elif output_bindings and route == "consumer":
        item = output_bindings[0]
        edges = (FragmentValueFlowEdge(
            item.value_node_identity, _sha("7"), "fragment:matrix",
            "fragment:consumer", "fragment_operand", _sha("8"), True),)
    elif output_bindings and route == "discard":
        discarded = tuple(item.value_node_identity for item in output_bindings)
    elif output_bindings and route == "instrumentation":
        instrumented = tuple(item.value_node_identity for item in output_bindings)
    live = tuple(item.value_node_identity for item in output_bindings
                 if route in {"sink", "consumer"})
    return FragmentOperandBoundary(
        "program", "function", "fragment:matrix", input_bindings,
        output_bindings, tuple(item.value_node_identity
                               for item in input_bindings), live, True,
        value_flow_edges=edges, observation_sinks=sinks,
        discarded_output_nodes=discarded,
        instrumentation_observed_nodes=instrumented,
    )


@pytest.mark.parametrize(
    ("name", "inputs", "outputs", "parameters", "expected_access"),
    (
        ("input-only", ((0, "input"),), (), {0: 0}, ("input",)),
        ("output-only", (), ((0, "output"),), {}, ("output",)),
        ("input-output", ((0, "input"),), ((1, "output"),),
         {0: 0}, ("input", "output")),
        ("read-write", (), ((0, "read_write"),), {0: 0},
         ("read_write",)),
    ),
)
def test_operand_mode_matrix_closes_without_shape_guessing(
    name, inputs, outputs, parameters, expected_access,
):
    del name
    boundary = _matrix_boundary(inputs=inputs, outputs=outputs)
    operand_ids = {index: f"operand:{index}"
                   for index, _access in inputs + outputs}
    authority = materialize_operand_observation_authority(
        boundary, operand_ids=operand_ids, proof_identity=_sha("9"),
        dependency_graph_identity=_sha("8"), parameter_indices=parameters,
    )
    assert tuple(item.access for item in authority.bindings) == expected_access
    assert authority.complete


@pytest.mark.parametrize(
    ("sink_kind", "relation_kind"),
    (
        ("function_return", "direct-return"),
        ("c_expression", "expression-return"),
        ("memory_store", "memory-sink"),
        ("branch_condition", "control-predicate"),
    ),
)
def test_typed_output_sink_matrix_is_content_addressed(sink_kind, relation_kind):
    boundary = _matrix_boundary(
        outputs=((0, "output"),), sink_kind=sink_kind)
    authority = materialize_operand_observation_authority(
        boundary, operand_ids={0: "operand:0"}, proof_identity=_sha("9"),
        dependency_graph_identity=_sha("8"),
    )
    binding = authority.bindings[0]
    assert binding.closure_kind == "sink"
    assert binding.observation_kind == sink_kind
    assert binding.observation_sink_identity.startswith("sha256:")
    assert relation_kind


@pytest.mark.parametrize(
    ("route", "expected"),
    (("consumer", "consumer"), ("discard", "discard"),
     ("instrumentation", "instrumentation")),
)
def test_non_return_output_closure_matrix(route, expected):
    boundary = _matrix_boundary(outputs=((0, "output"),), route=route)
    authority = materialize_operand_observation_authority(
        boundary, operand_ids={0: "operand:0"}, proof_identity=_sha("9"),
        dependency_graph_identity=_sha("8"),
        instrumentation_plan_identity=(
            _sha("7") if route == "instrumentation" else ""),
    )
    assert authority.bindings[0].closure_kind == expected


def test_malformed_binding_is_rejected_before_observation():
    boundary = _matrix_boundary(inputs=((0, "input"),))
    with pytest.raises(ValueError, match="one observation source"):
        materialize_operand_observation_authority(
            boundary, operand_ids={0: "operand:0"},
            proof_identity=_sha("9"), dependency_graph_identity=_sha("8"),
        )


def test_typed_binding_identity_mismatch_has_precise_reason():
    authority = _materializer_authority()
    authority["operandObservationAuthority"]["bindings"][0]["valueNodeIdentity"] = _sha("7")
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(((7, 9),), authority, trace_arity=1)
    assert caught.value.reason_code == "L2_OPERAND_OBSERVATION_PLAN_INVALID"


@pytest.mark.parametrize("sink_kind", ("c_expression", "memory_store",
                                        "branch_condition"))
def test_non_runtime_sink_requires_registered_observer(sink_kind):
    boundary = _matrix_boundary(
        outputs=((0, "output"),), sink_kind=sink_kind)
    typed = materialize_operand_observation_authority(
        boundary, operand_ids={0: "operand:0"}, proof_identity=_sha("9"),
        dependency_graph_identity=_sha("8"),
    )
    authority = {
        "fragmentId": boundary.fragment_id,
        "fragmentBoundaryIdentity": boundary.boundary_identity,
        "operands": [{
            "operandIndex": 0, "operandId": "operand:0",
            "declarationId": "decl:out:0",
            "valueNodeIdentity": _sha("1"), "accessMode": "output",
            "widthBits": 64, "signedness": "unsigned",
        }],
        "operandObservationAuthority": typed.to_dict(),
        "instrumentationPlan": None,
    }
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(((9,),), CanonicalOperandObservationPlan(typed), trace_arity=0)
    assert caught.value.reason_code == \
        "L2_OPERAND_OUTPUT_SINK_NOT_RUNTIME_OBSERVABLE"
