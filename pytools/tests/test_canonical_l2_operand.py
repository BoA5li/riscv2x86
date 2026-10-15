from copy import deepcopy

import pytest

from riscv2x86_py.canonical_l2_operand import (
    bind_canonical_l2_operands, canonical_l2_operand_binding_set,
    canonical_l2_operand_bindings_from_dict,
)
from riscv2x86_py.l2_effect_proof import (
    EffectRelationFact, L2EffectProofFacts, ShellRelationFact,
    SourceEffectFact, TargetEffectFact, identity,
)
from riscv2x86_py.l2_fragment_execution import (
    FragmentOperandBoundary, FragmentValueFlowEdge, OperandBinding,
)


def _proof(fragment_id="fragment:1"):
    source = SourceEffectFact("effect:source", "Scalar", "operand", True)
    target = TargetEffectFact("effect:target", "Scalar", "operand", True)
    relation = EffectRelationFact(
        "relation:scalar", source.effect_id, (target.effect_id,), "exact",
        ("value",), (), "", "", True)
    shell = ShellRelationFact(
        (), (), (), (), True, True, True, True, True, True)
    return L2EffectProofFacts(
        fragment_id, identity({"proof": fragment_id}), "plan", "constraints",
        identity({"renderer": fragment_id}), (source,), (target,),
        (relation,), shell, True).to_dict()


def _function(declarations, parameters=(), returned=""):
    return {
        "declarations": declarations,
        "parameterDeclarationIds": list(parameters),
        "returnDeclarationId": returned,
    }


def _boundary(inputs=(), outputs=(), edges=(), *, fragment_id="fragment:1"):
    live_in = tuple(item.value_node_identity for item in inputs)
    live_out = tuple(item.value_node_identity for item in outputs)
    discarded = tuple(item.value_node_identity for item in outputs) if not edges else ()
    return FragmentOperandBoundary(
        "program:1", "function:1", fragment_id, tuple(inputs), tuple(outputs),
        live_in, live_out, True, (), tuple(edges), (), discarded, (),
    ).to_dict()


def _node(fill):
    return "sha256:" + fill * 64


def test_output_input_join_is_indexed_and_content_bound():
    fragment = {
        "id": "fragment:1",
        "outputs": [{"constraint": "=r", "symbolicName": "dst"}],
        "inputs": [{"constraint": "r", "symbolicName": "src"}],
    }
    boundary = _boundary(
        inputs=(OperandBinding(1, "decl:src", _node("2"), "input", 64,
                               True, "unsigned"),),
        outputs=(OperandBinding(0, "decl:dst", _node("1"), "output", 64,
                                True, "unsigned"),),
    )
    result = bind_canonical_l2_operands(
        fragment, boundary,
        _function({"decl:dst": {"name": "out", "type": "uint64_t"},
                   "decl:src": {"name": "in", "type": "uint64_t"}},
                  ("decl:src",), "decl:dst"), _proof())
    assert [item.operand_index for item in result] == [0, 1]
    assert result[0].value_node_identity == _node("1")
    assert result[0].escape_kind == "function_return"
    assert result[1].parameter_index == 0


def test_read_write_is_one_logical_carrier_and_not_silently_split():
    fragment = {"id": "fragment:1",
                "outputs": [{"constraint": "+r", "symbolicName": "acc"}],
                "inputs": []}
    boundary = _boundary(outputs=(OperandBinding(
        0, "decl:acc", _node("3"), "read_write", 64, True, "unsigned"),))
    result = bind_canonical_l2_operands(
        fragment, boundary,
        _function({"decl:acc": {"name": "acc", "type": "uint64_t"}},
                  ("decl:acc",)), _proof())
    assert len(result) == 1
    assert result[0].access_mode == "read_write"
    assert result[0].value_node_identity == _node("3")


def test_tied_operand_references_existing_canonical_operand():
    fragment = {
        "id": "fragment:1",
        "outputs": [{"constraint": "=r", "symbolicName": "dst"}],
        "inputs": [{"constraint": "0", "symbolicName": "src"}],
    }
    boundary = _boundary(
        inputs=(OperandBinding(1, "decl:src", _node("5"), "input", 64,
                               True, "unsigned"),),
        outputs=(OperandBinding(0, "decl:dst", _node("4"), "output", 64,
                                True, "unsigned"),),
    )
    result = bind_canonical_l2_operands(
        fragment, boundary,
        _function({"decl:dst": {"name": "dst", "type": "uint64_t"},
                   "decl:src": {"name": "src", "type": "uint64_t"}},
                  ("decl:src",), "decl:dst"), _proof())
    assert result[1].tied_to_operand_id == result[0].operand_id


@pytest.mark.parametrize("field,value,match", [
    ("declarationIdentity", "decl:other", "declaration join"),
    ("access", "read_write", "access join"),
    ("widthBits", 32, "width join"),
    ("signedness", "signed", "signedness join"),
])
def test_typed_boundary_mismatch_fails_closed(field, value, match):
    fragment = {"id": "fragment:1", "outputs": [],
                "inputs": [{"constraint": "r", "symbolicName": "src"}]}
    boundary = _boundary(inputs=(OperandBinding(
        0, "decl:src", _node("6"), "input", 64, True, "unsigned"),))
    broken = deepcopy(boundary)
    broken["inputBindings"][0][field] = value
    unsigned = dict(broken); unsigned.pop("boundaryIdentity")
    broken["boundaryIdentity"] = identity(unsigned)
    with pytest.raises(ValueError, match=match):
        bind_canonical_l2_operands(
            fragment, broken,
            _function({"decl:src": {"name": "same-name", "type": "uint64_t"}},
                      ("decl:src",)), _proof())


def test_downstream_fragment_edge_is_value_node_bound_not_declaration_bound():
    producer = OperandBinding(
        0, "decl:shared", _node("7"), "output", 64, True, "unsigned")
    edge = FragmentValueFlowEdge(
        _node("7"), _node("8"), "fragment:1", "fragment:2",
        "fragment_operand", _node("9"), True)
    boundary = _boundary(outputs=(producer,), edges=(edge,))
    result = bind_canonical_l2_operands(
        {"id": "fragment:1",
         "outputs": [{"constraint": "=r", "symbolicName": "out"}],
         "inputs": []}, boundary,
        _function({"decl:shared": {"name": "x", "type": "uint64_t"}},
                  (), ""), _proof())
    assert result[0].value_node_identity == edge.producer_value_node
    assert edge.consumer_value_node != result[0].value_node_identity


def test_phase6d_fragment_mismatch_fails_closed():
    with pytest.raises(ValueError, match="Phase 6D"):
        bind_canonical_l2_operands(
            {"id": "fragment:1", "outputs": [],
             "inputs": [{"constraint": "r"}]},
            _boundary(inputs=(OperandBinding(
                0, "decl:src", _node("a"), "input", 64, True, "unsigned"),)),
            _function({"decl:src": {"name": "src", "type": "uint64_t"}},
                      ("decl:src",)), _proof("fragment:other"))


def test_binding_set_is_content_addressed_and_proof_bound():
    binding = bind_canonical_l2_operands(
        {"id": "fragment:1", "outputs": [],
         "inputs": [{"constraint": "r", "symbolicName": "src"}]},
        _boundary(inputs=(OperandBinding(
            0, "decl:src", _node("b"), "input", 64, True, "unsigned"),)),
        _function({"decl:src": {"name": "src", "type": "uint64_t"}},
                  ("decl:src",)), _proof())[0]
    proof_identity = _proof()["proofIdentity"]
    encoded = canonical_l2_operand_binding_set(
        (binding,), proof_identity=proof_identity)
    assert canonical_l2_operand_bindings_from_dict(
        encoded, expected_fragment_id="fragment:1",
        expected_proof_identity=proof_identity) == (binding,)
    tampered = deepcopy(encoded)
    tampered["bindings"][0]["valueNodeIdentity"] = _node("c")
    with pytest.raises(ValueError, match="identity"):
        canonical_l2_operand_bindings_from_dict(tampered)
