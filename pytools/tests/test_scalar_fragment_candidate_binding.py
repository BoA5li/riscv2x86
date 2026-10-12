from __future__ import annotations

import pytest

from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
from riscv2x86_py.compiler_value_flow import (
    COMPILER_FRAGMENT_CANDIDATE_SCHEMA, COMPILER_VALUE_NODE_SCHEMA,
    CompilerOperandBinding, CompilerValueNode, identity,
)
from riscv2x86_py.l2_fragment_execution import (
    FragmentOperandBoundary, OperandBinding, _candidate_for,
    materialize_fragment_execution_authority,
)


def _candidate(source_file="/tmp/case.c", source_digest="sha256:" + "1" * 64):
    key = {
        "sourceDigest": source_digest,
        "sourceFile": source_file,
        "functionIdentity": "sha256:" + "2" * 64,
        "beginOffset": 24,
        "endOffset": 48,
        "beginLine": 5,
        "beginColumn": 5,
    }
    return {
        "candidateIdentity": identity({
            "schemaVersion": "riscv2x86.compiler-fragment-binding-key.v2",
            **key,
        }),
        "fragmentBindingKey": key,
    }


def test_frontend_fragment_location_resolves_exact_compiler_candidate():
    candidate = _candidate()
    function = {
        "name": "probe",
        "functionId": "sha256:" + "2" * 64,
        "sourceDigest": "sha256:" + "1" * 64,
    }
    fragment = {
        "id": "/tmp/case.c:5:5",
        "enclosingFunction": "probe",
    }

    resolved, reason = _candidate_for(fragment, [candidate], function)

    assert resolved is candidate
    assert reason == ""


def test_candidate_from_another_source_digest_is_rejected():
    candidate = _candidate(source_digest="sha256:" + "3" * 64)
    function = {
        "name": "probe",
        "functionId": "sha256:" + "2" * 64,
        "sourceDigest": "sha256:" + "1" * 64,
    }
    fragment = {
        "id": "/tmp/case.c:5:5",
        "enclosingFunction": "probe",
    }

    resolved, reason = _candidate_for(fragment, [candidate], function)

    assert resolved is None
    assert reason == "L2_FRAGMENT_CANDIDATE_IDENTITY_NOT_FOUND"


def _range(begin, end):
    return {
        "begin": {"offset": begin, "tokLen": 1},
        "end": {"offset": end - 1, "tokLen": 1},
    }


def _ref(identity_value, begin, end):
    return {
        "kind": "DeclRefExpr",
        "range": _range(begin, end),
        "referencedDecl": {"id": identity_value},
        "type": {"qualType": "uint64_t"},
    }


def test_read_write_output_keeps_authoritative_downstream_value_flow():
    source = b"void padding(void);\nuint64_t probe(uint64_t out) { asm; return out; }\n"
    function = {
        "kind": "FunctionDecl",
        "name": "probe",
        "range": _range(20, len(source)),
        "type": {"qualType": "uint64_t (uint64_t)"},
        "inner": [
            {
                "kind": "ParmVarDecl",
                "id": "out",
                "name": "out",
                "range": _range(35, 47),
                "type": {"qualType": "uint64_t"},
            },
            {
                "kind": "GCCAsmStmt",
                "range": _range(50, 54),
                "outputConstraints": ["+r"],
                "numOutputs": 1,
                "inner": [_ref("out", 51, 52)],
            },
            {
                "kind": "ReturnStmt",
                "range": _range(56, 66),
                "inner": [_ref("out", 63, 66)],
            },
        ],
    }

    facts = _l2_operand_boundary_facts(
        function,
        source_digest="sha256:" + "4" * 64,
        function_identity="sha256:" + "5" * 64,
        source_file="/tmp/read-write.c",
        source_bytes=source,
    )
    candidate = facts["fragmentCandidates"][0]

    assert candidate["complete"] is True
    assert candidate["reasonCodes"] == []
    assert candidate["operandCountAuthority"] == {
        "outputCount": 1,
        "inputCount": 0,
        "inputCountAuthority":
            "clang-operand-sequence-minus-output-partition",
    }
    assert len(candidate["operandBindings"]) == 1
    assert candidate["operandBindings"][0]["access"] == "read_write"
    assert [item["useKind"] for item in candidate["downstreamUses"]] == [
        "function_return"
    ]


def test_input_only_fragment_materializes_without_fabricated_output():
    source_digest = "sha256:" + "1" * 64
    function_identity = "sha256:" + "2" * 64
    candidate = _candidate(source_digest=source_digest)
    declaration_identity = "decl:input"
    ast_identity = identity({"ast": "input"})
    type_identity = identity({"type": "uint64_t"})
    node_identity = identity({
        "schemaVersion": COMPILER_VALUE_NODE_SCHEMA,
        "declarationIdentity": declaration_identity,
        "definingAstNodeIdentity": ast_identity,
        "definingFragmentId": candidate["candidateIdentity"],
        "typeIdentity": type_identity,
        "widthBits": 64,
        "signedness": "unsigned",
    })
    node = CompilerValueNode(
        node_identity, declaration_identity, ast_identity,
        candidate["candidateIdentity"], type_identity, 64, "unsigned", True)
    binding = CompilerOperandBinding(
        0, declaration_identity, node_identity, "input", 64, "unsigned", True)
    candidate.update({
        "schemaVersion": COMPILER_FRAGMENT_CANDIDATE_SCHEMA,
        "asmIndex": 0,
        "asmOperandDeclarationIds": [declaration_identity],
        "valueNodes": [node.to_dict()],
        "operandBindings": [binding.to_dict()],
        "downstreamUses": [],
        "complete": True,
    })
    function = {
        "name": "probe",
        "functionId": function_identity,
        "sourceDigest": source_digest,
        "sourceFile": "/tmp/case.c",
        "l2OperandBoundary": {
            "declarations": {
                declaration_identity: {"name": "input", "type": "uint64_t"},
            },
            "parameterDeclarationIds": [declaration_identity],
            "returnDeclarationId": "",
            "fragmentCandidates": [candidate],
        },
    }
    finding = {
        "fragment": {
            "id": "/tmp/case.c:5:5",
            "enclosingFunction": "probe",
            "outputs": [],
            "inputs": [{"constraint": "r"}],
        },
        "approvalArtifact": {},
    }

    boundaries, graph, execution = materialize_fragment_execution_authority(
        [finding], function, "program:test")
    boundary = boundaries["/tmp/case.c:5:5"]

    assert boundary.complete is True
    assert boundary.output_bindings == ()
    assert len(boundary.input_bindings) == 1
    assert graph.complete is True
    assert execution.complete is True



def test_non_operand_ast_children_do_not_shift_candidate_operand_indices():
    source = b"uint64_t probe(uint64_t input) { asm; return input; }\n"
    function = {
        "kind": "FunctionDecl",
        "name": "probe",
        "range": _range(0, len(source)),
        "type": {"qualType": "uint64_t (uint64_t)"},
        "inner": [
            {
                "kind": "ParmVarDecl", "id": "input", "name": "input",
                "range": _range(15, 29), "type": {"qualType": "uint64_t"},
            },
            {
                "kind": "GCCAsmStmt",
                "range": _range(32, 36),
                "outputConstraints": [],
                "inputConstraints": ["r"],
                "numOutputs": 0,
                "numInputs": 1,
                "inner": [
                    {"kind": "StringLiteral", "range": _range(32, 33),
                     "type": {"qualType": "const char[4]"}},
                    _ref("input", 34, 35),
                ],
            },
            {
                "kind": "ReturnStmt", "range": _range(38, 50),
                "inner": [_ref("input", 45, 50)],
            },
        ],
    }

    facts = _l2_operand_boundary_facts(
        function,
        source_digest="sha256:" + "4" * 64,
        function_identity="sha256:" + "5" * 64,
        source_file="/tmp/non-operand-child.c",
        source_bytes=source,
    )
    candidate = facts["fragmentCandidates"][0]

    assert candidate["complete"] is True
    assert candidate["reasonCodes"] == []
    assert candidate["operandCountAuthority"] == {
        "outputCount": 0,
        "inputCount": 1,
        "inputCountAuthority": "clang-input-constraints",
    }
    assert len(candidate["operandBindings"]) == 1
    assert candidate["operandBindings"][0]["operandIndex"] == 0
    assert candidate["operandBindings"][0]["access"] == "input"


def test_output_boundary_without_sink_remains_incomplete():
    node_identity = "sha256:" + "1" * 64
    binding = OperandBinding(
        0, "decl:output", node_identity, "output", 64, True, "unsigned")

    incomplete = FragmentOperandBoundary(
        "program:test", "function:test", "fragment:test",
        (), (binding,), (), (), False,
        ("L2_FRAGMENT_LIVE_OUT_UNPROVED",),
    )
    assert incomplete.complete is False

    with pytest.raises(
            ValueError,
            match="fragment operand boundary completeness is inconsistent"):
        FragmentOperandBoundary(
            "program:test", "function:test", "fragment:test",
            (), (binding,), (), (), True,
        )



def test_real_clang_shape_joins_pointer_carrier_with_frontend_roles():
    source = (
        b"#include <stdint.h>\n"
        b"uint64_t probe(const uint64_t *base) { "
        b"uint64_t out; asm; return out; }\n"
    )
    out_ref = _ref("out", 62, 65)
    base_ref = _ref("base", 67, 71)
    function = {
        "kind": "FunctionDecl",
        "name": "probe",
        "range": _range(20, len(source)),
        "type": {"qualType": "uint64_t (const uint64_t *)"},
        "inner": [
            {
                "kind": "ParmVarDecl", "id": "base", "name": "base",
                "range": _range(35, 55),
                "type": {"qualType": "const uint64_t *"},
            },
            {
                "kind": "VarDecl", "id": "out", "name": "out",
                "range": _range(56, 61),
                "type": {"qualType": "uint64_t"},
            },
            {
                # Clang 10 JSON AST shape: ordered expressions, but no
                # outputConstraints/inputConstraints/numOutputs/numInputs.
                "kind": "GCCAsmStmt",
                "range": _range(61, 72),
                "inner": [
                    out_ref,
                    {
                        "kind": "ImplicitCastExpr",
                        "range": _range(67, 71),
                        "type": {"qualType": "const uint64_t *"},
                        "inner": [base_ref],
                    },
                ],
            },
            {
                "kind": "ReturnStmt", "range": _range(73, 84),
                "inner": [_ref("out", 80, 83)],
            },
        ],
    }
    source_digest = "sha256:" + "6" * 64
    function_identity = "sha256:" + "7" * 64
    facts = _l2_operand_boundary_facts(
        function,
        source_digest=source_digest,
        function_identity=function_identity,
        source_file="/tmp/real-clang-shape.c",
        source_bytes=source,
    )
    candidate = facts["fragmentCandidates"][0]

    assert candidate["compilerStructureComplete"] is True
    assert candidate["operandClassificationComplete"] is False
    assert candidate["complete"] is True
    assert candidate["reasonCodes"] == []
    assert candidate["classificationReasonCodes"] == [
        "L2_FRAGMENT_OPERAND_CLASSIFICATION_DEFERRED"
    ]
    assert [item["carrierKind"] for item in candidate["operandCarriers"]] == [
        "integer", "pointer"
    ]
    assert [item["widthBits"] for item in candidate["operandCarriers"]] == [
        64, 64
    ]

    function_facts = {
        "name": "probe",
        "functionId": function_identity,
        "sourceDigest": source_digest,
        "sourceFile": "/tmp/real-clang-shape.c",
        "l2OperandBoundary": facts,
    }
    finding = {
        "fragment": {
            "id": "/tmp/real-clang-shape.c:2:42",
            "enclosingFunction": "probe",
            "outputs": [{"constraint": "=r"}],
            "inputs": [{"constraint": "r"}],
        },
        "approvalArtifact": {},
    }

    boundaries, graph, execution = materialize_fragment_execution_authority(
        [finding], function_facts, "program:test")
    boundary = boundaries["/tmp/real-clang-shape.c:2:42"]

    assert boundary.complete is True
    assert [item.access for item in boundary.output_bindings] == ["output"]
    assert [item.access for item in boundary.input_bindings] == ["input"]
    assert boundary.input_bindings[0].width_bits == 64
    assert graph.complete is True
    assert execution.complete is True
