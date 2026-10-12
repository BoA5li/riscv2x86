from __future__ import annotations

from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.l2_fragment_execution import _candidate_for


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
            "schemaVersion": "riscv2x86.compiler-fragment-binding-key.v1",
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
    assert candidate["operandBindings"][0]["access"] == "read_write"
    assert [item["useKind"] for item in candidate["downstreamUses"]] == [
        "function_return"
    ]
