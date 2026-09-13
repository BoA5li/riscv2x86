from __future__ import annotations

from types import SimpleNamespace

from riscv2x86_py.automatic_l2_effect import (
    _branch_events, _memory_events, _scalar_events, _shell_relation,
)


def _artifact():
    return SimpleNamespace(fragment_id="fragment", recipe_id="recipe",
                           proof_identity="proof", target_route="x86-fence",
                           runtime_contract_id="riscv2x86.runtime.none")


def test_memory_trace_is_object_relative_and_records_value_and_order():
    function = {"name": "load", "returnType": "uint64_t"}
    stdout = "\n".join((
        "load:return=8877665544332211",
        "load:object=[1122334455667788,8877665544332211,0123456789abcdef,fedcba9876543210]",
    ))
    events = _memory_events(stdout, function)
    assert events is not None
    assert events[0]["objectId"] == "arg:load:object"
    assert events[0]["offset"] == 8
    assert events[0]["value"] == "0x8877665544332211"
    assert events[0]["order"] == 0


def test_store_trace_rejects_multiple_unmodelled_writes():
    function = {"name": "store", "returnType": "void"}
    stdout = "store:object=[0000000000000000,0000000000000000,0123456789abcdef,fedcba9876543210]\n"
    assert _memory_events(stdout, function) is None


def test_branch_trace_records_continuation_class():
    function = {"name": "branch"}
    lines = []
    values = (
        0x1111111111111111, 0x3333333333333333, 0x5555555555555555,
        0x0123456789ABCDEF, 0x13579BDF2468ACE0, 0x7FFFFFFFFFFFFFFF,
        3, 7, 13, 19, 29,
    )
    for index, result in enumerate(values):
        lines.append(f"branch:case={index}:return={result:016x}")
    events = _branch_events("\n".join(lines), function)
    assert events is not None
    assert events[0]["branchTaken"] is True
    assert events[0]["continuation"] == "return-arg:2"


def test_scalar_continuation_trace_preserves_repeated_order():
    function = {"name": "jump", "arity": 1}
    lines = [f"operand_trace=jump;{value:016x};{value:016x}" for value in range(8)]
    events = _scalar_events("\n".join(lines), function)
    assert events is not None and len(events) == 8
    assert events[1]["continuationClasses"] == ["return-arg:0"]


def test_shell_relation_requires_approved_typed_recipe():
    finding = {"fragment":{"id":"fragment","isVolatile":True,"clobbers":["memory"]},
               "approvalArtifact":{"proofStatus":"approved",
                                   "architectureSemanticsPreserved":True,
                                   "shellSemanticsPreserved":True},
               "translationOutcome":"strengthened"}
    relation, reason = _shell_relation(finding, _artifact())
    assert reason == "" and relation is not None
    assert relation["source"] == {"volatile":True,"memoryClobber":True,"ccClobber":False}
    assert relation["relationKind"] == "strengthened"
