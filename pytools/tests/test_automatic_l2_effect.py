from __future__ import annotations

from types import SimpleNamespace

from riscv2x86_py.automatic_l2_effect import (
    _branch_events, _build_failure_detail, _memory_events,
    _object_relative_memory_wrapper, _scalar_events, _shell_relation,
)
from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.l2_authority import (
    L2AuthorityProducer, L2AuthoritySidecar, L2SourceEffectAuthority,
)
from hashlib import sha256
import subprocess


def _digest(value):
    return "sha256:" + sha256(value.encode()).hexdigest()


def _artifact():
    relation = ApprovedEffectRelation(
        "relation:fence:0", "source-effect:0", ("target-effect:0",),
        "strengthened", ("compiler_ordering", "hardware_ordering", "kind"),
        (), "", True,
    )
    sidecar = L2AuthoritySidecar(
        "fragment", L2AuthorityProducer(
            "translation-proof-sidecar", "phase6d", "v1", _digest("producer"),
        ), _digest("shell"), (), (),
        (L2SourceEffectAuthority("source-effect:0", "fence", "ordering", True),),
        (relation,), (), (), True,
    )
    return SimpleNamespace(
        fragment_id="fragment", recipe_id="recipe", proof_identity=_digest("proof"),
        target_route="x86-fence", runtime_contract_id="riscv2x86.runtime.none",
        runtime_contract_version="v1", shell_facts_identity=_digest("shell"),
        l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity,
        sidecar=sidecar,
    )


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


def _memory_authority():
    return {"memoryObjects": [{"sizeBytes": 32}]}


def test_pointer_only_load_harness_does_not_emit_unused_sample_values():
    function = {"name": "read_word", "returnType": "uint64_t",
                "parameterTypes": ["const uint64_t *"], "pointerParameters": [0]}
    facts = SimpleNamespace(access_kind="load", byte_offset=0, width_bytes=8)
    wrapper = _object_relative_memory_wrapper(function, _memory_authority(), facts)
    assert "static const uint64_t values" not in wrapper


def test_zero_offset_store_harness_avoids_unsigned_less_than_zero():
    function = {"name": "write_word", "returnType": "void",
                "parameterTypes": ["uint64_t *", "uint64_t"],
                "pointerParameters": [0]}
    facts = SimpleNamespace(access_kind="store", byte_offset=0, width_bytes=8)
    wrapper = _object_relative_memory_wrapper(function, _memory_authority(), facts)
    assert "i<0" not in wrapper
    assert "i>=8" in wrapper


def test_effect_build_failure_preserves_side_and_compiler_diagnostics():
    source = subprocess.CompletedProcess(("rvcc",), 1, "source-out", "source-error")
    target = subprocess.CompletedProcess(("cc",), 0, "", "")
    detail = _build_failure_detail(source, target)
    assert detail["reasonCode"] == "L2_EFFECT_HARNESS_SOURCE_BUILD_FAILED"
    assert detail["source"] == {
        "returnCode": 1, "stderr": "source-error", "stdout": "source-out"}
    assert detail["target"]["returnCode"] == 0


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
    artifact = _artifact()
    finding = {"fragment":{"id":"fragment","isVolatile":True,"clobbers":["memory"]},
               "approvalArtifact":{"proofStatus":"approved", "proofIdentity":artifact.proof_identity,
                                   "architectureSemanticsPreserved":True,
                                   "shellSemanticsPreserved":True,
                                   "l2AuthoritySidecar":artifact.sidecar.to_dict()},
               "translationOutcome":"strengthened"}
    relation, reason = _shell_relation(finding, artifact)
    assert reason == "" and relation is not None
    assert relation["relations"][0]["relationKind"] == "strengthened"


def test_route_and_helper_text_never_create_an_approved_relation():
    artifact = _artifact()
    artifact.target_route = "looks-like-strengthened-fence-runtime-helper"
    relation, reason = _shell_relation({
        "fragment": {"id": "fragment"},
        "approvalArtifact": {"proofStatus": "approved"},
        "translationOutcome": "strengthened",
    }, artifact)
    assert relation is None
    assert reason == "L2_EFFECT_APPROVED_RELATION_MISSING"
