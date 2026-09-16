from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py.automatic_l2_operand import _instrumented_pair, _internal_traces
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
from riscv2x86_py.l2_semantic_profile import L2PatternKind
from tests.l2_profile_fixtures import profile_dict
from riscv2x86_py.l2_internal_value import (
    L2CanonicalType,
    L2InstrumentationPlan,
    L2InstrumentationPoint,
    L2InternalValueProofFacts,
    L2InternalValueProofPoint,
    L2NonInterferenceProof,
    bind_instrumentation_plan,
    composite_slice_manifest,
    instrumentation_plan_from_dict,
    internal_value_proof_facts_from_source_model,
)


def _proof(**overrides: bool) -> L2NonInterferenceProof:
    values = dict(operand_allocation_preserved=True, memory_clobber_preserved=True,
                  control_flow_preserved=True, volatile_behavior_preserved=True,
                  internal_state_non_escaping=True,
                  equivalent_observation_boundary=True)
    values.update(overrides)
    return L2NonInterferenceProof(**values)


def _facts(proof: L2NonInterferenceProof | None = None) -> L2InternalValueProofFacts:
    proof = proof or _proof()
    return L2InternalValueProofFacts(
        "fragment:0",
        (L2InternalValueProofPoint("value:operand:0", 0, 0,
                                   L2CanonicalType("integer", 64, "unsigned")),
         L2InternalValueProofPoint("value:operand:1", 1, 1,
                                   L2CanonicalType("integer", 64, "unsigned"))),
        proof, proof.complete,
    )


def _boundary() -> dict[str, object]:
    return {"complete": True, "asmStatementEndOffset": 20,
            "asmOperandDeclarationIds": ["tmp-id", "out-id", "lhs-id"],
            "declarations": {
                "tmp-id": {"name": "tmp", "type": "uint64_t"},
                "out-id": {"name": "out", "type": "uint64_t"},
                "lhs-id": {"name": "lhs", "type": "uint64_t"},
            }}


def test_frontend_value_program_produces_stable_points() -> None:
    instructions = (SimpleNamespace(output_operand_index=0),
                    SimpleNamespace(output_operand_index=1))
    model = SimpleNamespace(
        value_program=SimpleNamespace(instructions=instructions, complete=True,
                                      width_bits=64),
        operands=SimpleNamespace(complete=True), shell=SimpleNamespace(),
        operation=SimpleNamespace(may_trap=False),
        control_flow=SimpleNamespace(has_nonlocal_control_flow=False),
        completeness=SimpleNamespace(cfg_ok=True),
    )
    facts = internal_value_proof_facts_from_source_model("fragment:0", model)
    assert facts is not None and facts.complete
    assert [item.logical_value_id for item in facts.points] == [
        "value:operand:0", "value:operand:1"]
    assert facts.facts_identity.startswith("sha256:")


def test_plan_binds_compiler_declarations_and_round_trips() -> None:
    plan = bind_instrumentation_plan(_facts(), _boundary())
    assert [item.declaration_name for item in plan.points] == ["tmp", "out"]
    assert instrumentation_plan_from_dict(plan.to_dict()) == plan
    changed = plan.to_dict()
    changed["points"][0]["declarationName"] = "other"
    with pytest.raises(ValueError, match="stale"):
        instrumentation_plan_from_dict(changed)


def test_missing_non_interference_proof_cannot_form_complete_plan() -> None:
    proof = _proof(volatile_behavior_preserved=False)
    facts = _facts(proof)
    assert not facts.complete
    with pytest.raises(ValueError, match="incomplete"):
        bind_instrumentation_plan(facts, _boundary())


def test_instrumentation_uses_authoritative_offsets_not_text_search(tmp_path: Path) -> None:
    source = tmp_path / "input.c"
    target = tmp_path / "target.c"
    original = b"void f(void){OLD;}\n"
    begin, end = original.index(b"OLD"), original.index(b"OLD") + 4
    replacement = "NEW_LONG"
    source.write_bytes(original)
    target.write_bytes(original[:begin] + replacement.encode() + original[end:])
    plan = bind_instrumentation_plan(_facts(), _boundary(), insertion_offset=end)
    report = {"findings": [{"fileName": str(source), "rewriteBeginOffset": begin,
                            "rewriteEndOffset": end,
                            "suggestedReplacement": replacement}]}
    left, right = _instrumented_pair(source, target, report, report["findings"][0],
                                     plan.to_dict(), tmp_path)
    assert b"__r2x_l2_observe(2" in left.read_bytes()
    assert b"__r2x_l2_observe(2" in right.read_bytes()
    assert right.read_bytes().rindex(b"__r2x_l2_observe") > right.read_bytes().index(b"NEW_LONG")


def test_internal_mismatch_is_visible_even_when_final_result_can_match() -> None:
    source = "internal_trace;0000000000000002;0000000000000004\n"
    target = "internal_trace;0000000000000003;0000000000000004\n"
    assert _internal_traces(source, 2) != _internal_traces(target, 2)


def test_composite_slices_share_one_execution_identity() -> None:
    execution = "sha256:" + "1" * 64
    manifest = composite_slice_manifest(
        "fragment:0", ["shell_semantics", "logical_operands"], execution)
    assert {item["executionIdentity"] for item in manifest["slices"]} == {execution}
    assert manifest["fragmentId"] == "fragment:0"


def test_plan_rejects_shell_changing_instrumentation_claim() -> None:
    proof = _proof(memory_clobber_preserved=False)
    point = L2InstrumentationPoint(
        "point:0:0", "fragment:0", "value:operand:0", "after_fragment",
        L2CanonicalType("integer", 64, "unsigned"), proof.proof_identity,
        "tmp-id", "tmp", 0,
    )
    with pytest.raises(ValueError, match="non-interference"):
        L2InstrumentationPlan("fragment:0", 10, (point,), proof,
                              "sha256:" + "2" * 64, True)


def test_composite_authority_contains_internal_values_and_bound_plan(tmp_path: Path) -> None:
    boundary = _boundary()
    boundary.update({
        "parameterDeclarationIds": ["lhs-id"],
        "returnDeclarationId": "out-id",
        "declarationReferenceCounts": {"tmp-id": 1, "out-id": 2, "lhs-id": 1},
    })
    function = {"name": "sequence", "arity": 1, "returnType": "uint64_t",
                "parameterTypes": ["uint64_t"], "l2OperandBoundary": boundary}
    finding = {
        "rewriteEndOffset": 20,
        "fragment": {"id": "fragment:0", "enclosingFunction": "sequence",
                     "outputs": [{"constraint": "=&r", "symbolicName": "tmp"},
                                 {"constraint": "=r", "symbolicName": "out"}],
                     "inputs": [{"constraint": "r", "symbolicName": "lhs"}]},
        "l2SemanticProfile": profile_dict("fragment:0", L2PatternKind.COMPOSITE),
        "approvalArtifact": {
            "proofStatus": "approved", "architectureSemanticsPreserved": True,
            "shellSemanticsPreserved": True, "sourceModelId": "model",
            "constraintsId": "constraints", "preservationDecisionId": "decision",
            "planId": "plan", "targetEnvironmentId": "environment",
            "targetCatalogVersion": "catalog",
            "l2InternalValueProofFacts": _facts().to_dict(),
        },
    }
    frontend = tmp_path / "frontend"
    frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": [finding]}, [function], frontend) == 1
    approval = finding["approvalArtifact"]
    assert approval["l2InstrumentationPlan"]["complete"] is True
    sidecar = l2_authority_sidecar_from_dict(approval["l2AuthoritySidecar"])
    assert len(sidecar.internal_values) == 2
    assert {item.escape_kind for item in sidecar.internal_values} == {
        "non_escaping", "operand"}
    assert any(
        item.logical_subject.endswith(approval["l2InstrumentationPlan"]["planIdentity"])
        for item in sidecar.source_effects
    )
