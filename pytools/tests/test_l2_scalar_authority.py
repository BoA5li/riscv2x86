from copy import deepcopy

import pytest

from riscv2x86_py.l2_scalar_authority import (
    assess_scalar_authority_materializability,
    scalar_authority_decision_from_dict,
)
from tests.l2_profile_fixtures import profile_dict


def _finding():
    return {
        "fragment": {"id": "fragment", "outputs": [{"constraint": "=r"}],
                     "inputs": [{"constraint": "r"}]},
        "l2SemanticProfile": profile_dict("fragment"),
        "approvalArtifact": {
            "proofStatus": "approved", "sourceModelId": "model",
            "preservationDecisionId": "decision", "planId": "plan",
            "constraintsId": "constraints", "targetEnvironmentId": "environment",
            "targetCatalogVersion": "catalog",
        },
    }


def _function():
    return {"arity": 1, "l2OperandBoundary": {"fragmentCandidates": [{}]}}


def _boundary():
    from riscv2x86_py.l2_fragment_execution import (
        FragmentOperandBoundary, ObservationSinkBinding, OperandBinding)
    out_node, in_node = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    sink = "sha256:" + "3" * 64
    result = FragmentOperandBoundary(
        "program", "function", "fragment",
        (OperandBinding(1, "lhs", in_node, "input", 64, True),),
        (OperandBinding(0, "out", out_node, "output", 64, True),),
        (in_node,), (out_node,), True, (), (),
        (ObservationSinkBinding(sink, out_node, "function_return", True),))
    return result.to_dict()


def test_complete_scalar_decision_is_content_addressed():
    decision = assess_scalar_authority_materializability(
        _finding(), _function(), _boundary())
    assert decision.materializable
    parsed = scalar_authority_decision_from_dict(
        decision.to_dict(), expected_fragment_id="fragment")
    assert parsed.decision_identity == decision.decision_identity


def test_decision_cannot_be_reused_for_another_fragment_or_modified():
    raw = assess_scalar_authority_materializability(
        _finding(), _function(), _boundary()).to_dict()
    with pytest.raises(ValueError, match="fragment mismatch"):
        scalar_authority_decision_from_dict(raw, expected_fragment_id="other")
    changed = deepcopy(raw); changed["materializable"] = False
    with pytest.raises(ValueError):
        scalar_authority_decision_from_dict(changed)


def test_missing_live_out_and_stale_proof_fail_closed_precisely():
    boundary = _boundary()
    boundary["liveOutNodes"] = []
    boundary["observationSinks"] = []
    boundary["complete"] = False
    boundary["reasonCodes"] = ["L2_FRAGMENT_LIVE_OUT_UNPROVED"]
    # Rebind content identity so this tests semantic completeness, not tampering.
    from riscv2x86_py.l2_fragment_execution import identity
    payload = dict(boundary); payload.pop("boundaryIdentity")
    boundary["boundaryIdentity"] = identity(payload)
    decision = assess_scalar_authority_materializability(
        _finding(), _function(), boundary)
    assert not decision.materializable
    assert "L2_SCALAR_LIVE_OUT_UNPROVED" in decision.reason_codes


def test_unknown_decision_schema_is_rejected():
    raw = assess_scalar_authority_materializability(
        _finding(), _function(), _boundary()).to_dict()
    raw["schemaVersion"] = "unknown"
    with pytest.raises(ValueError):
        scalar_authority_decision_from_dict(raw)
