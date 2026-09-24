from copy import deepcopy

import pytest

from riscv2x86_py.l2_dimensions import L2Dimension
from riscv2x86_py.l2_materialization import assess_fragment_l2_materializability
from riscv2x86_py.l2_semantic_profile import L2PatternKind
from tests.l2_materialization_fixtures import attach_complete_scalar_authority
from tests.l2_profile_fixtures import profile_dict


def _finding():
    finding = {
        "translationOutcome": "emitted",
        "translationReasonCodes": [],
        "fragment": {"id": "fragment:closure", "inputs": [{"name": "lhs"}],
                     "outputs": [{"name": "out"}], "clobbers": []},
        "l2SemanticProfile": profile_dict(
            "fragment:closure", L2PatternKind.SCALAR),
    }
    return attach_complete_scalar_authority(finding)


def test_complete_authority_closes_boundary_relation_shell_and_execution():
    decision = assess_fragment_l2_materializability(_finding())
    assert decision.boundary_complete
    assert decision.relation_complete
    assert decision.shell_complete
    assert decision.executable
    assert decision.reason_codes == ()
    assert decision.required_dimensions == (
        L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS)


@pytest.mark.parametrize("removed,reason", [
    ("l2AuthoritySidecar", "L2_FRAGMENT_AUTHORITY_SIDECAR_MISSING"),
    ("l2EffectProofFacts", "L2_FRAGMENT_SHELL_PROOF_MISSING"),
])
def test_missing_authority_component_is_rejected_before_execution(removed, reason):
    finding = _finding()
    finding["approvalArtifact"].pop(removed)
    decision = assess_fragment_l2_materializability(finding)
    assert not decision.executable
    assert reason in decision.reason_codes


def test_persisted_decision_is_content_addressed_and_fragment_bound():
    decision = assess_fragment_l2_materializability(_finding()).to_dict()
    copied = deepcopy(decision)
    copied["fragmentId"] = "fragment:other"
    with pytest.raises(ValueError, match="fragment"):
        assess_fragment_l2_materializability(
            required_dimensions=(L2Dimension.LOGICAL_OPERANDS,
                                 L2Dimension.SHELL_SEMANTICS),
            materialization_decision=copied,
            expected_fragment_id="fragment:closure")

