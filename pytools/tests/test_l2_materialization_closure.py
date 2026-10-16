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



def test_ordinary_memory_authority_cannot_close_atomic_dimension():
    from types import SimpleNamespace
    from riscv2x86_py.l2_materialization import _sidecar_dimension_reasons
    sidecar = SimpleNamespace(memory_objects=(object(),), source_effects=(
        SimpleNamespace(effect_id='memory:access', effect_kind='WriteMemory', complete=True),),
        approved_effect_relations=())
    complete, reasons = _sidecar_dimension_reasons(
        sidecar, (L2Dimension.ATOMIC_MEMORY_ORDER,), L2PatternKind.ATOMIC)
    assert not complete
    assert reasons == ['L2_ATOMIC_RMW_EFFECT_AUTHORITY_MISSING']


def test_atomic_effect_needs_atomicity_and_ordering_relation_properties():
    from types import SimpleNamespace
    from riscv2x86_py.l2_materialization import _sidecar_dimension_reasons
    from riscv2x86_py.effect_relation import ApprovedEffectRelation
    sidecar = SimpleNamespace(memory_objects=(object(),), source_effects=(
        SimpleNamespace(effect_id='atomic:rmw', effect_kind='AtomicReadModifyWrite', complete=True),),
        approved_effect_relations=(ApprovedEffectRelation('r','atomic:rmw',('target:rmw',),
            'exact',('kind','value'),(),'',True),))
    complete, reasons = _sidecar_dimension_reasons(
        sidecar, (L2Dimension.ATOMIC_MEMORY_ORDER,), L2PatternKind.ATOMIC)
    assert not complete
    assert reasons == ['L2_ATOMIC_RMW_RELATION_INCOMPLETE']
