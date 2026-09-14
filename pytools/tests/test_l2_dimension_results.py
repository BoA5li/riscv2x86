import copy

import pytest

from riscv2x86_py.l2_dimensions import (
    L2ClaimScope, L2Dimension, L2DimensionStatus,
)
from riscv2x86_py.l2_results import (
    L2DimensionResult, L2FragmentResult,
)


def _id(character):
    return "sha256:" + character * 64


def _verified(dimension, scope=L2ClaimScope.ARCHITECTURAL):
    return L2DimensionResult.create(
        dimension=dimension, status=L2DimensionStatus.VERIFIED,
        claim_scope=scope, authority_identity=_id("a"),
        source_observation_identity=_id("b"),
        target_observation_identity=_id("c"),
        effect_relation_identity=_id("d"), execution_identity=_id("e"),
    )


def _close(required, results):
    return L2FragmentResult.close(
        fragment_id="fragment:1", requirement_identity=_id("f"),
        required_dimensions=required, dimension_results=results,
    )


def test_memory_evidence_cannot_hide_missing_required_operand():
    result = _close(
        (L2Dimension.LOGICAL_OPERANDS, L2Dimension.MEMORY_EFFECTS),
        (_verified(L2Dimension.MEMORY_EFFECTS),),
    )
    assert result.status is L2DimensionStatus.INCONCLUSIVE
    assert result.claim_scope is L2ClaimScope.NONE


def test_verified_dimension_without_evidence_identity_is_rejected():
    with pytest.raises(ValueError, match="no evidence identity"):
        L2DimensionResult.create(
            dimension=L2Dimension.LOGICAL_OPERANDS,
            status=L2DimensionStatus.VERIFIED,
            claim_scope=L2ClaimScope.ARCHITECTURAL,
            authority_identity=_id("a"), source_observation_identity=_id("b"),
            target_observation_identity=_id("c"), effect_relation_identity=_id("d"),
            execution_identity=_id("e"), materialize_evidence=False,
        )


def test_well_formed_but_content_mismatched_evidence_identity_is_rejected():
    value = _verified(L2Dimension.LOGICAL_OPERANDS).to_dict()
    value["executionIdentity"] = _id("9")
    with pytest.raises(ValueError, match="does not match content"):
        L2DimensionResult.from_dict(value)


def test_dimension_result_key_must_match_typed_dimension():
    result = _close(
        (L2Dimension.LOGICAL_OPERANDS,),
        (_verified(L2Dimension.LOGICAL_OPERANDS),),
    ).to_dict()
    result["dimensionResults"]["memory_effects"] = result["dimensionResults"].pop(
        "logical_operands"
    )
    with pytest.raises(ValueError, match="key does not match"):
        L2FragmentResult.from_dict(result)


def test_required_not_run_dimension_closes_as_not_run():
    not_run = L2DimensionResult.create(
        dimension=L2Dimension.LOGICAL_OPERANDS,
        status=L2DimensionStatus.NOT_RUN,
        reason_codes=("l2.binding.provider-missing",),
        materialize_evidence=False,
    )
    result = _close((L2Dimension.LOGICAL_OPERANDS,), (not_run,))
    assert result.status is L2DimensionStatus.NOT_RUN
    assert result.claim_scope is L2ClaimScope.NONE


def test_functional_scope_never_aggregates_to_architectural():
    result = _close(
        (L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
        (
            _verified(L2Dimension.LOGICAL_OPERANDS),
            _verified(
                L2Dimension.SHELL_SEMANTICS,
                L2ClaimScope.APPROVED_FUNCTIONAL_RELATION,
            ),
        ),
    )
    assert result.status is L2DimensionStatus.VERIFIED
    assert result.claim_scope is L2ClaimScope.APPROVED_FUNCTIONAL_RELATION
    assert result.claim_scope is not L2ClaimScope.ARCHITECTURAL


def test_extra_diagnostic_dimension_does_not_change_required_gate():
    diagnostic = L2DimensionResult.create(
        dimension=L2Dimension.MEMORY_EFFECTS,
        status=L2DimensionStatus.INCONCLUSIVE,
        reason_codes=("l2.diagnostic-only",),
    )
    result = _close(
        (L2Dimension.LOGICAL_OPERANDS,),
        (_verified(L2Dimension.LOGICAL_OPERANDS), diagnostic),
    )
    assert result.status is L2DimensionStatus.VERIFIED
    assert result.claim_scope is L2ClaimScope.ARCHITECTURAL


def test_fragment_parser_rejects_a_forged_architectural_aggregate():
    value = _close(
        (L2Dimension.LOGICAL_OPERANDS,),
        (_verified(
            L2Dimension.LOGICAL_OPERANDS,
            L2ClaimScope.APPROVED_FUNCTIONAL_RELATION,
        ),),
    ).to_dict()
    forged = copy.deepcopy(value)
    forged["claimScope"] = "architectural"
    with pytest.raises(ValueError, match="closed-dimension gate"):
        L2FragmentResult.from_dict(forged)
