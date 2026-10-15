from copy import deepcopy

import pytest

from riscv2x86_py.automatic_l2_operand import _sample_observations, L2OperandObservationError
from riscv2x86_py.l2_operand_observation_plan import CanonicalOperandObservationPlan
from riscv2x86_py.l2_fragment_execution import (
    L2OperandObservationAuthority, L2OperandObservationBinding,
)
from tests.test_l2_operand_observation_authority import _materializer_authority


@pytest.mark.parametrize("rows,kwargs,reason", [
    (None, {}, "L2_OPERAND_TRACE_MISSING"),
    ((), {}, "L2_OPERAND_TRACE_MISSING"),
    (((1, 2),), {"expected_sample_count": 2}, "L2_OPERAND_SAMPLE_COUNT_MISMATCH"),
    (((1, 2), (3,)), {}, "L2_OPERAND_TRACE_ARITY_MISMATCH"),
    (((True, 2),), {}, "L2_OPERAND_TRACE_VALUE_INVALID"),
    (((-1, 2),), {}, "L2_OPERAND_TRACE_VALUE_INVALID"),
])
def test_trace_contract_has_precise_reason(rows, kwargs, reason):
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(rows, _materializer_authority(), trace_arity=1, **kwargs)
    assert caught.value.reason_code == reason


def test_old_mixed_authority_payload_is_rejected():
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(((1, 2),), {"operands": [], "compilerFacts": []})
    assert caught.value.reason_code == "L2_OPERAND_OBSERVATION_PLAN_INVALID"


def _dependency_plan():
    sha = lambda char: "sha256:" + char * 64
    binding = L2OperandObservationBinding(
        "consumer", "operand:0", 0, "decl:input", sha("1"), "input",
        "producer", 64, "unsigned", None, "producer", sha("2"),
        "composite_dependency", "", "", "", sha("3"))
    return CanonicalOperandObservationPlan(L2OperandObservationAuthority(
        "consumer", sha("4"), sha("5"), sha("6"), (binding,), True))


def test_dependency_observation_needs_exact_edge_trace():
    plan = _dependency_plan()
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(((7, 9),), plan, trace_arity=1,
                             dependency_values={"sha256:" + "9" * 64: (7,)})
    assert caught.value.reason_code == "L2_OPERAND_DEPENDENCY_TRACE_MISSING"
    result = _sample_observations(((7, 9),), plan, trace_arity=1,
        dependency_values={"sha256:" + "3" * 64: (42,)})
    assert result[0]["logicalOperands"][0]["valueBefore"] == "0x000000000000002a"


def test_plan_tampering_is_not_repaired_by_trace_consumer():
    plan = deepcopy(_materializer_authority())
    plan["operandObservationAuthority"]["fragmentId"] = "foreign"
    with pytest.raises(L2OperandObservationError) as caught:
        _sample_observations(((7, 9),), plan, trace_arity=1)
    assert caught.value.reason_code == "L2_OPERAND_OBSERVATION_PLAN_INVALID"
