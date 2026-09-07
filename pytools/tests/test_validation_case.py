from copy import deepcopy

import pytest

from riscv2x86_py.validation_case import (
    INPUT_GENERATOR_VERSION, VALIDATION_CASE_SCHEMA,
    generate_validation_inputs, validation_case_from_dict,
)


def _case():
    return {
        "schemaVersion": VALIDATION_CASE_SCHEMA,
        "testId": "integer-add-rv64-001",
        "inputGenerator": INPUT_GENERATOR_VERSION,
        "seed": 20260906,
        "inputDomain": {
            "arguments": [
                {"name": "lhs", "type": "u64"},
                {"name": "shift", "type": "u64", "role": "shift"},
            ],
            "memoryObjects": [
                {"objectId": "output_buffer", "sizeBytes": 128,
                 "offsets": [0, 1, 64], "alignments": [1, 8]},
            ],
            "aliasPairs": [],
            "randomCases": 4,
        },
        "comparison": {
            "returnValue": True, "exitCode": True, "stdout": True,
            "stderr": True, "exportedState": ["out"],
            "memoryObjects": ["output_buffer"],
        },
    }


def test_case_schema_generates_replayable_boundary_random_and_memory_inputs():
    case = validation_case_from_dict(_case())
    first = generate_validation_inputs(case)
    second = generate_validation_inputs(case)
    assert first == second
    assert all(item["inputIdentity"].startswith("sha256:") for item in first)
    lhs = {item["arguments"]["lhs"] for item in first}
    assert {0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
            0xFFFFFFFFFFFFFFFF}.issubset(lhs)
    shifts = {item["arguments"]["shift"] for item in first}
    assert {0, 1, 63, 64, 65}.issubset(shifts)
    assert any(item["memory"].get("output_buffer", {}).get("offset") == 1 for item in first)


def test_case_schema_rejects_unknown_fields_bad_types_and_undeclared_observables():
    for mutation in (
        lambda item: item.update(unknown=True),
        lambda item: item.update(seed="7"),
        lambda item: item["comparison"].update(returnValue="true"),
        lambda item: item["comparison"].update(memoryObjects=["missing"]),
    ):
        candidate = deepcopy(_case()); mutation(candidate)
        with pytest.raises(ValueError):
            validation_case_from_dict(candidate)
