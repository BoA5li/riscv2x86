import importlib
import os

import pytest

z3 = pytest.importorskip("z3")


MODULE_NAME = os.environ.get("PHASE8_MODULE", "riscv2x86_py.verify")
v = importlib.import_module(MODULE_NAME)


@pytest.fixture
def verify_transform():
    checker = getattr(
        v,
        "_verify_z3_state_transform",
        None,
    )

    assert checker is not None, (
        "Implement _verify_z3_state_transform before "
        "running the Z3 integration tests"
    )

    return checker


def assert_status(result, expected):
    assert result.status == expected, (
        f"expected {expected}, got {result.status}: "
        f"{getattr(result, 'detail', '')}"
    )


def test_equivalent_integer_add_is_verified(
    verify_transform,
):
    def original(s):
        return {
            "out": s["a"] + s["b"],
        }

    def translated(s):
        temporary = s["a"] + s["b"]
        return {
            "out": temporary,
        }

    result = verify_transform(
        original,
        translated,
        inputs={
            "a": 64,
            "b": 64,
        },
        outputs={
            "out": 64,
        },
        timeout_ms=5000,
    )

    assert_status(result, "verified")


def test_add_changed_to_subtract_fails(
    verify_transform,
):
    def original(s):
        return {
            "out": s["a"] + s["b"],
        }

    def translated(s):
        return {
            "out": s["a"] - s["b"],
        }

    result = verify_transform(
        original,
        translated,
        inputs={
            "a": 64,
            "b": 64,
        },
        outputs={
            "out": 64,
        },
        timeout_ms=5000,
    )

    assert_status(result, "failed")


def test_reversed_branch_condition_fails(
    verify_transform,
):
    def original(s):
        return {
            "branch": z3.ULT(s["a"], s["b"]),
        }

    def translated(s):
        return {
            "branch": z3.UGE(s["a"], s["b"]),
        }

    result = verify_transform(
        original,
        translated,
        inputs={
            "a": 64,
            "b": 64,
        },
        outputs={},
        branch_outputs={
            "branch": "bool",
        },
        timeout_ms=5000,
    )

    assert_status(result, "failed")


def test_different_memory_write_address_fails(
    verify_transform,
):
    def original(s):
        memory = z3.Store(
            s["memory"],
            s["address"],
            s["value"],
        )
        return {
            "memory": memory,
        }

    def translated(s):
        wrong_address = s["address"] + 1
        memory = z3.Store(
            s["memory"],
            wrong_address,
            s["value"],
        )
        return {
            "memory": memory,
        }

    result = verify_transform(
        original,
        translated,
        inputs={
            "address": 64,
            "value": 8,
        },
        outputs={},
        memory_inputs={
            "memory": {
                "address_bits": 64,
                "value_bits": 8,
            },
        },
        memory_outputs={
            "memory": {
                "address_bits": 64,
                "value_bits": 8,
            },
        },
        timeout_ms=5000,
    )

    assert_status(result, "failed")


def test_missing_output_register_write_fails(
    verify_transform,
):
    def original(s):
        return {
            "rax": s["a"] + 1,
            "rdx": s["b"] + 2,
        }

    def translated(s):
        # rdx 没有按原语义更新。
        return {
            "rax": s["a"] + 1,
            "rdx": s["rdx_initial"],
        }

    result = verify_transform(
        original,
        translated,
        inputs={
            "a": 64,
            "b": 64,
            "rdx_initial": 64,
        },
        outputs={
            "rax": 64,
            "rdx": 64,
        },
        timeout_ms=5000,
    )

    assert_status(result, "failed")


def test_wrong_stack_pointer_adjustment_fails(
    verify_transform,
):
    def original(s):
        return {
            "sp": s["sp"] - 16,
        }

    def translated(s):
        return {
            "sp": s["sp"] - 8,
        }

    result = verify_transform(
        original,
        translated,
        inputs={
            "sp": 64,
        },
        outputs={
            "sp": 64,
        },
        timeout_ms=5000,
    )

    assert_status(result, "failed")


def test_wrong_return_address_fails(
    verify_transform,
):
    def original(s):
        return {
            "pc": s["return_address"],
        }

    def translated(s):
        return {
            "pc": s["return_address"] + 4,
        }

    result = verify_transform(
        original,
        translated,
        inputs={
            "return_address": 64,
        },
        outputs={
            "pc": 64,
        },
        timeout_ms=5000,
    )

    assert_status(result, "failed")