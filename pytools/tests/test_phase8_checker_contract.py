import importlib
import inspect
import os

import pytest


MODULE_NAME = os.environ.get("PHASE8_MODULE", "riscv2x86_py.verify")
v = importlib.import_module(MODULE_NAME)


CHECKERS = [
    "_verify_block_semantics_z3",
    "_verify_paths_angr",
    "_run_phase8_engineering_suite",
    "_run_phase8_microarch_suite",
]


@pytest.mark.parametrize("name", CHECKERS)
def test_checker_accepts_keyword_arguments(name):
    checker = getattr(v, name)
    signature = inspect.signature(checker)

    has_var_keyword = any(
        p.kind == inspect.Parameter.VAR_KEYWORD
        for p in signature.parameters.values()
    )

    expected_names = {
        "frag",
        "out",
        "lift",
        "ir_summary",
        "contract",
        "blocks",
        "obligations",
        "requirements",
    }

    declared_names = set(signature.parameters)

    assert has_var_keyword or declared_names & expected_names, (
        f"{name} cannot accept the Phase 8 context"
    )


@pytest.mark.parametrize("name", CHECKERS)
def test_checker_is_not_wrapper_alias(name):
    checker = getattr(v, name)

    wrapper_names = {
        "_run_strict_path_validation",
        "_run_engineering_validation",
        "_run_microarch_validation",
    }

    assert checker.__name__ not in wrapper_names


def test_result_status_values_are_available():
    statuses = {
        v._vr_verified("ok").status,
        v._vr_failed("test.failed", "failed").status,
        v._vr_build_only(
            "test.unavailable",
            "unavailable",
        ).status,
    }

    assert statuses == {
        "verified",
        "failed",
        "build_only",
    }