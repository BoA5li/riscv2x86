import importlib
import os

import pytest


MODULE_NAME = os.environ.get("PHASE8_MODULE", "riscv2x86_py.verify")
v = importlib.import_module(MODULE_NAME)


CANONICAL_CHECKERS = [
    "_verify_block_semantics_z3",
    "_verify_paths_angr",
    "_run_phase8_engineering_suite",
    "_run_phase8_microarch_suite",
]


@pytest.mark.parametrize("name", CANONICAL_CHECKERS)
def test_required_phase8_checker_is_defined(name):
    checker = getattr(v, name, None)

    assert checker is not None, (
        f"Phase 8 checker {name} is not defined"
    )
    assert callable(checker), (
        f"Phase 8 checker {name} is not callable"
    )


@pytest.mark.parametrize(
    ("canonical_name", "aliases"),
    [
        (
            "_verify_paths_angr",
            (
                "_verify_paths_angr",
                "_validate_paths_angr",
                "_verify_path_semantics_angr",
            ),
        ),
        (
            "_run_phase8_engineering_suite",
            (
                "_run_phase8_engineering_suite",
                "_verify_engineering_behavior",
            ),
        ),
        (
            "_run_phase8_microarch_suite",
            (
                "_run_phase8_microarch_suite",
                "_verify_microarchitectural_behavior",
                "_run_microarch_e2e_validation",
            ),
        ),
    ],
)
def test_finder_prefers_canonical_checker(
    canonical_name,
    aliases,
):
    canonical = getattr(v, canonical_name)

    selected = v._phase8_find_checker(*aliases)

    assert selected is canonical, (
        f"Expected {canonical_name}, got "
        f"{getattr(selected, '__name__', selected)!r}"
    )


def test_engineering_finder_does_not_select_wrapper():
    wrapper = getattr(v, "_run_engineering_validation", None)

    selected = v._phase8_find_checker(
        "_run_phase8_engineering_suite",
        "_verify_engineering_behavior",
    )

    assert selected is not None
    assert selected is not wrapper, (
        "_run_engineering_validation selected itself as "
        "its backend checker; this can cause recursion"
    )


def test_microarch_finder_does_not_select_wrapper():
    wrapper = getattr(v, "_run_microarch_validation", None)

    selected = v._phase8_find_checker(
        "_run_phase8_microarch_suite",
        "_verify_microarchitectural_behavior",
        "_run_microarch_e2e_validation",
    )

    assert selected is not None
    assert selected is not wrapper, (
        "_run_microarch_validation selected itself as "
        "its backend checker"
    )


def test_path_finder_does_not_select_wrapper():
    wrapper = getattr(v, "_run_strict_path_validation", None)

    selected = v._phase8_find_checker(
        "_verify_paths_angr",
        "_validate_paths_angr",
        "_verify_path_semantics_angr",
    )

    assert selected is not None
    assert selected is not wrapper