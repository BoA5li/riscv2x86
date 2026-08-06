import importlib
import os
from types import SimpleNamespace

import pytest


MODULE_NAME = os.environ.get("PHASE8_MODULE", "riscv2x86_py.verify")
v = importlib.import_module(MODULE_NAME)


def test_angr_checker_exists():
    checker = getattr(v, "_verify_paths_angr", None)

    assert checker is not None
    assert callable(checker)


def test_required_path_validation_without_artifact_is_not_verified():
    checker = v._verify_paths_angr

    contract = SimpleNamespace(
        requires_path_validation=True,
        metadata={},
    )

    result = v._run_phase8_checker(
        checker,
        layer="angr path validation",
        unavailable_reason="phase8.path_validator_unavailable",
        failed_reason="phase8.path_proof_failed",
        error_reason="phase8.path_checker_error",
        frag=SimpleNamespace(),
        out=SimpleNamespace(),
        lift=SimpleNamespace(),
        ir_summary=SimpleNamespace(),
        contract=contract,
        blocks=[],
        obligations=[],
        requirements=[],
    )

    assert result.status != "verified", (
        "angr checker returned verified without an "
        "executable artifact or path specification"
    )

    assert result.status in {
        "build_only",
        "unsupported",
        "failed",
    }