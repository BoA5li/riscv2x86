from types import SimpleNamespace

from riscv2x86_py import verify as v


def empty_contract():
    return SimpleNamespace(
        metadata={},
    )


def test_angr_backend_without_artifacts_is_build_only():
    result = v._verify_paths_angr(
        frag=SimpleNamespace(),
        out=SimpleNamespace(),
        lift=SimpleNamespace(),
        ir_summary=SimpleNamespace(),
        contract=empty_contract(),
        blocks=[],
        obligations=[],
        requirements=[],
    )

    assert result.status == "build_only"


def test_engineering_backend_without_suite_is_build_only():
    result = v._run_phase8_engineering_suite(
        frag=SimpleNamespace(),
        out=SimpleNamespace(),
        lift=SimpleNamespace(),
        ir_summary=SimpleNamespace(),
        contract=empty_contract(),
        blocks=[],
        obligations=[],
        requirements=[
            "unit_tests",
        ],
    )

    assert result.status == "build_only"


def test_microarch_backend_without_suite_is_build_only():
    result = v._run_phase8_microarch_suite(
        frag=SimpleNamespace(),
        out=SimpleNamespace(),
        lift=SimpleNamespace(),
        ir_summary=SimpleNamespace(),
        contract=empty_contract(),
        blocks=[],
        obligations=[],
        requirements=[
            "pmc_validation",
        ],
    )

    assert result.status == "build_only"


def test_engineering_missing_required_check_is_build_only():
    contract = SimpleNamespace(
        metadata={
            "phase8_engineering": {
                "required": [
                    "unit_tests",
                    "abi_validation",
                ],
                "commands": {
                    "unit_tests": [
                        "python",
                        "-c",
                        "raise SystemExit(0)",
                    ],
                },
            },
        },
    )

    result = v._run_phase8_engineering_suite(
        contract=contract,
    )

    assert result.status == "build_only"


def test_engineering_all_required_checks_pass():
    contract = SimpleNamespace(
        metadata={
            "phase8_engineering": {
                "required": [
                    "unit_tests",
                    "abi_validation",
                ],
                "commands": {
                    "unit_tests": [
                        "python",
                        "-c",
                        "raise SystemExit(0)",
                    ],
                    "abi_validation": [
                        "python",
                        "-c",
                        "raise SystemExit(0)",
                    ],
                },
                "timeout_sec": 10,
            },
        },
    )

    result = v._run_phase8_engineering_suite(
        contract=contract,
    )

    assert result.status == "verified"


def test_engineering_explicit_mismatch_is_failed():
    contract = SimpleNamespace(
        metadata={
            "phase8_engineering": {
                "required": [
                    "reference_differential",
                ],
                "commands": {
                    "reference_differential": [
                        "python",
                        "-c",
                        "raise SystemExit(1)",
                    ],
                },
                "timeout_sec": 10,
            },
        },
    )

    result = v._run_phase8_engineering_suite(
        contract=contract,
    )

    assert result.status == "failed"


def test_engineering_timeout_is_build_only():
    contract = SimpleNamespace(
        metadata={
            "phase8_engineering": {
                "required": [
                    "stress_test",
                ],
                "commands": {
                    "stress_test": [
                        "python",
                        "-c",
                        "import time; time.sleep(2)",
                    ],
                },
                "timeout_sec": 0.05,
            },
        },
    )

    result = v._run_phase8_engineering_suite(
        contract=contract,
    )

    assert result.status == "build_only"


def test_level_d_without_pmc_command_is_build_only():
    contract = SimpleNamespace(
        level="D",
        metadata={
            "phase8_microarch": {
                "required": [
                    "timing_distribution",
                    "pmc_validation",
                ],
                "commands": {
                    "timing_distribution": [
                        "python",
                        "-c",
                        "raise SystemExit(0)",
                    ],
                },
            },
        },
    )

    result = v._run_phase8_microarch_suite(
        contract=contract,
    )

    assert result.status == "build_only"


def test_all_microarch_checks_pass():
    contract = SimpleNamespace(
        level="D",
        metadata={
            "phase8_microarch": {
                "required": [
                    "timing_distribution",
                    "pmc_validation",
                ],
                "commands": {
                    "timing_distribution": [
                        "python",
                        "-c",
                        "raise SystemExit(0)",
                    ],
                    "pmc_validation": [
                        "python",
                        "-c",
                        "raise SystemExit(0)",
                    ],
                },
                "timeout_sec": 10,
            },
        },
    )

    result = v._run_phase8_microarch_suite(
        contract=contract,
    )

    assert result.status == "verified"