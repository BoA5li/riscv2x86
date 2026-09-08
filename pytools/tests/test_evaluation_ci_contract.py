from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def test_regular_ci_covers_required_evaluation_smoke_contracts():
    workflow = (ROOT / ".github/workflows/phase8-l0.yml").read_text()
    assert "phase10-evaluation-ci-matrix" in workflow
    assert "schema-staging-and-negative-contracts:" in workflow
    assert "test_translation_attempt.py" in workflow
    assert "test_candidate_materialization.py" in workflow
    assert "test_writeback_promotion.py" in workflow
    assert "test_evaluation_aggregate.py" in workflow
    assert workflow.count("--matrix-profile smoke") == 2
    assert "run_real_l1_differential.py --random-cases 4" in workflow
    assert "real-sanitizer-negatives:" in workflow


def test_nightly_declares_full_matrix_expanded_domain_and_controlled_routes():
    workflow = (ROOT / ".github/workflows/phase10-evaluation-nightly.yml").read_text()
    assert 'cron: "17 3 * * *"' in workflow
    assert workflow.count("--matrix-profile full") == 2
    assert "--random-cases 256" in workflow
    assert "test_l2_concurrency_runner.py" in workflow
    assert "test_l2_privileged_runner.py" in workflow
    assert "PRIVILEGED_RUNNER_ENABLED" in workflow
    assert "L3_CONTROLLED_RUNNER_ENABLED" in workflow
    assert workflow.count("riscv2x86_py.evaluation_cli") == 2
    assert "--source-program-artifact" not in workflow
    assert "nightly.controlled-runner-not-configured" in workflow
    assert "if-no-files-found: error" in workflow
    assert not (ROOT / ".github/workflows/phase8-l3-nightly.yml").exists()


def test_real_driver_profiles_are_explicit_cli_contracts():
    for script, marker in (
        ("run_real_l0_matrix.py", "--matrix-profile {smoke,full}"),
        ("run_real_l1_differential.py", "--random-cases"),
    ):
        result = subprocess.run(
            [sys.executable, str(ROOT / "pytools/tests" / script), "--help"],
            env={"PYTHONPATH": str(ROOT / "pytools")}, text=True,
            capture_output=True, check=False,
        )
        assert result.returncode == 0
        assert marker in result.stdout
