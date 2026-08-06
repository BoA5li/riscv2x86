import importlib
import os
from types import SimpleNamespace

import pytest

MODULE_NAME = os.environ.get("PHASE8_MODULE", "riscv2x86_py.verify")
v = importlib.import_module(MODULE_NAME)


def vr_verified(detail="passed"):
    return v._vr_verified(detail)


def vr_failed(reason="test.failed", detail="failed"):
    return v._vr_failed(reason, detail)


def vr_build_only(
    reason="test.unavailable",
    detail="unavailable",
):
    return v._vr_build_only(reason, detail)


@pytest.fixture
def phase8_env(monkeypatch):
    """
    将各验证层替换为确定性 stub，仅验证 Phase 8 控制流。

    实际 Z3、angr、clang 和工程测试应由集成测试覆盖。
    """
    calls = []

    frag = SimpleNamespace(
        microArch=None,
        notes=[],
    )

    out = SimpleNamespace(
        replacement="int translated(void) { return 1; }",
        kind="c",
        buildFamily="c",
        preservationLevel="A",
        preservationRoute="canonical_public_c",
    )

    lift = SimpleNamespace(
        ok=True,
        error="",
    )

    summary = SimpleNamespace(
        has_atomic=False,
        has_memory_barrier=False,
        has_call_or_return=False,
    )

    contract = SimpleNamespace(
        level="A",
        route="canonical_public_c",
        build_family="c",
        reason_codes=[],
        requires_build_check=True,
        requires_block_proof=True,
        requires_path_validation=False,
        metadata={},
    )

    monkeypatch.setattr(
        v,
        "_phase8_contract_from_output",
        lambda out, frag=None: contract,
    )

    monkeypatch.setattr(
        v,
        "_contract_mismatch_reasons",
        lambda out, frag=None: [],
    )

    def admission_stub(contract):
        calls.append("admission")
        return vr_verified("admission passed")

    monkeypatch.setattr(
        v,
        "_validate_admission",
        admission_stub,
    )

    def build_stub(**kwargs):
        calls.append("build")
        return None

    monkeypatch.setattr(
        v,
        "_run_artifact_build_gate",
        build_stub,
    )

    def recover_stub(lift, supplied_summary):
        calls.append("recover")
        return ["block0"], supplied_summary

    monkeypatch.setattr(
        v,
        "_recover_blocks_and_summary",
        recover_stub,
    )

    def obligations_stub(
        frag,
        blocks,
        ir_summary,
        contract,
    ):
        calls.append("collect_obligations")
        return ["registers", "memory", "branch"]

    monkeypatch.setattr(
        v,
        "_collect_block_proof_obligations",
        obligations_stub,
    )

    def structural_stub(contract, obligations):
        calls.append("structural")
        return vr_verified(
            "block structural obligations satisfied"
        )

    monkeypatch.setattr(
        v,
        "_validate_block_proofs",
        structural_stub,
    )

    def z3_stub(**kwargs):
        calls.append("z3")
        return vr_verified(
            "Z3 proved block semantic equivalence"
        )

    monkeypatch.setattr(
        v,
        "_verify_block_semantics_z3",
        z3_stub,
    )

    def path_stub(**kwargs):
        calls.append("angr")
        return vr_verified("path validation passed")

    monkeypatch.setattr(
        v,
        "_run_strict_path_validation",
        path_stub,
    )

    def semantic_stub(**kwargs):
        calls.append("semantic_closure")
        return vr_verified("family semantics passed")

    monkeypatch.setattr(
        v,
        "_run_semantic_closure",
        semantic_stub,
    )

    def engineering_stub(**kwargs):
        calls.append("engineering")
        return vr_verified("engineering suite passed")

    monkeypatch.setattr(
        v,
        "_run_engineering_validation",
        engineering_stub,
    )

    def microarch_stub(**kwargs):
        calls.append("microarch")
        return vr_verified(
            "microarchitectural validation not required"
        )

    monkeypatch.setattr(
        v,
        "_run_microarch_validation",
        microarch_stub,
    )

    return SimpleNamespace(
        calls=calls,
        frag=frag,
        out=out,
        lift=lift,
        summary=summary,
        contract=contract,
    )


def run_verify(env):
    # verify.py 的唯一对外主接口。
    return v.verify(
        env.frag,
        env.lift,
        env.summary,
        env.out,
    )


def test_all_required_layers_pass_returns_verified(
    phase8_env,
):
    result = run_verify(phase8_env)

    assert result.status == "verified"

    assert phase8_env.calls == [
        "admission",
        "build",
        "recover",
        "collect_obligations",
        "structural",
        "z3",
        "angr",
        "semantic_closure",
        "engineering",
        "microarch",
    ]


def test_build_failure_stops_all_later_layers(
    phase8_env,
    monkeypatch,
):
    def build_failure(**kwargs):
        phase8_env.calls.append("build")
        return vr_failed(
            "phase8.build_failed",
            "clang compilation failed",
        )

    monkeypatch.setattr(
        v,
        "_run_artifact_build_gate",
        build_failure,
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"
    assert phase8_env.calls == [
        "admission",
        "build",
    ]


def test_build_tool_unavailable_returns_build_only(
    phase8_env,
    monkeypatch,
):
    def build_unavailable(**kwargs):
        phase8_env.calls.append("build")
        return vr_build_only(
            "phase8.toolchain_unavailable",
            "clang not found",
        )

    monkeypatch.setattr(
        v,
        "_run_artifact_build_gate",
        build_unavailable,
    )

    result = run_verify(phase8_env)

    assert result.status == "build_only"
    assert phase8_env.calls == [
        "admission",
        "build",
    ]


def test_lift_unavailable_never_returns_verified(
    phase8_env,
):
    phase8_env.lift.ok = False
    phase8_env.lift.error = "unsupported instruction"

    result = run_verify(phase8_env)

    assert result.status == "build_only"
    assert "z3" not in phase8_env.calls
    assert "engineering" not in phase8_env.calls


def test_structural_failure_stops_before_z3(
    phase8_env,
    monkeypatch,
):
    def structural_failure(contract, obligations):
        phase8_env.calls.append("structural")
        return vr_failed(
            "phase8.block_obligation_failed",
            "stack-pointer obligation failed",
        )

    monkeypatch.setattr(
        v,
        "_validate_block_proofs",
        structural_failure,
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"
    assert "z3" not in phase8_env.calls
    assert "angr" not in phase8_env.calls
    assert "engineering" not in phase8_env.calls


def test_z3_counterexample_returns_failed(
    phase8_env,
    monkeypatch,
):
    def z3_counterexample(**kwargs):
        phase8_env.calls.append("z3")
        return vr_failed(
            "phase8.block_semantic_proof_failed",
            "Z3 found a register-state counterexample",
        )

    monkeypatch.setattr(
        v,
        "_verify_block_semantics_z3",
        z3_counterexample,
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"
    assert "angr" not in phase8_env.calls
    assert "engineering" not in phase8_env.calls


def test_z3_unavailable_cannot_be_promoted_to_verified(
    phase8_env,
    monkeypatch,
):
    def z3_unavailable(**kwargs):
        phase8_env.calls.append("z3")
        return vr_build_only(
            "phase8.block_semantic_checker_unavailable",
            "z3-solver is not installed",
        )

    monkeypatch.setattr(
        v,
        "_verify_block_semantics_z3",
        z3_unavailable,
    )

    result = run_verify(phase8_env)

    assert result.status == "build_only"
    assert "angr" not in phase8_env.calls
    assert "engineering" not in phase8_env.calls


def test_angr_counterexample_returns_failed(
    phase8_env,
    monkeypatch,
):
    def path_failure(**kwargs):
        phase8_env.calls.append("angr")
        return vr_failed(
            "phase8.path_proof_failed",
            "translated branch reaches an extra exit",
        )

    monkeypatch.setattr(
        v,
        "_run_strict_path_validation",
        path_failure,
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"
    assert "semantic_closure" not in phase8_env.calls
    assert "engineering" not in phase8_env.calls


def test_required_angr_unavailable_returns_build_only(
    phase8_env,
    monkeypatch,
):
    def path_unavailable(**kwargs):
        phase8_env.calls.append("angr")
        return vr_build_only(
            "phase8.path_validator_unavailable",
            "angr is not installed",
        )

    monkeypatch.setattr(
        v,
        "_run_strict_path_validation",
        path_unavailable,
    )

    result = run_verify(phase8_env)

    assert result.status == "build_only"
    assert "engineering" not in phase8_env.calls


def test_family_semantic_failure_is_not_closed_by_structure(
    phase8_env,
    monkeypatch,
):
    def semantic_failure(**kwargs):
        phase8_env.calls.append("semantic_closure")
        return vr_failed(
            "phase8.family_semantic_failed",
            "inline-asm clobber mismatch",
        )

    monkeypatch.setattr(
        v,
        "_run_semantic_closure",
        semantic_failure,
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"
    assert "engineering" not in phase8_env.calls


def test_engineering_failure_returns_failed(
    phase8_env,
    monkeypatch,
):
    def engineering_failure(**kwargs):
        phase8_env.calls.append("engineering")
        return vr_failed(
            "phase8.engineering_validation_failed",
            "reference differential test failed",
        )

    monkeypatch.setattr(
        v,
        "_run_engineering_validation",
        engineering_failure,
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"
    assert "microarch" not in phase8_env.calls


def test_missing_engineering_suite_cannot_return_verified(
    phase8_env,
    monkeypatch,
):
    def engineering_unavailable(**kwargs):
        phase8_env.calls.append("engineering")
        return vr_build_only(
            "phase8.engineering_validator_unavailable",
            "required engineering suite was not run",
        )

    monkeypatch.setattr(
        v,
        "_run_engineering_validation",
        engineering_unavailable,
    )

    result = run_verify(phase8_env)

    assert result.status == "build_only"
    assert "microarch" not in phase8_env.calls


def test_required_microarch_suite_unavailable_is_build_only(
    phase8_env,
    monkeypatch,
):
    def microarch_unavailable(**kwargs):
        phase8_env.calls.append("microarch")
        return vr_build_only(
            "phase8.microarch_validator_unavailable",
            "PMC validation was not run",
        )

    monkeypatch.setattr(
        v,
        "_run_microarch_validation",
        microarch_unavailable,
    )

    result = run_verify(phase8_env)

    assert result.status == "build_only"


def test_microarch_mismatch_returns_failed(
    phase8_env,
    monkeypatch,
):
    def microarch_failure(**kwargs):
        phase8_env.calls.append("microarch")
        return vr_failed(
            "phase8.microarch_validation_failed",
            "cache-footprint distribution differs",
        )

    monkeypatch.setattr(
        v,
        "_run_microarch_validation",
        microarch_failure,
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"


@pytest.mark.parametrize(
    ("legacy_result", "expected_status"),
    [
        (None, "verified"),
        ("", "verified"),
        (True, "verified"),
        (False, "failed"),
        ("clang: error: invalid instruction", "failed"),
    ],
)
def test_legacy_build_result_protocol(
    legacy_result,
    expected_status,
):
    result = v._coerce_build_check_result(
        legacy_result
    )
    assert result.status == expected_status


def test_checker_internal_type_error_is_not_retried():
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        raise TypeError("internal checker defect")

    result = v._run_phase8_checker(
        checker,
        layer="test checker",
        unavailable_reason="test.unavailable",
        failed_reason="test.failed",
        error_reason="test.error",
        frag=object(),
        out=object(),
        lift=object(),
        ir_summary=object(),
        contract=object(),
        blocks=[],
        obligations=[],
        requirements=[],
    )

    assert len(calls) == 1
    assert result.status == "build_only"
    assert "TypeError" in result.detail


def test_contract_mismatch_fails_before_build(
    phase8_env,
    monkeypatch,
):
    monkeypatch.setattr(
        v,
        "_contract_mismatch_reasons",
        lambda out, frag=None: [
            "declared C output contains standalone assembly"
        ],
    )

    result = run_verify(phase8_env)

    assert result.status == "failed"
    assert "build" not in phase8_env.calls
    assert "z3" not in phase8_env.calls