from dataclasses import replace

from riscv2x86_py.privileged_differential_validation import (
    EngineeringValidationRecord,
    PrivilegedMachineObservation,
    validate_privileged_differential,
)


PROOF = "sha256:" + "1" * 64


def _observation(runner="riscv-emulator"):
    return PrivilegedMachineObservation(
        runner, "runtime-v1", "initial-logical-state-1",
        (("mstatus", "0x80"),), "m",
        (("cause", "none"),), "pc:next",
        (("memory", "sha256:abc"),),
        (("mie", "1"),), (("satp", "bare"),), "normal",
        (("error-status", "0"), ("external-event", "none"),
         ("memory", "sha256:abc"), ("output:0", "7"),
         ("termination", "normal"), ("trap-to-result", "none")),
    )


def _engineering(version="runtime-v1", proof=PROOF):
    return tuple(
        EngineeringValidationRecord(
            compiler, optimization, sanitizer,
            True, True, True, True, True,
            "runtime-v1", version, proof,
        )
        for compiler in ("gcc", "clang")
        for optimization in ("-O0", "-O2", "-O3")
        for sanitizer in ("none", "asan", "ubsan")
    )


def _strict_manifest():
    return {
        "proofStatus": "approved",
        "preservationMode": "architecture_equivalent",
        "architectureSemanticsPreserved": True,
        "microarchitectureSemanticsPreserved": False,
        "observableEffectsProved": (), "ignoredSourceState": (),
        "proof": {"identity": PROOF},
    }


def _fallback_manifest():
    return {
        "proofStatus": "functional_approved",
        "preservationMode": "functional_equivalence_only",
        "architectureSemanticsPreserved": False,
        "microarchitectureSemanticsPreserved": False,
        "observableEffectsProved": (
            "error-status", "external-event", "memory", "output:0",
            "termination", "trap-to-result",
        ),
        "ignoredSourceState": ("csr:mstatus", "interrupt:timing"),
        "proof": {"identity": PROOF},
    }


def test_strict_validation_compares_complete_privileged_state_relation():
    source = _observation()
    target = replace(source, runner_id="x86-target-runtime")
    result = validate_privileged_differential(
        source=source, target=target, manifest=_strict_manifest(),
        engineering_records=_engineering(),
    )
    assert result.approved
    assert result.engineering_matrix_complete
    assert result.compared_effect_ids == (
        "continuation", "csr", "interrupt", "memory", "mmu-tlb",
        "privilege-mode", "termination", "trap",
    )
    assert result.validation_identity.startswith("sha256:")


def test_strict_state_difference_is_reported_by_dimension():
    source = _observation()
    target = replace(source, runner_id="x86-target-runtime",
                     csr_state=(("mstatus", "0x00"),))
    result = validate_privileged_differential(
        source=source, target=target, manifest=_strict_manifest(),
        engineering_records=_engineering(),
    )
    assert not result.approved
    assert "phase8.privileged.strict-csr-mismatch" in result.mismatch_codes


def test_fallback_compares_only_authorized_observable_projection():
    source = _observation()
    target = replace(
        source, runner_id="x86-target-runtime",
        csr_state=(("mstatus", "not-preserved"),),
        interrupt_state=(("mie", "not-preserved"),),
    )
    result = validate_privileged_differential(
        source=source, target=target, manifest=_fallback_manifest(),
        engineering_records=_engineering(),
    )
    assert result.approved
    assert result.ignored_state_ids == ("csr:mstatus", "interrupt:timing")
    assert "csr" not in result.compared_effect_ids


def test_fallback_rejects_ignored_state_escape_and_false_preservation_claim():
    manifest = _fallback_manifest()
    manifest["observableEffectsProved"] = tuple(
        sorted((*manifest["observableEffectsProved"], "csr:mstatus"))
    )
    manifest["architectureSemanticsPreserved"] = True
    result = validate_privileged_differential(
        source=_observation(),
        target=replace(_observation(), runner_id="x86-target-runtime"),
        manifest=manifest, engineering_records=_engineering(),
    )
    assert not result.approved
    assert "phase8.privileged.ignored-state-escape" in result.mismatch_codes
    assert "phase8.privileged.fallback-conclusion-invalid" in result.mismatch_codes


def test_wrong_runtime_version_and_incomplete_build_matrix_fail():
    result = validate_privileged_differential(
        source=_observation(),
        target=replace(_observation(), runner_id="x86-target-runtime"),
        manifest=_strict_manifest(),
        engineering_records=_engineering("runtime-v0")[:1],
    )
    assert not result.approved
    assert "phase8.privileged.runtime-version-mismatch" in result.mismatch_codes
    assert "phase8.privileged.engineering-matrix-incomplete" in result.mismatch_codes


def test_validation_identity_is_reproducible_and_change_sensitive():
    args = dict(
        source=_observation(),
        target=replace(_observation(), runner_id="x86-target-runtime"),
        manifest=_strict_manifest(), engineering_records=_engineering(),
    )
    first = validate_privileged_differential(**args)
    second = validate_privileged_differential(**args)
    changed = validate_privileged_differential(
        **{**args, "target": replace(args["target"], runtime_version="runtime-v2")}
    )
    assert first.validation_identity == second.validation_identity
    assert first.validation_identity != changed.validation_identity
