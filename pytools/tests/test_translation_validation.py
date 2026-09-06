from riscv2x86_py.translation_validation import (
    ProgramArtifact,
    TranslationArtifact,
    ValidationLayerResult,
    ValidationLevel,
    ValidationPlan,
    ValidationProfile,
    ValidationRuntimeRegistry,
    run_translation_validation,
)
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


def _translation(mode=PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY):
    return TranslationArtifact(
        "fragment-1", "source-model-1", "plan-1", "constraint-1", "proof-1",
        mode, "shell-1", "runtime-1", "v1", "recipe-1", (),
        "integer", "pure-c",
    )


def _program(name):
    return ProgramArtifact(name, "/tmp/" + name, "executable", "sha256:" + name, "build-1")


def _plan(profile):
    return ValidationPlan("validation-plan-1", profile, "qemu", "native", 7, 30, "registry-v1", "experiment-v1" if profile is ValidationProfile.MICROARCH else "")


def _registry(calls, levels):
    def validate(**kwargs):
        level = kwargs["level"]
        calls.append(level)
        return ValidationLayerResult(level, ValidationStatus.VERIFIED, "evidence:" + level.value)
    return ValidationRuntimeRegistry("registry-v1", {level: validate for level in levels})


def test_functional_plan_runs_l0_then_l1_and_is_reproducible():
    calls = []
    args = dict(
        translation_artifact=_translation(), source_program_artifact=_program("source"),
        target_program_artifact=_program("target"), validation_plan=_plan(ValidationProfile.FUNCTIONAL),
        target_environment={"architecture": "x86_64"},
        runtime_registry=_registry(calls, (ValidationLevel.L0, ValidationLevel.L1)),
    )
    first = run_translation_validation(**args)
    second = run_translation_validation(**args)
    assert first.status is ValidationStatus.VERIFIED
    assert first.completed_levels == (ValidationLevel.L0, ValidationLevel.L1)
    assert calls == [ValidationLevel.L0, ValidationLevel.L1, ValidationLevel.L0, ValidationLevel.L1]
    assert first.validation_identity == second.validation_identity


def test_missing_layer_runner_is_inconclusive_and_stops_pipeline():
    calls = []
    result = run_translation_validation(
        _translation(), _program("source"), _program("target"),
        _plan(ValidationProfile.FUNCTIONAL), {},
        _registry(calls, (ValidationLevel.L0,)),
    )
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert result.completed_levels == (ValidationLevel.L0,)
    assert result.reason_codes == ("validation.layer-runner-missing:L1",)


def test_strict_architecture_claim_rejects_build_only_profile_before_runner():
    result = run_translation_validation(
        _translation(PreservationMode.ARCHITECTURE_EQUIVALENT),
        _program("source"), _program("target"), _plan(ValidationProfile.BUILD), {},
        _registry([], (ValidationLevel.L0,)),
    )
    assert result.status is ValidationStatus.FAILED
    assert result.reason_codes == ("validation.strict-profile-insufficient",)


def test_microarchitecture_claim_requires_microarch_profile_and_l3():
    result = run_translation_validation(
        _translation(PreservationMode.MICROARCHITECTURE_INTENT_PRESERVED),
        _program("source"), _program("target"), _plan(ValidationProfile.ARCHITECTURAL), {},
        _registry([], (ValidationLevel.L0, ValidationLevel.L1, ValidationLevel.L2)),
    )
    assert result.status is ValidationStatus.FAILED
    assert result.reason_codes == ("validation.microarch-profile-insufficient",)
