from copy import deepcopy
from dataclasses import replace
from hashlib import sha256

from riscv2x86_py.validation_status import (
    WRITEBACK_VALIDATION_EVIDENCE_VERSION,
    PreservationMode,
    ValidationStatus,
    admit_writeback as _typed_admit_writeback,
    normalize_validation_status,
)
from riscv2x86_py.l0_artifact_manifest import (
    ExpectedArtifact, ExpectedElf, L0ArtifactManifest,
)
from riscv2x86_py.translation_validation import (
    ProgramArtifact, TargetEnvironment, TranslationArtifact, TranslationValidationResult,
    ValidationLayerResult, ValidationLevel, ValidationPlan, ValidationProfile,
)
from riscv2x86_py.output_manifest import build_output_manifest, output_manifest_from_dict


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode()).hexdigest()


PROOF = _digest("proof-1")
SHELL = _digest("shell-facts-1")


def _evidence(profile: str, levels: tuple[str, ...], ignored=()):
    manifest = _digest("manifest")
    source = _digest("source")
    target = _digest("target")
    return {
        "schemaVersion": WRITEBACK_VALIDATION_EVIDENCE_VERSION,
        "validationStatus": "verified",
        "validationIdentity": _digest("validation"),
        "validationProfile": profile,
        "levels": {
            level: {
                "status": "verified",
                "evidenceIdentity": _digest("evidence:" + level),
            }
            for level in levels
        },
        "proofIdentity": PROOF,
        "shellSemanticsPreserved": True,
        "shellFactsIdentity": SHELL,
        "runtimeRegistryVersion": "registry-v1",
        "translationManifestDigest": manifest,
        "sourceArtifactDigest": source,
        "targetArtifactDigest": target,
        "artifactManifestBinding": {
            "translationManifestDigest": manifest,
            "sourceArtifactDigest": source,
            "targetArtifactDigest": target,
        },
        "observationBinding": {
            "sourceObservationIdentity": _digest("source-observation"),
            "targetObservationIdentity": _digest("target-observation"),
            "translationManifestDigest": manifest,
            "sourceArtifactDigest": source,
            "targetArtifactDigest": target,
        },
        "runtimeContractId": "runtime-1",
        "runtimeContractVersion": "v1",
        "ignoredSourceState": list(ignored),
        "ignoredStateEscapes": False,
    }


def _artifact(mode: str, profile: str, levels: tuple[str, ...], ignored=()):
    functional = mode == "functional_equivalence_only"
    microarch = mode == "microarchitecture_intent_preserved"
    artifact = {
        "preservationMode": mode,
        "proofStatus": "functional_approved" if functional else "approved",
        "proofIdentity": PROOF,
        "shellFactsIdentity": SHELL,
        "shellSemanticsPreserved": True,
        "runtimeContractId": "runtime-1",
        "runtimeContractVersion": "v1",
        "ignoredSourceState": list(ignored),
        "functionalFallbackEnabled": functional,
        "architectureSemanticsPreserved": not functional,
        "microarchitectureSemanticsPreserved": microarch,
        "validationEvidence": _evidence(profile, levels, ignored),
    }
    artifact["validationEvidence"]["proofStatus"] = artifact["proofStatus"]
    for name in (
        "validationIdentity", "validationProfile", "validationStatus",
        "translationManifestDigest", "sourceArtifactDigest",
        "targetArtifactDigest",
    ):
        artifact[name] = artifact["validationEvidence"][name]
    if microarch:
        artifact["microarchitectureExperimentContractId"] = "spin-wait.v1"
        artifact["validationEvidence"][
            "microarchitectureExperimentContractId"
        ] = "spin-wait.v1"
    return artifact


def _set_profile(artifact, profile: str) -> None:
    artifact["validationProfile"] = profile
    artifact["validationEvidence"]["validationProfile"] = profile


def _typed_inputs(artifact, status="verified"):
    mode_value = artifact.get("preservationMode", "architecture_equivalent")
    mode = mode_value if isinstance(mode_value, PreservationMode) else PreservationMode(mode_value)
    translation = TranslationArtifact(
        "fragment-1", "source-model-1", "plan-1", "constraint-1",
        artifact.get("proofIdentity", PROOF), mode,
        artifact.get("shellFactsIdentity", SHELL),
        artifact.get("runtimeContractId", "runtime-1"),
        artifact.get("runtimeContractVersion", "v1"), "recipe-1",
        tuple(artifact.get("ignoredSourceState", ())), "integer", "c",
    )
    source_digest = artifact.get("sourceArtifactDigest", _digest("source"))
    target_digest = artifact.get("targetArtifactDigest", _digest("target"))
    source = ProgramArtifact("source", "/tmp/source.o", "object", source_digest)
    target = ProgramArtifact("target", "/tmp/target", "executable", target_digest)
    elf = ExpectedElf(
        "ELF64", "little", "REL", "RISC-V", "UNIX - System V", "0",
        "", "", (), (), "", (), (),
    )
    target_elf = ExpectedElf(
        "ELF64", "little", "EXEC", "Advanced Micro Devices X86-64",
        "UNIX - System V", "0", "", "", (), (), "", (), (),
    )
    source_expected = ExpectedArtifact(
        source_digest, source_digest, "object", "riscv64-linux-gnu-gcc",
        "riscv64-linux-gnu", (), (), elf, elf,
    )
    target_expected = ExpectedArtifact(
        target_digest, _digest("target-object"), "executable", "gcc",
        "x86_64-linux-gnu", (), (), target_elf, elf,
    )
    manifest = L0ArtifactManifest(
        translation.identity, translation.translation_plan_id,
        translation.proof_identity, translation.runtime_contract_id,
        translation.runtime_contract_version, translation.recipe_id,
        (), (), (), (), source_expected,
        {"gcc-O0-none": target_expected},
    )
    evidence = artifact.get("validationEvidence", {})
    profile = ValidationProfile(evidence.get("validationProfile", "architectural"))
    layers = tuple(
        ValidationLayerResult(
            ValidationLevel(name), ValidationStatus(item["status"]),
            item.get("evidenceIdentity", ""),
        )
        for name, item in evidence.get("levels", {}).items()
    )
    validation_status = normalize_validation_status(status)
    completed = tuple(item.level for item in layers if item.status is ValidationStatus.VERIFIED)
    result = TranslationValidationResult(
        validation_status, profile, completed, layers, (),
        evidence.get("validationIdentity", _digest("validation")),
    )
    environment = TargetEnvironment(
        "env-1", "rv64gc", "lp64d", "x86_64", "sysv_amd64",
        ("qemu",), ("native",), ("none",), "runtime-env-v1", "loader-v1",
    )
    plan = ValidationPlan(
        "validation-plan-1", profile, "qemu", "native", 1, 30, "registry-v1",
        "spin-wait.v1" if profile is ValidationProfile.MICROARCH else "",
    )
    output = build_output_manifest(
        result=result, plan=plan, translation=translation, source=source, target=target,
        environment=environment, artifact_manifest_digest=_digest("manifest"),
        approval_artifact=artifact,
        ignored_state_escapes=bool(evidence.get("ignoredStateEscapes", False)),
        l3_required=profile is ValidationProfile.MICROARCH,
    )
    return result, manifest, translation, source, target, environment, output


def admit_writeback(status, *, approval_artifact=None):
    artifact = approval_artifact or {}
    result, manifest, translation, source, target, environment, output = _typed_inputs(artifact, status)
    return _typed_admit_writeback(
        result, manifest, manifest_digest=_digest("manifest"),
        translation_artifact=translation, source_program_artifact=source,
        target_program_artifact=target, target_environment=environment,
        output_manifest=output, approval_artifact=artifact,
    )


def _admit_typed(artifact, result, manifest, translation, source, target, environment, output):
    return _typed_admit_writeback(
        result, manifest, manifest_digest=_digest("manifest"),
        translation_artifact=translation, source_program_artifact=source,
        target_program_artifact=target, target_environment=environment,
        output_manifest=output, approval_artifact=artifact,
    )


def test_status_normalization_accepts_strings_and_declared_enum_type():
    assert normalize_validation_status("verified") is ValidationStatus.VERIFIED
    assert normalize_validation_status(ValidationStatus.VERIFIED) is ValidationStatus.VERIFIED
    assert normalize_validation_status(ValidationStatus.FAILED) is ValidationStatus.FAILED


def test_legacy_build_only_is_inconclusive_and_cannot_write_back():
    assert normalize_validation_status("build_only") is ValidationStatus.INCONCLUSIVE
    result = admit_writeback("build_only")
    assert not result.allowed
    assert result.status is ValidationStatus.INCONCLUSIVE


def test_public_gate_rejects_the_old_status_only_call_contract():
    try:
        _typed_admit_writeback("verified")
    except TypeError:
        pass
    else:
        raise AssertionError("status-only writeback API must not remain callable")


def test_gate_rejects_result_that_does_not_match_bound_evidence():
    artifact = _artifact(
        "architecture_equivalent", "architectural", ("L0", "L1", "L2"),
    )
    result, manifest, translation, source, target, environment, output = _typed_inputs(artifact)
    spoofed = replace(result, validation_identity=_digest("other-validation"))
    admission = _admit_typed(
        artifact, spoofed, manifest, translation, source, target, environment, output,
    )
    assert not admission.allowed
    assert admission.reason_code == "validation.writeback-result-evidence-mismatch"


def test_gate_rejects_parsed_manifest_from_another_translation():
    artifact = _artifact(
        "architecture_equivalent", "architectural", ("L0", "L1", "L2"),
    )
    result, manifest, translation, source, target, environment, output = _typed_inputs(artifact)
    stale = replace(manifest, translation_identity=_digest("other-translation"))
    admission = _admit_typed(
        artifact, result, stale, translation, source, target, environment, output,
    )
    assert not admission.allowed
    assert admission.reason_code == "validation.writeback-typed-manifest-binding-mismatch"


def test_gate_rejects_program_artifact_not_bound_to_manifest():
    artifact = _artifact(
        "architecture_equivalent", "architectural", ("L0", "L1", "L2"),
    )
    result, manifest, translation, source, target, environment, output = _typed_inputs(artifact)
    stale_target = replace(target, artifact_digest=_digest("stale-target"))
    admission = _admit_typed(
        artifact, result, manifest, translation, source, stale_target, environment, output,
    )
    assert not admission.allowed
    assert admission.reason_code == "validation.writeback-typed-manifest-binding-mismatch"


def test_non_verified_status_never_writes_back():
    artifact = _artifact(
        "architecture_equivalent", "architectural", ("L0", "L1", "L2"),
    )
    assert not admit_writeback("failed", approval_artifact=artifact).allowed
    assert not admit_writeback("inconclusive", approval_artifact=artifact).allowed
    assert not admit_writeback("not_verified", approval_artifact=artifact).allowed


def test_architecture_writeback_requires_complete_bound_l0_l1_l2_evidence():
    artifact = _artifact(
        "architecture_equivalent", "architectural", ("L0", "L1", "L2"),
    )
    assert admit_writeback(ValidationStatus.VERIFIED, approval_artifact=artifact).allowed

    for mutation, reason in (
        (lambda item: item.pop("validationEvidence"), "validation.writeback-evidence-missing"),
        (lambda item: item.update(validationIdentity=_digest("other-validation")),
         "validation.writeback-manifest-evidence-mismatch"),
        (lambda item: _set_profile(item, "functional"),
         "validation.writeback-result-levels-invalid"),
        (lambda item: item["validationEvidence"]["levels"].pop("L2"),
         "validation.writeback-result-levels-invalid"),
        (lambda item: item.update(proofIdentity="different-proof"),
         "validation.writeback-proof-identity-mismatch"),
        (lambda item: item.update(shellSemanticsPreserved=False),
         "validation.writeback-shell-evidence-incomplete"),
        (lambda item: item["validationEvidence"]["artifactManifestBinding"].update(
            targetArtifactDigest=_digest("other-target")),
         "validation.writeback-artifact-binding-incomplete"),
        (lambda item: item["validationEvidence"]["observationBinding"].update(
            translationManifestDigest=_digest("other-manifest")),
         "validation.writeback-observation-binding-incomplete"),
        (lambda item: item["validationEvidence"].update(runtimeContractVersion="v2"),
         "validation.writeback-runtime-contract-mismatch"),
    ):
        candidate = deepcopy(artifact)
        mutation(candidate)
        result = admit_writeback("verified", approval_artifact=candidate)
        assert not result.allowed
        assert result.reason_code == reason


def test_architecture_equivalence_cannot_ignore_source_state():
    artifact = _artifact(
        "architecture_equivalent", "architectural", ("L0", "L1", "L2"),
        ignored=("csr:cycle",),
    )
    result = admit_writeback("verified", approval_artifact=artifact)
    assert not result.allowed
    assert result.reason_code == "validation.architecture-ignored-state-not-empty"


def test_functional_writeback_requires_l0_l1_observations_and_non_escaping_ignored_state():
    artifact = _artifact(
        "functional_equivalence_only", "functional", ("L0", "L1"),
        ignored=("csr:cycle-rate",),
    )
    assert admit_writeback("verified", approval_artifact=artifact).allowed

    escaping = deepcopy(artifact)
    escaping["validationEvidence"]["ignoredStateEscapes"] = True
    result = admit_writeback("verified", approval_artifact=escaping)
    assert not result.allowed
    assert result.reason_code == "validation.writeback-ignored-state-escape-unproven"

    unbound = deepcopy(artifact)
    unbound["validationEvidence"].pop("observationBinding")
    assert not admit_writeback("verified", approval_artifact=unbound).allowed


def test_microarchitecture_claim_requires_verified_l0_to_l3_and_matching_contract():
    artifact = _artifact(
        "microarchitecture_intent_preserved", "microarch",
        ("L0", "L1", "L2", "L3"),
    )
    assert admit_writeback("verified", approval_artifact=artifact).allowed

    spoofed = deepcopy(artifact)
    spoofed["validationEvidence"].pop("levels")
    spoofed["validationLevels"] = ("L0", "L1", "L2", "L3")
    assert not admit_writeback("verified", approval_artifact=spoofed).allowed

    failed_l3 = deepcopy(artifact)
    failed_l3["validationEvidence"]["levels"]["L3"]["status"] = "failed"
    assert not admit_writeback("verified", approval_artifact=failed_l3).allowed

    mismatched = deepcopy(artifact)
    mismatched["validationEvidence"][
        "microarchitectureExperimentContractId"
    ] = "different.v1"
    result = admit_writeback("verified", approval_artifact=mismatched)
    assert not result.allowed
    assert result.reason_code == "validation.microarch-evidence-incomplete"


def test_unknown_preservation_mode_is_rejected():
    result = admit_writeback("verified", approval_artifact={})
    assert not result.allowed
    assert result.reason_code == "validation.writeback-preservation-mode-missing"


def test_preservation_mode_parser_accepts_declared_enum_type():
    artifact = _artifact(
        "architecture_equivalent", "architectural", ("L0", "L1", "L2"),
    )
    artifact["preservationMode"] = PreservationMode.ARCHITECTURE_EQUIVALENT
    assert admit_writeback("verified", approval_artifact=artifact).allowed


def test_output_manifest_v3_round_trip_and_identity_are_stable():
    artifact = _artifact("architecture_equivalent", "architectural", ("L0", "L1", "L2"))
    _, _, _, _, _, _, output = _typed_inputs(artifact)
    parsed = output_manifest_from_dict(output.to_dict())
    assert parsed == output
    assert parsed.identity == output.identity
    assert parsed.schema_version == "riscv2x86.output-manifest.v3"


def test_gate_rejects_output_manifest_validation_or_environment_spoofing():
    artifact = _artifact("architecture_equivalent", "architectural", ("L0", "L1", "L2"))
    result, manifest, translation, source, target, environment, output = _typed_inputs(artifact)
    stale = replace(output, validation_identity=_digest("stale-validation"))
    admission = _admit_typed(
        artifact, result, manifest, translation, source, target, environment, stale,
    )
    assert admission.reason_code == "validation.output-manifest-validation-binding-mismatch"

    wrong_environment = replace(
        output, required_environment=replace(output.required_environment, target_mode="x86_64-kernel"),
    )
    admission = _admit_typed(
        artifact, result, manifest, translation, source, target, environment, wrong_environment,
    )
    assert admission.reason_code == "validation.output-manifest-environment-mismatch"


def test_functional_output_manifest_requires_declared_non_escaping_ignored_state():
    artifact = _artifact("functional_equivalence_only", "functional", ("L0", "L1"),
                         ignored=("csr:cycle-rate",))
    result, manifest, translation, source, target, environment, output = _typed_inputs(artifact)
    undeclared = replace(output, ignored_source_state=())
    admission = _admit_typed(
        artifact, result, manifest, translation, source, target, environment, undeclared,
    )
    assert admission.reason_code == "validation.output-manifest-ignored-state-invalid"


def test_l3_required_output_cannot_use_architectural_profile_without_contract():
    artifact = _artifact("architecture_equivalent", "architectural", ("L0", "L1", "L2"))
    result, manifest, translation, source, target, environment, output = _typed_inputs(artifact)
    l3_required = replace(output, l3_required=True)
    admission = _admit_typed(
        artifact, result, manifest, translation, source, target, environment, l3_required,
    )
    assert admission.reason_code == "validation.output-manifest-l3-contract-missing"
