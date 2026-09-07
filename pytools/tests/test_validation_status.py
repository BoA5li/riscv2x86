from copy import deepcopy
from hashlib import sha256

from riscv2x86_py.validation_status import (
    WRITEBACK_VALIDATION_EVIDENCE_VERSION,
    PreservationMode,
    ValidationStatus,
    admit_writeback,
    normalize_validation_status,
)


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode()).hexdigest()


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
        "proofIdentity": "proof-1",
        "shellSemanticsPreserved": True,
        "shellFactsIdentity": "shell-facts-1",
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
        "proofIdentity": "proof-1",
        "shellFactsIdentity": "shell-facts-1",
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


def test_status_normalization_accepts_strings_and_declared_enum_type():
    assert normalize_validation_status("verified") is ValidationStatus.VERIFIED
    assert normalize_validation_status(ValidationStatus.VERIFIED) is ValidationStatus.VERIFIED
    assert normalize_validation_status(ValidationStatus.FAILED) is ValidationStatus.FAILED


def test_legacy_build_only_is_inconclusive_and_cannot_write_back():
    assert normalize_validation_status("build_only") is ValidationStatus.INCONCLUSIVE
    result = admit_writeback("build_only")
    assert not result.allowed
    assert result.status is ValidationStatus.INCONCLUSIVE


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
         "validation.writeback-profile-insufficient"),
        (lambda item: item["validationEvidence"]["levels"].pop("L2"),
         "validation.writeback-level-evidence-incomplete"),
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
