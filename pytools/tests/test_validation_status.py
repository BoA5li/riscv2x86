from riscv2x86_py.validation_status import (
    ValidationStatus,
    admit_writeback,
    normalize_validation_status,
)


def test_legacy_build_only_is_inconclusive_and_cannot_write_back():
    assert normalize_validation_status("build_only") is ValidationStatus.INCONCLUSIVE
    result = admit_writeback("build_only")
    assert not result.allowed
    assert result.status is ValidationStatus.INCONCLUSIVE


def test_only_verified_can_write_back_architecture_equivalent_output():
    assert admit_writeback("verified", approval_artifact={
        "preservationMode": "architecture_equivalent",
        "proofStatus": "approved",
    }).allowed
    assert not admit_writeback("failed").allowed
    assert not admit_writeback("not_verified").allowed


def test_functional_writeback_requires_complete_fallback_manifest():
    incomplete = {
        "preservationMode": "functional_equivalence_only",
        "proofStatus": "functional_approved",
    }
    assert not admit_writeback("verified", approval_artifact=incomplete).allowed

    complete = {
        **incomplete,
        "functionalFallbackEnabled": True,
        "architectureSemanticsPreserved": False,
        "microarchitectureSemanticsPreserved": False,
        "ignoredSourceState": (),
    }
    assert admit_writeback("verified", approval_artifact=complete).allowed


def test_microarchitecture_claim_requires_l0_to_l3_contract_evidence():
    artifact = {
        "preservationMode": "microarchitecture_intent_preserved",
        "microarchitectureSemanticsPreserved": True,
    }
    assert not admit_writeback("verified", approval_artifact=artifact).allowed
    artifact.update({
        "validationLevels": ("L0", "L1", "L2", "L3"),
        "microarchitectureExperimentContractId": "spin-wait.v1",
    })
    assert admit_writeback("verified", approval_artifact=artifact).allowed
