from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_evidence_closure import (
    L2_PROVIDER_EVIDENCE_SCHEMA, L2ProviderExecutionDisposition,
    execution_plan_for_provider, partial_provider_evidence,
    provider_evidence_fields, provider_execution_disposition,
    provider_precondition_detail, validated_provider_evidence,
)


H = "sha256:" + "1" * 64
O = "sha256:" + "2" * 64


def artifact(fragment="fragment:a"):
    return SimpleNamespace(
        fragment_id=fragment, proof_identity=H, l2_authority_identity=H,
        effect_relation_set_identity=H, l2_authority_complete=True,
        target_route="registered-route", renderer_semantic_contract_id="contract-v1",
        runtime_contract_id="runtime", runtime_contract_version="v1",
    )


def test_complete_provider_evidence_closes_all_required_identities():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        source_observation_identity=O, target_observation_identity=O,
        execution_nonce={"attempt": 1}, dimensions=("logical_operands", "shell_semantics"))
    assert value["evidenceSchemaVersion"] == L2_PROVIDER_EVIDENCE_SCHEMA
    closed, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    assert reasons == ()
    assert closed is not None
    assert all(closed[name] for name in (
        "authorityIdentity", "effectRelationIdentity", "executionIdentity",
        "sourceObservationIdentity", "targetObservationIdentity"))


@pytest.mark.parametrize("name", [
    "authorityIdentity", "effectRelationIdentity", "executionPlanIdentity",
    "environmentAuthorityIdentity", "runtimeAdapterIdentity", "harnessIdentity",
    "executionIdentity",
])
def test_each_missing_identity_fails_closed(name):
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        source_observation_identity=O, target_observation_identity=O,
        execution_nonce={"attempt": 1}, dimensions=("logical_operands",))
    value[name] = ""
    closed, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    assert closed is None
    assert "l2.provider-evidence.identity-missing:" + name in reasons


def test_cross_fragment_authority_and_relation_are_rejected():
    value = provider_evidence_fields(
        artifact("fragment:a"), provider_id="provider", harness_identity=H,
        source_observation_identity=O, target_observation_identity=O,
        execution_nonce={"attempt": 1}, dimensions=("logical_operands",))
    other = artifact("fragment:b")
    other.l2_authority_identity = "sha256:" + "3" * 64
    other.effect_relation_set_identity = "sha256:" + "4" * 64
    closed, reasons = validated_provider_evidence(
        value, other, dimension="logical_operands", provider_id="provider")
    assert closed is None
    assert "l2.provider-evidence.authority-mismatch" in reasons
    assert "l2.provider-evidence.effect-relation-mismatch" in reasons


def test_harness_or_environment_change_changes_execution_plan():
    first = execution_plan_for_provider(
        artifact(), provider_id="provider", harness_identity=H)
    second = execution_plan_for_provider(
        artifact(), provider_id="provider", harness_identity=O)
    changed_environment = artifact()
    changed_environment.target_route = "another-registered-route"
    third = execution_plan_for_provider(
        changed_environment, provider_id="provider", harness_identity=H)
    assert len({first.plan_identity, second.plan_identity, third.plan_identity}) == 3


def test_incomplete_semantic_authority_cannot_create_execution_plan():
    value = artifact()
    value.l2_authority_complete = False
    with pytest.raises(ValueError, match="semantic authority is incomplete"):
        execution_plan_for_provider(value, provider_id="provider", harness_identity=H)


def test_precondition_detail_has_typed_non_execution_disposition():
    detail = provider_precondition_detail("L2_FRAGMENT_BOUNDARY_VALUE_FLOW_UNPROVED")
    disposition, reasons = provider_execution_disposition(detail, "inconclusive")
    assert disposition is L2ProviderExecutionDisposition.PRECONDITION_REJECTED
    assert reasons == ()
    assert set(detail) == {"executionDisposition", "reasonCode"}


def test_executed_inconclusive_retains_partial_evidence_only():
    detail = {
        "evidenceSchemaVersion": L2_PROVIDER_EVIDENCE_SCHEMA,
        "executionDisposition": "executed_inconclusive",
        "authorityIdentity": H,
    }
    evidence, reasons = partial_provider_evidence(
        detail, artifact(), dimension="logical_operands", provider_id="provider")
    assert evidence == {"authorityIdentity": H}
    assert reasons == (
        "l2.provider-evidence.dimension-observation-missing:logical_operands",
        "l2.provider-evidence.execution-plan-invalid",
    )


def test_dimensions_share_execution_but_not_observation_identity():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        source_observation_identity=O, target_observation_identity=O,
        execution_nonce={"attempt": 1},
        dimensions=("logical_operands", "shell_semantics"))
    observations = value["dimensionObservations"]
    assert observations["logical_operands"] != observations["shell_semantics"]
    logical, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    shell, shell_reasons = validated_provider_evidence(
        value, artifact(), dimension="shell_semantics", provider_id="provider")
    assert reasons == shell_reasons == ()
    assert logical["executionIdentity"] == shell["executionIdentity"]
    assert logical["sourceObservationIdentity"] != shell["sourceObservationIdentity"]


def test_execution_plan_payload_tampering_fails_closed():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        source_observation_identity=O, target_observation_identity=O,
        execution_nonce={"attempt": 1}, dimensions=("logical_operands",))
    value["executionPlan"]["providerId"] = "other-provider"
    closed, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    assert closed is None
    assert "l2.provider-evidence.execution-plan-invalid" in reasons


def test_disposition_cannot_claim_verified_for_failed_result():
    detail = {"executionDisposition": "executed_verified"}
    disposition, reasons = provider_execution_disposition(detail, "failed")
    assert disposition is L2ProviderExecutionDisposition.EXECUTED_VERIFIED
    assert reasons == ("l2.provider-execution-disposition.status-mismatch",)
