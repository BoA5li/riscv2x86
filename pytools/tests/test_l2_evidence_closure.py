from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_dimensions import L2Dimension
from riscv2x86_py.l2_evidence_closure import (
    L2_DIMENSION_EVIDENCE_SCHEMA, L2_PROVIDER_EVIDENCE_SCHEMA,
    L2DimensionEvidence, L2EvidenceProductionDisposition,
    L2ProviderExecutionDisposition,
    execution_plan_for_provider, partial_provider_evidence,
    provider_evidence_fields, provider_evidence_production_disposition,
    provider_execution_disposition,
    provider_precondition_detail, validate_provider_dimension_contract,
    validated_provider_evidence,
)


H = "sha256:" + "1" * 64
O = "sha256:" + "2" * 64


def dimensions(*names: L2Dimension):
    return {name: L2DimensionEvidence(
        O, O, ("property:" + name.value,)) for name in names}


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
        execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS))
    assert value["evidenceSchemaVersion"] == L2_PROVIDER_EVIDENCE_SCHEMA
    closed, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    assert reasons == ()
    assert closed is not None
    assert all(closed[name] for name in (
        "authorityIdentity", "effectRelationIdentity", "executionIdentity",
        "sourceObservationIdentity", "targetObservationIdentity"))


def test_program_authority_can_bind_multiple_fragment_plans_to_one_execution():
    from riscv2x86_py.l2_evidence_closure import identity
    payload = {"schemaVersion": "riscv2x86.l2-program-execution.v2",
               "programId": H, "functionId": H,
               "fragmentIds": ["fragment:a", "fragment:b"],
               "dependencyGraphIdentity": H, "executionMode": "composite"}
    authorized = identity(payload)
    values = [provider_evidence_fields(
        artifact(fragment), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": fragment}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS),
        authorized_execution_identity=authorized,
        execution_payload=payload,
    ) for fragment in ("fragment:a", "fragment:b")]
    assert {item["executionIdentity"] for item in values} == {authorized}
    assert (values[0]["executionPlanIdentity"]
            != values[1]["executionPlanIdentity"])


def test_complete_execution_identity_must_recompute_from_payload():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H, execution_nonce={"sample": 1},
        dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS))
    value["executionPayload"]["executionNonce"] = {"sample": 2}
    evidence, reasons = validated_provider_evidence(value, artifact(),
        dimension="logical_operands", provider_id="provider")
    assert evidence is None
    assert "l2.provider-evidence.execution-identity-invalid" in reasons


def test_partial_checks_present_identity_without_reporting_absent_chain():
    evidence, reasons = partial_provider_evidence({"authorityIdentity": "bad"}, artifact(),
        dimension="logical_operands", provider_id="provider")
    assert reasons == ("l2.provider-evidence.partial-identity-invalid:authorityIdentity",)
    assert evidence == {}


@pytest.mark.parametrize("name", [
    "authorityIdentity", "effectRelationIdentity", "executionPlanIdentity",
    "environmentAuthorityIdentity", "runtimeAdapterIdentity", "harnessIdentity",
    "executionIdentity",
])
def test_each_missing_identity_fails_closed(name):
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS))
    value[name] = ""
    closed, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    assert closed is None
    assert "l2.provider-evidence.identity-missing:" + name in reasons


def test_cross_fragment_authority_and_relation_are_rejected():
    value = provider_evidence_fields(
        artifact("fragment:a"), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS))
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
    assert set(detail) == {
        "executionDisposition", "evidenceProductionDisposition", "reasonCode"}
    production, production_reasons = provider_evidence_production_disposition(
        detail, disposition)
    assert production is L2EvidenceProductionDisposition.NOT_PRODUCED
    assert production_reasons == ()


def test_executed_inconclusive_retains_partial_evidence_only():
    detail = {
        "evidenceSchemaVersion": L2_PROVIDER_EVIDENCE_SCHEMA,
        "executionDisposition": "executed_inconclusive",
        "evidenceProductionDisposition": "partial",
        "authorityIdentity": H,
    }
    evidence, reasons = partial_provider_evidence(
        detail, artifact(), dimension="logical_operands", provider_id="provider")
    assert evidence == {"authorityIdentity": H}
    assert reasons == (
        "l2.provider-evidence.partial-incomplete:logical_operands",
    )


def test_dimensions_share_execution_but_not_observation_identity():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": 1},
        dimensions=(L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS))
    observations = value["dimensionObservations"]
    assert observations["logical_operands"] != observations["shell_semantics"]
    logical, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    shell, shell_reasons = validated_provider_evidence(
        value, artifact(), dimension="shell_semantics", provider_id="provider")
    assert reasons == shell_reasons == ()
    assert logical["executionIdentity"] == shell["executionIdentity"]
    assert logical["sourceObservationIdentity"] != shell["sourceObservationIdentity"]
    assert observations["logical_operands"]["schemaVersion"] == \
        L2_DIMENSION_EVIDENCE_SCHEMA
    assert observations["logical_operands"]["observedProperties"] == [
        "property:logical_operands"]


@pytest.mark.parametrize("field", [
    "authorityIdentity", "effectRelationIdentity", "executionIdentity",
])
def test_dimension_identity_cannot_diverge_from_execution_plan(field):
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS))
    value["dimensionObservations"]["logical_operands"][field] = O
    closed, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    assert closed is None
    assert ("l2.provider-evidence.dimension-identity-invalid:logical_operands:"
            + field) in reasons


def test_dimension_without_observed_properties_fails_closed():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS))
    value["dimensionObservations"]["logical_operands"]["observedProperties"] = []
    closed, reasons = validated_provider_evidence(
        value, artifact(), dimension="logical_operands", provider_id="provider")
    assert closed is None
    assert "l2.provider-evidence.observed-properties-incomplete:logical_operands" in reasons


def test_untyped_dimension_evidence_is_rejected_at_provider_boundary():
    with pytest.raises(ValueError, match="not typed"):
        provider_evidence_fields(
            artifact(), provider_id="provider", harness_identity=H,
            execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
            dimension_evidence={L2Dimension.LOGICAL_OPERANDS: {  # type: ignore[dict-item]
                "sourceEvidenceIdentity": O, "targetEvidenceIdentity": O,
            }})


def test_dimension_specific_evidence_must_cover_exact_declared_set():
    with pytest.raises(ValueError, match="does not match declared dimensions"):
        provider_evidence_fields(
            artifact(), provider_id="provider", harness_identity=H,
            execution_nonce={"attempt": 1},
            dimensions=(L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
            dimension_evidence={
                L2Dimension.LOGICAL_OPERANDS: L2DimensionEvidence(O, O, ("operand_value",)),
            },
        )


def test_executed_provider_result_dimension_contract_is_exact():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS))
    assert validate_provider_dimension_contract(
        value, ("logical_operands",)) == ()
    assert validate_provider_dimension_contract(
        value, ("logical_operands", "shell_semantics")) == (
            "l2.provider-evidence.dimension-contract-mismatch",)


def test_execution_plan_payload_tampering_fails_closed():
    value = provider_evidence_fields(
        artifact(), provider_id="provider", harness_identity=H,
        execution_nonce={"attempt": 1}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS))
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


def test_not_produced_evidence_is_not_schema_validated():
    detail = {
        "executionDisposition": "executed_inconclusive",
        "evidenceProductionDisposition": "not_produced",
        "reasonCode": "L2_OPERAND_OBSERVATION_MATERIALIZATION_FAILED",
    }
    execution, execution_reasons = provider_execution_disposition(
        detail, "inconclusive")
    production, production_reasons = provider_evidence_production_disposition(
        detail, execution)
    assert execution_reasons == production_reasons == ()
    assert production is L2EvidenceProductionDisposition.NOT_PRODUCED


@pytest.mark.parametrize("raw", ["partial", "complete"])
def test_produced_evidence_enters_schema_validation(raw):
    detail = {
        "executionDisposition": "executed_inconclusive",
        "evidenceProductionDisposition": raw,
    }
    execution, _ = provider_execution_disposition(detail, "inconclusive")
    production, reasons = provider_evidence_production_disposition(
        detail, execution)
    assert production.value == raw and reasons == ()
    checker = partial_provider_evidence if raw == "partial" else validated_provider_evidence
    _, closure_reasons = checker(
        detail, artifact(), dimension="logical_operands",
        provider_id="provider")
    assert ("l2.provider-evidence.partial-incomplete:logical_operands" if raw == "partial"
            else "l2.provider-evidence.schema-missing-or-unsupported") in closure_reasons
