from copy import deepcopy

import pytest

from riscv2x86_py.l2_effect_proof import effect_proof_facts_from_dict, identity
from riscv2x86_py.automatic_l2_authority import _proof_effect_authority
from tests.l2_effect_proof_fixtures import attach_effect_proof


def _approval():
    value = {"proofStatus": "approved", "sourceModelId": "model",
             "preservationDecisionId": "decision", "planId": "plan",
             "constraintsId": "constraints", "targetEnvironmentId": "environment",
             "targetCatalogVersion": "catalog"}
    attach_effect_proof(value, "fragment:one")
    return value


def test_effect_proof_is_content_addressed_and_rejects_stale_content():
    raw = _approval()["l2EffectProofFacts"]
    assert effect_proof_facts_from_dict(raw).complete
    stale = deepcopy(raw)
    stale["relations"][0]["preservedProperties"].append("subject")
    with pytest.raises(ValueError, match="identity"):
        effect_proof_facts_from_dict(stale)


def test_effect_proof_rejects_missing_shell_field_and_unknown_schema():
    raw = deepcopy(_approval()["l2EffectProofFacts"])
    del raw["shellRelation"]["earlyClobbers"]
    body = dict(raw); body.pop("factsIdentity")
    raw["factsIdentity"] = identity(body)
    with pytest.raises(ValueError, match="shell relation fields"):
        effect_proof_facts_from_dict(raw)
    raw = deepcopy(_approval()["l2EffectProofFacts"])
    raw["schemaVersion"] = "riscv2x86.l2-effect-proof-facts.v999"
    body = dict(raw); body.pop("factsIdentity")
    raw["factsIdentity"] = identity(body)
    with pytest.raises(ValueError, match="unsupported"):
        effect_proof_facts_from_dict(raw)


def test_semantic_relation_identity_is_independent_of_sample_domain():
    facts = effect_proof_facts_from_dict(_approval()["l2EffectProofFacts"])
    relation = facts.relations[0].approved_relation()
    samples_a = [{"sampleId": "sample:0", "effectRelationIdentity": relation.approval_identity}]
    samples_b = samples_a + [
        {"sampleId": f"sample:{index}", "effectRelationIdentity": relation.approval_identity}
        for index in range(1, 64)]
    assert {x["effectRelationIdentity"] for x in samples_a} == \
        {x["effectRelationIdentity"] for x in samples_b} == {relation.approval_identity}


def test_authority_materializer_only_accepts_phase6d_identity_closed_facts():
    approval = _approval()
    assert _proof_effect_authority(approval, "fragment:one") is not None
    for field in ("proofIdentity", "planId", "constraintsId",
                  "rendererContractIdentity"):
        stale = deepcopy(approval)
        stale[field] = "sha256:" + "0" * 64
        assert _proof_effect_authority(stale, "fragment:one") is None
    assert _proof_effect_authority(approval, "fragment:other") is None
