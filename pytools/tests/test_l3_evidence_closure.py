from __future__ import annotations

from copy import deepcopy

import pytest

from riscv2x86_py.l3_evidence_closure import (
    identity, parse_dimension, parse_fragment, parse_program, close_fragment, close_program,
)

H = "sha256:" + "a" * 64


def requirement(*ids):
    return {"fragmentId": "fragment:0", "programId": "program:0", "profileIdentity": H,
            "requirementIdentity": H, "eligibilityStatus": "eligible",
            "requiredProperties": [{"propertyId": x, "dimension": dimension, "unit": "fragment"}
                                   for x, dimension in ids]}


def dimension(property_id="p:access", dimension_name="access_pattern", *,
              scope="architectural_intent", l2="architectural"):
    payload = {"schemaVersion": "riscv2x86.l3-dimension-result.v1", "fragmentId": "fragment:0",
               "programId": "program:0", "propertyId": property_id, "dimension": dimension_name,
               "unit": "fragment", "status": "verified", "claimScope": scope,
               "requirementIdentity": H, "profileIdentity": H, "contractIdentity": H,
               "translationArtifactIdentity": H, "sourceArtifactIdentity": H, "targetArtifactIdentity": H,
               "sourceReportIdentity": H, "targetReportIdentity": H, "sourceEnvironmentIdentity": H,
               "targetEnvironmentIdentity": H, "executionIdentity": H, "comparisonEvidenceIdentity": H,
               "l0EvidenceIdentity": H, "l1EvidenceIdentity": H, "l2EvidenceIdentity": H,
               "l2ClaimScope": l2, "declaredLimitations": ["cache-geometry-not-claimed"],
               "uncoveredEffects": [], "reasonCodes": []}
    return dict(payload, resultIdentity=identity(payload))


def test_missing_required_dimension_is_inconclusive_and_member_gates_program():
    req = requirement(("p:access", "access_pattern"), ("p:control", "control_flow"))
    result = close_fragment(req, [dimension()], claim_scope="architectural_intent")
    assert result["status"] == "inconclusive"
    group = close_program("program:0", ["fragment:0"], [result], claim_scope="architectural_intent")
    assert group["status"] == "inconclusive"
    completed = close_fragment(req, [dimension(), dimension("p:control", "control_flow")],
                               claim_scope="architectural_intent")
    assert completed["status"] == "verified"
    assert close_program("program:0", ["fragment:0", "fragment:missing"], [completed],
                         claim_scope="architectural_intent")["status"] == "inconclusive"
    group = close_program("program:0", ["fragment:0"], [completed], claim_scope="architectural_intent")
    assert group["executionSampleCount"] == 1  # two properties share one execution
    assert parse_program(group, [completed]) == group
    forged_group = dict(group, executionSampleCount=2)
    forged_group["resultIdentity"] = identity({k: v for k, v in forged_group.items() if k != "resultIdentity"})
    with pytest.raises(ValueError, match="closure mismatch"):
        parse_program(forged_group, [completed])


def test_content_hash_and_report_hash_and_stale_contract_rejected():
    value = dimension()
    tampered = dict(value, contractIdentity="sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="content identity"):
        parse_dimension(tampered)
    with pytest.raises(ValueError, match="source report content"):
        parse_dimension(value, source_report={"event": "different"})
    stale = dict(dimension(), requirementIdentity="sha256:" + "b" * 64)
    stale["resultIdentity"] = identity({k: v for k, v in stale.items() if k != "resultIdentity"})
    with pytest.raises(ValueError, match="identity mismatch"):
        close_fragment(requirement(("p:access", "access_pattern")), [stale],
                       claim_scope="architectural_intent")


def test_effects_scope_and_unrequested_property_fail_closed():
    req = requirement(("p:access", "access_pattern"))
    assert close_fragment(req, [dimension()], claim_scope="architectural_intent",
                          uncovered_effects=["unexpected:write"])["status"] == "inconclusive"
    with pytest.raises(ValueError, match="scope"):
        parse_dimension(dimension(scope="architectural_intent", l2="approved_functional_relation"))
    with pytest.raises(ValueError, match="unrequested"):
        close_fragment(req, [dimension(), dimension("p:control", "control_flow")],
                       claim_scope="architectural_intent")
    two = requirement(("p:access", "access_pattern"), ("p:control", "control_flow"))
    mixed = dimension("p:control", "control_flow")
    mixed["executionIdentity"] = "sha256:" + "b" * 64
    mixed["resultIdentity"] = identity({k: v for k, v in mixed.items() if k != "resultIdentity"})
    with pytest.raises(ValueError, match="mixes incompatible"):
        close_fragment(two, [dimension(), mixed], claim_scope="architectural_intent")
    diagnostic = close_fragment(req, [dimension(scope="target_experiment_diagnostic",
                                                l2="approved_functional_relation")],
                                claim_scope="target_experiment_diagnostic")
    assert diagnostic["status"] == "verified"
    assert diagnostic["claimScope"] != "architectural_intent"
    with pytest.raises(ValueError, match="scope conflict"):
        close_program("program:0", ["fragment:0"], [diagnostic], claim_scope="architectural_intent")


def test_forged_result_and_duplicate_execution_never_inflate_program():
    req = requirement(("p:access", "access_pattern"))
    closed = close_fragment(req, [dimension()], claim_scope="architectural_intent")
    forged = deepcopy(closed)
    forged["dimensionResults"]["p:access"]["comparisonEvidenceIdentity"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="content identity"):
        parse_fragment(forged)
    with pytest.raises(ValueError, match="conflict"):
        close_program("program:0", ["fragment:0"], [closed, closed], claim_scope="architectural_intent")


def test_paper_layer_classifies_diagnostic_separately_from_formal_l3():
    import json
    from riscv2x86_py.paper_evaluation import _validation_maps

    req = requirement(("p:access", "access_pattern"))
    reports = {"source": {"event": "a"}, "target": {"event": "b"}}
    def observed(scope, l2):
        item = dimension(scope=scope, l2=l2)
        item["sourceReportIdentity"] = identity(reports["source"])
        item["targetReportIdentity"] = identity(reports["target"])
        item["resultIdentity"] = identity({k: v for k, v in item.items() if k != "resultIdentity"})
        return item
    diagnostic = close_fragment(req, [observed("target_experiment_diagnostic", "approved_functional_relation")],
                                claim_scope="target_experiment_diagnostic")
    layers = [{"level": "L3", "status": "verified", "evidenceIdentity": H,
               "detail": json.dumps({"fragmentResult": diagnostic, "platformReports": reports})}]
    evaluation = {"attempts": [{"fragmentId": "fragment:0", "validation": {"layers": layers}}]}
    statuses, *_ = _validation_maps(evaluation, {"fragment:0"})
    assert statuses["L3"] == "diagnostic_verified"
    layers[0]["detail"] = json.dumps({"fragmentResult": close_fragment(req, [observed("architectural_intent", "architectural")],
                               claim_scope="architectural_intent"), "platformReports": reports})
    statuses, *_ = _validation_maps(evaluation, {"fragment:0"})
    assert statuses["L3"] == "verified"
    stale = json.loads(layers[0]["detail"])
    stale["platformReports"]["source"]["event"] = "tampered"
    layers[0]["detail"] = json.dumps(stale)
    statuses, *_ = _validation_maps(evaluation, {"fragment:0"})
    assert statuses["L3"] == "inconclusive"
    layers[0]["detail"] = "successful experiment"
    statuses, *_ = _validation_maps(evaluation, {"fragment:0"})
    assert statuses["L3"] == "inconclusive"
