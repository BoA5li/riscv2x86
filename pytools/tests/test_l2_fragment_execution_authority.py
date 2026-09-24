from copy import deepcopy
from pathlib import Path

import pytest

from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_fragment_execution import (
    fragment_boundary_from_dict, materialize_fragment_execution_authority,
    program_execution_authority_from_dict,
)
from tests.l2_profile_fixtures import profile_dict
from tests.l2_effect_proof_fixtures import attach_effect_proof


def _function(*, cycle=False, same_name=False):
    from riscv2x86_py.compiler_value_flow import identity as flow_identity
    first_out = "tmp-a" if same_name else "tmp"
    second_in = "tmp-b" if same_name else "tmp"
    declarations = {
        "x": {"name": "x", "type": "uint64_t"},
        first_out: {"name": "tmp", "type": "uint64_t"},
        second_in: {"name": "tmp", "type": "uint64_t"},
        "out": {"name": "out", "type": "uint64_t"},
    }
    first_ids = [first_out, "out" if cycle else "x"]
    second_ids = ["out", second_in]
    function_id = "sha256:" + "8" * 64
    key_a = {"functionIdentity": function_id, "beginOffset": 10, "endOffset": 20}
    key_b = {"functionIdentity": function_id, "beginOffset": 30, "endOffset": 40}
    candidate_a = flow_identity({
        "schemaVersion": "riscv2x86.compiler-fragment-binding-key.v1", **key_a})
    candidate_b = flow_identity({
        "schemaVersion": "riscv2x86.compiler-fragment-binding-key.v1", **key_b})
    def node(tag):
        return "sha256:" + tag * 64
    def value_node(declaration, value, candidate):
        ast, type_id = node("d"), node("e")
        value = flow_identity({
            "schemaVersion": "riscv2x86.compiler-value-node.v1",
            "declarationIdentity": declaration,
            "definingAstNodeIdentity": ast,
            "definingFragmentId": candidate, "typeIdentity": type_id,
            "widthBits": 64, "signedness": "unsigned"})
        return {"schemaVersion": "riscv2x86.compiler-value-node.v1",
                "nodeIdentity": value, "declarationIdentity": declaration,
                "definingAstNodeIdentity": ast,
                "definingFragmentId": candidate, "typeIdentity": type_id,
                "widthBits": 64, "signedness": "unsigned", "complete": True}
    def binding(index, declaration, value, access):
        return {"operandIndex": index, "declarationIdentity": declaration,
                "valueNodeIdentity": value, "access": access, "widthBits": 64,
                "signedness": "unsigned", "complete": True}
    a_out = value_node(first_ids[0], "", candidate_a)["nodeIdentity"]
    a_in = value_node(first_ids[1], "", candidate_a)["nodeIdentity"]
    b_out = value_node(second_ids[0], "", candidate_b)["nodeIdentity"]
    b_in = value_node(second_ids[1], "", candidate_b)["nodeIdentity"]
    a_use = ({"valueNodeIdentity": a_out, "useNodeIdentity": node("5"),
              "useKind": "subsequent_asm_input", "consumerFragmentIdentity": candidate_b,
              "observationSinkIdentity": node("6"), "relationKind": "fragment_operand",
              "complete": True}
             if first_out == second_in else
             {"valueNodeIdentity": a_out, "useNodeIdentity": node("5"),
              "useKind": "discarded", "consumerFragmentIdentity": "",
              "observationSinkIdentity": "", "relationKind": "discarded",
              "complete": True})
    b_use = {"valueNodeIdentity": b_out, "useNodeIdentity": node("7"),
             "useKind": "function_return", "consumerFragmentIdentity": "",
             "observationSinkIdentity": node("9"), "relationKind": "function_return",
             "complete": True}
    candidates = [
        {"schemaVersion": "riscv2x86.compiler-fragment-boundary-candidate.v2",
         "asmIndex": 0, "fragmentBindingKey": key_a, "candidateIdentity": candidate_a,
         "asmOperandDeclarationIds": first_ids,
         "valueNodes": [value_node(first_ids[0], a_out, candidate_a),
                        value_node(first_ids[1], a_in, candidate_a)],
         "operandBindings": [binding(0, first_ids[0], a_out, "output"),
                             binding(1, first_ids[1], a_in, "input")],
         "downstreamUses": [a_use], "complete": True},
        {"schemaVersion": "riscv2x86.compiler-fragment-boundary-candidate.v2",
         "asmIndex": 1, "fragmentBindingKey": key_b, "candidateIdentity": candidate_b,
         "asmOperandDeclarationIds": second_ids,
         "valueNodes": [value_node(second_ids[0], b_out, candidate_b),
                        value_node(second_ids[1], b_in, candidate_b)],
         "operandBindings": [binding(0, second_ids[0], b_out, "output"),
                             binding(1, second_ids[1], b_in, "input")],
         "downstreamUses": [b_use], "complete": True},
    ]
    if cycle:
        candidates[1]["downstreamUses"] = [{
            "valueNodeIdentity": b_out, "useNodeIdentity": node("7"),
            "useKind": "subsequent_asm_input", "consumerFragmentIdentity": candidate_a,
            "observationSinkIdentity": node("9"), "relationKind": "fragment_operand",
            "complete": True}]
    return {
        "name": "sequence", "functionId": function_id,
        "programId": "sha256:" + "9" * 64, "arity": 1,
        "returnType": "uint64_t", "parameterTypes": ["uint64_t"],
        "l2OperandBoundary": {
            "schemaVersion": "riscv2x86.compiler-operand-boundary.v2",
            "complete": False, "parameterDeclarationIds": ["x"],
            "asmOperandDeclarationIds": [], "returnDeclarationId": "out",
            "declarations": declarations,
            "declarationReferenceCounts": {key: 1 for key in declarations},
            "asmStatementEndOffset": -1,
            "fragmentCandidates": candidates,
        },
    }


def _finding(fragment_id, output, input_):
    return {
        "translationOutcome": "emitted",
        "fragment": {"id": fragment_id, "enclosingFunction": "sequence",
                     "beginOffset": 12 if fragment_id.endswith("a") else 32,
                     "endOffset": 18 if fragment_id.endswith("a") else 38,
                     "outputs": [{"constraint": "=r", "symbolicName": output}],
                     "inputs": [{"constraint": "r", "symbolicName": input_}]},
        "l2SemanticProfile": profile_dict(fragment_id),
        "approvalArtifact": {
            "proofStatus": "approved", "architectureSemanticsPreserved": True,
            "shellSemanticsPreserved": True, "sourceModelId": "model:" + fragment_id,
            "constraintsId": "constraints:" + fragment_id,
            "preservationDecisionId": "decision:" + fragment_id,
            "planId": "plan:" + fragment_id, "targetEnvironmentId": "environment",
            "targetCatalogVersion": "catalog",
        },
    }


def _findings():
    findings = [_finding("fragment:a", "tmp", "x"),
                _finding("fragment:b", "out", "tmp")]
    for finding in findings:
        attach_effect_proof(finding["approvalArtifact"], finding["fragment"]["id"])
    return findings


def test_two_fragments_get_independent_boundaries_and_shared_execution(tmp_path: Path):
    findings, function = _findings(), _function()
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": findings}, [function], frontend) == 2
    executions = set()
    observations = set()
    for finding in findings:
        approval = finding["approvalArtifact"]
        boundary = fragment_boundary_from_dict(
            approval["l2FragmentOperandBoundary"],
            expected_fragment_id=finding["fragment"]["id"])
        execution = program_execution_authority_from_dict(
            approval["l2ProgramExecutionAuthority"],
            expected_fragment_id=finding["fragment"]["id"])
        assert boundary.complete and execution.complete
        assert execution.execution_mode == "composite"
        assert approval["l2AuthoritySidecar"]["authorityIdentity"]
        assert approval["l2AuthoritySidecar"]["approvedEffectRelations"]
        assert approval["shellFactsIdentity"]
        executions.add(execution.execution_identity)
        observations.add(execution.observation_identity(
            boundary.fragment_id, "logical_operands", "source"))
    assert len(executions) == 1
    assert len(observations) == 2
    graph = findings[0]["approvalArtifact"]["l2FragmentDependencyGraph"]
    assert len(graph["edges"]) == 1
    edge = graph["edges"][0]
    assert edge["producerFragmentId"] == "fragment:a"
    assert edge["consumerFragmentId"] == "fragment:b"
    assert edge["valueNodeIdentity"].startswith("sha256:")
    assert edge["consumerValueNodeIdentity"].startswith("sha256:")
    assert edge["valueNodeIdentity"] != edge["consumerValueNodeIdentity"]


def test_swapping_fragment_boundaries_is_rejected(tmp_path: Path):
    findings, function = _findings(), _function()
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    materialize_automatic_l2_authority({"findings": findings}, [function], frontend)
    left = findings[0]["approvalArtifact"]; right = findings[1]["approvalArtifact"]
    left["l2FragmentOperandBoundary"], right["l2FragmentOperandBoundary"] = (
        right["l2FragmentOperandBoundary"], left["l2FragmentOperandBoundary"])
    with pytest.raises(ValueError, match="fragment boundary"):
        fragment_boundary_from_dict(
            left["l2FragmentOperandBoundary"], expected_fragment_id="fragment:a")


def test_deleted_live_out_keeps_graph_inconclusive():
    findings, function = _findings(), _function()
    function = deepcopy(function)
    function["l2OperandBoundary"]["fragmentCandidates"][0]["downstreamUses"] = []
    boundaries, graph, execution = materialize_fragment_execution_authority(
        findings, function, function["programId"])
    assert not boundaries["fragment:a"].complete
    assert "L2_FRAGMENT_LIVE_OUT_UNPROVED" in boundaries["fragment:a"].reason_codes
    assert not graph.complete and not execution.complete


def test_fragment_dependency_cycle_is_inconclusive():
    findings = [_finding("fragment:a", "tmp", "out"),
                _finding("fragment:b", "out", "tmp")]
    _boundaries, graph, execution = materialize_fragment_execution_authority(
        findings, _function(cycle=True), "sha256:" + "9" * 64)
    assert graph.execution_mode == "inconclusive"
    assert "L2_FRAGMENT_DEPENDENCY_CYCLE" in graph.reason_codes
    assert not execution.complete and execution.execution_identity == ""


def test_same_operand_name_with_distinct_identity_does_not_create_edge():
    findings = [_finding("fragment:a", "tmp", "x"),
                _finding("fragment:b", "out", "tmp")]
    boundaries, graph, execution = materialize_fragment_execution_authority(
        findings, _function(same_name=True), "sha256:" + "9" * 64)
    assert boundaries["fragment:a"].complete
    assert graph.edges == ()
    assert execution.complete


def test_ambiguous_fragment_range_is_reported_without_guessing():
    findings, function = _findings(), _function()
    function = deepcopy(function)
    candidates = function["l2OperandBoundary"]["fragmentCandidates"]
    duplicate = deepcopy(candidates[0])
    candidates.insert(1, duplicate)
    boundaries, _graph, _execution = materialize_fragment_execution_authority(
        findings, function, function["programId"])
    assert not boundaries["fragment:a"].complete
    assert "L2_FRAGMENT_BOUNDARY_RANGE_AMBIGUOUS" in \
        boundaries["fragment:a"].reason_codes


def test_v1_candidate_is_explicitly_incomplete_and_never_synthesizes_value_nodes():
    findings, function = _findings(), _function()
    function = deepcopy(function)
    function["l2OperandBoundary"]["fragmentCandidates"] = [{
        "schemaVersion": "riscv2x86.compiler-fragment-boundary-candidate.v1",
        "fragmentId": "fragment:a", "beginOffset": 10, "endOffset": 20,
        "asmOperandDeclarationIds": ["tmp", "x"], "complete": True,
    }]
    boundaries, graph, execution = materialize_fragment_execution_authority(
        findings, function, function["programId"])
    assert not boundaries["fragment:a"].complete
    assert "L2_FRAGMENT_CANDIDATE_SCHEMA_UNSUPPORTED" in \
        boundaries["fragment:a"].reason_codes
    assert boundaries["fragment:a"].output_bindings == ()
    assert not graph.complete and not execution.complete
