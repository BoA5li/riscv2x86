from copy import deepcopy
from pathlib import Path

import pytest

from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_fragment_execution import (
    fragment_boundary_from_dict, materialize_fragment_execution_authority,
    program_execution_authority_from_dict,
)
from tests.l2_profile_fixtures import profile_dict


def _function(*, cycle=False, same_name=False):
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
    return {
        "name": "sequence", "functionId": "function:sequence",
        "programId": "sha256:" + "9" * 64, "arity": 1,
        "returnType": "uint64_t", "parameterTypes": ["uint64_t"],
        "l2OperandBoundary": {
            "schemaVersion": "riscv2x86.compiler-operand-boundary.v2",
            "complete": False, "parameterDeclarationIds": ["x"],
            "asmOperandDeclarationIds": [], "returnDeclarationId": "out",
            "declarations": declarations,
            "declarationReferenceCounts": {key: 1 for key in declarations},
            "asmStatementEndOffset": -1,
            "fragmentCandidates": [
                {"fragmentId": "fragment:a", "beginOffset": 10, "endOffset": 20,
                 "asmOperandDeclarationIds": first_ids, "complete": True},
                {"fragmentId": "fragment:b", "beginOffset": 30, "endOffset": 40,
                 "asmOperandDeclarationIds": second_ids, "complete": True},
            ],
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
    return [_finding("fragment:a", "tmp", "x"),
            _finding("fragment:b", "out", "tmp")]


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
    assert graph["edges"] == [{"producerFragmentId": "fragment:a",
                                "consumerFragmentId": "fragment:b",
                                "valueNodeIdentity": "decl-value:tmp"}]


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
    function["l2OperandBoundary"]["fragmentCandidates"][1][
        "asmOperandDeclarationIds"] = ["out", "x"]
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
    assert not boundaries["fragment:a"].complete
    assert graph.edges == ()
    assert not execution.complete


def test_ambiguous_fragment_range_is_reported_without_guessing():
    findings, function = _findings(), _function()
    function = deepcopy(function)
    candidates = function["l2OperandBoundary"]["fragmentCandidates"]
    candidates[0].pop("fragmentId")
    duplicate = deepcopy(candidates[0])
    candidates.insert(1, duplicate)
    boundaries, _graph, _execution = materialize_fragment_execution_authority(
        findings, function, function["programId"])
    assert not boundaries["fragment:a"].complete
    assert "L2_FRAGMENT_BOUNDARY_RANGE_AMBIGUOUS" in \
        boundaries["fragment:a"].reason_codes
