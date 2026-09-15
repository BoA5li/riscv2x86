from __future__ import annotations

from riscv2x86_py.automatic_l2_operand import _authority, _traces, _wrapper
from riscv2x86_py.translation_validation import TranslationArtifact
from riscv2x86_py.validation_status import PreservationMode
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from types import SimpleNamespace
import tempfile
from pathlib import Path
from tests.l2_profile_fixtures import profile_dict


def _artifact():
    return TranslationArtifact(
        "fragment", "model", "plan", "constraint", "proof",
        PreservationMode.ARCHITECTURE_EQUIVALENT, "sha256:" + "1" * 64,
        "riscv2x86.runtime.none", "v1", "recipe", (), "integer", "x86",
    )


def _function():
    return {
        "name": "add", "arity": 2, "returnType": "uint64_t",
        "parameterTypes": ["uint64_t", "uint64_t"],
        "l2OperandBoundary": {
            "schemaVersion": "riscv2x86.compiler-operand-boundary.v1", "complete": True,
            "parameterDeclarationIds": ["lhs-id", "rhs-id"],
            "asmOperandDeclarationIds": ["out-id", "lhs-id", "rhs-id"],
            "returnDeclarationId": "out-id",
            "declarationReferenceCounts": {"out-id": 2, "lhs-id": 1, "rhs-id": 1},
            "declarations": {
                "out-id": {"name": "out", "type": "uint64_t"},
                "lhs-id": {"name": "lhs", "type": "uint64_t"},
                "rhs-id": {"name": "rhs", "type": "uint64_t"},
            },
        },
    }


def test_authority_joins_compiler_boundary_and_frontend_shell():
    finding = {
        "fragment": {"id": "fragment", "enclosingFunction": "add",
                     "outputs": [{"constraint": "=&r", "symbolicName": "dst",
                                  "isEarlyClobber": True}],
                     "inputs": [{"constraint": "r", "symbolicName": "lhs"},
                                {"constraint": "r", "symbolicName": "rhs"}]},
        "approvalArtifact": {"proofStatus": "approved"},
        "l2SemanticProfile": profile_dict("fragment"),
    }
    artifact = _artifact()
    finding["approvalArtifact"].update({
        "architectureSemanticsPreserved": True,
        "shellSemanticsPreserved": True,
        "sourceModelId": "model",
        "constraintsId": "constraint",
        "preservationDecisionId": "decision",
        "planId": "plan",
        "targetEnvironmentId": "environment",
        "targetCatalogVersion": "catalog",
    })
    report = {"findings": [finding]}
    with tempfile.NamedTemporaryFile() as producer:
        assert materialize_automatic_l2_authority(
            report, [_function()], Path(producer.name),
        ) == 1
    sidecar = finding["approvalArtifact"]["l2AuthoritySidecar"]
    artifact_fields = dict(artifact.__dict__)
    artifact_fields.update(
        shell_facts_identity=sidecar["shellFactIdentity"],
        proof_identity=finding["approvalArtifact"]["proofIdentity"],
        l2_authority_identity=sidecar["authorityIdentity"],
        effect_relation_set_identity=__import__(
            "riscv2x86_py.l2_authority", fromlist=["l2_authority_sidecar_from_dict"]
        ).l2_authority_sidecar_from_dict(sidecar).effect_relation_set_identity,
        l2_authority_complete=True,
    )
    artifact = SimpleNamespace(**artifact_fields)
    authority, reason = _authority(finding, [_function()], artifact)
    assert reason == "" and authority is not None
    assert authority["operands"][0]["earlyClobber"] is True
    assert authority["operands"][0]["targetContractCarriedByProof"] is True
    assert authority["operands"][1]["declarationId"] == "lhs-id"
    assert authority["authorityIdentity"].startswith("sha256:")


def test_internal_temporary_is_inconclusive_not_silently_omitted():
    function = _function()
    function["l2OperandBoundary"]["asmOperandDeclarationIds"] = [
        "tmp-id", "out-id", "lhs-id", "rhs-id",
    ]
    function["l2OperandBoundary"]["declarations"]["tmp-id"] = {
        "name": "tmp", "type": "uint64_t",
    }
    finding = {
        "fragment": {"id": "fragment", "enclosingFunction": "add",
                     "outputs": [{"constraint": "=&r"}, {"constraint": "=r"}],
                     "inputs": [{"constraint": "r"}, {"constraint": "r"}]},
        "approvalArtifact": {"proofStatus": "approved"},
    }
    authority, reason = _authority(finding, [function], _artifact())
    assert authority is None
    assert reason == "L2_OPERAND_INTERNAL_VALUE_REQUIRES_INSTRUMENTATION"


def test_trace_parser_requires_complete_cartesian_domain():
    wrapper = _wrapper(_function())
    assert "operand_trace=add" in wrapper
    line = "operand_trace=add;0000000000000000;0000000000000001;0000000000000001\n"
    assert _traces(line, "add", 2) is None
    complete = line * 64
    assert len(_traces(complete, "add", 2)) == 64
