from pathlib import Path

from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
from tests.l2_profile_fixtures import profile_dict


def _ref(identity):
    return {"kind": "DeclRefExpr", "referencedDecl": {"id": identity}}


def test_compiler_reference_counts_do_not_count_expression_wrappers_twice():
    function = {
        "kind": "FunctionDecl",
        "inner": [
            {"kind": "ParmVarDecl", "id": "lhs", "name": "lhs",
             "type": {"qualType": "uint64_t"}},
            {"kind": "VarDecl", "id": "out", "name": "out",
             "type": {"qualType": "uint64_t"}},
            {"kind": "GCCAsmStmt", "inner": [_ref("out"), {
                "kind": "ImplicitCastExpr", "inner": [_ref("lhs")],
            }]},
            {"kind": "ReturnStmt", "inner": [{
                "kind": "ImplicitCastExpr", "inner": [_ref("out")],
            }]},
        ],
    }
    facts = _l2_operand_boundary_facts(function)
    assert facts["declarationReferenceCounts"] == {"out": 2, "lhs": 1}


def test_scalar_authority_is_bound_before_candidate_staging(tmp_path: Path):
    function = {
        "name": "add", "arity": 2, "returnType": "uint64_t",
        "parameterTypes": ["uint64_t", "uint64_t"],
        "l2OperandBoundary": {
            "complete": True,
            "parameterDeclarationIds": ["lhs", "rhs"],
            "asmOperandDeclarationIds": ["out", "lhs", "rhs"],
            "returnDeclarationId": "out",
            "declarationReferenceCounts": {"out": 2, "lhs": 1, "rhs": 1},
            "declarations": {
                "out": {"name": "out", "type": "uint64_t"},
                "lhs": {"name": "lhs", "type": "uint64_t"},
                "rhs": {"name": "rhs", "type": "uint64_t"},
            },
        },
    }
    finding = {
        "fragment": {
            "id": "fragment", "enclosingFunction": "add",
            "outputs": [{"constraint": "=r", "symbolicName": "dst"}],
            "inputs": [{"constraint": "r", "symbolicName": "lhs"},
                       {"constraint": "r", "symbolicName": "rhs"}],
        },
        "approvalArtifact": {
            "proofStatus": "approved", "architectureSemanticsPreserved": True,
            "shellSemanticsPreserved": True, "sourceModelId": "model",
            "constraintsId": "constraints", "preservationDecisionId": "decision",
            "planId": "plan", "targetEnvironmentId": "environment",
            "targetCatalogVersion": "catalog",
        },
        "l2SemanticProfile": profile_dict("fragment"),
    }
    frontend = tmp_path / "frontend"
    frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": [finding]}, [function], frontend,
    ) == 1
    sidecar = l2_authority_sidecar_from_dict(
        finding["approvalArtifact"]["l2AuthoritySidecar"]
    )
    assert sidecar.complete
    assert sidecar.operands[0].escape_kind == "function_return"
    assert len(sidecar.approved_effect_relations) == 64
