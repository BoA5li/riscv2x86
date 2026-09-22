from pathlib import Path

from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
from riscv2x86_py.l2_eligibility import L2EligibilityClassifier
from riscv2x86_py.l2_semantic_profile import L2PatternKind
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


def test_functional_counter_authority_is_typed_and_runtime_mediated(tmp_path: Path):
    finding = {
        "fragment": {"id": "fragment", "enclosingFunction": "read_clock",
                     "outputs": [], "inputs": []},
        "translationOutcome": "functional_fallback",
        "approvalArtifact": {
            "proofStatus": "functional_approved",
            "functionalFallbackEnabled": True,
            "preservationMode": "functional_equivalence_only",
            "architectureSemanticsPreserved": False,
            "sourceSemanticContractId": "riscv.time.observation.v1",
            "targetSemanticContractId": "x86.monotonic-time.observation.v1",
            "runtimeContractId": "riscv2x86_rt_monotonic_time_ns@v1",
            "runtimeContractVersion": "v1",
            "targetEnvironmentId": "environment",
            "targetCatalogVersion": "catalog",
            "sourceModelId": "model", "constraintsId": "constraints",
            "preservationDecisionId": "decision", "planId": "plan",
            "ignoredSourceState": ["csr:time:absolute-value", "csr:time:epoch"],
            "knownNonEquivalences": ["absolute values are not comparable"],
        },
        "l2SemanticProfile": profile_dict(
            "fragment", L2PatternKind.PRIVILEGED_READ),
    }
    frontend = tmp_path / "frontend"
    frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": [finding]}, [], frontend) == 1
    sidecar = l2_authority_sidecar_from_dict(
        finding["approvalArtifact"]["l2AuthoritySidecar"])
    assert sidecar.complete
    assert len(sidecar.runtime_contracts) == 1
    assert {item.relation_kind for item in sidecar.approved_effect_relations} == {
        "runtime_mediated"
    }
    assert all(item.escape_kind == "non_escaping" for item in sidecar.ignored_state)


def _memory_finding(fragment_id="memory-fragment"):
    return {
        "fragment": {
            "id": fragment_id, "enclosingFunction": "store",
            "outputs": [],
            "inputs": [
                {"constraint": "r", "symbolicName": "address"},
                {"constraint": "r", "symbolicName": "value"},
            ],
        },
        "translationOutcome": "emitted",
        "approvalArtifact": {
            "proofStatus": "approved", "architectureSemanticsPreserved": True,
            "shellSemanticsPreserved": True, "sourceModelId": "model",
            "constraintsId": "constraints", "preservationDecisionId": "decision",
            "planId": "plan", "targetEnvironmentId": "environment",
            "targetCatalogVersion": "catalog",
        },
        "l2SemanticProfile": profile_dict(
            fragment_id, L2PatternKind.MEMORY_STORE),
    }


def _memory_function():
    return {
        "name": "store", "arity": 2, "returnType": "void",
        "parameterTypes": ["uint64_t *", "uint64_t"],
        "l2OperandBoundary": {
            "complete": True,
            "parameterDeclarationIds": ["address", "value"],
            "asmOperandDeclarationIds": ["address", "value"],
            "returnDeclarationId": "",
            "declarationReferenceCounts": {"address": 1, "value": 1},
            "declarations": {
                "address": {"name": "address", "type": "uint64_t *"},
                "value": {"name": "value", "type": "uint64_t"},
            },
            "memoryObjectBindings": {"address": {
                "objectIdentity": "parameter-object:address",
                "objectSizeBytes": 32, "provenAlignmentBytes": 8,
                "aliasDomainIdentity": "parameter-alias-domain:address",
                "addressSpaceIdentity": "c.default", "volatile": False,
                "bindingOrigin": "automatic-aligned-memory-object-harness-v1",
            }},
        },
    }


def _memory_facts(fragment_id="memory-fragment", *, complete=True):
    from riscv2x86_py.l2_memory_object import L2MemoryProofFacts
    flags = dict(unique_object=complete, bounds_proven=complete,
                 alignment_proven=complete, alias_complete=complete,
                 non_atomic=complete)
    return L2MemoryProofFacts(
        fragment_id, "store", 0, 1, 8, 8, 8,
        "function_argument", "function_call", "object:0",
        memory_order="relaxed", complete=complete, **flags,
    ).to_dict()


def test_memory_materializer_records_content_bound_eligibility_authority(tmp_path: Path):
    finding = _memory_finding()
    finding["approvalArtifact"]["l2MemoryProofFacts"] = _memory_facts()
    frontend = tmp_path / "frontend"
    frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": [finding]}, [_memory_function()], frontend) == 1
    record = finding["approvalArtifact"]["l2AuthorityMaterialization"]
    sidecar = l2_authority_sidecar_from_dict(
        finding["approvalArtifact"]["l2AuthoritySidecar"])
    assert record["status"] == "materialized"
    assert record["reasonCode"] == "L2_MEMORY_AUTHORITY_MATERIALIZED"
    assert record["authorityIdentity"] == sidecar.authority_identity
    assert record["materializationIdentity"].startswith("sha256:")
    requirement = L2EligibilityClassifier().classify(finding, 0)
    assert requirement["eligibilityStatus"] == "eligible"
    assert requirement["disposition"] == "not_run"


def test_memory_materializer_records_precise_fail_closed_reason(tmp_path: Path):
    finding = _memory_finding()
    finding["approvalArtifact"]["l2MemoryProofFacts"] = _memory_facts(complete=False)
    frontend = tmp_path / "frontend"
    frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings": [finding]}, [_memory_function()], frontend) == 0
    record = finding["approvalArtifact"]["l2AuthorityMaterialization"]
    assert record["status"] == "rejected"
    assert record["reasonCode"] == "L2_MEMORY_ALIGNMENT_UNPROVED"
    assert "l2AuthoritySidecar" not in finding["approvalArtifact"]
