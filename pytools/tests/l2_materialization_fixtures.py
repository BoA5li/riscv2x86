from riscv2x86_py.l2_materialization import FragmentL2MaterializationDecision
from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.l2_authority import (
    L2AuthorityProducer, L2AuthoritySidecar, L2OperandAuthority,
    L2SourceEffectAuthority,
)
from tests.l2_effect_proof_fixtures import attach_effect_proof


def complete_materialization_decision(fragment_id, dimensions):
    return FragmentL2MaterializationDecision(
        fragment_id=fragment_id,
        required_dimensions=tuple(sorted(set(dimensions), key=lambda item: item.value)),
        boundary_complete=True,
        relation_complete=True,
        shell_complete=True,
        executable=True,
        reason_codes=(),
        authority_identity="sha256:" + "e" * 64,
    ).to_dict()


def attach_complete_scalar_authority(finding):
    fragment_id = finding["fragment"]["id"]
    approval = finding.setdefault("approvalArtifact", {})
    approval.update({
        "sourceModelId": "model", "preservationDecisionId": "decision",
        "planId": "plan", "constraintsId": "constraints",
        "proofStatus": "approved", "targetEnvironmentId": "environment",
        "targetCatalogVersion": "catalog",
    })
    attach_effect_proof(approval, fragment_id)
    operands = (
        L2OperandAuthority("operand:0", 0, "out", "output", "integer", 64,
                           "unsigned", "", False, "", "function_return"),
        L2OperandAuthority("operand:1", 1, "lhs", "input", "integer", 64,
                           "unsigned", "", False, "", "function_argument"),
    )
    source = L2SourceEffectAuthority(
        "scalar:continuation", "ScalarResult", "subject", True)
    relation = ApprovedEffectRelation(
        "relation:scalar:continuation", source.effect_id,
        ("target:scalar:continuation",), "exact",
        ("branch_continuation", "kind", "value"), (), "", True)
    sidecar = L2AuthoritySidecar(
        fragment_id,
        L2AuthorityProducer("translation-proof-sidecar", "test", "v1",
                            "sha256:" + "a" * 64),
        "sha256:" + "b" * 64, operands, (), (source,), (relation,), (), (), True)
    approval["l2AuthoritySidecar"] = sidecar.to_dict()
    return finding
