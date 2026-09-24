from riscv2x86_py.l2_effect_proof import (
    EffectRelationFact, L2EffectProofFacts, ShellRelationFact,
    SourceEffectFact, TargetEffectFact, identity,
)


def attach_effect_proof(approval, fragment_id, kind="scalar"):
    proof = identity({key: approval.get(key, "") for key in (
        "sourceModelId", "preservationDecisionId", "planId", "constraintsId",
        "proofStatus", "targetEnvironmentId", "targetCatalogVersion")})
    renderer = identity({"testRenderer": "semantic-v1"})
    specs = {
        "fence": (("before:read", "ReadMemory", ("kind", "subject", "value")),
                  ("fence:0", "Fence", ("compiler_ordering", "hardware_ordering", "kind", "subject")),
                  ("after:write", "WriteMemory", ("kind", "subject", "value"))),
        "memory": (("memory:access", "ReadMemory",
                    ("kind", "memory_coordinates", "memory_order", "subject", "value")),),
        "control": (("control:continuation", "ControlTransfer",
                     ("branch_condition", "branch_continuation", "branch_outcome",
                      "kind", "target", "value")),),
        "scalar": (("scalar:continuation", "ScalarResult",
                    ("branch_continuation", "kind", "value")),),
    }[kind]
    sources = tuple(SourceEffectFact(a, b, "subject", True) for a, b, _ in specs)
    targets = tuple(TargetEffectFact("target:" + a, b, "subject", True) for a, b, _ in specs)
    relations = tuple(EffectRelationFact(
        "relation:" + a, a, ("target:" + a,),
        "strengthened" if kind == "fence" and a == "fence:0" else "exact",
        tuple(sorted(properties)), (), "", "", True,
        (("before:read", "after:write"),) if a == "fence:0" else ())
        for a, _b, properties in specs)
    shell = ShellRelationFact((), (), (), (), True, True, True, True, True, True)
    facts = L2EffectProofFacts(fragment_id, proof, str(approval["planId"]),
                               str(approval["constraintsId"]), renderer,
                               sources, targets, relations, shell, True)
    approval["proofIdentity"] = proof
    approval["rendererContractIdentity"] = renderer
    approval["l2EffectProofFacts"] = facts.to_dict()
