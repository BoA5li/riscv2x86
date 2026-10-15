from dataclasses import replace
import shutil
import subprocess

import pytest

from riscv2x86_py.l2_fence_ordering import (
    fence_execution_observations, fence_ordering_observations_match,
    validate_fence_effect_closure,
)
from riscv2x86_py.l2_effect_proof import effect_proof_facts_from_dict
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_eligibility import L2EligibilityClassifier
from riscv2x86_py.automatic_l2_effect import _fence_wrapper
from tests.test_l2_fence_ordering_relations import _finding, _facts


TRACE = "synchronize_domain=completed\nfence_trace;1122334455667788;8877665544332211\n"


def test_operand_free_harness_produces_real_execution_witness(tmp_path):
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("native C compiler unavailable")
    source, executable = tmp_path / "harness.c", tmp_path / "harness"
    source.write_text(_fence_wrapper({"name": "synchronize_domain", "arity": 0,
        "returnType": "void", "parameterTypes": []}) +
        "void synchronize_domain(void){__atomic_thread_fence(__ATOMIC_SEQ_CST);}\n")
    subprocess.run([gcc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(source), "-o", str(executable)], check=True, capture_output=True)
    result = subprocess.run([str(executable)], check=True, text=True, capture_output=True)
    assert result.stdout.splitlines() == TRACE.splitlines()[::-1]


def _proof():
    finding = _finding()
    proof = effect_proof_facts_from_dict(finding["approvalArtifact"]["l2EffectProofFacts"])
    return proof


def test_real_fence_witness_closes_approved_ordering_relation():
    facts, proof = _facts(), _proof()
    validate_fence_effect_closure(facts, proof)
    relations = tuple(item.approved_relation() for item in proof.relations)
    source = fence_execution_observations(TRACE, "synchronize_domain", facts, relations, side="source")
    target = fence_execution_observations(TRACE, "synchronize_domain", facts, relations, side="target")
    assert fence_ordering_observations_match(source, target, relations) == (True, "")
    wrong = fence_execution_observations(TRACE.replace("8877665544332211", "0000000000000000"),
        "synchronize_domain", facts, relations, side="target")
    assert not fence_ordering_observations_match(source, wrong, relations)[0]


@pytest.mark.parametrize("stdout", ["synchronize_domain=completed\n", TRACE + TRACE, "", "fence_trace;bad;bad"])
def test_completion_alone_cannot_fabricate_ordering_observations(stdout):
    with pytest.raises(ValueError, match="L2_FENCE_"):
        fence_execution_observations(stdout, "synchronize_domain", _facts(),
            tuple(item.approved_relation() for item in _proof().relations), side="source")


@pytest.mark.parametrize("field", ["memory_clobber_preserved", "volatile_placement_preserved",
                                   "continuation_preserved", "compiler_visibility_preserved"])
def test_fence_shell_obligations_are_explicit(field):
    proof = _proof()
    with pytest.raises(ValueError, match="L2_FENCE_COMPILER_SHELL"):
        validate_fence_effect_closure(_facts(), replace(proof,
            shell_relation=replace(proof.shell_relation, **{field: False})))


def test_fence_missing_edge_is_rejected_without_scalar_fallback(tmp_path):
    finding = _finding()
    raw = finding["approvalArtifact"]["l2EffectProofFacts"]
    for relation in raw["relations"]:
        relation["orderingRequirements"] = []
    # Re-address the modified proof so this tests the semantic edge obligation.
    from riscv2x86_py.l2_effect_proof import identity
    raw.pop("factsIdentity")
    raw["factsIdentity"] = identity(raw)
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    function = {"name": "synchronize_domain", "arity": 0, "returnType": "void", "parameterTypes": []}
    assert materialize_automatic_l2_authority({"findings": [finding]}, [function], frontend) == 0
    assert finding["approvalArtifact"]["l2AuthorityMaterializationReasonCode"] == "L2_FENCE_ORDERING_EDGE_UNAPPROVED"
    assert L2EligibilityClassifier().classify(finding, 0)["eligibilityStatus"] != "eligible"
