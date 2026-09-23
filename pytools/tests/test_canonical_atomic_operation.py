from types import SimpleNamespace

import pytest

from riscv2x86_py.atomic_metadata_ingress import decode_atomic_operation
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.pcode_ir import CanonicalAtomicOperation, from_lifted
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel, TargetSemanticCatalog, run_semantic_proof_gate,
)
from riscv2x86_py.runtime_facts import (
    AtomicMemoryObjectRuntimeFact,
    TranslationRuntimeFacts,
)
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.source_model import (
    SourceAtomicRmwOperation,
    SourceMemoryOrdering,
    build_source_semantic_model,
)


def _amo_word(*, funct5=0, width=64, aq=False, rl=False, rd=10, rs1=11, rs2=10):
    funct3 = 0b011 if width == 64 else 0b010
    return (funct5 << 27) | (int(aq) << 26) | (int(rl) << 25) | \
        (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x2f


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("aq,rl,before,after", [
    (False, False, "relaxed", "relaxed"),
    (True, False, "relaxed", "acquire"),
    (False, True, "release", "relaxed"),
    (True, True, "release", "acquire"),
])
def test_decoder_emits_typed_width_and_ordering(width, aq, rl, before, after):
    decoded = decode_atomic_operation(
        _amo_word(width=width, aq=aq, rl=rl).to_bytes(4, "little"),
        xlen_bits=64,
    )
    assert decoded is not None
    assert decoded.operation_kind == "fetch_add"
    assert decoded.width_bits == width
    assert (decoded.ordering_before, decoded.ordering_after) == (before, after)
    assert decoded.result_semantics == "old_value"


def test_discarded_result_is_explicit():
    decoded = decode_atomic_operation(
        _amo_word(rd=0).to_bytes(4, "little"), xlen_bits=64,
    )
    assert decoded is not None
    assert decoded.result_register is None
    assert decoded.result_semantics == "none"


def test_non_atomic_pcode_shape_cannot_claim_atomicity():
    class Insn:
        addr = 0
        size = 4
        asm_mnem = "add"
        asm_body = ""
        atomic_operation = None
        raw_ops = [SimpleNamespace(opcode=name, inputs=[], output=None)
                   for name in ("LOAD", "INT_ADD", "STORE")]

    _, summary = from_lifted([Insn()])
    assert not summary.has_atomic
    assert summary.atomic_semantics is None
    assert summary.has_return is None


def _atomic_model(*, alignment=8, target_feature=True):
    address = SimpleNamespace(space="register", offset=11, size=8, name="a1")
    value = SimpleNamespace(space="register", offset=10, size=8, name="a0")
    class Insn:
        addr = 0
        size = 4
        asm_mnem = "diagnostic-only"
        asm_body = ""
        atomic_operation = decode_atomic_operation(
            _amo_word(aq=True, rl=True).to_bytes(4, "little"), xlen_bits=64,
        )
        raw_ops = [
            SimpleNamespace(opcode="LOAD", inputs=[SimpleNamespace(space="const", offset=0, size=8, name=""), address], output=value),
            SimpleNamespace(opcode="INT_ADD", inputs=[value, value], output=value),
            SimpleNamespace(opcode="STORE", inputs=[SimpleNamespace(space="const", offset=0, size=8, name=""), address, value], output=None),
        ]
    blocks, summary = from_lifted([Insn()])
    fragment = AsmFragment(
        rawAsmText="opaque diagnostic text", isVolatile=True, clobbers=["memory", "cc"],
        outputs=[AsmOperand(constraint="+r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="ptr", isOutput=False)],
    )
    facts = TranslationRuntimeFacts(
        rv_to_operand_index={"a0": 0, "a1": 1},
        operand_width_bits={0: 64, 1: 64},
        atomic_memory_objects={1: AtomicMemoryObjectRuntimeFact(
            "parameter-object:ptr", "riscv.default-data-address-space", alignment,
            "uint64_t",
        )},
    )
    return build_source_semantic_model(
        fragment=fragment, blocks=blocks, cfg=CFGResult(ok=True), summary=summary,
        xlen=64, runtime_facts=facts,
    )


def test_phase6a_closes_opaque_only_with_complete_atomic_authority():
    model = _atomic_model()
    assert model.atomic.complete
    assert model.atomic.rmw_operation is SourceAtomicRmwOperation.FETCH_ADD
    assert model.atomic.success_ordering is SourceMemoryOrdering.ACQ_REL
    assert model.atomic.result_semantics == "old_value"
    assert model.atomic.memory_object_identity == "parameter-object:ptr"
    assert model.operation.complete


def test_unproven_alignment_retains_global_fail_closed():
    model = _atomic_model(alignment=4)
    assert not model.atomic.complete
    assert model.operation.kind.value == "opaque"
    assert model.phase6b_candidate_facts.has_global_fail_closed_state


def test_canonical_atomic_rejects_missing_result_binding():
    with pytest.raises(ValueError):
        CanonicalAtomicOperation(
            "fetch_add", 64, "a1", "a0", None, "old_value",
            "relaxed", "relaxed", "system",
            "riscv.default-data-address-space", True,
        )


def test_matching_rmw_builtin_preserves_acq_rel_contract():
    model = _atomic_model()
    plan = next(item for item in generate_candidate_plans(model)
                if item.plan_id == "c-builtin.atomic-fetch-add")
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att(
        available_features={"compiler:atomic-builtin"},
        builtin_capabilities={"c_builtin:atomic"},
    )
    derived = derive_target_constraints(
        source_model=model, candidate_plan=plan, target_environment=environment,
    )
    assert derived.success and derived.constraints is not None
    contract = derived.constraints.c_builtin_constraint
    assert contract.builtin_identifier == "__atomic_fetch_add"
    assert contract.success_ordering == "acq_rel"
    assert contract.memory_object_identity == "parameter-object:ptr"
    semantic_id = plan.metadata["renderer_semantic_contract_id"]
    proof = run_semantic_proof_gate(
        source_model=model, preservation_decision=model.preservation,
        candidate_plan=plan, constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(
            frozenset({plan.kind}), frozenset({semantic_id}), "atomic-test-v1",
        ),
        compiler_capabilities=CompilerCapabilityModel(
            False, False, frozenset({"c_builtin:atomic"}),
        ),
    )
    assert proof.approved


def test_missing_atomic_builtin_capability_is_rejected():
    model = _atomic_model()
    plan = next(item for item in generate_candidate_plans(model)
                if item.plan_id == "c-builtin.atomic-fetch-add")
    derived = derive_target_constraints(
        source_model=model, candidate_plan=plan,
        target_environment=TargetEnvironment.fixed_sysv_amd64_gnu_att(),
    )
    assert not derived.success
    assert any("capability_unavailable" in item.value
               for item in derived.reason_codes)
