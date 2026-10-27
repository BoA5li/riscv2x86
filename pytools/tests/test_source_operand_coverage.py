from types import SimpleNamespace

import pytest

from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import IRSummary
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts, AtomicMemoryObjectRuntimeFact
from riscv2x86_py.runtime_fact_model import RuntimeFactStatus
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.shell_model import SourceShellModel
from riscv2x86_py.source_model import _build_operand_model, build_source_semantic_model
from riscv2x86_py.source_operand_coverage import snapshot, decision
from riscv2x86_py.route_authority import validate_route_decision
from riscv2x86_py.l2_semantic_profile import profile_from_source_model


def fragment(memory=True):
    return AsmFragment(id="typed:operand-coverage", outputs=[
        AsmOperand(constraint="=&r", exprText=n, isOutput=True, isEarlyClobber=True)
        for n in ("old", "next", "status")
    ] + ([AsmOperand(constraint="+A", exprText="*address", isOutput=True)] if memory else []),
        inputs=[AsmOperand(constraint="r", exprText=n) for n in ("address", "value")],
        isVolatile=True, clobbers=["memory"])


def objects(complete=True):
    fact = AtomicMemoryObjectRuntimeFact("object:argument", "space:data", 8,
        "uint64_t", "authority:fixture" if complete else None, "fetch_add", "add_mod_2n", 64,
        ("before:relaxed", "after:relaxed"), "read:fixture", "write:fixture", "space:fixture",
        operand_role="memory_lvalue")
    return {3: fact}


def build(frag, bindings, widths=None, atomic=None):
    facts = TranslationRuntimeFacts(rv_to_operand_index=bindings,
        operand_width_bits=widths if widths is not None else {i: 64 for i in range(len(frag.outputs + frag.inputs))},
        atomic_memory_objects=atomic or {})
    shell = SourceShellModel.from_fragment(frag)
    return shell, _build_operand_model(shell=shell, blocks=(), runtime_facts=facts,
        runtime_status=RuntimeFactStatus.from_runtime_facts(facts))


def test_unbound_memory_slot_cannot_be_a_complete_subset():
    shell, operands = build(fragment(), {"a0": 0, "a1": 1, "a2": 2, "a4": 4, "a5": 5})
    assert len(operands.operands) == 5
    assert not operands.complete
    assert "missing_authoritative_operand_index_binding:3" in operands.missing_fact_codes
    model = SimpleNamespace(shell=shell, operands=operands)
    value = snapshot("fragment:test", model)
    assert value["declaredOperandCount"] == 6
    assert value["modeledOperandCount"] == 5
    assert value["unmodeledIndexes"] == [3]
    assert value["slots"][3]["declaredReadWrite"] and not value["slots"][3]["modeled"]
    record = decision("fragment:test", model)
    validate_route_decision(record)
    assert record["accepted"] is False and record["inputsPayload"]["semanticApproval"] is False


@pytest.mark.parametrize("missing", range(6))
def test_every_declared_slot_requires_a_binding(missing):
    frag = fragment()
    # Register-only slots for this coverage test; no memory authority fabricated.
    frag.outputs[3].constraint = "+r"
    _, operands = build(frag, {"a" + str(i): i for i in range(6) if i != missing})
    assert not operands.complete
    assert f"missing_authoritative_operand_index_binding:{missing}" in operands.missing_fact_codes


@pytest.mark.parametrize("constraint", ["+A", "+m", "=A", "=m"])
@pytest.mark.parametrize("partial_object", [False, True])
def test_register_mapping_cannot_authorize_memory_lvalue(constraint, partial_object):
    frag = fragment();frag.outputs[3].constraint = constraint
    _, operands = build(frag, {"a" + str(i): i for i in range(6)},
                        atomic=objects(False) if partial_object else None)
    assert not operands.complete
    assert "missing_operand_semantics:3" in operands.missing_fact_codes
    assert 3 not in {o.source_operand_index for o in operands.operands}


def test_complete_memory_authority_preserves_read_write_role():
    shell, operands = build(fragment(), {"a0": 0, "a1": 1, "a2": 2, "a4": 4, "a5": 5}, atomic=objects())
    assert operands.complete and len(operands.operands) == 6
    memory = next(o for o in operands.operands if o.source_operand_index == 3)
    assert memory.kind.value == "memory" and memory.access.value == "read_write"
    assert memory.address.memory_object_identity == "object:argument"
    assert memory.address.atomic_authority_identity == "authority:fixture"
    assert decision("fragment:test", SimpleNamespace(shell=shell, operands=operands)) is None


def test_extra_and_missing_indexes_are_both_reported():
    _, operands = build(fragment(), {"a0": 0, "a1": 1, "a2": 2, "a4": 4, "a5": 5, "a6": 99})
    assert not operands.complete
    assert "missing_authoritative_operand_index_binding:3" in operands.missing_fact_codes
    assert "unexpected_authoritative_operand_index_binding:99" in operands.missing_fact_codes
    assert all(o.source_operand_index != 99 for o in operands.operands)


def test_empty_shell_with_extraneous_binding_is_not_complete():
    _, operands = build(AsmFragment(), {"a0": 0}, {0: 64})
    assert not operands.complete
    assert "unexpected_authoritative_operand_index_binding:0" in operands.missing_fact_codes
    _, empty = build(AsmFragment(), {}, {})
    assert empty.complete


def test_known_slots_with_missing_width_still_fail_closed():
    _, operands = build(fragment(memory=False), {"a" + str(i): i for i in range(5)}, {i: 64 for i in range(4)})
    assert not operands.complete and "missing_operand_width:4" in operands.missing_fact_codes


def test_full_source_model_and_profile_propagate_missing_slot():
    frag = fragment()
    summary = IRSummary(is_single_block=False, has_branch=True, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=True, reads_regs=set(), writes_regs=set(),
        reads_mem=True, writes_mem=True)
    model = build_source_semantic_model(fragment=frag, blocks=(), cfg=CFGResult(ok=True),
        summary=summary, xlen=64, runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2, "a4": 4, "a5": 5},
            operand_width_bits={i: 64 for i in range(6)}))
    assert not model.operands.complete
    profile = profile_from_source_model(frag.id, model)
    assert not profile.operand_shape.complete
    facts = model.phase6b_candidate_facts
    assert not facts.operand_bindings_are_authoritative
    assert not facts.operand_widths_are_authoritative
    assert facts.has_global_fail_closed_state
    # The ordinary translation result preserves the exact missing-slot
    # diagnostic, rather than only a generic Phase6 fail-closed reason.
    from riscv2x86_py.translate import _output
    context = SimpleNamespace(sourceModel=model, fragment=frag, xlen=64,
        decision=model.preservation, instruction_count=0, blocks=[])
    output = _output(kind="unsupported", replacement="", context=context, route="unsupported")
    assert "SOURCE_OPERAND_COVERAGE_INCOMPLETE" in output.reasonCodes
    diagnostics = output.metadata["routeAuthorityDiagnostics"]
    record = next(d for d in diagnostics if d["failureStage"] == "source_operand_coverage")
    assert record["inputsPayload"]["unmodeledIndexes"] == [3]
    assert output.metadata["l2SemanticProfile"]["operandShape"]["complete"] is False


def test_missing_bindings_do_not_claim_authority():
    _, operands = build(fragment(), {})
    assert not operands.complete
    assert "missing_authoritative_operand_index_binding" in operands.missing_fact_codes
    assert all(f"missing_authoritative_operand_index_binding:{i}" in operands.missing_fact_codes for i in range(6))


def test_existing_complete_direct_atomic_model_is_unchanged():
    from tests.test_canonical_atomic_operation import _atomic_model
    model = _atomic_model()
    assert model.operands.complete and model.atomic.complete
    assert snapshot("fixture:atomic", model)["complete"]
    assert decision("fixture:atomic", model) is None
