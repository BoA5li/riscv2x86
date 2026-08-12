"""Regression coverage for the finite two-output early-clobber sequence."""
from pathlib import Path
import shutil
import subprocess
import tempfile

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import Block, IRSummary, Op, Var, VarKind
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import CompilerCapabilityModel, TargetSemanticCatalog, run_semantic_proof_gate
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan, SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import Phase6FRenderRequest, RendererContext, render_approved_target_lowering
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.source_model import build_source_semantic_model

_ID = "x86.gnu-att.gpr.straight-line-u32-u64.v1"


def test_add_then_shift_two_output_early_clobber_contract() -> None:
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=&r", exprText="tmp", isOutput=True, isEarlyClobber=True),
                 AsmOperand(constraint="=r", exprText="res", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="a"), AsmOperand(constraint="r", exprText="b")],
        isVolatile=True,
    )
    add = Op(0x1000, "INT_ADD", Var(VarKind.REG, "register", 10, 8, "a0"),
             [Var(VarKind.REG, "register", 11, 8, "a1"), Var(VarKind.REG, "register", 12, 8, "a2")])
    shift = Op(0x1004, "INT_LEFT", Var(VarKind.REG, "register", 13, 8, "a3"),
               [Var(VarKind.REG, "register", 10, 8, "a0"), Var(VarKind.CONST, "const", 3, 8)])
    summary = IRSummary(
        is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a1", "a2"},
        writes_regs={"a0", "a3"}, reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False,
    )
    model = build_source_semantic_model(
        fragment=fragment, blocks=(Block(0x1000, [add, shift], summary),), cfg=CFGResult(ok=True),
        summary=summary, xlen=64,
        runtime_facts=TranslationRuntimeFacts({"a0": 0, "a3": 1, "a1": 2, "a2": 3},
                                               {0: 64, 1: 64, 2: 64, 3: 64}, "test"),
    )
    assert model.value_operation is not None
    assert model.value_operation.kind.value == "add_then_shift_left_immediate"
    assert model.value_program is not None
    assert len(model.value_program.instructions) == 2
    plan = next(item for item in generate_candidate_plans(model)
                if item.metadata.get("renderer_semantic_contract_id") == _ID)
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
    assert derived.success and derived.constraints is not None
    proof = run_semantic_proof_gate(
        source_model=model, preservation_decision=model.preservation, candidate_plan=plan,
        constraints=derived.constraints, target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({_ID}), "test-v1"),
        compiler_capabilities=CompilerCapabilityModel(True, False),
    )
    assert proof.approved and proof.evidence is not None
    approved = ApprovedTargetLoweringPlan(plan, derived.constraints, proof, proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
        "phase6e.semantic-fidelity", "1", SelectionTier.X86_INLINE_ASM)
    contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    assert contract is not None
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved, environment, RendererContext({plan.plan_id: contract}, {0: "tmp", 1: "res", 2: "a", 3: "b"}),
    ))
    assert rendered.emitted_text is not None
    assert '"=&r"(tmp), "=r"(res)' in rendered.emitted_text
    assert '"cc"' in rendered.emitted_text
    compiler = shutil.which("cc")
    if compiler:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sequence.c"
            source.write_text("#include <stdint.h>\nuint64_t f(uint64_t a,uint64_t b){uint64_t tmp,res;" + rendered.emitted_text + "return res;}\n")
            completed = subprocess.run([compiler, "-c", "-std=gnu11", str(source)], capture_output=True, text=True)
            assert completed.returncode == 0, completed.stderr


def test_straight_line_program_supports_other_operation_combinations() -> None:
    """The contract is a dataflow family, not an add/shift template match."""
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="t0", isOutput=True),
                 AsmOperand(constraint="=r", exprText="t1", isOutput=True),
                 AsmOperand(constraint="=r", exprText="res", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="a"), AsmOperand(constraint="r", exprText="b"),
                AsmOperand(constraint="r", exprText="c")], isVolatile=True,
    )
    register = lambda index, name: Var(VarKind.REG, "register", index, 8, name)
    ops = [
        Op(0x1000, "INT_ADD", register(10, "a0"), [register(13, "a3"), register(14, "a4")]),
        Op(0x1004, "INT_XOR", register(11, "a1"), [register(10, "a0"), register(15, "a5")]),
        Op(0x1008, "INT_RIGHT", register(12, "a2"), [register(11, "a1"), Var(VarKind.CONST, "const", 1, 8)]),
    ]
    summary = IRSummary(is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a3", "a4", "a5"},
        writes_regs={"a0", "a1", "a2"}, reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False, has_speculation_control=False)
    model = build_source_semantic_model(
        fragment=fragment, blocks=(Block(0x1000, ops, summary),), cfg=CFGResult(ok=True), summary=summary,
        xlen=64, runtime_facts=TranslationRuntimeFacts(
            {"a0": 0, "a1": 1, "a2": 2, "a3": 3, "a4": 4, "a5": 5},
            {index: 64 for index in range(6)}, "test"),
    )
    assert model.value_program is not None and len(model.value_program.instructions) == 3
    plan = next(item for item in generate_candidate_plans(model)
                if item.metadata.get("renderer_semantic_contract_id") == _ID)
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
    assert derived.success and derived.constraints is not None
    proof = run_semantic_proof_gate(source_model=model, preservation_decision=model.preservation,
        candidate_plan=plan, constraints=derived.constraints, target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({_ID}), "test-v1"),
        compiler_capabilities=CompilerCapabilityModel(True, False))
    assert proof.approved and proof.evidence is not None
    approved = ApprovedTargetLoweringPlan(plan, derived.constraints, proof, proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
        "phase6e.semantic-fidelity", "1", SelectionTier.X86_INLINE_ASM)
    contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    assert contract is not None
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved, environment, RendererContext({plan.plan_id: contract},
        {0: "t0", 1: "t1", 2: "res", 3: "a", 4: "b", 5: "c"})))
    assert rendered.emitted_text is not None
    assert "xorq" in rendered.emitted_text and "shrq $1" in rendered.emitted_text
