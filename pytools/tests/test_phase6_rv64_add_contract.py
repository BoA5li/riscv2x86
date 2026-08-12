"""Regression test for the proof-gated RV64 register-only add path."""

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import Block, IRSummary, Op, Var, VarKind
from riscv2x86_py.phase6c_constraints import (
    TargetEnvironment,
    derive_target_constraints,
)
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel,
    TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from riscv2x86_py.phase6e_selection import (
    ApprovedTargetLoweringPlan,
    SelectionTier,
)
from riscv2x86_py.phase6f_contract_registry import (
    GPR_INTEGER_RENDERER_CONTRACT_REGISTRY,
)
from riscv2x86_py.phase6f_renderer import (
    Phase6FRenderRequest,
    RendererContext,
    RenderedReplacementKind,
    render_approved_target_lowering,
)
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.source_model import build_source_semantic_model


_CONTRACT_ID = "x86.gnu-att.gpr.out-gpr-gpr-binary.v1"


def _build_rv64_add_model():
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="lhs"),
            AsmOperand(constraint="r", exprText="rhs"),
        ],
        isVolatile=True,
    )
    operation = Op(
        addr=0x1000,
        opcode="INT_ADD",
        output=Var(VarKind.REG, "register", 10, 8, "a0"),
        inputs=[
            Var(VarKind.REG, "register", 11, 8, "a1"),
            Var(VarKind.REG, "register", 12, 8, "a2"),
        ],
    )
    summary = IRSummary(
        is_single_block=True,
        has_branch=False,
        has_call_or_return=False,
        has_memory_barrier=False,
        has_atomic=False,
        reads_regs={"a1", "a2"},
        writes_regs={"a0"},
        reads_mem=False,
        writes_mem=False,
        has_return=False,
        has_tail_call=False,
        has_indirect_control_flow=False,
        has_timing_source=False,
        has_cache_operation=False,
        has_speculation_control=False,
    )
    return build_source_semantic_model(
        fragment=fragment,
        blocks=(Block(addr=0x1000, ops=[operation], summary=summary),),
        cfg=CFGResult(ok=True),
        summary=summary,
        xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
            operand_width_bits={0: 64, 1: 64, 2: 64},
            provenance="phase4-test",
        ),
    )


def test_rv64_add_has_proven_att_renderer_contract() -> None:
    model = _build_rv64_add_model()
    plan = next(
        candidate
        for candidate in generate_candidate_plans(model)
        if candidate.metadata.get("renderer_semantic_contract_id") == _CONTRACT_ID
    )
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived = derive_target_constraints(
        source_model=model,
        candidate_plan=plan,
        target_environment=environment,
    )
    assert derived.success
    assert derived.constraints is not None
    assert derived.constraints.preserve_volatile is True
    assert derived.constraints.preserve_cc_clobber is True

    proof = run_semantic_proof_gate(
        source_model=model,
        preservation_decision=model.preservation,
        candidate_plan=plan,
        constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(
            supported_plan_kinds=frozenset({plan.kind}),
            semantic_contract_ids=frozenset({_CONTRACT_ID}),
            version="rv64-add-test-v1",
        ),
        compiler_capabilities=CompilerCapabilityModel(
            supports_gnu_inline_asm=True,
            supports_asm_goto=False,
        ),
    )
    assert proof.approved
    assert proof.evidence is not None

    approved = ApprovedTargetLoweringPlan(
        plan=plan,
        constraints=derived.constraints,
        proof=proof,
        source_model_id=proof.evidence.source_model_id,
        preservation_decision_id=proof.evidence.preservation_decision_id,
        target_environment_id=proof.evidence.target_environment_id,
        selection_policy_id="phase6e.semantic-fidelity",
        selection_policy_version="1",
        selection_tier=SelectionTier.X86_INLINE_ASM,
    )
    renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    assert renderer_contract is not None
    assert renderer_contract.payload.template == "movq %1, %0\\n\\taddq %2, %0"
    assert renderer_contract.payload.output_operand_indexes == (0,)
    assert renderer_contract.payload.input_operand_indexes == (1, 2)

    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved_plan=approved,
        target_environment=environment,
        renderer_context=RendererContext(
            contracts_by_plan_id={plan.plan_id: renderer_contract},
            operand_bindings={0: "out", 1: "lhs", 2: "rhs"},
        ),
    ))
    assert rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
    assert rendered.diagnostics == ()
    assert rendered.emitted_text == (
        '__asm__ volatile ("movq %1, %0\\\\n\\\\taddq %2, %0" '
        ': "=&r"(out) : "r"(lhs), "r"(rhs) : "cc");'
    )
