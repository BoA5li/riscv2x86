"""Regression test for the proof-gated RV64 register-only add path."""

from pathlib import Path
import shutil
import subprocess
import tempfile

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
_IMMEDIATE_CONTRACT_ID = "x86.gnu-att.gpr.out-gpr-immediate-binary.v1"


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
    assert renderer_contract.payload.template == "movq %1, %0\n\taddq %2, %0"
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
        '__asm__ volatile ("movq %1, %0\\n\\taddq %2, %0" '
        ': "=&r"(out) : "r"(lhs), "r"(rhs) : "cc");'
    )

    compiler = shutil.which("cc")
    if compiler is None:
        return
    source = "#include <stdint.h>\nuint64_t f(uint64_t lhs, uint64_t rhs) { uint64_t out; " + rendered.emitted_text + " return out; }\n"
    with tempfile.TemporaryDirectory(prefix="riscv2x86-rv64-add-") as temp_dir:
        path = Path(temp_dir) / "rv64_add_lowered.c"
        path.write_text(source, encoding="utf-8")
        completed = subprocess.run(
            [compiler, "-c", "-std=gnu11", str(path), "-o", str(path.with_suffix(".o"))],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    assert completed.returncode == 0, completed.stderr


def test_rv64_register_immediate_operations_have_proven_att_contracts() -> None:
    """Cover the whole registered OP-IMM value family, not only addi."""
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    operation_kinds = {
        "INT_ADD": "addq",
        "INT_SUB": "subq",
        "INT_AND": "andq",
        "INT_OR": "orq",
        "INT_XOR": "xorq",
    }
    for opcode, target_opcode in operation_kinds.items():
        fragment = AsmFragment(
            outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
            inputs=[AsmOperand(constraint="r", exprText="value")],
            isVolatile=True,
        )
        operation = Op(
            addr=0x1000,
            opcode=opcode,
            output=Var(VarKind.REG, "register", 10, 8, "a0"),
            inputs=[
                Var(VarKind.REG, "register", 11, 8, "a1"),
                Var(VarKind.CONST, "const", 0x100, 8),
            ],
        )
        summary = IRSummary(
            is_single_block=True, has_branch=False, has_call_or_return=False,
            has_memory_barrier=False, has_atomic=False,
            reads_regs={"a1"}, writes_regs={"a0"}, reads_mem=False,
            writes_mem=False, has_return=False, has_tail_call=False,
            has_indirect_control_flow=False, has_timing_source=False,
            has_cache_operation=False, has_speculation_control=False,
        )
        model = build_source_semantic_model(
            fragment=fragment,
            blocks=(Block(addr=0x1000, ops=[operation], summary=summary),),
            cfg=CFGResult(ok=True), summary=summary, xlen=64,
            runtime_facts=TranslationRuntimeFacts(
                rv_to_operand_index={"a0": 0, "a1": 1},
                operand_width_bits={0: 64, 1: 64},
                provenance="phase4-op-imm-test",
            ),
        )
        assert model.value_operation is not None
        assert model.value_operation.immediate_value == 0x100
        plan = next(
            candidate for candidate in generate_candidate_plans(model)
            if candidate.metadata.get("renderer_semantic_contract_id")
            == _IMMEDIATE_CONTRACT_ID
        )
        derived = derive_target_constraints(
            source_model=model, candidate_plan=plan,
            target_environment=environment,
        )
        assert derived.success and derived.constraints is not None
        proof = run_semantic_proof_gate(
            source_model=model, preservation_decision=model.preservation,
            candidate_plan=plan, constraints=derived.constraints,
            target_environment=environment,
            target_semantic_catalog=TargetSemanticCatalog(
                supported_plan_kinds=frozenset({plan.kind}),
                semantic_contract_ids=frozenset({_IMMEDIATE_CONTRACT_ID}),
                version="rv64-op-imm-test-v1",
            ),
            compiler_capabilities=CompilerCapabilityModel(True, False),
        )
        assert proof.approved and proof.evidence is not None
        approved = ApprovedTargetLoweringPlan(
            plan, derived.constraints, proof,
            proof.evidence.source_model_id,
            proof.evidence.preservation_decision_id,
            proof.evidence.target_environment_id,
            "phase6e.semantic-fidelity", "1", SelectionTier.X86_INLINE_ASM,
        )
        renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
        assert renderer_contract is not None
        rendered = render_approved_target_lowering(Phase6FRenderRequest(
            approved, environment,
            RendererContext({plan.plan_id: renderer_contract}, {0: "out", 1: "value"}),
        ))
        assert rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
        assert f"{target_opcode} $256, %0" in rendered.emitted_text
        compiler = shutil.which("cc")
        if compiler is not None:
            source = (
                "#include <stdint.h>\n"
                "uint64_t f(uint64_t value) { uint64_t out; "
                + rendered.emitted_text + " return out; }\n"
            )
            with tempfile.TemporaryDirectory(prefix="riscv2x86-rv64-op-imm-") as temp_dir:
                path = Path(temp_dir) / "rv64_op_imm_lowered.c"
                path.write_text(source, encoding="utf-8")
                completed = subprocess.run(
                    [compiler, "-c", "-std=gnu11", str(path), "-o", str(path.with_suffix(".o"))],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False,
                )
            assert completed.returncode == 0, completed.stderr


def test_rv64_register_immediate_contract_accepts_transparent_copy_chain() -> None:
    """Model the common lifted form: COPY input -> UNIQUE -> ALU -> COPY output."""
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="value")],
        isVolatile=True,
    )
    source_reg = Var(VarKind.REG, "register", 11, 8, "a1")
    temporary_input = Var(VarKind.UNIQUE, "unique", 0x10, 8)
    temporary_output = Var(VarKind.UNIQUE, "unique", 0x20, 8)
    destination_reg = Var(VarKind.REG, "register", 10, 8, "a0")
    operations = [
        Op(0x1000, "COPY", temporary_input, [source_reg]),
        Op(0x1000, "INT_ADD", temporary_output, [
            temporary_input, Var(VarKind.CONST, "const", 0x100, 4),
        ]),
        Op(0x1000, "COPY", destination_reg, [temporary_output]),
    ]
    summary = IRSummary(
        is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a1"},
        writes_regs={"a0"}, reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False,
    )
    model = build_source_semantic_model(
        fragment=fragment,
        blocks=(Block(addr=0x1000, ops=operations, summary=summary),),
        cfg=CFGResult(ok=True), summary=summary, xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1},
            operand_width_bits={0: 64, 1: 64},
            provenance="phase4-copy-chain-test",
        ),
    )
    assert model.value_operation is not None
    assert model.value_operation.input_operand_indexes == (1,)
    assert model.value_operation.result_operand_index == 0
    assert model.value_operation.immediate_value == 0x100
    assert any(
        plan.metadata.get("renderer_semantic_contract_id")
        == _IMMEDIATE_CONTRACT_ID
        for plan in generate_candidate_plans(model)
    )


def test_rv64_variable_register_shifts_have_proven_cl_contracts() -> None:
    """Cover the complete SLL/SRL/SRA register-count semantic family."""
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    contract_id = "x86.gnu-att.gpr.out-gpr-variable-shift.u32-u64.v1"
    for opcode, expected in (("INT_LEFT", "shlq"), ("INT_RIGHT", "shrq"), ("INT_SRIGHT", "sarq")):
        fragment = AsmFragment(
            outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
            inputs=[AsmOperand(constraint="r", exprText="value"), AsmOperand(constraint="r", exprText="count")],
            isVolatile=True,
        )
        operation = Op(0x1000, opcode, Var(VarKind.REG, "register", 10, 8, "a0"), [
            Var(VarKind.REG, "register", 11, 8, "a1"), Var(VarKind.REG, "register", 12, 8, "a2"),
        ])
        summary = IRSummary(is_single_block=True, has_branch=False, has_call_or_return=False,
            has_memory_barrier=False, has_atomic=False, reads_regs={"a1", "a2"}, writes_regs={"a0"},
            reads_mem=False, writes_mem=False, has_return=False, has_tail_call=False,
            has_indirect_control_flow=False, has_timing_source=False, has_cache_operation=False,
            has_speculation_control=False)
        model = build_source_semantic_model(fragment=fragment,
            blocks=(Block(addr=0x1000, ops=[operation], summary=summary),), cfg=CFGResult(ok=True),
            summary=summary, xlen=64, runtime_facts=TranslationRuntimeFacts(
                rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
                operand_width_bits={0: 64, 1: 64, 2: 64}, provenance="variable-shift-test"))
        assert model.value_operation is not None
        plan = next(item for item in generate_candidate_plans(model)
            if item.metadata.get("renderer_semantic_contract_id") == contract_id)
        derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
        assert derived.success and derived.constraints is not None
        assert derived.constraints.operand_constraints[2].gnu_constraint_body == "c"
        proof = run_semantic_proof_gate(source_model=model, preservation_decision=model.preservation,
            candidate_plan=plan, constraints=derived.constraints, target_environment=environment,
            target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({contract_id}), "shift-test-v1"),
            compiler_capabilities=CompilerCapabilityModel(True, False))
        assert proof.approved and proof.evidence is not None
        approved = ApprovedTargetLoweringPlan(plan, derived.constraints, proof, proof.evidence.source_model_id,
            proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
            "phase6e.semantic-fidelity", "1", SelectionTier.X86_INLINE_ASM)
        renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
        assert renderer_contract is not None
        rendered = render_approved_target_lowering(Phase6FRenderRequest(approved, environment,
            RendererContext({plan.plan_id: renderer_contract}, {0: "out", 1: "value", 2: "count"})))
        assert rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
        assert f"{expected} %b2, %0" in rendered.emitted_text
        assert '"c"(count)' in rendered.emitted_text
        compiler = shutil.which("cc")
        if compiler is not None:
            source = "#include <stdint.h>\nuint64_t f(uint64_t value,uint64_t count){uint64_t out;" + rendered.emitted_text + "return out;}\n"
            with tempfile.TemporaryDirectory(prefix="riscv2x86-variable-shift-") as directory:
                path = Path(directory) / "shift.c"
                path.write_text(source, encoding="utf-8")
                completed = subprocess.run([compiler, "-c", "-std=gnu11", str(path), "-o", str(path.with_suffix(".o"))],
                    capture_output=True, text=True, check=False)
            assert completed.returncode == 0, completed.stderr


def test_rv64_variable_shift_accepts_only_architectural_count_mask_normalization() -> None:
    """SLEIGH's ``count & (XLEN - 1)`` UNIQUE temporary is not a second op."""
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="value"), AsmOperand(constraint="r", exprText="count")],
        isVolatile=True,
    )
    temporary = Var(VarKind.UNIQUE, "unique", 0x100, 8)
    operations = [
        Op(0x1000, "INT_AND", temporary, [
            Var(VarKind.REG, "register", 12, 8, "a2"),
            Var(VarKind.CONST, "const", 63, 8),
        ]),
        Op(0x1000, "INT_LEFT", Var(VarKind.REG, "register", 10, 8, "a0"), [
            Var(VarKind.REG, "register", 11, 8, "a1"), temporary,
        ]),
    ]
    summary = IRSummary(is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a1", "a2"}, writes_regs={"a0"},
        reads_mem=False, writes_mem=False, has_return=False, has_tail_call=False,
        has_indirect_control_flow=False, has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False)
    model = build_source_semantic_model(fragment=fragment,
        blocks=(Block(addr=0x1000, ops=operations, summary=summary),), cfg=CFGResult(ok=True),
        summary=summary, xlen=64, runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
            operand_width_bits={0: 64, 1: 64, 2: 64}, provenance="masked-shift-test"))
    assert model.value_operation is not None
    assert model.value_operation.shift_count_mask == 63
    assert any(plan.metadata.get("renderer_semantic_contract_id")
               == "x86.gnu-att.gpr.out-gpr-variable-shift.u32-u64.v1"
               for plan in generate_candidate_plans(model))


def test_rv64_variable_shift_accepts_copy_subpiece_zext_count_normalization() -> None:
    """Admit the complete structured temporary family emitted by lifters."""
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="value"), AsmOperand(constraint="r", exprText="count")],
        isVolatile=True,
    )
    low = Var(VarKind.UNIQUE, "unique", 0x101, 1)
    extended = Var(VarKind.UNIQUE, "unique", 0x102, 8)
    masked = Var(VarKind.UNIQUE, "unique", 0x103, 8)
    operations = [
        Op(0x1000, "SUBPIECE", low, [Var(VarKind.REG, "register", 12, 8, "a2"), Var(VarKind.CONST, "const", 0, 8)]),
        Op(0x1000, "INT_ZEXT", extended, [low]),
        Op(0x1000, "INT_AND", masked, [extended, Var(VarKind.CONST, "const", 63, 8)]),
        Op(0x1000, "INT_LEFT", Var(VarKind.REG, "register", 10, 8, "a0"), [Var(VarKind.REG, "register", 11, 8, "a1"), masked]),
    ]
    summary = IRSummary(is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a1", "a2"}, writes_regs={"a0"},
        reads_mem=False, writes_mem=False, has_return=False, has_tail_call=False,
        has_indirect_control_flow=False, has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False)
    model = build_source_semantic_model(fragment=fragment,
        blocks=(Block(addr=0x1000, ops=operations, summary=summary),), cfg=CFGResult(ok=True),
        summary=summary, xlen=64, runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
            operand_width_bits={0: 64, 1: 64, 2: 64}, provenance="extended-masked-shift-test"))
    assert model.value_operation is not None
    assert model.value_operation.input_operand_indexes == (1, 2)
    assert model.value_operation.shift_count_mask == 63


def test_rv64_variable_shift_accepts_sleigh_xlen_minus_one_mask_dag() -> None:
    """Match the actual ``INT_SUB(64, 1); INT_AND`` SLEIGH normalization."""
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="value"), AsmOperand(constraint="r", exprText="count")],
        isVolatile=True,
    )
    mask = Var(VarKind.UNIQUE, "unique", 0x201, 8)
    count = Var(VarKind.UNIQUE, "unique", 0x202, 8)
    operations = [
        Op(0x1000, "INT_SUB", mask, [Var(VarKind.CONST, "const", 64, 8), Var(VarKind.CONST, "const", 1, 8)]),
        Op(0x1000, "INT_AND", count, [Var(VarKind.REG, "register", 12, 8, "a2"), mask]),
        Op(0x1000, "INT_LEFT", Var(VarKind.REG, "register", 10, 8, "a0"), [Var(VarKind.REG, "register", 11, 8, "a1"), count]),
    ]
    summary = IRSummary(is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a1", "a2"}, writes_regs={"a0"},
        reads_mem=False, writes_mem=False, has_return=False, has_tail_call=False,
        has_indirect_control_flow=False, has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False)
    model = build_source_semantic_model(fragment=fragment,
        blocks=(Block(addr=0x1000, ops=operations, summary=summary),), cfg=CFGResult(ok=True),
        summary=summary, xlen=64, runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
            operand_width_bits={0: 64, 1: 64, 2: 64}, provenance="sleigh-xlen-minus-one-test"))
    assert model.value_operation is not None
    assert model.value_operation.input_operand_indexes == (1, 2)
    assert model.value_operation.shift_count_mask == 63
