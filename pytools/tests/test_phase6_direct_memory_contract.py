"""Regression coverage for the narrow direct scalar load/store contracts."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import CompilerCapabilityModel, TargetSemanticCatalog, run_semantic_proof_gate
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan, SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import Phase6FRenderRequest, RendererContext, render_approved_target_lowering
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.source_model import SourceOperationKind, build_source_semantic_model


def test_direct_u64_load_preserves_memory_shell_and_compiles() -> None:
    class LoadInsn:
        addr = 0
        size = 4
        asm_mnem = "ld"
        asm_body = "a0, 0(a1)"
        terminator_kind = None

    class LoadOp:
        opcode = "LOAD"
        output = SimpleNamespace(space="register", offset=10, size=8, name="a0")
        inputs = [
            SimpleNamespace(space="const", offset=0, size=8, name=""),
            SimpleNamespace(space="register", offset=11, size=8, name="a1"),
        ]

    LoadInsn.raw_ops = [LoadOp()]
    blocks, summary = from_lifted([LoadInsn()])
    fragment = AsmFragment(
        rawAsmText="ld %[dst], 0(%[base])",
        isVolatile=True,
        clobbers=["memory"],
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="addr", isOutput=False)],
    )
    model = build_source_semantic_model(
        fragment=fragment, blocks=blocks, cfg=CFGResult(ok=True), summary=summary,
        xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1},
            operand_width_bits={0: 64, 1: 64},
        ),
    )
    assert model.operation.kind is SourceOperationKind.LOAD
    assert model.operation.may_trap is False
    plan = generate_candidate_plans(model)[0]
    assert plan.metadata["renderer_semantic_contract_id"] == "x86.gnu-att.memory.load.gpr-address.u64.v1"
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att(
        # The fixed x86 target profile supplies its architecture identity;
        # callers provide only operational compiler/target capabilities.
        available_features={"x86:gpr_inline_asm"},
    )
    derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
    assert derived.success and derived.constraints is not None
    assert derived.constraints.memory_constraint.requires_memory_clobber
    semantic_id = plan.metadata["renderer_semantic_contract_id"]
    proof = run_semantic_proof_gate(
        source_model=model, preservation_decision=model.preservation,
        candidate_plan=plan, constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({semantic_id}), "direct-memory-test-v1"),
        compiler_capabilities=CompilerCapabilityModel(True, False),
    )
    assert proof.approved and proof.evidence is not None
    approved = ApprovedTargetLoweringPlan(
        plan, derived.constraints, proof, proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
        "test", "1", SelectionTier.X86_INLINE_ASM,
    )
    contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved, environment,
        RendererContext({plan.plan_id: contract}, {0: "out", 1: "addr"}),
    ))
    assert rendered.emitted_text == '__asm__ volatile ("movq (%1), %0" : "=r"(out) : "r"(addr) : "memory");'
    compiler = shutil.which("cc")
    if compiler:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "load.c"
            source.write_text("#include <stdint.h>\nvoid f(const uint64_t *addr) { uint64_t out; " + rendered.emitted_text + " }\n")
            completed = subprocess.run([compiler, "-c", "-std=gnu11", str(source)], capture_output=True, text=True, check=False)
            assert completed.returncode == 0, completed.stderr


def test_direct_u64_load_accepts_transparent_copy_and_add_zero_address_chain() -> None:
    """Ghidra may materialize ``0(base)`` through UNIQUE COPY/INT_ADD nodes."""
    class LoadInsn:
        addr = 0
        size = 4
        asm_mnem = "ld"
        asm_body = "a0, 0(a1)"
        terminator_kind = None

    base = SimpleNamespace(space="register", offset=11, size=8, name="a1")
    copied = SimpleNamespace(space="unique", offset=0x100, size=8, name="")
    address = SimpleNamespace(space="unique", offset=0x108, size=8, name="")
    zero = SimpleNamespace(space="const", offset=0, size=4, name="")
    sign_extended_zero = SimpleNamespace(space="unique", offset=0x104, size=8, name="")

    class CopyOp:
        opcode = "COPY"
        output = copied
        inputs = [base]

    class AddZeroOp:
        opcode = "INT_ADD"
        output = address
        inputs = [copied, sign_extended_zero]

    class SignExtendZeroOp:
        opcode = "INT_SEXT"
        output = sign_extended_zero
        inputs = [zero]

    class LoadOp:
        opcode = "LOAD"
        output = SimpleNamespace(space="register", offset=10, size=8, name="a0")
        inputs = [SimpleNamespace(space="const", offset=0, size=8, name=""), address]

    LoadInsn.raw_ops = [CopyOp(), SignExtendZeroOp(), AddZeroOp(), LoadOp()]
    blocks, summary = from_lifted([LoadInsn()])
    fragment = AsmFragment(
        rawAsmText="ld %[dst], 0(%[base])", isVolatile=True, clobbers=["memory"],
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="addr", isOutput=False)],
    )
    model = build_source_semantic_model(
        fragment=fragment, blocks=blocks, cfg=CFGResult(ok=True), summary=summary,
        xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1},
            operand_width_bits={0: 64, 1: 64},
        ),
    )
    assert model.operation.kind is SourceOperationKind.LOAD
    assert model.operation.may_trap is False
    assert model.operands.operands[1].address is not None
    plan = generate_candidate_plans(model)[0]
    assert plan.metadata["renderer_semantic_contract_id"] == "x86.gnu-att.memory.load.gpr-address.u64.v1"
