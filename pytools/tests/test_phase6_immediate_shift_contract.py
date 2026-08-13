"""Regression coverage for proof-gated fixed-count GPR shifts."""
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


_CONTRACT_ID = "x86.gnu-att.gpr.out-gpr-immediate-shift.u32-u64.v1"


def _model(opcode: str, width_bytes: int):
    fragment = AsmFragment(
        isVolatile=True,
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="value", isOutput=False)],
    )
    op = Op(
        addr=0x1000, opcode=opcode,
        output=Var(VarKind.REG, "register", 10, width_bytes, "a0"),
        inputs=[
            Var(VarKind.REG, "register", 11, width_bytes, "a1"),
            Var(VarKind.CONST, "const", 3, width_bytes, ""),
        ],
    )
    summary = IRSummary(
        is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a1"},
        writes_regs={"a0"}, reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False,
    )
    return build_source_semantic_model(
        fragment=fragment, blocks=(Block(addr=0x1000, ops=[op], summary=summary),),
        cfg=CFGResult(ok=True), summary=summary, xlen=width_bytes * 8,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1},
            operand_width_bits={0: width_bytes * 8, 1: width_bytes * 8},
        ),
    )


def test_fixed_count_shifts_have_dedicated_proof_bound_renderer_contracts() -> None:
    expected = {"INT_LEFT": "shl", "INT_RIGHT": "shr", "INT_SRIGHT": "sar"}
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att(
        available_features={"x86:gpr_inline_asm"},
    )
    for opcode, mnemonic in expected.items():
        for width_bytes, suffix in ((4, "l"), (8, "q")):
            model = _model(opcode, width_bytes)
            plan = generate_candidate_plans(model)[0]
            assert plan.metadata["renderer_semantic_contract_id"] == _CONTRACT_ID
            derived = derive_target_constraints(
                source_model=model, candidate_plan=plan, target_environment=environment)
            assert derived.success and derived.constraints is not None
            proof = run_semantic_proof_gate(
                source_model=model, preservation_decision=model.preservation,
                candidate_plan=plan, constraints=derived.constraints,
                target_environment=environment,
                target_semantic_catalog=TargetSemanticCatalog(
                    frozenset({plan.kind}), frozenset({_CONTRACT_ID}), "immediate-shift-test-v1"),
                compiler_capabilities=CompilerCapabilityModel(True, False),
            )
            assert proof.approved and proof.evidence is not None
            approved = ApprovedTargetLoweringPlan(
                plan, derived.constraints, proof, proof.evidence.source_model_id,
                proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
                "test", "1", SelectionTier.X86_INLINE_ASM,
            )
            renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
            rendered = render_approved_target_lowering(Phase6FRenderRequest(
                approved, environment,
                RendererContext({plan.plan_id: renderer_contract}, {0: "out", 1: "value"}),
            ))
            assert f"{mnemonic}{suffix} $3, %0" in rendered.emitted_text
            compiler = shutil.which("cc")
            if compiler:
                with tempfile.TemporaryDirectory() as directory:
                    source = Path(directory) / "shift.c"
                    source.write_text(
                        "#include <stdint.h>\n"
                        f"void f(uint{width_bytes * 8}_t value) {{ uint{width_bytes * 8}_t out; "
                        + rendered.emitted_text + " }\n")
                    completed = subprocess.run(
                        [compiler, "-c", "-std=gnu11", str(source), "-o", str(Path(directory) / "shift.o")],
                        capture_output=True, text=True, check=False)
                    assert completed.returncode == 0, completed.stderr
