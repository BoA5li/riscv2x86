"""Proof-gated regression coverage for the narrow full RISC-V fence route."""

from pathlib import Path
import shutil
import subprocess
import tempfile

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import BarrierInfo, BarrierKind, Block, FenceSet, IRSummary
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel,
    TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan, SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import (
    Phase6FRenderRequest,
    RendererContext,
    RenderedReplacementKind,
    render_approved_target_lowering,
)
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment
from riscv2x86_py.source_model import build_source_semantic_model


_MFENCE_CONTRACT_ID = "x86.gnu-att.mfence.full-system-seq-cst.v1"


def _summary(*, pred: FenceSet, succ: FenceSet) -> IRSummary:
    return IRSummary(
        is_single_block=True,
        has_branch=False,
        has_call_or_return=False,
        has_memory_barrier=True,
        has_atomic=False,
        reads_regs=set(),
        writes_regs=set(),
        reads_mem=False,
        writes_mem=False,
        barrier_infos=[BarrierInfo(
            kind=BarrierKind.MEMORY_FENCE,
            pred_mask=pred,
            succ_mask=succ,
            semantics_complete=True,
        )],
        has_return=False,
        has_tail_call=False,
        has_indirect_control_flow=False,
        has_timing_source=False,
        has_cache_operation=False,
        has_speculation_control=False,
    )


def _model(*, pred: FenceSet, succ: FenceSet):
    summary = _summary(pred=pred, succ=succ)
    return build_source_semantic_model(
        fragment=AsmFragment(
            rawAsmText="fence rw,rw",
            clobbers=["memory"],
            isVolatile=True,
        ),
        blocks=(Block(addr=0x1000, ops=[], summary=summary),),
        cfg=CFGResult(ok=True),
        summary=summary,
        xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={},
            operand_width_bits={},
            provenance="phase4-full-fence-test",
        ),
    )


def _environment() -> TargetEnvironment:
    return TargetEnvironment.fixed_sysv_amd64_gnu_att(
        available_features={"x86:gpr_inline_asm", "x86:hardware_fence"},
    )


def test_full_rw_fence_has_proven_mfence_contract_and_compiles() -> None:
    model = _model(pred=FenceSet.R | FenceSet.W, succ=FenceSet.R | FenceSet.W)
    assert model.barrier.complete
    assert model.barrier.hardware_memory_barrier
    assert model.barrier.compiler_barrier
    assert model.barrier.ordering is not None
    assert model.barrier.ordering.value == "seq_cst"
    assert model.barrier.scope is not None and model.barrier.scope.value == "system"

    plan = next(
        candidate for candidate in generate_candidate_plans(model)
        if candidate.metadata.get("renderer_semantic_contract_id") == _MFENCE_CONTRACT_ID
    )
    environment = _environment()
    derived = derive_target_constraints(
        source_model=model,
        candidate_plan=plan,
        target_environment=environment,
    )
    assert derived.success and derived.constraints is not None
    assert derived.constraints.memory_constraint.requires_memory_clobber
    assert derived.constraints.memory_constraint.requires_compiler_barrier
    assert derived.constraints.memory_constraint.requires_hardware_barrier

    proof = run_semantic_proof_gate(
        source_model=model,
        preservation_decision=model.preservation,
        candidate_plan=plan,
        constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(
            supported_plan_kinds=frozenset({plan.kind}),
            semantic_contract_ids=frozenset({_MFENCE_CONTRACT_ID}),
            version="rv64-full-fence-test-v1",
        ),
        compiler_capabilities=CompilerCapabilityModel(
            supports_gnu_inline_asm=True,
            supports_asm_goto=False,
        ),
    )
    assert proof.approved and proof.evidence is not None

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
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved_plan=approved,
        target_environment=environment,
        renderer_context=RendererContext(
            contracts_by_plan_id={plan.plan_id: renderer_contract},
            operand_bindings={},
        ),
    ))
    assert rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
    assert rendered.emitted_text == '__asm__ volatile ("mfence" :  :  : "memory");'

    compiler = shutil.which("cc")
    if compiler is None:
        return
    source = "void f(void) { " + rendered.emitted_text + " }\n"
    with tempfile.TemporaryDirectory(prefix="riscv2x86-rv64-fence-") as temp_dir:
        path = Path(temp_dir) / "rv64_fence_lowered.c"
        path.write_text(source, encoding="utf-8")
        completed = subprocess.run(
            [compiler, "-c", "-std=gnu11", str(path), "-o", str(path.with_suffix(".o"))],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    assert completed.returncode == 0, completed.stderr


def test_directional_fences_remain_fail_closed() -> None:
    """Do not infer lfence/sfence/mfence from partial RISC-V ordering sets."""
    model = _model(pred=FenceSet.R, succ=FenceSet.W)
    assert not model.barrier.complete
    assert model.barrier.ordering is None

    environment = _environment()
    mfence = next(
        candidate for candidate in generate_candidate_plans(model)
        if candidate.metadata.get("renderer_semantic_contract_id") == _MFENCE_CONTRACT_ID
    )
    derived = derive_target_constraints(
        source_model=model,
        candidate_plan=mfence,
        target_environment=environment,
    )
    assert not derived.success


def test_canonical_summary_marks_standalone_full_fence_as_no_control_flow() -> None:
    """The Phase-5 summary must not leave a known fence's CFG facts unknown."""
    from riscv2x86_py.pcode_ir import from_lifted

    class LiftedFence:
        addr = 0x1000
        size = 4
        raw_ops = []
        terminator_kind = None
        has_branch_op = False
        has_call_or_return_op = False
        has_unknown_barrier = False
        has_atomic = False
        atomic_mnemonic = None
        atomic_orderings = set()
        atomic_reads_mem = False
        atomic_writes_mem = False
        semantic_tags = frozenset()
        # This is Phase 5 input only.  Phase 6 consumes the resulting typed
        # BarrierInfo/IRSummary, never either source string.
        asm_mnem = "fence"
        asm_body = "rw,rw"

    _, summary = from_lifted([LiftedFence()])
    assert summary.barrier_info is not None
    assert summary.has_return is False
    assert summary.has_tail_call is False
    assert summary.has_indirect_control_flow is False
