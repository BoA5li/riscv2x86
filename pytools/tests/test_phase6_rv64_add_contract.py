"""Regression test for the proof-gated RV64 register-only add path."""

from pathlib import Path
import shutil
import subprocess
import tempfile

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGNode, CFGResult
from riscv2x86_py.functional_observability import analyze_functional_observability
from riscv2x86_py.pcode_ir import (
    Block, CanonicalCsrOperationKind, CanonicalInsn,
    CanonicalPrivilegedOperation, CanonicalPrivilegedOperationKind,
    IRSummary, Op, Var, VarKind,
)
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
from riscv2x86_py.privileged_execution_sidecar import (
    CsrAccessPolicyFacts, PrivilegedExecutionFacts, SourceExecutionProfile,
    SourcePrivilegeMode, TargetExecutionMode, UnknownCsrAccessDisposition,
)
from riscv2x86_py.privileged_state_analysis import analyze_privileged_state
from riscv2x86_py.helper_runtime_manifest import INSTRUCTION_STREAM_SYNC_LOCAL
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.shell_model import SourceShellModel
from riscv2x86_py.source_model import build_source_semantic_model
from riscv2x86_py.translate import translate


class _IngressLiftInsn:
    addr = 0x1000
    length = 4


class _IngressLift:
    ok = True
    insns = (_IngressLiftInsn(),)


_CONTRACT_ID = "x86.gnu-att.gpr.out-gpr-gpr-binary.v1"
_IMMEDIATE_CONTRACT_ID = "x86.gnu-att.gpr.out-gpr-immediate-binary.v1"
_LOCAL_BRANCH_SELECT_CONTRACT_ID = "x86.gnu-att.local-branch-select.compare.u32-u64.v1"
_LOCAL_UNCONDITIONAL_JUMP_CONTRACT_ID = "x86.gnu-att.local-unconditional-jump.copy.u32-u64.v1"


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
        is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False,
        reads_regs={"a1", "a2"}, writes_regs={"a0"},
        reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False,
    )
    return build_source_semantic_model(
        fragment=fragment, blocks=(Block(addr=0x1000, ops=[operation], summary=summary),),
        cfg=CFGResult(ok=True), summary=summary, xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
            operand_width_bits={0: 64, 1: 64, 2: 64}, provenance="phase4-test",
        ),
    )


def _build_rv64_local_branch_select_model(comparison_opcode="INT_EQUAL"):
    """Build a typed three-block local branch/select, without asm text."""
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText=name)
                for name in ("left", "right", "when_equal", "when_not_equal")],
        isVolatile=True,
    )
    a0 = Var(VarKind.REG, "register", 10, 8, "a0")
    a1 = Var(VarKind.REG, "register", 11, 8, "a1")
    a2 = Var(VarKind.REG, "register", 12, 8, "a2")
    a3 = Var(VarKind.REG, "register", 13, 8, "a3")
    a4 = Var(VarKind.REG, "register", 14, 8, "a4")
    predicate = Var(VarKind.UNIQUE, "unique", 0, 1)
    target = Var(VarKind.MEM, "ram", 0x1020, 8)
    join = Var(VarKind.MEM, "ram", 0x1030, 8)
    entry = Block(0x1000, [
        Op(0x1000, comparison_opcode, predicate, [a1, a2]),
        Op(0x1000, "CBRANCH", None, [target, predicate]),
    ], successors=[0x1010, 0x1020], successor_kinds={0x1010: "fallthrough", 0x1020: "branch_taken"},
       terminator_kind="cbranch", has_branch=True)
    fallthrough = Block(0x1010, [
        Op(0x1010, "COPY", a0, [a4]), Op(0x1010, "BRANCH", None, [join]),
    ], successors=[], terminator_kind="branch", has_branch=True)
    taken = Block(0x1020, [Op(0x1020, "COPY", a0, [a3])])
    summary = IRSummary(
        is_single_block=False, has_branch=True, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False,
        reads_regs={"a1", "a2", "a3", "a4"}, writes_regs={"a0"},
        reads_mem=False, writes_mem=False,
    )
    return build_source_semantic_model(
        fragment=fragment, blocks=(entry, fallthrough, taken),
        cfg=CFGResult(ok=True), summary=summary, xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2, "a3": 3, "a4": 4},
            operand_width_bits={index: 64 for index in range(5)},
            provenance="phase4-test",
        ),
    )


def test_rv64_local_branch_select_is_proof_bound_and_renderable() -> None:
    model = _build_rv64_local_branch_select_model()
    assert model.local_branch_select is not None
    plan = next(item for item in generate_candidate_plans(model)
                if item.metadata.get("renderer_semantic_contract_id") == _LOCAL_BRANCH_SELECT_CONTRACT_ID)
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
    assert derived.success and derived.constraints is not None
    proof = run_semantic_proof_gate(
        source_model=model, preservation_decision=model.preservation,
        candidate_plan=plan, constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(
            supported_plan_kinds=frozenset({plan.kind}),
            semantic_contract_ids=frozenset({_LOCAL_BRANCH_SELECT_CONTRACT_ID}),
            version="local-branch-select-test-v1"),
        compiler_capabilities=CompilerCapabilityModel(supports_gnu_inline_asm=True, supports_asm_goto=False),
    )
    assert proof.approved
    approved = ApprovedTargetLoweringPlan(
        plan=plan, constraints=derived.constraints, proof=proof,
        source_model_id=proof.evidence.source_model_id,
        preservation_decision_id=proof.evidence.preservation_decision_id,
        target_environment_id=proof.evidence.target_environment_id,
        selection_policy_id="test", selection_policy_version="1",
        selection_tier=SelectionTier.X86_INLINE_ASM,
    )
    renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    assert renderer_contract is not None
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved_plan=approved, target_environment=environment,
        renderer_context=RendererContext(
            contracts_by_plan_id={plan.plan_id: renderer_contract},
            operand_bindings={0: "out", 1: "left", 2: "right", 3: "when_equal", 4: "when_not_equal"},
        )))
    assert rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
    assert rendered.emitted_text is not None and "cmpq" in rendered.emitted_text and "je 1f" in rendered.emitted_text


def test_rv64_local_unconditional_jump_to_copy_is_proof_bound_and_renderable() -> None:
    """A direct local jump may elide only CFG-proven unreachable code."""
    fragment = AsmFragment(
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="init"),
                AsmOperand(constraint="r", exprText="alt")],
        isVolatile=True,
    )
    a0 = Var(VarKind.REG, "register", 10, 8, "a0")
    a1 = Var(VarKind.REG, "register", 11, 8, "a1")
    a2 = Var(VarKind.REG, "register", 12, 8, "a2")
    target = Var(VarKind.MEM, "ram", 0x1010, 8)
    entry = Block(0x1000, [Op(0x1000, "BRANCH", None, [target])],
                  successors=[0x1010], successor_kinds={0x1010: "branch"},
                  terminator_kind="branch", has_branch=True)
    unreachable = Block(0x1004, [Op(0x1004, "COPY", a0, [a2])])
    selected = Block(0x1010, [Op(0x1010, "COPY", a0, [a1])])
    summary = IRSummary(
        is_single_block=False, has_branch=True, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False,
        reads_regs={"a1", "a2"}, writes_regs={"a0"},
        reads_mem=False, writes_mem=False,
    )
    model = build_source_semantic_model(
        fragment=fragment, blocks=(entry, unreachable, selected),
        cfg=CFGResult(ok=True), summary=summary, xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
            operand_width_bits={0: 64, 1: 64, 2: 64}, provenance="phase4-test",
        ),
    )
    assert model.local_unconditional_jump is not None
    plan = next(item for item in generate_candidate_plans(model)
                if item.metadata.get("renderer_semantic_contract_id") == _LOCAL_UNCONDITIONAL_JUMP_CONTRACT_ID)
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
    assert derived.success and derived.constraints is not None
    proof = run_semantic_proof_gate(
        source_model=model, preservation_decision=model.preservation,
        candidate_plan=plan, constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(
            frozenset({plan.kind}), frozenset({_LOCAL_UNCONDITIONAL_JUMP_CONTRACT_ID}),
            "local-unconditional-jump-test-v1"),
        compiler_capabilities=CompilerCapabilityModel(True, False),
    )
    assert proof.approved
    approved = ApprovedTargetLoweringPlan(
        plan, derived.constraints, proof, proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
        "test", "1", SelectionTier.X86_INLINE_ASM,
    )
    renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved, environment,
        RendererContext({plan.plan_id: renderer_contract}, {0: "out", 1: "init", 2: "alt"}),
    ))
    assert rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
    assert rendered.emitted_text == '__asm__ volatile ("movq %1, %0" : "=r"(out) : "r"(init), "r"(alt) : );'


def test_rv64_local_branch_select_covers_canonical_integer_comparisons() -> None:
    """The local CFG family is keyed by typed compare semantics, not bltu text."""
    expected_jumps = {
        "INT_EQUAL": "je 1f", "INT_NOTEQUAL": "jne 1f",
        "INT_SLESS": "jl 1f", "INT_LESS": "jb 1f",
        "INT_SLESSEQUAL": "jle 1f", "INT_LESSEQUAL": "jbe 1f",
    }
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    for opcode, expected_jump in expected_jumps.items():
        model = _build_rv64_local_branch_select_model(opcode)
        assert model.local_branch_select is not None
        plan = next(item for item in generate_candidate_plans(model)
                    if item.metadata.get("renderer_semantic_contract_id") == _LOCAL_BRANCH_SELECT_CONTRACT_ID)
        derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
        assert derived.success and derived.constraints is not None
        proof = run_semantic_proof_gate(
            source_model=model, preservation_decision=model.preservation,
            candidate_plan=plan, constraints=derived.constraints,
            target_environment=environment,
            target_semantic_catalog=TargetSemanticCatalog(
                supported_plan_kinds=frozenset({plan.kind}),
                semantic_contract_ids=frozenset({_LOCAL_BRANCH_SELECT_CONTRACT_ID}),
                version="local-branch-select-test-v1"),
            compiler_capabilities=CompilerCapabilityModel(supports_gnu_inline_asm=True, supports_asm_goto=False),
        )
        assert proof.approved
        approved = ApprovedTargetLoweringPlan(
            plan=plan, constraints=derived.constraints, proof=proof,
            source_model_id=proof.evidence.source_model_id,
            preservation_decision_id=proof.evidence.preservation_decision_id,
            target_environment_id=proof.evidence.target_environment_id,
            selection_policy_id="test", selection_policy_version="1",
            selection_tier=SelectionTier.X86_INLINE_ASM,
        )
        renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
        assert renderer_contract is not None
        rendered = render_approved_target_lowering(Phase6FRenderRequest(
            approved_plan=approved, target_environment=environment,
            renderer_context=RendererContext(
                contracts_by_plan_id={plan.plan_id: renderer_contract},
                operand_bindings={0: "out", 1: "left", 2: "right", 3: "when_true", 4: "when_false"},
            )))
        assert rendered.emitted_text is not None and expected_jump in rendered.emitted_text


def test_rv64_counter_csr_read_is_a_structured_runtime_route() -> None:
    """Counter CSRs must not become an accidental rdtsc/clock rewrite."""
    fragment = AsmFragment(
        id="counter-frag",
        outputs=[AsmOperand(constraint="=r", exprText="time_val", isOutput=True)],
        isVolatile=True,
    )
    a0 = Var(VarKind.REG, "register", 10, 8, "a0")
    time = Var(VarKind.REG, "register", 0, 8, "time")
    summary = IRSummary(
        is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False,
        reads_regs={"time"}, writes_regs={"a0"}, reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False,
    )
    blocks = (Block(0x1000, [Op(0x1000, "COPY", a0, [time])], summary=summary,
                    instructions=[CanonicalInsn(
                        addr=0x1000, size=4,
                        privileged_operations=(CanonicalPrivilegedOperation(
                            kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
                            csr_id="riscv.csr.time",
                            csr_operation=CanonicalCsrOperationKind.READ,
                            required_privilege_mode="u", may_trap=False,
                            state_complete=True,
                        ),),
                    )]),)
    cfg = CFGResult(
        ok=True, entry=0x1000,
        nodes={0x1000: CFGNode(addr=0x1000, size=4, instr_addrs=[0x1000])},
    )
    execution_facts = PrivilegedExecutionFacts(
        fragment_id="counter-frag",
        source_execution_profile=SourceExecutionProfile.RISCV_USER_PROCESS,
        target_execution_mode=TargetExecutionMode.X86_USER_PROCESS,
        source_privilege_spec_version="1.12",
        source_isa_extensions=("i", "zicsr"),
        initial_privilege_mode=SourcePrivilegeMode.U,
        csr_access_policy=CsrAccessPolicyFacts(
            policy_id="counter-policy-v1",
            readable_csr_ids=("riscv.csr.time",), writable_csr_ids=(),
            unknown_access=UnknownCsrAccessDisposition.DENY, complete=True,
        ),
        target_runtime_contract_set_id="x86-counter-v1", complete=True,
        missing_fact_codes=(), provenance="compiler-plugin:test",
    )
    privileged_state = analyze_privileged_state(
        fragment_id="counter-frag", blocks=blocks, cfg=cfg,
        execution_facts=execution_facts,
    )
    observability = analyze_functional_observability(
        fragment_id="counter-frag",
        shell=SourceShellModel.from_fragment(fragment), summary=summary, cfg=cfg,
        privileged_state=privileged_state, operand_width_bits={0: 64},
    )
    facts = TranslationRuntimeFacts(
        rv_to_operand_index={"a0": 0}, operand_width_bits={0: 64}, provenance="phase4-test",
    )
    model = build_source_semantic_model(
        fragment=fragment, blocks=blocks, cfg=cfg, summary=summary,
        runtime_facts=facts, xlen=64, privileged_state=privileged_state,
        functional_observability=observability,
    )
    assert model.read_only_csr is not None
    assert model.read_only_csr.csr_name == "time"
    routed = translate(
        frag=fragment, lift=_IngressLift(), summary=summary, machine_code=b"\0\0\0\0", xlen=64,
        blocks=blocks, cfg=cfg, runtime_facts=facts,
        privileged_state=privileged_state,
        functional_observability=observability,
    )
    assert routed.kind == "needs_route"
    assert "TR_CSR_COUNTER_RUNTIME_CONTRACT_REQUIRED" in routed.reasonCodes

    functional_environment = TargetEnvironment.fixed_sysv_amd64_gnu_att(
        available_features={"x86:gpr_inline_asm", "x86:rdtsc"},
        builtin_capabilities={"compiler:x86-rdtsc-builtin"},
    )
    functional = translate(
        frag=fragment, lift=_IngressLift(), summary=summary,
        machine_code=b"\0\0\0\0", xlen=64, blocks=blocks,
        cfg=cfg, runtime_facts=facts,
        privileged_state=privileged_state,
        functional_observability=observability,
        target_environment=functional_environment,
        allow_functional_fallbacks=True,
    )
    assert functional.kind == "functional_c"
    assert functional.replacement == (
        "time_val = (uint64_t)__builtin_ia32_rdtsc();"
    )
    artifact = functional.metadata["approvalArtifact"]
    assert artifact["proofStatus"] == "functional_approved"
    assert artifact["preservationMode"] == "functional_equivalence_only"


def test_instruction_stream_barrier_requires_explicit_route() -> None:
    """Instruction-stream barriers must never be guessed as x86 fences."""
    fragment = AsmFragment(clobbers=["memory"], isVolatile=True)
    summary = IRSummary(
        is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_instruction_barrier=True,
        has_atomic=False, reads_regs=set(), writes_regs=set(),
        reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False,
    )
    blocks = (Block(
        0x1000,
        [Op(0x1000, "CALLOTHER", None, [
            Var(VarKind.CONST, "const", 5, 4),
        ])],
        summary=summary,
        instructions=[CanonicalInsn(addr=0x1000, size=4)],
    ),)
    routed = translate(
        frag=fragment, lift=_IngressLift(), summary=summary,
        machine_code=b"\0\0\0\0", xlen=64, blocks=blocks,
        cfg=CFGResult(ok=True),
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={}, operand_width_bits={}, provenance="phase4-test",
        ),
    )
    assert routed.kind == "needs_route"
    assert "TR_INSTRUCTION_STREAM_SYNC_RUNTIME_CONTRACT_REQUIRED" in routed.reasonCodes
    assert routed.metadata["functionalFallbackPermitted"] is True

    functional_environment = TargetEnvironment.fixed_sysv_amd64_gnu_att(
        helper_contract_capabilities={
            INSTRUCTION_STREAM_SYNC_LOCAL.required_environment_capability,
        },
    )
    functional = translate(
        frag=fragment, lift=_IngressLift(), summary=summary,
        machine_code=b"\0\0\0\0", xlen=64, blocks=blocks,
        cfg=CFGResult(ok=True),
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={}, operand_width_bits={}, provenance="phase4-test",
        ),
        target_environment=functional_environment,
        allow_functional_fallbacks=True,
    )
    assert functional.kind == "functional_c"
    assert functional.replacement == "riscv2x86_rt_instruction_stream_sync_local();"
    assert functional.metadata["approvalArtifact"]["replacementKind"] == "helper_call"


def test_instruction_stream_noop_elision_requires_explicit_certificate() -> None:
    fragment = AsmFragment(clobbers=["memory"], isVolatile=True)
    summary = IRSummary(
        is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_instruction_barrier=True,
        has_atomic=False, reads_regs=set(), writes_regs=set(),
        reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False,
        has_speculation_control=False,
    )
    blocks = (Block(
        0x1000, [], summary=summary,
        instructions=[CanonicalInsn(addr=0x1000, size=4)],
    ),)
    elided = translate(
        frag=fragment, lift=_IngressLift(), summary=summary,
        machine_code=b"\0\0\0\0", xlen=64, blocks=blocks,
        cfg=CFGResult(ok=True),
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={}, operand_width_bits={}, provenance="frontend-proof",
            instruction_stream_sync_noop_proven=True,
            instruction_stream_sync_proof_id="host-cfg:no-code-write-or-execution:v1",
        ),
    )
    assert elided.kind == "instruction_stream_elision"
    artifact = elided.metadata["approvalArtifact"]
    assert artifact["proofStatus"] == "approved"
    assert artifact["replacementKind"] == "instruction_stream_elision"


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


def test_rv64_boolean_comparisons_have_proven_setcc_contracts() -> None:
    """Cover canonical signed/unsigned compare plus XLEN boolean extension."""
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    contract_id = "x86.gnu-att.gpr.out-gpr-boolean-compare.u32-u64.v1"
    for opcode, expected in (("INT_SLESS", "setl"), ("INT_LESS", "setb"),
                             ("INT_EQUAL", "sete"), ("INT_NOTEQUAL", "setne")):
        fragment = AsmFragment(
            outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
            inputs=[AsmOperand(constraint="r", exprText="left"), AsmOperand(constraint="r", exprText="right")],
            isVolatile=True,
        )
        predicate = Var(VarKind.UNIQUE, "unique", 0x301, 1)
        operations = [
            Op(0x1000, opcode, predicate, [Var(VarKind.REG, "register", 11, 8, "a1"), Var(VarKind.REG, "register", 12, 8, "a2")]),
            Op(0x1000, "INT_ZEXT", Var(VarKind.REG, "register", 10, 8, "a0"), [predicate]),
        ]
        summary = IRSummary(is_single_block=True, has_branch=False, has_call_or_return=False,
            has_memory_barrier=False, has_atomic=False, reads_regs={"a1", "a2"}, writes_regs={"a0"},
            reads_mem=False, writes_mem=False, has_return=False, has_tail_call=False,
            has_indirect_control_flow=False, has_timing_source=False, has_cache_operation=False,
            has_speculation_control=False)
        model = build_source_semantic_model(fragment=fragment,
            blocks=(Block(addr=0x1000, ops=operations, summary=summary),), cfg=CFGResult(ok=True), summary=summary,
            xlen=64, runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={"a0": 0, "a1": 1, "a2": 2},
                operand_width_bits={0: 64, 1: 64, 2: 64}, provenance="boolean-compare-test"))
        plan = next(item for item in generate_candidate_plans(model)
                    if item.metadata.get("renderer_semantic_contract_id") == contract_id)
        derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
        assert derived.success and derived.constraints is not None and derived.constraints.preserve_cc_clobber
        proof = run_semantic_proof_gate(source_model=model, preservation_decision=model.preservation,
            candidate_plan=plan, constraints=derived.constraints, target_environment=environment,
            target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({contract_id}), "compare-test-v1"),
            compiler_capabilities=CompilerCapabilityModel(True, False))
        assert proof.approved and proof.evidence is not None
        approved = ApprovedTargetLoweringPlan(plan, derived.constraints, proof, proof.evidence.source_model_id,
            proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
            "phase6e.semantic-fidelity", "1", SelectionTier.X86_INLINE_ASM)
        recipe = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
        assert recipe is not None and expected in recipe.payload.template and "movzbq %b0, %0" in recipe.payload.template
        rendered = render_approved_target_lowering(Phase6FRenderRequest(
            approved, environment,
            RendererContext({plan.plan_id: recipe}, {0: "out", 1: "left", 2: "right"}),
        ))
        assert rendered.kind is RenderedReplacementKind.GNU_INLINE_ASM
        assert '"cc"' in rendered.emitted_text
        assert f"{expected} %b0" in rendered.emitted_text
        compiler = shutil.which("cc")
        if compiler is not None:
            source = (
                "#include <stdint.h>\n"
                "uint64_t f(int64_t left, int64_t right) { uint64_t out; "
                + rendered.emitted_text + " return out; }\n"
            )
            with tempfile.TemporaryDirectory(prefix="riscv2x86-boolean-compare-") as directory:
                path = Path(directory) / "comparison.c"
                path.write_text(source, encoding="utf-8")
                completed = subprocess.run(
                    [compiler, "-c", "-std=gnu11", str(path), "-o", str(path.with_suffix(".o"))],
                    capture_output=True, text=True, check=False,
                )
            assert completed.returncode == 0, completed.stderr
