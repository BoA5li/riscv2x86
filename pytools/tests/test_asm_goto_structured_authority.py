from dataclasses import replace
from types import SimpleNamespace

from riscv2x86_py.assemble import _asm_goto_condition_fact
from riscv2x86_py.candidate_plans import Phase6BCandidateFacts, generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import Block, CanonicalInsn, IRSummary, Op, Var, VarKind
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel, SemanticProofReasonCode, TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan, SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import (
    Phase6FRenderRequest, RendererContext, RenderedReplacementKind,
    render_approved_target_lowering,
)
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment, AsmGotoEdge, AsmOperand
from riscv2x86_py.shell_model import SourceShellModel
from riscv2x86_py.source_model import (
    SourceOperandAccess, SourceOperandBinding, SourceOperandKind,
    SourceOperandModel, SourceSignedness,
    _build_asm_goto_control_flow_authority, _runtime_fact_status,
    build_source_semantic_model,
)


def _fragment(raw="this text is deliberately not interpreted"):
    fragment_id = "fragment:goto"
    fallthrough = f"asm-goto:{fragment_id}:fallthrough"
    taken = f"asm-goto:{fragment_id}:label:taken"
    return AsmFragment(
        id=fragment_id, rawAsmText=raw, kind="InlineGoto", isVolatile=True,
        inputs=[AsmOperand(constraint="r", symbolicName="value")],
        clobbers=["memory"], gotoLabels=["taken"], hasAsmGoto=True,
        gotoEdges=[AsmGotoEdge("%l0", "taken", 0, taken)],
        asmGotoFallthroughContinuationId=fallthrough,
        asmGotoSuccessorContinuationIds=[fallthrough, taken],
        asmGotoControlFlowComplete=True,
    )


def _authority(raw="not assembly"):
    register = Var(VarKind.REG, "register", 10, 8, "a0")
    zero = Var(VarKind.CONST, "const", 0, 8)
    predicate = Var(VarKind.UNIQUE, "unique", 1, 1)
    target = Var(VarKind.CONST, "const", 0x100, 8)
    compare = Op(0, "INT_EQUAL", predicate, [register, zero])
    branch = Op(0, "CBRANCH", None, [target, predicate])
    instruction = CanonicalInsn(
        addr=0, size=4, ops=[compare, branch], terminator_kind="CBRANCH",
        direct_target=0x100, has_branch_op=True,
    )
    block = Block(0, ops=[compare, branch], instructions=[instruction],
                  terminator_kind="cbranch", has_branch=True)
    facts = TranslationRuntimeFacts(
        rv_to_operand_index={"a0": 0}, operand_width_bits={0: 64},
        provenance="test",
    )
    operand = SourceOperandBinding(
        0, SourceOperandKind.REGISTER, SourceOperandAccess.INPUT, 64,
        SourceSignedness.SIGNLESS, True, False, False, None, False, None,
        None, None, None,
    )
    fragment = _fragment(raw)
    return _build_asm_goto_control_flow_authority(
        fragment=fragment, shell=SourceShellModel.from_fragment(fragment),
        blocks=[block], cfg=CFGResult(ok=True),
        runtime_status=_runtime_fact_status(facts),
        operands=SourceOperandModel((operand,), True),
        memory=SimpleNamespace(reads_memory=False, writes_memory=False),
    )


def _candidate_facts(**updates):
    values = dict(
        model_is_consistent=True, has_global_fail_closed_state=False,
        has_opaque_semantics=False, has_unmodelled_semantics=False,
        operand_bindings_are_authoritative=True,
        operand_widths_are_authoritative=True, target_is_x86=True,
        microarch_classification_is_known=True,
        has_microarch_sensitive_semantics=False,
        has_stack_sensitive_semantics=False, has_frame_sensitive_semantics=False,
        has_required_helper_semantics=False, helper_runtime_contract_id=None,
        has_control_flow_semantics=True, has_asm_goto_semantics=True,
        has_call_semantics=False, has_return_semantics=False,
        has_branch_semantics=True, has_proven_local_branch_select=False,
        has_proven_local_unconditional_jump=False,
        asm_goto_condition_kind="zero", asm_goto_condition_operand_index=0,
        has_atomic_semantics=False, has_barrier_semantics=False,
        has_non_atomic_memory_semantics=False,
        shell_semantics_are_known=True, is_shell_neutral=False,
        c_semantics_are_defined=False, c_expression_eligible=False,
        c_structured_eligible=False, asm_goto_authority_complete=True,
    )
    values.update(updates)
    return Phase6BCandidateFacts(**values)


def _model(raw="not interpreted", comparison_opcode="INT_EQUAL"):
    register = Var(VarKind.REG, "register", 10, 8, "a0")
    zero = Var(VarKind.CONST, "const", 0, 8)
    predicate = Var(VarKind.UNIQUE, "unique", 1, 1)
    target = Var(VarKind.CONST, "const", 0x100, 8)
    ops = [Op(0, comparison_opcode, predicate, [register, zero]),
           Op(0, "CBRANCH", None, [target, predicate])]
    instruction = CanonicalInsn(
        addr=0, size=4, ops=ops, terminator_kind="CBRANCH",
        direct_target=0x100, has_branch_op=True)
    summary = IRSummary(
        is_single_block=True, has_branch=True, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={"a0"},
        writes_regs=set(), reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False,
        has_indirect_control_flow=False, has_timing_source=False,
        has_cache_operation=False, has_speculation_control=False,
    )
    block = Block(0, ops=ops, summary=summary, instructions=[instruction],
                  terminator_kind="cbranch", has_branch=True)
    return build_source_semantic_model(
        fragment=_fragment(raw), blocks=(block,), cfg=CFGResult(ok=True),
        summary=summary, xlen=64,
        runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0}, operand_width_bits={0: 64},
            provenance="test"),
    )


def test_decoder_predicate_wins_over_raw_template_text():
    authority = _authority("bnez %0, %l0")
    assert authority is not None and authority.complete
    assert authority.condition_kind == "zero"
    assert authority.lhs_binding == "operand:0"
    assert authority.memory_effect == "compiler_barrier"
    assert authority.clobbers == ("memory",)


def test_legacy_template_condition_fields_are_not_authority():
    fragment = _fragment("beqz %0, %l0")
    fragment.asmGotoConditionKind = "zero"
    fragment.asmGotoConditionOperandIndex = 0
    assert _asm_goto_condition_fact(fragment) == (None, None)


def test_complete_asm_goto_selects_only_structured_route():
    plans = generate_candidate_plans(
        SimpleNamespace(phase6b_candidate_facts=_candidate_facts()))
    assert [item.kind.value for item in plans] == ["structured_control_flow"]
    assert all(item.plan_id != "helper.control-flow-contract" for item in plans)


def test_incomplete_authority_does_not_select_structured_or_helper_route():
    plans = generate_candidate_plans(SimpleNamespace(
        phase6b_candidate_facts=_candidate_facts(
            asm_goto_authority_complete=False,
            asm_goto_condition_kind=None,
            asm_goto_condition_operand_index=None,
        )))
    assert [item.kind.value for item in plans] == ["unsupported"]
    assert plans[0].reason_codes == ("asm-goto-control-flow-authority-incomplete",)


def test_explicit_source_helper_contract_remains_independent():
    plans = generate_candidate_plans(SimpleNamespace(
        phase6b_candidate_facts=_candidate_facts(
            has_required_helper_semantics=True,
            helper_runtime_contract_id="branch_adapter@v1",
        )))
    assert [item.kind.value for item in plans] == ["helper_call"]
    assert plans[0].plan_id == "helper.branch_adapter@v1"


def test_structured_authority_closes_phase6c_6d_and_renderer():
    model = _model("unknown source mnemonic")
    assert model.control_flow.asm_goto_authority is not None
    plans = generate_candidate_plans(model)
    assert len(plans) == 1
    plan = plans[0]
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att(
        supports_gnu_asm_goto=True)
    derived = derive_target_constraints(
        source_model=model, candidate_plan=plan,
        target_environment=environment)
    assert derived.success and derived.constraints is not None
    assert derived.constraints.memory_constraint.requires_memory_clobber
    proof = run_semantic_proof_gate(
        source_model=model, preservation_decision=model.preservation,
        candidate_plan=plan, constraints=derived.constraints,
        target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(
            frozenset({plan.kind}),
            frozenset({"x86.gnu-att.asm-goto.bzero.u32-u64.v1"}),
            "asm-goto-structured-authority-test-v1"),
        compiler_capabilities=CompilerCapabilityModel(True, True),
    )
    assert proof.approved and proof.evidence is not None
    approved = ApprovedTargetLoweringPlan(
        plan, derived.constraints, proof, proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id,
        proof.evidence.target_environment_id,
        "test", "1", SelectionTier.X86_INLINE_ASM,
    )
    renderer_contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    assert renderer_contract is not None
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved, environment, RendererContext(
            {plan.plan_id: renderer_contract}, {0: "value"})))
    assert rendered.kind is RenderedReplacementKind.GNU_ASM_GOTO
    assert "testq %0, %0" in rendered.emitted_text
    assert "je %l[taken]" in rendered.emitted_text
    assert '"cc", "memory"' in rendered.emitted_text
    assert "unknown source mnemonic" not in rendered.emitted_text


def test_nonzero_decoder_relation_selects_jne_contract():
    model = _model(comparison_opcode="INT_NOTEQUAL")
    assert model.control_flow.asm_goto_authority.condition_kind == "nonzero"
    plan = generate_candidate_plans(model)[0]
    assert plan.metadata["renderer_semantic_contract_id"] == \
        "x86.gnu-att.asm-goto.bnonzero.u32-u64.v1"


def test_phase6d_rejects_swapped_continuation_and_signedness():
    model = _model()
    plan = generate_candidate_plans(model)[0]
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att(
        supports_gnu_asm_goto=True)
    derived = derive_target_constraints(
        source_model=model, candidate_plan=plan,
        target_environment=environment)
    assert derived.success and derived.constraints is not None
    flow = derived.constraints.structured_control_flow_contract
    assert flow is not None and flow.asm_goto_authority is not None
    authority = flow.asm_goto_authority
    swapped = replace(
        authority,
        taken_successor_block=authority.fallthrough_successor_block,
        fallthrough_successor_block=authority.taken_successor_block,
    )
    bad_flow = replace(flow, asm_goto_authority=swapped)
    bad_constraints = replace(
        derived.constraints, structured_control_flow_contract=bad_flow)
    for constraints in (
        bad_constraints,
        replace(derived.constraints, operand_constraints=(replace(
            derived.constraints.operand_constraints[0],
            required_signedness=SourceSignedness.UNSIGNED),)),
    ):
        proof = run_semantic_proof_gate(
            source_model=model, preservation_decision=model.preservation,
            candidate_plan=plan, constraints=constraints,
            target_environment=environment,
            target_semantic_catalog=TargetSemanticCatalog(
                frozenset({plan.kind}),
                frozenset({"x86.gnu-att.asm-goto.bzero.u32-u64.v1"}),
                "asm-goto-negative-test-v1"),
            compiler_capabilities=CompilerCapabilityModel(True, True),
        )
        assert not proof.approved
        assert SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED in proof.reason_codes


def test_cycle_or_unbound_predicate_fails_closed():
    authority = _authority()
    assert authority is not None
    # A decoder register not present in the runtime operand map cannot become
    # a condition binding; name similarity is never used as a fallback.
    register = Var(VarKind.REG, "register", 11, 8, "a1")
    target = Var(VarKind.CONST, "const", 0x100, 8)
    branch = Op(0, "CBRANCH", None, [target, register])
    instruction = CanonicalInsn(addr=0, size=4, ops=[branch],
        terminator_kind="CBRANCH", direct_target=0x100, has_branch_op=True)
    fragment = _fragment()
    rejected = _build_asm_goto_control_flow_authority(
        fragment=fragment, shell=SourceShellModel.from_fragment(fragment),
        blocks=[Block(0, ops=[branch], instructions=[instruction],
                      terminator_kind="cbranch", has_branch=True)],
        cfg=CFGResult(ok=True),
        runtime_status=_runtime_fact_status(TranslationRuntimeFacts(
            rv_to_operand_index={"a0": 0}, operand_width_bits={0: 64},
            provenance="test")),
        operands=SourceOperandModel((SourceOperandBinding(
            0, SourceOperandKind.REGISTER, SourceOperandAccess.INPUT, 64,
            SourceSignedness.SIGNLESS, True, False, False, None, False, None,
            None, None, None),), True),
        memory=SimpleNamespace(reads_memory=False, writes_memory=False),
    )
    assert rejected is None
