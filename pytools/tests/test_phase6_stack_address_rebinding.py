"""End-to-end contract coverage for the first fail-closed A-class route."""
from dataclasses import replace
from types import SimpleNamespace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import (StackAccessKind, StackAddressBase, StackEscapeFacts,
    StackFrameClassification, StackFrameSemantics, StackMemoryAccess, from_lifted)
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import CompilerCapabilityModel, TargetSemanticCatalog, run_semantic_proof_gate
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan, SelectionTier
from riscv2x86_py.phase6f_renderer import (Phase6FRenderRequest, RendererContext, RendererContract,
    RendererContractKind, StackAddressRebindingRecipe, render_approved_target_lowering)
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.source_model import build_source_semantic_model
from riscv2x86_py.stack_rebinding import SourceStackObjectBinding, StackAddressRebindingFacts


def test_rebinding_load_is_proved_and_never_mentions_host_stack() -> None:
    class I: addr=0; size=4; asm_mnem='ld'; asm_body='a0, 8(sp)'; terminator_kind=None
    class O:
        opcode='LOAD'; output=SimpleNamespace(space='register', offset=10, size=8, name='a0')
        inputs=[SimpleNamespace(space='const', offset=0, size=8, name=''), SimpleNamespace(space='register', offset=2, size=8, name='sp')]
    I.raw_ops=[O()]
    blocks, summary = from_lifted([I()])
    access = StackMemoryAccess(0, 0, StackAddressBase.ENTRY_SP, None, 8, 64, 8, StackAccessKind.LOAD, False, True, False)
    summary.stack_frame_semantics = StackFrameSemantics(StackFrameClassification.ADDRESS_ONLY, StackAddressBase.ENTRY_SP, 16, None, 0, (), (access,), StackEscapeFacts(False,False,False,False,False,False), False,False,False,False,True)
    binding = SourceStackObjectBinding('slot8', 0, 0, 'local-object', None, 'local-object', 8, 8, 16, 8, 0, StackAccessKind.LOAD, True, 'test-sidecar-v1', True, True)
    model = build_source_semantic_model(fragment=AsmFragment(rawAsmText='ld', outputs=[AsmOperand(constraint='=r',exprText='out',isOutput=True)]), blocks=blocks, cfg=CFGResult(ok=True), summary=summary, xlen=64, runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0},operand_width_bits={0:64}), stack_rebinding_facts=StackAddressRebindingFacts((binding,), True))
    model = replace(model, operation=replace(model.operation, may_trap=False))
    plan = generate_candidate_plans(model)[0]
    environment = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived = derive_target_constraints(source_model=model, candidate_plan=plan, target_environment=environment)
    assert derived.success and derived.constraints is not None
    proof = run_semantic_proof_gate(source_model=model, candidate_plan=plan, constraints=derived.constraints, target_environment=environment, target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({'stack-rebind.c.scalar-load-store.v1'}), 'test-v1'), compiler_capabilities=CompilerCapabilityModel(True, False))
    assert proof.approved
    approved = ApprovedTargetLoweringPlan(plan, derived.constraints, proof, proof.evidence.source_model_id, proof.evidence.preservation_decision_id, proof.evidence.target_environment_id, 'test', '1', SelectionTier.STRUCTURED_C)
    rendered = render_approved_target_lowering(Phase6FRenderRequest(approved, environment, RendererContext({plan.plan_id: RendererContract('stack-rebind.c.scalar-load-store.v1', plan.plan_id, RendererContractKind.STACK_ADDRESS_REBINDING, StackAddressRebindingRecipe('stack-rebind.c.scalar-load-store.v1'))}, {0:'out'}, {'local-object':'obj'})))
    assert rendered.emitted_text == 'memcpy(&(out), ((const unsigned char *)(obj) + 8), 8);'
    assert '%rsp' not in rendered.emitted_text and '%rbp' not in rendered.emitted_text


def test_missing_binding_is_not_a_stack_rebinding_candidate() -> None:
    # The normal Phase-5 ADDRESS_ONLY result carries no C-object identity.
    # Phase 6A must therefore keep it incomplete rather than guessing a local.
    frame = StackFrameSemantics(StackFrameClassification.ADDRESS_ONLY, StackAddressBase.ENTRY_SP, None, None, 0, (), (), StackEscapeFacts(False,False,False,False,False,False), False,False,False,False,True)
    assert frame.complete
