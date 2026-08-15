from riscv2x86_py.phase6c_constraints import (
    FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT, TargetConstraintDerivationResult,
    TargetConstraintReasonCode, TargetConstraintModel, TargetOperandClass,
    TargetOperandConstraint, TargetOperandRole, _validate_result_invariants,
)
from riscv2x86_py.plan_types import PlanPriorityTier, TargetLoweringFamily, TargetLoweringKind, TargetLoweringPlan
from riscv2x86_py.target_register_policy import (
    POLICY_VERSION, audit_translator_emitted_target_registers,
    canonical_target_register_name, is_forbidden_host_stack_frame_register,
)


def test_host_stack_frame_aliases_are_canonicalized_and_denied():
    assert canonical_target_register_name("ESP") == "rsp"
    assert canonical_target_register_name("{bpl}") == "rbp"
    assert all(is_forbidden_host_stack_frame_register(x) for x in ("rsp", "esp", "sp", "spl", "rbp", "ebp", "bp", "bpl"))
    assert not is_forbidden_host_stack_frame_register("r12")


def test_phase6c_rejects_fixed_host_stack_frame_operand():
    plan = TargetLoweringPlan(
        "test.fixed-stack", TargetLoweringKind.X86_GNU_INLINE_ASM,
        TargetLoweringFamily.X86_INLINE_ASM, PlanPriorityTier.X86_INLINE_ASM, 1,
    )
    constraints = TargetConstraintModel(
        plan.plan_id, FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT,
        (TargetOperandConstraint(0, TargetOperandRole.INPUT, frozenset({TargetOperandClass.GENERAL_REGISTER}), requires_fixed_register=True, fixed_register_name="rsp"),),
    )
    result = _validate_result_invariants(
        candidate_plan=plan,
        result=TargetConstraintDerivationResult.succeeded(constraints),
    )
    assert not result.success
    assert result.reason_codes == (TargetConstraintReasonCode.HOST_STACK_FRAME_FIXED_REGISTER_FORBIDDEN,)
    assert result.details["target_register_policy_version"] == POLICY_VERSION


def test_emitted_text_audit_catches_template_constraint_clobber_and_builtin():
    assert audit_translator_emitted_target_registers('__asm__ volatile ("mov %%rsp, %%rax");')
    assert audit_translator_emitted_target_registers('__asm__ volatile ("" : : "{rbp}"(x));')
    assert audit_translator_emitted_target_registers('__asm__ volatile ("" : : : "rsp");')
    assert audit_translator_emitted_target_registers('return __builtin_frame_address(0);')
    assert not audit_translator_emitted_target_registers('__asm__ volatile ("mov %%rax, %%rbx" : : "r"(x));')
