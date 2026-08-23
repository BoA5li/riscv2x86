from dataclasses import replace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import (
    TargetConstraintReasonCode,
    TargetEnvironment,
    derive_target_constraints,
)
from riscv2x86_py.plan_types import (
    PlanPriorityTier,
    TargetLoweringFamily,
    TargetLoweringKind,
)
from riscv2x86_py.privileged_state_analysis import PrivilegedSemanticClass
from tests.test_phase6_privileged_runtime_contract import (
    _environment,
    _registry,
    _source_model,
)


def _with_classes(*classes, whole_function=False):
    source = _source_model()
    privileged = replace(
        source.privileged_state,
        semantic_classes=tuple(sorted(classes, key=lambda item: item.value)),
        requires_whole_function_lowering=whole_function,
        strict_translation_eligible=not whole_function,
    )
    return replace(source, privileged_state=privileged)


def _only_plan(source):
    plans = generate_candidate_plans(source)
    assert len(plans) == 1
    assert all(plan.kind is not TargetLoweringKind.HELPER_CALL for plan in plans)
    return plans[0]


def test_privileged_semantic_classes_have_distinct_plan_kinds_and_families():
    cases = (
        (
            (PrivilegedSemanticClass.COUNTER_OBSERVATION,),
            TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER,
            TargetLoweringFamily.COUNTER_OBSERVATION,
            PlanPriorityTier.COUNTER_OBSERVATION,
        ),
        (
            (PrivilegedSemanticClass.TRAP_SERVICE,),
            TargetLoweringKind.SYSCALL_OR_SERVICE_ABI_ADAPTER,
            TargetLoweringFamily.PRIVILEGED_SERVICE_ABI,
            PlanPriorityTier.PRIVILEGED_SERVICE_ABI,
        ),
        (
            (PrivilegedSemanticClass.INTERRUPT_EVENT,),
            TargetLoweringKind.PRIVILEGED_EVENT_ADAPTER,
            TargetLoweringFamily.PRIVILEGED_EVENT,
            PlanPriorityTier.PRIVILEGED_EVENT,
        ),
        (
            (PrivilegedSemanticClass.ADDRESS_TRANSLATION_STATE,),
            TargetLoweringKind.MMU_RUNTIME_ADAPTER,
            TargetLoweringFamily.PRIVILEGED_MMU,
            PlanPriorityTier.PRIVILEGED_MMU,
        ),
        (
            (PrivilegedSemanticClass.TLB_MAINTENANCE,),
            TargetLoweringKind.MMU_RUNTIME_ADAPTER,
            TargetLoweringFamily.PRIVILEGED_MMU,
            PlanPriorityTier.PRIVILEGED_MMU,
        ),
        (
            (PrivilegedSemanticClass.PRIVILEGED_CSR_STATE,),
            TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER,
            TargetLoweringFamily.PRIVILEGED_RUNTIME,
            PlanPriorityTier.PRIVILEGED_RUNTIME,
        ),
    )
    for classes, kind, family, priority in cases:
        plan = _only_plan(_with_classes(*classes))
        assert (plan.kind, plan.family, plan.priority_tier) == (
            kind, family, priority
        )
        assert plan.metadata["exact_registry_lookup_required"] is True
        assert (
            plan.metadata[
                "source_symbol_or_service_number_inference_forbidden"
            ]
            is True
        )
        assert plan.metadata["direct_host_privileged_instruction_forbidden"] is True


def test_compound_privileged_effects_use_generic_exact_runtime():
    plan = _only_plan(_with_classes(
        PrivilegedSemanticClass.TRAP_SERVICE,
        PrivilegedSemanticClass.INTERRUPT_EVENT,
    ))
    assert plan.kind is TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER
    assert plan.metadata["strategy"] == "exact_compound_privileged_runtime"


def test_privilege_return_is_a_state_machine_needs_route_plan():
    plan = _only_plan(_with_classes(
        PrivilegedSemanticClass.PRIVILEGE_RETURN,
        whole_function=True,
    ))
    assert plan.kind is TargetLoweringKind.PRIVILEGED_STATE_MACHINE
    assert plan.family is TargetLoweringFamily.PRIVILEGED_STATE_MACHINE
    assert plan.metadata["local_fragment_replacement_forbidden"] is True


def test_phase6c_rejects_plan_class_spoofing_before_registry_lookup():
    source = _with_classes(PrivilegedSemanticClass.COUNTER_OBSERVATION)
    counter_plan = _only_plan(source)
    spoofed = replace(
        counter_plan,
        kind=TargetLoweringKind.SYSCALL_OR_SERVICE_ABI_ADAPTER,
        family=TargetLoweringFamily.PRIVILEGED_SERVICE_ABI,
        priority_tier=PlanPriorityTier.PRIVILEGED_SERVICE_ABI,
    )
    result = derive_target_constraints(
        source_model=source,
        candidate_plan=spoofed,
        target_environment=TargetEnvironment.fixed_sysv_amd64_gnu_att(),
    )
    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_PLAN_CLASS_MISMATCH,
    )


def test_mmu_plan_still_requires_exact_registered_contract():
    source = _with_classes(
        PrivilegedSemanticClass.ADDRESS_TRANSLATION_STATE
    )
    plan = _only_plan(source)
    result = derive_target_constraints(
        source_model=source,
        candidate_plan=plan,
        target_environment=TargetEnvironment.fixed_sysv_amd64_gnu_att(),
    )
    assert not result.success
    assert result.reason_codes == (
        TargetConstraintReasonCode.PRIVILEGED_RUNTIME_REGISTRY_MISSING,
    )
