"""Fail-closed matrix for privileged translation under both policies.

The matrix deliberately exercises stable Phase-6 eligibility, registry and
Phase-7 audit boundaries.  Enabling functional fallbacks is never treated as
authority for missing source, execution, mapping, shell, or runtime facts.
"""
from dataclasses import replace

import pytest

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import (
    TargetConstraintReasonCode,
    derive_target_constraints,
)
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel,
    SemanticProofReasonCode,
    TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from riscv2x86_py.privileged_emitted_audit import audit_privileged_emitted_text
from riscv2x86_py.privileged_functional_contracts import (
    PrivilegedFunctionalFallbackRegistry,
)
from riscv2x86_py.privileged_state_analysis import PrivilegedSemanticClass
from riscv2x86_py.plan_types import TargetLoweringKind
from tests.test_phase6_privileged_functional_fallback import (
    _environment as fallback_environment,
    _fallback_plan,
    _policy,
    _registry as fallback_registry,
)
from tests.test_phase6_privileged_runtime_contract import (
    _environment as strict_environment,
    _mapping_registries,
    _registry as strict_registry,
    _source_model,
)
from tests.test_function_privileged_analysis import (
    _analyze as analyze_function_state,
    _cfg as function_cfg,
    _facts as function_facts,
)


POLICIES = pytest.mark.parametrize("allow_fallback", (False, True))


@pytest.mark.parametrize(
    ("case_id", "semantic_class", "reason"),
    (
        ("mstatus", PrivilegedSemanticClass.PRIVILEGED_CSR_STATE,
         "privileged-state.csr-access-policy-incomplete"),
        ("sstatus", PrivilegedSemanticClass.PRIVILEGED_CSR_STATE,
         "privileged-state.csr-access-policy-incomplete"),
        ("medeleg", PrivilegedSemanticClass.PRIVILEGED_CSR_STATE,
         "privileged-execution.delegation-model-missing"),
        ("satp", PrivilegedSemanticClass.ADDRESS_TRANSLATION_STATE,
         "privileged-execution.address-space-identity-missing"),
        ("hgatp", PrivilegedSemanticClass.VIRTUALIZATION_STATE,
         "privileged-execution.virtual-memory-model-missing"),
        ("sfence.vma", PrivilegedSemanticClass.TLB_MAINTENANCE,
         "privileged-state.mmu-scope-incomplete"),
        ("hfence.gvma", PrivilegedSemanticClass.TLB_MAINTENANCE,
         "privileged-state.mmu-scope-incomplete"),
        ("mret", PrivilegedSemanticClass.PRIVILEGE_RETURN,
         "privileged-state.return-effect-incomplete"),
        ("sret", PrivilegedSemanticClass.PRIVILEGE_RETURN,
         "privileged-state.return-effect-incomplete"),
        ("dret", PrivilegedSemanticClass.PRIVILEGE_RETURN,
         "privileged-state.return-effect-incomplete"),
        ("wfi", PrivilegedSemanticClass.INTERRUPT_EVENT,
         "privileged-state.interrupt-effect-incomplete"),
        ("pmpcfg0", PrivilegedSemanticClass.PMP_STATE,
         "privileged-state.csr-field-effect-incomplete"),
        ("dcsr", PrivilegedSemanticClass.DEBUG_STATE,
         "privileged-state.debug-effect-incomplete"),
        ("hstatus", PrivilegedSemanticClass.VIRTUALIZATION_STATE,
         "privileged-state.virtualization-effect-incomplete"),
        ("ecall-unbound", PrivilegedSemanticClass.TRAP_SERVICE,
         "privileged-state.trap-binding-incomplete"),
        ("ebreak-unbound", PrivilegedSemanticClass.TRAP_SERVICE,
         "privileged-state.trap-binding-incomplete"),
        ("access-denied", PrivilegedSemanticClass.PRIVILEGED_CSR_STATE,
         "privileged-state.csr-access-trap-unmodelled"),
        ("missing-trap-handler", PrivilegedSemanticClass.TRAP_SERVICE,
         "privileged-execution.trap-handler-missing"),
    ),
)
@POLICIES
def test_incomplete_privileged_semantics_never_gain_a_route(
    case_id, semantic_class, reason, allow_fallback
):
    source = _source_model(allow_fallback)
    denied = replace(
        source.privileged_state,
        semantic_classes=(semantic_class,),
        complete=False,
        strict_translation_eligible=False,
        functional_fallback_eligible=False,
        requires_whole_function_lowering=(
            semantic_class is PrivilegedSemanticClass.PRIVILEGE_RETURN
        ),
        reason_codes=(reason,),
    )
    source = replace(source, privileged_state=denied)

    plans = generate_candidate_plans(
        source, privileged_functional_policy=_policy(allow_fallback)
    )
    if semantic_class is PrivilegedSemanticClass.PRIVILEGE_RETURN:
        assert tuple(plan.kind for plan in plans) == (
            TargetLoweringKind.PRIVILEGED_STATE_MACHINE,
        ), case_id
        assert plans[0].metadata["local_fragment_replacement_forbidden"] is True
    else:
        assert plans == (), case_id
    assert source.privileged_state.reason_codes == (reason,)


@pytest.mark.parametrize(
    "mutation",
    (
        "version-mismatch", "target-mode-mismatch",
        "shell-mismatch", "runtime-memory-mismatch",
    ),
)
@POLICIES
def test_strict_contract_mismatch_fails_before_rendering(
    mutation, allow_fallback
):
    source = _source_model(allow_fallback)
    environment = strict_environment()
    contract, _ = strict_registry(source, environment)
    if mutation == "version-mismatch":
        broken = contract
        source = replace(
            source,
            privileged_state=replace(
                source.privileged_state,
                state=replace(
                    source.privileged_state.state,
                    target_runtime_contract_set_id="stale-runtime-set",
                ),
            ),
        )
    elif mutation == "target-mode-mismatch":
        broken = replace(
            contract,
            target_execution_mode="x86_kernel",
            supported_target_modes=("x86_kernel",),
        )
    elif mutation == "shell-mismatch":
        broken = replace(contract, preserves_volatile_execution=False)
    else:
        broken = replace(contract, preserves_memory_effects=False)
    registry = type(strict_registry(source, environment)[1])(
        version="negative-matrix.strict.v1",
        contracts=(broken,),
        mapping_registries=_mapping_registries(broken),
    )
    result = derive_target_constraints(
        source_model=source,
        candidate_plan=generate_candidate_plans(source)[0],
        target_environment=environment,
        privileged_runtime_registry=registry,
    )
    if mutation == "runtime-memory-mismatch":
        assert result.success and result.constraints is not None
        proof = run_semantic_proof_gate(
            source_model=source,
            candidate_plan=generate_candidate_plans(source)[0],
            constraints=result.constraints,
            target_environment=environment,
            target_semantic_catalog=TargetSemanticCatalog(
                frozenset({generate_candidate_plans(source)[0].kind}),
                frozenset({broken.semantic_contract_id}),
                "negative-matrix.v1",
            ),
            compiler_capabilities=CompilerCapabilityModel(True, False),
            privileged_runtime_registry=registry,
        )
        assert not proof.approved
        assert proof.reason_codes == (SemanticProofReasonCode.ABI_UNPRESERVED,)
    else:
        assert not result.success
        assert result.reason_codes in (
            (TargetConstraintReasonCode.PRIVILEGED_RUNTIME_CONTRACT_MISSING,),
            (TargetConstraintReasonCode.PRIVILEGED_RUNTIME_VERSION_MISMATCH,),
            (TargetConstraintReasonCode.PRIVILEGED_SHELL_UNSUPPORTED,),
        )


@POLICIES
def test_ignored_state_escape_or_missing_authority_never_uses_fallback(
    allow_fallback,
):
    source = _source_model(True)
    privileged = replace(
        source.privileged_state,
        functional_fallback_eligible=False,
        reason_codes=("phase6d.privileged.ignored-state-escape",),
    )
    source = replace(source, privileged_state=privileged)
    plans = generate_candidate_plans(
        source, privileged_functional_policy=_policy(allow_fallback)
    )
    assert all(plan.kind.value != "privileged_functional_fallback" for plan in plans)


@POLICIES
def test_fallback_registry_mismatch_still_fails_closed(allow_fallback):
    source = _source_model(True)
    environment = fallback_environment()
    contract, _ = fallback_registry(source, environment)
    broken = replace(contract, target_execution_mode="x86_kernel")
    registry = PrivilegedFunctionalFallbackRegistry(
        version="negative-matrix.functional.v1", contracts=(broken,)
    )
    result = derive_target_constraints(
        source_model=source,
        candidate_plan=_fallback_plan(source, _policy(True)),
        target_environment=environment,
        privileged_functional_policy=_policy(allow_fallback),
        privileged_functional_registry=registry,
    )
    assert not result.success
    assert result.reason_codes in (
        (TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_POLICY_DISABLED,),
        (TargetConstraintReasonCode.PRIVILEGED_FUNCTIONAL_CONTRACT_MISSING,),
        (TargetConstraintReasonCode.PRIVILEGED_RUNTIME_PROFILE_MISMATCH,),
    )


@pytest.mark.parametrize(
    ("emitted", "reason"),
    (
        ("rv2x86_registered_adapter(%rsp);",
         "privileged-renderer.host-stack-frame-register-forbidden"),
        ("rv2x86_registered_adapter(__builtin_frame_address(0));",
         "privileged-renderer.host-stack-frame-register-forbidden"),
        ("rv2x86_registered_adapter(%cr3);",
         "privileged-renderer.host-control-register-forbidden"),
        ("rv2x86_registered_adapter(); /* hfence.gvma */",
         "privileged-renderer.source-privileged-instruction-residue"),
        ("rv2x86_registered_adapter(); /* dret */",
         "privileged-renderer.source-privileged-instruction-residue"),
    ),
)
@POLICIES
def test_emission_denylist_is_policy_independent(
    emitted, reason, allow_fallback
):
    del allow_fallback
    reasons = audit_privileged_emitted_text(
        emitted, expected_callable_identifier="rv2x86_registered_adapter"
    )
    assert reason in reasons


@pytest.mark.parametrize(
    "nonlocal_case",
    ("unwind", "setjmp-longjmp", "signal"),
)
@POLICIES
def test_whole_function_nonlocal_effects_remain_needs_route(
    nonlocal_case, allow_fallback
):
    del allow_fallback
    changes = {
        "has_unwind": nonlocal_case == "unwind",
        "has_setjmp_longjmp": nonlocal_case == "setjmp-longjmp",
        "has_signal_sensitive_state": nonlocal_case == "signal",
        "has_nonlocal_transfer": True,
    }
    facts = function_facts(exceptional=True, **changes)
    result = analyze_function_state(
        facts=facts, cfg=function_cfg(exceptional=True)
    )
    assert not result.complete
    assert "whole-function.privileged-nonlocal-route-required" in (
        result.missing_fact_codes
    )
