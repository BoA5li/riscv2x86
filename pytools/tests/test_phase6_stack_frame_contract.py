"""Regression guards for Phase-6A stack/frame routing.

These tests deliberately exercise only structured facts.  No test obtains a
classification by matching an assembly mnemonic or target-register spelling.
"""
from types import SimpleNamespace

from riscv2x86_py.candidate_plans import Phase6BCandidateFacts, generate_candidate_plans
from riscv2x86_py.source_model import SourceStackFrameKind, SourceStackFrameModel


def _facts(**updates):
    values = dict(
        model_is_consistent=True, has_global_fail_closed_state=False,
        has_opaque_semantics=False, has_unmodelled_semantics=False,
        operand_bindings_are_authoritative=True,
        operand_widths_are_authoritative=True, target_is_x86=True,
        microarch_classification_is_known=True,
        has_microarch_sensitive_semantics=False,
        has_stack_sensitive_semantics=False,
        has_frame_sensitive_semantics=False,
        has_required_helper_semantics=False,
        helper_runtime_contract_id=None,
        has_control_flow_semantics=False, has_asm_goto_semantics=False,
        has_call_semantics=False, has_return_semantics=False,
        has_branch_semantics=False, has_proven_local_branch_select=False,
        has_proven_local_unconditional_jump=False,
        asm_goto_condition_kind=None, asm_goto_condition_operand_index=None,
        has_atomic_semantics=False, has_barrier_semantics=False,
        has_non_atomic_memory_semantics=False,
        shell_semantics_are_known=True, is_shell_neutral=True,
        c_semantics_are_defined=False, c_expression_eligible=False,
        c_structured_eligible=False,
    )
    values.update(updates)
    return Phase6BCandidateFacts(**values)


def test_private_balanced_frame_requires_closed_logical_frame() -> None:
    frame = SourceStackFrameModel(
        SourceStackFrameKind.PRIVATE_BALANCED,
        frame_size_bytes=32,
        required_alignment_bytes=16,
        net_stack_delta_bytes=0,
        complete=True,
    )
    assert frame.is_local_virtual_frame_candidate
    assert not frame.requires_whole_function_lowering


def test_call_frame_is_not_offered_to_fragment_local_helper() -> None:
    facts = _facts(
        has_stack_sensitive_semantics=True,
        requires_whole_function_abi_lowering=True,
    )
    plans = generate_candidate_plans(SimpleNamespace(phase6b_candidate_facts=facts))
    assert len(plans) == 1
    assert plans[0].kind.value == "unsupported"
    assert plans[0].reason_codes == ("whole-function-abi-lowering-required",)


def test_private_frame_route_forbids_host_stack_pointer_mutation() -> None:
    facts = _facts(
        has_stack_sensitive_semantics=True,
        has_private_balanced_stack_frame=True,
    )
    plans = generate_candidate_plans(SimpleNamespace(phase6b_candidate_facts=facts))
    assert len(plans) == 1
    assert plans[0].metadata["strategy"] == "virtual_private_stack_frame"
    assert plans[0].metadata["host_stack_pointer_mutation_forbidden"] is True
