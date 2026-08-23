from dataclasses import replace

from riscv2x86_py.function_privileged_analysis import (
    FunctionPrivilegeExitMode,
    FunctionPrivilegedBlockTransfer,
    FunctionPrivilegedExecutionFacts,
    FunctionPrivilegedMachineState,
    FunctionPrivilegedTransferKind,
    analyze_function_privileged_state,
)
from riscv2x86_py.privileged_execution_sidecar import SourcePrivilegeMode
from riscv2x86_py.whole_function import (
    FunctionCfgEdge,
    FunctionCfgNode,
    FunctionExitBinding,
    FunctionExitKind,
    SourceFunctionControlFlowModel,
)


def _cfg(exceptional=False):
    exit_kind = FunctionExitKind.EXCEPTIONAL if exceptional else FunctionExitKind.NORMAL_RETURN
    return SourceFunctionControlFlowModel(
        "entry",
        (FunctionCfgNode("entry", "c", None, True),
         FunctionCfgNode("return", "asm", "fragment:mret", True)),
        (FunctionCfgEdge("entry", "return", "fallthrough", True),),
        (FunctionExitBinding("exit", "return", exit_kind, True),),
        True,
    )


def _state():
    return FunctionPrivilegedMachineState(
        SourcePrivilegeMode.M, "interrupt-enabled", "delegation-v1",
        "address-space-1", "saved-epc-1", "saved-status-1",
    )


def _facts(exceptional=False, **changes):
    mode = FunctionPrivilegeExitMode("exit", SourcePrivilegeMode.M, True)
    values = dict(
        function_id="fn:privileged-return",
        entry_privilege_mode=SourcePrivilegeMode.M,
        normal_exit_privilege_modes=() if exceptional else (mode,),
        exceptional_exit_modes=(mode,) if exceptional else (),
        trap_handler_bindings=(), interruptibility_regions=(),
        address_space_identity="address-space-1",
        member_fragment_ids=("fragment:mret",), complete=True,
        provenance="clang-plugin:test", missing_fact_codes=(),
        has_nonlocal_transfer=False, has_unwind=False,
        has_signal_sensitive_state=False, has_setjmp_longjmp=False,
    )
    values.update(changes)
    return FunctionPrivilegedExecutionFacts(**values)


def _transfers(kind="mret", continuation="saved-epc-1"):
    state = _state()
    return (
        FunctionPrivilegedBlockTransfer(
            "entry", FunctionPrivilegedTransferKind.IDENTITY, state,
            complete=True,
        ),
        FunctionPrivilegedBlockTransfer(
            "return", FunctionPrivilegedTransferKind.PRIVILEGE_RETURN, state,
            continuation_identity=continuation,
            privilege_return_kind=kind,
            complete=True,
        ),
    )


def _analyze(facts=None, cfg=None, transfers=None):
    return analyze_function_privileged_state(
        cfg=_cfg() if cfg is None else cfg,
        facts=_facts() if facts is None else facts,
        transfers=_transfers() if transfers is None else transfers,
        initial_interrupt_state="interrupt-enabled",
        initial_delegation_state="delegation-v1",
        initial_trap_continuation_state="saved-epc-1",
        initial_saved_status_state="saved-status-1",
    )


def test_mret_function_dataflow_tracks_all_restored_state():
    result = _analyze()
    assert result.complete
    assert result.privilege_returns_present
    assert result.all_return_continuations_complete
    assert result.all_normal_exits_restore_privilege
    assert result.all_normal_exits_restore_interrupt_state
    assert result.address_space_identity_preserved
    assert result.analysis_identity.startswith("sha256:")


def test_sret_and_dret_are_typed_privilege_returns():
    for kind in ("sret", "dret"):
        assert _analyze(transfers=_transfers(kind=kind)).complete


def test_privilege_return_without_continuation_fails_closed():
    result = _analyze(transfers=_transfers(continuation=None))
    assert not result.complete
    assert "whole-function.privileged-return-continuation-unproven" in result.missing_fact_codes


def test_unknown_privilege_return_kind_fails_closed():
    result = _analyze(transfers=_transfers(kind="ret"))
    assert not result.complete
    assert "whole-function.privileged-return-continuation-unproven" in result.missing_fact_codes


def test_exceptional_exit_and_nonlocal_state_require_dedicated_route():
    facts = _facts(
        exceptional=True, has_nonlocal_transfer=True, has_unwind=True,
    )
    result = _analyze(facts=facts, cfg=_cfg(exceptional=True))
    assert not result.complete
    assert "whole-function.privileged-nonlocal-route-required" in result.missing_fact_codes


def test_setjmp_signal_unknowns_are_never_assumed_absent():
    facts = _facts(has_setjmp_longjmp=None, has_signal_sensitive_state=None)
    result = _analyze(facts=facts)
    assert not result.complete
    assert "whole-function.privileged-nonlocal-effects-unknown" in result.missing_fact_codes


def test_address_space_change_at_normal_exit_is_rejected():
    changed = replace(_state(), address_space_state="address-space-2")
    transfers = (
        _transfers()[0],
        replace(_transfers()[1], output_state=changed),
    )
    result = _analyze(transfers=transfers)
    assert not result.complete
    assert "whole-function.address-space-identity-unproven" in result.missing_fact_codes
