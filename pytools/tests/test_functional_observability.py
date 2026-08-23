from riscv2x86_py.cfg import CFGNode, CFGResult
from riscv2x86_py.functional_observability import (
    FunctionalErrorKind,
    FunctionalFallbackPossibility,
    FunctionalObservabilityReasonCode,
    FunctionalTerminationKind,
    IgnoredPrivilegedStateKind,
    IgnoredStateDeclaration,
    analyze_functional_observability,
    functional_observability_contract_to_dict,
)
from riscv2x86_py.pcode_ir import (
    Block,
    CanonicalCsrFieldEffect,
    CanonicalCsrOperationKind,
    CanonicalInsn,
    CanonicalPrivilegedOperation,
    CanonicalPrivilegedOperationKind,
    IRSummary,
)
from riscv2x86_py.privileged_execution_sidecar import (
    AddressSpaceIdentityFacts,
    CsrAccessPolicyFacts,
    DelegationModelFacts,
    InterruptModelFacts,
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2,
    PrivilegedExecutionFacts,
    TrapHandlerBindingFacts,
    VirtualMemoryModelFacts,
    SourceExecutionProfile,
    SourcePrivilegeMode,
    TargetExecutionMode,
    UnknownCsrAccessDisposition,
)
from riscv2x86_py.privileged_state_analysis import analyze_privileged_state
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.shell_model import SourceShellModel


def _facts():
    return PrivilegedExecutionFacts(
        fragment_id="frag",
        source_execution_profile=SourceExecutionProfile.RISCV_MACHINE_FIRMWARE,
        target_execution_mode=TargetExecutionMode.EMULATOR,
        source_privilege_spec_version="1.12",
        source_isa_extensions=("i", "zicsr"),
        initial_privilege_mode=SourcePrivilegeMode.M,
        csr_access_policy=CsrAccessPolicyFacts(
            policy_id="test-policy-v1",
            readable_csr_ids=("riscv.csr.mstatus",),
            writable_csr_ids=("riscv.csr.mstatus",),
            unknown_access=UnknownCsrAccessDisposition.TRAP,
            complete=True,
        ),
        target_runtime_contract_set_id="test-runtime-v1",
        complete=True,
        missing_fact_codes=(),
        provenance="unit-test",
        delegation_model=DelegationModelFacts(
            "test-delegation-v2", True, True, (), (), True
        ),
        interrupt_model=InterruptModelFacts(
            "test-interrupt-v2", True, True, "test-priority-v1", True, True
        ),
        virtual_memory_model=VirtualMemoryModelFacts(
            "test-vm-v2", True, "test", 4096, 16, None, True
        ),
        trap_handler_binding=TrapHandlerBindingFacts(
            "test-trap-v2", "test-handler", "test-trap-abi-v1",
            "test-continuation-v1", True
        ),
        address_space=AddressSpaceIdentityFacts(
            "test-address-space", "test-process", "test-lifetime-v1",
            False, True
        ),
        os_or_runtime_identity="test-runtime",
        kernel_or_vmm_version="test-version",
        target_cpu_feature_profile_id="test-target-profile-v1",
        schema_version=PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2,
    )


def _summary(*, reads_memory=False, writes_memory=False, has_return=False):
    return IRSummary(
        is_single_block=True,
        has_branch=False,
        has_call_or_return=has_return,
        has_memory_barrier=False,
        has_atomic=False,
        reads_regs=set(),
        writes_regs=set(),
        reads_mem=reads_memory,
        writes_mem=writes_memory,
        has_return=has_return,
        has_tail_call=False,
        has_indirect_control_flow=False,
        has_timing_source=False,
        has_cache_operation=False,
        has_speculation_control=False,
    )


def _shell(*, outputs=1, memory_clobber=False, volatile=True):
    fragment = AsmFragment(
        id="frag",
        outputs=[
            AsmOperand(constraint="=r", exprText=f"out{index}", isOutput=True)
            for index in range(outputs)
        ],
        clobbers=["memory"] if memory_clobber else [],
        isVolatile=volatile,
    )
    return SourceShellModel.from_fragment(fragment)


def _cfg(block, *, unknown_target=False):
    node = CFGNode(
        addr=block.addr,
        size=block.size,
        has_unknown_target=unknown_target,
    )
    return CFGResult(ok=True, nodes={block.addr: node}, entry=block.addr)


def _privileged_model(operation, *, summary=None, unknown_target=False):
    block = Block(
        0x1000,
        instructions=[CanonicalInsn(
            0x1000, 4, privileged_operations=(operation,)
        )],
    )
    model = analyze_privileged_state(
        fragment_id="frag",
        blocks=(block,),
        cfg=_cfg(block, unknown_target=unknown_target),
        execution_facts=_facts(),
    )
    return block, model, summary or _summary()


def _analyze(operation, *, widths=None, ignored=(), summary=None, shell=None):
    block, privileged, effective_summary = _privileged_model(
        operation, summary=summary
    )
    return analyze_functional_observability(
        fragment_id="frag",
        shell=shell or _shell(),
        summary=effective_summary,
        cfg=_cfg(block),
        privileged_state=privileged,
        operand_width_bits={0: 64} if widths is None else widths,
        ignored_state_declarations=ignored,
    )


def _csr(operation):
    reads = operation in {
        CanonicalCsrOperationKind.READ,
        CanonicalCsrOperationKind.READ_WRITE,
        CanonicalCsrOperationKind.SET_BITS,
        CanonicalCsrOperationKind.CLEAR_BITS,
    }
    writes = operation in {
        CanonicalCsrOperationKind.WRITE,
        CanonicalCsrOperationKind.READ_WRITE,
        CanonicalCsrOperationKind.SET_BITS,
        CanonicalCsrOperationKind.CLEAR_BITS,
    }
    return CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
        csr_id="riscv.csr.mstatus",
        csr_semantic_class="privileged_status",
        csr_operation=operation,
        read_value_node_id="node:mstatus-old" if reads else None,
        write_value_node_id="node:mstatus-new" if writes else None,
        read_modify_write=operation in {
            CanonicalCsrOperationKind.READ_WRITE,
            CanonicalCsrOperationKind.SET_BITS,
            CanonicalCsrOperationKind.CLEAR_BITS,
        },
        affected_csr_fields=(CanonicalCsrFieldEffect(
            field_id="riscv.csr.mstatus.mie",
            old_value_node_id="node:mie-old",
            new_value_node_id="node:mie-new",
            writable_mask=0x8,
            warl_or_wlrl_policy_id="riscv.mstatus.mie.warl.v1",
            side_effect_ids=("interrupt-enable-change",),
            complete=True,
        ),) if writes else (),
        xlen_bits=64,
        required_extension_id="zicsr",
        access_gate_ids=("privilege-mode:m",),
        access_gate_evaluation_complete=True,
        required_privilege_mode="m",
        may_trap=False,
        state_complete=True,
    )


def test_read_only_csr_can_enter_exact_functional_fallback_proof():
    contract = _analyze(_csr(CanonicalCsrOperationKind.READ))

    assert contract.complete
    assert contract.privileged_fallback_possible
    assert contract.fallback_possibility is (
        FunctionalFallbackPossibility.POSSIBLE_WITH_EXACT_TARGET_CONTRACT
    )
    assert contract.outputs[0].width_bits == 64
    assert contract.required_privileged_value_sources == (
        "csr:riscv.csr.mstatus@0x1000:0:value",
    )
    assert "provide-exact-functional-value-contract" in (
        contract.required_target_obligations
    )


def test_mutating_csr_requires_explicit_ignored_state_authority():
    contract = _analyze(_csr(CanonicalCsrOperationKind.WRITE))

    assert contract.complete
    assert contract.fallback_possibility is FunctionalFallbackPossibility.IMPOSSIBLE
    assert contract.unignored_privileged_state_ids == (
        "csr:riscv.csr.mstatus@0x1000:0:state",
    )
    assert FunctionalObservabilityReasonCode.PRIVILEGED_STATE_NOT_IGNORED.value in (
        contract.reason_codes
    )


def test_explicit_complete_ignored_state_allows_target_contract_proof():
    state_id = "csr:riscv.csr.mstatus@0x1000:0:state"
    ignored = IgnoredStateDeclaration(
        state_id=state_id,
        kind=IgnoredPrivilegedStateKind.CSR,
        justification="experiment observes only the declared scalar result",
        provenance="compiler-observability-sidecar:v1",
        complete=True,
    )

    contract = _analyze(
        _csr(CanonicalCsrOperationKind.READ_WRITE), ignored=(ignored,)
    )

    assert contract.complete and contract.privileged_fallback_possible
    assert contract.ignored_states[0].state_id == state_id
    assert contract.unignored_privileged_state_ids == ()
    assert contract.required_privileged_value_sources


def test_unknown_or_incomplete_ignored_state_declaration_fails_closed():
    ignored = IgnoredStateDeclaration(
        state_id="csr:riscv.csr.not-present@0x1000:0:state",
        kind=IgnoredPrivilegedStateKind.CSR,
        justification="",
        provenance="",
        complete=False,
    )

    contract = _analyze(
        _csr(CanonicalCsrOperationKind.WRITE), ignored=(ignored,)
    )

    assert not contract.complete
    assert FunctionalObservabilityReasonCode.IGNORED_STATE_DECLARATION_INCOMPLETE.value in (
        contract.missing_fact_codes
    )


def test_privilege_return_cannot_be_downgraded_to_local_functional_fallback():
    operation = CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.PRIVILEGE_RETURN,
        return_kind="mret",
        restored_privilege_mode="m",
        restored_interrupt_state="mstatus.mpie-to-mie",
        return_pc_node_id="node:mepc",
        status_field_effect_ids=("mstatus.mie", "mstatus.mpp"),
        continuation_identity="continuation:test",
        state_complete=True,
    )
    contract = _analyze(operation, summary=_summary(has_return=True))

    assert contract.termination.kind is FunctionalTerminationKind.NONLOCAL_RETURN
    assert contract.complete
    assert contract.fallback_possibility is FunctionalFallbackPossibility.IMPOSSIBLE
    assert FunctionalObservabilityReasonCode.PRIVILEGE_RETURN_REQUIRES_EXACT_CONTROL_FLOW.value in (
        contract.reason_codes
    )


def test_trap_remains_an_observable_target_obligation():
    operation = CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.TRAP,
        trap_kind="environment_call",
        trap_cause="environment-call-from-m",
        tval_node_id="node:tval",
        trap_target_privilege_mode="m",
        handler_binding_id="test-trap-v2",
        saved_pc_node_id="node:mepc",
        saved_status_effect_ids=("mstatus.mpie", "mstatus.mpp"),
        delegation_path=("machine",),
        continuation_identity="handler:test",
        externally_observable=True,
        state_complete=True,
    )
    contract = _analyze(operation)

    assert contract.complete and contract.privileged_fallback_possible
    assert contract.trap.present is True and contract.trap.observable
    assert contract.error.kind is FunctionalErrorKind.ARCHITECTURAL_TRAP
    assert "preserve-error-behavior" in contract.required_target_obligations
    assert "preserve-trap-behavior" in contract.required_target_obligations


def test_trap_cannot_be_suppressed_by_ignored_state_declaration():
    operation = CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.TRAP,
        trap_kind="environment_call",
        trap_cause="environment-call-from-m",
        tval_node_id="node:tval",
        trap_target_privilege_mode="m",
        handler_binding_id="test-trap-v2",
        saved_pc_node_id="node:mepc",
        saved_status_effect_ids=("mstatus.mpie", "mstatus.mpp"),
        delegation_path=("machine",),
        continuation_identity="handler:test",
        externally_observable=True,
        state_complete=True,
    )
    declaration = IgnoredStateDeclaration(
        state_id="trap:environment_call@0x1000:0",
        kind=IgnoredPrivilegedStateKind.CSR,
        justification="invalid attempt to hide an observable trap",
        provenance="unit-test",
        complete=True,
    )
    contract = _analyze(operation, ignored=(declaration,))

    assert contract.complete
    assert contract.fallback_possibility is FunctionalFallbackPossibility.IMPOSSIBLE
    assert FunctionalObservabilityReasonCode.OBSERVABLE_EFFECT_CANNOT_BE_IGNORED.value in (
        contract.reason_codes
    )


def test_missing_output_width_is_unknown_and_never_possible():
    contract = _analyze(_csr(CanonicalCsrOperationKind.READ), widths={})

    assert not contract.complete
    assert contract.fallback_possibility is FunctionalFallbackPossibility.UNKNOWN
    assert FunctionalObservabilityReasonCode.OUTPUT_WIDTH_UNKNOWN.value in (
        contract.missing_fact_codes
    )


def test_memory_and_shell_observability_are_explicit_obligations():
    contract = _analyze(
        _csr(CanonicalCsrOperationKind.READ),
        summary=_summary(reads_memory=True, writes_memory=True),
        shell=_shell(memory_clobber=True, volatile=True),
    )

    assert contract.complete
    assert contract.memory.reads_memory and contract.memory.writes_memory
    assert contract.memory.compiler_memory_order_observable
    assert contract.memory.volatile_execution_observable
    assert "preserve-memory-effects" in contract.required_target_obligations
    assert "preserve-compiler-memory-order" in contract.required_target_obligations
    assert "preserve-volatile-execution" in contract.required_target_obligations


def test_incomplete_privileged_state_propagates_fail_closed_reasons():
    operation = CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
        csr_id=None,
        csr_operation=CanonicalCsrOperationKind.UNKNOWN,
        required_privilege_mode=None,
        state_complete=False,
    )
    contract = _analyze(operation)

    assert not contract.complete
    assert contract.fallback_possibility is FunctionalFallbackPossibility.UNKNOWN
    assert FunctionalObservabilityReasonCode.PRIVILEGED_STATE_INCOMPLETE.value in (
        contract.missing_fact_codes
    )


def test_absent_privileged_semantics_is_not_a_privileged_fallback_candidate():
    block = Block(0x1000, instructions=[CanonicalInsn(0x1000, 4)])
    privileged = analyze_privileged_state(
        fragment_id="frag",
        blocks=(block,),
        cfg=_cfg(block),
        execution_facts=_facts(),
    )
    contract = analyze_functional_observability(
        fragment_id="frag",
        shell=_shell(outputs=0, volatile=False),
        summary=_summary(),
        cfg=_cfg(block),
        privileged_state=privileged,
        operand_width_bits={},
    )

    assert contract.complete
    assert contract.fallback_possibility is FunctionalFallbackPossibility.NOT_APPLICABLE
    assert not contract.privileged_fallback_possible

    serialized = functional_observability_contract_to_dict(contract)
    assert serialized["fragmentId"] == "frag"
    assert serialized["fallbackPossibility"] == "not_applicable"
    assert serialized["privilegedFallbackPossible"] is False
