from types import SimpleNamespace

from riscv2x86_py.cfg import CFGNode, CFGResult
from riscv2x86_py.pcode_ir import (
    Block,
    CanonicalCsrFieldEffect,
    CanonicalCsrOperationKind,
    CanonicalInsn,
    CanonicalPrivilegedOperation,
    CanonicalPrivilegedOperationKind,
    Op,
    Var,
    VarKind,
    canonicalize_lifted_instruction,
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
    default_user_process_execution_facts,
)
from riscv2x86_py.privileged_state_analysis import (
    AddressTranslationEffectKind,
    CsrEffectOperation,
    InterruptEffectKind,
    PrivilegeReturnKind,
    PrivilegedStateReasonCode,
    TrapEffectKind,
    VirtualizationEffectKind,
    analyze_privileged_state,
)


def _facts(
    *,
    profile=SourceExecutionProfile.RISCV_MACHINE_FIRMWARE,
    mode=SourcePrivilegeMode.M,
    readable=("riscv.csr.mstatus",),
    writable=("riscv.csr.mstatus",),
    complete=True,
):
    missing = () if complete else ("privileged.source-privilege-spec-missing",)
    return PrivilegedExecutionFacts(
        fragment_id="frag",
        source_execution_profile=profile,
        target_execution_mode=TargetExecutionMode.EMULATOR,
        source_privilege_spec_version="1.12" if complete else None,
        source_isa_extensions=("i", "zicsr"),
        initial_privilege_mode=mode,
        csr_access_policy=CsrAccessPolicyFacts(
            policy_id="test-policy-v1",
            readable_csr_ids=readable,
            writable_csr_ids=writable,
            unknown_access=UnknownCsrAccessDisposition.TRAP,
            complete=True,
        ),
        target_runtime_contract_set_id="test-runtime-v1",
        complete=complete,
        missing_fact_codes=missing,
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


def _cfg(*blocks):
    return CFGResult(
        ok=True,
        nodes={block.addr: CFGNode(block.addr, block.size) for block in blocks},
        entry=blocks[0].addr if blocks else 0,
    )


def _model(block, facts=None):
    return analyze_privileged_state(
        fragment_id="frag",
        blocks=(block,),
        cfg=_cfg(block),
        execution_facts=facts or _facts(),
    )


def test_typed_csr_effect_joins_policy_and_privilege_mode():
    metadata = CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
        csr_id="riscv.csr.mstatus",
        csr_semantic_class="privileged_status",
        csr_operation=CanonicalCsrOperationKind.READ_WRITE,
        read_value_node_id="node:mstatus-old",
        write_value_node_id="node:mstatus-new",
        read_modify_write=True,
        affected_csr_fields=(CanonicalCsrFieldEffect(
            field_id="riscv.csr.mstatus.mie",
            old_value_node_id="node:mie-old",
            new_value_node_id="node:mie-new",
            writable_mask=0x8,
            warl_or_wlrl_policy_id="riscv.mstatus.mie.warl.v1",
            side_effect_ids=("interrupt-enable-change",),
            complete=True,
        ),),
        xlen_bits=64,
        required_extension_id="zicsr",
        access_gate_ids=("privilege-mode:m",),
        access_gate_evaluation_complete=True,
        required_privilege_mode="m",
        may_trap=False,
        state_complete=True,
    )
    block = Block(
        0x1000,
        instructions=[CanonicalInsn(0x1000, 4, privileged_operations=(metadata,))],
    )

    model = _model(block)

    assert model.present and model.complete
    assert model.access_permissions_complete
    assert model.csr_effects[0].operation is CsrEffectOperation.READ_WRITE
    assert model.csr_effects[0].required_privilege_mode is SourcePrivilegeMode.M
    assert model.csr_effects[0].access_allowed is True


def test_csr_effect_can_be_derived_from_canonical_varnodes_but_fails_closed_without_required_mode():
    csr = Var(VarKind.REG, "register", 0x300, 8, "riscv.csr.mstatus")
    output = Var(VarKind.REG, "register", 10, 8, "a0")
    op = Op(0x1000, "COPY", output, [csr])
    block = Block(0x1000, ops=[op])

    model = _model(block)

    assert model.present and not model.complete
    assert model.csr_effects[0].operation is CsrEffectOperation.READ
    assert model.csr_effects[0].csr_id == "riscv.csr.mstatus"
    assert PrivilegedStateReasonCode.CSR_ACCESS_POLICY_INCOMPLETE.value in model.missing_fact_codes


def test_denied_csr_access_requires_a_canonical_trap_effect():
    metadata = CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
        csr_id="riscv.csr.mstatus",
        csr_operation=CanonicalCsrOperationKind.READ,
        required_privilege_mode="m",
        state_complete=True,
    )
    block = Block(
        0x1000,
        instructions=[CanonicalInsn(0x1000, 4, privileged_operations=(metadata,))],
    )
    user_facts = _facts(
        profile=SourceExecutionProfile.RISCV_USER_PROCESS,
        mode=SourcePrivilegeMode.U,
        readable=(),
        writable=(),
    )

    model = _model(block, user_facts)

    assert model.csr_effects[0].access_allowed is False
    assert model.csr_effects[0].may_trap is True
    assert not model.complete
    assert PrivilegedStateReasonCode.CSR_ACCESS_TRAP_UNMODELLED.value in model.missing_fact_codes


def test_trap_return_interrupt_mmu_and_virtualization_are_separate_effects():
    operations = (
        CanonicalPrivilegedOperation(
            CanonicalPrivilegedOperationKind.TRAP,
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
        ),
        CanonicalPrivilegedOperation(
            CanonicalPrivilegedOperationKind.PRIVILEGE_RETURN,
            return_kind="mret",
            restored_privilege_mode="m",
            restored_interrupt_state="mstatus.mpie-to-mie",
            return_pc_node_id="node:mepc",
            status_field_effect_ids=("mstatus.mie", "mstatus.mpp"),
            continuation_identity="continuation:test",
            state_complete=True,
        ),
        CanonicalPrivilegedOperation(
            CanonicalPrivilegedOperationKind.INTERRUPT_STATE,
            interrupt_kind="wait",
            interrupt_enable_state="mstatus.mie",
            interrupt_pending_state="mip",
            interrupt_delegation_path=("machine",),
            interrupt_priority=1,
            interruptibility=True,
            event_source_id="platform-interrupt",
            wait_wakeup_relation_id="wfi-wakeup.v1",
            state_complete=True,
        ),
        CanonicalPrivilegedOperation(
            CanonicalPrivilegedOperationKind.ADDRESS_TRANSLATION,
            address_translation_kind="tlb_invalidation",
            translation_mode="test",
            asid=0,
            vmid=0,
            virtual_address_scope="all",
            address_space_identity="test-address-space",
            synchronization_scope="local-hart",
            shootdown_required=False,
            state_complete=True,
        ),
        CanonicalPrivilegedOperation(
            CanonicalPrivilegedOperationKind.VIRTUALIZATION_STATE,
            virtualization_kind="stage2_translation",
            state_complete=True,
        ),
    )
    block = Block(
        0x1000,
        instructions=[CanonicalInsn(0x1000, 4, privileged_operations=operations)],
    )

    model = _model(block)

    assert model.complete
    assert model.trap_effects[0].kind is TrapEffectKind.ENVIRONMENT_CALL
    assert model.return_effects[0].kind is PrivilegeReturnKind.MRET
    assert model.interrupt_effects[0].kind is InterruptEffectKind.WAIT
    assert model.address_translation_effects[0].kind is AddressTranslationEffectKind.TLB_INVALIDATION
    assert model.virtualization_effects[0].kind is VirtualizationEffectKind.STAGE2_TRANSLATION


def test_unclassified_callother_fails_closed_even_when_another_site_is_typed():
    trap = CanonicalPrivilegedOperation(
        CanonicalPrivilegedOperationKind.TRAP,
        trap_kind="breakpoint",
        state_complete=True,
    )
    block = Block(
        0x1000,
        ops=[Op(0x1000, "CALLOTHER", None, []), Op(0x1004, "CALLOTHER", None, [])],
        instructions=[CanonicalInsn(0x1004, 4, privileged_operations=(trap,))],
    )

    model = _model(block)

    assert not model.complete
    assert PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE.value in model.missing_fact_codes


def test_incomplete_execution_facts_and_cfg_are_propagated_only_for_present_privileged_state():
    trap = CanonicalPrivilegedOperation(
        CanonicalPrivilegedOperationKind.TRAP,
        trap_kind="environment_call",
        state_complete=True,
    )
    block = Block(
        0x1000,
        instructions=[CanonicalInsn(0x1000, 4, privileged_operations=(trap,))],
    )

    model = analyze_privileged_state(
        fragment_id="frag",
        blocks=(block,),
        cfg=CFGResult(ok=True),
        execution_facts=_facts(complete=False),
    )

    assert not model.complete
    assert PrivilegedStateReasonCode.EXECUTION_FACTS_INCOMPLETE.value in model.missing_fact_codes
    assert PrivilegedStateReasonCode.CFG_INCOMPLETE.value in model.missing_fact_codes

    ordinary = Block(0x2000, instructions=[CanonicalInsn(0x2000, 4)])
    ordinary_model = analyze_privileged_state(
        fragment_id="frag",
        blocks=(ordinary,),
        cfg=None,
        execution_facts=default_user_process_execution_facts("frag"),
    )
    assert not ordinary_model.present and ordinary_model.complete


def test_privileged_return_without_typed_kind_is_rejected():
    block = Block(0x1000, terminator_kind="return")

    model = _model(block)

    assert model.present and not model.complete
    assert PrivilegedStateReasonCode.RETURN_KIND_UNCLASSIFIED.value in model.missing_fact_codes


def test_raw_mnemonic_is_not_privileged_evidence_and_typed_metadata_survives_canonicalization():
    raw_only = SimpleNamespace(
        addr=0x1000,
        size=4,
        raw_ops=[],
        asm_mnem="mret",
        asm_body="",
    )
    canonical = canonicalize_lifted_instruction(raw_only)
    assert canonical.privileged_operations == ()

    typed = CanonicalPrivilegedOperation(
        CanonicalPrivilegedOperationKind.PRIVILEGE_RETURN,
        return_kind="mret",
        state_complete=True,
    )
    raw_typed = SimpleNamespace(
        addr=0x1004,
        size=4,
        raw_ops=[],
        asm_mnem="ignored",
        asm_body="ignored",
        privileged_operations=(typed,),
    )
    canonical_typed = canonicalize_lifted_instruction(raw_typed)
    assert canonical_typed.privileged_operations == (typed,)

    malformed = SimpleNamespace(
        addr=0x1008,
        size=4,
        raw_ops=[],
        privileged_operations=("mret",),
    )
    canonical_malformed = canonicalize_lifted_instruction(malformed)
    malformed_block = Block(0x1008, instructions=[canonical_malformed])
    malformed_model = analyze_privileged_state(
        fragment_id="frag",
        blocks=(malformed_block,),
        cfg=_cfg(malformed_block),
        execution_facts=_facts(),
    )
    assert malformed_model.present and not malformed_model.complete
    assert PrivilegedStateReasonCode.CANONICAL_METADATA_INCOMPLETE.value in malformed_model.missing_fact_codes
