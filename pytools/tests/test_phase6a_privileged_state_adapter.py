from dataclasses import replace
from types import SimpleNamespace

from riscv2x86_py.cfg import CFGNode, CFGResult
from riscv2x86_py.functional_observability import (
    analyze_functional_observability,
)
from riscv2x86_py.pcode_ir import (
    Block,
    CanonicalCsrOperationKind,
    CanonicalInsn,
    CanonicalPrivilegedOperation,
    CanonicalPrivilegedOperationKind,
    IRSummary,
    Op,
    Var,
    VarKind,
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
from riscv2x86_py.privileged_state_adapter import (
    PrivilegedAdapterReasonCode,
    SourcePrivilegedAccessModel,
    SourceReadOnlyCounterCsrModel,
    build_privileged_state_adapter,
)
from riscv2x86_py.privileged_state_analysis import (
    PrivilegeReturnEffect,
    PrivilegeReturnKind,
    analyze_privileged_state,
)
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.semantic_types import PreservationLevel, SemanticFeature
from riscv2x86_py.shell_model import SourceShellModel
from riscv2x86_py.source_model import (
    SourceOperationKind,
    build_source_semantic_model,
)


def _counter_inputs():
    fragment = AsmFragment(
        id="counter-frag",
        outputs=[
            AsmOperand(constraint="=r", exprText="counter", isOutput=True)
        ],
        isVolatile=True,
    )
    output = Var(VarKind.REG, "register", 10, 8, "a0")
    counter = Var(VarKind.REG, "register", 0, 8, "time")
    operation = Op(0x1000, "COPY", output, [counter])
    instruction = CanonicalInsn(
        addr=0x1000,
        size=4,
        privileged_operations=(CanonicalPrivilegedOperation(
            kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
            csr_id="riscv.csr.time",
            csr_operation=CanonicalCsrOperationKind.READ,
            required_privilege_mode="u",
            may_trap=False,
            state_complete=True,
        ),),
    )
    summary = IRSummary(
        is_single_block=True,
        has_branch=False,
        has_call_or_return=False,
        has_memory_barrier=False,
        has_atomic=False,
        reads_regs={"time"},
        writes_regs={"a0"},
        reads_mem=False,
        writes_mem=False,
        has_return=False,
        has_tail_call=False,
        has_indirect_control_flow=False,
        has_timing_source=False,
        has_cache_operation=False,
        has_speculation_control=False,
    )
    block = Block(
        0x1000,
        [operation],
        summary=summary,
        instructions=[instruction],
    )
    cfg = CFGResult(
        ok=True,
        nodes={0x1000: CFGNode(addr=0x1000, size=4, instr_addrs=[0x1000])},
        entry=0x1000,
    )
    execution = PrivilegedExecutionFacts(
        fragment_id="counter-frag",
        source_execution_profile=SourceExecutionProfile.RISCV_USER_PROCESS,
        target_execution_mode=TargetExecutionMode.X86_USER_PROCESS,
        source_privilege_spec_version="1.12",
        source_isa_extensions=("i", "zicsr"),
        initial_privilege_mode=SourcePrivilegeMode.U,
        csr_access_policy=CsrAccessPolicyFacts(
            policy_id="user-counter-policy-v1",
            readable_csr_ids=("riscv.csr.time",),
            writable_csr_ids=(),
            unknown_access=UnknownCsrAccessDisposition.DENY,
            complete=True,
        ),
        target_runtime_contract_set_id="x86-user-counter-v1",
        complete=True,
        missing_fact_codes=(),
        provenance="compiler-plugin:test",
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
    state = analyze_privileged_state(
        fragment_id="counter-frag",
        blocks=(block,),
        cfg=cfg,
        execution_facts=execution,
    )
    observability = analyze_functional_observability(
        fragment_id="counter-frag",
        shell=SourceShellModel.from_fragment(fragment),
        summary=summary,
        cfg=cfg,
        privileged_state=state,
        operand_width_bits={0: 64},
    )
    facts = TranslationRuntimeFacts(
        rv_to_operand_index={"a0": 0},
        operand_width_bits={0: 64},
        provenance="phase4-test",
    )
    return fragment, block, cfg, summary, state, observability, facts


def test_phase6a_nests_validated_counter_under_privileged_state():
    fragment, block, cfg, summary, state, observability, facts = (
        _counter_inputs()
    )
    model = build_source_semantic_model(
        fragment=fragment,
        blocks=(block,),
        cfg=cfg,
        summary=summary,
        runtime_facts=facts,
        xlen=64,
        privileged_state=state,
        functional_observability=observability,
    )

    assert model.privileged_state is not None
    assert model.privileged_state.complete
    assert model.privileged_state.functional_fallback_possible
    assert isinstance(model.read_only_csr, SourceReadOnlyCounterCsrModel)
    assert isinstance(model.read_only_csr, SourcePrivilegedAccessModel)
    assert model.read_only_csr.complete
    assert model.operation.kind is SourceOperationKind.PRIVILEGED
    assert SemanticFeature.PRIVILEGED_STATE in model.features
    assert SemanticFeature.CSR_ACCESS in model.features
    assert SemanticFeature.READ_ONLY_COUNTER_CSR in model.features
    assert model.preservation.level is PreservationLevel.D


def test_counter_without_phase5_authority_is_retained_but_not_approved():
    fragment, block, cfg, summary, _state, _observability, facts = (
        _counter_inputs()
    )
    model = build_source_semantic_model(
        fragment=fragment,
        blocks=(block,),
        cfg=cfg,
        summary=summary,
        runtime_facts=facts,
        xlen=64,
    )

    assert model.read_only_csr is not None
    assert not model.read_only_csr.complete
    assert model.privileged_state is not None
    assert not model.privileged_state.functional_fallback_possible
    assert PrivilegedAdapterReasonCode.STATE_MISSING in (
        model.privileged_state.reason_codes
    )
    assert SemanticFeature.PRIVILEGED_STATE_INCOMPLETE in model.features


def test_adapter_cross_checks_shell_memory_abi_and_whole_function_route():
    fragment, _block, _cfg, _summary, state, observability, _facts = (
        _counter_inputs()
    )
    return_state = replace(
        state,
        return_effects=(PrivilegeReturnEffect(
            block_address=0x1000,
            operation_index=0,
            kind=PrivilegeReturnKind.MRET,
            complete=True,
        ),),
    )
    candidate = SourceReadOnlyCounterCsrModel(
        effect_id="",
        result_operand_index=0,
        width_bits=64,
        complete=False,
        csr_name="time",
    )
    adapter = build_privileged_state_adapter(
        fragment_id="counter-frag",
        phase5_state=return_state,
        observability=observability,
        read_only_counter_candidate=candidate,
        shell=SourceShellModel.from_fragment(fragment),
        memory=SimpleNamespace(reads_memory=True, writes_memory=False),
        control_flow=SimpleNamespace(has_return=False),
        abi_effects=SimpleNamespace(calls=("call",)),
        whole_function_route=SimpleNamespace(required=False),
        whole_function_facts=SimpleNamespace(
            complete=False, fragment_ids=("another-fragment",)
        ),
    )

    assert adapter is not None and not adapter.complete
    for code in (
        PrivilegedAdapterReasonCode.MEMORY_EFFECT_MISMATCH,
        PrivilegedAdapterReasonCode.CONTROL_FLOW_EFFECT_MISMATCH,
        PrivilegedAdapterReasonCode.ABI_EFFECT_CONFLICT,
        PrivilegedAdapterReasonCode.WHOLE_FUNCTION_ROUTE_MISSING,
        PrivilegedAdapterReasonCode.WHOLE_FUNCTION_FACTS_MISMATCH,
    ):
        assert code in adapter.reason_codes
