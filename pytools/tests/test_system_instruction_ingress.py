"""Real pypcode ingress and environment joins, not QEMU production claims."""
from dataclasses import replace
import copy
import pytest
from riscv2x86_py.system_instruction_ingress import (
    SCHEMA, PROFILE, SystemInstructionAuthority, decode_system_instruction,
    bind_system_instructions, digest,
)
from riscv2x86_py.semantic_content import semantic_identity
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.cfg import build_cfg_from_blocks
from riscv2x86_py.privileged_state_analysis import analyze_privileged_state
from tests.test_privileged_state_analysis import _facts


def environment():
    facts = _facts()
    return replace(facts, virtual_memory_model=replace(facts.virtual_memory_model,
        address_translation_enabled=False, translation_mode='bare', page_size_bytes=None,
        asid_width_bits=None, vmid_width_bits=None))


def authority(code, facts, *, source_digest='sha256:'+'a'*64, fragment_id='frag', offset=0, operation=None):
    name = operation or decode_system_instruction(code[offset:offset+4])
    transition = {'registerEffects': 'all-gprs-preserved'}
    if name == 'ecall':
        transition.update(handlerBindingId=facts.trap_handler_binding.binding_id,
            continuationIdentity=facts.trap_handler_binding.continuation_model_id)
    else:
        transition.update(interruptEnableState=facts.interrupt_model.model_id+':enable',
            interruptPendingState=facts.interrupt_model.model_id+':pending',
            eventSourceId='reviewed-event-stream', waitWakeupRelationId='reviewed-wait-relation',
            spuriousWakeupPolicy='permitted')
    value = dict(schemaVersion=SCHEMA, profile=PROFILE, sourceDigest=source_digest,
        fragmentId=fragment_id, machineCodeDigest=digest(code), executionIdentity=semantic_identity(facts),
        mechanismIdentity='sha256:'+'b'*64,
        bindings=[dict(instructionOffset=offset, operation=name, transition=transition)])
    return seal(value)


def seal(value):
    value = copy.deepcopy(value); value.pop('authorityIdentity', None)
    value['authorityIdentity'] = semantic_identity(value)
    return value


def lifted(code, base=0x10000):
    result = lift(code, base_addr=base, xlen=64, require_authoritative_register_names=True)
    assert result.ok, result.error
    return result


@pytest.mark.parametrize('word,name', [(0x73,'ecall'),(0x10500073,'wfi')])
def test_real_lift_classifies_intrinsic_but_cannot_invent_environment(word, name):
    result = lifted(word.to_bytes(4,'little'))
    metadata = result.insns[0].privileged_operations
    assert len(metadata) == 1 and not metadata[0].state_complete
    blocks, _ = from_lifted(result.insns)
    state = analyze_privileged_state(fragment_id='frag', blocks=blocks,
        cfg=build_cfg_from_blocks(blocks), execution_facts=None)
    assert not state.complete
    assert [c.value for c in state.semantic_classes] == ['trap_service' if name=='ecall' else 'interrupt_event']


@pytest.mark.parametrize('word', [0x73, 0x10500073])
@pytest.mark.parametrize('bit', [7, 11, 12, 14, 15, 19, 20, 31])
def test_nonmatching_system_encodings_do_not_receive_ecall_wfi_authority(word, bit):
    assert decode_system_instruction((word ^ (1<<bit)).to_bytes(4, 'little')) is None


@pytest.mark.parametrize('code', [b'', b'\x73', bytes.fromhex('730000000000'), bytes.fromhex('93000000')])
def test_decoder_requires_exact_instruction_width_and_encoding(code):
    assert decode_system_instruction(code) is None


@pytest.mark.parametrize('word', [0x73,0x10500073])
@pytest.mark.parametrize('base', [0x10000,0x20004])
def test_real_bound_ingress_reaches_complete_effect_model(word, base):
    code = word.to_bytes(4,'little'); facts = environment()
    selected = SystemInstructionAuthority.from_dict(authority(code, facts))
    result = lifted(code, base)
    record = bind_system_instructions(result, machine_code=code, base_addr=base,
        source_digest=selected.source_digest, fragment_id='frag', facts=facts, authority=selected)
    assert record['semanticApproval'] is False
    blocks,_ = from_lifted(result.insns)
    state = analyze_privileged_state(fragment_id='frag', blocks=blocks,
        cfg=build_cfg_from_blocks(blocks), execution_facts=facts)
    assert state.complete, state.missing_fact_codes
    if word == 0x73:
        assert state.trap_effects[0].cause == 'environment-call-from-m'
    else:
        assert state.interrupt_effects[0].wait_wakeup_relation


@pytest.mark.parametrize('mutation', ['source', 'fragment', 'machine', 'execution', 'offset', 'operation',
    'handler', 'continuation', 'mode', 'mmu', 'facts-incomplete'])
def test_binding_rejects_stale_or_wrong_authority_without_modifying_lift(mutation):
    code = bytes.fromhex('73000000'); facts = environment()
    value = authority(code, facts)
    if mutation == 'source': value['sourceDigest'] = 'sha256:'+'c'*64
    if mutation == 'fragment': value['fragmentId'] = 'another'
    if mutation == 'machine': value['machineCodeDigest'] = 'sha256:'+'c'*64
    if mutation == 'execution': value['executionIdentity'] = 'sha256:'+'c'*64
    if mutation == 'offset': value['bindings'][0]['instructionOffset'] = 2
    if mutation == 'operation':
        value['bindings'] = authority(bytes.fromhex('73005010'), facts)['bindings']
    if mutation == 'handler': value['bindings'][0]['transition']['handlerBindingId'] = 'wrong'
    if mutation == 'continuation': value['bindings'][0]['transition']['continuationIdentity'] = 'wrong'
    if mutation in ('mode','mmu','facts-incomplete'):
        from riscv2x86_py.privileged_execution_sidecar import SourcePrivilegeMode
        if mutation == 'mode': facts=replace(facts, initial_privilege_mode=SourcePrivilegeMode.U)
        if mutation == 'mmu': facts=replace(facts, virtual_memory_model=_facts().virtual_memory_model)
        if mutation == 'facts-incomplete': facts=replace(facts, complete=False)
        value['executionIdentity'] = semantic_identity(facts)
    result = lifted(code); original = result.insns[0].privileged_operations
    selected=SystemInstructionAuthority.from_dict(seal(value))
    with pytest.raises(ValueError, match='SYSTEM_AUTHORITY_'):
        bind_system_instructions(result, machine_code=code, base_addr=0x10000,
            source_digest='sha256:'+'a'*64, fragment_id='frag', facts=facts, authority=selected)
    assert result.insns[0].privileged_operations == original


@pytest.mark.parametrize('mutation', ['empty','duplicate','unknown','identity','registers','policy'])
def test_declaration_is_canonical_explicit_and_never_a_verified_boolean(mutation):
    value = authority(bytes.fromhex('73005010'), environment())
    if mutation == 'empty': value['bindings'] = []
    if mutation == 'duplicate': value['bindings'] *= 2
    if mutation == 'unknown': value['bindings'][0]['transition']['verified'] = True
    if mutation == 'registers': value['bindings'][0]['transition']['registerEffects'] = 'ignored'
    if mutation == 'policy': value['bindings'][0]['transition']['spuriousWakeupPolicy'] = 'forbidden'
    value=seal(value)
    if mutation == 'identity': value['authorityIdentity'] = 'sha256:'+'f'*64
    with pytest.raises(ValueError, match='SYSTEM_AUTHORITY_'):
        SystemInstructionAuthority.from_dict(value)


def test_all_decoded_system_sites_must_be_covered_even_with_same_outputs():
    code = bytes.fromhex('7300000073000000'); facts=environment()
    selected=SystemInstructionAuthority.from_dict(authority(code, facts))
    with pytest.raises(ValueError, match='SITE_COVERAGE'):
        bind_system_instructions(lifted(code), machine_code=code, base_addr=0x10000,
            source_digest=selected.source_digest, fragment_id='frag', facts=facts, authority=selected)


def source_fixture(word):
    from riscv2x86_py.schema import AsmFragment
    from riscv2x86_py.source_model import build_source_semantic_model
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    facts = environment(); code = word.to_bytes(4,'little')
    value=authority(code, facts); selected=SystemInstructionAuthority.from_dict(value)
    result=lifted(code)
    bind_system_instructions(result,machine_code=code,base_addr=0x10000,
        source_digest=selected.source_digest,fragment_id='frag',facts=facts,authority=selected)
    blocks, summary=from_lifted(result.insns); cfg=build_cfg_from_blocks(blocks)
    state=analyze_privileged_state(fragment_id='frag',blocks=blocks,cfg=cfg,execution_facts=facts)
    # Deliberately unrelated diagnostic text: only bits and typed facts classify.
    fragment=AsmFragment(id='frag',rawAsmText='not consumed as authority',isVolatile=True,clobbers=['memory'])
    source=build_source_semantic_model(fragment=fragment, blocks=blocks,cfg=cfg,
        summary=summary,runtime_facts=TranslationRuntimeFacts(),xlen=64,privileged_state=state)
    return source, facts, value, blocks


def registry_fixture(word):
    from riscv2x86_py.privileged_runtime_contracts import (
        PrivilegedRuntimeContract, PrivilegedRuntimeRegistry, PrivilegedEnvironmentRouteKind,
        TargetTrapMapping, TargetInterruptMapping, privileged_source_identity, source_effect_id,
        target_environment_identity,
    )
    from riscv2x86_py.phase6c_constraints import TargetEnvironment
    from tests.test_phase6_privileged_runtime_contract import _mapping_registries
    source,facts,value,blocks=source_fixture(word)
    cap='runtime:reviewed-system-fixture:v1'
    target=TargetEnvironment.fixed_sysv_amd64_gnu_att(helper_contract_capabilities={cap})
    ecall=word==0x73;state=source.privileged_state.state
    trap=() if not ecall else (TargetTrapMapping(
        source_effect_id('trap',state.trap_effects[0].block_address,state.trap_effects[0].operation_index),
        'reviewed-cause-relation','reviewed-tval-relation','reviewed-handler-relation',
        'reviewed-continuation-relation','reviewed-result-relation'),)
    wait=() if ecall else (TargetInterruptMapping(
        source_effect_id('interrupt',state.interrupt_effects[0].block_address,state.interrupt_effects[0].operation_index),
        'runtime-event-state','reviewed-enable-pending','reviewed-delegation-priority',
        state.interrupt_effects[0].wait_wakeup_relation),)
    contract=PrivilegedRuntimeContract(contract_id='system-fixture',semantic_version='1',
        source_privileged_identity=privileged_source_identity(source.privileged_state),
        target_environment_id=target_environment_identity(target),runtime_symbol='reviewed_system_adapter',
        callable_identifier='reviewed_system_adapter',required_target_capability=cap,required_capabilities=(cap,),
        source_execution_profile=facts.source_execution_profile.value,
        target_execution_mode=facts.target_execution_mode.value,
        supported_source_profiles=(facts.source_execution_profile.value,),
        supported_target_modes=(facts.target_execution_mode.value,),
        supported_semantic_classes=tuple(c.value for c in state.semantic_classes),
        runtime_contract_set_id='test-runtime-v1',runtime_identity='test-runtime',runtime_contract_version='1',
        privilege_spec_version='1.12',isa_extension_profile_id='extensions:i,zicsr',
        environment_route_kind=PrivilegedEnvironmentRouteKind.ECALL if ecall else PrivilegedEnvironmentRouteKind.WFI,
        environment_contract_id='reviewed-system-environment-fixture',abi_contract_id='reviewed-system-abi',
        state_mapping_registry_id='sys-state@1',trap_mapping_registry_id='sys-trap@1',
        interrupt_mapping_registry_id='sys-interrupt@1',mmu_mapping_registry_id='sys-mmu@1',
        trap_mappings=trap,interrupt_mappings=wait,preserves_microarchitecture_intent=True,
        required_headers=('reviewed_system.h',), required_library='reviewed_system',required_libraries=('reviewed_system',))
    registry=PrivilegedRuntimeRegistry(version='system-fixture.v1',contracts=(contract,),
        mapping_registries=_mapping_registries(contract))
    return source,target,contract,registry


@pytest.mark.parametrize('word', [0x73,0x10500073])
def test_real_bits_to_phase6d_and_registered_renderer_without_text_matching(word):
    from riscv2x86_py.candidate_plans import generate_candidate_plans
    from riscv2x86_py.phase6c_constraints import derive_target_constraints
    from riscv2x86_py.phase6d_common import CompilerCapabilityModel,TargetSemanticCatalog,run_semantic_proof_gate
    from riscv2x86_py.phase6e_selection import Phase6ESelectionPolicy,Phase6ESelectionRequest,ProvenCandidate,select_final_target_lowering_plan
    from riscv2x86_py.phase6f_renderer import RendererContext,render_final_selection_result
    from riscv2x86_py.privileged_renderer_manifest import PrivilegedRendererManifest,PrivilegedRendererManifestEntry,PrivilegedRecipeKind
    from riscv2x86_py.phase6f_contract_registry import EMPTY_RENDERER_CONTRACT_REGISTRY,register_privileged_renderer_manifest
    source,target,contract,registry=registry_fixture(word)
    plans=generate_candidate_plans(source)
    assert len(plans)==1
    plan=plans[0]
    derived=derive_target_constraints(source_model=source,candidate_plan=plan,
        target_environment=target,privileged_runtime_registry=registry)
    assert derived.success,derived.reason_codes
    catalog=TargetSemanticCatalog(frozenset({plan.kind}),frozenset({contract.semantic_contract_id}),'system-fixture.v1')
    proof=run_semantic_proof_gate(source_model=source,candidate_plan=plan,constraints=derived.constraints,
        target_environment=target,target_semantic_catalog=catalog,compiler_capabilities=CompilerCapabilityModel(True,False),
        privileged_runtime_registry=registry)
    assert proof.approved,proof.reason_codes
    selected=select_final_target_lowering_plan(Phase6ESelectionRequest(source_model=source,
        preservation_decision=source.preservation,target_environment=target,candidates=(ProvenCandidate(plan,derived,proof),),
        generated_plan_ids=frozenset({plan.plan_id}),target_catalog_version=catalog.version+':'+','.join(catalog.semantic_contract_ids),
        compiler_capability_id='asm=True;goto=False',privileged_registry_version=registry.version))
    manifest=PrivilegedRendererManifest(manifest_id='system-test',version='1',entries=(
        PrivilegedRendererManifestEntry(contract.semantic_contract_id,plan.kind,'system-call.v1',
            PrivilegedRecipeKind.RUNTIME_CALL,contract.callable_identifier,(),(),contract.required_headers,
            contract.required_libraries,contract.required_target_capability,contract.target_environment_id,registry.version),))
    renderer=register_privileged_renderer_manifest(EMPTY_RENDERER_CONTRACT_REGISTRY,manifest)
    recipe=renderer.resolve(selected.selected_plan)
    assert recipe is not None
    output=render_final_selection_result(selected,target_environment=target,
        renderer_context=RendererContext({plan.plan_id:recipe},{},source_fragment_id='frag'))
    assert 'reviewed_system_adapter(' in (output.emitted_text or '')
    # These are trusted-contract component tests, not actual handler/QEMU execution.


@pytest.mark.parametrize('word', [0x73,0x10500073])
def test_valid_system_metadata_does_not_hide_extra_callother_or_memory_write(word):
    from riscv2x86_py.pcode_ir import _is_proven_system_intrinsic_control_closure, Op,Var,VarKind
    source,facts,value,blocks=source_fixture(word)
    ins=blocks[0].instructions[0]
    assert _is_proven_system_intrinsic_control_closure([ins])
    for extra in (Op(ins.addr,'CALLOTHER',None,[Var(VarKind.CONST,'const',99,4)]),
                  Op(ins.addr,'STORE',None,[Var(VarKind.CONST,'const',0,8)])):
        changed=replace(ins,ops=[*ins.ops,extra])
        assert not _is_proven_system_intrinsic_control_closure([changed])
