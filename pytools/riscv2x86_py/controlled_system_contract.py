"""Prepare normal Phase-4/6 inputs for the registered pending-MTIP/trap model.

Only facts established by the shipped implementation and explicit backend are
produced. Preparation is not approval. The ordinary 6C/6D/6F gates remain owners
of the proof, renderer selection and runtime consumption.
"""
from dataclasses import replace
import json
from pathlib import Path
import shutil
from .semantic_content import semantic_identity,semantic_payload
from .system_instruction_ingress import PROFILE,SCHEMA,digest,SystemInstructionAuthority,bind_system_instructions,decode_system_instruction
from .controlled_system_backend import validate_backend
from .privileged_execution_sidecar import (
    PrivilegedExecutionFacts,CsrAccessPolicyFacts,DelegationModelFacts,InterruptModelFacts,
    VirtualMemoryModelFacts,TrapHandlerBindingFacts,AddressSpaceIdentityFacts,
    SourceExecutionProfile,SourcePrivilegeMode,TargetExecutionMode,UnknownCsrAccessDisposition,
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2,
)


def camel(value):
    if isinstance(value,dict):
        def key(name):
            head,*rest=name.split('_');return head+''.join(x.title() for x in rest)
        return {key(k):camel(v) for k,v in value.items()}
    if isinstance(value,list):return [camel(v) for v in value]
    return value


def execution_facts(fragment_id, backend):
    ident=backend['backendIdentity']
    return PrivilegedExecutionFacts(fragment_id,SourceExecutionProfile.RISCV_MACHINE_FIRMWARE,
        TargetExecutionMode.VIRTUALIZED_RUNTIME,'1.12',('i','zicsr'),SourcePrivilegeMode.M,
        CsrAccessPolicyFacts('system-csr:'+ident,('riscv.csr.mcause','riscv.csr.mepc','riscv.csr.mie','riscv.csr.mip','riscv.csr.mstatus'),(),UnknownCsrAccessDisposition.TRAP,True),
        'controlled-system-v1',True,(),'registered-controlled-system:'+ident,
        DelegationModelFacts('system-no-delegation:'+ident,True,True,(),(),True),
        InterruptModelFacts('system-prepending-mtip:'+ident,True,True,'single-mtip',False,True),
        VirtualMemoryModelFacts('system-bare:'+ident,False,'bare',None,None,None,True),
        TrapHandlerBindingFacts('system-handler:'+ident,'m-ecall-save-restore-and-advance',
            'm-trap-all-gprs-preserved.v1','mret-to-next-instruction.v1',True),
        AddressSpaceIdentityFacts('system-private:'+ident,'single-hart-private-ram','one-boot',False,True),
        'controlled-system','1','x86_64-logical-m-state',PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2)


def execution_payload(facts):
    raw=camel(semantic_payload(facts));raw.pop('schemaVersion');raw.pop('userCounterBackendIdentity')
    raw['addressSpaceIdentity']=raw.pop('addressSpace')
    return {'schemaVersion':facts.schema_version,'provenance':facts.provenance,'fragments':[raw]}


def runtime_payload(contract,registry):
    from .privileged_runtime_contracts import PRIVILEGED_RUNTIME_REGISTRY_SCHEMA
    return {'schemaVersion':PRIVILEGED_RUNTIME_REGISTRY_SCHEMA,'version':registry.version,
        'contracts':[camel(semantic_payload(contract))],'mappingRegistryVersion':registry.mapping_registries.version,
        'mappingRegistries':[camel(semantic_payload(r)) for r in registry.mapping_registries._registries.values()]}


def source_model(finding,facts,authority):
    from dataclasses import fields
    from .schema import AsmFragment
    from .lift import lift
    from .pcode_ir import from_lifted
    from .cfg import build_cfg_from_blocks
    from .source_model import build_source_semantic_model
    from .runtime_facts import TranslationRuntimeFacts
    from .privileged_state_analysis import analyze_privileged_state
    code=bytes.fromhex(finding['machineCodeHex']);result=lift(code,xlen=64,base_addr=0x10000,require_authoritative_register_names=True)
    if not result.ok:raise ValueError('SYSTEM_CONTRACT_LIFT_FAILED:'+result.error)
    bind_system_instructions(result,machine_code=code,base_addr=0x10000,source_digest=finding['sourceDigest'],
        fragment_id=facts.fragment_id,facts=facts,authority=authority)
    blocks,summary=from_lifted(result.insns);cfg=build_cfg_from_blocks(blocks)
    state=analyze_privileged_state(fragment_id=facts.fragment_id,blocks=blocks,cfg=cfg,execution_facts=facts)
    fragment=AsmFragment(**{k:v for k,v in finding['fragment'].items() if k in {f.name for f in fields(AsmFragment)}})
    model=build_source_semantic_model(fragment=fragment,blocks=blocks,cfg=cfg,summary=summary,
        runtime_facts=TranslationRuntimeFacts(),xlen=64,privileged_state=state)
    if not model.privileged_state.strict_translation_eligible:raise ValueError('SYSTEM_SOURCE_MODEL_INCOMPLETE')
    return model


def prepare(*,source,report,fragment_id,backend_path,clang,output):
    from .mechanism_route_checks import compiler_bound_finding
    from .controlled_system_scope import scope
    from .privileged_runtime_contracts import (PrivilegedRuntimeContract,PrivilegedRuntimeRegistry,
        PrivilegedEnvironmentRouteKind,TargetTrapMapping,TargetInterruptMapping,privileged_source_identity,
        PrivilegedMappingRegistrySet,VersionedPrivilegedMappingRegistry,PrivilegedMappingRegistryKind,
        source_effect_id,target_environment_identity)
    from .production_target_environment import production_target_environment
    source=Path(source).resolve();output=Path(output).resolve();backend=validate_backend(backend_path)
    if output.exists():raise ValueError('SYSTEM_CONTRACT_OUTPUT_EXISTS')
    finding,_=compiler_bound_finding(source,report,fragment_id);shape=scope(source,finding,clang)
    code=bytes.fromhex(finding['machineCodeHex']);name=decode_system_instruction(code)
    if name is None:raise ValueError('SYSTEM_CONTRACT_SINGLE_INSTRUCTION_REQUIRED')
    facts=execution_facts(fragment_id,backend)
    transition={'registerEffects':'all-gprs-preserved'}
    if name=='ecall':transition.update(handlerBindingId=facts.trap_handler_binding_id,continuationIdentity=facts.trap_handler_binding.continuation_model_id)
    else:transition.update(interruptEnableState=facts.interrupt_model_id+':enable',interruptPendingState=facts.interrupt_model_id+':pending',
        eventSourceId='clint-mtip-prepending-global-mie-zero',waitWakeupRelationId='already-pending-local-event-immediate-resume',spuriousWakeupPolicy='permitted')
    authority={'schemaVersion':SCHEMA,'profile':PROFILE,'sourceDigest':digest(source.read_bytes()),'fragmentId':fragment_id,
        'machineCodeDigest':digest(code),'executionIdentity':semantic_identity(facts),'mechanismIdentity':backend['backendIdentity'],
        'bindings':[{'instructionOffset':0,'operation':name,'transition':transition}]}
    authority['authorityIdentity']=semantic_identity(authority)
    model=source_model(finding,facts,SystemInstructionAuthority.from_dict(authority));state=model.privileged_state.state
    route={'runtimeAdapterIdentity':'rv2x86_m_ecall_v1' if name=='ecall' else 'rv2x86_m_wfi_pending_v1',
        'targetMechanism':'registered-runtime-adapter','preservedSemantics':['architectural_state','compiler_shell'],
        'notPreservedSemantics':[],'backendIdentity':backend['backendIdentity'],'scopeIdentity':shape['scopeIdentity']}
    if name=='ecall':route.update(serviceModel='trap-only',trapHandlerIdentity=facts.trap_handler_binding.handler_identity,
        clobbers='all-gprs-preserved',memoryEffects='private-transport-only-no-program-memory-objects',
        continuation=facts.trap_handler_binding.continuation_model_id,addressSpaceRelation='bare-private-to-logical-private')
    else:route.update(interruptEnableState=transition['interruptEnableState'],pendingInterruptModel=facts.interrupt_model_id,
        delegationRelation=facts.delegation_model_id,virtualizationRelation='none',trapWakeupContinuation=transition['waitWakeupRelationId'],
        spuriousWakeupPolicy='permitted',targetWaitAdapter=route['runtimeAdapterIdentity'],schedulerRuntimeInteraction='event-already-pending-no-future-event-claim')
    cap='runtime:controlled-system:'+name+':v1';target=production_target_environment()
    trap=() if name!='ecall' else (TargetTrapMapping(source_effect_id('trap',state.trap_effects[0].block_address,state.trap_effects[0].operation_index),
        'm-cause-11-to-logical-cause-11','mtval-to-logical-trap-value','registered-save-restore-handler',
        facts.trap_handler_binding.continuation_model_id,'trap-only-no-service-result'),)
    wait=() if name!='wfi' else (TargetInterruptMapping(source_effect_id('interrupt',state.interrupt_effects[0].block_address,state.interrupt_effects[0].operation_index),
        'logical-mtip-state','mie-mtip-pending-global-mie-zero','no-delegation-single-event',state.interrupt_effects[0].wait_wakeup_relation),)
    contract=PrivilegedRuntimeContract(contract_id='controlled-system-'+name,semantic_version='1',
        source_privileged_identity=privileged_source_identity(model.privileged_state),target_environment_id=target_environment_identity(target),
        runtime_symbol=route['runtimeAdapterIdentity'],callable_identifier=route['runtimeAdapterIdentity'],
        required_target_capability=cap,required_capabilities=(cap,),source_execution_profile=facts.source_execution_profile.value,
        target_execution_mode=facts.target_execution_mode.value,supported_source_profiles=(facts.source_execution_profile.value,),
        supported_target_modes=(facts.target_execution_mode.value,),supported_semantic_classes=tuple(x.value for x in state.semantic_classes),
        environment_route_kind=PrivilegedEnvironmentRouteKind(name),environment_contract_id=semantic_identity(route),
        preserved_environment_semantics=tuple(route['preservedSemantics']),runtime_contract_set_id='controlled-system-v1',
        runtime_identity='controlled-system',runtime_contract_version='1',privilege_spec_version='1.12',isa_extension_profile_id='extensions:i,zicsr',
        abi_contract_id='m-trap-all-gprs-preserved.v1',state_mapping_registry_id='system-state@1',trap_mapping_registry_id='system-trap@1',
        interrupt_mapping_registry_id='system-interrupt@1',mmu_mapping_registry_id='system-mmu@1',trap_mappings=trap,interrupt_mappings=wait,
        required_headers=('controlled_system.h',),required_library='controlled_system',required_libraries=('controlled_system',),
        preserves_microarchitecture_intent=(name=='wfi'))
    mappings=PrivilegedMappingRegistrySet(version='controlled-system.v1',registries=tuple(
        VersionedPrivilegedMappingRegistry('system-'+kind.value,'1',kind,items) for kind,items in (
            (PrivilegedMappingRegistryKind.STATE,()),(PrivilegedMappingRegistryKind.TRAP,trap),
            (PrivilegedMappingRegistryKind.INTERRUPT,wait),(PrivilegedMappingRegistryKind.MMU,()))))
    registry=PrivilegedRuntimeRegistry(version='controlled-system.v1',contracts=(contract,),mapping_registries=mappings)
    output.mkdir(parents=True)
    def write(name,value):
        p=output/name;p.write_text(json.dumps(value,indent=2)+'\n');return p
    execution=write('execution.json',execution_payload(facts));write('system.json',authority)
    runtime=write('runtime.json',runtime_payload(contract,registry));write('scope.json',shape)
    def copy(path):
        src=Path(path);dst=output/src.name
        if src!=dst:shutil.copyfile(src,dst)
        return {'path':dst.name,'digest':digest(dst.read_bytes())}
    impl=Path(backend['implementationDirectory'])
    deployment={'schemaVersion':'riscv2x86.privileged-deployment.v1','mechanismIdentity':backend['backendIdentity'],
        'runtimeRegistryDigest':digest(runtime.read_bytes()),'sources':[copy(impl/'controlled_system.c')],
        'headers':{'controlled_system.h':copy(impl/'controlled_system.h')},
        'libraries':{'controlled_system':copy(backend['runtimeLibrary'])},'capabilities':[cap],
        'rendererManifest':{'manifestId':'controlled-system-renderers','version':'1','entries':[{
            'semanticContractId':contract.semantic_contract_id,'planKind':'syscall_or_service_abi_adapter' if name=='ecall' else 'privileged_event_adapter',
            'rendererContractId':'controlled-system-runtime-call.v1'}]}}
    deployment['deploymentIdentity']=semantic_identity(deployment);write('deployment.json',deployment)
    manifest={'schemaVersion':'riscv2x86.privileged-environment.v2','sourceDigest':authority['sourceDigest'],
        'fragmentId':fragment_id,'operation':name,'relationKind':'architectural_equivalence',
        'sourceExecutionProfile':{'privilegeSpecVersion':'1.12','initialPrivilegeMode':'m','isaExtensions':['i','zicsr'],
            'interruptModel':facts.interrupt_model_id,'delegationModel':facts.delegation_model_id,'virtualizationModel':'none',
            'virtualMemoryModel':facts.virtual_memory_model_id,'addressSpaceIdentity':facts.address_space_identity,'csrAccessPolicy':facts.csr_access_policy_id},
        'runtimeContractSet':{'identity':'controlled-system','version':'1'},'targetProfile':{'os':'controlled-system',
            'abi':'sysv_amd64','cpuProfile':facts.target_cpu_feature_profile_id},'routeContract':route,
        'pipelineInputs':{'executionSidecar':'execution.json','runtimeRegistry':'runtime.json','systemInstructionAuthority':'system.json','deployment':'deployment.json'}}
    path=write('environment.json',manifest)
    from .privileged_environment import load_privileged_environment_manifest,validate_privileged_environment_pipeline_authority
    validate_privileged_environment_pipeline_authority(load_privileged_environment_manifest(path,source=source))
    return {'environmentPath':str(path),'scope':shape,'operation':name,'semanticApproval':False}
