"""Deployment/manifest protocol fixtures; no fake QEMU production verdicts."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import pytest
from riscv2x86_py.semantic_content import semantic_identity,semantic_payload
from riscv2x86_py.system_instruction_ingress import digest
from riscv2x86_py.privileged_deployment import load_privileged_deployment,SCHEMA
from tests.test_system_instruction_ingress import registry_fixture


def camel(value):
    if isinstance(value,dict):
        def key(name):
            head,*rest=name.split('_');return head+''.join(x.title() for x in rest)
        return {key(k):camel(v) for k,v in value.items()}
    if isinstance(value,list):return [camel(x) for x in value]
    return value


def registry_json(registry,contract):
    from riscv2x86_py.privileged_runtime_contracts import PRIVILEGED_RUNTIME_REGISTRY_SCHEMA
    return {'schemaVersion':PRIVILEGED_RUNTIME_REGISTRY_SCHEMA,'version':registry.version,
        'contracts':[camel(semantic_payload(contract))], 'mappingRegistryVersion':registry.mapping_registries.version,
        'mappingRegistries':[camel(semantic_payload(r)) for r in registry.mapping_registries._registries.values()]}


def seal(value):
    value=copy.deepcopy(value);value.pop('deploymentIdentity',None)
    value['deploymentIdentity']=semantic_identity(value);return value


def fixture(tmp_path, word=0x73, contract=None):
    source,target,c,registry=registry_fixture(word);c=contract or c
    raw=registry_json(registry,c)
    registry_path=tmp_path/'runtime.json';registry_path.write_text(json.dumps(raw))
    def artifact(name,content):
        p=tmp_path/name;p.write_bytes(content)
        return {'path':name,'digest':digest(p.read_bytes())}
    value={'schemaVersion':SCHEMA,'mechanismIdentity':'sha256:'+'b'*64,
        'runtimeRegistryDigest':digest(registry_path.read_bytes()),
        'sources':[artifact('runtime.c',b'/* deployment fixture, not an implementation claim */')],
        'headers':{'reviewed_system.h':artifact('reviewed_system.h',b'void reviewed_system_adapter(void);')},
        'libraries':{'reviewed_system':artifact('library.a',b'fixture for dependency checks only')},
        'capabilities':list(c.required_capabilities), 'rendererManifest':{'manifestId':'reviewed-test-deployment',
            'version':'1','entries':[{'semanticContractId':c.semantic_contract_id,
                'planKind':'syscall_or_service_abi_adapter' if word==0x73 else 'privileged_event_adapter',
                'rendererContractId':'system-call.v1'}]}}
    path=tmp_path/'deployment.json';path.write_text(json.dumps(seal(value)))
    return path,registry_path,value,c,registry


@pytest.mark.parametrize('word',[0x73,0x10500073])
def test_deployment_ingress_installs_only_explicit_artifact_bound_recipes_and_capabilities(tmp_path,word):
    from riscv2x86_py.production_target_environment import production_target_environment
    path,runtime,raw,c,registry=fixture(tmp_path,word)
    absent=production_target_environment(runtime_registry=registry)
    assert c.required_target_capability not in absent.helper_contract_capabilities
    deployment=load_privileged_deployment(path,runtime_registry_path=runtime)
    installed=production_target_environment(runtime_registry=registry,deployment=deployment)
    assert c.required_target_capability in installed.helper_contract_capabilities
    assert deployment.identity in deployment.renderer_manifest.manifest_id
    assert deployment.renderer_manifest.entries[0].callable_identifier==c.callable_identifier


@pytest.mark.parametrize('mutation',['source','library','escape','registry','extra-capability','missing-library',
    'wrong-kind','missing-renderer','mechanism','identity'])
def test_changed_or_inconsistent_deployment_cannot_install_a_helper(tmp_path,mutation):
    path,runtime,raw,c,registry=fixture(tmp_path)
    if mutation=='source':(tmp_path/'runtime.c').write_text('changed')
    if mutation=='library':(tmp_path/'library.a').write_text('changed')
    if mutation=='escape':raw['libraries']['reviewed_system']['path']='../outside'
    if mutation=='registry':runtime.write_text('{}')
    if mutation=='extra-capability':raw['capabilities']=sorted([*raw['capabilities'],'unreviewed-capability'])
    if mutation=='missing-library':raw['libraries']={}
    if mutation=='wrong-kind':raw['rendererManifest']['entries'][0]['planKind']='privileged_event_adapter'
    if mutation=='missing-renderer':raw['rendererManifest']['entries']=[]
    if mutation=='mechanism':raw['mechanismIdentity']='yes'
    selected=seal(raw)
    if mutation=='identity':selected['deploymentIdentity']='sha256:'+'f'*64
    path.write_text(json.dumps(selected))
    with pytest.raises(ValueError,match='PRIV_DEPLOYMENT_'):
        load_privileged_deployment(path,runtime_registry_path=runtime)


def execution_file(tmp_path,facts):
    # Explicit V2 declaration, round-tripped through the actual production parser.
    from riscv2x86_py.privileged_execution_sidecar import load_privileged_execution_sidecar
    raw=camel(semantic_payload(facts))
    raw.pop('schemaVersion');raw.pop('userCounterBackendIdentity')
    raw['addressSpaceIdentity']=raw.pop('addressSpace')
    raw['virtualMemoryModel']['vmidWidthBits']=None
    path=tmp_path/'execution.json';path.write_text(json.dumps({'schemaVersion':facts.schema_version,
        'provenance':facts.provenance,'fragments':[raw]}))
    actual=load_privileged_execution_sidecar(path).facts_for(facts.fragment_id)
    assert actual==facts
    return path


@pytest.mark.parametrize('word',[0x73,0x10500073])
def test_v2_environment_binds_real_execution_system_authority_route_and_deployment(tmp_path,word):
    from riscv2x86_py.privileged_environment import load_privileged_environment_manifest,validate_privileged_environment_pipeline_authority
    from tests.test_system_instruction_ingress import environment,authority
    facts=environment();source=tmp_path/'renamed.c';source.write_text('/* compiler protocol fixture */')
    execution=execution_file(tmp_path,facts)
    name='ecall' if word==0x73 else 'wfi'
    system=authority(word.to_bytes(4,'little'),facts,source_digest=digest(source.read_bytes()))
    (tmp_path/'system.json').write_text(json.dumps(system))
    route={'runtimeAdapterIdentity':'reviewed_system_adapter','targetMechanism':'registered-runtime-adapter',
        'preservedSemantics':['architectural_state'],'notPreservedSemantics':[]}
    if name=='ecall':
        route.update(serviceModel='trap-only',trapHandlerIdentity=facts.trap_handler_binding.handler_identity,
            clobbers='all-gprs-preserved',memoryEffects='reviewed-memory-relation',
            continuation=facts.trap_handler_binding.continuation_model_id,addressSpaceRelation='reviewed-address-relation')
    else:
        route.update(interruptEnableState=facts.interrupt_model_id+':enable',pendingInterruptModel=facts.interrupt_model_id,
            delegationRelation=facts.delegation_model_id,virtualizationRelation='none',
            trapWakeupContinuation='reviewed-wait-relation',spuriousWakeupPolicy='permitted',
            targetWaitAdapter='reviewed_system_adapter',schedulerRuntimeInteraction='reviewed-scheduler-relation')
    c=registry_fixture(word)[2]
    c=replace(c,environment_contract_id=semantic_identity(route),preserved_environment_semantics=('architectural_state',))
    deployment,runtime,raw,_,_=fixture(tmp_path,word,c)
    manifest={'schemaVersion':'riscv2x86.privileged-environment.v2','sourceDigest':digest(source.read_bytes()),
        'fragmentId':'frag','operation':name,'relationKind':'architectural_equivalence',
        'sourceExecutionProfile':{'privilegeSpecVersion':'1.12','initialPrivilegeMode':'m','isaExtensions':['i','zicsr'],
            'interruptModel':facts.interrupt_model_id,'delegationModel':facts.delegation_model_id,
            'virtualizationModel':'none','virtualMemoryModel':facts.virtual_memory_model_id,
            'addressSpaceIdentity':facts.address_space_identity,'csrAccessPolicy':facts.csr_access_policy_id},
        'runtimeContractSet':{'identity':'test-runtime','version':'1'},
        'targetProfile':{'os':facts.os_or_runtime_identity,'abi':'sysv_amd64','cpuProfile':facts.target_cpu_feature_profile_id},
        'routeContract':route,'pipelineInputs':{'executionSidecar':execution.name,'runtimeRegistry':runtime.name,
            'systemInstructionAuthority':'system.json','deployment':deployment.name}}
    path=tmp_path/'environment.json';path.write_text(json.dumps(manifest))
    loaded=load_privileged_environment_manifest(path,source=source)
    validate_privileged_environment_pipeline_authority(loaded)
    # Correct memory identity cannot disguise a different virtualization model.
    manifest['sourceExecutionProfile']['virtualizationModel']=facts.virtual_memory_model_id
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='EXECUTION_DOMAIN_UNSUPPORTED'):
        validate_privileged_environment_pipeline_authority(load_privileged_environment_manifest(path,source=source))
