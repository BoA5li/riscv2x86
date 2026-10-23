"""Real native runtime tests and explicit simulated source protocol tests.

The /bin/true backend fixture is NOT a QEMU production acceptance result.
Actual source execution lives in test_controlled_system_production.py.
"""
import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py import controlled_system_backend as backend_module
from riscv2x86_py.semantic_content import semantic_identity
from riscv2x86_py.system_instruction_ingress import digest,PROFILE


@pytest.fixture
def backend(tmp_path,monkeypatch):
    cc=shutil.which('gcc');ar=shutil.which('ar')
    if not cc or not ar:pytest.skip('native GCC/ar unavailable')
    impl=tmp_path/'implementation';impl.mkdir()
    for name in backend_module.FILES:shutil.copyfile(backend_module.ROOT/name,impl/name)
    obj=impl/'controlled_system.o';library=impl/'libcontrolled_system.a'
    subprocess.run([cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fPIC','-c',
        str(impl/'controlled_system.c'),'-I',str(impl),'-o',str(obj)],check=True)
    subprocess.run([ar,'rcs',str(library),str(obj)],check=True)
    value={'schemaVersion':backend_module.LEGACY_SCHEMA,'profile':PROFILE,'baseCommit':backend_module.BASE,
        'implementationIdentity':backend_module.implementation_identity(),'implementationDirectory':str(impl),
        'qemuBinary':'/bin/true','qemuBinaryDigest':digest(Path('/bin/true').read_bytes()),
        'sourceCompiler':sys.executable,'sourceCompilerDigest':digest(Path(sys.executable).read_bytes()),
        'sourceMarch':'rv64i_zicsr','targetCompiler':cc,'targetCompilerDigest':digest(Path(cc).read_bytes()),
        'runtimeLibrary':str(library),'runtimeLibraryDigest':digest(library.read_bytes()),
        'buildIdentity':semantic_identity({'fixture':'not-actual-QEMU'})}
    value['backendIdentity']=semantic_identity(value)
    path=tmp_path/'backend.json';path.write_text(json.dumps(value))
    original=backend_module.checked
    def simulated_source_version(command,**kwargs):
        if command==['/bin/true','--version']:
            return SimpleNamespace(stdout='QEMU emulator version 7.2.0 (simulated source protocol)\n',returncode=0)
        return original(command,**kwargs)
    monkeypatch.setattr(backend_module,'checked',simulated_source_version)
    monkeypatch.setattr(backend_module,'_CHECKED_QEMU_BINARIES',set())
    return path,value


@pytest.mark.parametrize('operation',['ecall','wfi'])
@pytest.mark.parametrize('optimization',['-O0','-O2','-O3'])
def test_native_runtime_rebuilt_and_actual_target_executed(backend,tmp_path,operation,optimization):
    from riscv2x86_py.controlled_system_runner import expected
    path,value=backend
    assert backend_module.validate_backend(path)==value
    source=tmp_path/'renamed.c'
    call='rv2x86_m_ecall_v1' if operation=='ecall' else 'rv2x86_m_wfi_pending_v1'
    source.write_text('void independent_name(void){'+call+'();}\n')
    output=tmp_path/'native/program.elf'
    result=backend_module.build_program(backend_path=path,side='target',source=source,
        symbol='independent_name',operation=operation,output=output,optimization=optimization)
    actual=subprocess.run([str(output)],capture_output=True,text=True,check=False)
    assert actual.returncode==0 and actual.stderr==''
    assert json.loads(actual.stdout.removeprefix('RV2X86_SYSTEM:'))==expected(operation)
    assert result['programDigest']==digest(output.read_bytes())


def test_rehashed_unrelated_archive_is_not_a_valid_runtime(backend):
    path,value=backend
    library=Path(value['runtimeLibrary']);library.write_bytes(b'not-the-shipped-library')
    value['runtimeLibraryDigest']=digest(library.read_bytes());value.pop('backendIdentity')
    value['backendIdentity']=semantic_identity(value);path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='RUNTIME_REBUILD_MISMATCH'):backend_module.validate_backend(path)


def test_modified_implementation_cannot_review_itself_by_rehash(tmp_path,monkeypatch):
    for name in backend_module.FILES:shutil.copyfile(backend_module.ROOT/name,tmp_path/name)
    (tmp_path/'controlled_system.c').write_text('void rv2x86_m_ecall_v1(void){}')
    monkeypatch.setattr(backend_module,'ROOT',tmp_path)
    with pytest.raises(ValueError,match='IMPLEMENTATION_NOT_REVIEWED'):backend_module.implementation_identity()


@pytest.mark.parametrize('operation',['ecall','wfi'])
def test_kernel_c_has_no_native_c_syntax_errors(backend,operation):
    _,value=backend
    # Syntax only: no claim that RV64 assembly has been built or executed.
    subprocess.run([value['targetCompiler'],'-std=gnu11','-Wall','-Wextra','-Werror','-fsyntax-only',
        '-D__RV2X86_OPERATION='+('1' if operation=='ecall' else '2'),
        str(backend_module.ROOT/'controlled_system_kernel.c')],check=True)


@pytest.mark.parametrize('word',[0x73,0x10500073])
def test_registered_contract_real_pcode_proof_renderer_and_loader(backend,tmp_path,monkeypatch,word):
    from riscv2x86_py import controlled_system_contract as contracts,mechanism_route_checks,controlled_system_scope
    from riscv2x86_py.schema import AsmFragment
    from riscv2x86_py.privileged_environment import load_privileged_environment_manifest
    from riscv2x86_py.privileged_pipeline_inputs import load_privileged_pipeline_inputs
    from riscv2x86_py.production_target_environment import production_target_environment
    from riscv2x86_py.phase6f_contract_registry import EMPTY_RENDERER_CONTRACT_REGISTRY,register_privileged_renderer_manifest
    from riscv2x86_py.lift import lift
    from riscv2x86_py.pcode_ir import from_lifted
    from riscv2x86_py.cfg import build_cfg_from_blocks
    from riscv2x86_py.privileged_state_analysis import analyze_privileged_state
    from riscv2x86_py.system_instruction_ingress import bind_system_instructions
    from riscv2x86_py.translate import translate
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    path,value=backend;operation='ecall' if word==0x73 else 'wfi'
    source=tmp_path/'independent.c';source.write_text('void renamed(void){__asm__ volatile("'+operation+'" ::: "memory");}\n')
    fragment=AsmFragment(id='different-fragment',enclosingFunction='renamed',rawAsmText=operation,isVolatile=True,clobbers=['memory'])
    finding={'fragment':asdict(fragment),'sourceDigest':digest(source.read_bytes()),'machineCodeHex':word.to_bytes(4,'little').hex()}
    monkeypatch.setattr(mechanism_route_checks,'compiler_bound_finding',lambda *a:(finding,{}))
    shape={'functionSymbol':'renamed','scopeIdentity':semantic_identity({'fixture':'compiler-scope-only'})}
    monkeypatch.setattr(controlled_system_scope,'scope',lambda *a:shape)
    prepared=contracts.prepare(source=source,report='simulated-compiler-report',fragment_id=fragment.id,
        backend_path=path,clang=sys.executable,output=tmp_path/'contracts')
    manifest=load_privileged_environment_manifest(prepared['environmentPath'],source=source)
    # Exercise actual JSON loading, with the same entry points used by the CLI.
    loaded=load_privileged_pipeline_inputs(execution_sidecar_path=manifest.execution_sidecar,
        runtime_registry_path=manifest.runtime_registry,system_instruction_authority_path=manifest.system_instruction_authority,
        deployment_path=manifest.deployment,functional_registry_path=None,observability_sidecar_path=None,
        ignored_state_declarations_path=None,allow_functional_fallbacks=False)
    facts=loaded.execution_sidecar.facts_for(fragment.id)
    result=lift(word.to_bytes(4,'little'),xlen=64,base_addr=0x10000,require_authoritative_register_names=True)
    bind_system_instructions(result,machine_code=word.to_bytes(4,'little'),base_addr=0x10000,
        source_digest=finding['sourceDigest'],fragment_id=fragment.id,facts=facts,authority=loaded.system_instruction_authority)
    blocks,summary=from_lifted(result.insns);cfg=build_cfg_from_blocks(blocks)
    state=analyze_privileged_state(fragment_id=fragment.id,blocks=blocks,cfg=cfg,execution_facts=facts)
    from riscv2x86_py.privileged_source_state import complete_privileged_source_state
    from riscv2x86_py.csr_value_flow import authority_from_phase4_facts
    from riscv2x86_py.source_model import build_source_semantic_model
    from riscv2x86_py.privileged_runtime_contracts import privileged_source_identity
    legacy_state=state
    state=complete_privileged_source_state(state=state,fragment=fragment,lifted_insns=result.insns,
        blocks=blocks,cfg=cfg,execution_facts=facts,
        csr_operand_authority=authority_from_phase4_facts(lifted_insns=result.insns,runtime_facts=TranslationRuntimeFacts()))
    prepared_model=contracts.source_model(finding,facts,loaded.system_instruction_authority)
    actual=build_source_semantic_model(fragment=fragment,blocks=blocks,cfg=cfg,summary=summary,
        runtime_facts=TranslationRuntimeFacts(),xlen=64,privileged_state=state)
    legacy=build_source_semantic_model(fragment=fragment,blocks=blocks,cfg=cfg,summary=summary,
        runtime_facts=TranslationRuntimeFacts(),xlen=64,privileged_state=legacy_state)
    assert prepared_model.privileged_state.state==actual.privileged_state.state
    assert privileged_source_identity(prepared_model.privileged_state)==privileged_source_identity(actual.privileged_state)
    assert privileged_source_identity(legacy.privileged_state)!=privileged_source_identity(actual.privileged_state)
    target=production_target_environment(runtime_registry=loaded.runtime_registry,deployment=loaded.deployment)
    renderer=register_privileged_renderer_manifest(EMPTY_RENDERER_CONTRACT_REGISTRY,loaded.deployment.renderer_manifest)
    # Exercise pipeline.run's actual model completion, not a second hand-built
    # Phase-6 model. Only the external assembler is supplied as a protocol fixture.
    from riscv2x86_py import pipeline
    from riscv2x86_py.assemble import AssembleResult
    from riscv2x86_py.schema import Finding, save_report, load_report
    monkeypatch.setattr(pipeline,'assemble',lambda *_a,**_k:AssembleResult(
        True,word.to_bytes(4,'little'),[],translation_runtime_facts=TranslationRuntimeFacts()))
    pipeline_input=tmp_path/'pipeline-in.json';pipeline_output=tmp_path/'pipeline-out.json'
    save_report([Finding(fragment=fragment,sourceDigest=finding['sourceDigest'])],str(pipeline_input))
    pipeline.run(str(pipeline_input),str(pipeline_output),verify_enabled=False,privileged_pipeline_inputs=loaded)
    actual_finding=load_report(str(pipeline_output))[0]
    assert actual_finding.approvalArtifact.get('proofStatus')=='approved',(
        actual_finding.verificationDetail,actual_finding.translationPlanAttempts)
    assert actual_finding.approvalArtifact['systemOperation']==operation
    assert actual_finding.translationOutcome=='emitted'
    assert actual_finding.publicationOutcome=='withheld'
    assert 'rv2x86_m_' in actual_finding.translationAttemptArtifact['candidateReplacement']
    # A legacy/incomplete-state contract must still fail in pipeline.run, and
    # its actual expected/observed identities must survive report serialization.
    from riscv2x86_py.privileged_runtime_contracts import PrivilegedRuntimeRegistry
    current_contract=loaded.runtime_registry.resolve(actual.privileged_state,target)
    assert current_contract is not None
    stale=replace(current_contract,source_privileged_identity=privileged_source_identity(legacy.privileged_state))
    stale_registry=PrivilegedRuntimeRegistry(version=loaded.runtime_registry.version,contracts=(stale,),
        mapping_registries=loaded.runtime_registry.mapping_registries)
    stale_output=tmp_path/'pipeline-stale.json'
    pipeline.run(str(pipeline_input),str(stale_output),verify_enabled=False,
        privileged_pipeline_inputs=replace(loaded,runtime_registry=stale_registry))
    rejected=load_report(str(stale_output))[0]
    assert rejected.translationOutcome=='unsupported'
    assert rejected.translationPlanAttempts[0]['details']['resolutionReason']=='source_identity_mismatch'
    assert rejected.translationPlanAttempts[0]['details']['expectedSourceIdentity']==stale.source_privileged_identity
    translated=translate(fragment,result,summary,word.to_bytes(4,'little'),64,blocks=blocks,cfg=cfg,
        runtime_facts=TranslationRuntimeFacts(),target_environment=target,privileged_state=state,
        privileged_runtime_registry=loaded.runtime_registry,renderer_contract_registry=renderer)
    assert 'rv2x86_m_' in translated.replacement,(translated.kind,translated.reason_codes,translated.notes)
    assert translated.metadata['approvalArtifact']['systemOperation']==operation
    from riscv2x86_py.pipeline import _phase7_shell_semantics_blockers
    from riscv2x86_py.schema import Finding
    assert not _phase7_shell_semantics_blockers(Finding(fragment=fragment,approvalArtifact=translated.metadata['approvalArtifact']),translated)
    from riscv2x86_py.automatic_l2_authority import _proof_effect_authority
    assert _proof_effect_authority(translated.metadata['approvalArtifact'],fragment.id) is not None
    from riscv2x86_py.automatic_l2_authority import _system_runtime_authority_checked
    approval=translated.metadata['approvalArtifact']
    approval['l2FragmentOperandBoundary']={'complete':True,'asmOperandDeclarationIds':[],
        'asmOperandValueNodeIdentities':[]}
    finding.update(approvalArtifact=approval,suggestedReplacement=translated.replacement)
    authority=_system_runtime_authority_checked(finding,[{'name':'renamed','l2OperandBoundary':{
        'declarations':{},'parameterDeclarationIds':[],'returnDeclarationId':'','declarationReferenceCounts':{}}}],
        semantic_identity({'producer':'explicit-compiler-protocol-fixture'}))
    assert authority.complete
    # Real native execution + explicit simulated source transport exercises
    # the runner and persisted central evidence, never QEMU acceptance.
    from riscv2x86_py import controlled_system_runner as runner
    from riscv2x86_py.translation_validation import ProgramArtifact,ValidationLevel
    report=tmp_path/'approved.json';report.write_text(json.dumps({'findings':[finding]}))
    candidate=tmp_path/'candidate.c';candidate.write_text('void renamed(void){'+translated.replacement+'}\n')
    executable=tmp_path/'native/program.elf'
    built=backend_module.build_program(backend_path=path,side='target',source=candidate,symbol='renamed',
        operation=operation,output=executable)
    source_program=tmp_path/'simulated-source-transport';source_program.write_bytes(b'explicit source protocol fixture')
    config={'schemaVersion':runner.SCHEMA,'backendPath':str(path),'approvalPath':str(report),
        'environmentPath':prepared['environmentPath'],'sourcePath':str(source),'sourceDigest':finding['sourceDigest'],
        'frontend':sys.executable,'frontendDigest':digest(Path(sys.executable).read_bytes()),
        'clang':sys.executable,'clangDigest':digest(Path(sys.executable).read_bytes()),'targetPath':str(candidate),
        'scope':shape,'operation':operation,'observerIdentity':runner.observer_identity(),'timeoutSeconds':30}
    original_finding=runner.approved_finding;original_observe=runner.observe
    monkeypatch.setattr(runner,'approved_finding',lambda c,a:original_finding(c,a,replay=False))
    monkeypatch.setattr(controlled_system_scope,'target_scope',lambda *a:None)
    def observe(side,program,backend,timeout):
        if side=='target':return original_observe(side,program,backend,timeout)
        state=runner.expected(operation)
        return {'side':side,'programDigest':program['digest'],'command':[backend['qemuBinary'],'-machine','virt',
            '-cpu',backend_module.CPU_PROFILE,'-smp','1','-m','32M','-bios','none','-nographic','-monitor','none','-kernel',program['path']],
            'returnCode':0,'timedOut':False,'stdout':'RV2X86_SYSTEM:'+json.dumps(state)+'\n','stderr':'',
            'runnerBinaryDigest':backend['qemuBinaryDigest'],'state':state}
    monkeypatch.setattr(runner,'observe',observe)
    artifact=SimpleNamespace(fragment_id=fragment.id,proof_identity=approval['proofIdentity'],
        l2_authority_identity=authority.authority_identity,effect_relation_set_identity=authority.effect_relation_set_identity,
        l2_authority_complete=True,target_route='privileged_runtime',runtime_contract_id=approval['runtimeContractId'],
        runtime_contract_version=approval['runtimeContractVersion'])
    for level in (ValidationLevel.L1,ValidationLevel.L2):
        result=runner.run(config,level=level,translation_artifact=artifact,
            target_environment={'environmentId':runner.environment_id(runner.environment(config))},
            source_program_artifact=ProgramArtifact('source',str(source_program),'executable',digest(source_program.read_bytes()),semantic_identity({'build':'source-fixture'})),
            target_program_artifact=ProgramArtifact('target',str(executable),'executable',built['programDigest'],semantic_identity(built)),
            l2_provider_id='system-protocol-fixture',l2_provider_dimensions=runner.DIMENSIONS)
        assert result.status.value=='verified',result.detail
        runner.validate_persisted_result(json.loads(result.detail))
    from riscv2x86_py.approved_replacement import approved_replacement
    finding['suggestedReplacement']+=' /* changed */'
    with pytest.raises(ValueError,match='CANDIDATE_APPROVAL_TEXT_MISMATCH'):approved_replacement(finding)


def wire_result(operation='ecall'):
    from riscv2x86_py.controlled_system_runner import RESULT,LIMITATIONS,expected,environment_id
    binding={'backendIdentity':semantic_identity({'backend':1}),'qemuBinary':'/actual/qemu',
        'qemuBinaryDigest':semantic_identity({'binary':1}),'observerIdentity':semantic_identity({'observer':1})}
    binding['environmentProfileIdentity']=semantic_identity(binding)
    programs={side:{'path':'/actual/'+side,'digest':semantic_identity({'side':side}),
        'buildIdentity':semantic_identity({'build':side})} for side in ('source','target')}
    executions={}
    for side in programs:
        executions[side]={'side':side,'programDigest':programs[side]['digest'],
            'command':(['/actual/qemu','-machine','virt','-cpu',backend_module.CPU_PROFILE,'-smp','1','-m','32M','-bios','none',
                '-nographic','-monitor','none','-kernel','/actual/source'] if side=='source' else ['/actual/target']),
            'returnCode':0,'timedOut':False,'stderr':'','stdout':'RV2X86_SYSTEM:'+json.dumps(expected(operation))+'\n',
            'state':expected(operation),'runnerBinaryDigest':binding['qemuBinaryDigest'] if side=='source' else programs[side]['digest']}
    value={'schemaVersion':RESULT,'level':'L1','status':'verified','notClaimedProperties':LIMITATIONS,
        'environment':binding,'environmentId':environment_id(binding),'nonce':{'programs':programs,'operation':operation,
            'backendIdentity':binding['backendIdentity'],'observerIdentity':binding['observerIdentity']},
        'executions':executions,'claimScope':'architectural','claimBoundary':'bounded-m-mode-trap-or-prepending-event-logical-state'}
    value['evidenceIdentity']=semantic_identity(value);return value


@pytest.mark.parametrize('operation',['ecall','wfi'])
def test_persisted_real_observation_protocol_rechecks_raw_state_and_binding(operation):
    from riscv2x86_py.controlled_system_runner import validate_persisted_result
    validate_persisted_result(wire_result(operation))


@pytest.mark.parametrize('mutation',['events','state','stdout','stderr','exit','runner','environment','limitations','operation'])
def test_rehashed_protocol_mutation_never_verifies(mutation):
    from riscv2x86_py.controlled_system_runner import validate_persisted_result
    value=copy.deepcopy(wire_result());record=value['executions']['target']
    if mutation=='events':record['state']['events']=[1,3,2]
    if mutation=='state':record['state']['mcause']=0
    if mutation=='stdout':record['stdout']='RV2X86_SYSTEM:{}\n'
    if mutation=='stderr':record['stderr']='execution failed'
    if mutation=='exit':record['returnCode']=1
    if mutation=='runner':record['command']=['/other/target']
    if mutation=='environment':value['environment']['qemuBinary']='/other/qemu'
    if mutation=='limitations':value['notClaimedProperties']=[]
    if mutation=='operation':value['nonce']['operation']='wfi'
    value.pop('evidenceIdentity');value['evidenceIdentity']=semantic_identity(value)
    with pytest.raises(ValueError):validate_persisted_result(value)


def test_outer_native_label_cannot_hide_controlled_m_mode_execution():
    from riscv2x86_py.controlled_time_environment import audit_case_environment
    detail=wire_result()
    case={'targetEnvironment':{'environmentId':'native-linux-user'},'attempts':[{'validation':{'layers':[
        {'level':'L1','detail':json.dumps(detail),'evidenceIdentity':detail['evidenceIdentity']} ]}}]}
    with pytest.raises(ValueError,match='SYSTEM_CASE_LAYER_ENVIRONMENT_MISMATCH'):audit_case_environment(case)
    case['targetEnvironment']['environmentId']=detail['environmentId']
    audit_case_environment(case)


@pytest.mark.parametrize('side',['source','target'])
def test_timeout_retains_partial_execution_and_cannot_be_verified(monkeypatch,side):
    from riscv2x86_py import controlled_system_runner as runner
    value=wire_result();programs=value['nonce']['programs'];binding=value['environment']
    def timeout(*a,**kw):raise subprocess.TimeoutExpired(a[0],1,output=b'partial wire',stderr=b'')
    monkeypatch.setattr(runner.subprocess,'run',timeout)
    record=runner.observe(side,programs[side],binding,1)
    assert record['timedOut'] is True and record['stdout']=='partial wire' and record['command']
    value['executions'][side]=record
    assert runner.execution_status(value['executions'],programs,'ecall').value=='inconclusive'
    value['status']='inconclusive';value.pop('evidenceIdentity');value['evidenceIdentity']=semantic_identity(value)
    runner.validate_persisted_result(value)


@pytest.mark.parametrize('selected',[False,True])
def test_inventory_routes_builds_layers_and_environment_together(tmp_path,monkeypatch,selected):
    # Inventory wiring only; this test does not manufacture a production pass.
    from riscv2x86_py import automatic_batch_cli as auto,controlled_system_runner as runner
    source=tmp_path/'new_name.c';source.write_text('void another_name(void){}')
    frontend=tmp_path/'frontend';frontend.write_text('#!/bin/sh\n');frontend.chmod(0o755)
    monkeypatch.setattr(auto,'inspect_entry_points',lambda *a:(False,({'name':'another_name','arity':0,
        'returnType':'void','parameterTypes':[]},)))
    provider={'validatorType':'controlled-system-validation','providerId':'fixture','config':{
        'backendPath':'/declared/backend','scope':{'functionSymbol':'another_name'},'operation':'ecall'}}
    monkeypatch.setattr(auto,'_explicit_l2_providers',lambda *a:((provider,),('privileged_state_observation','shell_observation')) if selected else ((),()))
    binding=wire_result()['environment']
    monkeypatch.setattr(runner,'environment',lambda *a:binding)
    inventory=tmp_path/'inventory'
    result=auto.prepare_automatic_inventory(source,inventory,frontend=frontend)
    descriptor=json.loads(next((inventory/'cases').rglob('riscv2x86-evaluation.json')).read_text())
    request=descriptor['request'];validators=request['runtimeRegistryTemplate']['validators']
    if selected:
        assert all(validators[level]['type']=='controlled-system-validation' for level in ('L0','L1'))
        assert validators['L2']['config']['executionProfile']==runner.EXECUTION_PROFILE
        assert all(request[side+'Build']['artifactKind']=='executable' for side in ('source','target'))
        assert all('riscv2x86_py.controlled_system_backend' in request[side+'Build']['command'] for side in ('source','target'))
        env=json.loads(Path(request['targetEnvironment']).read_text())
        assert env['environmentId']==runner.environment_id(binding)
        assert env['sourceRunnerCapabilities']==['custom','qemu-system']
        assert result['programs'][0]['executionEnvironment']==binding
    else:
        assert validators['L1']['type']=='automatic-l1-functional-differential'
        assert request['targetBuild']['artifactKind']=='shared_library'
