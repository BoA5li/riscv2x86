"""Protocol/decoder regression. Synthetic source fixtures are not production."""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import pytest

from riscv2x86_py import l3_system_route as route
from riscv2x86_py import controlled_system_runner as system
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.l3_trace_support import identity
from tests.test_l3_production_acceptance import evaluated


@pytest.mark.parametrize('operation', ['ecall','wfi'])
def test_whole_entry_decoder_with_real_native_direct_call(tmp_path, monkeypatch, operation):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('native GCC required')
    source = tmp_path/'target.c'; elf = tmp_path/'target'
    source.write_text('void adapter(void){__asm__ volatile("" ::: "memory");}'
                      'void entry(void){adapter();} int main(void){entry();return 0;}')
    subprocess.run([cc,'-O0','-fno-inline','-fno-pie','-no-pie',str(source),'-o',str(elf)], check=True)
    original = route.Elf
    class Source:
        machine = 243
        def symbol(self, name): return (0x10000, 8, 1, 2)
        def code(self, name):
            return bytes.fromhex('73000000' if operation=='ecall' else '73005010')+bytes.fromhex('67800000')
    monkeypatch.setattr(route, 'Elf', lambda path: Source() if path=='synthetic-source' else original(path))
    programs = {'source':{'path':'synthetic-source'}, 'target':{'path':str(elf)}}
    result = route.mechanism(programs, {'scope':{'functionSymbol':'entry'},'operation':operation},
                             {'approvalArtifact':{'privilegedCallableIdentifier':'adapter'}})
    assert result['sourceEntry']['operationPC'] == 0x10000
    assert result['hardwarePCTraceObserved'] is False
    with pytest.raises(ValueError):
        route.mechanism(programs, {'scope':{'functionSymbol':'entry'},'operation':'wfi' if operation=='ecall' else 'ecall'},
                        {'approvalArtifact':{'privilegedCallableIdentifier':'adapter'}})


def test_legacy_runner_cannot_silently_label_an_l1_execution_as_l3():
    result = system.run({}, level=ValidationLevel.L3)
    assert result.status.value == 'inconclusive'
    assert 'SYSTEM_LEGACY_RUNNER_L3_POLICY_REQUIRED' in result.detail


def accepted_fixture(tmp_path, monkeypatch):
    report = evaluated(tmp_path)
    attempt = report['attempts'][0]
    layers = attempt['validation']['layers']
    programs = {side:{'path':report[side+'ProgramArtifact']['artifact_path'],
        'digest':report[side+'ProgramArtifact']['artifact_digest'],
        'buildIdentity':report[side+'ProgramArtifact']['build_identity']} for side in ('source','target')}
    from riscv2x86_py.translation_validation import translation_artifact_from_dict
    artifact = translation_artifact_from_dict(attempt['translationArtifact'])
    from riscv2x86_py.translation_validation import program_artifact_from_dict
    from riscv2x86_py.l3_execution_context import L3ExecutionContext
    context = L3ExecutionContext.create(program_artifact_from_dict(report['sourceProgramArtifact']),
                                        program_artifact_from_dict(report['targetProgramArtifact']))
    binding = {'backendIdentity':identity('backend'), 'observerIdentity':identity('observer'),
               'qemuBinary':'/synthetic/qemu','qemuBinaryDigest':identity('qemu')}
    binding['environmentProfileIdentity'] = system.semantic_identity(binding)
    config = {'operation':'ecall'}
    executions = {}
    for side in ('source','target'):
        command = ([binding['qemuBinary'],'-machine','virt','-cpu',system.CPU_PROFILE,'-smp','1',
            '-m','32M','-bios','none','-nographic','-monitor','none','-kernel',programs[side]['path']]
            if side=='source' else [programs[side]['path']])
        state = system.expected('ecall')
        executions[side] = {'side':side, 'programDigest':programs[side]['digest'], 'command':command,
            'returnCode':0, 'timedOut':False, 'stdout':'RV2X86_SYSTEM:'+json.dumps(state)+'\n', 'stderr':'',
            'state':state, 'runnerBinaryDigest':binding['qemuBinaryDigest'] if side=='source' else programs[side]['digest']}
    observation = {'schemaVersion':system.RESULT, 'level':'L1','status':'verified',
        'notClaimedProperties':system.LIMITATIONS, 'executions':executions,
        'environment':binding,'environmentId':system.environment_id(binding),
        'fragmentId':artifact.fragment_id,'proofIdentity':artifact.proof_identity,
        'claimScope':'architectural','claimBoundary':'bounded-m-mode-trap-or-prepending-event-logical-state',
        'nonce':{'programs':programs,'operation':'ecall','backendIdentity':binding['backendIdentity'],
                 'observerIdentity':binding['observerIdentity'],'runId':'synthetic-protocol-only'}}
    observation['evidenceIdentity'] = system.semantic_identity(observation)
    detail = route._seal({'schemaVersion':route.SCHEMA,'status':'verified','policy':route.POLICY,
        'implementationIdentity':route.implementation_identity(),
        'systemL3':True,'claimScope':'bounded-controlled-environment-intent',
        'physicalMicroarchitectureEquivalenceClaimed':False,'fragmentId':artifact.fragment_id,
        'translationArtifactIdentity':artifact.identity,'proofIdentity':artifact.proof_identity,
        'environmentId':system.environment_id(binding),'config':config,'programs':programs,
        'machineMechanism':{'synthetic':'machine-fixture'},'observation':observation,
        'systemIntent':{'reportPath':'fixture-report','specification':{'targetCallable':'adapter'},
                        'requirementManifest':report['translationEvaluationLink']['l3Requirements']},
        'executionBindings':{side:context.request_binding(side) for side in ('source','target')},
        'prerequisites':{r['level']:r['evidenceIdentity'] for r in layers[:3]}})
    layers[-1].update(detail=json.dumps(detail), evidenceIdentity=detail['evidenceIdentity'])
    layers[0]['detail'] = json.dumps({'schemaVersion':system.RESULT,'level':'L0','builds':[]})
    report['targetEnvironment'] = {'environmentId':detail['environmentId']}
    report['validationPlan'] = {'profile':'microarch','experimentContractId':route.POLICY['policyId']}
    monkeypatch.setattr(system,'load_config',lambda c:{'buildProfile':{}})
    monkeypatch.setattr(route,'require_build_profile',lambda c:c['buildProfile'])
    monkeypatch.setattr(system,'approved_finding',lambda c,a: {'finding':'fixture'})
    monkeypatch.setattr(system,'environment',lambda c:deepcopy(binding))
    monkeypatch.setattr(system,'audit_case_environment',lambda *a:None)
    calls = []
    monkeypatch.setattr(route,'rebuild',lambda *a:calls.append('rebuilt'))
    monkeypatch.setattr(route,'mechanism',lambda *a:{'synthetic':'machine-fixture'})
    monkeypatch.setattr(route,'intent_evidence',lambda *a:deepcopy(detail['systemIntent']))
    index = tmp_path/'index.json'
    import riscv2x86_py.l2_evidence_reader as reader
    import riscv2x86_py.l2_provider_artifacts as providers
    monkeypatch.setattr(reader,'read_l2_fragment_results',lambda r:[('attempt',SimpleNamespace(
        provider_evidence_index={'artifactPath':str(index)}))])
    monkeypatch.setattr(providers,'read_provider_evidence',lambda *a,**k:[{'providerDefinition':{
        'validatorType':'controlled-system-validation','config':config}}])
    return report, calls


def test_explicit_policy_audit_replays_before_acceptance(tmp_path, monkeypatch):
    report, calls = accepted_fixture(tmp_path,monkeypatch)
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    result = audit_evaluation(report)
    assert result['status']=='verified' and calls==['rebuilt']
    assert not result['physicalMicroarchitectureEquivalenceClaimed']


@pytest.mark.parametrize('mutation',['no-l3','extra-attempt','wrong-policy','missing-l2',
    'stale-program','wrong-machine','boolean-state','boolean-return','duplicate-state-key',
    'wrong-operation','wrong-environment','wrong-prerequisite'])
def test_rehashed_records_cannot_erase_obligations(tmp_path, monkeypatch, mutation):
    report, _ = accepted_fixture(tmp_path,monkeypatch)
    layers = report['attempts'][0]['validation']['layers']
    detail = json.loads(layers[-1]['detail'])
    if mutation=='no-l3': layers.pop()
    elif mutation=='extra-attempt': report['attempts'].append(deepcopy(report['attempts'][0]))
    elif mutation=='wrong-policy': detail['policy']['excluded']=[]
    elif mutation=='missing-l2': layers[2]['status']='not_run'
    elif mutation=='stale-program': Path(detail['programs']['source']['path']).write_bytes(b'changed')
    elif mutation=='wrong-machine': detail['machineMechanism']['synthetic']='changed'
    elif mutation=='boolean-state':
        observation = detail['observation']; observation['executions']['source']['state']['operation']=True
        observation['evidenceIdentity']=system.semantic_identity({k:v for k,v in observation.items() if k!='evidenceIdentity'})
    elif mutation in ('boolean-return','duplicate-state-key'):
        observation = detail['observation']
        record = observation['executions']['source']
        if mutation=='boolean-return':record['returnCode']=False
        else:record['stdout']=record['stdout'].replace('"operation": 1','"operation": 9, "operation": 1')
        observation['evidenceIdentity']=system.semantic_identity({k:v for k,v in observation.items() if k!='evidenceIdentity'})
    elif mutation=='wrong-operation': detail['config']['operation']='wfi'
    elif mutation=='wrong-environment': detail['environmentId']='native-linux'
    elif mutation=='wrong-prerequisite': detail['prerequisites']['L2']=identity('other')
    if mutation!='no-l3':
        detail=route._seal({k:v for k,v in detail.items() if k!='evidenceIdentity'})
        layers[-1].update(detail=json.dumps(detail),evidenceIdentity=detail['evidenceIdentity'])
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    with pytest.raises((ValueError,KeyError)): audit_evaluation(report)


def test_missing_prerequisites_never_starts_backend():
    result = route.run({}, level=ValidationLevel.L3, prior_layer_results=())
    assert result.status.value=='inconclusive'
    assert 'COMPLETED_PREREQUISITES_REQUIRED' in result.detail


def test_l3_run_starts_new_observation_and_emits_bound_context(tmp_path,monkeypatch):
    report,calls=accepted_fixture(tmp_path,monkeypatch)
    layers=report['attempts'][0]['validation']['layers']
    old=json.loads(layers[3]['detail'])
    intent=old['systemIntent']
    intent['profile']={'fixture':'profile'}
    monkeypatch.setattr(route,'intent_evidence',lambda *a:deepcopy(intent))
    from riscv2x86_py.translation_validation import (program_artifact_from_dict, translation_artifact_from_dict,
        ValidationLayerResult)
    from riscv2x86_py.validation_status import ValidationStatus
    from riscv2x86_py.l3_execution_context import L3ExecutionContext
    source=program_artifact_from_dict(report['sourceProgramArtifact'])
    target=program_artifact_from_dict(report['targetProgramArtifact'])
    invoked=[]
    def observe(c,**kwargs):
        invoked.append(kwargs['level'])
        return ValidationLayerResult(ValidationLevel.L1,ValidationStatus.VERIFIED,
            old['observation']['evidenceIdentity'],json.dumps(old['observation']))
    monkeypatch.setattr(system,'run',observe)
    prior=tuple(ValidationLayerResult(ValidationLevel(r['level']),ValidationStatus.VERIFIED,
        r['evidenceIdentity'],r.get('detail','')) for r in layers[:3])
    result=route.run(old['config'],report_path='fixture-report',level=ValidationLevel.L3,
        translation_artifact=translation_artifact_from_dict(report['attempts'][0]['translationArtifact']),
        source_program_artifact=source,target_program_artifact=target,prior_layer_results=prior,
        l3_execution_context=L3ExecutionContext.create(source,target),
        l3_requirement_manifest=intent['requirementManifest'],l3_intent_profile=intent['profile'])
    assert result.status is ValidationStatus.VERIFIED,result.detail
    assert calls==['rebuilt'] and invoked==[ValidationLevel.L1]
    detail=json.loads(result.detail)
    assert detail['systemIntent']==intent and detail['systemL3'] is True
    assert detail['executionBindings']['source']['invocationId']==detail['executionBindings']['target']['invocationId']


def test_system_intent_profile_keeps_all_properties_without_granting_execution():
    from riscv2x86_py.l3_system_intent import profile
    from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
    spec={'fragmentId':'fragment','programId':'program','relationIdentity':identity('relation'),
        'specIdentity':identity('spec'),'proofIdentity':identity('proof'),
        'requiredProperties':[{'propertyId':p,'dimension':'synchronization','unit':'fragment'}
                              for p in sorted(route.POLICY['properties'])]}
    result=profile(spec,identity('producer'))
    manifest=classify_l3_requirements({'findings':[{'fragment':{'id':'fragment'},
        'translationOutcome':'emitted','l3IntentProfile':result}]}).to_dict()
    req,=manifest['requirements']
    assert req['eligibilityStatus']=='eligible' and req['disposition']=='not_run'
    assert req['requiredProperties']==spec['requiredProperties']
    assert 'l3.execution.not-yet-configured' in req['reasonCodes']


@pytest.mark.parametrize('enabled', [False, True])
def test_automatic_inventory_selects_explicit_system_policy_only_when_requested(tmp_path, monkeypatch, enabled):
    from riscv2x86_py import automatic_batch_cli as auto
    source = tmp_path/'input.c'; source.write_text('void entry(void){__asm__ volatile("ecall" ::: "memory");}')
    frontend = tmp_path/'frontend'; frontend.write_text('fixture'); frontend.chmod(0o755)
    config = {'backendPath':'explicit-backend','scope':{'functionSymbol':'entry'},'operation':'ecall'}
    provider = {'providerId':'fixture-system','supportedDimensions':[d.value for d in system.DIMENSIONS],
        'supportedPatterns':['privileged_write'],'requiredCapabilities':['privileged_state_observation','shell_observation'],
        'executionProfiles':[system.EXECUTION_PROFILE],'bindingKind':'explicit','validatorType':'controlled-system-validation',
        'configSchemaVersion':system.SCHEMA,'config':config,'fragmentIds':['fragment'],'semanticProfileIds':[]}
    monkeypatch.setattr(auto,'_explicit_l2_providers',lambda *a:([provider],['privileged_state_observation','shell_observation']))
    monkeypatch.setattr(auto,'inspect_entry_points',lambda *a:(False,[{'name':'entry','functionId':'entry',
        'arity':0,'returnType':'void','parameterTypes':[],'pointerParameters':[]}]))
    monkeypatch.setattr(system,'environment',lambda c:{'environmentProfileIdentity':identity('env')})
    directory = tmp_path/'inventory'
    auto.prepare_automatic_inventory(source,directory,frontend=frontend,system_l3=enabled)
    payload = json.loads((directory/'cases/input/riscv2x86-evaluation.json').read_text())
    validators = payload['request']['runtimeRegistryTemplate']['validators']
    plan = json.loads((directory/'cases/input/validation-plan.json').read_text())
    if enabled:
        assert validators['L3']['type']=='controlled-system-l3'
        assert plan['profile']=='microarch' and plan['experimentContractId']==route.POLICY['policyId']
    else:
        assert 'L3' not in validators


def test_system_l3_flag_without_environment_provider_rejects(tmp_path, monkeypatch):
    from riscv2x86_py import automatic_batch_cli as auto
    source=tmp_path/'input.c'; source.write_text('unsigned long f(unsigned long x){return x;}')
    front=tmp_path/'front'; front.write_text('fixture'); front.chmod(0o755)
    monkeypatch.setattr(auto,'inspect_entry_points',lambda *a:(False,[]))
    with pytest.raises(ValueError,match='SYSTEM_L3_EXPLICIT_SYSTEM_PROVIDER_REQUIRED'):
        auto.prepare_automatic_inventory(source,tmp_path/'inventory',frontend=front,system_l3=True)
