"""SYSTEM L2 protocol and real artifact identity checks, not hardware claims."""
from dataclasses import replace
import copy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from riscv2x86_py.l2_system_routes import SCHEMA,load_system_route,validate_system_route,validate_system_events
from riscv2x86_py.semantic_content import semantic_identity
from riscv2x86_py.privileged_differential_validation import DifferentialPreservationMode
from tests.test_l2_privileged_runner import _runner,_initial,_digest,_observation,_config,_write_inputs


def route_payload(name='ecall'):
    return {'schemaVersion':SCHEMA,'operation':name,'fragmentId':'renamed-fragment',
        'sourceModelIdentity':'sha256:'+'1'*64,'proofIdentity':'sha256:'+'7'*64,
        'runtimeContractId':'runtime-1','runtimeContractVersion':'runtime-v1',
        'initialStateIdentity':_digest(_initial()),
        **{side+'RunnerIdentity':semantic_identity(_runner(side=='source')) for side in ('source','target')},
        **{side+'RunnerBinaryDigest':'sha256:'+sha256(Path('/bin/true').read_bytes()).hexdigest() for side in ('source','target')},
        'expectedEvents':['ecall.enter','ecall.handler','ecall.resume'] if name=='ecall' else ['wfi.enter','wfi.resume']}


def artifact(value):
    return SimpleNamespace(fragment_id=value['fragmentId'],source_model_identity=value['sourceModelIdentity'],
        proof_identity=value['proofIdentity'],translation_plan_id='privileged-runtime.'+value['operation']+'-environment.v1',
        runtime_contract_id=value['runtimeContractId'],runtime_contract_version=value['runtimeContractVersion'])


@pytest.mark.parametrize('name',['ecall','wfi'])
def test_system_route_is_not_a_fictional_csr_and_binds_approved_plan(tmp_path,name):
    from riscv2x86_py.l2_privileged_runner import load_csr_route_contract
    value=route_payload(name);path=tmp_path/'routes.json';path.write_text(json.dumps(value))
    selected=load_csr_route_contract(path)
    assert selected.routes==() and selected.payload['operation']==name
    config=SimpleNamespace(source_runner=_runner(True),target_runner=_runner(False))
    validate_system_route(selected,config,artifact(value),value['initialStateIdentity'],DifferentialPreservationMode.STRICT)


@pytest.mark.parametrize('mutation',['proof','source','fragment','plan','runtime','initial','source-tool','target-tool','mode','isolation'])
def test_system_route_never_accepts_another_execution_or_translation(mutation):
    value=route_payload();selected=load_system_route(value);a=artifact(value)
    config=SimpleNamespace(source_runner=_runner(True),target_runner=_runner(False));initial=value['initialStateIdentity'];mode=DifferentialPreservationMode.STRICT
    if mutation=='proof':a.proof_identity='sha256:'+'f'*64
    if mutation=='source':a.source_model_identity='sha256:'+'f'*64
    if mutation=='fragment':a.fragment_id='other'
    if mutation=='plan':a.translation_plan_id='counter-observation.strict-adapter.v1'
    if mutation=='runtime':a.runtime_contract_version='other'
    if mutation=='initial':initial='sha256:'+'f'*64
    if mutation=='source-tool':config.source_runner=replace(config.source_runner,runtime_version='other')
    if mutation=='target-tool':config.target_runner=replace(config.target_runner,command=('/bin/false',))
    if mutation=='mode':mode=DifferentialPreservationMode.FUNCTIONAL
    if mutation=='isolation':config.target_runner=_runner(False,target_mode='ordinary-user-process')
    with pytest.raises(ValueError,match='SYSTEM_ROUTE_'):
        validate_system_route(selected,config,a,initial,mode)


@pytest.mark.parametrize('mutation',['missing-handler','duplicate-enter','reordered','empty','operation'])
def test_system_route_requires_an_explicit_valid_event_obligation(mutation):
    value=route_payload()
    if mutation=='missing-handler':value['expectedEvents']=['ecall.enter','ecall.resume']
    if mutation=='duplicate-enter':value['expectedEvents'].insert(1,'ecall.enter')
    if mutation=='reordered':value['expectedEvents'].reverse()
    if mutation=='empty':value['expectedEvents']=[]
    if mutation=='operation':value['operation']='read'
    with pytest.raises(ValueError,match='SYSTEM_ROUTE_'):load_system_route(value)


@pytest.mark.parametrize('mutation',['both-empty','target-empty','different-order','timeout'])
def test_equal_final_outputs_cannot_hide_a_missing_or_different_system_event(mutation):
    value=route_payload();r=load_system_route(value)
    source=SimpleNamespace(external_events=tuple(value['expectedEvents']),termination_class='normal')
    target=copy.copy(source)
    if mutation=='both-empty':source.external_events=target.external_events=()
    if mutation=='target-empty':target.external_events=()
    if mutation=='different-order':target.external_events=tuple(reversed(target.external_events))
    if mutation=='timeout':source.termination_class=target.termination_class='timeout'
    with pytest.raises(ValueError,match='SYSTEM_ROUTE_'):validate_system_events(r,source,target)


@pytest.mark.parametrize('mutation',[None,'missing-echo','wrong-program','missing-program','changed-program'])
def test_system_l2_invokes_bound_programs_and_checks_execution_echo(tmp_path,monkeypatch,mutation):
    import riscv2x86_py.l2_privileged_runner as module
    from riscv2x86_py.translation_validation import ProgramArtifact,ValidationLayerResult,ValidationLevel
    from riscv2x86_py.validation_status import PreservationMode,ValidationStatus
    value=route_payload();paths,manifest,initial=_write_inputs(tmp_path,route=value)
    config=_config(paths)
    # Base effect provider is independently tested. This explicitly simulates
    # that prerequisite to test only the SYSTEM runner/central evidence protocol.
    monkeypatch.setattr(module,'run_l2_effect_trace_differential',lambda *_a,**_kw:
        ValidationLayerResult(ValidationLevel.L2,ValidationStatus.VERIFIED,'sha256:'+'a'*64))
    kwargs={}
    for side in ('source','target'):
        p=tmp_path/(side+'.program');p.write_bytes((side+'-artifact').encode())
        kwargs[side+'_program_artifact']=ProgramArtifact(side,str(p),'executable',
            'sha256:'+sha256(p.read_bytes()).hexdigest())
    if mutation=='missing-program':kwargs.pop('source_program_artifact')
    if mutation=='changed-program':Path(kwargs['source_program_artifact'].artifact_path).write_bytes(b'changed')
    a=artifact(value);a.preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT
    calls=[]
    def command(argv,stdin,timeout):
        request=json.loads(stdin);side=argv[-1];calls.append(request)
        spec=config.source_runner if side=='source' else config.target_runner
        observed=_observation(spec.runner_id,spec.execution_profile,initial)
        observed['externalEvents']=value['expectedEvents']
        observed['executionBindingIdentity']=request['executionBindingIdentity']
        observed['programArtifactDigest']=request['programArtifact']['artifact_digest']
        assert Path(request['programArtifact']['artifact_path']).read_bytes()==(side+'-artifact').encode()
        if mutation=='missing-echo':observed.pop('executionBindingIdentity')
        if mutation=='wrong-program':observed['programArtifactDigest']='sha256:'+'f'*64
        return module.CommandResult(0,json.dumps(observed))
    result=module.run_l2_privileged_differential(config,translation_artifact=a,
        comparison_policy=config.comparison_policy,privileged_command_runner=command,**kwargs)
    if mutation is None:
        assert result.status is ValidationStatus.VERIFIED,result.detail
        assert len(calls)==2 and calls[0]['executionBindingIdentity']!=calls[1]['executionBindingIdentity']
        assert json.loads(result.detail)['claimBoundary']=='bounded-system-events-and-logical-state'
    else:
        assert result.status is ValidationStatus.FAILED
        if mutation in ('missing-program','changed-program'):assert calls==[]
