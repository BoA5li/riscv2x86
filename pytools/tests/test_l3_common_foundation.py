"""Cross-family failure, protocol, provenance and replay boundary regressions."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import pytest
from tests.test_l3_program_regions import fixture
from tests.test_l3_scalar_trace import request
from tests.test_l3_protocol_resolution import ready_report,load_script
from riscv2x86_py.l3_trace_support import identity,digest
from riscv2x86_py.l3_intent_requirements import _hash,parse_l3_intent_profile,validate_intent_disposition


def program_request(tmp_path):
    _,findings,function=fixture(tmp_path)
    value=request(findings[0]);value['candidates']=[request(f)['candidates'][0] for f in findings]
    for item in value['candidates']:item['compilerFunctions']=[function]
    return dict(value,requestIdentity=_hash({k:v for k,v in value.items() if k!='requestIdentity'}))


def test_missing_backend_refusal_is_not_a_fallback_approval(tmp_path):
    from riscv2x86_py.l3_mechanism_selection import produce
    from riscv2x86_py.l3_property_obligations import analyze
    value=program_request(tmp_path)
    assert all(p['complete'] for p in produce(value,{'scalar-program':{}})['profiles'])
    refused=produce(value,{'memory':{}})
    assert len(refused['profiles'])==len(refused['dispositions'])==2
    for item,profile,decision in zip(value['candidates'],refused['profiles'],refused['dispositions']):
        assert profile['complete'] is False and profile['intentKind']=='unknown'
        assert profile['requiredProperties']==analyze(item['finding'],item['compilerFunctions'])['requiredProperties']
        assert not profile['sourceCapabilities'] and not profile['targetCapabilities']
        assert decision['status']=='prerequisites_missing'
        assert any('CAPABILITY_INCOMPLETE' in r for r in decision['reasonCodes'])
        parse_l3_intent_profile(profile);validate_intent_disposition(decision)


@pytest.mark.parametrize('kind',['atomic','control','fence','program','lrsc'])
@pytest.mark.parametrize('report,reason',[(None,'EVALUATION_MAPPING_REQUIRED'),
    ({'sourceProgramArtifact':None},'PROGRAM_ARTIFACT_REQUIRED'),
    ({'requirementStagingFailure':{'detail':'primary error'}},'UPSTREAM_FAILURE'),
    (dict(ready_report(),attempts=[]),'ATTEMPT'),(ready_report('inconclusive'),'COMPLETED_LAYERS_REQUIRED')])
def test_every_direct_audit_refuses_incomplete_evidence_with_stable_reason(kind,report,reason):
    import importlib
    module=importlib.import_module('riscv2x86_py.l3_'+kind+'_route')
    with pytest.raises(ValueError,match=reason):module.audit_result(report)


@pytest.mark.parametrize('kind',['atomic','control','fence','program','lrsc'])
@pytest.mark.parametrize('status',['verified','failed'])
def test_counterexample_readiness_never_requires_a_verified_l3_verdict(kind,status):
    import importlib
    module=importlib.import_module('riscv2x86_py.l3_'+kind+'_route')
    module.audit_prerequisites(ready_report(status))


@pytest.mark.parametrize('kind',['atomic','control','fence','program','lrsc'])
def test_each_driver_preserves_upstream_failure_before_auditing(tmp_path,monkeypatch,kind):
    import importlib
    module=load_script('run_l3_'+kind+'_trace.py')
    monkeypatch.syspath_prepend(str(Path(module.__file__).parent))
    backend=importlib.import_module('riscv2x86_py.l3_'+kind+'_backend')
    route=importlib.import_module('riscv2x86_py.l3_'+kind+'_route')
    source=tmp_path/'input.c';source.write_text('input')
    frontend=tmp_path/'frontend';frontend.write_text('tool')
    manifest=tmp_path/'backend.json';manifest.write_text('{}');out=tmp_path/'output'
    failure={'failureStage':'l3_intent_production','detail':'original production failure'}
    def run(*args,**kwargs):
        batch=out/'batch';batch.mkdir()
        (batch/'result.json').write_text(json.dumps({'status':'inconclusive',
            'requirementStagingFailure':failure,'attempts':[],'sourceProgramArtifact':None}))
        (batch/'batch-evaluation.json').write_text(json.dumps({'cases':[{'caseId':'arbitrary','resultPath':'result.json'}]}))
        return SimpleNamespace(returncode=2)
    monkeypatch.setattr(module.subprocess,'run',run)
    monkeypatch.setattr(backend,'validate',lambda _:None)
    monkeypatch.setattr(route,'audit_result',lambda _:pytest.fail('must not audit incomplete evidence'))
    monkeypatch.setattr(sys,'argv',['driver','--input',str(source),'--frontend',str(frontend),'--backend',str(manifest),'--output',str(out)])
    assert module.main()==2
    value=json.loads((out/'run-status.json').read_text())
    assert value['currentStage']=='normal_production_result'
    assert value['upstreamFailures'][0]['requirementStagingFailure']==failure
    assert value['independentAuditDisposition']['status']=='not_run'
    assert not any(value[k] for k in ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))


@pytest.mark.parametrize('kind',['control','program','fence','atomic','lrsc'])
def test_protocol_request_handles_nonascii_paths_with_the_ingress_hash(tmp_path,kind):
    import importlib
    module=importlib.import_module('riscv2x86_py.l3_'+kind+'_intent')
    value=program_request(tmp_path)
    value['sourcePath']='/tmp/不同目录/输入.c'
    value['requestIdentity']=_hash({k:v for k,v in value.items() if k!='requestIdentity'})
    result=module.produce(value)
    assert result['requestIdentity']==value['requestIdentity']
    for profile in result['profiles']:parse_l3_intent_profile(profile)
    for decision in result.get('dispositions',[]):validate_intent_disposition(decision)


def test_unicode_refusal_reason_uses_the_protocol_identity(tmp_path):
    from riscv2x86_py.l3_intent_refusal import produce,RouteUnavailable
    result=produce(program_request(tmp_path),RouteUnavailable('缺少有效观察器'))
    for decision in result['dispositions']:
        validate_intent_disposition(decision)
        assert '缺少有效观察器' in decision['reasonCodes']


def test_source_snapshot_includes_transitive_and_nested_implementations():
    from riscv2x86_py.l3_implementation_dependencies import implementation_dependencies,implementation_paths
    names=implementation_dependencies()
    assert {'l3_control_deployment.py','source_model.py','compiler_expression.py','l3_execution_context.py','l3_audit_prerequisites.py'}<=set(names)
    assert any('/' in name for name in names)
    assert len(names)==len(implementation_paths()) and names==tuple(sorted(set(names)))


def test_snapshot_recomputes_membership_and_rejects_symlinked_source(tmp_path):
    from riscv2x86_py.l3_implementation_dependencies import implementation_dependencies
    (tmp_path/'a.py').write_text('x=1')
    assert implementation_dependencies(tmp_path)==('a.py',)
    package=tmp_path/'nested';package.mkdir();(package/'b.py').write_text('x=2')
    assert implementation_dependencies(tmp_path)==('a.py','nested/b.py')
    (package/'c.py').symlink_to(tmp_path/'a.py')
    with pytest.raises(ValueError,match='SYMLINK'):implementation_dependencies(tmp_path)


def test_inventory_separates_declared_success_from_independent_acceptance(tmp_path,monkeypatch):
    module=load_script('inspect_l3_workflow.py')
    route=__import__('riscv2x86_py.l3_production_acceptance',fromlist=['audit_evaluation'])
    calls=[]
    def audit(report):
        calls.append(report)
        return {'status':'verified'}
    monkeypatch.setattr(route,'audit_evaluation',audit)
    for name,status in (('a','verified'),('b','inconclusive')):
        directory=tmp_path/name;directory.mkdir()
        (directory/'evaluation-result.json').write_text(json.dumps({'status':status,
            'reasonCodes':[] if status=='verified' else ['primary failure']}))
    value=module.collect(tmp_path)
    assert value['reportCount']==2 and value['independentlyVerifiedReportCount']==0
    assert not value['semanticApproval'] and not calls
    value=module.collect(tmp_path,audit=True)
    assert value['independentlyVerifiedReportCount']==1 and len(calls)==1
    assert value['records'][1]['reasonCodes']==['primary failure']
    assert value['records'][1]['independentAudit']['status']=='not_run'


def test_inventory_retains_bad_reports_and_does_not_hide_audit_failures(tmp_path,monkeypatch):
    module=load_script('inspect_l3_workflow.py')
    route=__import__('riscv2x86_py.l3_production_acceptance',fromlist=['audit_evaluation'])
    def audit(report):raise ValueError('raw evidence changed')
    monkeypatch.setattr(route,'audit_evaluation',audit)
    for name,content in (('a','broken json'),('b',json.dumps({'status':'verified'}))):
        directory=tmp_path/name;directory.mkdir()
        (directory/'evaluation-result.json').write_text(content)
    result=module.collect(tmp_path,audit=True)
    assert result['reportCount']==2 and len(result['errors'])==2
    assert result['independentlyVerifiedReportCount']==0
    assert 'raw evidence changed' in result['records'][1]['inspectionError']


@pytest.mark.parametrize('kind',['atomic','fence','control'])
def test_deployment_rederivation_rejects_boolean_integer_substitution(tmp_path,monkeypatch,kind):
    import importlib
    module=importlib.import_module('riscv2x86_py.l3_'+kind+'_deployment')
    report=tmp_path/'report.json'
    report.write_text(json.dumps({'findings':[{'fragment':{'id':'fragment'}}]}))
    spec={'fragmentId':'fragment','signed':True}
    call={'field':'signature'};plan={'values':[1]};function={'name':'probe'}
    fresh=(spec,call,plan,function) if kind=='control' else (spec,plan,function)
    monkeypatch.setattr(module,'bound_inputs',lambda *args:fresh)
    monkeypatch.setattr(module,'digest',lambda *args:'digest')
    body={'schemaVersion':module.SCHEMA,'backendIdentity':'backend','spec':dict(spec,signed=1),
        'samplePlan':plan,'functionName':'probe','callSignature':call,
        'inputs':{'source':'source','target':'target','report':str(report)},
        'inputDigests':{},'clang':'clang','clangDigest':'digest',
        'outsideFragmentEffectsClaimed':False,'physicalMicroarchitectureClaimed':False}
    # Rehash the altered document. Hash equality is insufficient: independently
    # rederived typed fields must still disagree with the serialized mutation.
    value=dict(body,deploymentIdentity=identity(body))
    with pytest.raises(ValueError,match='REPLAY_MISMATCH.*type'):
        module.validate(value,{'backendIdentity':'backend'},None,None)
