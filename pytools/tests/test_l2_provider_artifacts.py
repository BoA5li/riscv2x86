"""Invocation evidence is retained and independently rejects altered payloads."""
from dataclasses import replace
import json
from pathlib import Path

import pytest
from riscv2x86_py import l2_provider_artifacts as artifacts
from riscv2x86_py.l2_results import L2FragmentResult
from riscv2x86_py.translation_validation import ValidationLevel, ValidationLayerResult
from riscv2x86_py.validation_status import ValidationStatus
from tests.test_l2_requirement_driven_registry import _registry, _artifact, _observation, _precondition_factory


def definition():
    return {'providerId':'both','supportedDimensions':['logical_operands','shell_semantics'],
        'supportedPatterns':['scalar'],'requiredCapabilities':['logical_operand_observation','shell_observation'],
        'executionProfiles':['rv64gc-user-to-x86_64-user'],'bindingKind':'automatic',
        'validatorType':'test-provider','configSchemaVersion':'test-provider.v1',
        'config':{'schemaVersion':'test-provider.v1'},'fragmentIds':[]}


def run(tmp_path, factory=None):
    tmp_path.mkdir(parents=True,exist_ok=True)
    registry,_ = _registry(tmp_path,[definition()],**({'factory':factory} if factory else {}))
    layer = registry.validator_for(ValidationLevel.L2)(level=ValidationLevel.L2,
        translation_artifact=_artifact(),source_observation=_observation(),target_observation=_observation())
    return layer


def typed(layer): return L2FragmentResult.from_dict(json.loads(layer.detail))


def test_one_invocation_serves_two_dimensions_and_can_be_audited(tmp_path):
    layer=run(tmp_path)
    assert layer.status is ValidationStatus.VERIFIED
    result=typed(layer)
    assert result.to_dict()['schemaVersion']=='riscv2x86.l2-fragment-result.v3'
    records=artifacts.read_provider_evidence(result,case_root=tmp_path)
    assert len(records)==1
    record=records[0]
    assert set(record['centralAssessments'])=={'logical_operands','shell_semantics'}
    assert record['reportedResult']==record['normalizedResult']
    assert json.loads(record['reportedResult']['detail'])['executionDisposition']=='executed_verified'
    assert len(list(tmp_path.rglob('provider-*.json')))==1
    assert result.evidence_identity != replace(result,provider_evidence_index=None).evidence_identity


def test_repeated_invocations_never_overwrite_prior_results(tmp_path):
    first=typed(run(tmp_path/'first'))
    second=typed(run(tmp_path/'second'))
    assert first.provider_evidence_index != second.provider_evidence_index
    assert artifacts.read_provider_evidence(first,case_root=tmp_path)
    assert artifacts.read_provider_evidence(second,case_root=tmp_path)


def rehash(result, change):
    ref=dict(result.provider_evidence_index)
    index_path=Path(ref['artifactPath']); index=json.loads(index_path.read_text())
    entry=index['invocations'][0]; path=index_path.parent/entry['artifactPath']
    record=json.loads(path.read_text()); change(record)
    record['invocationIdentity']=artifacts.identity({k:v for k,v in record.items() if k!='invocationIdentity'})
    path.write_text(json.dumps(record))
    entry['invocationIdentity']=record['invocationIdentity']
    index['indexIdentity']=artifacts.identity({k:v for k,v in index.items() if k!='indexIdentity'})
    index_path.write_text(json.dumps(index)); ref['indexIdentity']=index['indexIdentity']
    return replace(result,provider_evidence_index=ref)


@pytest.mark.parametrize('mutation',['execution','observation','provider','assessment'])
def test_rehashed_envelope_still_cannot_change_approved_semantic_bindings(tmp_path,mutation):
    result=typed(run(tmp_path))
    def mutate(record):
        detail=json.loads(record['normalizedResult']['detail'])
        if mutation=='execution': detail['executionPayload']['executionNonce']={'different':True}
        if mutation=='observation': detail['dimensionObservations']['logical_operands']['sourceObservationIdentity']='sha256:'+'0'*64
        if mutation=='provider': record['providerId']='different'
        if mutation=='assessment': record['centralAssessments']['logical_operands']['closureDisposition']='failed'
        record['normalizedResult']['detail']=json.dumps(detail)
    result=rehash(result,mutate)
    with pytest.raises(ValueError): artifacts.read_provider_evidence(result,case_root=tmp_path)


@pytest.mark.parametrize('mutation',['missing','tampered','outside','wrong-context'])
def test_index_ingress_rejects_missing_stale_and_cross_case_evidence(tmp_path,mutation):
    result=typed(run(tmp_path/'case'))
    path=Path(result.provider_evidence_index['artifactPath'])
    if mutation=='missing': path.unlink()
    if mutation=='tampered': path.write_text('{}')
    if mutation=='outside':
        with pytest.raises(ValueError): artifacts.read_provider_evidence(result,case_root=tmp_path/'other')
        return
    if mutation=='wrong-context':
        with pytest.raises(ValueError): artifacts.read_provider_evidence(result,case_root=tmp_path,
            translation_artifact={'proof_identity':'sha256:'+'0'*64})
        return
    with pytest.raises(ValueError): artifacts.read_provider_evidence(result,case_root=tmp_path)


def test_persistence_failure_never_returns_verified_and_keeps_captured_results(tmp_path,monkeypatch):
    def reject(*args,**kwargs): raise OSError('disk unavailable')
    monkeypatch.setattr(artifacts,'atomic_json',reject)
    layer=run(tmp_path)
    assert layer.status is ValidationStatus.INCONCLUSIVE
    detail=json.loads(layer.detail)
    assert detail['reasonCode']=='l2.provider-evidence.persistence-failed'
    assert detail['failureStage']=='provider_evidence_persistence'
    assert detail['capturedProviderResults']['both']['reportedResult']['status']=='verified'


def test_provider_exception_is_preserved_without_fabricating_execution(tmp_path):
    def factory(_config):
        def validate(**kwargs): raise RuntimeError('provider crashed during invocation')
        return validate
    layer=run(tmp_path,factory)
    assert layer.status is ValidationStatus.INCONCLUSIVE
    result=typed(layer)
    record,=artifacts.read_provider_evidence(result,case_root=tmp_path)
    assert record['exception']['exceptionType']=='RuntimeError'
    assert 'executionDisposition' not in json.loads(record['normalizedResult']['detail'])
    assert all(x.reason_codes==('l2.provider-invocation.exception',) for x in result.dimension_results)


def test_precondition_result_needs_no_execution_or_observation(tmp_path):
    layer=run(tmp_path,_precondition_factory)
    record,=artifacts.read_provider_evidence(typed(layer),case_root=tmp_path)
    detail=json.loads(record['reportedResult']['detail'])
    assert detail['executionDisposition']=='precondition_rejected'
    assert record['observationSnapshot'] is None
    assert 'executionIdentity' not in detail


def test_unknown_child_object_is_preserved_and_rejected(tmp_path):
    layer=run(tmp_path,lambda _: lambda **kwargs: {'bad':'not a layer result'})
    assert layer.status is not ValidationStatus.VERIFIED
    record,=artifacts.read_provider_evidence(typed(layer),case_root=tmp_path)
    assert record['reportedResult']['invalidPythonType']=='dict'


def test_legacy_fragment_has_no_invented_audit_reference(tmp_path):
    result=replace(typed(run(tmp_path)),provider_evidence_index=None)
    assert result.to_dict()['schemaVersion']=='riscv2x86.l2-fragment-result.v2'
    with pytest.raises(ValueError,match='reference-missing'):
        artifacts.read_provider_evidence(result,case_root=tmp_path)


def test_snapshot_keeps_operand_trace_payload_and_recomputes_observation_identity(tmp_path):
    source={'boundary':[[1,2]],'internal':[],'dependencies':None}
    target={'boundary':[[1,2]],'internal':[],'dependencies':None}
    observation={'sourceTracePayload':source,'targetTracePayload':target,
                 'sourceTraceDigest':artifacts.identity(source),'targetTraceDigest':artifacts.identity(target)}
    path=tmp_path/'observation.json'; path.write_text(json.dumps(observation))
    detail={'schemaVersion':'riscv2x86.auto-l2-operand-result.v2','replayArtifact':path.name,
            'observationEvidenceIdentity':artifacts.identity(observation),
            'dimensionObservations':{'logical_operands':{'sourceEvidenceIdentity':artifacts.identity(source),
                                                        'targetEvidenceIdentity':artifacts.identity(target)}}}
    result=ValidationLayerResult(ValidationLevel.L2,ValidationStatus.VERIFIED,artifacts.identity(observation),json.dumps(detail))
    snapshot=artifacts.capture_observation_artifact(result,{'config':{'replayDirectory':str(tmp_path)}})
    path.unlink()  # The committed envelope owns a snapshot, not an unstable filename.
    artifacts.validate_observation_snapshot(snapshot,detail)
    snapshot['payload']['sourceTracePayload']['boundary'][0][0]=9
    with pytest.raises(ValueError): artifacts.validate_observation_snapshot(snapshot,detail)


def test_v3_cannot_omit_reference_or_masquerade_as_v2(tmp_path):
    result=typed(run(tmp_path))
    value=result.to_dict(); value['providerEvidenceIndex']=None
    with pytest.raises(ValueError): L2FragmentResult.from_dict(value)
    value=result.to_dict(); value['schemaVersion']='riscv2x86.l2-fragment-result.v2'
    with pytest.raises(ValueError): L2FragmentResult.from_dict(value)


def test_index_commit_failure_leaves_no_passing_fragment_result(tmp_path,monkeypatch):
    original=artifacts.atomic_json
    def write(path,value):
        if Path(path).name=='index.json': raise OSError('index commit interrupted')
        return original(path,value)
    monkeypatch.setattr(artifacts,'atomic_json',write)
    layer=run(tmp_path)
    assert layer.status is ValidationStatus.INCONCLUSIVE
    assert json.loads(layer.detail)['reasonCode']=='l2.provider-evidence.persistence-failed'
    assert len(list(tmp_path.rglob('provider-*.json')))==1
    assert not list(tmp_path.rglob('index.json'))


def test_counts_use_invocations_not_number_of_dimensions(tmp_path):
    layer=run(tmp_path)
    case={'attempts':[{'attemptArtifactId':'attempt','fragmentId':'fragment:1',
        'validation':{'layers':[{'level':'L2','status':layer.status.value,
                                'evidenceIdentity':layer.evidence_identity,'detail':layer.detail}]}}]}
    counts=artifacts.provider_audit_counts(case,tmp_path)
    assert counts['providerInvocationCounts']['automatic']=={'executed_verified':1}
    assert counts['auditedProviderExecutionCounts']['automatic']=={'executed_verified':1}
    assert counts['providerArtifactAuditCounts']['persisted_provider_invocations']==1
    assert counts['providerArtifactAuditCounts']['centrally_verified_provider_invocations']==1


def test_effect_snapshot_rebuilds_each_dimension_payload(tmp_path):
    from riscv2x86_py.automatic_l2_effect import _effect_dimension_evidence
    from riscv2x86_py.l2_dimensions import L2Dimension
    observation={'fragmentId':'fragment:1','mode':'scalar-effect-functions',
        'approvedRelationAuthority':{'shell':{'volatile':True}},
        'source':{'events':[{'kind':'ScalarResult','value':3}],'exitCode':0,'stderr':''},
        'target':{'events':[{'kind':'ScalarResult','value':3}],'exitCode':0,'stderr':''}}
    evidence=_effect_dimension_evidence(observation,(L2Dimension.SHELL_SEMANTICS,))[L2Dimension.SHELL_SEMANTICS]
    independently_expected={'schemaVersion':'riscv2x86.l2-effect-dimension-evidence.v1',
        'fragmentId':'fragment:1','mode':'scalar-effect-functions','dimension':'shell_semantics',
        'side':'source','authority':{'shell':{'volatile':True}},'executionObservation':observation['source']}
    assert evidence.source_evidence_identity==artifacts.identity(independently_expected)
    detail={'schemaVersion':'riscv2x86.auto-l2-effect-result.v2','replayArtifact':'effect.json',
        'observationEvidenceIdentity':artifacts.identity(observation),
        'dimensionObservations':{'shell_semantics':{'sourceEvidenceIdentity':evidence.source_evidence_identity,
                                                   'targetEvidenceIdentity':evidence.target_evidence_identity}}}
    snapshot={'schemaVersion':'riscv2x86.l2-observation-snapshot.v1','relativePath':'effect.json',
              'contentIdentity':artifacts.identity(observation),'payload':observation}
    artifacts.validate_observation_snapshot(snapshot,detail)
    detail['dimensionObservations']['shell_semantics']['sourceEvidenceIdentity']='sha256:'+'0'*64
    with pytest.raises(ValueError,match='effect-observation-binding-invalid'):
        artifacts.validate_observation_snapshot(snapshot,detail)


def test_shared_execution_counts_separate_two_invocations(tmp_path):
    layers=[run(tmp_path/'first'),run(tmp_path/'second')]
    attempts=[{'attemptArtifactId':f'attempt:{i}','fragmentId':'fragment:1',
        'validation':{'layers':[{'level':'L2','status':layer.status.value,
                                'evidenceIdentity':layer.evidence_identity,'detail':layer.detail}]}}
        for i,layer in enumerate(layers)]
    counts=artifacts.provider_audit_counts({'attempts':attempts},tmp_path)
    assert counts['providerInvocationCounts']['automatic']=={'executed_verified':2}
    assert counts['auditedProviderExecutionCounts']['automatic']=={'executed_verified':1}


def test_paper_reload_rejects_deleted_provider_evidence(tmp_path):
    from riscv2x86_py.paper_evaluation import _load_evaluation
    from riscv2x86_py.evaluation import EVALUATION_RESULT_SCHEMA
    layer=run(tmp_path)
    value={'schemaVersion':EVALUATION_RESULT_SCHEMA,'targetEnvironment':{},'status':'verified',
           'attempts':[{'fragmentId':'fragment:1','validation':{'layers':[
               {'level':'L2','evidenceIdentity':layer.evidence_identity,'detail':layer.detail}]}}]}
    value['evaluationIdentity']=artifacts.identity(value)
    value['replayArtifact']='replay/evaluation-replay.json'
    path=tmp_path/'evaluation-result.json'; path.write_text(json.dumps(value))
    assert _load_evaluation(path)['status']=='verified'
    Path(typed(layer).provider_evidence_index['artifactPath']).unlink()
    with pytest.raises(ValueError,match='unreadable'): _load_evaluation(path)


def test_batch_audit_cli_checks_files_not_just_verified_summary(tmp_path,capsys):
    from riscv2x86_py.evaluation import EVALUATION_RESULT_SCHEMA
    case_root=tmp_path/'cases'/'one'
    layer=run(case_root)
    value={'schemaVersion':EVALUATION_RESULT_SCHEMA,'status':'verified',
        'attempts':[{'attemptArtifactId':'attempt','fragmentId':'fragment:1',
            'validation':{'layers':[{'level':'L2','status':'verified',
                'evidenceIdentity':layer.evidence_identity,'detail':layer.detail}]}}]}
    value['evaluationIdentity']=artifacts.identity(value)
    (case_root/'evaluation-result.json').write_text(json.dumps(value))
    batch={'cases':[{'caseId':'one','status':'verified','evaluationIdentity':value['evaluationIdentity'],
        'resultPath':'cases/one/evaluation-result.json','programValidationLevels':{'L2':'verified'}}]}
    path=tmp_path/'batch-evaluation.json';path.write_text(json.dumps(batch))
    assert artifacts.main(['--batch',str(path)])==0
    summary=json.loads(capsys.readouterr().out)
    assert summary['auditedCases']==1 and summary['providerInvocations']==1
    Path(typed(layer).provider_evidence_index['artifactPath']).unlink()
    assert artifacts.main(['--batch',str(path)])==1
    assert len(json.loads(capsys.readouterr().out)['failures'])==1


def test_empty_audit_is_not_a_verified_experiment(tmp_path,capsys):
    path=tmp_path/'batch.json';path.write_text('{"cases":[]}')
    assert artifacts.main(['--batch',str(path)])==2
    assert json.loads(capsys.readouterr().out)['auditDisposition']=='not_applicable'
