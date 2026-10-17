"""Known obligations survive authority rejection; rejection is a typed result."""
from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_semantic_profile import profile_from_source_model, L2PatternKind
from riscv2x86_py.l2_eligibility import L2EligibilityClassifier
from riscv2x86_py.l2_dimensions import L2Dimension, L2DimensionStatus
from riscv2x86_py.l2_results import L2FragmentResult
from riscv2x86_py.l2_evidence_reader import read_l2_fragment_results, read_l2_provider_results, _identity
from riscv2x86_py.l2_provider_artifacts import provider_audit_counts, main as audit_main
from riscv2x86_py.batch_evaluation_cli import _l2_coverage_diagnostics
from riscv2x86_py.validation_runtime_registry import validation_runtime_registry_from_dict
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.evaluation import EVALUATION_RESULT_SCHEMA
from tests.test_asm_goto_structured_authority import _model


def classified():
    model = _model()
    profile = profile_from_source_model('fragment:goto', model)
    report = {'findings':[{'fragment':{'id':'fragment:goto','gotoLabels':['taken'],
        'outputs':[], 'inputs':[{'constraint':'r'}]},
        'translationOutcome':'emitted','l2SemanticProfile':profile.to_dict()}]}
    manifest = L2EligibilityClassifier().classify_report(report)
    return profile,report,manifest


def run_precondition(tmp_path):
    profile,report,manifest = classified()
    report_path=tmp_path/'report.json'; report_path.write_text(json.dumps(report))
    manifest_path=tmp_path/'requirements.json'; manifest_path.write_text(json.dumps(manifest))
    config={'schemaVersion':'riscv2x86.l2-requirement-driven-registry.v3',
        'requirementManifestPath':str(manifest_path), 'fragmentId':'fragment:goto',
        'semanticProfilePath':str(report_path), 'semanticProfileSource':'translated-report',
        'providerSelectionUnit':'fragment', 'executionProfile':profile.execution_profile,
        'environmentCapabilities':[], 'environmentExecutionProfiles':[profile.execution_profile],
        'resolvedPlanPath':str(tmp_path/'resolved.json'), 'providers':[]}
    registry=validation_runtime_registry_from_dict({'schemaVersion':'riscv2x86.validation-runtime-registry.v2',
        'version':'test','validators':{'L2':{'type':'requirement-driven','config':config}}})
    layer=registry.validator_for(ValidationLevel.L2)(level=ValidationLevel.L2,
        translation_artifact=SimpleNamespace(fragment_id='fragment:goto',
            l2_semantic_profile_identity=profile.profile_identity,l2_pattern_kind='asm_goto'))
    result={'schemaVersion':EVALUATION_RESULT_SCHEMA,'status':'inconclusive',
        'translationEvaluationLink':{'l2Requirements':manifest},
        'attempts':[{'attemptArtifactId':'attempt:goto','fragmentId':'fragment:goto',
            'validation':{'layers':[{'level':'L2','status':layer.status.value,
                'detail':layer.detail,'evidenceIdentity':layer.evidence_identity}]}}]}
    return manifest,layer,result


def test_known_asm_goto_obligations_are_not_unknown_or_erased():
    profile,_,manifest=classified()
    assert profile.pattern_kind is L2PatternKind.ASM_GOTO
    requirement=manifest['requirements'][0]
    assert requirement['requiredDimensions']==['control_flow','logical_operands','shell_semantics']
    assert requirement['eligibilityStatus']=='inconclusive'
    assert 'L2_ASM_GOTO_CONTINUATION_OBSERVATION_AUTHORITY_REQUIRED' in requirement['reasonCodes']
    assert 'asm_goto_continuation_observation' in requirement['requiredCapabilities']


def test_noneligible_runtime_result_is_typed_readable_and_keeps_root_reasons(tmp_path):
    manifest,layer,case=run_precondition(tmp_path)
    raw=json.loads(layer.detail)
    assert raw['schemaVersion']=='riscv2x86.l2-fragment-result.v4'
    assert raw['reasonCodes']==manifest['requirements'][0]['reasonCodes']
    assert raw['precondition']['executionDisposition']=='precondition_rejected'
    assert raw['precondition']['evidenceProductionDisposition']=='not_produced'
    parsed,=read_l2_fragment_results(case,manifest)
    assert parsed[1].status is L2DimensionStatus.INCONCLUSIVE
    assert read_l2_provider_results(case,tmp_path,manifest)==()
    assert provider_audit_counts(case,tmp_path)['providerArtifactAuditCounts']=={'valid_precondition_rejections':1}
    assert not (tmp_path/'l2-provider-evidence').exists()


def test_coverage_denominator_includes_blocked_obligations_without_missing_plan_noise(tmp_path):
    _,_,case=run_precondition(tmp_path)
    counts=_l2_coverage_diagnostics(case,tmp_path)
    assert counts['schemaVersion']=='riscv2x86.l2-coverage-diagnostics.v4'
    assert counts['caseCounts']=={'total':1,'l2_required':1,'l2_precondition_blocked':1}
    assert counts['fragmentCounts']['required']==1
    assert counts['requiredDimensionCounts']['required']==3
    assert counts['requiredDimensionCounts']['with_result']==3
    assert counts['observationProductionCounts']=={'not_produced':3}
    assert 'resolved_plan_missing' not in counts['missingCapabilityCounts']
    assert 'provider_unbound' not in counts['missingCapabilityCounts']


@pytest.mark.parametrize('mutation', ['schema','execution','evidence','status','root','requirement','fragment'])
def test_precondition_result_mutations_cannot_create_verified_evidence(tmp_path, mutation):
    _,_,case=run_precondition(tmp_path)
    layer=case['attempts'][0]['validation']['layers'][0]
    raw=json.loads(layer['detail'])
    if mutation=='schema': raw['schemaVersion']='riscv2x86.l2-fragment-result.v3'
    if mutation=='execution': raw['precondition']['executionDisposition']='executed_verified'
    if mutation=='evidence': raw['dimensionResults']['control_flow']['executionIdentity']='sha256:'+'8'*64
    if mutation=='status': layer['status']='verified'
    if mutation=='root': raw['reasonCodes']=['different']
    if mutation=='requirement': raw['requirementIdentity']=''
    if mutation=='fragment': raw['fragmentId']='different'
    layer['detail']=json.dumps(raw)
    with pytest.raises(ValueError): read_l2_fragment_results(case)


def test_missing_requirement_is_explicit_and_does_not_invent_identity():
    result=L2FragmentResult.reject_precondition(fragment_id='f',requirement_identity='',
        required_dimensions=(),reason_codes=('l2.requirement.fragment-missing',),
        failure_stage='requirement_ingress',eligibility_status='missing')
    assert L2FragmentResult.from_dict(result.to_dict()).requirement_identity==''
    with pytest.raises(ValueError):
        replace(result,precondition={**result.precondition,'eligibilityStatus':'eligible'})


def test_audit_includes_nonverified_case_and_rejects_stale_rejection(tmp_path,capsys):
    _,_,case=run_precondition(tmp_path)
    case['evaluationIdentity']=_identity(case)
    path=tmp_path/'cases'/'goto'/'evaluation-result.json'; path.parent.mkdir(parents=True)
    path.write_text(json.dumps(case))
    summary={'caseId':'goto','status':'inconclusive','resultPath':'cases/goto/evaluation-result.json',
        'evaluationIdentity':case['evaluationIdentity'],'programValidationLevels':{'L2':'inconclusive'}}
    batch=tmp_path/'batch.json'; batch.write_text(json.dumps({'cases':[summary]}))
    capsys.readouterr()  # Discard fixture source-model diagnostics before CLI stdout.
    assert audit_main(['--batch',str(batch)])==0
    output=json.loads(capsys.readouterr().out)
    assert output['auditScope']=='all'
    assert output['validatedCaseResults']==1
    assert output['preconditionRejectedFragments']==1
    assert output['providerInvocations']==0
    case['attempts'][0]['validation']['layers'][0]['detail']='{}'
    case['evaluationIdentity']=_identity({k:v for k,v in case.items() if k!='evaluationIdentity'})
    path.write_text(json.dumps(case)); summary['evaluationIdentity']=case['evaluationIdentity']
    batch.write_text(json.dumps({'cases':[summary]}))
    assert audit_main(['--batch',str(batch)])==1
    assert json.loads(capsys.readouterr().out)['failures']


def test_top_level_failure_reasons_keep_requirement_root_instead_of_only_wrapper(tmp_path):
    from riscv2x86_py.translation_validation import _layer_failure_reasons
    manifest,layer,_=run_precondition(tmp_path)
    reasons=_layer_failure_reasons(layer)
    assert 'L2_ASM_GOTO_CONTINUATION_OBSERVATION_AUTHORITY_REQUIRED' in reasons
    assert 'l2.requirement.not-eligible' not in reasons
    assert 'validation.layer-not-verified:L2' in reasons
    assert set(manifest['requirements'][0]['reasonCodes']).issubset(reasons)


def test_rejection_identity_is_checked_on_export_reload(tmp_path):
    from riscv2x86_py.l2_evidence_reader import audit_provider_references
    _,_,case=run_precondition(tmp_path)
    assert audit_provider_references(case,tmp_path)==()
    case['attempts'][0]['validation']['layers'][0]['evidenceIdentity']='sha256:'+'0'*64
    with pytest.raises(ValueError): audit_provider_references(case,tmp_path)
