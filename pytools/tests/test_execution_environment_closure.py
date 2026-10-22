"""Environment attribution and implementation review gates, not execution mocks
presented as production acceptance. Real execution is tested separately.
"""
from copy import deepcopy
import json
from types import SimpleNamespace
import pytest
from riscv2x86_py.semantic_content import semantic_identity


def withhold(finding):
    from riscv2x86_py.schema import make_translation_attempt_artifact
    finding['translationAttemptArtifact']=make_translation_attempt_artifact(
        fragment_id=finding['fragment']['id'],candidate_kind='runtime_c',candidate_route='proof-bound-runtime',
        candidate_replacement=finding['suggestedReplacement'],candidate_rule_name='phase6.lower_to_c',
        translation_outcome='emitted',publication_outcome='withheld',validation_outcome='not_verified')
    finding['suggestedReplacement']=''


@pytest.mark.parametrize('mutation',['text','fragment','identity','outcome','public'])
def test_withheld_candidate_cannot_be_redirected_or_promoted(mutation):
    from dataclasses import asdict
    from tests.test_controlled_time import pipeline_fixture
    from riscv2x86_py.approved_replacement import approved_replacement
    f,result,approval,*_=pipeline_fixture()
    finding={'fragment':asdict(f),'approvalArtifact':approval,'suggestedReplacement':result.suggested_replacement}
    withhold(finding)
    assert approved_replacement(finding)==result.suggested_replacement
    assert finding['suggestedReplacement']==''
    a=finding['translationAttemptArtifact']
    if mutation=='text':a['candidateReplacement']='unapproved();'
    if mutation=='fragment':a['fragmentId']='other-fragment'
    if mutation=='outcome':a['translationOutcome']='needs_route'
    if mutation=='public':finding['suggestedReplacement']='conflicting();'
    if mutation=='identity':a['attemptIdentity']='sha256:'+'0'*64
    else:a['attemptIdentity']=semantic_identity({k:v for k,v in a.items() if k!='attemptIdentity'})
    with pytest.raises(ValueError):approved_replacement(finding)


def test_rehashed_unknown_source_cannot_inherit_local_mechanism_review():
    from tests.test_mechanism_preparation import domain
    from riscv2x86_py.instruction_stream_domain import validate_domain
    value=domain()
    evidence=value['mechanismEvidence']
    evidence['sourceDigests']['accel/tcg/translate-all.c']='sha256:'+'0'*64
    evidence['evidenceIdentity']=semantic_identity({k:v for k,v in evidence.items() if k!='evidenceIdentity'})
    value['domainIdentity']=semantic_identity({k:v for k,v in value.items() if k!='domainIdentity'})
    with pytest.raises(ValueError,match='NOT_REVIEWED'):
        validate_domain(value,fragment_id=value['fragmentId'],environment_id=value['targetEnvironmentId'],cpu_profile=value['targetCpuProfileId'])


def test_changed_target_helper_needs_new_review(monkeypatch):
    from tests.test_mechanism_preparation import evidence
    from riscv2x86_py import local_sync_mechanism as mechanism
    monkeypatch.setattr(mechanism,'digest',lambda path:'sha256:'+'0'*64)
    with pytest.raises(ValueError,match='TARGET_MECHANISM_NOT_REVIEWED'):
        mechanism.require_reviewed_implementation(evidence())


def controlled_binding():
    from tests.test_controlled_time import pipeline_fixture
    from riscv2x86_py.controlled_time_environment import environment_binding
    _,_,approval,_,_=pipeline_fixture()
    trace=approval['proofPayload']['fieldProof']['constraints'][0]['counter_contract_payload']['trace_relation']
    config={'sourceRunner':['declared-runner','-L','/declared/sysroot'],'observerDigest':'sha256:'+'9'*64}
    return config,trace,environment_binding(config,trace)


def test_environment_identity_separates_command_backend_and_observer():
    from riscv2x86_py.controlled_time_environment import environment_binding,environment_id
    config,trace,binding=controlled_binding()
    changed=deepcopy(config);changed['sourceRunner'].append('-cpu=another')
    assert environment_id(environment_binding(changed,trace))!=environment_id(binding)
    changed=deepcopy(config);changed['observerDigest']='sha256:'+'8'*64
    assert environment_id(environment_binding(changed,trace))!=environment_id(binding)
    assert binding['claims']['fullArchitecturalTimeClock']=='not_verified'
    assert binding['claims']['nativeTime']=='not_verified'
    assert binding['claims']['microarchitecture']=='not_verified'


def test_native_case_label_cannot_contain_controlled_layer(monkeypatch):
    from riscv2x86_py import time_trace_runner
    from riscv2x86_py.controlled_time_environment import audit_case_environment,environment_id
    _,_,binding=controlled_binding()
    # Only attribution is isolated here; the production validator independently
    # replays full execution in test_controlled_time and optional real tests.
    monkeypatch.setattr(time_trace_runner,'validate_persisted_result',lambda value:None)
    detail={'schemaVersion':time_trace_runner.RESULT,'environmentId':environment_id(binding),'evidenceIdentity':'evidence'}
    case={'targetEnvironment':{'environmentId':'auto-rv64gc-qemu-x86-native-v1'},
        'attempts':[{'validation':{'layers':[{'level':'L1','detail':json.dumps(detail),'evidenceIdentity':'evidence'}]}}]}
    with pytest.raises(ValueError,match='CASE_LAYER_ENVIRONMENT_MISMATCH'):audit_case_environment(case)
    case['targetEnvironment']['environmentId']=environment_id(binding)
    audit_case_environment(case)
