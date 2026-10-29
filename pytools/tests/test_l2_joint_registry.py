"""Real central matching/persistence and native plumbing; NOT dual-ISA acceptance.

Proof/AST joins are fixtures. Explicit native compiler/runner test doubles are
confined here; production continues to require the real toolchain and backend.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import pytest
from riscv2x86_py.l2_joint_contract import providers, assess, CAPABILITIES, EXECUTION_PROFILE
from riscv2x86_py.l3_trace_support import digest
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


def config(tmp_path, findings, functions):
    return dict(schemaVersion='riscv2x86.auto-l2-effect-runner.v1',mode='joint-program-functions',
        sourcePath=str(tmp_path/'source.c'),targetPath=str(tmp_path/'target.c'),
        sourceDigest=digest(tmp_path/'source.c'),targetDigest=digest(tmp_path/'target.c'),
        translatedReport=str(tmp_path/'translated_report.json'),functions=functions,
        workDirectory=str(tmp_path/'work'),replayDirectory=str(tmp_path/'replay'),
        timeoutSeconds=30,qemuBinary='joint-native-test-runner')


def setup(tmp_path,monkeypatch):
    from tests.test_l3_joint_program import fixture
    from riscv2x86_py.l3_joint_spec import spec
    source,findings,fn=fixture(tmp_path)
    (tmp_path/'source.c').write_bytes(source);(tmp_path/'target.c').write_bytes(source)
    (tmp_path/'translated_report.json').write_text(json.dumps({'findings':findings}))
    program=spec(findings,[fn])
    from riscv2x86_py import l3_joint_deployment,automatic_batch_cli
    monkeypatch.setattr(l3_joint_deployment,'bound',lambda *a:(program,fn))
    from riscv2x86_py import automatic_l2_joint
    monkeypatch.setattr(automatic_l2_joint,'bound',lambda *a:(program,fn))
    monkeypatch.setattr(automatic_batch_cli,'inspect_entry_points',lambda *a,**kw:(False,[fn]))
    tools=tmp_path/'tools';tools.mkdir();gcc=shutil.which('gcc')
    compiler=tools/'riscv64-linux-gnu-gcc'
    compiler.write_text('#!/bin/bash\nargs=();for v in "$@";do case "$v" in -march=*|-mabi=*) ;; *) args+=("$v");; esac;done\nexec '+gcc+' "${args[@]}"\n');compiler.chmod(0o755)
    runner=tools/'joint-native-test-runner';runner.write_text('#!/bin/bash\nexec "$@"\n');runner.chmod(0o755)
    import os
    monkeypatch.setenv('PATH',str(tools)+':'+os.environ['PATH'])
    # Only used as a pinned AST test-double token, never claimed as real Clang.
    monkeypatch.setenv('RV2X86_SYSTEM_CLANG',gcc)
    return findings,fn,config(tmp_path,findings,[fn])


def artifact(f):
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    a=f['approvalArtifact'];s=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    return SimpleNamespace(fragment_id=f['fragment']['id'],preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
        proof_identity=a['proofIdentity'],shell_facts_identity=s.shell_fact_identity,l2_authority_identity=s.authority_identity,
        effect_relation_set_identity=s.effect_relation_set_identity,l2_authority_complete=True,
        l2_semantic_profile_identity=f['l2SemanticProfile']['profileIdentity'],l2_pattern_kind=f['l2SemanticProfile']['patternKind'])


def registry(tmp_path,findings,c,f):
    from riscv2x86_py.l2_eligibility import classify_l2_requirements
    from riscv2x86_py.validation_runtime_registry import validation_runtime_registry_from_dict
    manifest=tmp_path/'requirements.json';manifest.write_text(json.dumps(classify_l2_requirements({'findings':findings})))
    runtime=dict(schemaVersion='riscv2x86.l2-requirement-driven-registry.v3',
        requirementManifestPath=str(manifest),semanticProfilePath=c['translatedReport'],fragmentId=f['fragment']['id'],
        semanticProfileSource='translated-report',providerSelectionUnit='fragment',
        environmentCapabilities=list(CAPABILITIES),environmentExecutionProfiles=[EXECUTION_PROFILE],
        executionProfile=EXECUTION_PROFILE,resolvedPlanPath=str(tmp_path/'plan.json'),providers=providers(c))
    return validation_runtime_registry_from_dict({'schemaVersion':'riscv2x86.validation-runtime-registry.v2','version':'joint-integration',
        'validators':{'L2':{'type':'requirement-driven','config':runtime}}})


@pytest.mark.parametrize('index',[0,1,2])
def test_production_registration_exact_resolution_and_persisted_native_observation(tmp_path,monkeypatch,index):
    findings,fn,c=setup(tmp_path,monkeypatch)
    plans=assess(findings,providers(c),CAPABILITIES,[EXECUTION_PROFILE])
    assert len(plans)==3
    f=findings[index];r=registry(tmp_path,findings,c,f)
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    layer=r.validator_for(ValidationLevel.L2)(level=ValidationLevel.L2,translation_artifact=artifact(f),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is ValidationStatus.VERIFIED,layer.detail
    from riscv2x86_py.l2_results import L2FragmentResult
    from riscv2x86_py.l2_provider_artifacts import read_provider_evidence
    result=L2FragmentResult.from_dict(json.loads(layer.detail))
    records=read_provider_evidence(result,case_root=tmp_path,translation_artifact=vars(artifact(f)))
    assert len(records)==1
    assert len(records[0]['centralAssessments'])==(2 if index==1 else 3)
    summary=json.loads(records[0]['normalizedResult']['detail'])
    assert summary['replayArtifact']=='joint-observation.json'
    assert (Path(c['replayDirectory'])/summary['replayArtifact']).is_file()
    # Corrupt the actual retained output; replay must reject despite a cached verdict.
    observation=json.loads((Path(c['replayDirectory'])/summary['replayArtifact']).read_text())
    command=next(Path(p) for p in observation['files'] if p.endswith('source-execute.command.json'))
    command.write_text('{}')
    with pytest.raises(ValueError):read_provider_evidence(result,case_root=tmp_path)


@pytest.mark.parametrize('capability',CAPABILITIES[1:])
def test_missing_provider_capability_remains_rejected(tmp_path,monkeypatch,capability):
    findings,fn,c=setup(tmp_path,monkeypatch);defs=providers(c)
    for d in defs:d['requiredCapabilities'].remove(capability)
    with pytest.raises(ValueError):assess(findings,defs,CAPABILITIES,[EXECUTION_PROFILE])


def test_scalar_rejects_memory_superset_provider_declaration(tmp_path,monkeypatch):
    findings,fn,c=setup(tmp_path,monkeypatch);defs=providers(c)
    defs[0]['supportedDimensions'].insert(1,'memory_effects')
    with pytest.raises(ValueError,match='DIMENSIONS_NOT_EXACT'):assess(findings,defs,CAPABILITIES,[EXECUTION_PROFILE])


def test_m0_checks_actual_configuration_without_granting_execution(tmp_path,monkeypatch):
    findings,fn,c=setup(tmp_path,monkeypatch)
    from riscv2x86_py.l3_capability_assessment import assess as assessment
    conf={'providers':providers(c),'environmentCapabilities':list(CAPABILITIES),'environmentExecutionProfiles':[EXECUTION_PROFILE]}
    v=assessment(findings,[fn],{'joint'},conf)
    assert v['preExecutionPrerequisitesComplete']
    assert set(v['runtimeStages'].values())=={'not_run'} and not v['productionAcceptanceComplete']
    for d in conf['providers']:d['requiredCapabilities']=['joint_program_observation']
    v=assessment(findings,[fn],{'joint'},conf)
    assert not v['configurationPrerequisitesComplete'] and not v['preExecutionPrerequisitesComplete']
    assert 'dimension-capability-undeclared' in str(v['configurationAssessment'])


def test_complete_native_counterexample_stays_failed_through_central_persistence(tmp_path,monkeypatch):
    findings,fn,c=setup(tmp_path,monkeypatch)
    target=Path(c['targetPath']);target.write_bytes(target.read_bytes().replace(b'addq',b'subq'))
    c['targetDigest']=digest(target)
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    layer=registry(tmp_path,findings,c,findings[1]).validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2,translation_artifact=artifact(findings[1]),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is ValidationStatus.FAILED,layer.detail
    assert json.loads(layer.detail)['status']=='failed'


@pytest.mark.parametrize('reference',['/tmp/absolute.json','../outside.json','missing.json'])
def test_observation_reference_does_not_bypass_replay_root(tmp_path,reference):
    from riscv2x86_py.l2_provider_artifacts import capture_observation_artifact
    result=SimpleNamespace(detail=json.dumps({'replayArtifact':reference}))
    with pytest.raises((ValueError,OSError)):
        capture_observation_artifact(result,{'config':{'replayDirectory':str(tmp_path)}})


def test_joint_observer_contract_and_scalar_decision_are_both_replayable(tmp_path,monkeypatch):
    findings,fn,c=setup(tmp_path,monkeypatch)
    f=findings[1];a=f['approvalArtifact']
    assert a['l2ScalarAuthorityDecision']['materializable'] is True
    assert a['l2JointOperandObservationContract']['executionObserved'] is False
    from riscv2x86_py.l3_joint_spec import spec
    a['l2JointOperandObservationContract']['points'].pop()
    with pytest.raises(ValueError):spec(findings,[fn])


@pytest.mark.parametrize('mutation',['boolean-code','changed-boundary','changed-plan'])
def test_rehashed_persisted_values_require_semantic_and_type_replay(tmp_path,monkeypatch,mutation):
    findings,fn,c=setup(tmp_path,monkeypatch)
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    registry(tmp_path,findings,c,findings[0]).validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2,translation_artifact=artifact(findings[0]),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    value=json.loads((Path(c['replayDirectory'])/'joint-observation.json').read_text())
    if mutation=='boolean-code':
        command=next(Path(p) for p in value['files'] if p.endswith('source-execute.command.json'))
        record=json.loads(command.read_text());record['returnCode']=False;command.write_text(json.dumps(record))
        value['files'][str(command)]=digest(command)
    if mutation=='changed-boundary':value['source']['boundaries'][1]['values'][0]='0000000000000000'
    if mutation=='changed-plan':value['samplePlan']['inputs'][0]['initialObjectHex']='00'*value['programSpec']['object']['size']
    from riscv2x86_py.l2_joint_replay import replay
    with pytest.raises(ValueError):replay(value)
