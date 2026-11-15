"""Adapter protocol tests; mocked external compiler/backend, real materializer.

These do not claim real Ghidra/RISC-V execution or GMP acceptance.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py import native_original_pipeline as route
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.schema import (Finding,AsmFragment,TranslationOutcome,ValidationOutcome,
    PublicationOutcome,make_translation_attempt_artifact,save_report)
from riscv2x86_py.translation_attempt import save_translation_attempt_archive,terminal_attempt_from_finding
from .test_native_instance_binding import example


@pytest.fixture
def adapted(tmp_path,monkeypatch):
    ast,report,raw=example();receipt={'target':'riscv64','analysisInputIdentity':'fixture-input',
        'context':{'workingDirectory':str(tmp_path),'environment':{'PATH':os.environ['PATH']}},
        'analysisInput':{'inspectionArguments':['-O2','-march=rv64gc','-mabi=lp64d']}}
    receipt_path=tmp_path/'native-input.json';receipt_path.write_text(json.dumps(receipt))
    bundle={'frontend':str(Path(sys.executable).resolve()),'frontendDigest':d.digest(sys.executable),
            'nativeInputReceiptPath':str(receipt_path)}
    bundle_path=tmp_path/'bundle.json';bundle_path.write_text(json.dumps(bundle))
    # Already verified native boundary is isolated here. Exact physical binding
    # and original artifact parsing/materialization run without mocks.
    monkeypatch.setattr(route.binding,'validate_artifacts',lambda value:None)
    monkeypatch.setattr(route,'validated_input',lambda value:{'inputBytes':raw,'canonicalAst':ast})
    calls=[]
    def run(command,**kwargs):
        calls.append((command,kwargs))
        if '--report-json' in command:
            value=deepcopy(report);file=command[command.index('--')-1]
            value['findings'][0]['fileName']=file
            value['findings'][0]['fragment']['fileName']=file
            Path(command[command.index('--report-json')+1]).write_text(json.dumps(value))
        return SimpleNamespace(returncode=0,stdout=b'fixture stdout',stderr=b'')
    monkeypatch.setattr(route.subprocess,'run',run)
    prepared=route.prepare(bundle_path,tmp_path/'prepared')
    return tmp_path,prepared,calls,raw


def backend_fixture(monkeypatch,prepared,raw,*,outcome=TranslationOutcome.EMITTED,failed=False):
    calls=[]
    frontend_text=Path(prepared['frontendReport']['path']).read_text()
    def run(command,**kwargs):
        calls.append(command)
        if '--report-json' in command:
            Path(command[command.index('--report-json')+1]).write_text(frontend_text)
            return SimpleNamespace(returncode=0,stdout=b'fixture frontend',stderr=b'')
        if failed:return SimpleNamespace(returncode=5,stdout=b'',stderr=b'backend failed')
        report=Path(command[command.index('--out')+1]);start=raw.index(b'__asm__');stop=raw.index(b';',start)+1
        emitted=outcome==TranslationOutcome.EMITTED
        finding=Finding(fileName=prepared['source']['path'],hasRewriteRange=True,
            rewriteBeginOffset=start,rewriteEndOffset=stop,rawSourceText=raw[start:stop].decode(),
            fragment=AsmFragment(id='fixture-fragment',fileName=prepared['source']['path'],beginOffset=start,endOffset=stop),
            translationOutcome=outcome.value,validationOutcome=ValidationOutcome.NOT_VERIFIED.value,
            publicationOutcome=PublicationOutcome.WITHHELD.value)
        finding.approvalArtifact={'requiredHeaders':[]}
        finding.translationAttemptArtifact=make_translation_attempt_artifact(
            fragment_id='fixture-fragment',candidate_kind='c' if emitted else outcome.value,
            candidate_route='phase6f_rendered' if emitted else '',
            candidate_replacement='hi = left * right;' if emitted else '',
            candidate_rule_name='fixture-only' if emitted else '',translation_outcome=outcome,
            validation_outcome=finding.validationOutcome,publication_outcome=finding.publicationOutcome,
            reason_codes=('fixture.not-semantic-proof',))
        save_report([finding],str(report))
        save_translation_attempt_archive((terminal_attempt_from_finding(finding,0),),str(report)+'.attempts.json')
        return SimpleNamespace(returncode=0 if emitted else 1,stdout=b'fixture backend',stderr=b'')
    monkeypatch.setattr(route.subprocess,'run',run)
    return calls


def test_exact_physical_input_is_reexported_under_captured_environment(adapted):
    root,value,calls,raw=adapted
    assert Path(value['source']['path']).read_bytes()==raw
    assert calls[0][1]['env']=={'PATH':os.environ['PATH']}
    assert value['expandedInstanceCount']==1
    assert value['sourceLocationCount'] is None and value['dependencyCompileContextCount'] is None
    assert not value['originalSourceEditAuthorized'] and not value['semanticApproval']
    assert route.check_input(root/'prepared/result.json')==value


def test_original_cli_and_materializer_are_called_without_legacy_generator(adapted,monkeypatch):
    root,prepared,_,raw=adapted
    from riscv2x86_py import native_project_translation as legacy
    monkeypatch.setattr(legacy,'acquire',lambda *a,**k:pytest.fail('legacy generator must not execute'))
    calls=backend_fixture(monkeypatch,prepared,raw)
    value=route.translate(root/'prepared/result.json',root/'translated')
    assert calls[0][1:3]==['-m','riscv2x86_py.cli'] and '--skip-verify' in calls[0]
    assert value['attemptOutcomes']==['emitted'] and not value['semanticApproval']
    assert (root/'translated/candidate-staging/input.i').read_bytes()!=raw
    assert route.check_translation(root/'translated/result.json')==value
    assert route.audit(root/'translated/result.json',root/'audit')['originalBackendReplayComplete']


def test_unsupported_original_outcome_is_not_replaced_by_legacy_candidate(adapted,monkeypatch):
    root,prepared,_,raw=adapted
    backend_fixture(monkeypatch,prepared,raw,outcome=TranslationOutcome.UNSUPPORTED)
    value=route.translate(root/'prepared/result.json',root/'translated')
    assert value['attemptOutcomes']==['unsupported'] and value['command']['returnCode']==1
    assert (root/'translated/candidate-staging/input.i').read_bytes()==raw
    assert not value['productionAcceptanceComplete']


def test_missing_backend_report_keeps_failure_without_complete_result(adapted,monkeypatch):
    root,prepared,_,raw=adapted;backend_fixture(monkeypatch,prepared,raw,failed=True)
    with pytest.raises(route.StageFailure):route.translate(root/'prepared/result.json',root/'failed')
    assert not (root/'failed/result.json').exists()
    assert json.loads((root/'failed/run-status.json').read_text())['status']=='failed'


@pytest.mark.parametrize('flag',['originalSourceEditAuthorized','semanticApproval','productionAcceptanceComplete'])
def test_rehashed_scope_escalation_rejected(adapted,flag):
    root,value,_,_=adapted;value[flag]=True
    file=root/'prepared/result.json';file.write_text(json.dumps(d.seal(
        {k:v for k,v in value.items() if k!='originalInputIdentity'},'originalInputIdentity')))
    with pytest.raises(ValueError,match='CLAIM_ESCALATION'):route.check_input(file)


def test_changed_exact_source_rejected(adapted):
    root,value,_,_=adapted;Path(value['source']['path']).write_text('different')
    with pytest.raises(ValueError):route.check_input(root/'prepared/result.json')


def test_cli_cannot_silently_select_legacy_generator(tmp_path):
    import importlib.util
    file=Path(__file__).resolve().parents[2]/'experiment/translate_native_project.py'
    spec=importlib.util.spec_from_file_location('legacy_cli',file);cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
    assert cli.main(['create','--bundle','absent','--target-compiler','absent','--output',str(tmp_path/'never')])==2
    assert not (tmp_path/'never').exists()


def test_request_binding_preserves_original_layers_builds_and_comparison(adapted,monkeypatch):
    from .test_evaluation_runner import _setup
    from riscv2x86_py.evaluation import load_evaluation_request
    root,prepared,_,raw=adapted;backend_fixture(monkeypatch,prepared,raw)
    route.translate(root/'prepared/result.json',root/'translated')
    # Explicit synthetic request. No ABI/domain/provider is invented by adapter.
    request,_,_=_setup(root/'template')
    def build(value):return {'artifactId':value.artifact_id,'artifactKind':value.artifact_kind,
        'outputRelativePath':value.output_relative_path,'command':list(value.command)}
    template={'schemaVersion':request.schema_version,'sourceRoot':request.source_root,
        'sourceRelativePath':request.source_relative_path,'targetRelativePath':request.target_relative_path,
        'translatedReport':request.translated_report,'attemptArchive':request.attempt_archive,
        'validationPlan':request.validation_plan,'targetEnvironment':request.target_environment,
        'runtimeRegistryTemplate':request.runtime_registry_template,'translationArtifacts':{},
        'sourceBuild':build(request.source_build),'targetBuild':build(request.target_build),
        'translationCommand':list(request.translation_command),'comparisonPolicy':request.comparison_policy,
        'validationUnit':request.validation_unit,'validationGroupId':request.validation_group_id,
        'selectedAttemptIds':list(request.selected_attempt_ids)}
    file=root/'template.json';file.write_text(json.dumps(template))
    result=route.evaluation_request(root/'translated/result.json',file,root/'request.json')
    for key in ('validationPlan','targetEnvironment','runtimeRegistryTemplate','translationArtifacts',
                'sourceBuild','targetBuild','comparisonPolicy','validationUnit','validationGroupId','selectedAttemptIds'):
        assert result[key]==template[key]
    bound=load_evaluation_request(root/'request.json')
    assert bound.source_relative_path==bound.target_relative_path=='input.i'
    assert not bound.translation_command
    assert bound.translated_report==str(root/'translated/translated.json')
    template['translationArtifacts']={'not-an-attempt-in-this-run':{'fragment_id':'foreign'}}
    file.write_text(json.dumps(template))
    with pytest.raises(ValueError,match='STALE_OR_FOREIGN'):
        route.evaluation_request(root/'translated/result.json',file,root/'foreign.json')
    assert not (root/'foreign.json').exists()
