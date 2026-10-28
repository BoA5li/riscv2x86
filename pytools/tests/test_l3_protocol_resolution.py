"""Regression evidence for producer framing, scoped ELF lookup and audit readiness."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

from riscv2x86_py.l3_trace_support import Elf, identity
from tests.test_l3_production_ingress import ingress


def compile_files(tmp_path, texts, *flags):
    paths=[]
    for i,text in enumerate(texts):
        path=tmp_path/f'unit{i}.c';path.write_text(text);paths.append(str(path))
    out=tmp_path/'program'
    result=subprocess.run(['gcc',*flags,*paths,'-o',str(out)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    return out


def test_real_linked_local_duplicates_do_not_poison_other_symbols(tmp_path):
    path=compile_files(tmp_path,[
        'static int lock=1; int left(void){return lock;}',
        'static int lock=2; int right(void){return lock;}',
        'int left(void);int right(void);int main(void){return left()+right()!=3;}'])
    assert subprocess.run([str(path)]).returncode==0
    elf=Elf(path)
    assert elf.code('left') and elf.code('right')
    assert len(elf.symbols['lock'])==2
    assert all(r['binding']==0 for r in elf.symbols['lock'])
    with pytest.raises(ValueError,match='AMBIGUOUS_SYMBOL:lock'):elf.symbol('lock')


def test_public_query_selects_external_definition_over_local_namesake(tmp_path):
    path=compile_files(tmp_path,[
        'static int probe(void){return 1;} int left(void){return probe();}',
        'int probe(void){return 2;} int main(void){return probe()!=2;}'])
    elf=Elf(path)
    assert len(elf.symbols['probe'])==2
    external=[r for r in elf.symbols['probe'] if r['binding']==1]
    assert elf.symbol('probe')==external[0]['symbol']


def test_symtab_dynsym_same_definition_is_deduplicated(tmp_path):
    elf=Elf(compile_files(tmp_path,['int probe(void){return 2;}'],'-shared','-fPIC'))
    assert len(elf.symbols['probe'])==2
    assert elf.code('probe')


@pytest.mark.parametrize('mutation',['distinct_external','unterminated_name','bad_string_table','truncated'])
def test_elf_rejects_actual_ambiguity_and_malformed_tables(tmp_path,mutation):
    path=compile_files(tmp_path,['int first(void){return 1;} int other(void){return 2;}'],'-shared','-fPIC')
    elf=Elf(path);raw=bytearray(path.read_bytes())
    if mutation=='distinct_external':
        # Rename other to first in every table, retaining two distinct addresses.
        for section in elf.sections:
            if section[1] not in (2,11):continue
            entries=[section[4]+24*i for i in range(section[5]//24)]
            first=next(at for at in entries if struct.unpack_from('<Q',raw,at+8)[0]==elf.symbol('first')[0])
            other=next(at for at in entries if struct.unpack_from('<Q',raw,at+8)[0]==elf.symbol('other')[0])
            raw[other:other+4]=raw[first:first+4]
        path.write_bytes(raw)
        with pytest.raises(ValueError,match='AMBIGUOUS_SYMBOL:first'):Elf(path).code('first')
        return
    table=next(s for s in elf.sections if s[1]==2)
    strings=elf.sections[table[6]]
    if mutation=='unterminated_name':raw[strings[4]+strings[5]-1]=65
    if mutation=='bad_string_table':
        shoff=struct.unpack_from('<Q',raw,40)[0]
        struct.pack_into('<I',raw,shoff+table[6]*64+4,1)
    if mutation=='truncated':raw=raw[:64]
    path.write_bytes(raw)
    with pytest.raises(ValueError):Elf(path)


def lrsc_request(tmp_path):
    from tests.test_l3_lrsc_sequence import finding_spec
    from tests.test_l3_scalar_trace import request
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    from riscv2x86_py.l3_trace_support import digest
    f,functions=finding_spec();f['translationOutcome']='emitted';f['sourceDigest']=functions[0]['sourceDigest']
    frontend=tmp_path/'frontend';frontend.write_text('fixture identity')
    assert materialize_automatic_l2_authority({'findings':[f]},functions,frontend)==1
    program=identity({'schemaVersion':'riscv2x86.automatic-program.v1','producerDigest':digest(frontend)})
    boundaries,_,_=materialize_fragment_execution_authority([f],functions[0],program)
    f['approvalArtifact']['l2FragmentOperandBoundary']=boundaries[f['fragment']['id']].to_dict()
    req=request(f);req['candidates'][0]['compilerFunctions']=functions
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    return req


def test_actual_lrsc_cli_replays_source_and_emits_one_json_document(tmp_path):
    import riscv2x86_py.l3_lrsc_intent as producer
    path=Path(producer.__file__).resolve()
    command=[sys.executable,'-m','riscv2x86_py.l3_lrsc_intent','--implementation',str(path)]
    for name in producer.DEPENDENCIES:command+=['--dependency',str((path.parent/name))]
    result=subprocess.run(command,input=json.dumps(lrsc_request(tmp_path)),capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    response=json.loads(result.stdout)
    assert response['profiles'][0]['complete'] is True
    assert '[DEBUG]' not in result.stdout


def test_json_channel_owner_routes_nested_prints_to_stderr():
    result=subprocess.run([sys.executable,'-c',
        'from riscv2x86_py.l3_trace_support import emit_json\n'
        'def run():\n print("nested diagnostic")\n return {"complete": False}\n'
        'emit_json(run)'],capture_output=True,text=True)
    assert result.returncode==0
    assert json.loads(result.stdout)=={'complete':False}
    assert result.stderr=='nested diagnostic\n'


@pytest.mark.parametrize('prefix',['[DEBUG] diagnostic\n','{}\n'])
def test_consumer_rejects_contaminated_response_and_keeps_raw_execution(ingress,prefix):
    from riscv2x86_py.l3_intent_ingress import produce_intents,digest
    source,report,manifest,tool,_,seal=ingress
    tool.write_text('print('+repr(prefix)+',end="")\n'+tool.read_text());seal()
    original=report.read_bytes()
    with pytest.raises(ValueError,match='producer-response-json-invalid') as error:
        produce_intents(source,report,manifest)
    paths=list(report.parent.glob(report.name+'.l3-intent-execution-*.json'))
    assert len(paths)==1
    raw=json.loads(paths[0].read_text())
    assert raw['stdout'].startswith(prefix) and raw['returnCode']==0
    assert raw['semanticApproval'] is False
    assert digest(paths[0]) in str(error.value)
    assert report.read_bytes()==original
    assert not Path(str(report)+'.l3-intent-production.json').exists()
    previous=paths[0].read_bytes()
    with pytest.raises(ValueError):produce_intents(source,report,manifest)
    assert len(list(report.parent.glob(report.name+'.l3-intent-execution-*.json')))==2
    assert paths[0].read_bytes()==previous


def ready_report(status='verified'):
    return {'status':status,'sourceProgramArtifact':{},'targetProgramArtifact':{},
        'translationEvaluationLink':{'l3Requirements':{}},'attempts':[{
            'translationArtifact':{},'validation':{'layers':[
                {'level':level,'status':'verified' if level!='L3' else status,'detail':{}}
                for level in ('L0','L1','L2','L3')]}}]}


@pytest.mark.parametrize('status',['verified','failed'])
def test_audit_readiness_allows_completed_counterexamples(status):
    from riscv2x86_py.l3_lrsc_route import audit_prerequisites
    audit_prerequisites(ready_report(status))


@pytest.mark.parametrize('report,reason',[
    (None,'EVALUATION_MAPPING_REQUIRED'),
    ({'requirementStagingFailure':{'detail':'original protocol failure'}},'UPSTREAM_FAILURE'),
    ({'sourceProgramArtifact':None},'PROGRAM_ARTIFACT_REQUIRED'),
    ({'sourceProgramArtifact':{},'targetProgramArtifact':{}},'REQUIREMENTS_REQUIRED'),
    (dict(ready_report(),attempts=[]),'SINGLE_ATTEMPT_REQUIRED'),
    (ready_report('inconclusive'),'COMPLETED_LAYERS_REQUIRED'),
])
def test_audit_refuses_incomplete_reports_before_artifact_deserialization(report,reason):
    from riscv2x86_py.l3_lrsc_route import audit_result
    with pytest.raises(ValueError,match=reason):audit_result(report)


def load_script(name):
    path=Path(__file__).resolve().parents[2]/'experiment'/name
    spec=importlib.util.spec_from_file_location(name[:-3],path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def test_driver_preserves_primary_staging_failure_and_does_not_audit(tmp_path,monkeypatch):
    import riscv2x86_py.l3_lrsc_backend as backend
    import riscv2x86_py.l3_lrsc_route as route
    module=load_script('run_l3_lrsc_trace.py')
    monkeypatch.syspath_prepend(str(Path(module.__file__).parent))
    out=tmp_path/'production';source=tmp_path/'probe.c';source.write_text('source')
    frontend=tmp_path/'frontend';frontend.write_text('tool');manifest=tmp_path/'backend.json';manifest.write_text('{}')
    failure={'failureStage':'l3_intent_production','detail':'original malformed producer response'}
    def run(*args,**kwargs):
        batch=out/'batch';batch.mkdir()
        (batch/'result.json').write_text(json.dumps({'status':'inconclusive',
            'requirementStagingFailure':failure,'sourceProgramArtifact':None,'attempts':[]}))
        (batch/'batch-evaluation.json').write_text(json.dumps({'cases':[{'caseId':'probe','resultPath':'result.json'}]}))
        return SimpleNamespace(returncode=2)
    monkeypatch.setattr(module.subprocess,'run',run)
    monkeypatch.setattr(backend,'validate',lambda _:None)
    monkeypatch.setattr(route,'audit_result',lambda _:pytest.fail('audit must not run'))
    monkeypatch.setattr(sys,'argv',['driver','--input',str(source),'--frontend',str(frontend),'--backend',str(manifest),'--output',str(out)])
    assert module.main()==2
    status=json.loads((out/'run-status.json').read_text())
    assert status['currentStage']=='normal_production_result'
    assert status['upstreamFailures'][0]['requirementStagingFailure']==failure
    assert status['independentAuditDisposition']['status']=='not_run'
    assert 'original malformed producer response' in status['blockers'][0]
    assert all(status[key] is False for key in ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))


def test_inspector_empty_root_returns_failure_with_summary(tmp_path,monkeypatch,capsys):
    module=load_script('inspect_lrsc_machine.py')
    monkeypatch.setattr(sys,'argv',['inspect','--root',str(tmp_path)])
    assert module.main()==2
    summary=json.loads(capsys.readouterr().out)
    assert summary['complete'] is False and summary['errors']


def test_malformed_producer_diagnostic_survives_requirement_staging(ingress):
    from riscv2x86_py.l3_intent_ingress import produce_intents,IntentProducerError
    from riscv2x86_py.requirement_staging import write_requirement_failure,read_staged_requirements,RequirementArtifactError
    source,report,manifest,tool,_,seal=ingress
    tool.write_text('print("not JSON")');seal()
    with pytest.raises(IntentProducerError) as error:produce_intents(source,report,manifest)
    write_requirement_failure(report,error.value,'l3_intent_production')
    with pytest.raises(RequirementArtifactError) as staged:read_staged_requirements(report)
    detail=staged.value.detail
    assert staged.value.reason_code=='evaluation.l3-requirement-artifact-production-failed'
    assert detail['producerFailure']==error.value.producer_failure
    assert detail['artifactPath']==error.value.producer_failure['executionTranscriptPath']
    assert detail['schema']=='riscv2x86.l3-intent-execution-diagnostic.v1'
    assert detail['jsonPath']=='$.stdout'


def test_actual_selection_cli_owns_stdout_during_backend_loading(tmp_path):
    import riscv2x86_py.l3_mechanism_selection as selection
    request=tmp_path/'request.json';request.write_text(json.dumps(lrsc_request(tmp_path)))
    # Backend load is isolated here: this test checks CLI framing, not calibration.
    script=('import json,sys\nfrom pathlib import Path\n'
        'import riscv2x86_py.l3_mechanism_selection as m\n'
        'p=Path(m.__file__).resolve()\n'
        'def noisy_load(*args,**kwargs):\n print("backend diagnostic")\n return {}\n'
        'm.load=noisy_load\n'
        'sys.argv=["producer","--implementation",str(p),"--selection-file","fixture"]\n'
        'for name in m.producer_dependencies():sys.argv += ["--dependency",str((p.parent/name))]\n'
        'm.main()\n')
    result=subprocess.run([sys.executable,'-c',script],input=request.read_text(),capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    response=json.loads(result.stdout)
    assert response['requestIdentity']==json.loads(request.read_text())['requestIdentity']
    assert 'backend diagnostic' in result.stderr
    assert not response['profiles'][0]['complete']


@pytest.mark.parametrize('case',['nonzero','schema','startup'])
def test_other_producer_failures_keep_typed_execution_diagnostic(ingress,monkeypatch,case):
    import riscv2x86_py.l3_intent_ingress as module
    source,report,manifest,tool,_,seal=ingress
    if case=='nonzero':tool.write_text('import sys\nprint("diagnostic",file=sys.stderr)\nsys.exit(3)')
    if case=='schema':tool.write_text('print("null")')
    seal()
    if case=='startup':
        def fail(*args,**kwargs):raise OSError('startup unavailable')
        monkeypatch.setattr(module.subprocess,'run',fail)
    with pytest.raises(module.IntentProducerError) as error:module.produce_intents(source,report,manifest)
    evidence=error.value.producer_failure
    record=json.loads(Path(evidence['executionTranscriptPath']).read_text())
    assert module.digest(evidence['executionTranscriptPath'])==evidence['executionTranscriptDigest']
    assert record['returnCode']==(3 if case=='nonzero' else 0 if case=='schema' else None)
    assert record['semanticApproval'] is False


def test_receipt_replay_does_not_append_to_original_evidence_directory(ingress):
    from riscv2x86_py.l3_intent_ingress import produce_intents
    source,report,manifest,_,_,_=ingress
    original=report.read_bytes()
    result=produce_intents(source,report,manifest,replay=True)
    assert result['findings'][0]['l3IntentProfile']['complete']
    assert report.read_bytes()==original
    assert not list(report.parent.glob(report.name+'.l3-intent-*'))
