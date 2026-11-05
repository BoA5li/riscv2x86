import json
from pathlib import Path
import sys
import pytest
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_inspection_pilot import execute,verify_members


def fixture(tmp_path,*,inspect_code=0,replay_code=0,omit=False,duplicate=False):
    source=tmp_path/'x.c';source.write_text('int x;')
    cid=identity('context')
    plan={'purpose':'compiler-acquisition-pilot-only','sourcePaths':[str(source)],
          'contextIdentities':[cid],'semanticApproval':False}
    report={'schemaVersion':'riscv2x86.real-project-context-preflight.v1','errors':[],
      'semanticApproval':False,'productionAcceptanceComplete':False,
      'records':[{'context':{'contextIdentity':cid,'sourcePath':str(source)},'status':'inspected',
                  'inspection':{'contextAcquisitionConsistent':True,'functions':[]}}]}
    if omit:report['records']=[]
    if duplicate:report['records']*=2
    report['preflightIdentity']=identity(report)
    tooling=tmp_path/'tooling';(tooling/'experiment').mkdir(parents=True)
    program=tooling/'experiment/prepare_real_project_experiment.py'
    program.write_text('''import json,sys
from pathlib import Path
if sys.argv[1]=='inspect':
 print('inspect output')
 if INSPECT_CODE:sys.exit(INSPECT_CODE)
 Path(sys.argv[sys.argv.index('--output')+1]).write_text(REPORT)
else:
 print(json.dumps({'contextReplayComplete':True,'buildVariantCount':1,'semanticApproval':False,'productionAcceptanceComplete':False}))
 sys.exit(REPLAY_CODE)
'''.replace('INSPECT_CODE',str(inspect_code)).replace('REPLAY_CODE',str(replay_code)).replace('REPORT',repr(json.dumps(report))))
    record=tmp_path/'records.json';record.write_text('{}')
    planpath=tmp_path/'plan.json';planpath.write_text(json.dumps(plan))
    return tooling,record,planpath,str(Path(sys.executable)),tmp_path/'result'


def test_completed_pilot_is_not_semantic_or_asm_inventory_approval(tmp_path):
    args=fixture(tmp_path);assert execute(*args)==0
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert state['compilerInspectionComplete'] and state['independentContextReplayComplete']
    assert not state['asmInstanceInventoryComplete'] and not state['productionAcceptanceComplete']
    summary=json.loads((args[-1]/'summary.json').read_text())
    assert summary['primaryFunctionsWithAsmSyntax']==0 and not summary['endToEndEligibilityAssessed']


@pytest.mark.parametrize('stage,code',[('inspect',5),('replay',7)])
def test_actual_failed_stage_stops_pilot(tmp_path,stage,code):
    args=fixture(tmp_path,inspect_code=code if stage=='inspect' else 0,replay_code=code if stage=='replay' else 0)
    assert execute(*args)==code
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert state['primaryFailure']['stage']==stage and state['primaryFailure']['returnCode']==code
    assert not state['independentContextReplayComplete']
    if stage=='inspect':assert not (args[-1]/'replay.log').exists()


@pytest.mark.parametrize('kind',['omit','duplicate'])
def test_successful_parser_cannot_hide_missing_or_duplicate_contexts(tmp_path,kind):
    args=fixture(tmp_path,**{kind:True});assert execute(*args)==2
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert 'MEMBER_CLOSURE_MISMATCH' in state['primaryFailure']['detail']
    assert not (args[-1]/'replay.log').exists()


def test_invalid_plan_has_a_persistent_failure_record(tmp_path):
    args=fixture(tmp_path);args[2].write_text('{}')
    assert execute(*args)==2
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert state['primaryFailure']['stage']=='plan'
    assert not (args[-1]/'inspect.log').exists()


def test_boolean_replay_count_cannot_masquerade_as_one_context(tmp_path):
    args=fixture(tmp_path)
    path=args[0]/'experiment/prepare_real_project_experiment.py'
    path.write_text(path.read_text().replace("'buildVariantCount':1", "'buildVariantCount':True"))
    assert execute(*args)==2
    state=json.loads((args[-1]/'run-status.json').read_text())
    assert 'REPLAY_INCOMPLETE' in state['primaryFailure']['detail']
    assert not state['independentContextReplayComplete']
