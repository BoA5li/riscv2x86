"""Benchmark diagnostics are subordinate to production and fresh audit."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import pytest
from riscv2x86_py.l3_trace_support import require_json_match

spec=importlib.util.spec_from_file_location('atomic_perf',Path(__file__).resolve().parents[2]/'experiment/run_atomic_performance_comparison.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def result(root,kind,base='0000000000001000'):
    root.mkdir();(root/'run-status.json').write_text(json.dumps({'currentStage':'complete','blockers':[],
        'executionComplete':True,'independentResultAuditComplete':True,'productionAcceptanceComplete':True}))
    inputs=[{'old':'1','input':'2','arguments':['2',None,'3']}]
    row={'sample':0,'old':'1','input':'2','result':'3','after':['3','4'],
         'objectBase':base,'token':'nonce','arguments':['2',base,'3']}
    detail={kind+'Deployment':{'samplePlan':{'inputs':inputs,'objectCellCount':2},'spec':{'returnRole':'next'}},
        'platformReports':{side:{'samples':[deepcopy(row)]} for side in ('source','target')},'comparison':{'memory':{'status':'verified'}}}
    layers=[{'level':level,'status':'verified'} for level in ('L0','L1','L2','L3')];layers[-1]['detail']=json.dumps(detail)
    report=root/'batch/cases/probe/evaluation-result.json';report.parent.mkdir(parents=True)
    report.write_text(json.dumps({'status':'verified','attempts':[{'validation':{'layers':layers}}]}))
    return report,detail


@pytest.mark.parametrize('kind',['atomic','lrsc'])
def test_only_run_specific_addresses_and_nonce_normalized(tmp_path,kind):
    result(tmp_path/'a',kind);result(tmp_path/'b',kind,'0000000000002000')
    a=module.audited_workload(tmp_path/'a',kind)[1];b=module.audited_workload(tmp_path/'b',kind)[1]
    require_json_match(a,b,'changed')


@pytest.mark.parametrize('mutation',['missing','extra','output','input','auxiliary','role'])
def test_diagnostic_comparison_does_not_hide_changed_workload(tmp_path,mutation):
    path,detail=result(tmp_path/'a','lrsc');original=module.audited_workload(tmp_path/'a','lrsc')[1]
    rows=detail['platformReports']['source']['samples']
    if mutation=='missing':rows.clear()
    if mutation=='extra':rows.append(deepcopy(rows[0]))
    if mutation=='output':rows[0]['after'][0]='9'
    if mutation=='input':detail['lrscDeployment']['samplePlan']['inputs'][0]['input']='9'
    if mutation=='auxiliary':rows[0]['arguments'][2]='9'
    if mutation=='role':detail['lrscDeployment']['spec']['returnRole']='status'
    data=json.loads(path.read_text());data['attempts'][0]['validation']['layers'][-1]['detail']=json.dumps(detail);path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        actual=module.audited_workload(tmp_path/'a','lrsc')[1];require_json_match(original,actual,'changed')


@pytest.mark.parametrize('failure',['stage','flag','layer','report'])
def test_failed_acceptance_cannot_become_performance_success(tmp_path,failure):
    report,_=result(tmp_path/'a','atomic')
    state_path=tmp_path/'a/run-status.json';state=json.loads(state_path.read_text());data=json.loads(report.read_text())
    if failure=='stage':state['currentStage']='incomplete'
    if failure=='flag':state['independentResultAuditComplete']=False
    if failure=='layer':data['attempts'][0]['validation']['layers'][-1]['status']='inconclusive'
    if failure=='report':data['status']='failed'
    state_path.write_text(json.dumps(state));report.write_text(json.dumps(data))
    with pytest.raises(ValueError):module.audited_workload(tmp_path/'a','atomic')


@pytest.mark.parametrize('policy,entries,fixed,modes',[
    ('comparison',['selection','direct'],None,['0','1']),
    ('direct',['direct','direct'],None,['0','1']),
    ('selection',['selection','selection'],None,['0','1']),
    ('comparison',['selection','direct'],'1',['1','1']),
    ('comparison',['selection','direct'],'0',['0','0']),
])
def test_benchmark_records_and_executes_selected_entry_policy(tmp_path,monkeypatch,policy,entries,fixed,modes):
    import sys
    tools=[]
    for name in ('input','frontend','backend'):
        p=tmp_path/name;p.write_text('fixture');tools.append(str(p))
    calls=[]
    def measure(command,directory,env,timeout):
        calls.append((command,dict(env)))
        if '--audit-report' not in command:
            result(directory/'production','lrsc')
            state_path=directory/'production/run-status.json'
            state=json.loads(state_path.read_text())
            state['entryMode']=command[command.index('--entry-mode')+1]
            state_path.write_text(json.dumps(state))
        return {'command':command,'returnCode':0,'wallSeconds':1.,'timedOut':False}
    monkeypatch.setattr(module,'measurement',measure)
    out=tmp_path/'comparison'
    argv=['benchmark','--kind','lrsc','--input',tools[0],
        '--frontend',tools[1],'--backend',tools[2],'--output',str(out),'--lrsc-entry',policy]
    if fixed is not None:argv.extend(('--fixed-performance-mode',fixed))
    monkeypatch.setattr(sys,'argv',argv)
    assert module.main()==0
    summary=json.loads((out/'comparison.json').read_text())
    assert summary['lrscEntryPolicy']==policy and summary['complete']
    assert [r['entryMode'] for r in summary['runs']]==entries
    assert [r['mode'] for r in summary['runs']]==modes
    assert [r['condition'] for r in summary['runs']]==['0','1']
    assert summary['comparisonAxis']==('entry-only' if fixed is not None else 'entry-and-reuse' if policy=='comparison' else 'reuse-only')
    assert len(calls)==4 and sum('--audit-report' in c for c,e in calls)==2
    for i,entry in enumerate(entries):
        command,env=calls[2*i]
        assert command[command.index('--entry-mode')+1]==entry
        assert env['RV2X86_ATOMIC_PERFORMANCE']==modes[i]


@pytest.mark.parametrize('change',['extra','missing','missing-field'])
def test_benchmark_never_truncates_argument_vector_with_zip(tmp_path,change):
    path,detail=result(tmp_path/'a','lrsc')
    args=detail['platformReports']['source']['samples'][0]['arguments']
    if change=='extra':args.append('extra')
    elif change=='missing-field':detail['platformReports']['source']['samples'][0].pop('arguments')
    else:args.pop()
    data=json.loads(path.read_text());data['attempts'][0]['validation']['layers'][-1]['detail']=json.dumps(detail)
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='ARGUMENT_COUNT_CHANGED'):
        module.audited_workload(tmp_path/'a','lrsc')


def test_benchmark_normalizes_only_the_bound_object_argument(tmp_path):
    path,detail=result(tmp_path/'a','lrsc')
    detail['platformReports']['source']['samples'][0]['arguments'][1]='another-object'
    data=json.loads(path.read_text());data['attempts'][0]['validation']['layers'][-1]['detail']=json.dumps(detail)
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='OBJECT_ARGUMENT_UNBOUND'):
        module.audited_workload(tmp_path/'a','lrsc')
