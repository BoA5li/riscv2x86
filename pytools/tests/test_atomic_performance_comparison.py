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
