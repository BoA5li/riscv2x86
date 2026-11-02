"""A/B diagnostic normalization does not substitute for independent acceptance."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import pytest
from riscv2x86_py.l3_trace_support import require_json_match

spec=importlib.util.spec_from_file_location('joint_perf',Path(__file__).resolve().parents[2]/'experiment/run_joint_performance_comparison.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def group():
    row={'sample':0,'token':'unique','planIdentity':'plan','value':'0011',
         'objects':[{'objectId':'object','size':2,'base':'ab00','hex':'1122'}]}
    return {'deployment':{'spec':{'members':[{}]},'samplePlan':{'inputs':[{'layout':{'offset':0},'arguments':['01']}] }},
        'reports':{side:{'samples':[deepcopy(row)],'events':[{'sample':0,'region':0,'pc':12,'address':32,'access':'read','size':2}]} for side in ('source','target')}}


def test_same_workload_ignores_only_invocation_transport_fields():
    first=group();second=deepcopy(first)
    for report in second['reports'].values():
        report['samples'][0].update(token='another',planIdentity='path-dependent')
        report['samples'][0]['objects'][0]['base']='cdef'
        report['events'][0].update(pc=100,address=600)
    require_json_match(module.workload(first),module.workload(second),'changed')


@pytest.mark.parametrize('mutation',['input','output','size','order','missing-event','extra-sample'])
def test_workload_and_observable_output_changes_remain_visible(mutation):
    first=group();second=deepcopy(first);report=second['reports']['source']
    if mutation=='input':second['deployment']['samplePlan']['inputs'][0]['layout']['offset']=2
    if mutation=='output':report['samples'][0]['objects'][0]['hex']='3344'
    if mutation=='size':report['events'][0]['size']=4
    if mutation=='order':report['events'][0]['region']=1
    if mutation=='missing-event':report['events']=[]
    if mutation=='extra-sample':report['samples'].append(deepcopy(report['samples'][0]))
    with pytest.raises(ValueError):require_json_match(module.workload(first),module.workload(second),'changed')
