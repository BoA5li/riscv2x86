"""Domain expectations never follow case names or observed success."""
import json
from pathlib import Path
from riscv2x86_py.l3_coverage_inventory import collect,diagnose
from riscv2x86_py.l3_supported_domain import catalog
from riscv2x86_py.l3_trace_support import identity


def test_catalog_has_twelve_axes_and_no_execution_approval():
    c=catalog();assert len(c['axes'])==len({r['axisId'] for r in c['axes']})==12
    assert not c['semanticApproval'] and not c['productionAcceptanceComplete']
    assert c['jointDomain']['membershipValidator']=='l3_joint_spec.spec'


def test_missing_runs_stay_in_frozen_denominator(tmp_path):
    sources=tmp_path/'inputs';sources.mkdir();results=tmp_path/'results';results.mkdir()
    for i in range(32):(sources/('unrelated_'+str(i)+'.c')).write_text('void f(void){}')
    v=collect(sources,results,capabilities=['joint'])
    assert v['sourceCount']==32 and v['statusCounts']=={'not_run':32}
    assert all(r['expectedDomainMembership']=='not_assessed' for r in v['records'])
    assert not v['productionAcceptanceComplete']


def test_l2_matching_blocker_precedes_unaudited_l3():
    layer={'level':'L2','status':'inconclusive','detail':json.dumps({'reasonCodes':['l2.provider.dimension-capability-undeclared']})}
    r={'status':'inconclusive','attempts':[{'fragmentId':'x','translationOutcome':'emitted','validation':{'layers':[
        {'level':'L0','status':'verified'},{'level':'L1','status':'verified'},layer]}}]}
    v=diagnose(r,Path('/tmp'))
    assert v['firstRecordedBlocker']=={'stage':'L2','status':'inconclusive'}
    assert v['members'][0]['blockers'][0]['substage']=='provider-resolution'
    assert v['recordedStages']['L3']==v['audit']['status']=='not_run'
    assert not v['productionAcceptanceComplete']


def test_recorded_verified_is_not_independent_acceptance(tmp_path):
    v=diagnose({'status':'verified','attempts':[]},tmp_path)
    assert v['audit']['status']=='inconclusive' and not v['productionAcceptanceComplete']


def test_tampered_report_is_a_ledger_error_not_disappearing_seed(tmp_path):
    sources=tmp_path/'inputs';sources.mkdir();(sources/'a.c').write_text('void f(void){}')
    results=tmp_path/'results';results.mkdir();(results/'evaluation-result.json').write_text('{"status":"verified"}')
    v=collect(sources,results)
    assert len(v['errors'])==1 and v['sourceCount']==1 and v['statusCounts']=={'not_run':1}


def test_all_runs_retained_without_choosing_latest_passing(tmp_path):
    sources=tmp_path/'inputs';sources.mkdir();source=sources/'a.c';source.write_text('void f(void){}')
    results=tmp_path/'results';results.mkdir()
    for name,status in (('before','failed'),('after','inconclusive')):
        directory=results/name;directory.mkdir()
        r={'status':status,'reasonCodes':['pending'],'attempts':[],
           'commands':[{'phase':'translation','status':'failed','command':['translator','--source',str(source)]}]}
        r['evaluationIdentity']=identity(r);(directory/'evaluation-result.json').write_text(json.dumps(r))
    v=collect(sources,results)
    assert len(v['records'][0]['runs'])==2 and v['statusCounts']=={'blocked':1}
