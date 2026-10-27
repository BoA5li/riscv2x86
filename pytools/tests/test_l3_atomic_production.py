"""Opt-in real direct-atomic production, unrelated names and negative audits."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

CASES=[(64,'fetch_add','relaxed',False),(32,'fetch_add','acq_rel',False),
       (64,'exchange','release',False),(32,'exchange','acquire',False),
       (64,'fetch_add','relaxed',True),(32,'exchange','relaxed',True)]

CASES += [(w,op,order,discard) for op in ('fetch_and','fetch_or','fetch_xor')
          for w,order,discard in ((64,'relaxed',False),(32,'acq_rel',False),(64,'acquire',True),(32,'release',True))]


@pytest.mark.parametrize('width,operation,order,discard',CASES)
def test_real_direct_atomic_renamed_production(tmp_path,width,operation,order,discard):
    backend=os.environ.get('RV2X86_L3_ATOMIC_BACKEND','')
    if not backend:pytest.skip('explicit calibrated direct atomic RMW backend not selected')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND','')
    assert Path(backend).is_file() and frontend and Path(frontend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'unrelated.c'
    opcode={'fetch_add':'amoadd','exchange':'amoswap','fetch_and':'amoand','fetch_or':'amoor','fetch_xor':'amoxor'}[operation]+('.w' if width==32 else '.d')+{'relaxed':'','acquire':'.aq','release':'.rl','acq_rel':'.aqrl'}[order]
    if discard:
        body='__asm__ volatile("'+opcode+' zero,%1,%0": "+A"(*p):"r"(v):"memory");'
    else:
        body='uint64_t out;__asm__ volatile("'+opcode+' %0,%2,%1":"=r"(out),"+A"(*p):"r"(v):"memory");return out;'
    source.write_text('#include <stdint.h>\n'+('void' if discard else 'uint64_t')+' unrelated(uint'+str(width)+'_t *p,uint64_t v){'+body+'}\n')
    root=Path(__file__).resolve().parents[2];out=tmp_path/'production'
    r=subprocess.run([sys.executable,str(root/'experiment/run_l3_atomic_trace.py'),'--input',str(source),'--frontend',frontend,'--backend',backend,'--output',str(out),'--l3-producer-timeout-seconds','600'],capture_output=True,text=True,check=False,timeout=7200)
    logs={str(p):p.read_text(errors='replace')[-12000:] for p in out.glob('*.log')}
    assert r.returncode==0,r.stdout+r.stderr+json.dumps(logs)
    status=json.loads((out/'run-status.json').read_text());assert status['productionAcceptanceComplete'] and status['independentResultAuditComplete']
    reports=list(out.glob('batch/cases/*/evaluation-result.json'));assert len(reports)==1
    evaluation=json.loads(reports[0].read_text());layers=evaluation['attempts'][0]['validation']['layers']
    assert [(l['level'],l['status']) for l in layers]==[(level,'verified') for level in ('L0','L1','L2','L3')]
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    from riscv2x86_py.l3_atomic_route import audit_result
    assert audit_evaluation(evaluation)['status']=='verified'
    detail=json.loads(layers[3]['detail'])
    if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
    assert len(detail['comparison']['synchronization']['subpropertyResults'])==4
    assert detail['comparison']['synchronization']['concurrentAtomicityMeasured'] is False
    for side in ('source','target'):
        events=detail['platformReports'][side]['atomicEvents'];assert events
        assert all(e['completed'] and e['callbackShapeMatched'] and e['outcomeMatchesApprovedOperation'] and e['mechanismSatisfiesApprovedContract'] for e in events)
    if operation in {'fetch_and','fetch_or','fetch_xor'} and not discard:
        assert detail['platformReports']['target']['mechanism']['instruction']['mechanism']=='x86-locked-cas-loop'
        for event in detail['platformReports']['target']['atomicEvents']:
            assert event['retryObservation']['abstractSuccessfulRmwCount']==1
            assert event['retryObservation']['attempts'][-1]['outcome']=='success'
    changed=deepcopy(evaluation);changed['attempts'][0]['validation']['layers'][3]['status']='not_run'
    with pytest.raises(ValueError):audit_result(changed)
    trace=Path(detail['platformReports']['source']['evidence']['rawTracePath']);trace.write_text(trace.read_text()+'M 0 0 0 0 8 W\n')
    with pytest.raises(ValueError):audit_result(evaluation)
