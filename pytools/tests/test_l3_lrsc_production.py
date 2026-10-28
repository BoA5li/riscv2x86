"""Opt-in real production and independent audit; requires a calibrated backend."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

CASES=[(w,op,False) for w in (32,64) for op in ('add','and','or','xor')]+[(32,'add',True)]

@pytest.mark.parametrize('width,operation,word',CASES)
def test_real_lrsc_production_and_independent_audit(tmp_path,width,operation,word):
    backend=os.environ.get('RV2X86_L3_LRSC_BACKEND');frontend=os.environ.get('RISCV2X86_TEST_FRONTEND')
    if not backend:pytest.skip('RV2X86_L3_LRSC_BACKEND not selected')
    assert frontend and Path(frontend).is_file() and Path(backend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'unrelated.c'
    template='1: lr.'+('w' if width==32 else 'd')+'.aq %[old],(%[p])\\n\\t'+operation+('w' if word else '')+' %[next],%[old],%[value]\\n\\tsc.'+('w' if width==32 else 'd')+'.rl %[status],%[next],(%[p])\\n\\tbnez %[status],1b'
    source.write_text('#include <stdint.h>\nuint64_t unrelated(uint'+str(width)+'_t *p,uint64_t value){uint64_t old,next,status;__asm__ volatile("'+template+'": [old]"=&r"(old),[next]"=&r"(next),[status]"=&r"(status),[object]"+A"(*p):[p]"r"(p),[value]"r"(value):"memory");return old;}\n')
    root=Path(__file__).resolve().parents[2];out=tmp_path/'production'
    r=subprocess.run([sys.executable,str(root/'experiment/run_l3_lrsc_trace.py'),'--input',str(source),'--frontend',frontend,'--backend',backend,'--output',str(out),'--l3-producer-timeout-seconds','600'],capture_output=True,text=True,check=False,timeout=7200)
    assert r.returncode==0,r.stdout+r.stderr+json.dumps({str(p):p.read_text(errors='replace')[-10000:] for p in out.glob('*.log')})
    state=json.loads((out/'run-status.json').read_text());assert state['productionAcceptanceComplete'] and state['independentResultAuditComplete']
    paths=list(out.glob('batch/cases/*/evaluation-result.json'));assert len(paths)==1
    evaluation=json.loads(paths[0].read_text());layers=evaluation['attempts'][0]['validation']['layers']
    assert [(l['level'],l['status']) for l in layers]==[(l,'verified') for l in ('L0','L1','L2','L3')]
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    from riscv2x86_py.l3_lrsc_route import audit_result
    assert audit_evaluation(evaluation)['status']=='verified'
    detail=json.loads(layers[3]['detail'])
    if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
    assert set(detail['comparison'])=={'control','memory','synchronization'}
    assert all(v['status']=='verified' for v in detail['comparison'].values())
    for side in ('source','target'):
        for event in detail['platformReports'][side]['atomicEvents']:
            assert event['retryObservation']['attempts'][-1]['outcome']=='success'
            assert not any(a['failedStatusValueObserved'] for a in event['retryObservation']['attempts'])
    changed=deepcopy(evaluation);changed['attempts'][0]['validation']['layers'][3]['status']='not_run'
    with pytest.raises(ValueError):audit_result(changed)
    trace=Path(detail['platformReports']['source']['evidence']['rawTracePath']);trace.write_text(trace.read_text()+'M 0 0 0 0 8 W\n')
    with pytest.raises(ValueError):audit_result(evaluation)
