"""Opt-in dual-ISA real fence production and independent negative audits."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('mask',['rw, rw','rw,rw'])
def test_real_renamed_fence_production(tmp_path,mask):
    backend=os.environ.get('RV2X86_L3_FENCE_BACKEND','')
    if not backend:pytest.skip('explicit calibrated executed-fence backend not selected')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND','')
    assert Path(backend).is_file() and frontend and Path(frontend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'independent_location.c'
    source.write_text('void unrelated_sync(void) { __asm__ volatile ("fence '+mask+'" ::: "memory"); }\n')
    root=Path(__file__).resolve().parents[2];output=tmp_path/'production'
    result=subprocess.run([sys.executable,str(root/'experiment/run_l3_fence_trace.py'),
        '--input',str(source),'--frontend',frontend,'--backend',backend,'--output',str(output)],
        capture_output=True,text=True,check=False,timeout=2400)
    logs={str(p):p.read_text(errors='replace')[-12000:] for p in output.glob('*.log')}
    assert result.returncode==0,result.stdout+result.stderr+json.dumps(logs)
    status=json.loads((output/'run-status.json').read_text())
    assert status['executionComplete'] and status['independentResultAuditComplete'] and status['productionAcceptanceComplete']
    paths=list(output.glob('batch/cases/*/evaluation-result.json'));assert len(paths)==1
    evaluation=json.loads(paths[0].read_text());layers=evaluation['attempts'][0]['validation']['layers']
    assert [(l['level'],l['status']) for l in layers]==[(l,'verified') for l in ('L0','L1','L2','L3')]
    from riscv2x86_py.l3_fence_route import audit_result
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    audited=audit_result(evaluation)
    assert audited['status']=='verified' and audited['physicalMicroarchitectureClaimed'] is False
    assert audit_evaluation(evaluation)['status']=='verified'
    detail=json.loads(layers[3]['detail'])
    if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
    sync=detail['comparison']['synchronization']
    assert sync['physicalMemoryOrderMeasured'] is False
    assert all(x['status']=='verified' for x in sync['subpropertyResults'].values())
    for side in ('source','target'):
        r=detail['platformReports'][side]
        assert not r['memory'] and len(r['fenceEvents'])==len(r['samples'])==3
        assert all(e['kind']=='ordinary-rw-fence' and e['completed'] for e in r['fenceEvents'])
    # Neither a changed report nor changed immutable raw evidence may pass audit.
    changed=deepcopy(evaluation);changed['attempts'][0]['validation']['layers'][3]['status']='inconclusive'
    with pytest.raises(ValueError):audit_result(changed)
    changed=deepcopy(evaluation);changed['translationEvaluationLink']['l3Requirements']['requirements'][0]['requiredProperties'].pop()
    with pytest.raises(ValueError):audit_result(changed)
    trace=Path(detail['platformReports']['source']['evidence']['rawTracePath'])
    trace.write_text(trace.read_text().replace('P 0 0 ','P 1 0 ',1))
    with pytest.raises(ValueError):audit_result(evaluation)
