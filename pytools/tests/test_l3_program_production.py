"""Opt-in real whole-program execution; no isolated-fragment substitutes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('regions',[2,3])
def test_real_ordered_scalar_program_production(tmp_path,regions):
    backend=os.environ.get('RV2X86_L3_PROGRAM_BACKEND','')
    if not backend:pytest.skip('explicit calibrated ordered-region backend not selected')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND','')
    assert frontend and Path(frontend).is_file() and Path(backend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'independent_name.c'
    source.write_text('#include <stdint.h>\nuint64_t unrelated(uint64_t a,uint64_t b,uint64_t c){uint64_t v0,v1'+(',v2' if regions==3 else '')+';'
        '__asm__ volatile("add %0,%1,%2":"=r"(v0):"r"(a),"r"(b):"cc");'
        '__asm__ volatile("xor %0,%1,%2":"=r"(v1):"r"(v0),"r"(c):"cc");'+
        ('__asm__ volatile("and %0,%1,%2":"=r"(v2):"r"(v1),"r"(a):"cc");return v2;}' if regions==3 else 'return v1;}'))
    output=tmp_path/'production';repo=Path(__file__).resolve().parents[2]
    r=subprocess.run([sys.executable,str(repo/'experiment/run_l3_program_trace.py'),'--input',str(source),'--frontend',frontend,'--backend',backend,'--output',str(output)],capture_output=True,text=True,check=False,timeout=2400)
    logs={str(p):p.read_text(errors='replace')[-12000:] for p in output.glob('*.log')}
    assert r.returncode==0,r.stdout+r.stderr+json.dumps(logs)
    reports=list(output.glob('batch/cases/*/evaluation-result.json'));assert len(reports)==1
    report=json.loads(reports[0].read_text());assert len(report['attempts'])==regions
    from riscv2x86_py.l3_program_route import audit_result
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    audit=audit_result(report);assert audit['status']=='verified' and audit['captureGroupCount']==1 and len(audit['fragments'])==regions
    assert audit_evaluation(report)['programExecutionUnitCount']==1
    identities=set();paths=set()
    for attempt in report['attempts']:
        layers=attempt['validation']['layers'];assert [l['status'] for l in layers]==['verified']*4
        d=json.loads(layers[3]['detail']);paths.add(d['programCapturePath'])
        identities.update(v['executionIdentity'] for v in d['fragmentResult']['dimensionResults'].values())
    assert len(paths)==len(identities)==1
    group=json.loads(Path(next(iter(paths))).read_text())
    for side in ('source','target'):
        assert len(group['deployment']['sides'][side]['regions'])==regions
        assert not group['reports'][side]['events']
        assert len(group['reports'][side]['samples'])==8
    missing=json.loads(json.dumps(report));missing['attempts'].pop()
    with pytest.raises(ValueError):audit_result(missing)
    trace=Path(group['reports']['source']['evidence']['rawTracePath']);trace.write_text(trace.read_text().replace('B 0 0 ','B 0 1 ',1))
    with pytest.raises(ValueError):audit_result(report)
