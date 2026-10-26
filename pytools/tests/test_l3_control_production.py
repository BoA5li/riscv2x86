"""Opt-in real frontend, dual QEMU control capture and independent result audit."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('kind',['equal','not_equal','unsigned_less','signed_less','jump','goto'])
def test_real_control_production_and_counterexample(tmp_path,kind):
    backend=os.environ.get('RV2X86_L3_CONTROL_BACKEND','')
    if not backend:pytest.skip('explicit calibrated control backend not selected')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND','')
    assert Path(backend).is_file() and frontend and Path(frontend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'unrelated.c'
    if kind=='goto':
        text='unsigned long route(unsigned long value){__asm__ goto("beq %0,zero,%l[destination]"::"r"(value)::destination);return 17;destination:return 29;}'
    elif kind=='jump':
        text='unsigned long route(unsigned long selected,unsigned long other){unsigned long out;__asm__ volatile("j 1f\\n\\taddi %0,%2,0\\n1: addi %0,%1,0":"=&r"(out):"r"(selected),"r"(other):"cc");return out;}'
    else:
        instruction={'equal':'beq','not_equal':'bne','unsigned_less':'bltu','signed_less':'blt'}[kind]
        integer='long' if kind=='signed_less' else 'unsigned long'
        text='unsigned long route('+integer+' a,'+integer+' b,unsigned long yes,unsigned long no){unsigned long out;__asm__ volatile("'+instruction+' %1,%2,1f\\n\\taddi %0,%4,0\\n\\tj 2f\\n1: addi %0,%3,0\\n2:":"=&r"(out):"r"(a),"r"(b),"r"(yes),"r"(no):"cc");return out;}'
    source.write_text(text+'\n');output=tmp_path/'production';repo=Path(__file__).resolve().parents[2]
    result=subprocess.run([sys.executable,str(repo/'experiment/run_l3_control_trace.py'),'--input',str(source),'--frontend',frontend,'--backend',backend,'--output',str(output)],capture_output=True,text=True,check=False,timeout=1800)
    log=output/'batch.log'
    assert result.returncode==(1 if kind=='jump' else 0),result.stdout+result.stderr+(log.read_text()[-15000:] if log.is_file() else '')
    status=json.loads((output/'run-status.json').read_text())
    assert status['executionComplete'] and status['independentResultAuditComplete']
    assert status['productionAcceptanceComplete']==(kind!='jump')
    reports=list(output.glob('batch/cases/*/evaluation-result.json'));assert len(reports)==1
    report=json.loads(reports[0].read_text());layers=report['attempts'][0]['validation']['layers']
    assert [l['level'] for l in layers]==['L0','L1','L2','L3'] and all(l['status']=='verified' for l in layers[:3])
    from riscv2x86_py.l3_control_route import audit_result
    audited=audit_result(report);assert audited['status']==('failed' if kind=='jump' else 'verified')
    assert audited['comparison']['control']['logicalContinuation']=='verified'
    assert audited['comparison']['control']['actualTransferShape']==('failed' if kind=='jump' else 'verified')
    assert audited['comparison']['memory']['status']=='verified'
    detail=json.loads(layers[3]['detail']);trace=Path(detail['platformReports']['source']['evidence']['rawTracePath'])
    text=trace.read_text();trace.write_text(text.replace('P 0 0 ','P 1 0 ',1))
    with pytest.raises(ValueError):audit_result(report)
