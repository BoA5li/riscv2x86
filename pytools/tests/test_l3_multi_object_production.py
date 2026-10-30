"""Opt-in real compiler/dual-ISA production and independent multi-view audit."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('width,signed,fence,reverse',[(8,False,False,False),(16,True,False,False),
    (32,False,True,False),(64,False,False,True),(64,False,True,False),(64,True,True,True)])
def test_real_multi_object_alias_state_and_audit(tmp_path,width,signed,fence,reverse):
    backend=os.environ.get('RV2X86_L3_JOINT_BACKEND')
    if not backend:pytest.skip('explicit freshly calibrated joint backend required')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND');assert frontend and Path(frontend).is_file()
    typ=('int' if signed else 'uint')+str(width)+'_t'
    parameters=[typ+' *address',typ+' *destination','uint64_t input']
    if reverse:parameters.reverse()
    load={8:'lb' if signed else 'lbu',16:'lh' if signed else 'lhu',32:'lw' if signed else 'lwu',64:'ld'}[width]
    store={8:'sb',16:'sh',32:'sw',64:'sd'}[width]
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'alias.c'
    source.write_text('#include <stdint.h>\nuint64_t alias_probe('+','.join(parameters)+'){\nuint64_t loaded,result,final_value;\n'
        '__asm__ volatile("'+load+' %0,8(%1)":"=r"(loaded):"r"(address):"memory");\n'
        '__asm__ volatile("add %0,%1,%2":"=r"(result):"r"(loaded),"r"(input):"cc");\n'
        '__asm__ volatile("'+store+' %0,8(%1)"::"r"(result),"r"(destination):"memory");\n'
        +('__asm__ volatile("fence rw,rw":::"memory");\n' if fence else '')+
        '__asm__ volatile("'+load+' %0,8(%1)":"=r"(final_value):"r"(address):"memory");\nreturn final_value;}\n')
    repo=Path(__file__).resolve().parents[2];out=tmp_path/'production'
    result=subprocess.run([sys.executable,str(repo/'experiment/run_l3_joint_trace.py'),'--input',str(source),
        '--frontend',frontend,'--backend',backend,'--output',str(out),'--timeout-seconds','240','--l3-producer-timeout-seconds','600'],
        check=False,capture_output=True,text=True,timeout=7200)
    logs='\n'.join(p.read_text(errors='replace')[-18000:] for p in out.glob('*.log'))
    assert result.returncode==0,result.stdout+result.stderr+logs
    state=json.loads((out/'run-status.json').read_text())
    assert state['currentStage']=='complete' and not state['blockers']
    assert all(state[k] is True for k in ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))
    report=json.loads(next(out.glob('batch/cases/*/evaluation-result.json')).read_text())
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['programExecutionUnitCount']==1
    groups={json.loads(a['validation']['layers'][3]['detail'])['jointCapturePath'] for a in report['attempts']}
    assert len(groups)==1 and len(report['attempts'])==4+int(fence)
    group=json.loads(Path(next(iter(groups))).read_text());p=group['deployment']['spec']
    assert len(p['objectLayout']['views'])==2 and len(p['objectLayout']['layouts'])==3
    for side in ('source','target'):
        rows=group['reports'][side]['samples'];assert len(rows)==8
        assert rows[1]['objects'][0]['base']==rows[1]['objects'][1]['base']
        assert len(group['reports'][side]['events'])==8*(3+int(fence))
    # Effective negative audit: cached success cannot hide altered raw evidence.
    trace=Path(group['reports']['source']['evidence']['rawTracePath']);lines=trace.read_text().splitlines()
    index=next(i for i,line in enumerate(lines) if line.startswith('M '));del lines[index]
    trace.write_text('\n'.join(lines)+'\n')
    with pytest.raises(ValueError):audit_evaluation(report)
