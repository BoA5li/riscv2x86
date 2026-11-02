"""Opt-in real frontend/dual-ISA definitions and joint-alias acceptance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('width,pointer_count,fence',[(16,3,False),(64,3,True),(16,4,True),(64,4,False)])
def test_real_redefinition_and_complete_alias_layouts(tmp_path,width,pointer_count,fence):
    backend=os.environ.get('RV2X86_L3_JOINT_BACKEND')
    if not backend:pytest.skip('freshly calibrated joint backend required')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND');assert frontend and Path(frontend).is_file()
    names=['first','second','third','fourth'][:pointer_count]
    load,store=('lhu','sh') if width==16 else ('ld','sd')
    source=tmp_path/'inputs'/'transfer.c';source.parent.mkdir()
    source.write_text('#include <stdint.h>\nuint64_t transfer_views('+','.join('uint'+str(width)+'_t *'+n for n in names)+'){\nuint64_t value;\n'
        '__asm__ volatile("'+load+' %0,0(%1)":"=r"(value):"r"(first):"memory");\n'
        '__asm__ volatile("'+store+' %0,0(%1)"::"r"(value),"r"(second):"memory");\n'
        +('__asm__ volatile("fence rw,rw":::"memory");\n' if fence else '')+
        '__asm__ volatile("'+load+' %0,0(%1)":"=r"(value):"r"(third):"memory");\n'
        '__asm__ volatile("'+store+' %0,0(%1)"::"r"(value),"r"('+('fourth' if pointer_count==4 else 'first')+'):"memory");\nreturn value;}\n')
    repo=Path(__file__).resolve().parents[2];out=tmp_path/'production'
    result=subprocess.run([sys.executable,str(repo/'experiment/run_l3_joint_trace.py'),'--input',str(source),
        '--frontend',frontend,'--backend',backend,'--output',str(out),'--timeout-seconds','240',
        '--l3-producer-timeout-seconds','600'],capture_output=True,text=True,check=False,timeout=7200)
    assert result.returncode==0,result.stdout+result.stderr+'\n'.join(p.read_text(errors='replace')[-18000:] for p in out.glob('*.log'))
    state=json.loads((out/'run-status.json').read_text())
    assert state['currentStage']=='complete' and not state['blockers']
    assert all(state[k] is True for k in ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))
    report=json.loads(next(out.glob('batch/cases/*/evaluation-result.json')).read_text())
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['programExecutionUnitCount']==1
    details=[json.loads(a['validation']['layers'][3]['detail']) for a in report['attempts']]
    groups={d['jointCapturePath'] for d in details};assert len(groups)==1
    group=json.loads(Path(next(iter(groups))).read_text());deployment=group['deployment']
    program,plan=deployment['spec'],deployment['samplePlan'];flow=program['valueFlowContract']
    assert len(flow['definitions'])==2
    assert flow['returnedVersion']==flow['definitions'][-1]
    assert len(program['objectLayout']['views'])==pointer_count
    assert plan['allDeclaredLayoutsScheduled'] and all(r['samples'] for r in plan['layoutCoverage'])
    assert len(plan['inputs'])>8
    if pointer_count==4:assert len(plan['inputs'])>32
    for side in ('source','target'):
        assert len(group['reports'][side]['samples'])==len(plan['inputs'])
        assert len(group['reports'][side]['events'])==len(plan['inputs'])*(4+int(fence))
    # Standalone audit rereads raw events even after production succeeded.
    trace=Path(group['reports']['source']['evidence']['rawTracePath'])
    lines=trace.read_text().splitlines();i=next(i for i,s in enumerate(lines) if s.startswith('M '));del lines[i]
    trace.write_text('\n'.join(lines)+'\n')
    with pytest.raises(ValueError):audit_evaluation(report)
