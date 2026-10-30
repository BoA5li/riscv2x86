"""Real frontend and dual-ISA joint typed/fence production acceptance.

Requires freshly calibrated backend. Native fixture tests never replace this.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('width,signed,fences',[(8,False,0),(16,True,0),(32,False,0),
    (8,False,1),(16,True,1),(32,True,1),(64,False,1),(64,False,2)])
def test_real_joint_typed_access_and_fence_audit(tmp_path,width,signed,fences):
    backend=os.environ.get('RV2X86_L3_JOINT_BACKEND')
    if not backend:pytest.skip('explicit freshly calibrated joint backend required')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND');assert frontend and Path(frontend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'context.c'
    load={8:'lb' if signed else 'lbu',16:'lh' if signed else 'lhu',32:'lw' if signed else 'lwu',64:'ld'}[width]
    store={8:'sb',16:'sh',32:'sw',64:'sd'}[width]
    fence='__asm__ volatile("fence rw,rw":::"memory");\n'
    source.write_text('#include <stdint.h>\nuint64_t context_observer('+('int' if signed else 'uint')+str(width)+'_t *address,uint64_t input){\nuint64_t loaded,result;\n'
        '__asm__ volatile("'+load+' %0,8(%1)":"=r"(loaded):"r"(address):"memory");\n'
        +(fence if fences else '')+
        '__asm__ volatile("add %0,%1,%2":"=r"(result):"r"(loaded),"r"(input):"cc");\n'
        +(fence if fences==2 else '')+
        '__asm__ volatile("'+store+' %0,16(%1)"::"r"(result),"r"(address):"memory");\nreturn result;\n}\n')
    repo=Path(__file__).resolve().parents[2];output=tmp_path/'production'
    done=subprocess.run([sys.executable,str(repo/'experiment/run_l3_joint_trace.py'),'--input',str(source),
        '--frontend',frontend,'--backend',backend,'--timeout-seconds','240','--l3-producer-timeout-seconds','600',
        '--output',str(output)],capture_output=True,text=True,check=False,timeout=7200)
    logs='\n'.join(p.read_text(errors='replace')[-16000:] for p in output.glob('*.log'))
    assert done.returncode==0,done.stdout+done.stderr+logs
    state=json.loads((output/'run-status.json').read_text())
    assert state['currentStage']=='complete' and not state['blockers']
    assert all(state[k] is True for k in ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))
    report=json.loads(next(output.glob('batch/cases/*/evaluation-result.json')).read_text())
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['status']=='verified'
    assert len(report['attempts'])==3+fences
    groups=set()
    for attempt in report['attempts']:
        assert [x['status'] for x in attempt['validation']['layers']]==['verified']*4
        detail=json.loads(attempt['validation']['layers'][3]['detail']);groups.add(detail['jointCapturePath'])
        if 'synchronization' in detail['comparison']:
            assert detail['comparison']['synchronization']['physicalMemoryOrderMeasured'] is False
    assert len(groups)==1
    group=json.loads(Path(next(iter(groups))).read_text())
    for side in ('source','target'):
        events=group['reports'][side]['events']
        assert len(events)==8*(2+fences)
        assert all(e['size']==width//8 for e in events if e['access'] in ('read','write'))
        assert all(e['machineMechanism']['kind']=='ordinary-rw-fence' for e in events if e['access']=='fence')
    # Standalone audit must reread actual captured execution, not a saved verdict.
    trace=Path(group['reports']['source']['evidence']['rawTracePath'])
    raw=trace.read_text();lines=raw.splitlines()
    if fences:
        region=1;line=next(i for i,v in enumerate(lines) if v.startswith('E 0 '+str(region)+' '));del lines[line]
    else:
        line=next(i for i,v in enumerate(lines) if v.startswith('M '));del lines[line]
    trace.write_text('\n'.join(lines)+'\n')
    with pytest.raises(ValueError):audit_evaluation(report)
