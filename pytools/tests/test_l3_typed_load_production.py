"""Opt-in real compiler -> L0-L3 -> independent audit, including counterexamples."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

CASES=[(width,extension,signed,64,False) for width,extension in
       ((8,'sx'),(8,'zx'),(16,'sx'),(16,'zx'),(32,'sx'),(32,'zx'),(64,'id'))
       for signed in (False,True)] + [(16,'zx',False,64,True),(32,'zx',True,32,False),(32,'zx',False,32,False)]


@pytest.mark.parametrize('width,extension,signed,carrier,const',CASES)
def test_real_typed_load_and_audit(tmp_path,width,extension,signed,carrier,const,pointee_signed=False):
    backend=os.environ.get('RV2X86_L3_TYPED_LOAD_BACKEND')
    if not backend:pytest.skip('explicit freshly calibrated read/write backend required')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND')
    assert frontend and Path(frontend).is_file()
    from riscv2x86_py.l3_memory_backend import validate_backend,require_access
    require_access(validate_backend(backend),{'access':'read','width':width//8})
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'independent.c'
    result='int64_t' if signed else 'uint64_t';out=('int' if signed else 'uint')+str(carrier)+'_t'
    op={8:('lb','lbu'),16:('lh','lhu'),32:('lw','lwu'),64:('ld','ld')}[width][extension!='sx']
    source.write_text('#include <stdint.h>\n'+result+' independent_probe('+('const ' if const else '')+('int' if pointee_signed else 'uint')+str(width)+'_t *address){\n'
        +out+' output;\n__asm__ volatile("'+op+' %[out],'+str(3*(width//8))+'(%[base])" : [out] "=r"(output) : [base] "r"(address) : "memory");\nreturn output;\n}\n')
    root=Path(__file__).resolve().parents[2];output=tmp_path/'production'
    done=subprocess.run([sys.executable,str(root/'experiment/run_l3_memory_trace.py'),'--input',str(source),
        '--frontend',frontend,'--backend',backend,'--timeout-seconds','240','--l3-producer-timeout-seconds','600','--output',str(output)],
        capture_output=True,text=True,timeout=1500,check=False)
    logs='\n'.join(str(p)+':\n'+p.read_text(errors='replace')[-14000:] for p in output.rglob('batch.log'))
    assert done.returncode==0,done.stdout+done.stderr+logs
    state=json.loads((output/'run-status.json').read_text())
    assert state['productionAcceptanceComplete'] is True and not state['blockers']
    paths=list(output.glob('batch/cases/*/evaluation-result.json'));assert len(paths)==1
    report=json.loads(paths[0].read_text());assert report['status']=='verified'
    for attempt in report['attempts']:
        assert [(l['level'],l['status']) for l in attempt['validation']['layers']]==[(l,'verified') for l in ('L0','L1','L2','L3')]
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['status']=='verified'
    detail=json.loads(report['attempts'][0]['validation']['layers'][3]['detail'])
    if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
    for side in ('source','target'):
        events=detail['platformReports'][side]['events'];assert len(events)==4
        assert all((e['offset'],e['size'],e['access'])==(3*(width//8),width//8,'read') for e in events)
    trace=Path(detail['platformReports']['source']['evidence']['rawTracePath'])
    trace.write_text(trace.read_text().replace(' '+str(width//8)+' R',' '+str(width//8)+' W',1))
    with pytest.raises(ValueError):audit_evaluation(report)


def test_real_signed_pointee_load_and_audit(tmp_path):
    test_real_typed_load_and_audit(tmp_path,8,"sx",False,64,False,pointee_signed=True)
