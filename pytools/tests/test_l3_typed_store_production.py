"""Opt-in real frontend/L0-L3/QEMU/independent-audit typed-store matrix."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('width',[1,2,4,8])
@pytest.mark.parametrize('reverse',[False,True])
@pytest.mark.parametrize('void',[False,True])
def test_real_typed_store_and_independent_audit(tmp_path,width,reverse,void,widen=False):
    backend=os.environ.get('RV2X86_L3_TYPED_MEMORY_BACKEND')
    if not backend:pytest.skip('explicit calibrated typed-store QEMU backend not selected')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND')
    assert frontend and Path(frontend).is_file()
    assert Path(backend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'unrelated.c'
    typ='uint'+str(width*8)+'_t';parameters=[typ+' *address','uint64_t input']
    if reverse:parameters.reverse()
    mnemonic={1:'sb',2:'sh',4:'sw',8:'sd'}[width]
    source.write_text('#include <stdint.h>\n'+('void' if void else 'uint64_t' if widen else typ)+' independent_store_name('
        +','.join(parameters)+'){\n__asm__ volatile("'+mnemonic+' %[value],'+str(3*width)
        +'(%[base])" :: [base] "r"(address),[value] "r"(input) : "memory");\n'
        +('' if void else 'return address[3];\n')+'}\n')
    root=Path(__file__).resolve().parents[2];output=tmp_path/'production'
    result=subprocess.run([sys.executable,str(root/'experiment/run_l3_memory_trace.py'),
        '--input',str(source),'--frontend',frontend,'--backend',backend,'--output',str(output),
        '--timeout-seconds','240','--l3-producer-timeout-seconds','600'],
        capture_output=True,text=True,check=False,timeout=1500)
    logs=[str(p)+':\n'+p.read_text(errors='replace')[-16000:] for p in output.rglob('batch.log')]
    assert result.returncode==0,result.stdout+result.stderr+'\n'.join(logs)
    state=json.loads((output/'run-status.json').read_text())
    assert state['productionAcceptanceComplete'] is True
    assert not state['blockers']
    paths=list(output.glob('batch/cases/*/evaluation-result.json'));assert len(paths)==1
    report=json.loads(paths[0].read_text())
    assert report['status']=='verified'
    for attempt in report['attempts']:
        layers=attempt['validation']['layers']
        assert [l['level'] for l in layers]==['L0','L1','L2','L3']
        assert all(l['status']=='verified' for l in layers)
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['status']=='verified'
    detail=json.loads(report['attempts'][0]['validation']['layers'][3]['detail'])
    if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
    for side in ('source','target'):
        events=detail['platformReports'][side]['events']
        assert len(events)==4
        assert all((e['offset'],e['size'],e['access'])==(3*width,width,'write') for e in events)
    # Production counterexample: an altered capture cannot survive independent replay.
    trace=Path(detail['platformReports']['source']['evidence']['rawTracePath'])
    trace.write_text(trace.read_text().replace(' '+str(width)+' W',' '+str(width)+' R',1))
    with pytest.raises(ValueError):audit_evaluation(report)


def test_real_widened_store_return_and_independent_audit(tmp_path):
    test_real_typed_store_and_independent_audit(tmp_path,4,True,False,widen=True)
