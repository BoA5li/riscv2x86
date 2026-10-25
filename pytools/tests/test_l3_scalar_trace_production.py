"""Opt-in frontend -> actual dual-QEMU -> independent L3 audit for scalars."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('operation,constant',[('addi',67),('slli',18),('addi',-7)])
def test_real_register_scalar_data_access_intent(tmp_path,operation,constant):
    manifest=os.environ.get('RV2X86_L3_TRACE_BACKEND','')
    if not manifest:pytest.skip('explicit calibrated dual-ISA QEMU L3 backend not selected')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND','')
    assert Path(manifest).is_file(),'selected L3 backend manifest missing'
    assert frontend and Path(frontend).is_file(),'selected real frontend missing'
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'unrelated_scalar.c'
    source.write_text('#include <stdint.h>\nuint64_t unrelated_scalar(uint64_t x){uint64_t out;\n'
        f'__asm__ volatile("{operation} %[dst],%[src],%[imm]" : [dst] "=r"(out) : [src] "r"(x),[imm] "i"({constant}) : "cc");\nreturn out;}}\n')
    root=Path(__file__).resolve().parents[2];output=tmp_path/'production'
    completed=subprocess.run([sys.executable,str(root/'experiment/run_l3_memory_trace.py'),
        '--input',str(source),'--frontend',frontend,'--backend',manifest,'--output',str(output)],
        capture_output=True,text=True,check=False,timeout=1200)
    logs=[str(p)+':\n'+p.read_text()[-10000:] for p in output.rglob('batch.log')]
    assert completed.returncode==0,completed.stdout+completed.stderr+'\n'.join(logs)
    status=json.loads((output/'run-status.json').read_text());assert status['productionAcceptanceComplete']
    assert status['physicalMicroarchitectureClaimed'] is False
    reports=list(output.glob('batch/cases/*/evaluation-result.json'));assert len(reports)==1
    report=json.loads(reports[0].read_text());layers=report['attempts'][0]['validation']['layers']
    assert [x['level'] for x in layers]==['L0','L1','L2','L3']
    assert all(x['status']=='verified' for x in layers)
    detail=json.loads(json.loads(layers[-1]['detail'])['providerDetail'])
    assert detail['traceDeployment']['spec']['access']=='none'
    assert detail['propertyObligations']['requiredProperties']==[
        {'propertyId':'memory.fragment-access','dimension':'access_pattern','unit':'fragment'}]
    assert detail['cacheModelResults'] is None
    for side in ('source','target'):
        actual=detail['platformReports'][side]
        assert actual['events']==[] and len(actual['samples'])==4 and 'objects' not in actual
        text=Path(actual['evidence']['rawTracePath']).read_text()
        assert sum(x.startswith('B ') for x in text.splitlines())==4
        assert sum(x.startswith('E ') for x in text.splitlines())==4
        assert text.splitlines()[-1]=='F 4 4 0 0'
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['status']=='verified'
    # Valid-looking empty stream without a matching invocation is not evidence.
    trace=Path(detail['platformReports']['source']['evidence']['rawTracePath'])
    trace.write_text(trace.read_text().replace('F 4 4 0 0','F 0 0 0 0'))
    with pytest.raises(ValueError):audit_evaluation(report)
