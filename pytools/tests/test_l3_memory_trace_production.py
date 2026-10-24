"""Opt-in REAL frontend/build/QEMU/provider/audit acceptance; not a fixture pass."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('cache_model',[False,True])
def test_real_ordinary_read_renamed_production(tmp_path,cache_model):
    manifest=os.environ.get('RV2X86_L3_TRACE_BACKEND','')
    if not manifest:pytest.skip('explicit calibrated dual-ISA QEMU L3 backend not selected')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND','')
    assert Path(manifest).is_file(),'selected L3 backend manifest missing'
    assert frontend and Path(frontend).is_file(),'selected real frontend missing'
    source=tmp_path/'arbitrary_file.c'
    source.write_text('#include <stdint.h>\nuint64_t independent_read_name(const uint64_t *base) {\n'
        'uint64_t result;\n__asm__ volatile("ld %[dst],24(%[src])" : [dst] "=r"(result) : [src] "r"(base) : "memory");\nreturn result;\n}\n')
    root=Path(__file__).resolve().parents[2]
    command=[sys.executable,str(root/'experiment/run_l3_memory_trace.py'),'--input',str(source),
        '--frontend',frontend,'--backend',manifest,'--output',str(tmp_path/'production')]
    if cache_model:
        from riscv2x86_py.l3_cache_model import DEFAULT
        model=tmp_path/'model.json';model.write_text(json.dumps(DEFAULT));command.extend(['--cache-model',str(model)])
    result=subprocess.run(command,capture_output=True,text=True,check=False,timeout=1200)
    logs=[str(p)+':\n'+p.read_text()[-10000:] for p in (tmp_path/'production').rglob('batch.log')]
    assert result.returncode==0,result.stdout+result.stderr+'\n'.join(logs)
    status=json.loads((tmp_path/'production/run-status.json').read_text())
    assert status['productionAcceptanceComplete']
    assert not status['physicalMicroarchitectureClaimed']
    evaluations=list((tmp_path/'production/batch/cases').rglob('evaluation-result.json'))
    assert len(evaluations)==1
    report=json.loads(evaluations[0].read_text());layers=report['attempts'][0]['validation']['layers']
    assert [x['level'] for x in layers]==['L0','L1','L2','L3']
    assert all(x['status']=='verified' for x in layers)
    raw=json.loads(layers[-1]['detail']);detail=json.loads(raw['providerDetail'])
    assert detail['observationScope']=='compiler-asm-region-only'
    assert bool(detail['cacheModelResults'])==cache_model
    for side in ('source','target'):
        assert len(detail['platformReports'][side]['events'])==4
        assert all(e['offset']==24 and e['size']==8 and e['access']=='read' for e in detail['platformReports'][side]['events'])
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['status']=='verified'
    # Independent audit must re-read raw evidence; recomputing a report hash
    # cannot conceal a changed capture, compiler region or executable.
    trace=Path(detail['platformReports']['source']['evidence']['rawTracePath'])
    trace.write_text(trace.read_text().replace(' 8 R',' 8 W',1))
    with pytest.raises(ValueError):audit_evaluation(report)
