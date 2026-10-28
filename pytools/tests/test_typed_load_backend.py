"""Actual native calibration binaries; callback transcripts below are fixtures."""
import json
import shutil
import subprocess
from copy import deepcopy
import pytest
from riscv2x86_py import l3_memory_backend as b
from riscv2x86_py.l3_trace_support import Elf,digest,identity,run


@pytest.mark.parametrize('width',[1,2,4,8])
def test_real_read_probe_code_and_exit(tmp_path,width):
    case={'side':'target','access':'read','width':width}
    src=tmp_path/'probe.s';binary=tmp_path/'probe';src.write_text(b.probe(case))
    tools={'targetCompiler':shutil.which('cc'),'targetExecutor':'/fixture/qemu','plugin':'/fixture/plugin','targetRunnerArguments':[]}
    run(b.build_command(tools,case,src,binary),tmp_path,'build',120)
    elf=Elf(binary);reg=b.region(elf)
    expected={1:'480fb637',2:'480fb737',4:'8b37',8:'488b37'}
    assert b.region_code(elf,reg).hex()==expected[width]
    assert subprocess.run([str(binary)]).returncode==0
    token='b'*64;trace=tmp_path/'guest-trace.log'
    trace.write_text(f"H 1 {token} x86_64 {reg['start']:x} {reg['end']:x}\nB 0 {reg['start']:x}\nM 0 0 {reg['start']:x} {elf.symbol('data')[0]:x} {width} R\nE 0 {reg['end']:x}\nF 1 1 1 0\n")
    option=','.join([tools['plugin'],'start='+hex(reg['start']),'end='+hex(reg['end']),'limit=4096','output='+str(trace.resolve()),'token='+token])
    cp=tmp_path/'execute.command.json';cp.write_text(json.dumps({'command':[tools['targetExecutor'],'-plugin',option,str(binary),token],
        'returnCode':0,'timedOut':False,'stdout':'','stderr':''}))
    record={'case':case,'assembly':str(src),'binary':str(binary),'binaryDigest':digest(binary),
        'buildCommandDigest':digest(tmp_path/'build.command.json'),'evidence':{'rawTracePath':str(trace),'rawTraceDigest':digest(trace),'token':token,'commandRecordDigest':digest(cp)}}
    b.validate_record(record,tools)
    trace.write_text(trace.read_text().replace(f'{width} R',f'{width} W'))
    record['evidence']['rawTraceDigest']=digest(trace)
    with pytest.raises(ValueError,match='EVENT_MISMATCH'):b.validate_record(record,tools)


def test_load_wrapper_requires_both_isa_complete_read_and_write_calibration(tmp_path,monkeypatch):
    base=tmp_path/'base.json';base.write_text('{}')
    tools={k:[] if k.endswith('Arguments') else '/fixture/'+k for k in b.TOOLS}
    monkeypatch.setattr(b.base,'validate_backend',lambda *a,**kw:tools)
    monkeypatch.setattr(b,'validate_record',lambda *a:None)
    value={'schemaVersion':b.LOAD_SCHEMA,'baseBackendPath':str(base),'baseBackendDigest':digest(base),**tools,
        'files':{p:digest(p) for p in b.implementation_paths()},'calibration':[{'case':c} for c in b.LOAD_CASES]}
    value['backendIdentity']=identity(value)
    b.validate_backend(value)
    assert len(value['calibration'])==16
    bad=deepcopy(value);bad['calibration'][-1]=bad['calibration'][0];bad['backendIdentity']=identity({k:v for k,v in bad.items() if k!='backendIdentity'})
    with pytest.raises(ValueError,match='COVERAGE_INVALID'):b.validate_backend(bad)
    for width in (1,2,4):
        with pytest.raises(ValueError,match='LOAD_WIDTH_CALIBRATION_REQUIRED'):
            b.require_access({'schemaVersion':b.SCHEMA},{'access':'read','width':width})
        b.require_access(value,{'access':'read','width':width})
