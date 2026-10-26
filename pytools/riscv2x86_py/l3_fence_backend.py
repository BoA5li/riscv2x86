"""Fence-specific calibration over an immutable calibrated PC/memory observer.

The base control plugin already records every executed PC and region completion.
These additional probes calibrate full/partial/missing fences on both ISAs.
"""
import argparse
import json
from pathlib import Path
from . import l3_control_backend as control
from .l3_fence_machine import region_mechanism
from .l3_status import write_status_atomic,record_failure
from .l3_trace_support import Elf,digest,identity,run,save

SCHEMA='riscv2x86.qemu-executed-fence-backend.v1'
KINDS=('full','partial','missing')
DEPENDENCIES=('l3_fence_backend.py','l3_fence_machine.py','l3_status.py','l3_trace_support.py',
 'l3_fence_deployment.py','l3_fence_spec.py','l3_fence_compare.py','l3_fence_route.py','l3_fence_intent.py',
 'l3_control_deployment.py','l3_property_obligations.py','l3_sync_obligations.py','l2_fence_ordering.py','fence_semantics.py')
parse_capture=control.parse_capture


def base(value):
    if digest(value['controlBackendPath'])!=value['controlBackendDigest']:raise ValueError('L3_FENCE_BASE_CHANGED')
    return control.validate(value['controlBackendPath'])


def command(value,side,binary,region,trace,token):
    return control.command(base(value),side,binary,region,trace,token)


def capture(value,side,binary,region,directory,calls,timeout):
    validate(value)
    result=control.capture(base(value),side,binary,region,directory,calls,timeout)
    validate(value)
    return result


def probe(side,kind):
    body=({'full':'fence rw,rw','partial':'fence r,r','missing':'addi x0,x0,0'} if side=='source'
          else {'full':'mfence','partial':'lfence','missing':'nop'})[kind]
    prefix='.option norvc\n' if side=='source' else ''
    finish='li a0,0\nli a7,93\necall\n' if side=='source' else 'movq $60,%rax\nxorq %rdi,%rdi\nsyscall\n'
    return prefix+'.text\n.globl _start\n_start:\n.globl begin\nbegin:\n'+body+'\n.globl end\nend:\n'+finish+'.section .note.GNU-stack,"",@progbits\n'


def region(elf):
    return {'start':elf.symbol('begin')[0],'end':elf.symbol('end')[0],'exits':[elf.symbol('end')[0]]}


def check_calibration(value,r):
    b=base(value);side,kind=r['side'],r['kind'];binary=Path(r['binary']);elf=Elf(binary);reg=region(elf)
    e=r['evidence'];trace=Path(e['rawTracePath']);cmd=trace.with_name('execute.command.json')
    build=Path(r['assembly']).with_name('build.command.json');c=json.loads(cmd.read_text());bc=json.loads(build.read_text())
    flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if side=='source' else []
    expected_command=[b[side+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',r['assembly'],'-o',str(binary)]
    if (elf.machine!=(243 if side=='source' else 62) or digest(binary)!=r['binaryDigest']
            or Path(r['assembly']).read_text()!=probe(side,kind) or digest(build)!=r['buildCommandDigest']
            or bc['command']!=expected_command or bc['returnCode']!=0 or bc['timedOut'] is not False
            or digest(trace)!=e['rawTraceDigest'] or digest(cmd)!=e['commandRecordDigest']
            or c['command']!=command(value,side,str(binary),reg,trace,e['token'])
            or c['returnCode']!=0 or c['timedOut'] is not False or c['stdout'] or c['stderr']):
        raise ValueError('L3_FENCE_CALIBRATION_CHANGED')
    observed=control.parse_capture(trace.read_text(),e['token'],'riscv64' if side=='source' else 'x86_64',reg,1)
    if observed!={'paths':[{'pcs':[reg['start']],'exit':reg['end']}],'memory':[]}:
        raise ValueError('L3_FENCE_CALIBRATION_TRACE_MISMATCH')
    mechanism=region_mechanism(elf,reg)
    expected={'full':'ordinary-rw-fence','missing':'nop','partial':'partial-or-io-fence' if side=='source' else 'partial-fence'}[kind]
    if mechanism['kind']!=expected or r['mechanism']!=mechanism:raise ValueError('L3_FENCE_CALIBRATION_MECHANISM_MISMATCH')


def validate(path):
    value=json.loads(Path(path).read_text()) if isinstance(path,(str,Path)) else path
    fields={'schemaVersion','controlBackendPath','controlBackendDigest','files','calibration','backendIdentity',*control.TOOLS}
    if (not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA
            or value['backendIdentity']!=identity({k:v for k,v in value.items() if k!='backendIdentity'})):
        raise ValueError('L3_FENCE_BACKEND_INVALID')
    b=base(value)
    if any(value[k]!=b[k] for k in control.TOOLS):raise ValueError('L3_FENCE_BACKEND_TOOL_CHANGED')
    required={str(Path(__file__).with_name(n).resolve()) for n in DEPENDENCIES}
    if set(value['files'])!=required:raise ValueError('L3_FENCE_BACKEND_DEPENDENCIES_MISSING')
    for p,sha in value['files'].items():
        if digest(p)!=sha:raise ValueError('L3_FENCE_BACKEND_FILE_CHANGED:'+p)
    records=value['calibration']
    if not isinstance(records,list) or len(records)!=6 or {(r['side'],r['kind']) for r in records}!={(s,k) for s in ('source','target') for k in KINDS}:
        raise ValueError('L3_FENCE_CALIBRATION_INCOMPLETE')
    for r in records:check_calibration(value,r)
    return value


def prepare(control_path,output):
    control_path=Path(control_path).resolve();b=control.validate(control_path);out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    status={'stage':'calibration','complete':False,'semanticApproval':False,'calibrationCompleted':[]}
    try:
        write_status_atomic(out/'build-status.json',status)
        value={'schemaVersion':SCHEMA,'controlBackendPath':str(control_path),'controlBackendDigest':digest(control_path),
               **{k:b[k] for k in control.TOOLS},'files':{str(Path(__file__).with_name(n).resolve()):digest(Path(__file__).with_name(n)) for n in DEPENDENCIES},'calibration':[]}
        for side in ('source','target'):
            for kind in KINDS:
                status['calibrationCurrent']={'side':side,'kind':kind};write_status_atomic(out/'build-status.json',status)
                work=out/'calibration'/side/kind;work.mkdir(parents=True);asm=work/'probe.S';asm.write_text(probe(side,kind));binary=work/'probe'
                flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if side=='source' else []
                run([b[side+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',asm,'-o',binary],work,'build')
                _,_,e=control.capture(b,side,binary,region(Elf(binary)),work/'capture',1,120)
                record={'side':side,'kind':kind,'assembly':str(asm),'binary':str(binary),'binaryDigest':digest(binary),
                        'buildCommandDigest':digest(work/'build.command.json'),'evidence':e,'mechanism':region_mechanism(Elf(binary),region(Elf(binary)))}
                check_calibration(value,record);value['calibration'].append(record)
                status['calibrationCompleted'].append({'side':side,'kind':kind});write_status_atomic(out/'build-status.json',status)
        value['backendIdentity']=identity(value);validate(value);status['stage']='publication';write_status_atomic(out/'build-status.json',status)
        save(out/'backend.json',value);status.update(stage='complete',complete=True,backendIdentity=value['backendIdentity']);write_status_atomic(out/'build-status.json',status)
        return value
    except Exception as exc:
        record_failure(out/'build-status.json',status,exc)
        raise


def main():
    p=argparse.ArgumentParser();p.add_argument('--control-backend',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    b=prepare(a.control_backend,a.output)
    print(json.dumps({'backendPath':str(Path(a.output).resolve()/'backend.json'),'backendIdentity':b['backendIdentity'],'semanticApproval':False}))
if __name__=='__main__':main()
