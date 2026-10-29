"""Calibrated multi-region observer; legacy QEMU preparation stays immutable."""
import argparse
import json
import tempfile
from pathlib import Path
from uuid import uuid4
from .l3_trace_support import Elf,digest,identity,run,save,require_json_document,require_json_match
from .l3_qemu_backend import validate_backend
from .l3_status import write_status_atomic, record_failure

SCHEMA='riscv2x86.qemu-joint-regions.v1'
TOOLS=('sourceExecutor','targetExecutor','sourceCompiler','targetCompiler','sourceRunnerArguments','targetRunnerArguments')


def parse_capture(text,token,side,regions,calls):
    lines=text.splitlines();events=[];active=False;sample=0;index=0;finished=False
    if not lines or lines[0].split()!=['H','3',token,'riscv64' if side=='source' else 'x86_64']:raise ValueError('L3_JOINT_CAPTURE_HEADER')
    for line in lines[1:]:
        p=line.split()
        if finished or not p:raise ValueError('L3_JOINT_CAPTURE_TRAILING')
        try:
            if p[0] in ('B','E') and len(p)==4:
                if sample>=calls or int(p[1])!=sample or int(p[2])!=index:raise ValueError('order')
                region=regions[index];begin=p[0]=='B'
                if active==begin or int(p[3],16)!=region['start' if begin else 'end']:raise ValueError('boundary')
                active=begin
                if not begin:
                    index+=1
                    if index==len(regions):index=0;sample+=1
            elif p[0]=='M' and len(p)==8:
                seq,s,i,pc,address,size=int(p[1]),int(p[2]),int(p[3]),int(p[4],16),int(p[5],16),int(p[6])
                if (not active or seq!=len(events) or (s,i)!=(sample,index) or not regions[index]['start']<=pc<regions[index]['end']
                        or address<0 or size not in (1,2,4,8,16,32,64) or p[7] not in ('R','W')):raise ValueError('memory')
                events.append({'sample':s,'region':i,'pc':pc,'address':address,'size':size,'access':p[7]})
            elif p[0]=='F' and len(p)==5:
                if active or sample!=calls or index or list(map(int,p[1:]))!=[calls,0,len(events),0]:raise ValueError('footer')
                finished=True
            else:raise ValueError('unexpected/escape')
        except (ValueError,IndexError) as exc:raise ValueError('L3_JOINT_CAPTURE_INCOMPLETE:'+str(exc)) from exc
    if not finished:raise ValueError('L3_JOINT_CAPTURE_INCOMPLETE')
    return events


def command(b,side,binary,regions,path,token):
    if any(',' in str(p) for p in (b['plugin'],path)):raise ValueError('L3_JOINT_PLUGIN_PATH_AMBIGUOUS')
    ranges=';'.join(hex(r['start'])+':'+hex(r['end']) for r in regions)
    return [b[side+'Executor'],*b[side+'RunnerArguments'],'-plugin',b['plugin']+',regions='+ranges+',output='+str(path)+',token='+token,str(binary),token]


def capture(b,side,binary,regions,directory,calls,timeout,*,calibration=False,negative=False):
    validate(b,uncalibrated=calibration);directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    path=directory/'guest-trace.log';token=uuid4().hex+uuid4().hex;before=digest(binary)
    result=run(command(b,side,binary,regions,path,token),directory,'execute',timeout)
    validate(b,uncalibrated=calibration)
    if result.stderr or digest(binary)!=before:raise ValueError('L3_JOINT_EXECUTION_CHANGED_OR_STDERR')
    events=None if negative else parse_capture(path.read_text(),token,side,regions,calls)
    return events,result.stdout,{'token':token,'rawTracePath':str(path),'rawTraceDigest':digest(path),'commandRecordDigest':digest(directory/'execute.command.json')}


def probe(side,kind):
    prefix=('la a0,data\n' if kind in {'read','write'} else '') if side=='source' else ('lea data(%rip),%rdi\n' if kind in {'read','write'} else '')
    prefix+=('j b1\n' if side=='source' else 'jmp b1\n') if kind=='skip' else ''
    op='addi a1,a1,0\n' if side=='source' else 'nop\n'
    access=('ld a1,0(a0)\n' if side=='source' else 'movq (%rdi),%rax\n') if kind=='read' else op
    if kind=='write':
        prefix+=('li a1,13\n' if side=='source' else 'movq $13,%rax\n')
        access='sd a1,0(a0)\n' if side=='source' else 'movq %rax,(%rdi)\n'
    finish='li a0,0\nli a7,93\necall\n' if side=='source' else 'movq $60,%rax\nxorq %rdi,%rdi\nsyscall\n'
    return '.text\n.globl _start\n_start:\n'+prefix+'.globl b0\nb0:\n'+op+'.globl e0\ne0:\n'+op+'.globl b1\nb1:\n'+access+'.globl e1\ne1:\n'+finish+'.data\n.balign 8\n.globl data\ndata: .quad 7\n'


def regions_of(elf):return [{'start':elf.symbol('b'+str(i))[0],'end':elf.symbol('e'+str(i))[0]} for i in range(2)]


def check_calibration(b,r):
    side,kind=r['side'],r['kind'];elf=Elf(r['binary']);regions=regions_of(elf);e=r['evidence'];trace=Path(e['rawTracePath']);cp=trace.with_name('execute.command.json')
    build=Path(r['assembly']).with_name('build.command.json');flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if side=='source' else []
    c=json.loads(cp.read_text());bc=json.loads(build.read_text())
    if (elf.machine!=(243 if side=='source' else 62) or digest(r['binary'])!=r['binaryDigest'] or Path(r['assembly']).read_text()!=probe(side,kind)
            or digest(trace)!=e['rawTraceDigest'] or digest(cp)!=e['commandRecordDigest'] or digest(build)!=r['buildCommandDigest']
            or c['command']!=command(b,side,r['binary'],regions,trace,e['token']) or c['returnCode']!=0 or c['timedOut'] is not False or c['stdout'] or c['stderr']
            or bc['command']!=[b[side+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',r['assembly'],'-o',r['binary']]
            or bc['returnCode']!=0 or bc['timedOut'] is not False):raise ValueError('L3_JOINT_CALIBRATION_CHANGED')
    with tempfile.TemporaryDirectory(prefix='rv2x86-joint-calibration-') as temporary:
        work=Path(temporary);assembly=work/'probe.S';assembly.write_text(probe(side,kind));binary=work/'probe'
        run([b[side+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',assembly,'-o',binary],work,'rebuild',120)
        require_json_match(Elf(binary).execution_image(),elf.execution_image(),'L3_JOINT_CALIBRATION_IMAGE_CHANGED')
    if kind=='skip':
        if trace.read_text().splitlines()!=['H 3 '+e['token']+' '+('riscv64' if side=='source' else 'x86_64'),
            'U 0 1 '+format(regions[1]['start'],'x'),'F 0 0 0 1']:raise ValueError('L3_JOINT_SKIPPED_REGION_NOT_DETECTED')
        return
    events=parse_capture(trace.read_text(),e['token'],side,regions,1)
    expected=[] if kind=='empty' else [{'sample':0,'region':1,'pc':regions[1]['start'],'address':elf.symbol('data')[0],'size':8,'access':'W' if kind=='write' else 'R'}]
    if events!=expected:raise ValueError('L3_JOINT_CALIBRATION_MISMATCH')


def validate(value,*,uncalibrated=False,_context=None):
    b=json.loads(Path(value).read_text()) if isinstance(value,(str,Path)) else value
    require_json_document(b,'L3_JOINT_BACKEND_JSON_INVALID')
    fields={'schemaVersion','baseBackendPath','baseBackendDigest','plugin','files','calibration','backendIdentity',*TOOLS}
    if not isinstance(b,dict) or set(b)!=fields or b['schemaVersion']!=SCHEMA or b['backendIdentity']!=identity({k:v for k,v in b.items() if k!='backendIdentity'}):raise ValueError('L3_JOINT_BACKEND_INVALID')
    from .l3_backend_validation import checked
    base=checked(_context,validate_backend,b['baseBackendPath'])
    if digest(b['baseBackendPath'])!=b['baseBackendDigest'] or any(b[k]!=base[k] for k in TOOLS):raise ValueError('L3_JOINT_BASE_CHANGED')
    impl=Path(__file__).resolve();source=impl.parents[2]/'runtime/l3_qemu_program_trace.c';headers=[p for p in base['files'] if p.endswith('/include/qemu/qemu-plugin.h')];build=Path(b['plugin']).with_name('plugin.command.json')
    if len(headers)!=1 or not {str(impl),str(impl.with_name('l3_status.py')),str(impl.with_name('l3_backend_validation.py')),str(source),str(build),b['plugin'],headers[0]}<=set(b['files']):raise ValueError('L3_JOINT_BACKEND_FILES_MISSING')
    from .l3_implementation_dependencies import implementation_paths
    if not set(implementation_paths())<=set(b['files']):raise ValueError('L3_JOINT_IMPLEMENTATION_FILES_MISSING')
    for p,sha in b['files'].items():
        if digest(p)!=sha:raise ValueError('L3_JOINT_BACKEND_FILE_CHANGED:'+p)
    c=json.loads(build.read_text())
    if c['command']!=[b['targetCompiler'],'-std=gnu11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-I'+str(Path(headers[0]).parents[1]),str(source),'-o',b['plugin']] or c['returnCode']!=0 or c['timedOut'] is not False:raise ValueError('L3_JOINT_PLUGIN_BUILD_CHANGED')
    records=b['calibration']
    if not isinstance(records,list) or not (uncalibrated and records==[]) and (len(records)!=8 or {(r['side'],r['kind']) for r in records}!={(s,k) for s in ('source','target') for k in ('empty','read','write','skip')}):raise ValueError('L3_JOINT_CALIBRATION_INCOMPLETE')
    for r in records:check_calibration(b,r)
    return b


def prepare(base_path,output):
    base_path=Path(base_path).resolve();base=validate_backend(base_path);out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    status={'stage':'plugin','status':'running','complete':False,'semanticApproval':False,'calibrationCompleted':[]}
    def checkpoint():write_status_atomic(out/'build-status.json',status)
    try:
        checkpoint()
        impl=Path(__file__).resolve();source=impl.parents[2]/'runtime/l3_qemu_program_trace.c';header=next(Path(p) for p in base['files'] if p.endswith('/include/qemu/qemu-plugin.h'));plugin=out/'program-trace.so'
        run([base['targetCompiler'],'-std=gnu11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-I'+str(header.parents[1]),source,'-o',plugin],out,'plugin')
        b={'schemaVersion':SCHEMA,'baseBackendPath':str(base_path),'baseBackendDigest':digest(base_path),**{k:base[k] for k in TOOLS},'plugin':str(plugin),'files':{str(p):digest(p) for p in (impl,impl.with_name('l3_status.py'),impl.with_name('l3_backend_validation.py'),source,header,plugin,out/'plugin.command.json')},'calibration':[]}
        from .l3_implementation_dependencies import implementation_paths
        b['files'].update({p:digest(p) for p in implementation_paths()})
        b['backendIdentity']=identity(b);status['stage']='calibration';checkpoint();records=[]
        for side in ('source','target'):
            for kind in ('empty','read','write','skip'):
                status['calibrationCurrent']={'side':side,'kind':kind};checkpoint()
                work=out/'calibration'/side/kind;work.mkdir(parents=True);asm=work/'probe.S';asm.write_text(probe(side,kind));binary=work/'probe'
                flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if side=='source' else []
                run([base[side+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',asm,'-o',binary],work,'build')
                _,_,e=capture(b,side,binary,regions_of(Elf(binary)),work/'capture',1,120,calibration=True,negative=kind=='skip')
                r={'side':side,'kind':kind,'binary':str(binary),'binaryDigest':digest(binary),'assembly':str(asm),'buildCommandDigest':digest(work/'build.command.json'),'evidence':e};check_calibration(b,r);records.append(r)
                status['calibrationCompleted'].append({'side':side,'kind':kind});checkpoint()
        status['stage']='validation';checkpoint()
        b['calibration']=records;b['backendIdentity']=identity({k:v for k,v in b.items() if k!='backendIdentity'});validate(b)
        status['stage']='publication';checkpoint();save(out/'backend.json',b)
        status.update(stage='final_status',complete=False,backendIdentity=b['backendIdentity'],backendPublished=True);checkpoint()
        status.update(stage='complete',status='complete',complete=True);checkpoint();return b
    except Exception as exc:
        record_failure(out/'build-status.json',status,exc)
        raise


def main():
    p=argparse.ArgumentParser();p.add_argument('--base-backend',required=True);p.add_argument('--output',required=True);a=p.parse_args();b=prepare(a.base_backend,a.output)
    print(json.dumps({'backendPath':str(Path(a.output).resolve()/'backend.json'),'backendIdentity':b['backendIdentity'],'semanticApproval':False}))
if __name__=='__main__':main()
