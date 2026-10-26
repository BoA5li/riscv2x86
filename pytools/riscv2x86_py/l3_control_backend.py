"""Separately calibrated control plugin over an unchanged reviewed QEMU backend."""
import argparse
import json
from pathlib import Path
import subprocess
from uuid import uuid4
from .l3_trace_support import Elf,digest,identity,run,save

SCHEMA='riscv2x86.qemu-control-trace-backend.v1'
KINDS=('false','true','direct','escape','read')
TOOLS=('sourceExecutor','targetExecutor','sourceCompiler','targetCompiler','sourceRunnerArguments','targetRunnerArguments')


def parse_capture(text,token,target,region,calls):
    lines=text.splitlines();header=['H','2',token,target,format(region['start'],'x'),format(region['end'],'x')]
    if not lines or lines[0].split()!=header:raise ValueError('L3_CONTROL_CAPTURE_HEADER_INVALID')
    paths=[];memory=[];active=None;finished=False;steps=0
    for line in lines[1:]:
        p=line.split()
        if finished or not p:raise ValueError('L3_CONTROL_CAPTURE_TRAILING_RECORD')
        try:
            if p[0]=='B' and len(p)==3:
                if active is not None or int(p[1])!=len(paths) or int(p[2],16)!=region['start']:raise ValueError('entry')
                active={'pcs':[],'exit':None};paths.append(active)
            elif p[0]=='P' and len(p)==4:
                pc=int(p[3],16)
                if active is None or int(p[1])!=steps or int(p[2])!=len(paths)-1 or not region['start']<=pc<region['end'] or len(active['pcs'])>=128:raise ValueError('position')
                active['pcs'].append(pc);steps+=1
            elif p[0]=='X' and len(p)==3:
                pc=int(p[2],16)
                if active is None or int(p[1])!=len(paths)-1 or pc not in region['exits'] or not active['pcs']:raise ValueError('exit')
                active['exit']=pc;active=None
            elif p[0]=='M' and len(p)==7:
                seq,sample,pc,address,width=int(p[1]),int(p[2]),int(p[3],16),int(p[4],16),int(p[5])
                if (active is None or seq!=len(memory) or sample!=len(paths)-1 or not active['pcs'] or active['pcs'][-1]!=pc
                        or width not in (1,2,4,8,16,32,64) or address<0 or p[6] not in {'R','W'}):raise ValueError('memory')
                memory.append({'sample':sample,'pc':pc,'address':address,'size':width,'access':'read' if p[6]=='R' else 'write'})
            elif p[0]=='F' and len(p)==6:
                if active is not None or list(map(int,p[1:]))!=[len(paths),len(paths),steps,len(memory),0]:raise ValueError('footer')
                finished=True
            else:raise ValueError('unknown/escape record')
        except (ValueError,IndexError) as exc:raise ValueError('L3_CONTROL_CAPTURE_INCOMPLETE:'+str(exc)) from exc
    if not finished or len(paths)!=calls:raise ValueError('L3_CONTROL_CAPTURE_INCOMPLETE')
    return {'paths':paths,'memory':memory}


def command(backend,side,binary,region,trace,token):
    if any(',' in str(p) for p in (backend['plugin'],trace)):raise ValueError('L3_CONTROL_PLUGIN_PATH_HAS_COMMA')
    option=','.join([backend['plugin'],'start='+hex(region['start']),'end='+hex(region['end']),
        'exits='+':'.join(hex(p) for p in region['exits']),'limit=4096','output='+str(Path(trace).resolve()),'token='+token])
    return [backend[side+'Executor'],*backend[side+'RunnerArguments'],'-plugin',option,str(binary),token]


def capture(backend,side,binary,region,directory,calls,timeout,*,calibration=False,allow_invalid=False):
    validate(backend,uncalibrated=calibration);directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    trace=directory/'guest-trace.log';token=uuid4().hex+uuid4().hex;before=digest(binary)
    result=run(command(backend,side,binary,region,trace,token),directory,'execute',timeout)
    validate(backend,uncalibrated=calibration)
    if before!=digest(binary) or result.stderr:raise ValueError('L3_CONTROL_EXECUTION_CHANGED_OR_STDERR')
    parsed=None if allow_invalid else parse_capture(trace.read_text(),token,'riscv64' if side=='source' else 'x86_64',region,calls)
    return parsed,result.stdout,{'token':token,'rawTracePath':str(trace),'rawTraceDigest':digest(trace),
        'commandRecordDigest':digest(directory/'execute.command.json')}


def calibration_assembly(side,kind):
    if side=='source':
        prefix='la a0,data\n' if kind=='read' else 'li a0,'+('1' if kind=='true' else '0')+'\n'
        body='ld a1,0(a0)\n' if kind=='read' else 'j forbidden\n' if kind=='escape' else 'j taken\n' if kind=='direct' else 'bnez a0,taken\n'
        finish='li a0,0\nli a7,93\necall\n'
    else:
        prefix='lea data(%rip),%rdi\n' if kind=='read' else 'movq $'+('1' if kind=='true' else '0')+',%rax\n'
        body='movq (%rdi),%rax\n' if kind=='read' else 'jmp forbidden\n' if kind=='escape' else 'jmp taken\n' if kind=='direct' else 'testq %rax,%rax\njne taken\n'
        finish='movq $60,%rax\nxorq %rdi,%rdi\nsyscall\n'
    return '.text\n.globl _start\n_start:\n'+prefix+'.globl begin\nbegin:\n'+body+'.globl end\n.globl fall\nend:\nfall:\n'+finish+'.globl taken\ntaken:\n'+finish+'.globl forbidden\nforbidden:\n'+finish+'.data\n.balign 8\n.globl data\ndata: .quad 7\n'


def calibration_region(elf,kind):
    return {'start':elf.symbol('begin')[0],'end':elf.symbol('end')[0],
            'exits':sorted([elf.symbol('fall')[0]]+([elf.symbol('taken')[0]] if kind in ('true','false','direct') else []))}


def check_calibration(raw,record):
    side,kind=record['side'],record['kind'];binary=Path(record['binary']);elf=Elf(binary)
    if elf.machine!=(243 if side=='source' else 62) or digest(binary)!=record['binaryDigest']:raise ValueError('L3_CONTROL_CALIBRATION_BINARY_CHANGED')
    region=calibration_region(elf,kind)
    evidence=record['evidence'];trace=Path(evidence['rawTracePath']);cmd_path=trace.with_name('execute.command.json')
    cmd=json.loads(cmd_path.read_text())
    if digest(trace)!=evidence['rawTraceDigest'] or digest(cmd_path)!=evidence['commandRecordDigest'] or cmd['command']!=command(raw,side,str(binary),region,trace,evidence['token']) or cmd['returnCode']!=0 or cmd['timedOut'] is not False or cmd['stderr'] or cmd['stdout']:
        raise ValueError('L3_CONTROL_CALIBRATION_EXECUTION_INVALID')
    if Path(record['assembly']).read_text()!=calibration_assembly(side,kind):raise ValueError('L3_CONTROL_CALIBRATION_SOURCE_CHANGED')
    build_path=Path(record['assembly']).with_name('build.command.json');build=json.loads(build_path.read_text())
    flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if side=='source' else []
    if (digest(build_path)!=record['buildCommandDigest'] or build['command']!=[raw[side+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',record['assembly'],'-o',str(binary)]
            or build['returnCode']!=0 or build['timedOut'] is not False):raise ValueError('L3_CONTROL_CALIBRATION_BUILD_CHANGED')
    if kind=='escape':
        expected=['H 2 '+evidence['token']+' '+('riscv64' if side=='source' else 'x86_64')+' '+format(region['start'],'x')+' '+format(region['end'],'x'),
                  'B 0 '+format(region['start'],'x'),'P 0 0 '+format(region['start'],'x'),
                  'U 0 '+format(elf.symbol('forbidden')[0],'x'),'F 1 0 1 0 1']
        if trace.read_text().splitlines()!=expected:raise ValueError('L3_CONTROL_ESCAPE_CALIBRATION_NOT_OBSERVED')
        try:parse_capture(trace.read_text(),evidence['token'],'riscv64' if side=='source' else 'x86_64',region,1)
        except ValueError:return
        raise ValueError('L3_CONTROL_ESCAPE_CALIBRATION_ACCEPTED')
    observed=parse_capture(trace.read_text(),evidence['token'],'riscv64' if side=='source' else 'x86_64',region,1)
    from .l3_control_machine import decode
    section=elf.symbol('begin')[2];s=elf.sections[section]
    code=elf.slice(s[4]+region['start']-s[3],region['end']-region['start'])
    insns=decode(code,region['start'],elf.machine);pcs=[i['pc'] for i in insns]
    if kind in ('false','true','direct'):
        from .l3_control_machine import graph,selected_path
        start=elf.symbol('_start')[0]
        prefix=elf.slice(s[4]+start-s[3],region['end']-start)
        witness=graph(prefix,start,region,elf.machine)
        selected_path(witness,observed['paths'][0]['pcs'],observed['paths'][0]['exit'],[])
        if (insns[-1]['op']!=('jump' if kind=='direct' else 'branch')
                or insns[-1]['target']!=elf.symbol('taken')[0]):raise ValueError('L3_CONTROL_CALIBRATION_TRANSFER_MISSING')
    expected_exit=elf.symbol('taken' if kind in ('true','direct') else 'fall')[0]
    if observed['paths']!=[{'pcs':pcs,'exit':expected_exit}]:raise ValueError('L3_CONTROL_CALIBRATION_PATH_MISMATCH')
    expected=[] if kind!='read' else [{'sample':0,'pc':region['start'],'address':elf.symbol('data')[0],'size':8,'access':'read'}]
    if observed['memory']!=expected:raise ValueError('L3_CONTROL_CALIBRATION_MEMORY_MISMATCH')


def validate(raw,*,uncalibrated=False):
    if isinstance(raw,(str,Path)):raw=json.loads(Path(raw).read_text())
    fields={'schemaVersion','baseBackendPath','baseBackendDigest','plugin','files','calibration','backendIdentity',*TOOLS}
    if not isinstance(raw,dict) or set(raw)!=fields or raw['schemaVersion']!=SCHEMA or raw['backendIdentity']!=identity({k:v for k,v in raw.items() if k!='backendIdentity'}):raise ValueError('L3_CONTROL_BACKEND_IDENTITY_INVALID')
    from .l3_qemu_backend import validate_backend
    if digest(raw['baseBackendPath'])!=raw['baseBackendDigest']:raise ValueError('L3_CONTROL_BASE_BACKEND_CHANGED')
    base=validate_backend(raw['baseBackendPath'])
    if any(raw[k]!=base[k] for k in TOOLS):raise ValueError('L3_CONTROL_BASE_TOOL_SELECTION_CHANGED')
    implementation=Path(__file__).resolve();plugin_source=implementation.parents[1].parent/'runtime/l3_qemu_control_trace.c'
    headers=[p for p in base['files'] if p.endswith('/include/qemu/qemu-plugin.h')]
    build_path=Path(raw['plugin']).with_name('plugin.command.json')
    required=[raw['plugin'],str(implementation),str(plugin_source),str(build_path),*headers]
    if len(headers)!=1 or not set(required)<=set(raw['files']):raise ValueError('L3_CONTROL_BACKEND_FILES_INCOMPLETE')
    for path,sha in raw['files'].items():
        if digest(path)!=sha:raise ValueError('L3_CONTROL_BACKEND_FILE_CHANGED:'+path)
    build=json.loads(build_path.read_text())
    if (build['command']!=[raw['targetCompiler'],'-std=gnu11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-I'+str(Path(headers[0]).parents[1]),str(plugin_source),'-o',raw['plugin']]
            or build['returnCode']!=0 or build['timedOut'] is not False):raise ValueError('L3_CONTROL_PLUGIN_BUILD_CHANGED')
    records=raw['calibration']
    if not isinstance(records,list) or (len(records)!=10 and not(uncalibrated and records==[])):raise ValueError('L3_CONTROL_CALIBRATION_INCOMPLETE')
    if records:
        if {(r['side'],r['kind']) for r in records}!={(s,k) for s in ('source','target') for k in KINDS}:raise ValueError('L3_CONTROL_CALIBRATION_COVERAGE_INVALID')
        for record in records:check_calibration(raw,record)
    return raw


def prepare(base_path,output):
    from .l3_qemu_backend import validate_backend
    base_path=Path(base_path).resolve();base=validate_backend(base_path);output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    status={'stage':'plugin','complete':False,'semanticApproval':False}
    def checkpoint(): (output/'build-status.json').write_text(json.dumps(status,indent=2))
    checkpoint()
    try:
        header=next(Path(p) for p in base['files'] if p.endswith('/include/qemu/qemu-plugin.h'))
        source=Path(__file__).resolve().parents[2]/'runtime/l3_qemu_control_trace.c';plugin=output/'control-trace.so'
        run([base['targetCompiler'],'-std=gnu11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-I'+str(header.parents[1]),source,'-o',plugin],output,'plugin')
        raw={'schemaVersion':SCHEMA,'baseBackendPath':str(base_path),'baseBackendDigest':digest(base_path),
             **{k:base[k] for k in TOOLS},'plugin':str(plugin),'files':{str(p):digest(p) for p in (source,plugin,header,Path(__file__).resolve(),output/'plugin.command.json')},'calibration':[]}
        raw['backendIdentity']=identity(raw);status['stage']='calibration';checkpoint();records=[]
        for side in ('source','target'):
            for kind in KINDS:
                work=output/'calibration'/side/kind;work.mkdir(parents=True)
                asm=work/'probe.S';asm.write_text(calibration_assembly(side,kind));binary=work/'probe'
                flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if side=='source' else []
                run([base[side+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',asm,'-o',binary],work,'build')
                _,stdout,evidence=capture(raw,side,binary,calibration_region(Elf(binary),kind),work/'capture',1,120,calibration=True,allow_invalid=kind=='escape')
                if stdout:raise ValueError('L3_CONTROL_CALIBRATION_STDOUT_UNEXPECTED')
                record={'side':side,'kind':kind,'binary':str(binary),'binaryDigest':digest(binary),'assembly':str(asm),'buildCommandDigest':digest(work/'build.command.json'),'evidence':evidence}
                check_calibration(raw,record);records.append(record)
        raw['calibration']=records;raw['backendIdentity']=identity({k:v for k,v in raw.items() if k!='backendIdentity'});validate(raw)
        save(output/'backend.json',raw);status.update(stage='complete',complete=True,backendIdentity=raw['backendIdentity']);checkpoint();return raw
    except Exception as exc:
        status['error']=str(exc);checkpoint();raise


def main():
    p=argparse.ArgumentParser();p.add_argument('--base-backend',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    result=prepare(a.base_backend,a.output);print(json.dumps({'backendPath':str(Path(a.output).resolve()/'backend.json'),'backendIdentity':result['backendIdentity'],'semanticApproval':False}))

if __name__=='__main__':main()
