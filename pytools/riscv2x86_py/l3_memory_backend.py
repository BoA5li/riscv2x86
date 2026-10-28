"""Width-calibrated ordinary-store wrapper over an unchanged reviewed QEMU base.

Legacy backends remain valid for their existing domain. Narrow stores require
fresh 1/2/4/8-byte calibration on both ISAs; no manifest hash substitution.
"""
import argparse
import json
from pathlib import Path
import tempfile
from . import l3_qemu_backend as base
from .l3_trace_support import Elf, digest, identity, run, save, require_json_match, require_json_document
from .l3_implementation_dependencies import implementation_paths
from .l3_status import write_status_atomic, record_failure

SCHEMA='riscv2x86.qemu-typed-store-backend.v1'
TOOLS=('sourceExecutor','targetExecutor','sourceCompiler','targetCompiler',
       'sourceRunnerArguments','targetRunnerArguments','plugin')
CASES=[{'side':side,'width':width} for side in ('source','target') for width in (1,2,4,8)]


def probe(case):
    width=case['width']
    if case['side']=='source':
        return ('.option norvc\n.text\n.globl _start\n_start:la a0,data\nli a1,128\n'
            '.globl begin\nbegin:'+{1:'sb',2:'sh',4:'sw',8:'sd'}[width]+' a1,0(a0)\n'
            '.globl end\nend:ld t0,0(a0)\nli t1,128\nbne t0,t1,bad\nli a0,0\nj done\n'
            'bad:li a0,9\ndone:li a7,93\necall\n.data\n.balign 8\n.globl data\ndata:.quad 0\n')
    return ('.text\n.globl _start\n_start:lea data(%rip),%rdi\nmovq $128,%rsi\n'
        '.globl begin\nbegin:mov'+{1:'b %sil',2:'w %si',4:'l %esi',8:'q %rsi'}[width]+',(%rdi)\n'
        '.globl end\nend:cmpq $128,(%rdi)\njne bad\nxorq %rdi,%rdi\njmp done\n'
        'bad:movq $9,%rdi\ndone:movq $60,%rax\nsyscall\n.data\n.balign 8\n.globl data\ndata:.quad 0\n')


def expected_code(case):
    if case['side']=='source':
        return ((11<<20)|(10<<15)|({1:0,2:1,4:2,8:3}[case['width']]<<12)|0x23).to_bytes(4,'little')
    return bytes.fromhex({1:'408837',2:'668937',4:'8937',8:'488937'}[case['width']])


def build_command(backend,case,assembly,binary):
    flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if case['side']=='source' else []
    return [backend[case['side']+'Compiler'],*flags,'-nostdlib','-static','-no-pie',
        '-Wl,--build-id=none',str(assembly),'-o',str(binary)]


def region(elf):
    return {'start':elf.symbol('begin')[0],'end':elf.symbol('end')[0]}


def region_code(elf,reg):
    matches=[s for s in elf.sections if s[2]&4 and s[3]<=reg['start']<reg['end']<=s[3]+s[5]]
    if len(matches)!=1:raise ValueError('L3_STORE_CALIBRATION_REGION_INVALID')
    s=matches[0]
    return elf.slice(s[4]+reg['start']-s[3],reg['end']-reg['start'])


def validate_record(record,backend):
    case=record['case'];side=case['side'];assembly=Path(record['assembly']);binary=Path(record['binary'])
    if (assembly.read_text()!=probe(case) or digest(binary)!=record['binaryDigest']
            or digest(assembly.with_name('build.command.json'))!=record['buildCommandDigest']):
        raise ValueError('L3_STORE_CALIBRATION_BUILD_CHANGED')
    built=json.loads(assembly.with_name('build.command.json').read_text())
    if (type(built['returnCode']) is not int or built['command']!=build_command(backend,case,assembly,binary) or built['returnCode']!=0
            or built['timedOut'] is not False):raise ValueError('L3_STORE_CALIBRATION_BUILD_INVALID')
    elf=Elf(binary);reg=region(elf)
    if elf.machine!=(243 if side=='source' else 62) or region_code(elf,reg)!=expected_code(case):
        raise ValueError('L3_STORE_CALIBRATION_MACHINE_MISMATCH')
    # Rebuild the probe rather than accepting a rehashed arbitrary executable.
    with tempfile.TemporaryDirectory(prefix='rv2x86-store-calibration-') as temp:
        work=Path(temp);fresh=work/'probe';src=work/'probe.s';src.write_text(probe(case))
        run(build_command(backend,case,src,fresh),work,'rebuild',120)
        require_json_match(Elf(fresh).execution_image(),elf.execution_image(),'L3_STORE_CALIBRATION_IMAGE_CHANGED')
    evidence=record['evidence'];trace=Path(evidence['rawTracePath']);cp=trace.with_name('execute.command.json')
    if digest(trace)!=evidence['rawTraceDigest'] or digest(cp)!=evidence['commandRecordDigest']:
        raise ValueError('L3_STORE_CALIBRATION_CAPTURE_CHANGED')
    command=json.loads(cp.read_text())
    option=','.join([backend['plugin'],'start='+hex(reg['start']),'end='+hex(reg['end']),
        'limit=4096','output='+str(trace.resolve()),'token='+evidence['token']])
    if (type(command['returnCode']) is not int or command['command']!=[backend[side+'Executor'],*backend[side+'RunnerArguments'],
            '-plugin',option,str(binary),evidence['token']] or command['returnCode']!=0
            or command['timedOut'] is not False or command['stdout'] or command['stderr']):
        raise ValueError('L3_STORE_CALIBRATION_EXECUTION_INVALID')
    events=base.parse_capture(trace.read_text(),token=evidence['token'],
        target='riscv64' if side=='source' else 'x86_64',region=reg,calls=1)
    require_json_match([{'sample':0,'pc':reg['start'],'address':elf.symbol('data')[0],
        'size':case['width'],'access':'write'}],events,'L3_STORE_CALIBRATION_EVENT_MISMATCH')


def validate_backend(value, *, _context=None):
    if isinstance(value,(str,Path)):value=json.loads(Path(value).read_text())
    if not isinstance(value,dict) or value.get('schemaVersion')!=SCHEMA:
        return base.validate_backend(value)
    require_json_document(value,'L3_STORE_BACKEND_JSON_INVALID')
    fields={'schemaVersion','baseBackendPath','baseBackendDigest','files','calibration','backendIdentity',*TOOLS}
    if set(value)!=fields or value['backendIdentity']!=identity({k:v for k,v in value.items() if k!='backendIdentity'}):
        raise ValueError('L3_STORE_BACKEND_IDENTITY_INVALID')
    if digest(value['baseBackendPath'])!=value['baseBackendDigest']:raise ValueError('L3_STORE_BASE_CHANGED')
    from .l3_backend_validation import checked
    backend=checked(_context,base.validate_backend,value['baseBackendPath'])
    if any(value[k]!=backend[k] for k in TOOLS):raise ValueError('L3_STORE_BASE_TOOL_MISMATCH')
    if set(value['files'])!=set(implementation_paths()) or any(digest(p)!=sha for p,sha in value['files'].items()):
        raise ValueError('L3_STORE_IMPLEMENTATION_CHANGED')
    records=value['calibration']
    if type(records) is not list or len(records)!=len(CASES):raise ValueError('L3_STORE_CALIBRATION_INCOMPLETE')
    require_json_match(CASES,[r['case'] for r in records],'L3_STORE_CALIBRATION_COVERAGE_INVALID')
    for record in records:validate_record(record,backend)
    return value


def require_access(backend,spec):
    if spec['access']=='write' and spec['width']!=8 and backend.get('schemaVersion')!=SCHEMA:
        raise ValueError('L3_MEMORY_STORE_WIDTH_CALIBRATION_REQUIRED:'+str(spec['width']))


def capture(backend,*args,**kwargs):
    validated=validate_backend(backend)
    inner=(base.validate_backend(validated['baseBackendPath']) if validated.get('schemaVersion')==SCHEMA else validated)
    result=base.capture(inner,*args,**kwargs)
    validate_backend(backend)
    return result


def prepare(base_path,output):
    base_path=Path(base_path).resolve();out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    status={'stage':'base-validation','complete':False,'semanticApproval':False,'calibrationCompleted':[]}
    def checkpoint():write_status_atomic(out/'build-status.json',status)
    checkpoint()
    try:
        backend=base.validate_backend(base_path)
        value={'schemaVersion':SCHEMA,'baseBackendPath':str(base_path),'baseBackendDigest':digest(base_path),
            **{k:backend[k] for k in TOOLS},'files':{p:digest(p) for p in implementation_paths()},'calibration':[]}
        status['stage']='calibration';checkpoint()
        for case in CASES:
            work=out/'calibration'/case['side']/str(case['width']);work.mkdir(parents=True)
            src=work/'probe.s';binary=work/'probe';src.write_text(probe(case))
            run(build_command(backend,case,src,binary),work,'build',120)
            _,_,evidence=base.capture(backend,case['side'],binary,region(Elf(binary)),work,1,120)
            record={'case':case,'assembly':str(src),'binary':str(binary),'binaryDigest':digest(binary),
                'buildCommandDigest':digest(work/'build.command.json'),'evidence':evidence}
            validate_record(record,backend);value['calibration'].append(record)
            status['calibrationCompleted'].append(case);checkpoint()
        value['backendIdentity']=identity(value);validate_backend(value)
        save(out/'backend.json',value)
        status.update(stage='complete',complete=True,backendIdentity=value['backendIdentity']);checkpoint()
        return value
    except Exception as exc:
        record_failure(out/'build-status.json',status,exc);raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-backend',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();value=prepare(args.base_backend,args.output)
    print(json.dumps({'backendPath':str(Path(args.output).resolve()/'backend.json'),
        'backendIdentity':value['backendIdentity'],'semanticApproval':False}))


if __name__=='__main__':main()
