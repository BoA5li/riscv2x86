"""Versioned loop observer with replayed LR/SC and CAS success/failure calibration."""
import argparse
import json
from pathlib import Path
from uuid import uuid4
from . import l3_control_backend as control
from .l3_atomic_backend import parse_capture,memory_by_step
from .l3_trace_support import Elf,digest,identity,save,run
from .l3_status import write_status_atomic,record_failure
SCHEMA='riscv2x86.qemu-lrsc-sequence-backend.v1'
DEPENDENCIES=('l3_lrsc_backend.py','l3_lrsc_spec.py','l3_lrsc_machine.py','l3_lrsc_observation.py',
    'l3_lrsc_compare.py','l3_lrsc_deployment.py','l3_lrsc_route.py','l3_lrsc_intent.py',
    'lrsc_sequence.py','lrsc_source.py','lrsc_target.py','lrsc_compiler_binding.py','l2_lrsc_authority.py',
    'l3_atomic_retry.py','l3_atomic_spec.py','l3_atomic_backend.py','l3_atomic_compare.py',
    'l3_control_machine.py','l3_property_obligations.py','l3_sync_obligations.py',
    'l3_trace_support.py','l3_status.py','l3_backend_validation.py')
from .l3_atomic_intent import DEPENDENCIES as _ATOMIC_DEPENDENCIES
DEPENDENCIES=tuple(sorted(set(DEPENDENCIES)|set(_ATOMIC_DEPENDENCIES)|{
    'l3_atomic_intent.py','l3_source_eligibility.py','l3_mechanism_selection.py',
    'l3_execution_plan.py','l3_production_acceptance.py','automatic_batch_cli.py'}))
CASES=[{'side':'source','width':w,'retry':retry,'bits':bits} for w in (32,64)
       for bits in range(16) for retry in (False,True)]
CASES += [{'side':'target','width':w,'retry':retry,'bits':0} for w in (32,64) for retry in (False,True)]


def plugin_source():return Path(__file__).resolve().parents[2]/'runtime/l3_qemu_lrsc_trace.c'


def command(value,side,binary,region,trace,token):
    return control.command(value,side,binary,region,trace,token)


def _capture(value,side,binary,region,directory,calls,timeout):
    work=Path(directory);work.mkdir(parents=True,exist_ok=False);trace=work/'guest-trace.log';token=uuid4().hex+uuid4().hex
    before=digest(binary);result=run(command(value,side,binary,region,trace,token),work,'execute',timeout)
    if before!=digest(binary) or result.stderr:raise ValueError('L3_LRSC_EXECUTION_CHANGED_OR_STDERR')
    observed=parse_capture(trace.read_text(),token,'riscv64' if side=='source' else 'x86_64',region,calls)
    return observed,result.stdout,{'token':token,'rawTracePath':str(trace),'rawTraceDigest':digest(trace),
        'commandRecordDigest':digest(work/'execute.command.json')}


def capture(value,side,binary,region,directory,calls,timeout):
    validate(value);result=_capture(value,side,binary,region,directory,calls,timeout);validate(value);return result


def probe(case):
    w=case['width'];retry=case['retry']
    if case['side']=='source':
        b=case['bits'];suffix=lambda aq,rl:'.aqrl' if aq and rl else '.aq' if aq else '.rl' if rl else ''
        lr='lr'+('.w' if w==32 else '.d')+suffix(bool(b&1),bool(b&2))
        sc='sc'+('.w' if w==32 else '.d')+suffix(bool(b&4),bool(b&8))
        # Calibration-only invalidation SC clears the reservation; it is never
        # inserted into the user's program or accepted by the production model.
        middle=('beqz t3,compute\n.globl invalidate\ninvalidate:sc'+('.w' if w==32 else '.d')+' t4,t0,(a0)\nli t3,0\n') if retry else ''
        body='.option norvc\n.text\n.globl _start\n_start:la a0,data\nli a1,3\nli t3,1\n.globl begin\nbegin:\n'+lr+' t0,(a0)\n'+middle
        body+='.globl compute\ncompute:add t1,t0,a1\n.globl atomic_site\natomic_site:'+sc+' t2,t1,(a0)\n.globl backedge\nbackedge:bnez t2,begin\n.globl end\nend:\n'
        body+=('lw' if w==32 else 'ld')+' t1,0(a0)\nli t0,10\nbne t1,t0,bad\nli a0,0\nj done\nbad:li a0,9\ndone:li a7,93\necall\n'
    else:
        size='l' if w==32 else 'q';acc='%eax' if w==32 else '%rax';nxt='%edx' if w==32 else '%rdx'
        body='.text\n.globl _start\n_start:lea data(%rip),%rdi\nmovq $3,%rsi\n.globl begin\nbegin:'
        body+=('xorq %rax,%rax\n' if retry else 'mov'+size+' (%rdi),'+acc+'\n')
        body+='.globl compute\ncompute:mov'+size+' '+acc+','+nxt+'\nadd'+size+' '+('%esi' if w==32 else '%rsi')+','+nxt+'\n.globl atomic_site\natomic_site:lock cmpxchg'+size+' '+nxt+',(%rdi)\n.globl backedge\nbackedge:jne compute\n.globl end\nend:cmp'+size+' $10,(%rdi)\njne bad\nxorq %rdi,%rdi\njmp done\nbad:movq $9,%rdi\ndone:movq $60,%rax\nsyscall\n'
    return body+'.data\n.balign 8\n.globl data\ndata:.quad 7\n.section .note.GNU-stack,"",@progbits\n'


def build_command(value,case,asm,binary):
    flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if case['side']=='source' else []
    return [value[case['side']+'Compiler'],'-nostdlib','-static','-no-pie',*flags,str(asm),'-o',str(binary)]


def region(elf):
    start=elf.symbol('begin')[0];end=elf.symbol('end')[0]
    return {'start':start,'end':end,'exits':[end]}


def _pcs(elf,start,end):
    section=elf.sections[elf.symbol('begin')[2]];raw=elf.slice(section[4]+start-section[3],end-start);out=[];i=0
    if elf.machine==243:
        while i<len(raw):out.append(start+i);i+=2 if raw[i]&3!=3 else 4
        if i!=len(raw):raise ValueError('L3_LRSC_CALIBRATION_ENCODING')
    else:
        from .l3_atomic_retry import decode
        out=[r['pc'] for r in decode(raw,start)]
    return out


def shapes(value,record):
    case=record['case'];elf=Elf(record['binary']);reg=region(elf);e=record['evidence'];trace=Path(e['rawTracePath'])
    if digest(trace)!=e['rawTraceDigest']:raise ValueError('L3_LRSC_CALIBRATION_TRACE_CHANGED')
    observed=parse_capture(trace.read_text(),e['token'],'riscv64' if case['side']=='source' else 'x86_64',reg,1)
    # Exact probe program and PC path independently establish which SC/CAS
    # failed. A missing callback alone never supplies an outcome label.
    allpcs=_pcs(elf,reg['start'],reg['end']);compute=elf.symbol('compute')[0];at=elf.symbol('atomic_site')[0]
    if case['side']=='source' and case['retry']:
        inv=elf.symbol('invalidate')[0];branch=allpcs[1]
        expected=allpcs+[reg['start'],branch]+[p for p in allpcs if p>=compute]
    elif case['side']=='target' and case['retry']:expected=allpcs+[p for p in allpcs if p>=compute]
    else:expected=allpcs
    if observed['paths']!=[{'pcs':expected,'exit':reg['end']}]:raise ValueError('L3_LRSC_CALIBRATION_PATH_NOT_PROVED')
    groups=memory_by_step(observed);result={};address=elf.symbol('data')[0];width=case['width']//8
    occurrences=[i for i,p in enumerate(expected) if p==at]
    if len(occurrences)!=(2 if case['retry'] else 1):raise ValueError('L3_LRSC_CALIBRATION_OUTCOMES_MISSING')
    for i,pc in enumerate(expected):
        events=groups.get(i,[])
        if any(m['pc']!=pc or m['sample']!=0 or m['address']!=address or m['size']!=width for m in events):raise ValueError('L3_LRSC_CALIBRATION_OBJECT')
        kinds=[m['access'] for m in events]
        if pc==at:
            outcome='success' if i==occurrences[-1] else 'failure';result[outcome]=kinds
        elif case['side']=='source' and pc==reg['start']:
            if kinds!=['read']:raise ValueError('L3_LRSC_CALIBRATION_LR_CALLBACK')
        elif case['side']=='source' and case['retry'] and pc==elf.symbol('invalidate')[0]:
            if kinds.count('write')!=1:raise ValueError('L3_LRSC_INVALIDATION_SUCCESS_REQUIRED')
        elif case['side']=='target' and not case['retry'] and pc==reg['start']:
            if kinds!=['read']:raise ValueError('L3_LRSC_CALIBRATION_INITIAL_READ')
        elif kinds:raise ValueError('L3_LRSC_CALIBRATION_UNATTRIBUTED_MEMORY')
    if any(i not in range(len(expected)) for i in groups):raise ValueError('L3_LRSC_CALIBRATION_EXTRA_CALLBACK')
    if result['success'].count('write')!=1 or any(k not in ('read','write') for v in result.values() for k in v):raise ValueError('L3_LRSC_CALIBRATION_SUCCESS_WRITE_REQUIRED')
    return result


def check(value,r):
    case=r['case'];binary=Path(r['binary']);asm=Path(r['assembly']);e=r['evidence'];work=binary.parent
    if asm.read_text()!=probe(case) or digest(binary)!=r['binaryDigest']:raise ValueError('L3_LRSC_CALIBRATION_PROGRAM_CHANGED')
    build=json.loads((work/'build.command.json').read_text());execute=json.loads(Path(e['rawTracePath']).with_name('execute.command.json').read_text())
    if (digest(work/'build.command.json')!=r['buildCommandDigest'] or build['command']!=build_command(value,case,asm,binary)
        or build['returnCode']!=0 or build['timedOut'] or build['stderr']):raise ValueError('L3_LRSC_CALIBRATION_BUILD_CHANGED')
    if (digest(Path(e['rawTracePath']).with_name('execute.command.json'))!=e['commandRecordDigest']
        or execute['command']!=command(value,case['side'],binary,region(Elf(binary)),e['rawTracePath'],e['token'])
        or execute['returnCode']!=0 or execute['timedOut'] or execute['stderr'] or execute['stdout']):raise ValueError('L3_LRSC_CALIBRATION_EXECUTION_CHANGED')
    if r['callbackShapes']!=shapes(value,r):raise ValueError('L3_LRSC_CALIBRATION_REPLAY_MISMATCH')


def callback_shape(value,side,width,bits,outcome):
    matches=[r['callbackShapes'][outcome] for r in value['calibration'] if r['case']['side']==side and r['case']['width']==width
        and r['case']['bits']==(bits if side=='source' else 0) and outcome in r['callbackShapes']]
    if not matches or any(x!=matches[0] for x in matches):raise ValueError('L3_LRSC_CALLBACK_UNCALIBRATED_OR_INCONSISTENT')
    return matches[0]


def validate(path,*,_context=None):
    v=json.loads(Path(path).read_text()) if isinstance(path,(str,Path)) else path
    fields={'schemaVersion','controlBackendPath','controlBackendDigest','plugin','files','calibration','backendIdentity',*control.TOOLS}
    if not isinstance(v,dict) or set(v)!=fields or v['schemaVersion']!=SCHEMA or v['backendIdentity']!=identity({k:x for k,x in v.items() if k!='backendIdentity'}):raise ValueError('L3_LRSC_BACKEND_INVALID')
    if digest(v['controlBackendPath'])!=v['controlBackendDigest']:raise ValueError('L3_LRSC_BASE_CHANGED')
    from .l3_backend_validation import checked
    b=checked(_context,control.validate,v['controlBackendPath'],nested=True)
    if any(v[k]!=b[k] for k in control.TOOLS):raise ValueError('L3_LRSC_TOOLS_CHANGED')
    headers=[p for p in b['files'] if p.endswith('/include/qemu/qemu-plugin.h')];build=Path(v['plugin']).with_name('plugin.command.json')
    required={str(Path(__file__).with_name(n).resolve()) for n in DEPENDENCIES}|{str(plugin_source()),v['plugin'],str(build),*headers}
    if len(headers)!=1 or set(v['files'])!=required or any(digest(p)!=sha for p,sha in v['files'].items()):raise ValueError('L3_LRSC_DEPENDENCIES_CHANGED')
    record=json.loads(build.read_text())
    expected=[v['targetCompiler'],'-std=gnu11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-I'+str(Path(headers[0]).parents[1]),str(plugin_source()),'-o',v['plugin']]
    if record['command']!=expected or record['returnCode']!=0 or record['timedOut'] or record['stderr']:raise ValueError('L3_LRSC_PLUGIN_BUILD_CHANGED')
    if len(v['calibration'])!=len(CASES) or sorted(identity(r['case']) for r in v['calibration'])!=sorted(identity(c) for c in CASES):raise ValueError('L3_LRSC_CALIBRATION_INCOMPLETE')
    for r in v['calibration']:check(v,r)
    for side in ('source','target'):
        for w in (32,64):
            for bits in range(16) if side=='source' else (0,):
                for outcome in ('failure','success'):callback_shape(v,side,w,bits,outcome)
    return v


def prepare(control_path,output):
    control_path=Path(control_path).resolve();b=control.validate(control_path);out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    status={'stage':'plugin','complete':False,'semanticApproval':False,'calibrationCompleted':[]};write_status_atomic(out/'build-status.json',status)
    try:
        headers=[p for p in b['files'] if p.endswith('/include/qemu/qemu-plugin.h')]
        if len(headers)!=1:raise ValueError('L3_LRSC_PLUGIN_HEADER_REQUIRED')
        plugin=out/'lrsc-trace.so';run([b['targetCompiler'],'-std=gnu11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-I'+str(Path(headers[0]).parents[1]),plugin_source(),'-o',plugin],out,'plugin')
        files=[Path(__file__).with_name(n).resolve() for n in DEPENDENCIES]+[plugin_source(),plugin,out/'plugin.command.json',Path(headers[0])]
        value={'schemaVersion':SCHEMA,'controlBackendPath':str(control_path),'controlBackendDigest':digest(control_path),
            **{k:b[k] for k in control.TOOLS},'plugin':str(plugin),'files':{str(p):digest(p) for p in files},'calibration':[]}
        status['stage']='calibration';write_status_atomic(out/'build-status.json',status)
        for i,c in enumerate(CASES):
            status['calibrationCurrent']=c;write_status_atomic(out/'build-status.json',status)
            work=out/'calibration'/str(i);work.mkdir(parents=True);asm=work/'probe.S';asm.write_text(probe(c));binary=work/'probe'
            run(build_command(value,c,asm,binary),work,'build');_,_,e=_capture(value,c['side'],binary,region(Elf(binary)),work/'capture',1,120)
            r={'case':c,'assembly':str(asm),'binary':str(binary),'binaryDigest':digest(binary),'buildCommandDigest':digest(work/'build.command.json'),'evidence':e}
            r['callbackShapes']=shapes(value,r);check(value,r);value['calibration'].append(r);status['calibrationCompleted'].append(c);write_status_atomic(out/'build-status.json',status)
        value['backendIdentity']=identity(value);validate(value);save(out/'backend.json',value)
        status.update(stage='complete',complete=True,backendIdentity=value['backendIdentity']);write_status_atomic(out/'build-status.json',status);return value
    except Exception as exc:record_failure(out/'build-status.json',status,exc);raise


def main():
    p=argparse.ArgumentParser();p.add_argument('--control-backend',required=True);p.add_argument('--output',required=True);a=p.parse_args();b=prepare(a.control_backend,a.output)
    print(json.dumps({'backendPath':str(Path(a.output).resolve()/'backend.json'),'backendIdentity':b['backendIdentity'],'semanticApproval':False}))

if __name__=='__main__':main()
