"""Calibrated raw callback shape for direct AMO/XADD/XCHG, not invented R/W pairs."""
import argparse
import json
from pathlib import Path
from . import l3_control_backend as control
from .l3_atomic_machine import atomic_instruction
from .l3_trace_support import Elf,digest,identity,run,save
from .l3_status import write_status_atomic,record_failure

SCHEMA='riscv2x86.qemu-direct-atomic-backend.v1'
DEPENDENCIES=('l3_atomic_backend.py','l3_atomic_machine.py','l3_atomic_spec.py','l3_atomic_compare.py',
 'l3_atomic_deployment.py','l3_atomic_route.py','l3_atomic_intent.py','l3_trace_support.py','l3_status.py',
 'l3_control_machine.py','l3_property_obligations.py','l3_sync_obligations.py','l3_source_eligibility.py',
 'l2_atomic_authority.py','atomic_builtin_shell.py')
CASES=[{'side':s,'operation':o,'width':w,'ordering':order,'locked':locked,'discard':discard}
       for s in ('source','target') for o in ('fetch_add','exchange') for w in (32,64)
       for order in (('relaxed','acquire','release','acq_rel') if s=='source' else ('full',)) for locked in (True,) for discard in ((False,True) if s=='source' or o=='fetch_add' else (False,))]
CASES += [{'side':'target','operation':'fetch_add','width':w,'ordering':'unproved','locked':False,'discard':discard} for w in (32,64) for discard in (False,True)]
parse_capture=control.parse_capture


def base(value):
    if digest(value['controlBackendPath'])!=value['controlBackendDigest']:raise ValueError('L3_ATOMIC_BASE_BACKEND_CHANGED')
    return control.validate(value['controlBackendPath'])


def command(value,side,binary,region,trace,token):
    return control.command(base(value),side,binary,region,trace,token)


def capture(value,side,binary,region,directory,calls,timeout):
    validate(value);result=control.capture(base(value),side,binary,region,directory,calls,timeout);validate(value)
    return result


def probe(case):
    side,op,w=case['side'],case['operation'],case['width'];expected=10 if op=='fetch_add' else 3
    if side=='source':
        suffix={'relaxed':'','acquire':'.aq','release':'.rl','acq_rel':'.aqrl'}[case['ordering']]
        insn=('amoadd' if op=='fetch_add' else 'amoswap')+('.w' if w==32 else '.d')+suffix+(' zero,a1,(a0)\n' if case['discard'] else ' a2,a1,(a0)\n')
        return ('.option norvc\n.text\n.globl _start\n_start:\nla a0,data\nli a1,3\n.globl begin\nbegin:\n'+insn
                +'.globl end\nend:\n'+('' if case['discard'] else 'li t0,7\nbne a2,t0,bad\n')+('lw' if w==32 else 'ld')+' t1,0(a0)\nli t0,'+str(expected)+'\nbne t1,t0,bad\nli a0,0\nj done\nbad:li a0,9\ndone:li a7,93\necall\n'
                +'.data\n.balign 8\n.globl data\ndata:.quad 7\n.section .note.GNU-stack,"",@progbits\n')
    reg='%esi' if w==32 else '%rsi';size='l' if w==32 else 'q'
    insn=('lock ' if case['locked'] and op=='fetch_add' else '')+('add' if case['discard'] else 'xadd' if op=='fetch_add' else 'xchg')+size+' '+reg+',(%rdi)\n'
    return ('.text\n.globl _start\n_start:\nlea data(%rip),%rdi\nmovq $3,%rsi\n.globl begin\nbegin:\n'+insn
            +'.globl end\nend:\n'+('' if case['discard'] else 'cmpq $7,%rsi\njne bad\n')+'cmp'+size+' $'+str(expected)+',(%rdi)\njne bad\nxorq %rdi,%rdi\njmp done\nbad:movq $9,%rdi\ndone:movq $60,%rax\nsyscall\n'
            +'.data\n.balign 8\n.globl data\ndata:.quad 7\n.section .note.GNU-stack,"",@progbits\n')


def region(elf):
    return {'start':elf.symbol('begin')[0],'end':elf.symbol('end')[0],'exits':[elf.symbol('end')[0]]}


def instruction(elf,reg):
    a=reg['start'];n=reg['end']-a;sections=[s for s in elf.sections if s[2]&4 and s[3]<=a and a+n<=s[3]+s[5]]
    if len(sections)!=1:raise ValueError('L3_ATOMIC_PROBE_SECTION_INVALID')
    s=sections[0];result=atomic_instruction(elf.slice(s[4]+a-s[3],n),elf.machine)
    if result is None:raise ValueError('L3_ATOMIC_PROBE_ENCODING_INVALID')
    return result


def build_command(b,case,asm,binary):
    flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if case['side']=='source' else []
    return [b[case['side']+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',str(asm),'-o',str(binary)]


def check_calibration(value,r,b):
    case=r['case'];side=case['side'];binary=Path(r['binary']);elf=Elf(binary);reg=region(elf);insn=instruction(elf,reg)
    e=r['evidence'];trace=Path(e['rawTracePath']);cp=trace.with_name('execute.command.json');bp=Path(r['assembly']).with_name('build.command.json')
    c=json.loads(cp.read_text());bc=json.loads(bp.read_text())
    if (elf.machine!=(243 if side=='source' else 62) or digest(binary)!=r['binaryDigest'] or insn!=r['instruction']
            or Path(r['assembly']).read_text()!=probe(case) or digest(bp)!=r['buildCommandDigest']
            or bc['command']!=build_command(b,case,r['assembly'],binary) or bc['returnCode']!=0 or bc['timedOut'] is not False
            or digest(trace)!=e['rawTraceDigest'] or digest(cp)!=e['commandRecordDigest']
            or c['command']!=control.command(b,side,str(binary),reg,trace,e['token'])
            or c['returnCode']!=0 or c['timedOut'] is not False or c['stdout'] or c['stderr']):
        raise ValueError('L3_ATOMIC_CALIBRATION_CHANGED')
    expected_roles=(10,11,0 if case['discard'] else 12) if side=='source' else (7,6,None if case['discard'] else 6)
    if ((insn['addressRegister'],insn['inputRegister'],insn['resultRegister'])!=expected_roles
            or insn.get('displacement',0)!=0):raise ValueError('L3_ATOMIC_CALIBRATION_REGISTER_ROLE_MISMATCH')
    observed=parse_capture(trace.read_text(),e['token'],'riscv64' if side=='source' else 'x86_64',reg,1)
    accesses=observed['memory'];kinds=[x['access'] for x in accesses]
    if (observed['paths']!=[{'pcs':[reg['start']],'exit':reg['end']}]
            or kinds not in (['read'],['write'],['read','write']) or kinds!=r['callbackAccessKinds']
            or any(x!={'sample':0,'pc':reg['start'],'address':elf.symbol('data')[0],'size':case['width']//8,'access':x['access']} for x in accesses)
            or insn['operation']!=case['operation'] or insn['width']!=case['width']
            or (side=='source' and insn['ordering']!=case['ordering'])
            or (side=='target' and (insn['mechanism'] in {'x86-unlocked-xadd','x86-unlocked-add'})!= (not case['locked']))):
        raise ValueError('L3_ATOMIC_CALIBRATION_OBSERVATION_MISMATCH')


def callback_shape(value,side,insn):
    matched=[r for r in value['calibration'] if r['case']['side']==side
             and all(r['instruction'][k]==insn[k] for k in ('mechanism','operation','width','ordering'))
             and (side!='source' or (r['instruction']['resultRegister']==0)==(insn['resultRegister']==0))]
    shapes={tuple(r['callbackAccessKinds']) for r in matched}
    if len(shapes)!=1:raise ValueError('L3_ATOMIC_CALLBACK_CAPABILITY_UNCALIBRATED')
    return list(shapes.pop())


def validate(path):
    value=json.loads(Path(path).read_text()) if isinstance(path,(str,Path)) else path
    fields={'schemaVersion','controlBackendPath','controlBackendDigest','files','calibration','backendIdentity',*control.TOOLS}
    if (not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA
            or value['backendIdentity']!=identity({k:v for k,v in value.items() if k!='backendIdentity'})):
        raise ValueError('L3_ATOMIC_BACKEND_INVALID')
    b=base(value)
    if any(value[k]!=b[k] for k in control.TOOLS):raise ValueError('L3_ATOMIC_BACKEND_TOOL_CHANGED')
    required={str(Path(__file__).with_name(n).resolve()) for n in DEPENDENCIES}
    if set(value['files'])!=required or any(digest(p)!=sha for p,sha in value['files'].items()):raise ValueError('L3_ATOMIC_BACKEND_DEPENDENCY_CHANGED')
    records=value['calibration']
    if (not isinstance(records,list) or len(records)!=len(CASES)
            or sorted(identity(r['case']) for r in records)!=sorted(identity(c) for c in CASES)):
        raise ValueError('L3_ATOMIC_CALIBRATION_INCOMPLETE')
    for r in records:check_calibration(value,r,b)
    return value


def prepare(control_path,output):
    control_path=Path(control_path).resolve();b=control.validate(control_path);out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    status={'stage':'calibration','complete':False,'semanticApproval':False,'calibrationCompleted':[]}
    try:
        write_status_atomic(out/'build-status.json',status)
        value={'schemaVersion':SCHEMA,'controlBackendPath':str(control_path),'controlBackendDigest':digest(control_path),
               **{k:b[k] for k in control.TOOLS},'files':{str(Path(__file__).with_name(n).resolve()):digest(Path(__file__).with_name(n)) for n in DEPENDENCIES},'calibration':[]}
        for i,case in enumerate(CASES):
            status['calibrationCurrent']=case;write_status_atomic(out/'build-status.json',status)
            work=out/'calibration'/str(i);work.mkdir(parents=True);asm=work/'probe.S';asm.write_text(probe(case));binary=work/'probe'
            run(build_command(b,case,asm,binary),work,'build')
            observed,_,e=control.capture(b,case['side'],binary,region(Elf(binary)),work/'capture',1,120)
            record={'case':case,'assembly':str(asm),'binary':str(binary),'binaryDigest':digest(binary),'buildCommandDigest':digest(work/'build.command.json'),
                    'evidence':e,'instruction':instruction(Elf(binary),region(Elf(binary))),'callbackAccessKinds':[x['access'] for x in observed['memory']]}
            check_calibration(value,record,b);value['calibration'].append(record);status['calibrationCompleted'].append(case);write_status_atomic(out/'build-status.json',status)
        value['backendIdentity']=identity(value);validate(value);save(out/'backend.json',value)
        status.update(stage='complete',complete=True,backendIdentity=value['backendIdentity']);write_status_atomic(out/'build-status.json',status);return value
    except Exception as exc:
        record_failure(out/'build-status.json',status,exc);raise


def main():
    p=argparse.ArgumentParser();p.add_argument('--control-backend',required=True);p.add_argument('--output',required=True);a=p.parse_args();b=prepare(a.control_backend,a.output)
    print(json.dumps({'backendPath':str(Path(a.output).resolve()/'backend.json'),'backendIdentity':b['backendIdentity'],'semanticApproval':False}))
if __name__=='__main__':main()
