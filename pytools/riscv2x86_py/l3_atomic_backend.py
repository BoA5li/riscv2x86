"""Calibrated AMO/LOCK/CAS callbacks, including failure paths; no invented R/W pairs."""
import argparse
import json
from pathlib import Path
from . import l3_control_backend as control
from .l3_atomic_machine import atomic_instruction
from .l3_trace_support import Elf,digest,identity,run,save
from .l3_status import write_status_atomic,record_failure

SCHEMA='riscv2x86.qemu-attributed-atomic-backend.v2'

CASES=[{'side':s,'operation':o,'width':w,'ordering':order,'locked':locked,'discard':discard}
       for s in ('source','target') for o in ('fetch_add','exchange') for w in (32,64)
       for order in (('relaxed','acquire','release','acq_rel') if s=='source' else ('full',)) for locked in (True,) for discard in ((False,True) if s=='source' or o=='fetch_add' else (False,))]
CASES += [{'side':'target','operation':'fetch_add','width':w,'ordering':'unproved','locked':False,'discard':discard} for w in (32,64) for discard in (False,True)]
# Preserve legacy ordering of the original 42 cases for reproducible baselines.
CASES += [{'side':'source','operation':op,'width':w,'ordering':order,'locked':True,'discard':discard}
          for op in ('fetch_and','fetch_or','fetch_xor') for w in (32,64)
          for order in ('relaxed','acquire','release','acq_rel') for discard in (False,True)]
CASES += [{'side':'target','operation':op,'width':w,'ordering':'full' if locked else 'unproved','locked':locked,'discard':True}
          for op in ('fetch_and','fetch_or','fetch_xor') for w in (32,64) for locked in (True,False)]
CASES += [{'side':'target','operation':op,'width':w,'ordering':'full' if locked else 'unproved',
           'locked':locked,'discard':False,'implementation':'cas-loop','predicate':predicate,'retry':retry}
          for op in ('fetch_and','fetch_or','fetch_xor') for w in (32,64)
          for predicate in ('direct','setcc') for locked,retry in ((True,False),(True,True),(False,False))]

from .l3_implementation_dependencies import implementation_dependencies,implementation_paths
DEPENDENCIES=implementation_dependencies()


def parse_capture(text,token,target,region,calls):
    observed=control.parse_capture(text,token,target,region,calls)
    timeline=[];current=None
    for line in text.splitlines():
        parts=line.split()
        if parts[0]=='P':current=(int(parts[1]),int(parts[2]),int(parts[3],16))
        elif parts[0] in ('B','X','U','F'):current=None
        elif parts[0]=='M':
            if current is None or (int(parts[2]),int(parts[3],16))!=current[1:]:
                raise ValueError('L3_ATOMIC_CALLBACK_INSTRUCTION_ATTRIBUTION_MISMATCH')
            timeline.append({'step':current[0],'memoryIndex':int(parts[1])})
    observed['memoryTimeline']=timeline
    return observed


def base(value,context=None):
    if digest(value['controlBackendPath'])!=value['controlBackendDigest']:raise ValueError('L3_ATOMIC_BASE_BACKEND_CHANGED')
    from .l3_backend_validation import checked
    return checked(context,control.validate,value['controlBackendPath'],nested=True)


def command(value,side,binary,region,trace,token):
    return control.command(base(value),side,binary,region,trace,token)


def capture(value,side,binary,region,directory,calls,timeout):
    validate(value);_,stdout,evidence=control.capture(base(value),side,binary,region,directory,calls,timeout);validate(value)
    observed=parse_capture(Path(evidence['rawTracePath']).read_text(),evidence['token'],'riscv64' if side=='source' else 'x86_64',region,calls)
    return observed,stdout,evidence


def probe(case):
    from .l3_atomic_semantics import result
    side,op,w=case['side'],case['operation'],case['width'];expected=result(op,7,3,w)
    if case.get('implementation')=='cas-loop':return retry_probe(case)
    if side=='source':
        suffix={'relaxed':'','acquire':'.aq','release':'.rl','acq_rel':'.aqrl'}[case['ordering']]
        insn={'fetch_add':'amoadd','exchange':'amoswap','fetch_and':'amoand','fetch_or':'amoor','fetch_xor':'amoxor'}[op]+('.w' if w==32 else '.d')+suffix+(' zero,a1,(a0)\n' if case['discard'] else ' a2,a1,(a0)\n')
        return ('.option norvc\n.text\n.globl _start\n_start:\nla a0,data\nli a1,3\n.globl begin\nbegin:\n'+insn
                +'.globl end\nend:\n'+('' if case['discard'] else 'li t0,7\nbne a2,t0,bad\n')+('lw' if w==32 else 'ld')+' t1,0(a0)\nli t0,'+str(expected)+'\nbne t1,t0,bad\nli a0,0\nj done\nbad:li a0,9\ndone:li a7,93\necall\n'
                +'.data\n.balign 8\n.globl data\ndata:.quad 7\n.section .note.GNU-stack,"",@progbits\n')
    reg='%esi' if w==32 else '%rsi';size='l' if w==32 else 'q'
    insn=('lock ' if case['locked'] and op!='exchange' else '')+({'fetch_add':'add','fetch_and':'and','fetch_or':'or','fetch_xor':'xor'}[op] if case['discard'] else 'xadd' if op=='fetch_add' else 'xchg')+size+' '+reg+',(%rdi)\n'
    return ('.text\n.globl _start\n_start:\nlea data(%rip),%rdi\nmovq $3,%rsi\n.globl begin\nbegin:\n'+insn
            +'.globl end\nend:\n'+('' if case['discard'] else 'cmpq $7,%rsi\njne bad\n')+'cmp'+size+' $'+str(expected)+',(%rdi)\njne bad\nxorq %rdi,%rdi\njmp done\nbad:movq $9,%rdi\ndone:movq $60,%rax\nsyscall\n'
            +'.data\n.balign 8\n.globl data\ndata:.quad 7\n.section .note.GNU-stack,"",@progbits\n')


def retry_probe(case):
    from .l3_atomic_semantics import result
    width=case['width'];wide=width==64;size='q' if wide else 'l'
    a='%rax' if wide else '%eax';desired='%rdx' if wide else '%edx';inp='%rsi' if wide else '%esi';saved='%r8' if wide else '%r8d'
    initial=('mov'+size+' $0,'+a+'\n') if case['retry'] else ('mov'+size+' (%rdi),'+a+'\n')
    predicate='jne retry\n' if case['predicate']=='direct' else 'sete %cl\ntest %cl,%cl\nje retry\n'
    body=initial+'retry:\nmov'+size+' '+a+','+saved+'\nmov'+size+' '+a+','+desired+'\n'+case['operation'].removeprefix('fetch_')+size+' '+inp+','+desired+'\n'+('lock ' if case['locked'] else '')+'cmpxchg'+size+' '+desired+',(%rdi)\n'+predicate
    return ('.text\n.globl _start\n_start:\nlea data(%rip),%rdi\nmovq $3,%rsi\n.globl begin\nbegin:\n'+body
        +'.globl end\nend:\ncmp'+size+' $7,'+saved+'\njne bad\ncmp'+size+' $'+str(result(case['operation'],7,3,width))+',(%rdi)\njne bad\nxorq %rdi,%rdi\njmp done\nbad:movq $9,%rdi\ndone:movq $60,%rax\nsyscall\n'
        +'.data\n.balign 8\n.globl data\ndata:.quad 7\n.section .note.GNU-stack,"",@progbits\n')


def retry_machine(elf,reg,case):
    from .l3_atomic_retry import prove
    a=reg['start'];n=reg['end']-a
    sections=[s for s in elf.sections if s[2]&4 and s[3]<=a and a+n<=s[3]+s[5]]
    if len(sections)!=1:raise ValueError('L3_ATOMIC_PROBE_SECTION_INVALID')
    section=sections[0]
    return prove(elf.slice(section[4]+a-section[3],n),a,
                 calibration_mismatch=case['retry'],suffix=False)


def region(elf):
    return {'start':elf.symbol('begin')[0],'end':elf.symbol('end')[0],'exits':[elf.symbol('end')[0]]}


def instruction(elf,reg,case=None):
    if case is not None and case.get("implementation")=="cas-loop":return retry_machine(elf,reg,case)["instruction"]
    a=reg['start'];n=reg['end']-a;sections=[s for s in elf.sections if s[2]&4 and s[3]<=a and a+n<=s[3]+s[5]]
    if len(sections)!=1:raise ValueError('L3_ATOMIC_PROBE_SECTION_INVALID')
    s=sections[0];result=atomic_instruction(elf.slice(s[4]+a-s[3],n),elf.machine)
    if result is None:raise ValueError('L3_ATOMIC_PROBE_ENCODING_INVALID')
    return result


def build_command(b,case,asm,binary):
    flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax'] if case['side']=='source' else []
    return [b[case['side']+'Compiler'],*flags,'-nostdlib','-nostartfiles','-static','-no-pie','-Wl,--build-id=none',str(asm),'-o',str(binary)]


def check_calibration(value,r,b):
    case=r['case'];side=case['side'];binary=Path(r['binary']);elf=Elf(binary);reg=region(elf);insn=instruction(elf,reg,case)
    e=r['evidence'];trace=Path(e['rawTracePath']);cp=trace.with_name('execute.command.json');bp=Path(r['assembly']).with_name('build.command.json')
    c=json.loads(cp.read_text());bc=json.loads(bp.read_text())
    if (elf.machine!=(243 if side=='source' else 62) or digest(binary)!=r['binaryDigest'] or insn!=r['instruction']
            or Path(r['assembly']).read_text()!=probe(case) or digest(bp)!=r['buildCommandDigest']
            or bc['command']!=build_command(b,case,r['assembly'],binary) or bc['returnCode']!=0 or bc['timedOut'] is not False
            or digest(trace)!=e['rawTraceDigest'] or digest(cp)!=e['commandRecordDigest']
            or c['command']!=control.command(b,side,str(binary),reg,trace,e['token'])
            or c['returnCode']!=0 or c['timedOut'] is not False or c['stdout'] or c['stderr']):
        raise ValueError('L3_ATOMIC_CALIBRATION_CHANGED')
    observed=parse_capture(trace.read_text(),e['token'],'riscv64' if side=='source' else 'x86_64',reg,1)
    accesses=observed['memory'];kinds=[x['access'] for x in accesses]
    if r['callbackAccessKinds']!=kinds:raise ValueError('L3_ATOMIC_CALIBRATION_CALLBACK_LIST_CHANGED')
    if case.get('implementation')=='cas-loop':
        from .l3_atomic_retry import attempts
        machine=retry_machine(elf,reg,case)
        count=attempts(machine,observed['paths'][0])
        if count!=(2 if case['retry'] else 1):raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_ATTEMPT_MISMATCH')
        expected=retry_shapes(machine,observed,count,elf.symbol('data')[0],case['width']//8)
        if r.get('callbackAccessByOutcome')!=expected:raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_SHAPE_CHANGED')
    else:
        expected_roles=(10,11,0 if case['discard'] else 12) if side=='source' else (7,6,None if case['discard'] else 6)
        if ((insn['addressRegister'],insn['inputRegister'],insn['resultRegister'])!=expected_roles
                or insn.get('displacement',0)!=0):raise ValueError('L3_ATOMIC_CALIBRATION_REGISTER_ROLE_MISMATCH')
        if (observed['paths']!=[{'pcs':[reg['start']],'exit':reg['end']}]
                or kinds not in (['read'],['write'],['read','write']) or kinds!=r['callbackAccessKinds']
                or any(x!={'sample':0,'pc':reg['start'],'address':elf.symbol('data')[0],'size':case['width']//8,'access':x['access']} for x in accesses)):
            raise ValueError('L3_ATOMIC_CALIBRATION_OBSERVATION_MISMATCH')
    if (insn['operation']!=case['operation'] or insn['width']!=case['width']
            or (side=='source' and insn['ordering']!=case['ordering'])
            or (side=='target' and (insn['mechanism'].startswith('x86-unlocked-') != (not case['locked'])))):
        raise ValueError('L3_ATOMIC_CALIBRATION_OBSERVATION_MISMATCH')


def memory_by_step(observed):
    groups={}
    if len(observed.get('memoryTimeline',[]))!=len(observed['memory']):raise ValueError('L3_ATOMIC_MEMORY_TIMELINE_REQUIRED')
    for index,item in enumerate(observed['memoryTimeline']):
        if item['memoryIndex']!=index:raise ValueError('L3_ATOMIC_MEMORY_TIMELINE_CHANGED')
        groups.setdefault(item['step'],[]).append(observed['memory'][index])
    return groups


def retry_shapes(machine,observed,count,address,width):
    groups=memory_by_step(observed);pcs=observed['paths'][0]['pcs'];shapes={};used=[]
    for step,pc in enumerate(pcs):
        memory=groups.get(step,[]);used+=memory
        if pc==machine['retry']['casPC']:
            remaining=sum(1 for p in pcs[step:] if p==pc)
            outcome='success' if remaining==1 else 'failure'
            kinds=[m['access'] for m in memory]
            # Keep the exact measured callback vector. A callback is not an
            # architectural R/W event; failed CAS may emit none on a backend.
            if (outcome=='success' and not kinds) or any(k not in ('read','write') for k in kinds):
                raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_CALLBACK_MISSING')
            if outcome in shapes and shapes[outcome]!=kinds:raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_CALLBACK_CONFLICT')
            shapes[outcome]=kinds
        elif pc in {x['pc'] for x in machine['retry']['initialMemory']}:
            if [m['access'] for m in memory]!=['read']:raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_INITIAL_READ')
        elif memory:raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_EXTRA_ACCESS')
        if any(m['sample']!=0 or m['pc']!=pc or m['address']!=address or m['size']!=width for m in memory):
            raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_OBJECT_MISMATCH')
    if used!=observed['memory'] or set(shapes)!=({'failure','success'} if count>1 else {'success'}):
        raise ValueError('L3_ATOMIC_RETRY_CALIBRATION_INCOMPLETE')
    return shapes


def callback_shape(value,side,insn,outcome="success"):
    matched=[r for r in value['calibration'] if r['case']['side']==side
             and all(r['instruction'][k]==insn[k] for k in ('mechanism','operation','width','ordering'))
             and (side!='source' or (r['instruction']['resultRegister']==0)==(insn['resultRegister']==0))]
    shapes={tuple(r['callbackAccessByOutcome'][outcome]) if 'callbackAccessByOutcome' in r else tuple(r['callbackAccessKinds'])
            for r in matched if 'callbackAccessByOutcome' not in r or outcome in r['callbackAccessByOutcome']}
    if len(shapes)!=1:raise ValueError('L3_ATOMIC_CALLBACK_CAPABILITY_UNCALIBRATED')
    return list(shapes.pop())


def validate(path,*,_context=None):
    value=json.loads(Path(path).read_text()) if isinstance(path,(str,Path)) else path
    if isinstance(value,dict) and value.get('schemaVersion')=='riscv2x86.qemu-direct-atomic-backend.v1':
        raise ValueError('L3_ATOMIC_BACKEND_RECALIBRATION_REQUIRED')
    fields={'schemaVersion','controlBackendPath','controlBackendDigest','files','calibration','backendIdentity',*control.TOOLS}
    if (not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA
            or value['backendIdentity']!=identity({k:v for k,v in value.items() if k!='backendIdentity'})):
        raise ValueError('L3_ATOMIC_BACKEND_INVALID')
    b=base(value,_context)
    if any(value[k]!=b[k] for k in control.TOOLS):raise ValueError('L3_ATOMIC_BACKEND_TOOL_CHANGED')
    required=set(implementation_paths())
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
               **{k:b[k] for k in control.TOOLS},'files':{name:digest(name) for name in implementation_paths()},'calibration':[]}
        for i,case in enumerate(CASES):
            status['calibrationCurrent']=case;write_status_atomic(out/'build-status.json',status)
            work=out/'calibration'/str(i);work.mkdir(parents=True);asm=work/'probe.S';asm.write_text(probe(case));binary=work/'probe'
            run(build_command(b,case,asm,binary),work,'build')
            observed,_,e=control.capture(b,case['side'],binary,region(Elf(binary)),work/'capture',1,120)
            record={'case':case,'assembly':str(asm),'binary':str(binary),'binaryDigest':digest(binary),'buildCommandDigest':digest(work/'build.command.json'),
                    'evidence':e,'instruction':instruction(Elf(binary),region(Elf(binary)),case),'callbackAccessKinds':[x['access'] for x in observed['memory']]}
            if case.get('implementation')=='cas-loop':
                observed=parse_capture(Path(e['rawTracePath']).read_text(),e['token'],'x86_64',region(Elf(binary)),1)
                machine=retry_machine(Elf(binary),region(Elf(binary)),case)
                record['callbackAccessByOutcome']=retry_shapes(machine,observed,2 if case['retry'] else 1,Elf(binary).symbol('data')[0],case['width']//8)
            check_calibration(value,record,b);value['calibration'].append(record);status['calibrationCompleted'].append(case);write_status_atomic(out/'build-status.json',status)
        value['backendIdentity']=identity(value);validate(value);save(out/'backend.json',value)
        status.update(stage='complete',complete=True,backendIdentity=value['backendIdentity']);write_status_atomic(out/'build-status.json',status);return value
    except Exception as exc:
        record_failure(out/'build-status.json',status,exc);raise


def main():
    p=argparse.ArgumentParser();p.add_argument('--control-backend',required=True);p.add_argument('--output',required=True);a=p.parse_args();b=prepare(a.control_backend,a.output)
    print(json.dumps({'backendPath':str(Path(a.output).resolve()/'backend.json'),'backendIdentity':b['backendIdentity'],'semanticApproval':False}))
if __name__=='__main__':main()
