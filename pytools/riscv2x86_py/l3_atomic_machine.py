"""Decode real direct RMW instructions and bounded straight-line functions.

Calls and unknown encodings remain unsupported; CAS loops require a separate invariant proof. This module
never derives atomicity from an observed pair of ordinary memory callbacks.
"""
from .l3_trace_support import identity
from .l3_atomic_semantics import RV_OPERATIONS
from .l3_control_machine import decode as integer_decode


def atomic_instruction(code,machine):
    code=bytes(code)
    if machine==243 and len(code)==4:
        w=int.from_bytes(code,'little');op=(w>>27)&31;f=(w>>12)&7
        if w&127==0x2f and f in (2,3) and op in RV_OPERATIONS:
            aq,rl=bool(w&(1<<26)),bool(w&(1<<25))
            return {'op':'atomic','operation':RV_OPERATIONS[op],
                    'width':32 if f==2 else 64,'addressRegister':(w>>15)&31,'inputRegister':(w>>20)&31,
                    'resultRegister':(w>>7)&31,'mechanism':'rv-amo',
                    'ordering':'acq_rel' if aq and rl else 'acquire' if aq else 'release' if rl else 'relaxed'}
    if machine==62:
        i=0;locked=False;rex=0;discard=False
        if code[:1]==b'\xf0':locked=True;i+=1
        if i<len(code) and 0x40<=code[i]<=0x4f:rex=code[i];i+=1
        width=64 if rex&8 else 32
        if code[i:i+2]==b'\x0f\xc1':operation='fetch_add';i+=2
        elif code[i:i+1]==b'\x87':operation='exchange';i+=1
        elif code[i:i+1] in (b'\x01',b'\x21',b'\x09',b'\x31'):
            operation={1:'fetch_add',0x21:'fetch_and',9:'fetch_or',0x31:'fetch_xor'}[code[i]];i+=1;discard=True
        else:return None
        if i>=len(code):return None
        m=code[i];i+=1;mod=m>>6;rm=m&7
        if mod==3 or (mod==0 and rm==5):return None
        base=rm+(8 if rex&1 else 0)
        if rm==4:
            if i>=len(code):return None
            sib=code[i];i+=1
            if ((sib>>3)&7)!=4 or rex&2 or (mod==0 and sib&7==5):return None
            base=(sib&7)+(8 if rex&1 else 0)
        n=1 if mod==1 else 4 if mod==2 else 0
        if i+n!=len(code):return None
        disp=int.from_bytes(code[i:i+n],'little',signed=True) if n else 0
        return {'op':'atomic','operation':operation,'width':width,'addressRegister':base,'displacement':disp,
                'inputRegister':((m>>3)&7)+(8 if rex&4 else 0),
                'resultRegister':None if discard else ((m>>3)&7)+(8 if rex&4 else 0),
                'mechanism':(('x86-locked-' if locked else 'x86-unlocked-')+{'fetch_add':'add','fetch_and':'and','fetch_or':'or','fetch_xor':'xor'}[operation]) if discard else 'x86-locked-xadd' if locked and operation=='fetch_add' else
                            'x86-unlocked-xadd' if operation=='fetch_add' else 'x86-memory-xchg',
                'ordering':'ordinary-memory-full-order' if locked or operation=='exchange' else 'unproved'}
    return None


def decode(code,base,machine):
    rows=[];i=0
    while i<len(code):
        insn=None;n=0
        for length in range(1,min(15,len(code)-i)+1):
            raw=code[i:i+length];a=atomic_instruction(raw,machine)
            if a is not None:insn=a;n=length;break
            if machine==243:
                if raw in (b'\x82\x80',bytes.fromhex('67800000')):insn={'op':'return'};n=length;break
                # ADDIW (including SEXT.W), plus 32-bit stack accesses.
                if length==4:
                    w=int.from_bytes(raw,'little');opcode=w&127;f=(w>>12)&7
                    if opcode==0x1b and f==0:
                        insn={'op':'add','rd':(w>>7)&31,'rs':(w>>15)&31,'imm':int.from_bytes(raw,'little',signed=True)>>20,'width':32};n=length;break
                    if opcode in (3,0x23) and f in (2,6):
                        insn={'op':'aux-memory','width':32};n=length;break
                if length==2:
                    w=int.from_bytes(raw,'little');q=w&3;f=w>>13
                    if (q==0 and f in (2,6)) or (q==2 and f in (2,6)) or (q==1 and f==1 and (w>>7)&31):
                        insn={'op':'auxiliary'};n=length;break
            if machine==62:
                if raw==b'\xc3':insn={'op':'return'};n=length;break
                if raw==b'\xc9' or len(raw)==1 and 0x58<=raw[0]<=0x5f or raw in (b'\x48\x98',):
                    insn={'op':'auxiliary'};n=length;break
                if len(raw)==2 and 0x40<=raw[0]<=0x4f and 0x58<=raw[1]<=0x5f:
                    insn={'op':'auxiliary'};n=length;break
                # MOVSXD register/register is the common 32->64 result projection.
                if len(raw)==3 and 0x48<=raw[0]<=0x4f and raw[1]==0x63 and raw[2]>>6==3:
                    insn={'op':'auxiliary'};n=length;break
            try:
                candidates=integer_decode(raw,base+i,machine)
                if len(candidates)==1 and candidates[0]['size']==length:
                    insn={k:v for k,v in candidates[0].items() if k not in ('pc','size','bytes')};n=length;break
            except (ValueError,IndexError):pass
        if insn is None:raise ValueError('L3_ATOMIC_MACHINE_ENCODING_UNSUPPORTED:'+str(machine)+':'+hex(base+i))
        if insn['op'] in {'branch','jump'}:raise ValueError('L3_ATOMIC_RETRY_OR_CONTROL_ROUTE_REQUIRED')
        rows.append(dict(insn,pc=base+i,size=n,bytes=code[i:i+n].hex()));i+=n
        if len(rows)>256:raise ValueError('L3_ATOMIC_FUNCTION_BUDGET_EXCEEDED')
    return rows


def function_mechanism(elf,name,invocation=None):
    address=elf.symbol(name)[0]
    try:
        rows=decode(elf.code(name),address,elf.machine)
    except ValueError:
        if elf.machine!=62:raise
        from .l3_atomic_retry import prove
        return prove(elf.code(name),address,invocation)
    atoms=[r for r in rows if r['op']=='atomic']
    if len(atoms)!=1 or not rows or rows[-1]['op']!='return' or any(r['op']=='return' for r in rows[:-1]):
        raise ValueError('L3_ATOMIC_SINGLE_STRAIGHT_LINE_OPERATION_REQUIRED')
    atom=atoms[0];end=atom['pc']+atom['size']
    if not any(r['pc']==end for r in rows):raise ValueError('L3_ATOMIC_COMPLETION_BOUNDARY_MISSING')
    body={'schemaVersion':'riscv2x86.atomic-machine-region.v1','machine':elf.machine,'instruction':atom,
          'functionBytes':elf.code(name).hex(),'instructions':rows,
          'region':{'start':atom['pc'],'end':end,'exits':[end]},'physicalMicroarchitectureClaimed':False}
    return dict(body,mechanismIdentity=identity(body))


def satisfies(instruction,operation,side):
    if instruction['operation']!=operation['rmw_operation'] or instruction['width']!=operation['width_bits']:return False
    if operation.get('result_semantics')=='old_value' and (instruction['resultRegister'] is None or side=='source' and instruction['resultRegister']==0):return False
    if side=='target':return instruction['mechanism'] in {'x86-locked-xadd','x86-locked-add','x86-memory-xchg','x86-locked-and','x86-locked-or','x86-locked-xor','x86-locked-cas-loop'}
    orders={'relaxed':set(),'acquire':{'acquire'},'release':{'release'},'acq_rel':{'acquire','release'}}
    need=operation['success_ordering'];actual=instruction['ordering']
    return need in orders and actual in orders and orders[need]<=orders[actual]
