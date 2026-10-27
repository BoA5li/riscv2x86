"""Typed x86 CAS-loop proof and complete-PC-path attribution.

A bounded decoder and two-epoch symbolic loop invariant validate the actual
address, desired-value computation, refreshed accumulator, failure backedge and
old-value projection. Unknown encodings/control, helper calls and side effects
reject. No runtime register values or concurrent linearizability are inferred.
"""
from copy import deepcopy
from .l3_trace_support import identity


def low(value, width):
    if isinstance(value, int): return value & ((1 << width) - 1)
    if isinstance(value, tuple) and value[0]=='sign32' and width<=32:return low(value[1],width)
    if isinstance(value, tuple) and value[0] == 'low':
        return low(value[2], min(width, value[1]))
    if isinstance(value, tuple) and value[0] == 'old' and value[2] <= width: return value
    if isinstance(value, tuple) and value[0] in ('and','or','xor'):
        return value if value[1]<=width else bitwise(value[0],value[2],value[3],width)
    return value if width == 64 else ('low', width, value)


def bitwise(op, left, right, width):
    pair = sorted((low(left, width), low(right, width)), key=repr)
    return (op, width, *pair)


def invert(value):
    return value[1] if isinstance(value, tuple) and value[0] == 'not' else ('not', value)


def decode(code, base):
    rows = []; i = 0
    def read(n):
        nonlocal i
        if i+n > len(code): raise ValueError('L3_ATOMIC_RETRY_TRUNCATED')
        v = int.from_bytes(code[i:i+n], 'little'); i += n; return v
    def signed(v, n): return v - (1 << n) if v & (1 << (n-1)) else v
    while i < len(code):
        begin = i; pc = base+i; rex = 0; locked = False; op = read(1)
        if op == 0xf0: locked = True; op = read(1)
        if 0x40 <= op <= 0x4f: rex = op; op = read(1)
        width = 64 if rex & 8 else 32
        def modrm():
            m = read(1); mode = m >> 6
            reg = ((m >> 3) & 7) + (8 if rex & 4 else 0)
            rm = (m & 7) + (8 if rex & 1 else 0)
            if mode == 3: return reg, {'register': rm}
            if m & 7 == 4:
                sib = read(1)
                if ((sib >> 3) & 7) != 4 or rex & 2 or (mode == 0 and sib & 7 == 5):
                    raise ValueError('L3_ATOMIC_RETRY_INDEXED_ADDRESS_UNSUPPORTED')
                rm = (sib & 7) + (8 if rex & 1 else 0)
            if mode == 0 and rm & 7 == 5: raise ValueError('L3_ATOMIC_RETRY_RIP_ADDRESS_UNSUPPORTED')
            disp = signed(read(1), 8) if mode == 1 else signed(read(4), 32) if mode == 2 else 0
            return reg, {'base': rm, 'offset': disp}
        regop = lambda r: {'register': r}
        row = None
        if op in (0x89, 0x8b, 0x21, 0x23, 0x09, 0x0b, 0x31, 0x33):
            reg, rm = modrm(); reverse = op in (0x8b, 0x23, 0x0b, 0x33)
            left, right = (regop(reg), rm) if reverse else (rm, regop(reg))
            name = 'move' if op in (0x89, 0x8b) else {0x21:'and',0x23:'and',0x09:'or',0x0b:'or',0x31:'xor',0x33:'xor'}[op]
            row = {'op': name, 'destination': left, 'source': right, 'width': width}
        elif op == 0x0f:
            sub = read(1)
            if sub == 0xb1:
                reg, rm = modrm()
                if 'base' not in rm: raise ValueError('L3_ATOMIC_RETRY_CAS_MEMORY_REQUIRED')
                row = {'op':'cas', 'address':rm, 'desired':reg, 'width':width, 'locked':locked}
            elif sub in (0x94, 0x95):
                reg, rm = modrm()
                if reg or 'register' not in rm or (not rex and rm['register'] >= 4):
                    raise ValueError('L3_ATOMIC_RETRY_SETCC_UNSUPPORTED')
                row = {'op':'setcc','register':rm['register'],'equal':sub==0x94}
            elif sub in (0x84, 0x85):
                delta = signed(read(4), 32)
                row = {'op':'branch','equal':sub==0x84,'target':base+i+delta}
            else: raise ValueError('L3_ATOMIC_RETRY_OPCODE_UNSUPPORTED')
        elif op in (0x74, 0x75):
            delta = signed(read(1), 8); row = {'op':'branch','equal':op==0x74,'target':base+i+delta}
        elif op in (0x84, 0x85):
            reg, rm = modrm()
            if 'register' not in rm or (op==0x84 and not rex and (reg>=4 or rm['register']>=4)):
                raise ValueError('L3_ATOMIC_RETRY_TEST_UNSUPPORTED')
            row = {'op':'test','left':reg,'right':rm['register'],'width':8 if op==0x84 else width}
        elif 0x50 <= op <= 0x57: row = {'op':'push','register':op-0x50+(8 if rex&1 else 0)}
        elif 0x58 <= op <= 0x5f: row = {'op':'pop','register':op-0x58+(8 if rex&1 else 0)}
        elif op in (0x81, 0x83):
            group, rm = modrm(); delta = signed(read(1 if op==0x83 else 4),8 if op==0x83 else 32)
            if group not in (0,5) or rm != regop(4) or width != 64:
                raise ValueError('L3_ATOMIC_RETRY_STACK_ARITHMETIC_REQUIRED')
            row = {'op':'stack-add','value':delta if group==0 else -delta}
        elif op == 0x63 and width==64:
            reg, rm = modrm();row={'op':'sext32','destination':regop(reg),'source':rm,'width':64}
        elif op == 0x98 and width==64: row={'op':'sext32','destination':regop(0),'source':regop(0),'width':64}
        elif op == 0xc9: row={'op':'leave'}
        elif op == 0xc3: row={'op':'return'}
        elif op == 0x90: row={'op':'nop'}
        elif op==0xc7:
            group,rm=modrm();value=signed(read(4),32)
            if group or 'register' not in rm:raise ValueError('L3_ATOMIC_RETRY_CONSTANT_UNSUPPORTED')
            row={'op':'move','destination':rm,'source':{'constant':value},'width':width}
        elif 0xb8 <= op <= 0xbf:
            row={'op':'move','destination':regop(op-0xb8+(8 if rex&1 else 0)),
                 'source':{'constant':read(8 if width==64 else 4)},'width':width}
        elif op == 0xf3 and code[i:i+3]==bytes.fromhex('0f1efa'):
            i+=3;row={'op':'nop'}
        if row is None or locked and row['op']!='cas': raise ValueError('L3_ATOMIC_RETRY_ENCODING_UNSUPPORTED:'+hex(pc))
        rows.append(dict(row,pc=pc,size=i-begin,bytes=code[begin:i].hex()))
        if len(rows)>256: raise ValueError('L3_ATOMIC_RETRY_FUNCTION_BUDGET')
    return rows


def state(pointer, value):
    regs={7:('parameter',0),6:('parameter',1),4:('stack',0)}
    return {'registers':regs,'memory':{},'byteRegisters':{},'zero':None,
            'pointer':('parameter',pointer),'input':('parameter',value)}


def read_register(s, register, width):
    if width==8 and register in s['byteRegisters']: return s['byteRegisters'][register]
    return low(s['registers'].get(register,('unknown',register)), width)


def write_register(s, register, value, width):
    if width==8:
        s['byteRegisters'][register]=value
        s['registers'][register]=('partial-byte',s['registers'].get(register),value)
    else:
        s['byteRegisters'].pop(register,None);s['registers'][register]=low(value,width)


def address(s, operand):
    v=read_register(s,operand['base'],64);delta=operand['offset']
    if isinstance(v,tuple) and v[0]=='stack':return ('stack',v[1]+delta)
    if v==s['pointer'] and delta==0:return ('object',0)
    raise ValueError('L3_ATOMIC_RETRY_ADDRESS_UNBOUND')


def get(s, operand, width):
    if 'constant' in operand:return low(operand['constant'],width)
    if 'register' in operand:return read_register(s,operand['register'],width)
    a=address(s,operand)
    if a[0]!='stack':raise ValueError('L3_ATOMIC_RETRY_STACK_READ_UNBOUND')
    if (a[1],width) in s['memory']:return s['memory'][(a[1],width)]
    # A compiler may read the low word of a known 64-bit input spill.
    candidates=[value for (slot,bits),value in s['memory'].items() if slot==a[1] and bits>=width]
    if len(candidates)!=1:raise ValueError('L3_ATOMIC_RETRY_STACK_READ_UNBOUND')
    return low(candidates[0],width)


def put(s, operand, value, width):
    if 'register' in operand:write_register(s,operand['register'],value,width);return
    a=address(s,operand)
    if a[0]!='stack':raise ValueError('L3_ATOMIC_RETRY_EXTRA_OBJECT_WRITE')
    for (slot,w) in list(s['memory']):
        if slot<a[1]+width//8 and a[1]<slot+w//8:del s['memory'][(slot,w)]
    s['memory'][(a[1],width)]=low(value,width)


def step(s, row, *, region=False, roles=None):
    op=row['op']
    if region and op not in ('move','and','or','xor','sext32','setcc','test','nop'):
        raise ValueError('L3_ATOMIC_RETRY_REGION_SIDE_EFFECT_UNSUPPORTED')
    if op in ('move','and','or','xor','sext32'):
        width=row['width'];src=row['source']
        if 'base' in src and region:
            a=address(s,src)
            if a[0]!='stack':raise ValueError('L3_ATOMIC_RETRY_UNEXPECTED_OBJECT_READ')
            if get(s,src,width)!=low(s['input'],width):raise ValueError('L3_ATOMIC_RETRY_LOOP_STACK_INPUT_REQUIRED')
            if roles is not None:roles.append({'pc':row['pc'],'role':'compiler-input-stack','stackOffset':a[1],'widthBytes':width//8,'access':'read'})
        value=get(s,src,32 if op=='sext32' else width)
        if op in ('and','or','xor'):
            if 'register' not in row['destination']:raise ValueError('L3_ATOMIC_RETRY_LOOP_STORE_UNSUPPORTED')
            value=bitwise(op,get(s,row['destination'],width),value,width);s['zero']=None
        if op=='sext32':value=('sign32',low(value,32))
        if region and 'base' in row['destination']:raise ValueError('L3_ATOMIC_RETRY_LOOP_STACK_WRITE_UNSUPPORTED')
        put(s,row['destination'],value,width)
    elif op=='push':
        sp=s['registers'][4]
        if not isinstance(sp,tuple) or sp[0]!='stack':raise ValueError('L3_ATOMIC_RETRY_STACK_UNBOUND')
        s['registers'][4]=('stack',sp[1]-8)
        put(s,{'base':4,'offset':0},read_register(s,row['register'],64),64)
    elif op=='pop':
        sp=s['registers'][4];value=get(s,{'base':4,'offset':0},64)
        write_register(s,row['register'],value,64);s['registers'][4]=('stack',sp[1]+8)
    elif op=='leave':
        s['registers'][4]=s['registers'].get(5)
        step(s,{'op':'pop','register':5})
    elif op=='stack-add':
        sp=s['registers'][4]
        if sp[0]!='stack':raise ValueError('L3_ATOMIC_RETRY_STACK_UNBOUND')
        s['registers'][4]=('stack',sp[1]+row['value']);s['zero']=None
    elif op=='setcc':
        if s['zero'] is None:raise ValueError('L3_ATOMIC_RETRY_FLAGS_UNBOUND')
        write_register(s,row['register'],s['zero'] if row['equal'] else invert(s['zero']),8)
    elif op=='test':
        a=read_register(s,row['left'],row['width']);b=read_register(s,row['right'],row['width'])
        if a!=b or a not in (('cas-success',),('not',('cas-success',))):raise ValueError('L3_ATOMIC_RETRY_PREDICATE_UNBOUND')
        s['zero']=invert(a)
    elif op=='nop':pass
    else:raise ValueError('L3_ATOMIC_RETRY_UNSUPPORTED_STATE_TRANSITION:'+op)


def prove(code, base, invocation=None, *, calibration_mismatch=False, suffix=True):
    rows=decode(code,base);cas=[r for r in rows if r['op']=='cas'];branches=[r for r in rows if r['op']=='branch']
    if len(cas)!=1 or len(branches)!=1:raise ValueError('L3_ATOMIC_RETRY_SINGLE_CAS_BACKEDGE_REQUIRED')
    atom=cas[0];branch=branches[0];pcs=[r['pc'] for r in rows]
    if branch['target'] not in pcs or not base<branch['target']<=atom['pc']<branch['pc']:
        raise ValueError('L3_ATOMIC_RETRY_BACKEDGE_INVALID')
    loop_index=pcs.index(branch['target']);branch_index=pcs.index(branch['pc']);cas_index=pcs.index(atom['pc'])
    inv=invocation or {'pointerParameter':0,'valueParameter':1,'operation':{'result_semantics':'old_value'},'widthRoles':{'resultCarrierWidth':atom['width'],'resultExtension':'identity'}}
    s=state(inv['pointerParameter'],inv['valueParameter']);loads=[]
    for index,row in enumerate(rows[:loop_index]):
        if row['op']=='move' and 'base' in row['source'] and address(s,row['source'])[0]=='object':
            if loads or row['destination']!={'register':0} or row['width']!=atom['width']:
                raise ValueError('L3_ATOMIC_RETRY_INITIAL_LOAD_INVALID')
            write_register(s,0,('old',0,atom['width']),atom['width']);loads.append(index)
        else:
            if loads and 'base' in row.get('source',{}):raise ValueError('L3_ATOMIC_RETRY_INITIAL_REGION_EXTRA_READ')
            step(s,row,region=bool(loads))
    if not loads:
        if not calibration_mismatch or read_register(s,0,atom['width'])!=0:raise ValueError('L3_ATOMIC_RETRY_INITIAL_LOAD_REQUIRED')
        # Calibration only: a deliberately mismatching expected value exercises failure.
        loads=[0];initial='mismatch-zero'
    else:initial='object-load'
    start_index=loads[0]
    if any(r['op'] in ('push','pop','leave','stack-add') for r in rows[start_index:loop_index]):
        raise ValueError('L3_ATOMIC_RETRY_INITIAL_REGION_SIDE_EFFECT')
    width=atom['width'];operations=[];memory_roles=[];success_state=None
    for epoch in (0,1):
        old=('old',epoch,width)
        if epoch or initial=='object-load':write_register(s,0,old,width)
        roles=[]
        for row in rows[loop_index:branch_index]:
            if row['op']=='cas':
                if address(s,row['address'])!=('object',0):raise ValueError('L3_ATOMIC_RETRY_CAS_OBJECT_MISMATCH')
                expected=get(s,{'register':0},width);desired=get(s,{'register':row['desired']},width)
                candidates=[op for op in ('and','or','xor') if desired==bitwise(op,expected,low(s['input'],width),width)]
                if len(candidates)!=1 or expected!=(0 if initial=='mismatch-zero' and epoch==0 else old):
                    raise ValueError('L3_ATOMIC_RETRY_DESIRED_VALUE_NOT_RECOMPUTED')
                operations.append(candidates[0]);s['zero']=('cas-success',)
            else:step(s,row,region=True,roles=roles)
        taken=s['zero'] if branch['equal'] else invert(s['zero']) if s['zero'] is not None else None
        if taken!=('not',('cas-success',)):raise ValueError('L3_ATOMIC_RETRY_FAILURE_BACKEDGE_NOT_PROVED')
        if epoch==0:memory_roles=roles
        elif roles!=memory_roles:raise ValueError('L3_ATOMIC_RETRY_MEMORY_INVARIANT_CHANGED')
        success_state=deepcopy(s)
        # Failure updates accumulator; all other loop-carried values remain, so a
        # stale desired value derived in the previous epoch cannot pass induction.
    if len(set(operations))!=1:raise ValueError('L3_ATOMIC_RETRY_OPERATION_CHANGED')
    if suffix:
        tail=rows[branch_index+1:]
        if not tail or tail[-1]['op']!='return' or any(r['op']=='return' for r in rows[:-1]):raise ValueError('L3_ATOMIC_RETRY_RETURN_REQUIRED')
        for row in tail[:-1]:step(success_state,row)
        if inv['operation']['result_semantics']=='old_value':
            wanted=('old',1,width)
            if inv['widthRoles']['resultExtension']=='sign_extend':wanted=('sign32',low(wanted,32))
            if read_register(success_state,0,inv['widthRoles']['resultCarrierWidth'])!=low(wanted,inv['widthRoles']['resultCarrierWidth']):
                raise ValueError('L3_ATOMIC_RETRY_OLD_VALUE_RETURN_NOT_PROVED')
    elif branch_index!=len(rows)-1:raise ValueError('L3_ATOMIC_RETRY_REGION_TRAILING_CODE')
    if branch_index-start_index+1>128:raise ValueError('L3_ATOMIC_RETRY_INVOCATION_BUDGET_EXCEEDED')
    end=branch['pc']+branch['size'];start=rows[start_index]['pc']
    initial_roles=([{'pc':rows[start_index]['pc'],'role':'object-load','widthBytes':width//8,'access':'read'}] if initial=='object-load' else [])
    instruction={'op':'atomic','operation':'fetch_'+operations[0],'width':width,
                 'addressRegister':atom['address']['base'],'displacement':atom['address']['offset'],
                 'inputRegister':None,'resultRegister':0,
                 'mechanism':'x86-locked-cas-loop' if atom['locked'] else 'x86-unlocked-cas-loop',
                 'ordering':'ordinary-memory-full-order' if atom['locked'] else 'unproved'}
    body={'schemaVersion':'riscv2x86.atomic-retry-machine.v1','machine':62,'instruction':instruction,
          'functionBytes':bytes(code).hex(),'instructions':rows,'region':{'start':start,'end':end,'exits':[end]},
          'retry':{'initialMode':initial,'prefixPCs':[r['pc'] for r in rows[start_index:loop_index]],
                   'loopPCs':[r['pc'] for r in rows[loop_index:branch_index+1]],'casPC':atom['pc'],
                   'initialMemory':initial_roles,'loopMemory':memory_roles,
                   'maximumAttempts':min(64,(128-(loop_index-start_index))//(branch_index-loop_index+1)),
                   'maximumInstructionPositionsPerInvocation':128,
                   'proofMethod':'two-epoch-symbolic-dataflow-and-failure-backedge'},
          'physicalMicroarchitectureClaimed':False}
    return dict(body,mechanismIdentity=identity(body))


def attempts(machine,path):
    retry=machine['retry'];prefix=retry['prefixPCs'];loop=retry['loopPCs'];pcs=path['pcs']
    if path['exit']!=machine['region']['end'] or pcs[:len(prefix)]!=prefix:raise ValueError('L3_ATOMIC_RETRY_PATH_INCOMPLETE')
    rest=pcs[len(prefix):]
    if not rest or len(rest)%len(loop):raise ValueError('L3_ATOMIC_RETRY_PATH_INCOMPLETE')
    count=len(rest)//len(loop)
    if count>retry['maximumAttempts'] or rest!=loop*count:raise ValueError('L3_ATOMIC_RETRY_PATH_INVALID')
    return count
