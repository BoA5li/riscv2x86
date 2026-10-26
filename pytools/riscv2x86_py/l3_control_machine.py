"""Bounded binary decoder and symbolic path witness for RV64/AMD64 integer CFGs.

Unknown encodings, calls, indirect transfers, indexed addressing, cycles and
unbound values reject the route. This is deliberately not a general ISA lifter.
No mnemonic text, source labels or case names select the semantics.
"""
from .l3_trace_support import identity


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits-1)) else value


def decode(code, base, machine):
    rows=[]; i=0
    def read(n):
        nonlocal i
        if i+n>len(code):raise ValueError('L3_CONTROL_INSTRUCTION_TRUNCATED')
        v=int.from_bytes(code[i:i+n],'little');i+=n;return v
    while i<len(code):
        begin=i; pc=base+i; r={}
        if machine==243:
            w=read(2); q=w&3; f=w>>13
            if q!=3:
                rd=(w>>7)&31; small=signed(((w>>12)&1)*32+((w>>2)&31),6)
                if q==1 and f==0:r={'op':'add','rd':rd,'rs':rd,'imm':small}
                elif q==1 and f==2:r={'op':'constant','rd':rd,'imm':small}
                elif q==1 and f==3 and rd==2:
                    imm=((w>>12)&1)<<9|((w>>6)&1)<<4|((w>>5)&1)<<6|((w>>3)&3)<<7|((w>>2)&1)<<5
                    if not imm:raise ValueError('L3_CONTROL_RESERVED_INSTRUCTION')
                    r={'op':'add','rd':2,'rs':2,'imm':signed(imm,10)}
                elif q==0 and f==0:
                    imm=((w>>11)&3)<<4|((w>>7)&15)<<6|((w>>6)&1)<<2|((w>>5)&1)<<3
                    if not imm:raise ValueError('L3_CONTROL_RESERVED_INSTRUCTION')
                    r={'op':'add','rd':8+((w>>2)&7),'rs':2,'imm':imm}
                elif q==2 and f==4 and not w&0x1000 and rd and (w>>2)&31:
                    r={'op':'move','rd':rd,'rs':(w>>2)&31}
                elif q==0 and f in (3,7):
                    imm=((w>>10)&7)<<3|((w>>5)&3)<<6
                    r={'op':'load' if f==3 else 'store','rd':8+((w>>2)&7),'rs':8+((w>>7)&7),'imm':imm,'width':64}
                elif q==2 and f==3 and rd:
                    imm=((w>>12)&1)<<5|((w>>5)&3)<<3|((w>>2)&7)<<6
                    r={'op':'load','rd':rd,'rs':2,'imm':imm,'width':64}
                elif q==2 and f==7:
                    imm=((w>>10)&7)<<3|((w>>7)&7)<<6
                    r={'op':'store','rd':(w>>2)&31,'rs':2,'imm':imm,'width':64}
                elif q==1 and f==5:
                    imm=((w>>12)&1)<<11|((w>>11)&1)<<4|((w>>9)&3)<<8|((w>>8)&1)<<10|((w>>7)&1)<<6|((w>>6)&1)<<7|((w>>3)&7)<<1|((w>>2)&1)<<5
                    r={'op':'jump','target':pc+signed(imm,12)}
                elif q==1 and f in (6,7):
                    imm=((w>>12)&1)<<8|((w>>10)&3)<<3|((w>>5)&3)<<6|((w>>3)&3)<<1|((w>>2)&1)<<5
                    r={'op':'branch','left':8+((w>>7)&7),'right':0,'condition':'equal' if f==6 else 'not_equal','target':pc+signed(imm,9)}
            else:
                w|=read(2)<<16;op=w&127;rd=(w>>7)&31;rs=(w>>15)&31;rt=(w>>20)&31;f=(w>>12)&7
                if op==0x13 and f==0:r={'op':'add','rd':rd,'rs':rs,'imm':signed(w>>20,12)}
                elif op==3 and f==3:r={'op':'load','rd':rd,'rs':rs,'imm':signed(w>>20,12),'width':64}
                elif op==0x23 and f==3:r={'op':'store','rd':rt,'rs':rs,'imm':signed(((w>>25)<<5)|((w>>7)&31),12),'width':64}
                elif op==0x63 and f in (0,1,4,5,6,7):
                    imm=((w>>31)&1)<<12|((w>>7)&1)<<11|((w>>25)&63)<<5|((w>>8)&15)<<1
                    r={'op':'branch','left':rs,'right':rt,'condition':{0:'equal',1:'not_equal',4:'signed_less',5:'signed_greater_equal',6:'unsigned_less',7:'unsigned_greater_equal'}[f],'target':pc+signed(imm,13)}
                elif op==0x6f and rd==0:
                    imm=((w>>31)&1)<<20|((w>>12)&255)<<12|((w>>20)&1)<<11|((w>>21)&1023)<<1
                    r={'op':'jump','target':pc+signed(imm,21)}
        elif machine==62:
            rex=0; op=read(1)
            if op==0xf3 and code[i:i+3]==b'\x0f\x1e\xfa':i+=3;r={'op':'nop'}
            else:
                if 0x40<=op<=0x4f:rex=op;op=read(1)
                width=64 if rex&8 else 32
                def modrm():
                    m=read(1);mod=m>>6; reg=((m>>3)&7)+(8 if rex&4 else 0);rm=(m&7)+(8 if rex&1 else 0)
                    if mod==3:return reg,{'reg':rm}
                    if m&7==4:
                        sib=read(1)
                        if ((sib>>3)&7)!=4 or rex&2:raise ValueError('L3_CONTROL_INDEXED_ADDRESS_UNSUPPORTED')
                        rm=(sib&7)+(8 if rex&1 else 0)
                    if mod==0 and rm&7==5:raise ValueError('L3_CONTROL_ABSOLUTE_ADDRESS_UNSUPPORTED')
                    disp=signed(read(1),8) if mod==1 else signed(read(4),32) if mod==2 else 0
                    return reg,{'base':rm,'disp':disp}
                if op==0x90:r={'op':'nop'}
                elif 0x50<=op<=0x57:r={'op':'push','rs':op-0x50+(8 if rex&1 else 0)}
                elif op in (0x89,0x8b,0x39,0x3b,0x85):
                    reg,rm=modrm()
                    if op in (0x39,0x3b,0x85):
                        if 'reg' not in rm or width!=64:raise ValueError('L3_CONTROL_PREDICATE_ENCODING_UNSUPPORTED')
                        r={'op':'test' if op==0x85 else 'compare','left':rm['reg'] if op!=0x3b else reg,'right':reg if op!=0x3b else rm['reg']}
                    elif 'reg' in rm:r={'op':'move','rd':rm['reg'] if op==0x89 else reg,'rs':reg if op==0x89 else rm['reg'],'width':width}
                    else:r={'op':'store' if op==0x89 else 'load','rd':reg,'rs':rm['base'],'imm':rm['disp'],'width':width}
                elif op in (0x81,0x83):
                    group,rm=modrm();n=1 if op==0x83 else 4;imm=signed(read(n),8*n)
                    if 'reg' not in rm or group not in (0,5) or width!=64:raise ValueError('L3_CONTROL_ARITHMETIC_UNSUPPORTED')
                    r={'op':'add','rd':rm['reg'],'rs':rm['reg'],'imm':imm if group==0 else -imm}
                elif 0xb8<=op<=0xbf:r={'op':'constant','rd':op-0xb8+(8 if rex&1 else 0),'imm':read(8 if width==64 else 4),'width':width}
                elif op==0xc7:
                    group,rm=modrm();imm=signed(read(4),32)
                    if group or 'reg' not in rm:raise ValueError('L3_CONTROL_CONSTANT_ENCODING_UNSUPPORTED')
                    r={'op':'constant','rd':rm['reg'],'imm':imm,'width':width}
                elif op in (0xeb,0xe9):
                    n=1 if op==0xeb else 4;disp=signed(read(n),n*8);r={'op':'jump','target':base+i+disp}
                elif 0x70<=op<=0x7f or op==0x0f:
                    cc=op&15; n=1
                    if op==0x0f:
                        other=read(1)
                        if not 0x80<=other<=0x8f:raise ValueError('L3_CONTROL_X86_OPCODE_UNSUPPORTED')
                        cc=other&15;n=4
                    cond={2:'unsigned_less',3:'unsigned_greater_equal',4:'equal',5:'not_equal',6:'unsigned_less_equal',7:'unsigned_greater',12:'signed_less',13:'signed_greater_equal',14:'signed_less_equal',15:'signed_greater'}.get(cc)
                    if cond is None:raise ValueError('L3_CONTROL_X86_CONDITION_UNSUPPORTED')
                    disp=signed(read(n),8*n);r={'op':'branch','condition':cond,'target':base+i+disp}
        if not r:raise ValueError('L3_CONTROL_MACHINE_OPCODE_UNSUPPORTED:'+str(machine)+':'+hex(pc))
        rows.append(dict(r,pc=pc,size=i-begin,bytes=code[begin:i].hex()))
        if len(rows)>1024:raise ValueError('L3_CONTROL_MACHINE_BUDGET_EXCEEDED')
    return rows


def initial(machine):
    regs={r:'parameter:'+str(i) for i,r in enumerate((10,11,12,13) if machine==243 else (7,6,2,1))}
    regs[2 if machine==243 else 4]=('stack',0)
    if machine==243:regs[0]=0
    return {'registers':regs,'memory':{},'compare':None}


def step(state, insn, machine):
    regs=state['registers'];mem=state['memory'];op=insn['op']
    def get(r):return regs.get(r,'unbound:'+str(r))
    def address():
        base=get(insn['rs'])
        if not isinstance(base,tuple) or base[0]!='stack':raise ValueError('L3_CONTROL_STACK_BINDING_UNPROVEN')
        return base[1]+insn['imm']
    if op=='move':value=get(insn['rs'])
    elif op=='constant':value=insn['imm']&((1<<64)-1)
    elif op=='add':
        # AMD64 arithmetic overwrites flags. A later Jcc must not reuse an
        # earlier CMP/TEST witness after ADD/SUB (RISC-V has no flag state).
        if machine==62:state['compare']=None
        base=get(insn['rs']);imm=insn['imm']
        if isinstance(base,tuple):value=('stack',base[1]+imm)
        elif not imm:value=base
        elif isinstance(base,int):value=(base+imm)&((1<<64)-1)
        else:raise ValueError('L3_CONTROL_VALUE_ARITHMETIC_UNSUPPORTED')
    elif op=='load':
        if insn['width']!=64:raise ValueError('L3_CONTROL_STACK_WIDTH_UNSUPPORTED')
        if address() not in mem:raise ValueError('L3_CONTROL_STACK_VALUE_UNBOUND')
        value=mem[address()]
    elif op=='store':
        if insn['width']!=64:raise ValueError('L3_CONTROL_STACK_WIDTH_UNSUPPORTED')
        slot=address()
        for old in list(mem):
            if old<slot+8 and slot<old+8:del mem[old]
        mem[slot]=get(insn['rd']);return
    elif op=='push':
        sp=get(4)
        if not isinstance(sp,tuple):raise ValueError('L3_CONTROL_STACK_BINDING_UNPROVEN')
        regs[4]=('stack',sp[1]-8);mem[sp[1]-8]=get(insn['rs']);return
    elif op in ('compare','test'):
        left,right=get(insn['left']),get(insn['right'])
        if op=='test':
            if left!=right:raise ValueError('L3_CONTROL_TEST_PREDICATE_UNSUPPORTED')
            right=0
        state['compare']=(left,right);return
    elif op=='nop':return
    else:raise ValueError('L3_CONTROL_NONLINEAR_PREFIX')
    if insn.get('width',64)!=64:
        if not isinstance(value,int):raise ValueError('L3_CONTROL_NARROW_PARAMETER_UNSUPPORTED')
        value&=0xffffffff
    if not(machine==243 and insn['rd']==0):regs[insn['rd']]=value


def graph(code, function_start, region, machine, result_register=None):
    """Decode prefix and region; enumerate a finite acyclic graph from bytes."""
    from copy import deepcopy
    limit=region['end']-function_start
    instructions=decode(code[:limit],function_start,machine);by_pc={i['pc']:i for i in instructions}
    state=initial(machine)
    for i in instructions:
        if i['pc']>=region['start']:break
        step(state,i,machine)
    exits=set(region['exits']);paths=[]
    def walk(pc,state,trace,conditions,transfers):
        if pc in exits:
            value=None if result_register is None else state['registers'].get(result_register)
            paths.append({'pcs':trace,'conditions':conditions,'transfers':transfers,'exit':pc,'value':value});return
        if pc in trace or len(trace)>=128:raise ValueError('L3_CONTROL_CYCLIC_GRAPH_UNSUPPORTED')
        if pc not in by_pc or not region['start']<=pc<region['end']:raise ValueError('L3_CONTROL_UNBOUND_SUCCESSOR')
        insn=by_pc[pc];trace=trace+[pc];next_pc=pc+insn['size'];op=insn['op']
        if op=='branch':
            pair=((state['registers'].get(insn['left'],'unbound'),state['registers'].get(insn['right'],'unbound')) if machine==243 else state['compare'])
            if pair is None or any(isinstance(x,str) and not x.startswith('parameter:') for x in pair):raise ValueError('L3_CONTROL_PREDICATE_UNBOUND')
            if insn['target']==next_pc:raise ValueError('L3_CONTROL_BRANCH_OUTCOME_UNOBSERVABLE')
            for taken,successor in ((False,next_pc),(True,insn['target'])):
                walk(successor,deepcopy(state),trace,conditions+[{'kind':insn['condition'],'left':pair[0],'right':pair[1],'taken':taken}],transfers+[{'pc':pc,'kind':'conditional','taken':taken,'target':successor}])
        elif op=='jump':walk(insn['target'],state,trace,conditions,transfers+[{'pc':pc,'kind':'direct','taken':True,'target':insn['target']}])
        else:
            step(state,insn,machine);walk(next_pc,state,trace,conditions,transfers)
        if len(paths)>16:raise ValueError('L3_CONTROL_PATH_BUDGET_EXCEEDED')
    walk(region['start'],state,[],[],[])
    body={'schemaVersion':'riscv2x86.control-machine-graph.v1','machine':machine,
          'region':region,'instructions':[x for x in instructions if x['pc']>=region['start']],
          'paths':paths,'resultRegister':result_register}
    return dict(body,graphIdentity=identity(body))


def condition(kind,left,right):
    if kind.startswith('signed_'):left=signed(left,64);right=signed(right,64)
    op=kind.removeprefix('signed_').removeprefix('unsigned_')
    return {'equal':lambda:left==right,'not_equal':lambda:left!=right,'less':lambda:left<right,
            'greater_equal':lambda:left>=right,'less_equal':lambda:left<=right,'greater':lambda:left>right}[op]()


def value_of(value,inputs):
    if isinstance(value,int):return value
    if isinstance(value,str) and value.startswith('parameter:'):return inputs[int(value.split(':')[1])]
    raise ValueError('L3_CONTROL_VALUE_UNBOUND')


def selected_path(graph,pcs,exit_pc,inputs):
    matches=[p for p in graph['paths'] if p['pcs']==pcs and p['exit']==exit_pc]
    if len(matches)!=1:raise ValueError('L3_CONTROL_OBSERVED_PATH_INVALID')
    path=matches[0]
    if any(condition(c['kind'],value_of(c['left'],inputs),value_of(c['right'],inputs))!=c['taken'] for c in path['conditions']):
        raise ValueError('L3_CONTROL_OBSERVED_PREDICATE_MISMATCH')
    return path
