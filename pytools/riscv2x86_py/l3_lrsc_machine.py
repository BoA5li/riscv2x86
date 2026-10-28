"""Final-ELF sequence recognition with ABI/object dataflow, not text matching."""
from copy import deepcopy
from .l3_trace_support import identity
from . import l3_atomic_retry as x
from . import l3_control_machine as rv
from .lrsc_sequence import candidate


def low(v,w):
    if isinstance(v,tuple):
        if v[0]=='low':return low(v[2],min(w,v[1]))
        if v[0]=='sign32' and w<=32:return low(v[1],w)
        if v[0] in ('add','and','or','xor'):return expression(v[0],v[2],v[3],min(w,v[1]))
    return x.low(v,w)


def expression(op,a,b,w):
    return (op,w,*sorted((low(a,w),low(b,w)),key=repr))


def target_step(s,row,*,region=False,roles=None):
    if region and row['op'] in ('add','and','or','xor') and 'base' in row['source']:
        if x.address(s,row['source'])[0]!='stack' or x.get(s,row['source'],row['width'])!=x.low(s['input'],row['width']):
            raise ValueError('L3_LRSC_LOOP_INPUT_MEMORY_UNBOUND')
        if roles is not None:roles.append({'pc':row['pc'],'stackOffset':x.address(s,row['source'])[1],'widthBytes':row['width']//8})
    if row['op']=='add':
        if 'register' not in row['destination']:raise ValueError('L3_LRSC_TARGET_EXTRA_STORE')
        v=expression('add',x.get(s,row['destination'],row['width']),x.get(s,row['source'],row['width']),row['width'])
        x.put(s,row['destination'],v,row['width']);s['zero']=None
    elif row['op'] in ('and','or','xor'):
        v=expression(row['op'],x.get(s,row['destination'],row['width']),x.get(s,row['source'],row['width']),row['width'])
        if 'register' not in row['destination']:raise ValueError('L3_LRSC_TARGET_EXTRA_STORE')
        x.put(s,row['destination'],v,row['width']);s['zero']=None
    else:x.step(s,row,region=region,roles=roles)


def target(code,base,spec):
    rows=x.decode(code,base);cas=[r for r in rows if r['op']=='cas'];branches=[r for r in rows if r['op']=='branch']
    if len(cas)!=1 or len(branches)!=1:raise ValueError('L3_LRSC_TARGET_SINGLE_LOOP_REQUIRED')
    c,b=cas[0],branches[0];pcs=[r['pc'] for r in rows];w=spec['operation']['width_bits']
    if not c['locked'] or c['width']!=w or b['target'] not in pcs or not base<b['target']<=c['pc']<b['pc']:
        raise ValueError('L3_LRSC_TARGET_LOCK_OR_BACKEDGE_INVALID')
    li=pcs.index(b['target']);bi=pcs.index(b['pc']);s=x.state(spec['pointerParameter'],spec['valueParameter']);loads=[]
    for i,r in enumerate(rows[:li]):
        if r['op']=='move' and 'base' in r['source'] and x.address(s,r['source'])==('object',0):
            if loads or r['destination']!={'register':0} or r['width']!=w:raise ValueError('L3_LRSC_TARGET_INITIAL_LOAD')
            loads.append(i);x.write_register(s,0,('old',0,w),w)
        else:target_step(s,r,region=bool(loads))
    if len(loads)!=1:raise ValueError('L3_LRSC_TARGET_LOAD_REQUIRED')
    roles=None
    for epoch in (0,1):
        old=('old',epoch,w);x.write_register(s,0,old,w);current=[]
        for r in rows[li:bi]:
            if r['op']=='cas':
                if x.address(s,r['address'])!=('object',0):raise ValueError('L3_LRSC_CAS_OBJECT')
                expected=low(x.read_register(s,0,w),w);wanted=expression(spec['operation']['rmw_operation'][6:],old,s['input'],w)
                if expected!=old or low(x.read_register(s,r['desired'],w),w)!=wanted:raise ValueError('L3_LRSC_CAS_RECOMPUTATION')
                s['zero']=('cas-success',)
            else:target_step(s,r,region=True,roles=current)
        predicate=s['zero'] if b['equal'] else x.invert(s['zero']) if s['zero'] is not None else None
        if predicate!=('not',('cas-success',)):raise ValueError('L3_LRSC_CAS_FAILURE_BRANCH')
        if roles is not None and roles!=current:raise ValueError('L3_LRSC_CAS_LOOP_MEMORY_CHANGED')
        roles=current;success=deepcopy(s)
    tail=rows[bi+1:]
    if not tail or tail[-1]['op']!='return' or any(r['op']=='return' for r in rows[:-1]):raise ValueError('L3_LRSC_TARGET_RETURN')
    for r in tail[:-1]:target_step(success,r)
    wanted=('old',1,w)
    if w==32:wanted=('sign32',low(wanted,32))
    if x.read_register(success,0,64)!=wanted or success['registers'].get(4)!=('stack',0):raise ValueError('L3_LRSC_TARGET_RETURN_VALUE_OR_STACK')
    start=rows[loads[0]]['pc'];end=b['pc']+b['size']
    body={'machine':62,'instruction':{'operation':spec['operation']['rmw_operation'],'width':w,'mechanism':'x86-locked-cas-loop','ordering':'ordinary-memory-full-order'},
          'functionBytes':bytes(code).hex(),'instructions':rows,'region':{'start':start,'end':end,'exits':[end]},
          'retry':{'prefixPCs':pcs[loads[0]:li],'loopPCs':pcs[li:bi+1],'casPC':c['pc'],
                   'initialMemory':[{'pc':start,'widthBytes':w//8}], 'loopMemory':roles,'maximumAttempts':min(64,(128-(li-loads[0]))//(bi-li+1))}}
    return dict(body,mechanismIdentity=identity(body))


def _rv_rows(code,base):
    rows=[];offset=0
    while offset<len(code):
        raw=code[offset:];size=2 if raw[0]&3!=3 else 4
        if len(raw)<size:raise ValueError('L3_LRSC_RV_TRUNCATED')
        if raw[:size] in (bytes.fromhex('8280'),bytes.fromhex('67800000')):
            r={'op':'return','pc':base+offset,'size':size,'bytes':raw[:size].hex()}
        else:r=rv.decode(raw[:size],base+offset,243)[0]
        rows.append(r);offset+=size
    return rows


def source(code,base,spec):
    candidates=[]
    for off in range(0,len(code),2):
        for n in (14,16):
            try:seq=candidate(bytes(code[off:off+n]),base_address=base+off)
            except ValueError:continue
            candidates.append((off,n,seq))
    if len(candidates)!=1:raise ValueError('L3_LRSC_SOURCE_SINGLE_SEQUENCE_REQUIRED')
    off,n,q=candidates[0];seq=spec['sourceSequence'];w=q['memoryWidthBits']
    if (w!=seq['memory_width_bits'] or q['arithmeticWidthBits']!=seq['arithmetic_width_bits'] or q['operation']!=seq['operation']
        or tuple(q['lrOrderingBits'][k] for k in ('aq','rl'))!=tuple(seq['lr_ordering_bits'])
        or tuple(q['scOrderingBits'][k] for k in ('aq','rl'))!=tuple(seq['sc_ordering_bits'])):
        raise ValueError('L3_LRSC_SOURCE_SEQUENCE_CONTRACT_MISMATCH')
    prefix=_rv_rows(code[:off],base);tail=_rv_rows(code[off+n:],base+off+n)
    if not tail or tail[-1]['op']!='return' or any(r['op']=='return' for r in prefix+tail[:-1]):raise ValueError('L3_LRSC_SOURCE_RETURN_REQUIRED')
    s=rv.initial(243)
    for r in prefix:rv.step(s,r,243)
    if (s['registers'].get(q['addressRegister'])!='parameter:'+str(spec['pointerParameter'])
        or s['registers'].get(q['inputRegister'])!='parameter:'+str(spec['valueParameter'])):
        raise ValueError('L3_LRSC_SOURCE_PARAMETER_BINDING')
    old='source-old:'+str(w);s['registers'][q['oldRegister']]=old
    s['registers'][q['nextRegister']]=('source-next',);s['registers'][q['statusRegister']]=0
    for r in tail[:-1]:rv.step(s,r,243)
    if s['registers'].get(10)!=old or s['registers'].get(2)!=('stack',0):raise ValueError('L3_LRSC_SOURCE_RETURN_OR_STACK')
    pcs=q['instructionAddresses'];end=base+off+n
    body={'machine':243,'instruction':{'operation':q['operation'],'width':w,'mechanism':'rv-lrsc-loop','ordering':'approved-lrsc-bits'},
          'functionBytes':bytes(code).hex(),'sequence':q,'prefix':prefix,'suffix':tail,
          'region':{'start':base+off,'end':end,'exits':[end]},
          'retry':{'prefixPCs':[],'loopPCs':pcs,'lrPC':pcs[0],'scPC':pcs[2],'maximumAttempts':32}}
    return dict(body,mechanismIdentity=identity(body))


def function_mechanism(elf,name,spec):
    return (source if elf.machine==243 else target if elf.machine==62 else invalid)(elf.code(name),elf.symbol(name)[0],spec)


def invalid(*args):raise ValueError('L3_LRSC_ELF_MACHINE_UNSUPPORTED')


def attempts(machine,path):
    r=machine['retry'];p=r['prefixPCs'];loop=r['loopPCs'];pcs=path['pcs']
    if path['exit']!=machine['region']['end'] or pcs[:len(p)]!=p:raise ValueError('L3_LRSC_PATH_INCOMPLETE')
    remaining=pcs[len(p):]
    if not loop or not remaining or len(remaining)%len(loop):raise ValueError('L3_LRSC_PATH_INCOMPLETE')
    count=len(remaining)//len(loop)
    if count>r['maximumAttempts'] or remaining!=loop*count:raise ValueError('L3_LRSC_PATH_INVALID')
    return count
