"""Every attempt is retained; branch paths, not callback absence, label outcomes."""
from .l3_lrsc_machine import attempts
from .l3_lrsc_backend import memory_by_step,callback_shape


def observe(machine,backend,observed,sample,step_offset,row,atom,object_bytes):
    path=observed['paths'][sample];count=attempts(machine,path);r=machine['retry'];groups=memory_by_step(observed)
    source=machine['machine']==243;base=int(row['objectBase'],16);valid=base>0 and base%atom['alignment_bytes']==0
    bits=sum(int(machine['sequence'][name][flag])<<i for i,(name,flag) in enumerate((('lrOrderingBits','aq'),('lrOrderingBits','rl'),('scOrderingBits','aq'),('scOrderingBits','rl')))) if source else 0
    at=r['scPC'] if source else r['casPC'];initial={x['pc']:x for x in r.get('initialMemory',[])};stack={x['pc']:x for x in r.get('loopMemory',[])}
    actual=[];internal=[];records=[];frame=None
    for local,pc in enumerate(path['pcs']):
        events=groups.get(step_offset+local,[]);role='none';width=atom['width_bits']//8
        if source and pc==r['lrPC']:kinds=['read'];role='lr'
        elif pc==at:
            number=(local-len(r['prefixPCs']))//len(r['loopPCs']);outcome='success' if number==count-1 else 'failure'
            kinds=callback_shape(backend,'source' if source else 'target',atom['width_bits'],bits,outcome);role='sc' if source else 'cas'
            records.append({'attempt':number,'outcome':outcome,'pc':pc,'rawCallbackKinds':[e['access'] for e in events],
                'outcomeSource':'proved-failure-backedge-and-actual-complete-PC-path',
                'failedStatusValueObserved':False,'callbackObserved':bool(events)})
        elif pc in initial:kinds=['read'];role='initial-load'
        elif pc in stack:kinds=['read'];role='compiler-input-stack';width=stack[pc]['widthBytes']
        else:kinds=[]
        if [e['access'] for e in events]!=kinds:valid=False
        for e in events:
            if e['pc']!=pc or e['sample']!=sample or e['size']!=width:valid=False
            access={'offsetBytes':e['address']-base,'widthBytes':e['size'],'access':e['access']}
            if role=='compiler-input-stack':
                candidate=e['address']-stack[pc]['stackOffset']
                if frame is None:frame=candidate
                if frame!=candidate or not(e['address']+e['size']<=base or e['address']>=base+object_bytes):valid=False
                internal.append(dict(access,role=role,pc=pc))
            else:
                if e['address']!=base:valid=False
                actual.append(access)
    if len(records)!=count:raise ValueError('L3_LRSC_ATTEMPT_ATTRIBUTION_INCOMPLETE')
    return {'bound':valid,'objectAccesses':actual,'internalAccesses':internal,'attempts':records,'attemptCount':count,
        'abstractSuccessfulRmwCount':1,'physicalMemoryOrderMeasured':False}
