"""Attribute every CAS-region callback to a proved instruction occurrence.

Compiler input-stack reads remain explicit internal observations, never counted
as source object effects. Failed attempts are retained and are not invented
successful writes. Outcome labels follow the proved failure backedge and actual
PC path, not a nonexistent runtime-register/value callback.
"""
from .l3_atomic_backend import callback_shape, memory_by_step
from .l3_atomic_retry import attempts


def observe(machine, backend, observed, sample, step_offset, row, atom, object_bytes):
    path=observed['paths'][sample];count=attempts(machine,path);retry=machine['retry']
    groups=memory_by_step(observed);prefix=retry['prefixPCs'];loop=retry['loopPCs']
    initial={r['pc']:r for r in retry['initialMemory']};stack={r['pc']:r for r in retry['loopMemory']}
    base=int(row['objectBase'],16);valid=base>0 and base%atom['alignment_bytes']==0
    actual=[];internal=[];trace_attempts=[];frame=None
    for local_step,pc in enumerate(path['pcs']):
        events=groups.get(step_offset+local_step,[])
        if pc in initial:
            descriptor=initial[pc];kinds=['read'];role='object-load'
        elif pc in stack:
            descriptor=stack[pc];kinds=['read'];role='compiler-input-stack'
        elif pc==retry['casPC']:
            number=(local_step-len(prefix))//len(loop)
            outcome='success' if number==count-1 else 'failure'
            kinds=callback_shape(backend,'target',machine['instruction'],outcome)
            descriptor={'widthBytes':machine['instruction']['width']//8};role='cas-'+outcome
            trace_attempts.append({'attempt':number,'outcome':outcome,'pc':pc,
                                   'rawCallbackKinds':[e['access'] for e in events],
                                   'outcomeSource':'proved-machine-branch-and-actual-PC-path',
                                   'objectOperandEvidence':'symbolic-stable-address-and-observed-successful-object-access',
                                   'callbackObserved':bool(events)})
        else:
            if events:valid=False
            descriptor={'widthBytes':0};kinds=[];role='unexpected'
        if [e['access'] for e in events]!=kinds:valid=False
        for event in events:
            if event['sample']!=sample or event['pc']!=pc or event['size']!=descriptor['widthBytes']:valid=False
            access={'offsetBytes':event['address']-base,'widthBytes':event['size'],'access':event['access']}
            if role=='compiler-input-stack':
                candidate=event['address']-descriptor['stackOffset']
                if frame is None:frame=candidate
                if frame!=candidate or not (event['address']+event['size']<=base or event['address']>=base+object_bytes):valid=False
                internal.append(dict(access,pc=pc,role=role,stackOffset=descriptor['stackOffset']))
            else:
                if event['address']!=base or event['size']!=atom['width_bits']//8:valid=False
                actual.append(access)
    return {'bound':valid,'objectAccesses':actual,'internalAccesses':internal,
            'attempts':trace_attempts,'attemptCount':count,
            'abstractSuccessfulRmwCount':1,'physicalMemoryOrderMeasured':False}
