"""L1 typed layouts reuse actual invocation construction, not L2/L3 verdicts."""
import json
from .l3_trace_support import identity
from .object_layout_contract import build
from .l3_multi_object_observation import sample_plan,harness


def wrapper(functions):
    chunks=[];calls=[]
    for index,function in enumerate(functions):
        if not function.get('pointerParameters'):
            from .automatic_validation import _memory_object_wrapper
            source=_memory_object_wrapper([function])
        else:
            layout=build(function)
            program={'functionName':function['name'],'specIdentity':identity({'function':function['functionId'],'L1':'typed-layout-v1'}),
                'callSignature':function['compilerMemoryCallSignature'],'objectLayout':layout,'pointerParameters':function['pointerParameters']}
            source=harness(program,sample_plan(program,8),include_addresses=False)
        name='__rv2x86_l1_run_'+str(index)
        source=source.replace('int main(', 'static int '+name+'(',1).replace('dump_object','dump_object_'+str(index))
        chunks.append(source)
        calls.append('if('+name+('(2,args)' if function.get('pointerParameters') else '()')+'){return 2;}\n')
    return '\n'.join(chunks)+'\nint main(void){char *args[]={"l1","'+('a'*64)+'"};\n'+''.join(calls)+'return 0;}\n'


def observations(stdout):
    from .l3_multi_object_observation import strict_decoder
    decoder=strict_decoder();position=0;result=[]
    while True:
        start=stdout.find('{',position)
        if start<0:break
        try:row,end=decoder.raw_decode(stdout[start:])
        except ValueError as exc:raise ValueError('L1_MULTI_OBJECT_OUTPUT_INVALID') from exc
        if not isinstance(row,dict) or not isinstance(row.get('objects'),list):raise ValueError('L1_MULTI_OBJECT_OUTPUT_INVALID')
        for obj in row['objects']:
            if not isinstance(obj,dict) or set(obj)!={'objectId','size','base','hex'}:raise ValueError('L1_MULTI_OBJECT_OUTPUT_INVALID')
            data=bytes.fromhex(obj['hex'])
            if len(data)!=obj['size']:raise ValueError('L1_MULTI_OBJECT_SIZE')
            result.append({'objectId':obj['objectId'],'order':len(result),'values':[data.hex()]})
        position=start+end
    return result
