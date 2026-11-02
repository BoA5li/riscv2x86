"""Compact typed call harness: same finite plan, exact-size typed VLAs per call.

No byte-buffer type punning, sample removal or allocation-capacity enlargement.
Tables carry only compiler/spec-bound layout inputs. Observations remain real.
"""
import json
import re
from .object_layout_contract import materialize,allocation_bytes


def generate(program,plan,*,include_addresses=True):
    from .l3_joint_observation import sample_symbol
    name=program['functionName'];call=program['callSignature'];views=program['objectLayout']['views'];rows=plan['inputs']
    if not re.fullmatch(r'[A-Za-z_]\w*',name):raise ValueError('L3_MULTI_FUNCTION_NAME')
    n=len(rows);v=len(views);parameters=call['parameters']
    counts=[];owners=[];offsets=[];initial=[];max_bytes=1
    for row in rows:
        allocations,mapping=materialize(row['layout'],views)
        raw=allocation_bytes(row['layout'],views,row['initialObjects']);by_allocation={}
        for i,view in enumerate(views):by_allocation.setdefault(mapping[view['objectId']]['allocationId'],i)
        count=[1]*v;owner=[];offset=[];data=[[] for _ in views]
        for aid,i in by_allocation.items():
            a=allocations[aid];cell=views[i]['pointee']['widthBits']//8
            if a['pointee']!=views[i]['pointee'] or a['size']%cell:raise ValueError('L3_MULTI_ALLOCATION_SIZE')
            count[i]=a['size']//cell;data[i]=list(raw[aid]);max_bytes=max(max_bytes,a['size'])
        for view in views:
            binding=mapping[view['objectId']];i=by_allocation[binding['allocationId']];cell=view['pointee']['widthBits']//8
            if view['pointee']!=views[i]['pointee'] or binding['offset']%cell:raise ValueError('L3_MULTI_VIEW_ALIGNMENT')
            owner.append(i);offset.append(binding['offset']//cell)
        counts.append(count);owners.append(owner);offsets.append(offset);initial.append(data)
    def initializer(value):
        if isinstance(value,list):return '{'+','.join(initializer(x) for x in value)+'}'
        return str(value)
    entry='__rv2x86_entry_'+program['specIdentity'].split(':')[1][:16]
    lines=['#include <stdint.h>','#include <stdio.h>','#include <string.h>','#include <inttypes.h>',
        'unsigned '+sample_symbol(program)+';',
        'extern '+call['result']['cType']+' '+entry+'('+','.join(p['cType'] for p in parameters)+') __asm__('+json.dumps(name)+');']
    for key,data in (('counts',counts),('owners',owners),('offsets',offsets)):
        lines.append('static const unsigned '+key+'['+str(n)+']['+str(v)+']='+initializer(data)+';')
    # Empty owners have a one-element unused typed object, initialized to zero.
    initial=[[data if data else [0] for data in sample] for sample in initial]
    lines.append('static const unsigned char initial['+str(n)+']['+str(v)+']['+str(max_bytes)+']='+initializer(initial)+';')
    by_param={view['parameterIndex']:i for i,view in enumerate(views)}
    if any(i not in by_param for i in range(len(parameters))):
        arguments=[[('UINT64_C(0x'+value+')') if value is not None else '0' for value in row['arguments']] for row in rows]
        lines.append('static const uint64_t arguments['+str(n)+']['+str(len(parameters))+']={'+','.join('{'+','.join(row)+'}' for row in arguments)+'};')
    lines.extend(['int main(int argc,char **argv){if(argc!=2||strlen(argv[1])!=64)return 2;',
        'for(unsigned sample=0;sample<'+str(n)+';sample++){'])
    for i,view in enumerate(views):
        typ=view['pointee']['cType'];symbol='allocation'+str(i)
        lines.extend(['_Alignas(64) '+typ+' '+symbol+'[counts[sample]['+str(i)+']];',
            'memcpy('+symbol+',initial[sample]['+str(i)+'],sizeof '+symbol+');'])
    for i,view in enumerate(views):
        lines.append(view['pointee']['cType']+' *view'+str(i)+';switch(owners[sample]['+str(i)+']){')
        for j,other in enumerate(views):
            if other['pointee']==view['pointee']:
                lines.append('case '+str(j)+':view'+str(i)+'=allocation'+str(j)+'+offsets[sample]['+str(i)+'];break;')
        lines.append('default:return 3;}')
    args=['view'+str(by_param[i]) if i in by_param else '('+p['cType']+')arguments[sample]['+str(i)+']' for i,p in enumerate(parameters)]
    invocation=entry+'('+','.join(args)+')'
    returned=invocation+';uint64_t returned=0;' if call['result']['kind']=='void' else 'uint64_t returned=(uint64_t)'+invocation+';'
    lines.append(sample_symbol(program)+'=sample;'+returned)
    prefix='{"sample":%u,"planIdentity":'+json.dumps(plan['planIdentity'])+',"token":"%s","value":"%016llx","objects":['
    lines.append('printf('+json.dumps(prefix)+',sample,argv[1],(unsigned long long)returned);')
    for i,view in enumerate(views):
        expression='view'+str(i);start=(',' if i else '')+'{"objectId":'+json.dumps(view['objectId'])+',"size":'+str(view['size'])+',"base":"'
        lines.append('printf('+json.dumps(start)+' "%" PRIxPTR '+json.dumps('","hex":"')+',(uintptr_t)'+(expression if include_addresses else '0')+');')
        lines.append('for(unsigned i=0;i<'+str(view['size'])+';i++){printf("%02x",((unsigned char *)'+expression+')[i]);}puts("\\\"}");')
    return '\n'.join(lines+['puts("]}");','}','return 0;}'])+'\n'
