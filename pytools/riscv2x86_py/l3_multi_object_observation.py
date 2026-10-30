"""Actual typed multi-allocation calls and alias-coherent boundary observations.

Used only with a compiler/proof-bound joint spec. Per-invocation layouts are
explicit test inputs, not proofs that arbitrary incoming pointers are disjoint.
"""
import json
import re
from .l3_trace_support import identity,require_json_document,require_json_match
from .object_layout_contract import materialize,initial_objects,allocation_bytes,project_bytes


def strict_decoder():
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('L3_MULTI_DUPLICATE_JSON_KEY')
            result[key]=value
        return result
    def constant(value):raise ValueError('L3_MULTI_NONFINITE_JSON')
    return json.JSONDecoder(object_pairs_hook=pairs,parse_constant=constant)


def sample_plan(program,count):
    contract=program['objectLayout'];params=program['callSignature']['parameters'];pointers=program['pointerParameters']
    values=[0,1,(1<<64)-1,1<<63,(1<<63)-1,0x5a17d3e4c29b806f,0xc4ceb9fe1a85ec53,0xffffffff]
    rows=[]
    for sample in range(count):
        case=contract['layouts'][sample%len(contract['layouts'])]
        rows.append({'sample':sample,'layout':case,'arguments':[None if i in pointers else format(values[(sample+i)%len(values)],'016x') for i in range(len(params))],
            'initialObjects':initial_objects(case,contract['views'],sample)})
    body={'schemaVersion':'riscv2x86.joint-sample-plan.v2','specIdentity':program['specIdentity'],'inputs':rows,
        'layoutContractIdentity':contract['contractIdentity'],'layoutSampling':'round-robin-listed-inputs; not exhaustive-value-or-layout-proof'}
    return dict(body,planIdentity=identity(body))


def harness(program,plan,*,include_addresses=True):
    from .l3_joint_observation import sample_symbol
    name=program['functionName'];call=program['callSignature'];views=program['objectLayout']['views']
    if not re.fullmatch(r'[A-Za-z_]\w*',name):raise ValueError('L3_MULTI_FUNCTION_NAME')
    entry='__rv2x86_entry_'+program['specIdentity'].split(':')[1][:16]
    lines=['#include <stdint.h>','#include <stdio.h>','#include <string.h>','#include <inttypes.h>',
        'unsigned '+sample_symbol(program)+';',
        'extern '+call['result']['cType']+' '+entry+'('+','.join(p['cType'] for p in call['parameters'])+') __asm__('+json.dumps(name)+');',
        'int main(int argc,char **argv){if(argc!=2||strlen(argv[1])!=64)return 2;']
    by_param={v['parameterIndex']:v for v in views}
    for sample,row in enumerate(plan['inputs']):
        allocations,mapping=materialize(row['layout'],views);raw=allocation_bytes(row['layout'],views,row['initialObjects']);symbols={}
        lines.append('{')
        for index,(aid,a) in enumerate(allocations.items()):
            symbol='allocation'+str(index);symbols[aid]=symbol;cell=a['pointee']['widthBits']//8
            if a['size']%cell:raise ValueError('L3_MULTI_ALLOCATION_SIZE')
            lines.extend(['_Alignas(64) '+a['pointee']['cType']+' '+symbol+'['+str(a['size']//cell)+'];',
                'const unsigned char initial'+str(index)+'[]={'+','.join(str(v) for v in raw[aid])+'};',
                'memcpy('+symbol+',initial'+str(index)+',sizeof '+symbol+');'])
        args=[];expressions={}
        for i,p in enumerate(call['parameters']):
            if i in by_param:
                v=by_param[i];b=mapping[v['objectId']];cell=v['pointee']['widthBits']//8
                expression='('+symbols[b['allocationId']]+'+'+str(b['offset']//cell)+')'
                if b['offset']%cell:raise ValueError('L3_MULTI_VIEW_ALIGNMENT')
                expressions[v['objectId']]=expression;args.append(expression)
            else:args.append('('+p['cType']+')UINT64_C(0x'+row['arguments'][i]+')')
        invocation=entry+'('+','.join(args)+')'
        returned=invocation+';uint64_t returned=0;' if call['result']['kind']=='void' else 'uint64_t returned=(uint64_t)'+invocation+';'
        lines.append(sample_symbol(program)+'='+str(sample)+';'+returned)
        prefix={'sample':sample,'planIdentity':plan['planIdentity']}
        text='{'+','.join(json.dumps(k)+':'+json.dumps(v) for k,v in prefix.items())+','
        lines.append('printf('+json.dumps(text+'"token":"%s","value":"%016llx","objects":[')+',argv[1],(unsigned long long)returned);')
        for i,v in enumerate(views):
            expr=expressions[v['objectId']]
            # PRIxPTR is a C macro and must remain outside C string quoting.
            start=(',' if i else '')+'{"objectId":'+json.dumps(v['objectId'])+',"size":'+str(v['size'])+',"base":"'
            lines.append('printf('+json.dumps(start)+' "%" PRIxPTR '+json.dumps('","hex":"')+',(uintptr_t)'+(expr if include_addresses else '0')+');')
            lines.append('for(unsigned i=0;i<'+str(v['size'])+';i++){printf("%02x",((unsigned char *)'+expr+')[i]);}puts("\\\"}");')
        lines.extend(['puts("]}");','}'])
    return '\n'.join(lines+['return 0;}'])+'\n'


def parse_samples(text,token,program,plan):
    views=program['objectLayout']['views'];rows=[]
    decoder=strict_decoder();remaining=text
    while remaining.strip():
        remaining=remaining.lstrip();r,end=decoder.raw_decode(remaining);remaining=remaining[end:]
        require_json_document(r,'L3_MULTI_SAMPLE_JSON')
        sample=len(rows)
        if (not isinstance(r,dict) or set(r)!={'sample','planIdentity','token','value','objects'}
                or type(r['sample']) is not int or r['sample']!=sample or sample>=len(plan['inputs'])
                or r['token']!=token or r['planIdentity']!=plan['planIdentity']
                or not isinstance(r['value'],str) or re.fullmatch('[0-9a-f]{16}',r['value']) is None
                or not isinstance(r['objects'],list) or len(r['objects'])!=len(views)):
            raise ValueError('L3_MULTI_SAMPLE_BINDING')
        case=plan['inputs'][sample]['layout'];allocations,mapping=materialize(case,views);bases={};objects={}
        for v,obj in zip(views,r['objects']):
            if (not isinstance(obj,dict) or set(obj)!={'objectId','size','base','hex'} or obj['objectId']!=v['objectId']
                    or type(obj['size']) is not int or obj['size']!=v['size']
                    or not isinstance(obj['base'],str) or re.fullmatch('[0-9a-f]+',obj['base']) is None
                    or not isinstance(obj['hex'],str) or re.fullmatch('[0-9a-f]{'+str(v['size']*2)+'}',obj['hex']) is None):
                raise ValueError('L3_MULTI_OBJECT_BINDING')
            base=int(obj['base'],16);b=mapping[v['objectId']];aid=b['allocationId'];allocation_base=base-b['offset']
            if base<=0 or base%v['alignment'] or allocation_base<=0 or allocation_base%allocations[aid]['alignment']:
                raise ValueError('L3_MULTI_OBJECT_ALIGNMENT')
            if aid in bases and bases[aid]!=allocation_base:raise ValueError('L3_MULTI_ACTUAL_ALIAS_MISMATCH')
            bases[aid]=allocation_base;objects[v['objectId']]=obj['hex']
        pairs=list(bases)
        for i,a in enumerate(pairs):
            for b in pairs[i+1:]:
                if max(bases[a],bases[b])<min(bases[a]+allocations[a]['size'],bases[b]+allocations[b]['size']):
                    raise ValueError('L3_MULTI_ACTUAL_DISJOINT_MISMATCH')
        allocation_bytes(case,views,objects);rows.append(r)
    if len(rows)!=len(plan['inputs']):raise ValueError('L3_MULTI_SAMPLES_INCOMPLETE')
    return rows


def normalized(row):
    return {k:([{key:value for key,value in obj.items() if key!='base'} for obj in v] if k=='objects' else v) for k,v in row.items() if k!='token'}


def instrument(source,sites,program):
    from .l3_joint_observation import sample_symbol
    views=program['objectLayout']['views'];edits=[]
    for index,(site,member) in enumerate(zip(sites,program['members'])):
        end=site['end']
        if source[end:end+1]==b';':end+=1
        elif source[end-1:end]!=b';':raise ValueError('L2_MULTI_STATEMENT_END')
        for edge,pos in (('pre',site['begin']),('post',end)):
            ops=[o for o in member['operands'] if o['kind']=='integer' and o['access'] in ({'input','read_write'} if edge=='pre' else {'output','read_write'})]
            if any(re.fullmatch(r'[A-Za-z_]\w*',o['name']) is None for o in ops+views):raise ValueError('L2_MULTI_DECLARATION_NAME')
            fmt='J %u '+str(index)+' '+edge+' '+str(len(ops))+' '+','.join('%016llx' for _ in ops)+' '
            code='\nprintf('+json.dumps(fmt)+','+sample_symbol(program)+''.join(',(unsigned long long)'+o['name'] for o in ops)+');'
            for i,v in enumerate(views):
                if i:code+='putchar(58);'
                code+='for(unsigned __rv2x86_i=0;__rv2x86_i<'+str(v['size'])+';__rv2x86_i++){printf("%02x",((unsigned char *)'+v['name']+')[__rv2x86_i]);}'
            code+='puts("");\n';edits.append((pos,code.encode()))
    for _,(pos,code) in sorted(enumerate(edits),key=lambda x:(x[1][0],x[0]),reverse=True):source=source[:pos]+code+source[pos:]
    return ('#include <stdint.h>\n#include <stdio.h>\nextern unsigned '+sample_symbol(program)+';\n').encode()+source


def parse_l2(text,token,program,plan):
    from .l3_joint_observation import JointSemanticMismatch
    views=program['objectLayout']['views'];members=program['members'];boundaries=[];final=[]
    for line in text.splitlines():
        if line.startswith('J '):
            p=line.split();position=len(boundaries);sample=position//(2*len(members));index=(position//2)%len(members);edge='post' if position%2 else 'pre'
            if sample>=len(plan['inputs']) or len(p) not in (6,7):raise ValueError('L2_MULTI_TRACE_FORMAT')
            ops=[o for o in members[index]['operands'] if o['kind']=='integer' and o['access'] in ({'input','read_write'} if edge=='pre' else {'output','read_write'})]
            values=p[5].split(',') if ops else [];data=p[-1].split(':')
            if (p[1:5]!=[str(sample),str(index),edge,str(len(ops))] or len(values)!=len(ops)
                    or any(re.fullmatch('[0-9a-f]{16}',v) is None for v in values) or len(data)!=len(views)
                    or any(re.fullmatch('[0-9a-f]{'+str(v['size']*2)+'}',d) is None for v,d in zip(views,data))):raise ValueError('L2_MULTI_TRACE_BINDING')
            boundaries.append({'sample':sample,'region':index,'edge':edge,'values':values,'objects':{v['objectId']:d for v,d in zip(views,data)}})
        else:final.append(line)
    if len(boundaries)!=2*len(members)*len(plan['inputs']):raise ValueError('L2_MULTI_TRACE_INCOMPLETE')
    rows=parse_samples('\n'.join(final),token,program,plan)
    result={'boundaries':boundaries,'samples':[normalized(r) for r in rows]}
    def mismatch(code):raise JointSemanticMismatch(code,result)
    for sample,row in enumerate(rows):
        case=plan['inputs'][sample]['layout'];_,mapping=materialize(case,views);previous=plan['inputs'][sample]['initialObjects']
        values={p['declarationIdentity']:int(plan['inputs'][sample]['arguments'][i],16) for i,p in enumerate(program['callSignature']['parameters']) if i not in program['pointerParameters']}
        for index,member in enumerate(members):
            pre,post=boundaries[(sample*len(members)+index)*2:(sample*len(members)+index)*2+2]
            if pre['objects']!=previous:mismatch('L2_MULTI_OBJECT_CONTINUITY')
            before=allocation_bytes(case,views,pre['objects']);allocation_bytes(case,views,post['objects']);s=member['spec']
            inputs=[o for o in member['operands'] if o['kind']=='integer' and o['access'] in {'input','read_write'}]
            outputs=[o for o in member['operands'] if o['kind']=='integer' and o['access'] in {'output','read_write'}]
            if any(values.get(o['declarationIdentity'])!=int(v,16) for o,v in zip(inputs,pre['values'])):mismatch('L2_MULTI_DATAFLOW')
            if member.get('versionedProgramBoundary') is not None:
                from .versioned_program_contract import decode,evaluate
                expected=evaluate(decode(member['versionedProgramBoundary']['program']),{o['index']:int(v,16) for o,v in zip(inputs,pre['values'])})
                if {o['index']:int(v,16) for o,v in zip(outputs,post['values'])}!=expected:mismatch('L2_MULTI_VERSIONED_VALUE')
            if s['access'] in ('read','write'):
                b=mapping[s['objectId']];start=b['offset']+s['offset'];memory=before[b['allocationId']];facts=member['memoryFacts']
                if s['access']=='read':
                    value=int.from_bytes(memory[start:start+s['width']],'little',signed=facts.get('valueProjection')=='sign_extend')&((1<<64)-1)
                    i=next(i for i,o in enumerate(outputs) if o['index']==facts['valueOperandIndex'])
                    if int(post['values'][i],16)!=value:mismatch('L2_MULTI_LOAD_VALUE')
                else:
                    value=next(int(pre['values'][i],16) for i,o in enumerate(inputs) if o['index']==facts['valueOperandIndex'])
                    memory[start:start+s['width']]=(value&((1<<(8*s['width']))-1)).to_bytes(s['width'],'little')
            if project_bytes(case,views,before)!=post['objects']:mismatch('L2_MULTI_OBJECT_EFFECT')
            values.update({o['declarationIdentity']:int(v,16) for o,v in zip(outputs,post['values'])});previous=post['objects']
        if previous!={o['objectId']:o['hex'] for o in row['objects']}:mismatch('L2_MULTI_FINAL_OBJECT')
        if values.get(program['returnDeclarationIdentity'])!=int(row['value'],16):mismatch('L2_MULTI_RETURN_VALUE')
    return result


def compare(reports,program,index):
    views=program['objectLayout']['views'];member=program['members'][index];s=member['spec'];reasons=[];streams={}
    plan=sample_plan(program,len(reports['source']['samples']))
    for side,r in reports.items():
        events=r['events'];stream=[]
        for sample,row in enumerate(r['samples']):
            case=plan['inputs'][sample]['layout'];_,mapping=materialize(case,views)
            before=allocation_bytes(case,views,plan['inputs'][sample]['initialObjects']);after=allocation_bytes(case,views,{o['objectId']:o['hex'] for o in row['objects']})
            writes=set()
            for m in program['members']:
                a=m['spec']
                if a['access']=='write':
                    v=mapping[a['objectId']];writes.update((v['allocationId'],i) for i in range(v['offset']+a['offset'],v['offset']+a['offset']+a['width']))
            if any(value!=before[aid][i] and (aid,i) not in writes for aid,data in after.items() for i,value in enumerate(data)):reasons.append('L3_MULTI_UNAPPROVED_WRITE')
            actual=[e for e in events if e['sample']==sample]
            if member.get('fenceBasis') is not None:
                if len(actual)!=1 or actual[0].get('access')!='fence' or actual[0].get('completed') is not True or actual[0].get('machineMechanism',{}).get('kind')!='ordinary-rw-fence':reasons.append('L3_MULTI_FENCE_MECHANISM')
                expected=[i for i,m in enumerate(program['members']) if m['spec']['access']!='none' or m.get('fenceBasis') is not None]
                if [e['region'] for e in r.get('programEvents',[]) if e['sample']==sample]!=expected:reasons.append('L3_MULTI_FENCE_SEQUENCE')
            elif len(actual)!=(0 if s['access']=='none' else 1):reasons.append('L3_MULTI_EVENT_COUNT')
            else:
                for e in actual:
                    obj=next(o for o in row['objects'] if o['objectId']==s['objectId'])
                    relative={'offset':e['address']-int(obj['base'],16),'size':e['size'],'access':e['access']}
                    if relative!={'offset':s['offset'],'size':s['width'],'access':s['access']}:reasons.append('L3_MULTI_ACCESS_MISMATCH')
                    stream.append(relative)
        if any(type(e['sample']) is not int or not 0<=e['sample']<len(r['samples']) for e in events):reasons.append('L3_MULTI_EVENT_SAMPLE')
        streams[side]=stream
    if [normalized(r) for r in reports['source']['samples']]!=[normalized(r) for r in reports['target']['samples']]:reasons.append('L3_MULTI_VALUE_OR_OBJECT_MISMATCH')
    if streams['source']!=streams['target']:reasons.append('L3_MULTI_EVENT_RELATION')
    result={'status':'failed' if reasons else 'verified','reasonCodes':sorted(set(reasons))}
    if member.get('fenceBasis') is not None:
        result['synchronization']={'status':result['status'],'reasonCodes':result['reasonCodes'],'physicalMemoryOrderMeasured':False,'concurrentAtomicityMeasured':False,
            'subpropertyResults':{p:{'status':result['status'],'verificationMethod':method} for p,method in (
                ('sync.compiler-contract','static-approved-contract'),
                ('sync.fence-mechanism','actual-single-instruction-region-entry-and-completion'),
                ('sync.ordering-contract','approved-ordering-and-same-invocation-access-sequence'))}}
    return result
