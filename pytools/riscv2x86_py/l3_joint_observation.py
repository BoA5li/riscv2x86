"""Typed whole-call objects/returns and separate instrumented L2 boundaries."""
import json
import re
from .l3_trace_support import require_json_document


def sample_symbol(program):return '__rv2x86_joint_sample_'+program['specIdentity'].split(':')[1][:16]


def harness(program,plan):
    call=program['callSignature'];params=call['parameters'];pointer=program['pointerParameter'];size=program['object']['size']
    if size%8:raise ValueError('L3_JOINT_TYPED_OBJECT_SIZE')
    name=program['functionName']
    if not re.fullmatch(r'[A-Za-z_]\w*',name):raise ValueError('L3_JOINT_FUNCTION_NAME')
    arguments=['object' if i==pointer else '('+p['cType']+')args[sample]['+str(i)+']' for i,p in enumerate(params)]
    args=','.join('{'+','.join('UINT64_C(0x'+(v or '0')+')' for v in row['arguments'])+'}' for row in plan['inputs'])
    initial=','.join('{'+','.join(str(v) for v in bytes.fromhex(row['initialObjectHex']))+'}' for row in plan['inputs'])
    return '''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
unsigned %(symbol)s;
extern %(result)s %(name)s(%(parameters)s);
int main(int argc,char **argv){
 if(argc!=2 || strlen(argv[1])!=64)return 2;
 static const uint64_t args[%(count)d][%(arity)d]={%(args)s};
 static const unsigned char initial[%(count)d][%(size)d]={%(initial)s};
 for(unsigned sample=0;sample<%(count)d;sample++){
  _Alignas(64) %(pointee)s object[%(cells)d];
  memcpy(object,initial[sample],sizeof object);%(symbol)s=sample;
  uint64_t returned=(uint64_t)%(name)s(%(arguments)s);
  printf("{\\"token\\":\\"%%s\\",\\"sample\\":%%u,\\"planIdentity\\":\\"%(plan)s\\",\\"objectBase\\":\\"%%" PRIxPTR "\\",\\"objectSize\\":%%zu,\\"value\\":\\"%%016" PRIx64 "\\",\\"objectHex\\":\\"",argv[1],sample,(uintptr_t)object,sizeof object,returned);
  for(unsigned i=0;i<sizeof object;i++)printf("%%02x",((unsigned char *)object)[i]);
  puts("\\"}");
 }
 return 0;
}
''' % dict(symbol=sample_symbol(program),result=call['result']['cType'],name=name,
    parameters=','.join(p['cType'] for p in params),count=len(plan['inputs']),arity=len(params),args=args,
    initial=initial,size=size,pointee=params[pointer]['pointee']['cType'],cells=size//8,arguments=','.join(arguments),plan=plan['planIdentity'])


def parse_samples(text,token,program,plan):
    rows=[];size=program['object']['size']
    for line in text.splitlines():
        row=json.loads(line);require_json_document(row,'L3_JOINT_SAMPLE_JSON_INVALID')
        if (not isinstance(row,dict) or set(row)!={'token','sample','planIdentity','objectBase','objectSize','value','objectHex'}
                or row['token']!=token or type(row['sample']) is not int or row['sample']!=len(rows) or len(rows)>=len(plan['inputs'])
                or row['planIdentity']!=plan['planIdentity'] or type(row['objectSize']) is not int or row['objectSize']!=size
                or not isinstance(row['objectBase'],str) or re.fullmatch('[0-9a-f]+',row['objectBase']) is None
                or int(row['objectBase'],16)<=0 or int(row['objectBase'],16)%program['object']['alignment']
                or not isinstance(row['value'],str) or re.fullmatch('[0-9a-f]{16}',row['value']) is None
                or not isinstance(row['objectHex'],str) or re.fullmatch('[0-9a-f]{'+str(size*2)+'}',row['objectHex']) is None):
            raise ValueError('L3_JOINT_SAMPLE_BINDING_INVALID')
        rows.append(row)
    if len(rows)!=len(plan['inputs']):raise ValueError('L3_JOINT_SAMPLES_INCOMPLETE')
    return rows


def compare(reports,program,index):
    reasons=[];member=program['members'][index];s=member['spec'];streams={}
    from .l3_joint_spec import sample_plan
    plan=sample_plan(program,len(reports['source']['samples']))
    writes={i for m in program['members'] if m['spec']['access']=='write' for i in range(m['spec']['offset'],m['spec']['offset']+m['spec']['width'])}
    for side,r in reports.items():
        rows=r['samples'];events=r['events'];stream=[]
        for row,initial in zip(rows,plan['inputs']):
            data=bytes.fromhex(row['objectHex']);before=bytes.fromhex(initial['initialObjectHex'])
            if any(data[i]!=before[i] for i in range(len(before)) if i not in writes):reasons.append('L3_JOINT_UNAPPROVED_OBJECT_WRITE')
        for sample,row in enumerate(rows):
            actual=[e for e in events if e['sample']==sample]
            if len(actual)!=(0 if s['access']=='none' else 1):reasons.append('L3_JOINT_REGION_EVENT_COUNT_MISMATCH');continue
            for e in actual:
                relative={'offset':e['address']-int(row['objectBase'],16),'size':e['size'],'access':e['access']}
                if relative!={'offset':s['offset'],'size':s['width'],'access':s['access']}:reasons.append('L3_JOINT_REGION_ACCESS_MISMATCH')
                stream.append(relative)
        if any(type(e['sample']) is not int or not 0<=e['sample']<len(rows) for e in events):reasons.append('L3_JOINT_SAMPLE_EVENT_UNBOUND')
        streams[side]=stream
    normalized=lambda side:[{k:v for k,v in row.items() if k not in {'token','objectBase'}} for row in reports[side]['samples']]
    if normalized('source')!=normalized('target'):reasons.append('L3_JOINT_FUNCTION_VALUE_OR_OBJECT_MISMATCH')
    if streams['source']!=streams['target']:reasons.append('L3_JOINT_EVENT_RELATION_MISMATCH')
    reasons=sorted(set(reasons))
    return {'status':'failed' if reasons else 'verified','reasonCodes':reasons}


def instrument(source,sites,program):
    """L2 test variant only. L3 always executes the exact original function code."""
    size=program['object']['size'];call=program['callSignature'];pointer=program['pointerParameter']
    # The address operand declaration was compiler-bound to this parameter.
    base=next(o['name'] for m in program['members'] for o in m['operands'] if o['kind']=='pointer')
    if not re.fullmatch(r'[A-Za-z_]\w*',base):raise ValueError('L2_JOINT_DECLARATION_NAME_INVALID')
    edits=[]
    for index,(site,member) in enumerate(zip(sites,program['members'])):
        begin,end=site['begin'],site['end']
        if source[end:end+1]==b';':end+=1
        elif source[end-1:end]!=b';':raise ValueError('L2_JOINT_STATEMENT_END_REQUIRED')
        for edge,position in (('pre',begin),('post',end)):
            operands=[o for o in member['operands'] if o['kind']=='integer' and o['access'] in
                      ({'input','read_write'} if edge=='pre' else {'output','read_write'})]
            if any(not re.fullmatch(r'[A-Za-z_]\w*',o['name']) for o in operands):raise ValueError('L2_JOINT_DECLARATION_NAME_INVALID')
            formats=','.join('%016llx' for _ in operands)
            # A whitespace token stream makes unambiguous strict parsing easy.
            fmt='J %u '+str(index)+' '+edge+' '+str(len(operands))+' '+formats+' '
            code='\nprintf('+json.dumps(fmt)+','+sample_symbol(program)+''.join(',(unsigned long long)'+o['name'] for o in operands)+');'
            code+='for(unsigned __rv2x86_i=0;__rv2x86_i<'+str(size)+';__rv2x86_i++)printf("%02x",((unsigned char *)'+base+')[__rv2x86_i]);puts("");\n'
            edits.append((position,code.encode()))
    for _,(pos,data) in sorted(enumerate(edits),key=lambda x:(x[1][0],x[0]),reverse=True):source=source[:pos]+data+source[pos:]
    return ('#include <stdint.h>\n#include <stdio.h>\nextern unsigned '+sample_symbol(program)+';\n').encode()+source


class JointSemanticMismatch(ValueError):
    def __init__(self,reason,observation):
        super().__init__(reason);self.observation=observation


def parse_l2(text,token,program,plan):
    boundary=[];final=[];members=program['members'];size=program['object']['size']
    for line in text.splitlines():
        if line.startswith('{'):final.append(line);continue
        p=line.split()
        sample=(len(boundary)//(2*len(members)));index=(len(boundary)//2)%len(members);edge='post' if len(boundary)%2 else 'pre'
        if sample>=len(plan['inputs']) or len(p) not in {6,7} or p[:1]!=['J']:raise ValueError('L2_JOINT_TRACE_INCOMPLETE')
        ops=[o for o in members[index]['operands'] if o['kind']=='integer' and o['access'] in ({'input','read_write'} if edge=='pre' else {'output','read_write'})]
        expected=[str(sample),str(index),edge,str(len(ops))]
        if p[1:5]!=expected:raise ValueError('L2_JOINT_TRACE_ORDER_INVALID')
        values=p[5].split(',') if ops else []
        data=p[-1]
        if (len(values)!=len(ops) or any(re.fullmatch('[0-9a-f]{16}',v) is None for v in values)
                or re.fullmatch('[0-9a-f]{'+str(size*2)+'}',data) is None):raise ValueError('L2_JOINT_TRACE_VALUE_INVALID')
        boundary.append({'sample':sample,'region':index,'edge':edge,'values':values,'objectHex':data})
    if len(boundary)!=2*len(members)*len(plan['inputs']):raise ValueError('L2_JOINT_TRACE_INCOMPLETE')
    rows=parse_samples('\n'.join(final),token,program,plan)
    observation={'boundaries':boundary,'samples':[{k:v for k,v in r.items() if k not in {'token','objectBase'}} for r in rows]}
    def mismatch(reason):raise JointSemanticMismatch(reason,observation)
    for sample,row in enumerate(rows):
        previous=plan['inputs'][sample]['initialObjectHex']
        values={p['declarationIdentity']:int(plan['inputs'][sample]['arguments'][i],16) for i,p in enumerate(program['callSignature']['parameters']) if i!=program['pointerParameter']}
        for index,member in enumerate(members):
            pre,post=boundary[(sample*len(members)+index)*2:(sample*len(members)+index)*2+2]
            if pre['objectHex']!=previous:mismatch('L2_JOINT_OBJECT_CONTINUITY_MISMATCH')
            before=bytes.fromhex(pre['objectHex']);after=bytes.fromhex(post['objectHex']);s=member['spec']
            inputs=[o for o in member['operands'] if o['kind']=='integer' and o['access'] in {'input','read_write'}]
            outputs=[o for o in member['operands'] if o['kind']=='integer' and o['access'] in {'output','read_write'}]
            if any(values.get(o['declarationIdentity'])!=int(v,16) for o,v in zip(inputs,pre['values'])):mismatch('L2_JOINT_DATAFLOW_MISMATCH')
            values.update({o['declarationIdentity']:int(v,16) for o,v in zip(outputs,post['values'])})
            if s['access'] in {'none','read'} and before!=after:mismatch('L2_JOINT_UNAPPROVED_WRITE')
            if s['access']=='read':
                output=next(i for i,o in enumerate([o for o in member['operands'] if o['kind']=='integer' and o['access'] in {'output','read_write'}]) if o['index']==member['memoryFacts']['valueOperandIndex'])
                if int(post['values'][output],16)!=int.from_bytes(before[s['offset']:s['offset']+8],'little'):mismatch('L2_JOINT_LOAD_VALUE_MISMATCH')
            if s['access']=='write':
                input_ops=[o for o in member['operands'] if o['kind']=='integer' and o['access'] in {'input','read_write'}]
                value=next(int(pre['values'][i],16) for i,o in enumerate(input_ops) if o['index']==member['memoryFacts']['valueOperandIndex'])
                expected=bytearray(before);expected[s['offset']:s['offset']+8]=value.to_bytes(8,'little')
                if after!=expected:mismatch('L2_JOINT_STORE_VALUE_MISMATCH')
            previous=post['objectHex']
        if previous!=row['objectHex']:mismatch('L2_JOINT_FINAL_OBJECT_MISMATCH')
        if values.get(program['returnDeclarationIdentity'])!=int(row['value'],16):mismatch('L2_JOINT_RETURN_VALUE_MISMATCH')
    return observation
