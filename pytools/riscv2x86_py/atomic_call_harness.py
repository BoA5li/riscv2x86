"""Actual typed calls with serialized integer arguments and complete objects."""
import re
from .atomic_call_contract import argument_values
from .l3_trace_support import require_json_match


def generate(name,spec,plan):
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name) is None:raise ValueError('ATOMIC_CALL_NAME_INVALID')
    contract=spec['callContract'];params=contract['parameters'];pointer=contract['pointerParameter']
    if plan.get('callContractIdentity')!=contract['contractIdentity']:
        raise ValueError('ATOMIC_CALL_SAMPLE_CONTRACT_MISMATCH')
    for i,row in enumerate(plan['inputs']):
        require_json_match(argument_values(contract,i,int(row['input'],16)),row['arguments'],
                           'ATOMIC_CALL_SAMPLE_ARGUMENTS_CHANGED')
    n=len(params);bits=spec['operation']['width_bits'];cells=plan['objectCellCount']
    rows=','.join('{'+','.join('0x'+x+'ULL' for x in [row['old'],*['0'*16 if x is None else x for x in row['arguments']]])+'}' for row in plan['inputs'])
    code=['#include <stdint.h>','#include <stdio.h>','#include <string.h>',
          spec['returnType']+' '+name+'('+','.join(p['cType'] for p in params)+');',
          'int main(int argc,char **argv){if(argc!=2||strlen(argv[1])!=64)return 2;',
          'const unsigned long long rows[]['+str(n+1)+']={'+rows+'};',
          'for(unsigned i=0;i<sizeof(rows)/sizeof(rows[0]);i++){',
          'uint'+str(bits)+'_t object['+str(cells)+'] __attribute__((aligned('+str(max(16,spec['operation']['alignment_bytes']))+')))={0,0x31,0x72,0x53};',
          'object[0]=(uint'+str(bits)+'_t)rows[i][0];unsigned long long before=object[0];']
    for i,p in enumerate(params):
        code.append(p['cType']+' arg'+str(i)+'='+('object' if i==pointer else '('+p['cType']+')rows[i]['+str(i+1)+']')+';')
    call=name+'('+','.join('arg'+str(i) for i in range(n))+')'
    code.append(call+';unsigned long long result=0;' if spec['returnType']=='void' else spec['returnType']+' returned='+call+';unsigned long long result=(unsigned long long)returned;')
    code+=['printf("{\\"sample\\":%u,\\"token\\":\\"%s\\",\\"objectBase\\":\\"%016llx\\",\\"old\\":\\"%016llx\\",\\"input\\":\\"%016llx\\",\\"result\\":\\"%016llx\\",\\"after\\":[",i,argv[1],(unsigned long long)(uintptr_t)object,before,(unsigned long long)arg'+str(contract['valueParameter'])+',result);',
           'for(unsigned j=0;j<'+str(cells)+';j++)printf("%s\\"%016llx\\"",j?",":"",(unsigned long long)object[j]);',
           'printf("],\\"arguments\\":[");']
    for i in range(n):
        value='(unsigned long long)(uintptr_t)arg'+str(i) if i==pointer else '(unsigned long long)arg'+str(i)
        code.append('printf("'+(',' if i else '')+'\\"%016llx\\"",'+value+');')
    code+=['puts("]}");','}return 0;}']
    return '\n'.join(code)+'\n'
