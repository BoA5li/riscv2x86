"""Executable observation producer for the explicit local instruction protocol.

Calls the approved fragment's exported zero-argument function in the actual
built shared library. Reported fetch values come from executing modified code,
never from computing the expected result. This tool does not approve a domain
or prove that an arbitrary enclosing function is noninterfering.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from .approved_replacement import approved_replacement
from .instruction_stream_domain import validate_domain
from .l2_instruction_visibility_runner import OBSERVATION, SCHEMA, decode_probe
from .semantic_content import semantic_identity


def digest(data):return 'sha256:'+sha256(data).hexdigest()


def probe_bytes(value,side):
    if type(value) is not int or not 0<=value<2048:raise ValueError('ISS_PROBE_VALUE_UNSUPPORTED')
    return (((value<<20)|0x513).to_bytes(4,'little')+bytes.fromhex('67800000')
        if side=='source' else b'\xb8'+value.to_bytes(4,'little')+b'\xc3')


def c_probe(symbol,side,values):
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',symbol) is None:
        raise ValueError('ISS_PROBE_SYMBOL_INVALID')
    arrays=','.join('{'+','.join(str(x) for x in probe_bytes(v,side))+'}' for v in values)
    size=len(probe_bytes(values[0],side))
    # No implicit cache flush is inserted: the observed call is the only sync
    # boundary between the volatile code stores and executing that code.
    return r'''#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sched.h>
#include <string.h>
int main(int argc,char **argv) {
 if(argc!=2)return 20;
 void *library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!library)return 21;
 void *entry=dlsym(library,"SYMBOL");if(!entry)return 22;
 void (*synchronize)(void);memcpy(&synchronize,&entry,sizeof(synchronize));
 unsigned char *code=mmap(0,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(code==MAP_FAILED)return 23;
 unsigned char versions[COUNT][SIZE]={ARRAYS};
 uint32_t (*execute)(void);void *address=code;memcpy(&execute,&address,sizeof(execute));
 for(unsigned int i=0;i<COUNT;i++){
   int before=sched_getcpu();
   for(unsigned int j=0;j<SIZE;j++)((volatile unsigned char*)code)[j]=versions[i][j];
   synchronize();
   uint32_t observed=execute();int after=sched_getcpu();
   if(printf("%u %u %d %d\n",i,observed,before,after)<0)return 24;
 }
 if(munmap(code,4096)!=0)return 25;
 return dlclose(library)!=0;
}'''.replace('SYMBOL',symbol).replace('COUNT',str(len(values))).replace('SIZE',str(size)).replace('ARRAYS',arrays)


def observe(request,*,side,symbol,approval_path,compiler,runner=(),values=(1,7),timeout=30):
    if side not in {'source','target'} or request.get('schemaVersion')!=SCHEMA or request.get('side')!=side:
        raise ValueError('ISS_HARNESS_REQUEST_INVALID')
    if len(values)<2 or len(set(values))<2:raise ValueError('ISS_HARNESS_VERSION_COVERAGE_REQUIRED')
    for key in ('executionIdentity','executionPlanIdentity'):
        if re.fullmatch(r'sha256:[0-9a-f]{64}',str(request.get(key))) is None:
            raise ValueError('ISS_HARNESS_EXECUTION_IDENTITY_INVALID')
    domain=request['domainAuthority'];fid=request['fragmentId']
    validate_domain(domain,fragment_id=fid,environment_id=domain['targetEnvironmentId'],cpu_profile=domain['targetCpuProfileId'])
    cpu=domain[side+'Execution']['pinnedCpu']
    if not hasattr(os,'sched_getaffinity') or os.sched_getaffinity(0)!={cpu}:
        raise ValueError('ISS_HARNESS_PINNING_REQUIRED')
    report=json.loads(Path(approval_path).read_text());findings=report['findings']
    matches=[f for f in findings if (f['fragment'].get('id') or f['fragment'].get('fragmentId'))==fid]
    if len(matches)!=1:raise ValueError('ISS_HARNESS_FRAGMENT_AMBIGUOUS')
    finding=matches[0];fragment=finding['fragment']
    from .l2_instruction_stream import validate_instruction_stream_approval
    validate_instruction_stream_approval(finding['approvalArtifact'],fragment,approved_replacement(finding),
        source_digest=finding.get('sourceDigest'))
    from .compiler_instruction_sync_scope import validate_scope
    validate_scope(finding['approvalArtifact'].get('l2InstructionSyncFunctionScope'),fragment,finding.get('sourceDigest'))
    if semantic_identity(domain)!=semantic_identity(finding['approvalArtifact']['instructionStreamProof']['phase6Proof']['contract']['domain_authority']):
        raise ValueError('ISS_HARNESS_APPROVED_DOMAIN_MISMATCH')
    if (fragment.get('enclosingFunction')!=symbol or fragment.get('inputs') or fragment.get('outputs')
            or sum(f['fragment'].get('enclosingFunction')==symbol for f in findings)!=1):
        raise ValueError('ISS_HARNESS_FUNCTION_BINDING_UNSUPPORTED')
    program=request[side+'Program'];data=Path(program['path']).read_bytes()
    if digest(data)!=program['digest']:raise ValueError('ISS_HARNESS_PROGRAM_IDENTITY_MISMATCH')
    # Both sides must execute their own actual ELF shared library.
    machine=243 if side=='source' else 62
    if (len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[16:18],'little')!=3
            or int.from_bytes(data[18:20],'little')!=machine):
        raise ValueError('ISS_HARNESS_SHARED_LIBRARY_ABI_UNSUPPORTED')
    compiler_path=Path(shutil.which(compiler) or compiler).resolve()
    if side=='source' and not runner:raise ValueError('ISS_SOURCE_RUNNER_REQUIRED')
    if side=='target' and runner:raise ValueError('ISS_TARGET_RUNNER_UNSUPPORTED')
    compiler_identity=digest(compiler_path.read_bytes())
    with tempfile.TemporaryDirectory(prefix='riscv2x86-iss-') as directory:
        root=Path(directory);source=root/'probe.c';binary=root/'probe';library=root/'program.so'
        library.write_bytes(data);source.write_text(c_probe(symbol,side,values))
        command=[str(compiler_path),'-std=gnu11','-O0','-Wall','-Wextra','-Werror','-fno-lto',
            str(source),'-ldl','-o',str(binary)]
        built=subprocess.run(command,capture_output=True,text=True,timeout=timeout,check=False)
        if built.returncode:raise ValueError('ISS_PROBE_BUILD_FAILED:'+built.stderr[-4000:])
        binary_identity=digest(binary.read_bytes())
        completed=subprocess.run([*runner,str(binary),str(library)],capture_output=True,text=True,timeout=timeout,check=False)
        if completed.returncode:raise ValueError('ISS_PROBE_EXECUTION_FAILED:'+str(completed.returncode)+':'+completed.stderr[-4000:])
    lines=completed.stdout.splitlines()
    if len(lines)!=len(values):raise ValueError('ISS_PROBE_OUTPUT_INVALID')
    events=[]
    for i,(line,value) in enumerate(zip(lines,values)):
        fields=line.split()
        if len(fields)!=4:raise ValueError('ISS_PROBE_OUTPUT_INVALID')
        index,observed,before,after=map(int,fields)
        if index!=i or before!=cpu or after!=cpu:raise ValueError('ISS_PROBE_CONTEXT_MISMATCH')
        code=probe_bytes(value,side).hex();decode_probe(code,side)
        record={'callReturned':True,'callIndex':i,'functionSymbol':symbol,
            'programDigest':program['digest'],'probeSourceDigest':digest(c_probe(symbol,side,values).encode()),
            'probeBinaryDigest':binary_identity,'compilerDigest':compiler_identity,
            'rawOutput':line,'cpuBefore':before,'cpuAfter':after}
        events.extend([{'eventIndex':len(events),'kind':'code_write','objectIdentity':'probe-code-object','codeHex':code},
            {'eventIndex':len(events)+1,'kind':'synchronize','fragmentId':fid,'traceRecord':{
                'origin':'execution_trace','executionSiteIdentity':semantic_identity({'fragmentId':fid,'symbol':symbol}),
                'recordPayload':record,'recordIdentity':semantic_identity(record)}},
            {'eventIndex':len(events)+2,'kind':'instruction_fetch','objectIdentity':'probe-code-object','observedValue':observed}])
    return {'schemaVersion':OBSERVATION,'fragmentId':fid,'executionIdentity':request['executionIdentity'],
        'executionPlanIdentity':request['executionPlanIdentity'],'side':side,'programDigest':program['digest'],
        'executionContext':domain[side+'Execution'],'events':events,'termination':'normal'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--side',choices=['source','target'],required=True)
    parser.add_argument('--function-symbol',required=True);parser.add_argument('--approval',required=True)
    parser.add_argument('--compiler',required=True);parser.add_argument('--timeout',type=int,default=30)
    parser.add_argument('--runner',nargs=argparse.REMAINDER,default=[])
    args=parser.parse_args()
    try:
        result=observe(json.load(sys.stdin),side=args.side,symbol=args.function_symbol,approval_path=args.approval,
            compiler=args.compiler,runner=args.runner,timeout=args.timeout)
        print(json.dumps(result,sort_keys=True));return 0
    except (OSError,ValueError,TypeError,KeyError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'failureStage':'instruction_visibility_execution','exceptionType':type(exc).__name__,
            'detail':str(exc),'evidenceProductionDisposition':'not_produced'}),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
