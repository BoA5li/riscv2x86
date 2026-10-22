"""Execute actual ELF functions in a declared controlled TIME environment."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from .semantic_content import semantic_identity
from .time_trace_contract import validate_time_contract


def digest(path):return 'sha256:'+sha256(Path(path).read_bytes()).hexdigest()


class ObserverExecutionError(ValueError):
    def __init__(self, code, record):
        super().__init__(code)
        self.record=record


def function_extent(data, symbol, machine):
    """Read the ELF64 little-endian dynamic function symbol; no disassembly guess."""
    if (len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or
            int.from_bytes(data[16:18],'little')!=3 or int.from_bytes(data[18:20],'little')!=machine):
        raise ValueError('TIME_SHARED_LIBRARY_ABI_REQUIRED')
    shoff=struct.unpack_from('<Q',data,40)[0];entsize,count=struct.unpack_from('<HH',data,58)
    if entsize!=64 or not count or shoff+count*64>len(data):raise ValueError('TIME_ELF_SECTIONS_INVALID')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*64) for i in range(count)]
    matches=[]
    for section in sections:
        if section[1]!=11:continue
        if section[6]>=count or section[9]!=24:raise ValueError('TIME_ELF_SYMBOLS_INVALID')
        strings=sections[section[6]];strings=data[strings[4]:strings[4]+strings[5]]
        if section[4]+section[5]>len(data) or section[5]%24:raise ValueError('TIME_ELF_SYMBOLS_INVALID')
        for offset in range(section[4],section[4]+section[5],24):
            name,info,other,index,value,size=struct.unpack_from('<IBBHQQ',data,offset)
            if name>=len(strings):raise ValueError('TIME_ELF_SYMBOLS_INVALID')
            if strings[name:].split(b'\0',1)[0]==symbol.encode() and info&15==2 and index and size:
                matches.append((value,size))
    if len(matches)!=1:raise ValueError('TIME_FUNCTION_SYMBOL_AMBIGUOUS')
    return matches[0]


def probe_source(symbol, count):
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',symbol) is None:raise ValueError('TIME_SYMBOL_INVALID')
    return r'''#define _GNU_SOURCE
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
int main(int argc, char **argv) {
 if(argc!=2)return 20;
 void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!h)return 21;
 void *entry=dlsym(h,"SYMBOL");if(!entry)return 22;
 uint64_t (*call)(void);memcpy(&call,&entry,sizeof(call));
 printf("site %" PRIxPTR "\n",(uintptr_t)entry);
 for(unsigned int i=0;i<COUNT;i++) {
   uint64_t value=call();
   if(printf("%u %016" PRIx64 "\n",i,value)<0)return 23;
 }
 return dlclose(h)!=0;
}
'''.replace('SYMBOL',symbol).replace('COUNT',str(count))


def observe(*,side,program,symbol,values,compiler,runner,contract,timeout):
    validate_time_contract(contract)
    if side not in {'source','target'}:raise ValueError('TIME_SIDE_INVALID')
    data=Path(program['path']).read_bytes()
    if 'sha256:'+sha256(data).hexdigest()!=program['digest']:raise ValueError('TIME_PROGRAM_CHANGED')
    _,extent=function_extent(data,symbol,243 if side=='source' else 62)
    compiler=Path(shutil.which(compiler) or compiler).resolve()
    if not compiler.is_file():raise ValueError('TIME_COMPILER_MISSING')
    if side=='source':
        if not runner or digest(shutil.which(runner[0]) or runner[0])!=contract['sourceBackend']['binaryDigest']:
            raise ValueError('TIME_SOURCE_BINARY_MISMATCH')
    elif runner:raise ValueError('TIME_TARGET_RUNNER_UNSUPPORTED')
    with tempfile.TemporaryDirectory(prefix='rv2x86-controlled-time-') as directory:
        root=Path(directory);source=root/'observer.c';binary=root/'observer';library=root/'program.so'
        source.write_text(probe_source(symbol,len(values)));library.write_bytes(data)
        command=[str(compiler),'-std=gnu11','-O0','-fno-lto','-Wall','-Wextra','-Werror',
                 str(source),'-ldl','-o',str(binary)]
        built=subprocess.run(command,capture_output=True,text=True,timeout=timeout,check=False)
        if built.returncode:raise ValueError('TIME_OBSERVER_BUILD_FAILED:'+built.stderr[-2000:])
        trajectory=root/'trajectory';events=root/'events'
        trajectory.write_text(''.join(f'{v:016x}\n' for v in values))
        env=dict(os.environ);env.update(RV2X86_TIME_INPUT_V1=str(trajectory),RV2X86_TIME_EVENTS_V1=str(events))
        try:
            completed=subprocess.run([*runner,str(binary),str(library)],env=env,
                capture_output=True,text=True,timeout=timeout,check=False)
        except subprocess.TimeoutExpired as exc:
            def text(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
            raise ObserverExecutionError('TIME_GUEST_EXECUTION_TIMEOUT',{
                'side':side,'programDigest':program['digest'],'executionStarted':True,
                'stdout':text(exc.stdout),'stderr':text(exc.stderr),
                'events':events.read_text() if events.is_file() else ''}) from exc
        record={'side':side,'programDigest':program['digest'],'observerSource':source.read_text(),
            'observerDigest':digest(binary),'compilerDigest':digest(compiler),'buildCommand':command,
            'returnCode':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr,
            'events':events.read_text() if events.is_file() else '', 'functionSize':extent}
        if side=='source' and digest(shutil.which(runner[0]) or runner[0])!=contract['sourceBackend']['binaryDigest']:
            raise ValueError('TIME_SOURCE_BINARY_CHANGED')
        if digest(program['path'])!=program['digest']:raise ValueError('TIME_PROGRAM_CHANGED')
        return record


def validate_observation(record, *, side, program_digest, values):
    if record['side']!=side or record['programDigest']!=program_digest:
        raise ValueError('TIME_OBSERVATION_BINDING_MISMATCH')
    if record['returnCode']!=0:raise ValueError('TIME_EXECUTION_FAILED')
    lines=record['stdout'].splitlines();events=record['events'].splitlines()
    if len(lines)!=len(values)+1 or len(events)!=len(values):raise ValueError('TIME_READ_EVENT_COUNT_MISMATCH')
    if not re.fullmatch(r'site [0-9a-f]+',lines[0]):raise ValueError('TIME_ACTUAL_SITE_REQUIRED')
    site=int(lines[0].split()[1],16);extent=record['functionSize']
    if type(extent) is not int or not 0<extent<65536:raise ValueError('TIME_ACTUAL_SITE_REQUIRED')
    projection=[]
    for i,(line,event,value) in enumerate(zip(lines[1:],events,values)):
        if not re.fullmatch(r'[0-9]+ [0-9a-f]{16}',line) or not re.fullmatch(r'[0-9]+ [0-9a-f]{16} [0-9a-f]{16}',event):
            raise ValueError('TIME_OBSERVATION_FORMAT_INVALID')
        output_index,result=line.split();read_index,read,pc=event.split()
        if int(output_index)!=i or int(read_index)!=i:raise ValueError('TIME_READ_EVENT_ORDER_MISMATCH')
        if side=='source' and not site<=int(pc,16)<site+extent:raise ValueError('TIME_READ_OUTSIDE_BOUND_FUNCTION')
        if side=='target' and int(pc,16)!=0:raise ValueError('TIME_TARGET_EVENT_FORMAT_INVALID')
        projection.append((i,int(read,16),int(result,16)))
    # The caller distinguishes valid source execution from a wrong target.
    return projection,all(read==value and result==value for (_,read,result),value in zip(projection,values))
