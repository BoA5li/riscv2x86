"""Replay a selected native compile into fresh artifacts, without approval.

The same semantic arguments and cwd are used for the compiler's dependency
scans. These checks establish acquisition consistency, not immutable snapshots,
link closure, compiler equivalence, translation or any L0--L3 conclusion.
"""
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess

from .compiler_call_dependencies import parse_dependencies, _snapshot
from .project_compile_context import validate, digest
from .project_build_records import identity


def build(context, output, *, timeout=240):
    validate(context)
    if not context['inspectionReady']:raise ValueError('PROJECT_NATIVE_CONTEXT_BLOCKED')
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    cwd=Path(context['workingDirectory']);compiler=context['nativeCompiler']
    base=[compiler,*context['inspectionArguments']]
    depcmd=[*base,'-M','-MT','rv2x86_call_inventory',context['sourcePath']]
    commands=[]
    def run(argv):
        result=subprocess.run(argv,cwd=cwd,capture_output=True,text=True,timeout=timeout,check=False)
        commands.append({'arguments':argv,'directory':str(cwd),'returnCode':result.returncode,
                         'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode:raise ValueError('PROJECT_NATIVE_COMPILER_FAILED:'+result.stderr[-4000:])
        return result.stdout
    try:
        paths=parse_dependencies(run(depcmd));before=_snapshot(paths,cwd)
        object_path=output/'native.o'; dep_path=output/'native.d'
        argv=[compiler];args=context['nativeArguments'][1:];i=0
        while i<len(args):
            if args[i] in {'-o','-MF'}:
                flag=args[i];argv.extend([flag,str(object_path if flag=='-o' else dep_path)]);i+=2
            else:argv.append(args[i]);i+=1
        if '-o' not in argv:argv.extend(['-o',str(object_path)])
        run(argv)
        if parse_dependencies(run(depcmd))!=paths or _snapshot(paths,cwd)!=before:
            raise ValueError('PROJECT_NATIVE_DEPENDENCIES_CHANGED')
        validate(context)
        raw=object_path.read_bytes()
        if len(raw)<20 or raw[:4]!=b'\x7fELF' or raw[5] not in (1,2):
            raise ValueError('PROJECT_NATIVE_ELF_REQUIRED')
        machine=struct.unpack(('<' if raw[5]==1 else '>')+'H',raw[18:20])[0]
        body={'schemaVersion':'riscv2x86.project-native-compile-replay.v1',
              'contextIdentity':context['contextIdentity'],'commands':commands,'dependencies':before,
              'objectPath':str(object_path),'objectDigest':'sha256:'+sha256(raw).hexdigest(),
              'elfMachine':machine,'nativeCompileReplayed':True,'acquisitionConsistent':True,
              'linkClosureVerified':False,'immutableSnapshot':False,
              'semanticApproval':False,'productionAcceptanceComplete':False}
        result=dict(body,replayIdentity=identity(body))
        (output/'native-replay.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    except (OSError,ValueError,subprocess.SubprocessError):
        (output/'native-failure.json').write_text(json.dumps({'commands':commands,
            'contextIdentity':context['contextIdentity'],'nativeCompileReplayed':False,
            'semanticApproval':False,'productionAcceptanceComplete':False},indent=2)+'\n')
        raise
