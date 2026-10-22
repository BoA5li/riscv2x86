"""Build a separate, explicit QEMU controlled-TIME environment.

Never modifies/installs over the native QEMU. Uses a detached worktree at the
reviewed 7.2.0 commit, replaces only the CONFIG_USER_ONLY read_time body, and
records all commands, patched sources, trace protocol and binary identities.
This environment must be explicitly selected; it is not native TIME semantics.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from .semantic_content import semantic_identity
from .time_trace_contract import QEMU_BASE, MECHANISM, validate_backend


def digest(path):
    return 'sha256:' + sha256(Path(path).read_bytes()).hexdigest()


ORIGINAL = '''#if defined(CONFIG_USER_ONLY)
static RISCVException read_time(CPURISCVState *env, int csrno,
                                target_ulong *val)
{
    *val = cpu_get_host_ticks();
    return RISCV_EXCP_NONE;
}'''
REPLACEMENT = '''#if defined(CONFIG_USER_ONLY)
#include "riscv2x86_time_trace.h"
static RISCVException read_time(CPURISCVState *env, int csrno,
                               target_ulong *val)
{
    *val = rv2x86_time_trace_read_v1(env->pc);
    return RISCV_EXCP_NONE;
}'''


def build(source, output, *, jobs=2):
    source=Path(source).resolve(); output=Path(output).resolve()
    if output.exists(): raise ValueError('TIME_BACKEND_OUTPUT_EXISTS')
    head=subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
    if head != QEMU_BASE: raise ValueError('TIME_BACKEND_BASE_COMMIT_UNSUPPORTED')
    output.mkdir(parents=True); steps=[]
    def run(name, command, cwd=None):
        with (output/(name+'.log')).open('w') as log:
            code=subprocess.run(command,cwd=cwd,stdout=log,stderr=subprocess.STDOUT,check=False).returncode
        steps.append({'stage':name,'command':command,'returnCode':code})
        (output/'build-status.json').write_text(json.dumps({'steps':steps,'semanticApproval':False},indent=2)+'\n')
        if code: raise ValueError('TIME_BACKEND_BUILD_FAILED:'+name)
    work=output/'source'
    run('worktree',['git','-C',str(source),'worktree','add','--detach',str(work),QEMU_BASE])
    # Dependencies are pinned by the original superproject; no guessed source.
    run('submodules',['git','-C',str(work),'submodule','update','--init','meson'])
    csr=work/'target/riscv/csr.c'; text=csr.read_text()
    if text.count(ORIGINAL)!=1: raise ValueError('TIME_BACKEND_SOURCE_CONTEXT_MISMATCH')
    csr.write_text(text.replace(ORIGINAL,REPLACEMENT))
    header=Path(__file__).resolve().parents[2]/'runtime/include/riscv2x86_time_trace.h'
    (csr.parent/header.name).write_bytes(header.read_bytes())
    build_dir=output/'build';build_dir.mkdir()
    run('configure',[str(work/'configure'),'--target-list=riscv64-linux-user','--disable-system'],cwd=build_dir)
    run('compile',['make','-j'+str(jobs)],cwd=build_dir)
    binary=build_dir/'qemu-riscv64'
    run('version',[str(binary),'--version'])
    manifest={'schemaVersion':'riscv2x86.controlled-time-backend.v1','mechanism':MECHANISM,
        'baseCommit':QEMU_BASE,'sourceDigest':digest(csr),'traceHeaderDigest':digest(header),
        'binaryDigest':digest(binary),'buildIdentity':semantic_identity({
            'steps':steps,'configDigest':digest(build_dir/'config-host.mak'),
            'sourceDigest':digest(csr),'traceHeaderDigest':digest(header),
            'compilerEnvironment':{k:os.environ.get(k) for k in ('CC','CFLAGS','LDFLAGS')}})}
    manifest['backendIdentity']=semantic_identity(manifest);validate_backend(manifest)
    (output/'backend.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return {'backendPath':str(output/'backend.json'),'binaryPath':str(binary),
            'backendIdentity':manifest['backendIdentity'],'semanticApproval':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qemu-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--jobs',type=int,default=2)
    a=p.parse_args()
    try:
        if a.jobs<1: raise ValueError('TIME_BACKEND_JOBS_INVALID')
        print(json.dumps(build(a.qemu_source,a.output,jobs=a.jobs)));return 0
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(json.dumps({'failureStage':'controlled_time_backend_build','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__': sys.exit(main())
