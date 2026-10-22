"""Explicit single-hart QEMU-system M-mode backend and native logical adapter.

Scope: one void/no-operand SYSTEM fragment, RV64I+Zicsr, bare addressing,
M-mode ECALL return or WFI with MTIP already pending and global MIE clear.
Not Linux user-mode, future-event liveness, or microarchitecture equivalence.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from .semantic_content import semantic_identity
from .system_instruction_ingress import PROFILE,digest

BASE='b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56'
SCHEMA='riscv2x86.controlled-system-backend.v1'
CPU_PROFILE='rv64,priv_spec=v1.12.0'
FILES=('controlled_system.h','controlled_system.c','controlled_system_boot.S',
       'controlled_system.ld','controlled_system_kernel.c')
ROOT=Path(__file__).resolve().parents[2]/'runtime/system'
# Reviewed together with the bounded predicates in controlled_system_contract:
# full integer trap save/restore + mepc advance/MRET; MTIP pending before WFI;
# private observer transport; x86 adapter updates the corresponding logical state.
# A changed implementation requires a new mechanism review, not just a rehash.
REVIEWED_IMPLEMENTATION='sha256:9890c66f75dfe41075c9a272199b22a1e3b80be6d0df8ed3e8ae5bc64e0e4be0'
_REBUILT_LIBRARIES=set()
_CHECKED_QEMU_BINARIES=set()


def checked(command, *, cwd=None, log=None, timeout=3600):
    result=subprocess.run(command,cwd=cwd,capture_output=True,text=True,timeout=timeout,check=False)
    if log is not None: Path(log).write_text(result.stdout+result.stderr)
    if result.returncode: raise ValueError('SYSTEM_COMMAND_FAILED:'+json.dumps(command)+':'+result.stderr[-2000:])
    return result


def executable(value):
    path=Path(shutil.which(str(value)) or str(value)).absolute()
    if not path.is_file() or not os.access(path,os.X_OK):raise ValueError('SYSTEM_TOOL_UNAVAILABLE:'+str(path))
    return str(path)


def implementation_identity():
    actual=semantic_identity({name:digest((ROOT/name).read_bytes()) for name in FILES})
    if actual!=REVIEWED_IMPLEMENTATION:raise ValueError('SYSTEM_BACKEND_IMPLEMENTATION_NOT_REVIEWED')
    return actual


def validate_backend(path):
    path=Path(path).resolve();value=json.loads(path.read_text())
    fields={'schemaVersion','profile','baseCommit','implementationIdentity','implementationDirectory',
        'qemuBinary','qemuBinaryDigest','sourceCompiler','sourceCompilerDigest','sourceMarch','targetCompiler',
        'targetCompilerDigest','runtimeLibrary','runtimeLibraryDigest','buildIdentity','backendIdentity'}
    if not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA or value['profile']!=PROFILE or value['baseCommit']!=BASE:
        raise ValueError('SYSTEM_BACKEND_SCHEMA_INVALID')
    if semantic_identity({k:v for k,v in value.items() if k!='backendIdentity'})!=value['backendIdentity']:
        raise ValueError('SYSTEM_BACKEND_IDENTITY_MISMATCH')
    if value['sourceMarch'] not in ('rv64i_zicsr','rv64i'):raise ValueError('SYSTEM_BACKEND_SOURCE_ISA_INVALID')
    if value['implementationIdentity']!=implementation_identity():raise ValueError('SYSTEM_BACKEND_IMPLEMENTATION_CHANGED')
    implementation=Path(value['implementationDirectory'])
    for name in FILES:
        if digest((implementation/name).read_bytes())!=digest((ROOT/name).read_bytes()):
            raise ValueError('SYSTEM_BACKEND_IMPLEMENTATION_COPY_CHANGED')
    for key in ('qemuBinary','sourceCompiler','targetCompiler','runtimeLibrary'):
        actual=Path(value[key])
        if not actual.is_file() or digest(actual.read_bytes())!=value[key+'Digest']:
            raise ValueError('SYSTEM_BACKEND_ARTIFACT_CHANGED:'+key)
    if value['qemuBinaryDigest'] not in _CHECKED_QEMU_BINARIES:
        version=checked([value['qemuBinary'],'--version'],timeout=30).stdout
        if not version.startswith('QEMU emulator version 7.2.0 '):
            raise ValueError('SYSTEM_BACKEND_QEMU_SYSTEM_VERSION_MISMATCH')
        _CHECKED_QEMU_BINARIES.add(value['qemuBinaryDigest'])
    # Reproduce the target archive from the pinned implementation, rather than
    # treating an arbitrary library digest as evidence of its source semantics.
    key=(value['implementationIdentity'],value['targetCompilerDigest'],value['runtimeLibraryDigest'])
    if key not in _REBUILT_LIBRARIES:
        with tempfile.TemporaryDirectory(prefix='rv2x86-system-runtime-rebuild-') as temp:
            obj=Path(temp)/'controlled_system.o';library=Path(temp)/'libcontrolled_system.a'
            checked([value['targetCompiler'],'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fPIC','-c',
                str(implementation/'controlled_system.c'),'-I',str(implementation),'-o',str(obj)],timeout=120)
            checked([executable('ar'),'rcs',str(library),str(obj)],timeout=120)
            if digest(library.read_bytes())!=value['runtimeLibraryDigest']:
                raise ValueError('SYSTEM_BACKEND_RUNTIME_REBUILD_MISMATCH')
        _REBUILT_LIBRARIES.add(key)
    return value


def build(source,output,*,source_compiler='riscv64-linux-gnu-gcc',target_compiler='gcc',jobs=2):
    source=Path(source).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('SYSTEM_BACKEND_OUTPUT_EXISTS')
    if type(jobs) is not int or jobs<1:raise ValueError('SYSTEM_BACKEND_JOBS_INVALID')
    cc=executable(source_compiler);target=executable(target_compiler);ar=executable('ar')
    if checked(['git','-C',str(source),'rev-parse','HEAD']).stdout.strip()!=BASE:
        raise ValueError('SYSTEM_BACKEND_QEMU_BASE_UNSUPPORTED')
    output.mkdir(parents=True);steps=[]
    probe=output/'csr-probe.c';probe.write_text('void probe(void){__asm__ volatile("csrr t0, mstatus" ::: "t0");}\n')
    march=None
    for spelling in ('rv64i_zicsr','rv64i'):
        result=subprocess.run([cc,'-march='+spelling,'-mabi=lp64','-c',str(probe),'-o',str(output/'csr-probe.o')],capture_output=True,text=True,check=False)
        (output/('probe-'+spelling+'.log')).write_text(result.stdout+result.stderr)
        if result.returncode==0: march=spelling;break
    if march is None:raise ValueError('SYSTEM_BACKEND_SOURCE_CSR_ASSEMBLER_UNAVAILABLE')
    def run(stage,command,cwd=None):
        try:
            result=checked(command,cwd=cwd,log=output/(stage+'.log'))
            steps.append({'stage':stage,'command':command,'returnCode':result.returncode})
        except Exception:
            steps.append({'stage':stage,'command':command,'returnCode':None});raise
        finally:
            (output/'build-status.json').write_text(json.dumps({'steps':steps,'semanticApproval':False},indent=2)+'\n')
    work=output/'source'
    run('worktree',['git','-C',str(source),'worktree','add','--detach',str(work),BASE])
    run('submodules',['git','-C',str(work),'submodule','update','--init','meson','dtc','ui/keycodemapdb'])
    build_dir=output/'build';build_dir.mkdir()
    run('configure',[str(work/'configure'),'--target-list=riscv64-softmmu','--disable-user',
        '--disable-docs','--disable-werror','--disable-gtk','--disable-sdl','--disable-vnc'],cwd=build_dir)
    run('compile',['make','-j'+str(jobs)],cwd=build_dir)
    binary=build_dir/'qemu-system-riscv64'
    run('version',[str(binary),'--version'])
    implementation=output/'implementation';implementation.mkdir()
    for name in FILES:shutil.copyfile(ROOT/name,implementation/name)
    obj=implementation/'controlled_system.o';library=implementation/'libcontrolled_system.a'
    run('target-runtime',[target,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fPIC','-c',
        str(implementation/'controlled_system.c'),'-I',str(implementation),'-o',str(obj)])
    run('target-archive',[ar,'rcs',str(library),str(obj)])
    value={'schemaVersion':SCHEMA,'profile':PROFILE,'baseCommit':BASE,
        'implementationIdentity':implementation_identity(),'implementationDirectory':str(implementation),
        'qemuBinary':str(binary),'qemuBinaryDigest':digest(binary.read_bytes()),
        'sourceCompiler':cc,'sourceCompilerDigest':digest(Path(cc).read_bytes()),'sourceMarch':march,
        'targetCompiler':target,'targetCompilerDigest':digest(Path(target).read_bytes()),
        'runtimeLibrary':str(library),'runtimeLibraryDigest':digest(library.read_bytes()),
        'buildIdentity':semantic_identity({'steps':steps,'configurationDigest':digest((build_dir/'config-host.mak').read_bytes()),
            'implementationIdentity':implementation_identity()})}
    value['backendIdentity']=semantic_identity(value)
    manifest=output/'backend.json';manifest.write_text(json.dumps(value,indent=2)+'\n')
    validate_backend(manifest)
    return {'backendPath':str(manifest),'backendIdentity':value['backendIdentity'],'semanticApproval':False}


def build_program(*,backend_path,side,source,symbol,operation,output,optimization='-O0'):
    value=validate_backend(backend_path);output=Path(output).resolve();source=Path(source).resolve()
    if side not in ('source','target') or operation not in ('ecall','wfi') or optimization not in ('-O0','-O2','-O3'):
        raise ValueError('SYSTEM_BUILD_PROFILE_INVALID')
    import re
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',symbol) or symbol=='main' or symbol.startswith('__rv2x86_'):
        raise ValueError('SYSTEM_BUILD_SYMBOL_INVALID')
    if output.exists():raise ValueError('SYSTEM_PROGRAM_OUTPUT_EXISTS')
    output.parent.mkdir(parents=True,exist_ok=True);impl=Path(value['implementationDirectory'])
    wrapper=output.parent/'system-wrapper.c';number=1 if operation=='ecall' else 2
    text='#include '+json.dumps(str(source))+'\n'
    if side=='source':
        text+='void __rv2x86_probe(void){'+symbol+'();}\n'
        command=[value['sourceCompiler'],'-std=gnu11',optimization,'-Wall','-Wextra','-Werror',
            '-march='+value['sourceMarch'],'-mabi=lp64','-mcmodel=medany','-mno-relax','-msmall-data-limit=0',
            '-ffreestanding','-fno-builtin','-fno-inline','-fno-pic','-fno-pie','-fno-stack-protector',
            '-fno-asynchronous-unwind-tables','-nostdlib','-nostartfiles','-static','-D__RV2X86_OPERATION='+str(number),
            str(wrapper),str(impl/'controlled_system_kernel.c'),str(impl/'controlled_system_boot.S'),
            '-Wl,-T,'+str(impl/'controlled_system.ld'),'-Wl,--build-id=none','-o',str(output)]
    else:
        text+='#include "controlled_system.h"\nint main(void){__rv2x86_system_initialize('+str(number)+');'
        text+='__rv2x86_system_event('+str(1 if number==1 else 4)+');'+symbol+'();'
        text+='__rv2x86_system_event('+str(3 if number==1 else 5)+');__rv2x86_system_finish();return 0;}\n'
        command=[value['targetCompiler'],'-std=gnu11',optimization,'-Wall','-Wextra','-Werror',
            '-fno-inline','-I',str(impl),'-include',str(impl/'controlled_system.h'),str(wrapper),value['runtimeLibrary'],
            '-Wl,--build-id=none','-o',str(output)]
    wrapper.write_text(text)
    checked(command,log=output.with_name(output.name+'.build.log'),timeout=120)
    data=output.read_bytes()
    if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[18:20],'little')!=(243 if side=='source' else 62):
        raise ValueError('SYSTEM_PROGRAM_ELF_ARCHITECTURE_MISMATCH')
    return {'programDigest':digest(data),'backendIdentity':value['backendIdentity'],'command':command,
        'sourceDigest':digest(source.read_bytes()),'side':side,'optimization':optimization}


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    b=sub.add_parser('backend');b.add_argument('--qemu-source',required=True,type=Path);b.add_argument('--output',required=True,type=Path)
    b.add_argument('--jobs',type=int,default=2);b.add_argument('--source-compiler',default='riscv64-linux-gnu-gcc');b.add_argument('--target-compiler',default='gcc')
    r=sub.add_parser('program')
    for key in ('backend','source','output'):r.add_argument('--'+key,required=True,type=Path)
    r.add_argument('--side',choices=('source','target'),required=True);r.add_argument('--symbol',required=True)
    r.add_argument('--operation',choices=('ecall','wfi'),required=True)
    a=p.parse_args()
    try:
        result=build(a.qemu_source,a.output,source_compiler=a.source_compiler,target_compiler=a.target_compiler,jobs=a.jobs) if a.action=='backend' else build_program(
            backend_path=a.backend,side=a.side,source=a.source,symbol=a.symbol,operation=a.operation,output=a.output)
        print(json.dumps(result));return 0
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(json.dumps({'failureStage':'controlled_system_build','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
