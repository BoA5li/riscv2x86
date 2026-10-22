"""Mechanically collected identities, separate from reviewed domain assumptions."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from collections.abc import Mapping
from .semantic_content import semantic_identity
from .time_trace_contract import QEMU_BASE, digest_ok

SCHEMA='riscv2x86.qemu-local-mechanism-evidence.v1'
FILES=('target/riscv/csr.c','include/qemu/timer.h',
       'target/riscv/insn_trans/trans_rvi.c.inc','accel/tcg/translate-all.c',
       'accel/tcg/user-exec.c','accel/tcg/tb-maint.c')


def digest(path):return 'sha256:'+sha256(Path(path).read_bytes()).hexdigest()


def collect(source,binary,build):
    source=Path(source).resolve();binary=Path(binary).resolve();build=Path(build).resolve()
    def git(*args):
        return subprocess.run(['git','-C',str(source),*args],capture_output=True,text=True,check=True).stdout.strip()
    if Path(git('rev-parse','--show-toplevel'))!=source or git('rev-parse','HEAD')!=QEMU_BASE:
        raise ValueError('MECHANISM_QEMU_SOURCE_UNSUPPORTED')
    if git('status','--porcelain','--untracked-files=no'):
        raise ValueError('MECHANISM_QEMU_SOURCE_MODIFIED')
    if binary.read_bytes()!= (build/'qemu-riscv64').read_bytes():
        raise ValueError('MECHANISM_INSTALLED_BUILD_MISMATCH')
    data=binary.read_bytes()
    if data[:6]!=b'\x7fELF\x02\x01' or data[18:20]!=b'\x3e\x00':
        raise ValueError('MECHANISM_HOST_ARCH_UNSUPPORTED')
    config=(build/'config-host.mak').read_text()
    if 'TARGET_DIRS=riscv64-linux-user\n' not in config or 'SRC_PATH='+str(source)+'\n' not in config:
        raise ValueError('MECHANISM_QEMU_BUILD_UNSUPPORTED')
    payload={'schemaVersion':SCHEMA,'sourceCommit':QEMU_BASE,
        'binaryDigest':digest(binary),'buildConfigDigest':digest(build/'config-host.mak'),
        'sourceDigests':{name:digest(source/name) for name in FILES},
        'sourceTimeMechanism':'qemu-7.2-linux-user-x86_64-rdtsc',
        'sourceSyncMechanism':'qemu-7.2-linux-user-write-protect-invalidate-and-tb-exit',
        'semanticApproval':False}
    payload['evidenceIdentity']=semantic_identity(payload)
    return payload


def validate(value):
    fields={'schemaVersion','sourceCommit','binaryDigest','buildConfigDigest','sourceDigests',
            'sourceTimeMechanism','sourceSyncMechanism','semanticApproval','evidenceIdentity'}
    if (not isinstance(value,Mapping) or set(value)!=fields or value['schemaVersion']!=SCHEMA
            or value['sourceCommit']!=QEMU_BASE or value['semanticApproval'] is not False
            or not digest_ok(value['binaryDigest']) or not digest_ok(value['buildConfigDigest'])
            or not isinstance(value['sourceDigests'],Mapping) or set(value['sourceDigests'])!=set(FILES)
            or any(not digest_ok(v) for v in value['sourceDigests'].values())
            or value['sourceTimeMechanism']!='qemu-7.2-linux-user-x86_64-rdtsc'
            or value['sourceSyncMechanism']!='qemu-7.2-linux-user-write-protect-invalidate-and-tb-exit'
            or value['evidenceIdentity']!=semantic_identity({k:v for k,v in value.items() if k!='evidenceIdentity'})):
        raise ValueError('MECHANISM_EVIDENCE_INVALID')
    return value


def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qemu-source',required=True);p.add_argument('--qemu-binary',required=True)
    p.add_argument('--qemu-build',required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        if a.output.exists():raise ValueError('MECHANISM_OUTPUT_EXISTS')
        value=collect(a.qemu_source,a.qemu_binary,a.qemu_build);validate(value)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(value,indent=2)+'\n')
        print(json.dumps({'evidencePath':str(a.output),'evidenceIdentity':value['evidenceIdentity'],'semanticApproval':False}));return 0
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(json.dumps({'failureStage':'mechanism_evidence','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
