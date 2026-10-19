"""Content-bound provenance for the canonical, separately compiled runtime."""
from pathlib import Path
from hashlib import sha256
import json
import subprocess
import re
import shlex

def semantic_identity(value):
    encoded=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    return 'sha256:'+sha256(encoded).hexdigest()


def unsupported_flags(flags):
    known={'-DNDEBUG','-D_GNU_SOURCE','-D__STDC_CONSTANT_MACROS','-D__STDC_FORMAT_MACROS','-D__STDC_LIMIT_MACROS',
           '-fPIC','-fno-lto','-fno-omit-frame-pointer','-std=c11','-std=gnu11','-std=c17','-std=gnu17'}
    return [x for x in shlex.split(flags) if x not in known and re.fullmatch(r'-(?:O[0123sgz]|g[0-3]?|ggdb[0-3]?|W[A-Za-z0-9_=,-]+|fstack-protector(?:-strong|-all)?)',x) is None]

SCHEMA='riscv2x86.runtime-build.v1'
SOURCES=('runtime/riscv2x86_runtime_helpers.c','runtime/riscv2x86_csr_runtime.c',
         'runtime/include/riscv2x86_runtime_helpers.h','runtime/include/riscv2x86_csr_runtime.h')
BUILD_CONTRACT='automatic-gcc-separate-tu-no-lto-v1'


def digest(path):return 'sha256:'+sha256(Path(path).read_bytes()).hexdigest()


def write_manifest(root,archive,compiler,compiler_id,output,compiler_flags=""):
    root=Path(root).resolve();archive=Path(archive).resolve();compiler=Path(compiler).resolve()
    if compiler_id not in ('GNU','Clang','AppleClang'):
        raise ValueError('RUNTIME_BUILD_COMPILER_UNSUPPORTED')
    version=subprocess.run([str(compiler),'--version'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True).stdout
    try:archive_path=str(archive.relative_to(root))
    except ValueError:archive_path=str(archive)
    payload={'schemaVersion':SCHEMA,'archivePath':archive_path,
        'archiveDigest':digest(archive),'compilerPath':str(compiler),'compilerDigest':digest(compiler),
        'compilerId':compiler_id,'compilerVersion':version,'buildContract':BUILD_CONTRACT,
        'compilerFlags':compiler_flags,'unsupportedCompilerFlags':unsupported_flags(compiler_flags),
        'sources':{p:digest(root/p) for p in SOURCES}}
    payload['manifestIdentity']=semantic_identity(payload)
    output=Path(output);temporary=output.with_name(output.name+'.tmp')
    temporary.write_text(json.dumps(payload,sort_keys=True,indent=2)+'\n')
    parsed=json.loads(temporary.read_text())
    if parsed['manifestIdentity']!=semantic_identity({k:v for k,v in parsed.items() if k!='manifestIdentity'}):
        raise ValueError('RUNTIME_BUILD_MANIFEST_WRITE_INVALID')
    temporary.replace(output)
    return payload


def validate_manifest(root):
    root=Path(root).resolve();path=root/'build/riscv2x86-runtime-build.json'
    value=json.loads(path.read_text())
    expected={'schemaVersion','archivePath','archiveDigest','compilerPath','compilerDigest',
              'compilerId','compilerVersion','buildContract','compilerFlags','unsupportedCompilerFlags','sources','manifestIdentity'}
    if (set(value)!=expected or value['schemaVersion']!=SCHEMA
            or value['manifestIdentity']!=semantic_identity({k:v for k,v in value.items() if k!='manifestIdentity'})
            or value['buildContract']!=BUILD_CONTRACT
            or value['compilerId'] not in ('GNU','Clang','AppleClang')
            or set(value['sources'])!=set(SOURCES)):
        raise ValueError('RUNTIME_BUILD_MANIFEST_INVALID')
    if value['unsupportedCompilerFlags']!=unsupported_flags(value['compilerFlags']) or value['unsupportedCompilerFlags']:
        raise ValueError('RUNTIME_BUILD_COMPILER_FLAGS_UNSUPPORTED')
    archive=(root/value['archivePath']).resolve()
    if archive!=root/'build/libriscv2x86_runtime.a' or digest(archive)!=value['archiveDigest']:
        raise ValueError('RUNTIME_BUILD_ARCHIVE_IDENTITY_MISMATCH')
    if digest(value['compilerPath'])!=value['compilerDigest']:
        raise ValueError('RUNTIME_BUILD_COMPILER_IDENTITY_MISMATCH')
    if any(digest(root/p)!=expected for p,expected in value['sources'].items()):
        raise ValueError('RUNTIME_BUILD_SOURCE_IDENTITY_MISMATCH')
    return value
