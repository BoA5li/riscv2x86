import shutil
import subprocess
from pathlib import Path
import platform
import json
import pytest
from riscv2x86_py.runtime_build_manifest import write_manifest,validate_manifest,SOURCES


def build(tmp_path):
    gcc=shutil.which('gcc');ar=shutil.which('ar')
    if platform.machine() not in ('x86_64','amd64') or not gcc or not ar:pytest.skip('requires x86 GNU-compatible tools')
    root=Path(__file__).resolve().parents[2]
    for relative in SOURCES:
        target=tmp_path/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/relative,target)
    output=tmp_path/'build';output.mkdir()
    objects=[]
    for source in SOURCES[:2]:
        obj=output/(Path(source).stem+'.o')
        result=subprocess.run([gcc,'-O2','-fno-lto','-I'+str(tmp_path/'runtime/include'),'-c',str(tmp_path/source),'-o',str(obj)],capture_output=True,text=True)
        assert result.returncode==0,result.stderr
        objects.append(str(obj))
    archive=output/'libriscv2x86_runtime.a'
    result=subprocess.run([ar,'rcs',str(archive),*objects],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    compiler_id='Clang' if 'clang' in subprocess.check_output([gcc,'--version'],text=True).lower() else 'GNU'
    write_manifest(tmp_path,archive,gcc,compiler_id,output/'riscv2x86-runtime-build.json', '-O2 -fno-lto')
    return archive


def test_real_archive_manifest_rejects_stale_source_and_archive(tmp_path):
    archive=build(tmp_path)
    result=validate_manifest(tmp_path)
    assert result['sources'].keys()==set(SOURCES)
    old=(tmp_path/SOURCES[0]).read_bytes();(tmp_path/SOURCES[0]).write_bytes(old+b'\n')
    with pytest.raises(ValueError,match='SOURCE_IDENTITY_MISMATCH'):validate_manifest(tmp_path)
    (tmp_path/SOURCES[0]).write_bytes(old)
    archive.write_bytes(archive.read_bytes()+b'changed')
    with pytest.raises(ValueError,match='ARCHIVE_IDENTITY_MISMATCH'):validate_manifest(tmp_path)


def test_noncanonical_compiler_flags_do_not_grant_runtime_contract(tmp_path):
    archive=build(tmp_path)
    path=tmp_path/'build/riscv2x86-runtime-build.json';payload=json.loads(path.read_text())
    write_manifest(tmp_path,archive,payload['compilerPath'],payload['compilerId'],path,'-Dclock_gettime=other_clock')
    with pytest.raises(ValueError,match='COMPILER_FLAGS_UNSUPPORTED'):validate_manifest(tmp_path)
