from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tarfile
import pytest
from riscv2x86_py.project_source_release import verify,replay


def fixture(tmp_path):
    source=tmp_path/'src';source.mkdir();(source/'include').mkdir()
    (source/'include/config.h').write_bytes(b'#define VALUE 1\n');(source/'a.c').write_bytes(b'int x;\n')
    (source/'alias.h').symlink_to('include/config.h')
    archive=tmp_path/'release.tar.gz'
    with tarfile.open(archive,'w:gz') as t:t.add(source,arcname='release')
    spec={'id':'fixture','version':'1','root':'release','sha256':sha256(archive.read_bytes()).hexdigest()}
    return spec,archive,source


def test_real_tar_file_types_and_symlinks_are_checked(tmp_path):
    spec,a,s=fixture(tmp_path);value=verify(spec,a,s)
    path=tmp_path/'proof.json';path.write_text(json.dumps(value))
    assert replay(path)==value['releaseIdentity']
    assert value['sourceTreeMatchesRelease'] and not value['semanticApproval'] and not value['immutableSnapshot']
    assert any(r['kind']=='symlink' for r in value['entries'])
    (s/'a.c').write_text('changed\n')
    with pytest.raises(ValueError,match='CONTENT_MISMATCH'):replay(path)


@pytest.mark.parametrize('mutation',['extra','missing','symlink','mode','archive'])
def test_unrecorded_changes_are_not_silently_accepted(tmp_path,mutation):
    spec,a,s=fixture(tmp_path)
    if mutation=='extra':(s/'generated.h').write_text('int y;')
    elif mutation=='missing':(s/'a.c').unlink()
    elif mutation=='symlink':(s/'alias.h').unlink();(s/'alias.h').symlink_to('/etc/passwd')
    elif mutation=='mode':(s/'a.c').chmod(0o755)
    else:a.write_bytes(b'wrong archive')
    with pytest.raises((ValueError,OSError)):verify(spec,a,s)


def test_symlink_parent_cannot_redirect_regular_member_reads(tmp_path):
    spec,a,s=fixture(tmp_path)
    external=tmp_path/'external';external.mkdir();(external/'config.h').write_bytes(b'#define VALUE 1\n')
    (s/'include/config.h').unlink();(s/'include').rmdir();(s/'include').symlink_to(external,target_is_directory=True)
    with pytest.raises(ValueError):verify(spec,a,s)


def test_capture_run_replays_release_before_and_after(tmp_path):
    from riscv2x86_py.project_build_capture import create,run,inventory
    import shutil
    spec,a,s=fixture(tmp_path);proof=tmp_path/'proof.json';proof.write_text(json.dumps(verify(spec,a,s)))
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native GCC required')
    session=create(tmp_path/'capture',{'cc':gcc});config=tmp_path/'capture/capture.json'
    run(config,'build',[session['wrappers']['cc']['path'],'-c',str(s/'a.c'),'-o',str(tmp_path/'x.o')],cwd=tmp_path,source_proof=proof)
    assert inventory(config)['importComplete']
    (s/'unexpected').write_text('changed')
    with pytest.raises(ValueError):run(config,'second',['/bin/true'],cwd=tmp_path,source_proof=proof)


def test_invalid_source_member_paths_cannot_escape_root(tmp_path):
    s=tmp_path/'source';s.mkdir();a=tmp_path/'evil.tar'
    with tarfile.open(a,'w') as t:
        m=tarfile.TarInfo('release/../outside');m.size=1;t.addfile(m,io.BytesIO(b'x'))
    spec={'id':'bad','version':'1','root':'release','sha256':sha256(a.read_bytes()).hexdigest()}
    with pytest.raises(ValueError,match='MEMBER_PATH_INVALID'):verify(spec,a,s)


def test_source_changes_during_successful_command_are_an_acquisition_failure(tmp_path):
    from riscv2x86_py.project_build_capture import create,run,inventory
    import sys
    spec,a,s=fixture(tmp_path);proof=tmp_path/'proof.json';proof.write_text(json.dumps(verify(spec,a,s)))
    create(tmp_path/'capture',{'python':sys.executable});config=tmp_path/'capture/capture.json'
    with pytest.raises(ValueError,match='CLOSING_INPUTS_CHANGED'):
        run(config,'mutate',[sys.executable,'-c','import sys;open(sys.argv[1],"w").write("changed")',str(s/'a.c')],
            cwd=tmp_path,source_proof=proof)
    finishes=list((tmp_path/'capture/runs').glob('*.finish.json'))
    assert len(finishes)==1
    row=json.loads(finishes[0].read_text())
    assert row['returnCode']==0 and row['sourceReleaseError']
    assert not inventory(config)['importComplete']
